#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Owned Redfish and SSH session lifecycle for DUT facades.

This module owns transport-session registries and their teardown rules. The
established :class:`DUT` and :class:`DUTManager` methods remain the public
facades and are resolved at each call boundary so existing extensions and tests
can continue to replace those seams.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import asyncssh

from ..utils.redfish_tls import RedfishTLSPolicy
from ..utils.redfish_transport import (
    build_redfish_request_headers,
    encode_basic_auth_header,
    format_redfish_url_host,
)
from ..utils.ssh_security import (
    asyncssh_host_key_options,
    canonical_asyncssh_host_key_alias,
)
from ..utils.transport_support import catalog_transport_support
from .finalization_receipt import (
    capture_owned_awaitable,
    drain_owned_tasks,
    select_authoritative_exception,
)
from .redfish_session_auth import (
    AUTH_REQUEST_TIMEOUT_SECONDS,
    RedfishSessionAuthentication,
    RedfishSessionAuthenticationError,
    read_authentication_document,
)

logger = logging.getLogger(__name__)


def authoritative_cleanup_error(errors: List[BaseException]) -> BaseException:
    """
    Select the interruption-aware authoritative cleanup failure.

    After applying local validation, the function forwards ``errors`` to
    ``select_authoritative_exception`` and preserves its return and exception
    contract.

    Args:
        errors: Entries supplied as ``errors`` without transferring container
            ownership.

    Returns:
        A ``BaseException`` describing authoritative cleanup error.
    """

    return select_authoritative_exception(errors)


class RedfishSessionPool:
    """
    Own one pooled ``aiohttp`` session for a DUT Redfish endpoint.

    The type coordinates ``_log_runtime``, ``initialize``, ``get_session``,
    ``release_session``, and ``handle_session_conflict`` and retains the state
    those operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        dut_id: str,
        connection_info: Dict[str, Any],
        logger=None,
        session_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize a ``RedfishSessionPool`` instance.

        The initializer records ``_initialized``, ``_lock``, ``auth``,
        ``connection_info``, and ``connection_pool_limit`` for later operations
        and establishes the instance invariants before any public method runs.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            connection_info: Mapping supplying fields for initialize a
                ``RedfishSessionPool`` instance.
            logger: Sanitized logger used for operator-visible diagnostics.
            session_config: Optional Session config governing initialize a
                ``RedfishSessionPool`` instance.

        Raises:
            ValueError: If the authentication mode is not a supported policy or
                the existing TLS configuration is invalid.
        """
        self.dut_id = dut_id
        self.connection_info = connection_info
        self.logger = logger
        self.session = None
        self.auth = None
        self.connector = None
        self._lock = asyncio.Lock()
        self._initialized = False
        self._active_authentication_requests = 0
        self._authentication_drained = asyncio.Event()
        self._authentication_drained.set()

        self.instance_id = f"{os.getpid()}_{int(time.time() * 1000) % 10000}"
        self.session_config = session_config or {}
        # Governed runtime configuration materializes its preferred ``auto``
        # mode. Direct legacy pool callers without that model retain Basic.
        self.authentication_mode = self.session_config.get(
            "authentication_mode", "basic"
        )
        if type(
            self.authentication_mode
        ) is not str or self.authentication_mode not in {"auto", "basic", "session"}:
            raise ValueError("Invalid Redfish authentication mode")
        self.allows_basic_fallback = self.authentication_mode == "basic"
        self._authentication: Optional[RedfishSessionAuthentication] = None
        self.connection_pool_limit = self.session_config.get(
            "connection_pool_limit", 20
        )
        self.connection_pool_limit_per_host = self.session_config.get(
            "connection_pool_limit_per_host", 8
        )
        self.session_timeout = self.session_config.get("session_timeout", 300)
        self.keepalive_timeout = self.session_config.get("keepalive_timeout", 300)
        self.tls_policy = RedfishTLSPolicy.from_session_config(self.session_config)
        self.ssl_parameter = (
            self.session_config["ssl"]
            if "ssl" in self.session_config
            else self.tls_policy.build_ssl_parameter(
                use_https=self.connection_info.get("use_https", True)
            )
        )
        self.ttl_dns_cache = self.session_config.get("ttl_dns_cache", 300)
        self.use_dns_cache = self.session_config.get("use_dns_cache", True)
        self.force_close = self.session_config.get("force_close", False)
        self.enable_cleanup_closed = self.session_config.get(
            "enable_cleanup_closed", True
        )

    async def _log_runtime(self, level: str, message: str) -> None:
        """
        Log runtime.

        The implementation uses ``level`` and ``message`` to log runtime. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        if self.logger and hasattr(self.logger, "write_to_dut_runtime_log"):
            await self.logger.write_to_dut_runtime_log(
                self.dut_id, level, "RedfishSessionPool", message
            )
        elif level == "ERROR":
            logger.error("[%s] %s", self.dut_id, message)
        elif level == "WARNING":
            logger.warning("[%s] %s", self.dut_id, message)
        else:
            logger.info("[%s] %s", self.dut_id, message)

    async def initialize(self) -> bool:
        """
        Serialize session initialization and drain cleanup after interruption.

        The lifecycle lock prevents concurrent collectors from creating duplicate
        authenticated sessions. Cleanup retains ownership until every operation
        completes, even when the caller is cancelled during login.

        Returns:
            Whether the pool initialized successfully under its authentication
            policy. Ordinary setup failures retain the existing false result.

        Raises:
            BaseException: A caller interruption or incomplete cleanup, after
                all cleanup operations started by this owner have been observed.
        """

        async with self._lock:
            try:
                return await self._initialize_locked()
            except BaseException as error:
                raise await self._cleanup_failure_locked(error)

    async def _cleanup_failure_locked(self, error: BaseException) -> BaseException:
        """
        Drain failed initialization or renewal while preserving its primary error.

        Cleanup runs as owned work without cancelling a pending logout. Its
        outcome is combined with the original failure only after both are known.

        Args:
            error: Existing setup failure or caller interruption to preserve.

        Returns:
            The authoritative exception after every cleanup result is observed.

        Side Effects:
            Attempts exact-resource logout and closes owned HTTP resources while
            the caller retains the lifecycle lock.
        """

        errors = [error]
        task = asyncio.create_task(capture_owned_awaitable(self._cleanup_locked()))
        try:
            outcomes = await drain_owned_tasks((task,), cancel_on_wait_error=False)
            if outcomes[0].error is not None:
                errors.append(outcomes[0].error)
        except BaseException as cleanup_error:
            errors.append(cleanup_error)
        return authoritative_cleanup_error(errors)

    async def _initialize_locked(self) -> bool:
        """
        Initialize and verify the pooled session.

        The implementation uses current instance state to initialize and verify
        the pooled session. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. It updates
        ``_initialized``, ``auth``, ``connector``, and ``session`` on the
        instance as part of that state transition. Remote I/O uses the
        configured transport policy and returns only after its response or
        failure has been observed.

        Returns:
            Whether the initialize and verify the pooled session operation
            succeeds.

        Raises:
            BaseException: If interruption or incomplete cleanup prevents an
                ordinary false result; the caller must retain cleanup ownership.
                The initialization error remains primary unless cleanup is
                interrupted, and secondary cleanup failures remain visible.
        """

        try:
            if self._initialized:
                return True

            if (
                self.session is not None
                or self.connector is not None
                or self._authentication is not None
            ):
                await self._cleanup_locked()

            await self._log_runtime(
                "INFO",
                "Initializing high-performance Redfish session with connection pooling",
            )
            self.connector = aiohttp.TCPConnector(
                ssl=self.ssl_parameter,
                limit=self.connection_pool_limit,
                limit_per_host=self.connection_pool_limit_per_host,
                ttl_dns_cache=self.ttl_dns_cache,
                use_dns_cache=self.use_dns_cache,
                force_close=self.force_close,
                enable_cleanup_closed=self.enable_cleanup_closed,
                keepalive_timeout=None if self.force_close else self.keepalive_timeout,
            )
            session_options: Dict[str, Any] = {}
            if self.authentication_mode != "basic":
                # Cookie authentication must not mask an expired token or an
                # endpoint whose explicit credentials have been disabled.
                session_options["cookie_jar"] = aiohttp.DummyCookieJar()
            self.session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=aiohttp.ClientTimeout(total=self.session_timeout),
                auto_decompress=False,
                headers={
                    "User-Agent": f"nvdebug/1.0-instance-{self.instance_id}",
                    "Accept-Encoding": "gzip, deflate",
                },
                **session_options,
            )

            username = self.connection_info["username"]
            password = self.connection_info["password"]
            if self.connection_info.get("auth_enabled", True) and username and password:
                self.auth = encode_basic_auth_header(username, password)
            else:
                self.auth = None

            negotiate_authentication = (
                self.authentication_mode != "basic" and self.auth is not None
            )
            if negotiate_authentication and not self.connection_info["use_https"]:
                if self.authentication_mode == "session":
                    raise RedfishSessionAuthenticationError("HTTPS requirement")
                negotiate_authentication = False
            self.allows_basic_fallback = not negotiate_authentication
            root_document = None
            request_options: Dict[str, Any] = {}
            if negotiate_authentication:
                request_options["timeout"] = aiohttp.ClientTimeout(
                    total=AUTH_REQUEST_TIMEOUT_SECONDS
                )

            protocol = "https" if self.connection_info["use_https"] else "http"
            url_host = format_redfish_url_host(self.connection_info["host"])
            test_url = (
                f"{protocol}://{url_host}:"
                f"{self.connection_info['port']}"
                f"{self.connection_info['service_root']}"
            )
            async with self.session.get(
                test_url,
                allow_redirects=False,
                auto_decompress=False,
                headers=build_redfish_request_headers(
                    self.auth,
                    {"Accept-Encoding": "gzip, deflate"},
                ),
                **self.tls_policy.request_kwargs(
                    self.ssl_parameter,
                    use_https=self.connection_info.get("use_https", True),
                ),
                **request_options,
            ) as response:
                if response.status == 200:
                    if negotiate_authentication:
                        root_document = await read_authentication_document(response)
                else:
                    await self._log_runtime(
                        "ERROR", f"Redfish session test failed: HTTP {response.status}"
                    )
                    await self._cleanup_locked()
                    return False

            if root_document is not None:
                self._authentication = RedfishSessionAuthentication(
                    self.connection_info, self.auth, self.tls_policy, self.ssl_parameter
                )
                if await self._authentication.discover(self.session, root_document):
                    await self._authentication.login(self.session)
                elif self.authentication_mode == "session":
                    raise RedfishSessionAuthenticationError("required capability")
                else:
                    self._authentication = None
                    self.allows_basic_fallback = True
                    await self._log_runtime(
                        "INFO",
                        "Redfish token sessions are not advertised, enabled, or supported; "
                        "retaining Basic authentication",
                    )

            self._initialized = True
            await self._log_runtime(
                "INFO",
                "High-performance Redfish session initialized successfully "
                f"(authentication={'session' if self._authentication else 'basic' if self.auth else 'anonymous'})",
            )
            return True
        except Exception as error:
            await self._log_runtime(
                "ERROR",
                "Failed to initialize Redfish session: "
                + (
                    str(error)
                    if isinstance(error, RedfishSessionAuthenticationError)
                    else type(error).__name__
                ),
            )
            try:
                await self._cleanup_locked()
            except BaseException as cleanup_error:
                raise authoritative_cleanup_error([error, cleanup_error])
            return False

    async def get_session(self) -> Optional[Dict[str, Any]]:
        """
        Return the shared transport and a current endpoint-bound token snapshot.

        Reinitialize closed transports and serialize token renewal before request
        admission, waiting for existing token users to exit their responses. The
        existing ``auth`` field remains the credential identity
        used by the HTTP engine's rebinding checks; a token is separate and is
        accompanied by its pinned HTTPS authority.

        Returns:
            The existing ``session``, ``auth``, and ``connector`` mapping, with
            ``auth_token`` and ``auth_origin`` only when token authentication is
            active; ``None`` when initialization does not succeed.

        Raises:
            BaseException: Renewal or cleanup failure after owned cleanup drains.
        """

        if not self._initialized or (self.session and self.session.closed):
            if self.session and self.session.closed:
                self._initialized = False
            await self._log_runtime(
                "DEBUG",
                "Session not initialized or closed, reinitializing "
                f"(instance: {self.instance_id})",
            )
            if not await self.initialize():
                return None
        async with self._lock:
            if not self._initialized:
                return None
            if self._authentication is not None:
                renewal_required = self._authentication.needs_renewal()
                if renewal_required:
                    # Waiting changes no remote state. Cancellation here must not
                    # tear down the session still owned by another collector.
                    await self._authentication_drained.wait()
                try:
                    if renewal_required:
                        await self._authentication.logout(self.session)
                        await self._authentication.login(self.session)
                    self._authentication.mark_used()
                except BaseException as error:
                    self._initialized = False
                    raise await self._cleanup_failure_locked(error)
            result = {
                "session": self.session,
                "auth": self.auth,
                "connector": self.connector,
            }
            if self._authentication is not None:
                result["auth_token"] = self._authentication.token
                result["auth_origin"] = self._authentication.origin
            return result

    @contextmanager
    def use_authentication(self, observed_token: str) -> Iterator[None]:
        """
        Retain a token from request admission through response-context exit.

        Enter immediately after obtaining the pool snapshot, before yielding to
        another task. Entry and release contain no await: renewal can hold the
        lifecycle lock while waiting for all request owners to release, and
        cancellation cannot strand an outstanding user count.

        Args:
            observed_token: Exact token from this pool's request snapshot.

        Yields:
            No value; the context protects the surrounding HTTP request.

        Raises:
            RedfishSessionAuthenticationError: If the snapshot no longer belongs
                to this initialized authentication owner.

        Side Effects:
            Counts active token users and signals when renewal or cleanup may
            delete the exact owned login resource.
        """

        if (
            not self._initialized
            or self._authentication is None
            or self._authentication.token != observed_token
        ):
            raise RedfishSessionAuthenticationError("request token ownership")
        self._active_authentication_requests += 1
        self._authentication_drained.clear()
        try:
            yield
        finally:
            self._active_authentication_requests -= 1
            if self._active_authentication_requests == 0:
                self._authentication_drained.set()

    async def invalidate_authentication(self, observed_token: str) -> None:
        """
        Retire only the token rejected by a completed HTTP request.

        This operation performs no request replay or immediate transport close.
        The next pool admission owns renewal under the lifecycle lock. Comparing
        and marking the token is atomic within the event loop and must not wait
        for that lock: a renewal may already hold it while draining this request.

        Args:
            observed_token: Token snapshot that received an unauthorized response.
        """

        if self._authentication is not None:
            self._authentication.invalidate(observed_token)

    async def release_session(self, session_obj: Dict[str, Any]) -> None:
        """
        Release a shared session (intentionally a no-op).

        The implementation uses ``session_obj`` to release a shared session
        (intentionally a no-op). Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            session_obj: Mapping supplying fields for release a shared session
                (intentionally a no-op).
        """

    async def handle_session_conflict(self, error: Exception) -> bool:
        """
        Invalidate the session after an eligible conflict.

        The implementation uses ``error`` to invalidate the session after an
        eligible conflict. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. It updates
        ``_initialized`` and ``session`` on the instance as part of that state
        transition.

        Args:
            error: Exception or failure detail associated with the operation.

        Returns:
            Whether the invalidate the session after an eligible conflict
            operation succeeds.
        """

        if not self.session_config.get("handle_session_conflicts", True):
            return False
        error_text = str(error).lower()
        if not any(
            keyword in error_text
            for keyword in ("session", "closed", "unauthorized", "forbidden")
        ):
            return False

        await self._log_runtime(
            "WARNING",
            "Detected potential session conflict, reinitializing session "
            f"(instance: {self.instance_id})",
        )
        await self.cleanup()
        return True

    async def cleanup(self) -> None:
        """
        Serialize and drain logout plus HTTP cleanup before propagating cancellation.

        Failed resource handles remain attached for the existing cleanup retry
        contract. Remote logout waits for active token users and is restricted
        to this pool's created session.

        Raises:
            BaseException: The authoritative cleanup failure or caller control
                after every owned cleanup operation has completed.
        """

        async def close_under_lock() -> None:
            """
            Close this pool only after its current lifecycle operation completes.

            Side Effects:
                Acquires the lifecycle lock and attempts every owned resource.
            """

            async with self._lock:
                await self._cleanup_locked()

        task = asyncio.create_task(capture_owned_awaitable(close_under_lock()))
        outcomes = await drain_owned_tasks((task,), cancel_on_wait_error=False)
        if outcomes[0].error is not None:
            raise outcomes[0].error

    async def _cleanup_locked(self) -> None:
        """
        Close every resource owned by the pool.

        The implementation uses current instance state to close every resource
        owned by the pool. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. It updates
        ``_initialized``, ``connector``, and ``session`` on the instance as part
        of that state transition. If the function cannot close every resource
        owned by the pool, its exception reaches the caller instead of being
        converted into a successful result.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to close every resource owned by the pool.
        """

        await self._authentication_drained.wait()
        cleanup_errors: List[BaseException] = []
        if self._authentication is not None:
            try:
                if self.session is not None and not self.session.closed:
                    await self._authentication.logout(self.session)
                else:
                    # A dead HTTP session does not imply that its server-side
                    # authentication resource disappeared. The auth owner pins
                    # the old endpoint and TLS policy for this bounded cleanup.
                    async with aiohttp.ClientSession(
                        auto_decompress=False,
                        cookie_jar=aiohttp.DummyCookieJar(),
                        headers={"Accept-Encoding": "identity"},
                    ) as cleanup_session:
                        await self._authentication.logout(cleanup_session)
                self._authentication = None
            except BaseException as error:
                cleanup_errors.append(error)
        if self.session is not None:
            try:
                if not self.session.closed:
                    await self.session.close()
                self.session = None
            except BaseException as error:
                cleanup_errors.append(error)

        if self.connector is not None:
            try:
                if not self.connector.closed:
                    await self.connector.close()
                self.connector = None
            except BaseException as error:
                cleanup_errors.append(error)

        self._initialized = False
        if cleanup_errors:
            try:
                await self._log_runtime(
                    "ERROR",
                    "Redfish session cleanup did not close every owned resource",
                )
            except BaseException as logging_error:
                cleanup_errors.append(logging_error)
            raise authoritative_cleanup_error(cleanup_errors)

        await self._log_runtime("INFO", "Redfish session cleaned up")

    async def get_session_stats(self) -> Dict[str, Any]:
        """
        Return bounded, non-sensitive pool metrics.

        The implementation uses current instance state to produce bounded,
        non-sensitive pool metrics. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Returns:
            A mapping containing the ``initialized``, ``connection_limit``,
            ``connection_limit_per_host``, ``total_connections``, and
            ``active_connections`` fields.
        """

        if self.session and self.connector:
            return {
                "initialized": self._initialized,
                "connection_limit": self.connector.limit,
                "connection_limit_per_host": self.connector.limit_per_host,
                "total_connections": (
                    len(self.connector._resolver_cache)
                    if hasattr(self.connector, "_resolver_cache")
                    else 0
                ),
                "active_connections": (
                    len(self.connector._acquired)
                    if hasattr(self.connector, "_acquired")
                    else 0
                ),
            }
        return {
            "initialized": False,
            "connection_limit": 0,
            "connection_limit_per_host": 0,
            "total_connections": 0,
            "active_connections": 0,
        }


async def create_redfish_session(owner: Any) -> bool:
    """
    Create or verify a DUT's Redfish session through its facade seams.

    The implementation uses ``owner`` to create or verify a DUT's Redfish
    session through its facade seams. Owned asynchronous work is awaited before
    return, so completion does not leave an unobserved task behind. Remote I/O
    uses the configured transport policy and returns only after its response or
    failure has been observed.

    Args:
        owner: Owner object whose ``_create_fallback_session``,
            ``_log_runtime``, ``get_redfish_connection_info``, ``get_session``,
            and ``redfish_auth`` state is read while performing or verify a
            DUT's Redfish session through its facade seams.

    Returns:
        Whether the or verify a DUT's Redfish session through its facade seams
        operation succeeds.
    """

    connection_info: Optional[Dict[str, Any]] = None
    try:
        if owner.redfish_session is not None:
            return True

        await owner._log_runtime("INFO", "Testing Redfish session pool")
        connection_info = owner.get_redfish_connection_info()
        username = connection_info["username"]
        password = connection_info["password"]
        if connection_info.get("auth_enabled", True) and username and password:
            owner.redfish_auth = encode_basic_auth_header(username, password)
        else:
            owner.redfish_auth = None

        authentication_mode = getattr(owner, "redfish_session_config", {}).get(
            "authentication_mode", "basic"
        )
        if (
            owner.redfish_auth is not None
            and authentication_mode in {"auto", "session"}
            and (authentication_mode == "session" or connection_info["use_https"])
            and not owner.redfish_session_pool
        ):
            if not await owner.initialize_redfish_session_pool():
                return False

        protocol = "https" if connection_info["use_https"] else "http"
        url_host = format_redfish_url_host(connection_info["host"])
        test_url = (
            f"{protocol}://{url_host}:{connection_info['port']}"
            f"{connection_info['service_root']}"
        )
        if owner.redfish_session_pool:
            request_pool = owner.redfish_session_pool
            session_obj = await request_pool.get_session()
            if session_obj:
                with (
                    request_pool.use_authentication(session_obj["auth_token"])
                    if session_obj.get("auth_token") is not None
                    else nullcontext()
                ):
                    async with session_obj["session"].get(
                        test_url,
                        allow_redirects=False,
                        auto_decompress=False,
                        headers=build_redfish_request_headers(
                            session_obj["auth"],
                            {"Accept-Encoding": "gzip, deflate"},
                            auth_token=session_obj.get("auth_token"),
                        ),
                        **owner.redfish_tls_request_kwargs(
                            use_https=connection_info["use_https"]
                        ),
                    ) as response:
                        if response.status == 200:
                            await owner._log_runtime(
                                "INFO", "Redfish session pool test successful"
                            )
                            return True
                        if (
                            response.status == 401
                            and session_obj.get("auth_token") is not None
                        ):
                            await request_pool.invalidate_authentication(
                                session_obj["auth_token"]
                            )
                        await owner._log_runtime(
                            "ERROR",
                            f"Redfish session pool test failed: HTTP {response.status}",
                        )
                        return False

            await owner._log_runtime(
                "ERROR", "Failed to get session from pool for testing"
            )
            if (
                getattr(
                    getattr(owner, "redfish_session_pool", None),
                    "allows_basic_fallback",
                    True,
                )
                is False
            ):
                return False
            return await owner._create_fallback_session(connection_info)

        await owner._log_runtime(
            "WARNING", "Session pool not available, using fallback"
        )
        return await owner._create_fallback_session(connection_info)
    except Exception as error:
        await owner._log_runtime("ERROR", f"Failed to create Redfish session: {error}")
        if connection_info is None:
            return False
        if (
            getattr(
                getattr(owner, "redfish_session_pool", None),
                "allows_basic_fallback",
                True,
            )
            is False
        ):
            return False
        return await owner._create_fallback_session(connection_info)


async def create_fallback_redfish_session(
    owner: Any, connection_info: Dict[str, Any]
) -> bool:
    """
    Create and verify the DUT-owned non-pooled fallback session.

    The implementation uses ``owner`` and ``connection_info`` to create and
    verify the DUT-owned non-pooled fallback session. Owned asynchronous work is
    awaited before return, so completion does not leave an unobserved task
    behind. Remote I/O uses the configured transport policy and returns only
    after its response or failure has been observed.

    Args:
        owner: Owner object whose ``_log_runtime``, ``close_redfish_session``,
            ``get``, ``redfish_auth``, and ``redfish_connector`` state is read
            while performing and verify the DUT-owned non-pooled fallback
            session.
        connection_info: Mapping supplying fields for and verify the DUT-owned
            non-pooled fallback session.

    Returns:
        Whether the and verify the DUT-owned non-pooled fallback session
        operation succeeds.
    """

    try:
        if (
            getattr(
                getattr(owner, "redfish_session_pool", None),
                "allows_basic_fallback",
                True,
            )
            is False
        ):
            await owner._log_runtime(
                "ERROR", "Required Redfish session authentication is unavailable"
            )
            return False
        await owner._log_runtime("INFO", "Creating fallback Redfish session")
        owner.redfish_connector = aiohttp.TCPConnector(
            ssl=owner.redfish_ssl,
            limit=owner.redfish_fallback_connection_pool_limit,
            limit_per_host=owner.redfish_fallback_connection_pool_limit_per_host,
            ttl_dns_cache=owner.redfish_ttl_dns_cache,
            use_dns_cache=owner.redfish_use_dns_cache,
            force_close=owner.redfish_force_close,
            enable_cleanup_closed=owner.redfish_enable_cleanup_closed,
            keepalive_timeout=(
                None if owner.redfish_force_close else owner.redfish_keepalive_timeout
            ),
        )
        owner.redfish_session = aiohttp.ClientSession(
            connector=owner.redfish_connector,
            timeout=aiohttp.ClientTimeout(total=owner.redfish_session_timeout),
            auto_decompress=False,
            headers={
                "User-Agent": "nvdebug/1.0",
                "Accept-Encoding": "gzip, deflate",
            },
        )

        protocol = "https" if connection_info["use_https"] else "http"
        url_host = format_redfish_url_host(connection_info["host"])
        test_url = (
            f"{protocol}://{url_host}:{connection_info['port']}"
            f"{connection_info['service_root']}"
        )
        async with owner.redfish_session.get(
            test_url,
            allow_redirects=False,
            auto_decompress=False,
            headers=build_redfish_request_headers(
                owner.redfish_auth,
                {"Accept-Encoding": "gzip, deflate"},
            ),
            **owner.redfish_tls_request_kwargs(use_https=connection_info["use_https"]),
        ) as response:
            if response.status == 200:
                await owner._log_runtime(
                    "INFO", "Fallback Redfish session created successfully"
                )
                return True

            await owner._log_runtime(
                "ERROR",
                f"Fallback Redfish session test failed: HTTP {response.status}",
            )
            await owner.close_redfish_session()
            return False
    except Exception as error:
        await owner._log_runtime(
            "ERROR", f"Failed to create fallback Redfish session: {error}"
        )
        await owner.close_redfish_session()
        return False


async def initialize_redfish_session_pool(
    owner: Any,
    pool_factory: Callable[..., RedfishSessionPool] = RedfishSessionPool,
) -> bool:
    """
    Initialize the DUT-owned Redfish pool without changing its facade.

    Logging may yield after the initial empty-owner check. Recheck ownership
    after that yield, then publish a newly constructed pool before the next
    await so concurrent collectors cannot overwrite an independently initialized
    pool. The pool itself serializes authentication and transport initialization.
    Materialize the governed auto policy for incomplete facades without mutating
    their configuration; direct legacy pool constructors retain their own default.

    Args:
        owner: Owner object whose ``_log_runtime``, ``dut_id``,
            ``get_redfish_connection_info``, ``initialize``, and ``logger``
            state is read while performing initialize the DUT-owned Redfish pool
            without changing its facade.
        pool_factory: Callable invoked at the pool factory boundary.

    Returns:
        ``True`` when a pool is already owned or a newly created pool initializes
        successfully; ``False`` after an ordinary setup failure. Request
        admission through ``get_session`` waits for any ongoing initialization.
    """

    try:
        if owner.redfish_session_pool is not None:
            return True

        await owner._log_runtime(
            "INFO", "Initializing high-performance Redfish session pool"
        )
        if owner.redfish_session_pool is not None:
            return True
        connection_info = owner.get_redfish_connection_info()
        configured = getattr(owner, "redfish_session_config", None)
        session_config = {
            "authentication_mode": "auto",
            **(configured if isinstance(configured, dict) else {}),
        }
        owner.redfish_session_pool = pool_factory(
            owner.dut_id,
            connection_info,
            owner.logger,
            session_config,
        )
        if await owner.redfish_session_pool.initialize():
            await owner._log_runtime(
                "INFO",
                "High-performance Redfish session pool initialized successfully",
            )
            return True

        await owner._log_runtime(
            "ERROR", "Failed to initialize high-performance session pool"
        )
        return False
    except Exception as error:
        await owner._log_runtime(
            "ERROR", f"Failed to initialize Redfish session pool: {error}"
        )
        return False


async def close_redfish_session(owner: Any) -> None:
    """
    Close all Redfish resources while retaining failed handles for retry.

    Capture every handle before awaiting cleanup so another collector can install
    replacements without having them closed by this older operation. Clear each
    successfully closed handle only while it remains the owner's current handle.
    Failed cleanup retains ownership for retry and reports its authoritative
    exception after every original resource has had a close attempt.

    Args:
        owner: DUT facade holding the pool, legacy HTTP session, connector, and
            runtime logger. Only successfully closed, unchanged handles are cleared.

    Raises:
        BaseException: If closing or logging fails, including cancellation. All
            original resources still receive their close attempt before propagation.
    """

    cleanup_errors: List[BaseException] = []
    pool = owner.redfish_session_pool
    session = owner.redfish_session
    connector = owner.redfish_connector
    if pool is not None:
        try:
            await pool.cleanup()
            if owner.redfish_session_pool is pool:
                owner.redfish_session_pool = None
            await owner._log_runtime("INFO", "Redfish session pool closed")
        except BaseException as error:
            cleanup_errors.append(error)

    if session is not None:
        try:
            await session.close()
            if owner.redfish_session is session:
                owner.redfish_session = None
            await owner._log_runtime("INFO", "Redfish session closed")
        except BaseException as error:
            cleanup_errors.append(error)

    if connector is not None:
        try:
            await connector.close()
            if owner.redfish_connector is connector:
                owner.redfish_connector = None
        except BaseException as error:
            cleanup_errors.append(error)

    if cleanup_errors:
        try:
            await owner._log_runtime(
                "ERROR", "Redfish session cleanup did not close every owned resource"
            )
        except BaseException as logging_error:
            cleanup_errors.append(logging_error)
        raise authoritative_cleanup_error(cleanup_errors)


async def close_all_redfish_sessions(owner: Any) -> None:
    """
    Finalize the default controller and retained collector controller owners.

    Ordinary session replacement closes only the default controller. This
    finalization boundary snapshots the additional owners before awaiting and
    attempts each cleanup even if a sibling controller fails.

    Args:
        owner: DUT whose completed collectors may retain failed session handles.

    Raises:
        BaseException: If any controller cannot close its owned resources.
    """

    views = getattr(owner, "_collector_controller_views", set())
    retained = tuple(views)
    errors: List[BaseException] = []
    try:
        await owner.close_redfish_session()
    except BaseException as error:
        errors.append(error)
    for view in retained:
        try:
            await view.close_redfish_session()
            views.discard(view)
        except BaseException as error:
            errors.append(error)
    if errors:
        raise authoritative_cleanup_error(errors)


async def cleanup_dut_ssh_proxy_tunnels(owner: Any) -> bool:
    """
    Close one DUT's tracked proxy tunnels and verify ownership is empty.

    The implementation uses ``owner`` to close one DUT's tracked proxy tunnels
    and verify ownership is empty. Owned asynchronous work is awaited before
    return, so completion does not leave an unobserved task behind. If the
    function cannot close one DUT's tracked proxy tunnels and verify ownership
    is empty, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        owner: Owner object whose ``_get_live_ssh_proxy_tunnel_ports``,
            ``_log_runtime``, ``dut_id``, and ``ssh_proxy_tunnel_ports`` state
            is read while performing close one DUT's tracked proxy tunnels and
            verify ownership is empty.

    Returns:
        Whether the close one DUT's tracked proxy tunnels and verify ownership
        is empty operation succeeds.

    Raises:
        RuntimeError: If SSH proxy tunnel cleanup did not complete for DUT
            ``dut_id``; SSH proxy cleanup retained tracked ownership for DUT
            ``dut_id``; or SSH proxy cleanup retained a live route for DUT
            ``dut_id``.
        BaseException: If a delegated failure occurs while the function attempts
            to close one DUT's tracked proxy tunnels and verify ownership is
            empty.
    """

    await owner._log_runtime(
        "DEBUG", f"cleanup_ssh_proxy_tunnels called for DUT {owner.dut_id}"
    )
    proxy_service = getattr(owner, "ssh_proxy_service", None)
    if not proxy_service:
        await owner._log_runtime(
            "DEBUG",
            f"No SSH proxy service found for DUT {owner.dut_id} - nothing to cleanup",
        )
        owner.ssh_proxy_tunnel_ports = {}
        return True

    try:
        await owner._log_runtime(
            "INFO", f"Cleaning up SSH proxy tunnels for DUT {owner.dut_id}"
        )
        success = await proxy_service.cleanup_tunnels(owner.dut_id)
        if success is not True:
            await owner._log_runtime(
                "ERROR",
                f"SSH proxy tunnel cleanup returned False for DUT {owner.dut_id}",
            )
            raise RuntimeError(
                f"SSH proxy tunnel cleanup did not complete for DUT {owner.dut_id}"
            )

        has_tracked_tunnels = getattr(proxy_service, "has_tracked_tunnels", None)
        if (
            not callable(has_tracked_tunnels)
            or has_tracked_tunnels(owner.dut_id) is not False
        ):
            raise RuntimeError(
                f"SSH proxy cleanup retained tracked ownership for DUT {owner.dut_id}"
            )
        if owner._get_live_ssh_proxy_tunnel_ports(strict=True):
            raise RuntimeError(
                f"SSH proxy cleanup retained a live route for DUT {owner.dut_id}"
            )
        await owner._log_runtime(
            "INFO",
            f"SSH proxy tunnels cleaned up successfully for DUT {owner.dut_id}",
        )
    except BaseException as error:
        try:
            await owner._log_runtime(
                "ERROR",
                "Failed to cleanup SSH proxy tunnels for DUT "
                f"{owner.dut_id}: {type(error).__name__}",
            )
        except BaseException as logging_error:
            raise authoritative_cleanup_error([error, logging_error])
        raise
    return True


class DUTSessionRegistry:
    """
    Own manager-wide SSH routes, proxies, retries, and HMC recovery locks.

    ``DUTManager`` historically exposed the backing dictionaries. ``bind``
    adopts replacements of those dictionaries so lightweight ``__new__`` test
    doubles and extensions retain the same seams while lifecycle code has one
    explicit owner.
    """

    def __init__(self) -> None:
        """
        Initialize a ``DUTSessionRegistry`` instance.

        The initializer records ``hmc_redfish_recovery_locks``,
        ``orphaned_ssh_connections``, ``owned_proxy_connections``,
        ``ssh_connection_locks``, and ``ssh_connections`` for later operations
        and establishes the instance invariants before any public method runs.
        """
        self.ssh_connections: Dict[Any, asyncssh.SSHClientConnection] = {}
        self.ssh_connection_locks: Dict[Any, asyncio.Lock] = {}
        self.owned_proxy_connections: Dict[int, asyncssh.SSHClientConnection] = {}
        self.orphaned_ssh_connections: Dict[int, asyncssh.SSHClientConnection] = {}
        self.hmc_redfish_recovery_locks: Dict[str, asyncio.Lock] = {}

    def bind(self, owner: Any) -> "DUTSessionRegistry":
        """
        Adopt facade state and expose registry-owned dictionaries.

        The implementation uses ``owner`` to adopt facade state and expose
        registry-owned dictionaries. It updates ``hmc_redfish_recovery_locks``,
        ``orphaned_ssh_connections``, ``owned_proxy_connections``,
        ``ssh_connection_locks``, and ``ssh_connections`` on the instance as
        part of that state transition.

        Args:
            owner: Owner object whose ``_hmc_redfish_recovery_locks``,
                ``_orphaned_ssh_connections``, ``_owned_proxy_connections``,
                ``ssh_connection_locks``, and ``ssh_connections`` state is read
                while performing adopt facade state and expose registry-owned
                dictionaries.

        Returns:
            The validated ``self``.
        """

        facade_connections = getattr(owner, "ssh_connections", None)
        if (
            facade_connections is not None
            and facade_connections is not self.ssh_connections
        ):
            self.ssh_connections = facade_connections
        owner.ssh_connections = self.ssh_connections

        facade_locks = getattr(owner, "ssh_connection_locks", None)
        if facade_locks is not None and facade_locks is not self.ssh_connection_locks:
            self.ssh_connection_locks = facade_locks
        owner.ssh_connection_locks = self.ssh_connection_locks

        facade_proxies = getattr(owner, "_owned_proxy_connections", None)
        if (
            facade_proxies is not None
            and facade_proxies is not self.owned_proxy_connections
        ):
            self.owned_proxy_connections = facade_proxies
        owner._owned_proxy_connections = self.owned_proxy_connections

        facade_orphans = getattr(owner, "_orphaned_ssh_connections", None)
        if (
            facade_orphans is not None
            and facade_orphans is not self.orphaned_ssh_connections
        ):
            self.orphaned_ssh_connections = facade_orphans
        owner._orphaned_ssh_connections = self.orphaned_ssh_connections

        facade_hmc_locks = getattr(owner, "_hmc_redfish_recovery_locks", None)
        if (
            facade_hmc_locks is not None
            and facade_hmc_locks is not self.hmc_redfish_recovery_locks
        ):
            self.hmc_redfish_recovery_locks = facade_hmc_locks
        owner._hmc_redfish_recovery_locks = self.hmc_redfish_recovery_locks
        return self

    def hmc_recovery_lock(self, dut_id: str) -> asyncio.Lock:
        """
        Return the single recovery lock for one forwarded HMC endpoint.

        After applying local validation, the function forwards ``dut_id`` to
        ``self.hmc_redfish_recovery_locks.setdefault`` and preserves its return
        and exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A ``Lock`` representing HMC recovery lock.
        """

        return self.hmc_redfish_recovery_locks.setdefault(dut_id, asyncio.Lock())

    @staticmethod
    def connection_cache_key(
        *,
        dut_id: str,
        hmc: bool,
        host: str,
        port: int,
        username: Optional[str],
        proxy_host: Optional[str],
        proxy_port: Optional[int],
        proxy_username: Optional[str],
        host_key_policy: str,
        known_hosts_file: Optional[str],
        ssh_key_path: Optional[str] = None,
        passwordless: bool = False,
        proxy_key_path: Optional[str] = None,
        proxy_passwordless: bool = False,
        credential_generation: Optional[Any] = None,
    ) -> Tuple[Any, ...]:
        """
        Return a secret-free identity for one pooled SSH route.

        The key spans every input that decides which transport a cached route
        actually represents: the endpoint, the proxy chain, the host-key trust
        settings, the selected authentication method, and an opaque per-run
        token standing in for the authentication material. A change to any of
        them yields a different key, so the stale-route retirement performed by
        ``get_ssh_connection`` closes and rebuilds the transport instead of
        handing back a session established under superseded inputs.

        The secret-free guarantee is preserved by derivation rather than by
        omission. Passwords and passphrases are never placed in the tuple.
        Callers pass ``credential_generation`` as the non-exporting
        ``CredentialGenerationFingerprint`` produced by
        ``HostSSHConnectionPool.credential_generation_fingerprint``, whose HMAC
        key is owned by the run, never exported, and zeroised at pool shutdown.

        The five trailing parameters are keyword-only and default to the values
        that were implicit before they existed, so callers and test doubles
        written against the narrower signature keep producing the historical
        identity in the leading elements.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.
            host: Text supplied as host in the format accepted by this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            username: Text supplied as username in the format accepted by this
                function.
            proxy_host: Text supplied as proxy host in the format accepted by
                this function.
            proxy_port: Numeric proxy port used while the operation performs
                bounded accounting.
            proxy_username: Text supplied as proxy username in the format
                accepted by this function.
            host_key_policy: Host key policy governing secret-free identity for
                one pooled SSH route.
            known_hosts_file: filesystem location used as the known hosts file
                for this operation.
            ssh_key_path: Filesystem location of the endpoint private key
                selected for this route, or ``None`` when key authentication is
                not configured. Only the location participates in the identity;
                the key material never does.
            passwordless: Whether the endpoint is contacted without an
                interactive secret, which separates an agent or host-configured
                login from a password login to the same account.
            proxy_key_path: Filesystem location of the proxy private key, or
                ``None`` when no proxy is configured or the proxy does not use
                key authentication.
            proxy_passwordless: Whether the proxy hop is contacted without an
                interactive secret.
            credential_generation: Opaque, non-exporting token separating one
                generation of authentication material from another, or ``None``
                when the caller has no pool-scoped token to supply. The value is
                embedded unchanged so that equality and hashing use the token's
                own constant-time protocol.

        Returns:
            A tuple whose leading ten elements are the historical route
            identity in order: DUT identifier, ``"hmc"`` or ``"bmc"`` transport
            kind, host, port, username, proxy host, proxy port, proxy username,
            host key policy, and known-hosts file. The five appended elements
            are the normalized endpoint key path, the endpoint passwordless
            flag, the normalized proxy key path, the proxy passwordless flag,
            and the credential-generation token. Optional text fields normalize
            to ``None`` when absent, and elements ``[0:2]`` remain the coarse
            identity read by ``connection_key_matches``, ``connection_label``,
            and ``_lock_key_for_connection_key``.
        """

        return (
            str(dut_id),
            "hmc" if hmc else "bmc",
            str(host or ""),
            int(port),
            str(username or ""),
            str(proxy_host) if proxy_host is not None else None,
            int(proxy_port) if proxy_port is not None else None,
            str(proxy_username) if proxy_username is not None else None,
            str(host_key_policy or "strict"),
            str(known_hosts_file) if known_hosts_file is not None else None,
            str(ssh_key_path) if ssh_key_path is not None else None,
            bool(passwordless),
            str(proxy_key_path) if proxy_key_path is not None else None,
            bool(proxy_passwordless),
            credential_generation,
        )

    @staticmethod
    def connection_key_matches(connection_key: Any, dut_id: str, hmc: bool) -> bool:
        """
        Match route-aware and legacy connection keys during cleanup.

        The implementation uses ``connection_key``, ``dut_id``, and ``hmc`` to
        match route-aware and legacy connection keys during cleanup.

        Args:
            connection_key: Stable connection key used for lookup and
                operator-facing diagnostics.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.

        Returns:
            Whether the match route-aware and legacy connection keys during
            cleanup operation succeeds.
        """

        connection_kind = "hmc" if hmc else "bmc"
        if isinstance(connection_key, tuple):
            return connection_key[:2] == (str(dut_id), connection_kind)
        return connection_key == f"{dut_id}_{connection_kind}"

    @staticmethod
    def connection_label(connection_key: Any) -> str:
        """
        Return a non-sensitive lifecycle label for an SSH route.

        The implementation uses ``connection_key`` to produce a non-sensitive
        lifecycle label for an SSH route.

        Args:
            connection_key: Stable connection key used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical connection label.
        """

        if isinstance(connection_key, tuple) and len(connection_key) >= 2:
            return f"{connection_key[0]}_{connection_key[1]}"
        return str(connection_key)

    @staticmethod
    def _lock_key_for_connection_key(connection_key: Any) -> Any:
        """
        Project one route key onto the coarser cache-lock namespace.

        Route keys carry the full mutable transport identity, while cache locks
        are registered under the deliberately coarse two-field namespace
        produced by ``DUTManager._ssh_connection_lock_key``: the DUT identifier
        and the ``"hmc"``/``"bmc"`` transport kind. That coarseness is
        intentional and must not be widened. One stable guard per DUT transport
        is what serializes retirement of a superseded route against creation of
        its replacement; a lock keyed by the endpoint, proxy, trust, or
        credential fields would admit two coroutines into the connect, close,
        and publish sequence for the same transport at once, and would let the
        per-run route ceiling be bypassed by rewriting a mutable field.

        Projecting is therefore the only correct way for a route-keyed caller to
        address the lock registry. Removal sites that pass an unprojected route
        key silently no-op, leaving the lock population permanently growing and
        the ceiling measured against entries no live route owns.

        Args:
            connection_key: Route identity to project. A tuple of at least two
                elements contributes its first two elements. The legacy
                ``f"{dut_id}_{kind}"`` string that ``connection_key_matches``
                still accepts is already a lock-namespace value and is returned
                unchanged, as is any shorter tuple, so mixed-vintage registries
                stay addressable.

        Returns:
            The lock-namespace key for ``connection_key``: a two-element tuple
            for route tuples, or the original value for legacy and
            already-projected keys. The result is idempotent, so projecting a
            lock key again returns an equal value.
        """

        if isinstance(connection_key, tuple) and len(connection_key) >= 2:
            return (connection_key[0], connection_key[1])
        return connection_key

    def _release_connection_lock(self, connection_key: Any) -> bool:
        """
        Drop the cache lock for one route unless a coroutine still holds it.

        The caller supplies a route key, which is projected onto the lock
        namespace before the registry is touched, so the entry that
        ``get_ssh_connection`` created is the entry that is removed and the
        bounded lock population actually shrinks as routes close.

        A lock that is currently held is retained. Dropping it would let the
        next caller install a fresh ``asyncio.Lock`` under the same key and
        enter the credentialed connect, close, and publish sequence alongside
        the coroutine still inside the old guard. Retention is safe for
        finalization: the connection itself is closed by the caller
        independently of this call, and the retained entry is reconsidered by
        the teardown sweep in ``close_all_ssh_connections``. A lock object that
        does not expose a callable ``locked`` is treated as held for the same
        reason, so an unexpected registry value can never widen the race.

        Args:
            connection_key: Route or lock key naming the guard to release.
                Legacy string keys are accepted unchanged.

        Returns:
            ``True`` when an entry was removed, and ``False`` when no entry
            existed or the lock was retained because it is held.
        """

        lock_key = self._lock_key_for_connection_key(connection_key)
        lock = self.ssh_connection_locks.get(lock_key)
        if lock is None:
            return False
        locked = getattr(lock, "locked", None)
        if not callable(locked) or locked():
            return False
        return self.ssh_connection_locks.pop(lock_key, None) is not None

    @staticmethod
    def has_ssh_auth_method(
        password: Optional[str],
        ssh_key_path: Optional[str],
        passwordless: bool,
    ) -> bool:
        """
        Return whether ``password`` has SSH auth method.

        After applying local validation, the function forwards ``password``,
        ``ssh_key_path``, and ``passwordless`` to ``bool`` and preserves its
        return and exception contract.

        Args:
            password: Sensitive value supplied through the approved input
                boundary and never logged.
            ssh_key_path: filesystem location used as the SSH key path for this
                operation.
            passwordless: Sensitive value supplied through the approved input
                boundary and never logged.

        Returns:
            Whether ``password`` has SSH auth method.
        """
        return bool(ssh_key_path or passwordless or password)

    @staticmethod
    def build_ssh_connect_kwargs(
        host: str,
        port: int,
        username: Optional[str],
        password: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
        passwordless: bool = False,
        connect_timeout: float = 30.0,
        keepalive_interval: Optional[int] = None,
        proxy_client: Optional[asyncssh.SSHClientConnection] = None,
        host_key_policy: str = "insecure",
        known_hosts_file: Optional[str] = None,
        host_key_alias: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build AsyncSSH kwargs with the established auth/trust precedence.

        The implementation uses ``host``, ``port``, ``username``, ``password``,
        and ``ssh_key_path`` to build AsyncSSH kwargs with the established
        auth/trust precedence. If the function cannot build AsyncSSH kwargs with
        the established auth/trust precedence, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            host: Text supplied as host in the format accepted by this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            username: Text supplied as username in the format accepted by this
                function.
            password: Sensitive value supplied through the approved input
                boundary and never logged.
            ssh_key_path: Optional filesystem location used as the SSH key path
                for this operation.
            passwordless: Sensitive value supplied through the approved input
                boundary and never logged.
            connect_timeout: Maximum duration in seconds allowed for connect
                timeout.
            keepalive_interval: Seconds between SSH liveness probes; ``None``
                selects 60 seconds and zero disables probes. Three unanswered
                probes are tolerated before the connection is closed.
            proxy_client: Optional proxy client; ``None`` selects the function's
                default behavior.
            host_key_policy: Host key policy governing asyncSSH kwargs with the
                established auth/trust precedence.
            known_hosts_file: Optional filesystem location used as the known
                hosts file for this operation.
            host_key_alias: Optional host key alias; ``None`` selects the
                function's default behavior.

        Returns:
            The validated ``connect_kwargs``.

        Raises:
            ValueError: If SSH host not configured; SSH username not configured;
                or SSH password, key path, or passwordless auth required.
        """

        if not host:
            raise ValueError("SSH host not configured")
        if not username:
            raise ValueError("SSH username not configured")
        if not DUTSessionRegistry.has_ssh_auth_method(
            password, ssh_key_path, passwordless
        ):
            raise ValueError("SSH password, key path, or passwordless auth required")

        connect_kwargs: Dict[str, Any] = {
            "host": host,
            "port": port,
            "username": username,
            "connect_timeout": connect_timeout,
            "keepalive_interval": (
                60 if keepalive_interval is None else keepalive_interval
            ),
            "keepalive_count_max": 3,
        }
        if proxy_client is not None:
            host_key_alias = canonical_asyncssh_host_key_alias(host)
        connect_kwargs.update(
            asyncssh_host_key_options(
                host_key_policy,
                known_hosts_file,
                host_key_alias=host_key_alias,
            )
        )
        if proxy_client:
            connect_kwargs["tunnel"] = proxy_client
        if ssh_key_path:
            connect_kwargs["client_keys"] = [ssh_key_path]
            if password:
                connect_kwargs["passphrase"] = password
        elif not passwordless:
            connect_kwargs["password"] = password
        return connect_kwargs

    async def get_ssh_connection(
        self, owner: Any, dut_id: str, hmc: bool = False
    ) -> Optional[asyncssh.SSHClientConnection]:
        """
        Get or create one persistent, route-keyed BMC/HMC connection.

        The implementation uses ``owner``, ``dut_id``, and ``hmc`` to get or
        create one persistent, route-keyed BMC/HMC connection. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. If the function cannot get or create one
        persistent, route-keyed BMC/HMC connection, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            owner: Owner object whose ``_build_ssh_connect_kwargs``,
                ``_close_ssh_connection_chain``,
                ``_close_ssh_connection_chain_after_failure``,
                ``_connect_raw_ssh_bounded``, ``_get_host_ssh_pool``,
                ``_ssh_connection_cache_limit``, and
                ``_ssh_connection_lock_key`` state is read while performing get
                or create one persistent, route-keyed BMC/HMC connection. The
                run-owned host SSH pool supplies the credential-generation
                token that partitions routes across a credential change.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.

        Returns:
            The established ``SSHClientConnection`` used for SSH connection, or
            ``None`` when the requested value is unavailable.

        Raises:
            ConnectionError: If failed to establish strict SSH proxy connection.
            RuntimeError: If BMC/HMC SSH connection cache limit reached.
        """

        self.bind(owner)
        connection_label = f"{dut_id}_{'hmc' if hmc else 'bmc'}"
        try:
            dut = owner.get_dut(dut_id)
            if hmc:
                if catalog_transport_support(dut.config, "hmc") is False:
                    await owner.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Skipping HMC SSH connection for {dut_id}: "
                        "baseboard catalog declares supports_hmc=false",
                    )
                    return None
                host = dut.credentials.hmc_ip
                port = dut.credentials.hmc_ssh_port
                username = (
                    dut.credentials.hmc_ssh_username or dut.credentials.hmc_username
                )
                password = (
                    dut.credentials.hmc_ssh_password or dut.credentials.hmc_password
                )
                ssh_key_path = dut.credentials.hmc_ssh_key_path
                passwordless = dut.credentials.hmc_ssh_passwordless
            else:
                host = dut.credentials.bmc_ip
                port = dut.credentials.bmc_ssh_port
                username = (
                    dut.credentials.bmc_ssh_username or dut.credentials.bmc_username
                )
                password = (
                    dut.credentials.bmc_ssh_password or dut.credentials.bmc_password
                )
                ssh_key_path = dut.credentials.bmc_ssh_key_path
                passwordless = dut.credentials.bmc_ssh_passwordless

            proxy_host = None if hmc else dut.credentials.ssh_proxy_host
            # Optional proxy authentication fields are read defensively: an
            # absent attribute means "not configured" and must read the same as
            # an unset one. Route identity is never allowed to fail resolution
            # over an optional field, because that would disable pooling for the
            # DUT instead of merely re-partitioning it.
            proxy_password = (
                getattr(dut.credentials, "ssh_proxy_password", None)
                if proxy_host is not None
                else None
            )
            # The fingerprint is an opaque per-run HMAC token, so a credential
            # rotation changes the route key without any secret entering it.
            # A retired pool key raises HostSSHPoolShutdown, which the handler
            # below turns into a recorded transport failure rather than reuse
            # of a route this run can no longer identify.
            host_ssh_pool = owner._get_host_ssh_pool()
            credential_generation = host_ssh_pool.credential_generation_fingerprint(
                password, proxy_password
            )
            connection_key = self.connection_cache_key(
                dut_id=dut_id,
                hmc=hmc,
                host=host,
                port=port,
                username=username,
                proxy_host=proxy_host,
                proxy_port=(
                    dut.credentials.ssh_proxy_port if proxy_host is not None else None
                ),
                proxy_username=(
                    dut.credentials.ssh_proxy_username
                    if proxy_host is not None
                    else None
                ),
                host_key_policy=dut.credentials.ssh_host_key_policy,
                known_hosts_file=dut.credentials.ssh_known_hosts_file,
                ssh_key_path=ssh_key_path,
                passwordless=passwordless,
                proxy_key_path=(
                    getattr(dut.credentials, "ssh_proxy_key_path", None)
                    if proxy_host is not None
                    else None
                ),
                proxy_passwordless=(
                    bool(getattr(dut.credentials, "ssh_proxy_passwordless", False))
                    if proxy_host is not None
                    else False
                ),
                credential_generation=credential_generation,
            )
        except Exception as error:
            await owner.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                f"Failed to resolve SSH connection route for {connection_label}: {error}",
            )
            return None

        # Mutable endpoint and proxy values are part of the cache identity, but
        # not the lock identity.  A stable per-DUT/transport lock bounds the
        # registry and serializes retirement of a superseded route.
        connection_lock_key = owner._ssh_connection_lock_key(dut_id, hmc)
        if connection_lock_key not in self.ssh_connection_locks:
            if len(self.ssh_connection_locks) >= owner._ssh_connection_cache_limit():
                await owner.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    "BMC/HMC SSH cache route limit reached",
                )
                return None
            self.ssh_connection_locks[connection_lock_key] = asyncio.Lock()
        lock = self.ssh_connection_locks[connection_lock_key]
        async with lock:
            stale_connection_keys = [
                key
                for key in list(self.ssh_connections)
                if key != connection_key
                and owner._ssh_connection_key_matches(key, dut_id, hmc)
            ]
            for stale_connection_key in stale_connection_keys:
                stale_conn = self.ssh_connections.pop(stale_connection_key)
                try:
                    await owner._close_ssh_connection_chain(stale_conn)
                except BaseException as error:
                    if not isinstance(error, Exception):
                        raise
                    await owner.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DUTManager",
                        "Failed to retire prior BMC/HMC SSH cache route: "
                        f"{type(error).__name__}",
                    )
                    return None

            if connection_key in self.ssh_connections:
                conn = self.ssh_connections[connection_key]
                try:
                    await asyncio.wait_for(conn.run("echo test"), timeout=5)
                    return conn
                except Exception:
                    await owner.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"SSH connection {connection_label} is dead, removing",
                    )
                    self.ssh_connections.pop(connection_key, None)
                    await owner._close_ssh_connection_chain(conn)

            proxy_client = None
            conn = None
            try:
                if not hmc and dut.credentials.ssh_proxy_host:
                    proxy_client = await owner.create_proxy_connection(dut_id)
                    if proxy_client is None:
                        raise ConnectionError(
                            "Failed to establish strict SSH proxy connection"
                        )
                connect_kwargs = owner._build_ssh_connect_kwargs(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    ssh_key_path=ssh_key_path,
                    passwordless=passwordless,
                    connect_timeout=30,
                    keepalive_interval=None,
                    proxy_client=proxy_client,
                    host_key_policy=dut.credentials.ssh_host_key_policy,
                    known_hosts_file=dut.credentials.ssh_known_hosts_file,
                )
                if (
                    connection_key not in self.ssh_connections
                    and len(self.ssh_connections) >= owner._ssh_connection_cache_limit()
                ):
                    raise RuntimeError("BMC/HMC SSH connection cache limit reached")
                conn = await owner._connect_raw_ssh_bounded(
                    capacity_scope=str(dut_id),
                    role="endpoint",
                    connect_kwargs=connect_kwargs,
                )
                if proxy_client is not None:
                    self.owned_proxy_connections[id(conn)] = proxy_client
                self.ssh_connections[connection_key] = conn
                await owner.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    f"Created new SSH connection for {connection_label}",
                )
                return conn
            except BaseException as error:
                await owner._close_ssh_connection_chain_after_failure(
                    error, conn, proxy_client
                )
                if not isinstance(error, Exception):
                    raise
                await owner.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"Failed to create SSH connection for {connection_label}: {error}",
                )
                return None

    async def close_connection_chain(
        self,
        owner: Any,
        conn: Optional[asyncssh.SSHClientConnection],
        proxy_client: Optional[asyncssh.SSHClientConnection],
        close_bounded: Callable[..., Any],
    ) -> None:
        """
        Close an endpoint and its exact owned jump connection.

        The implementation uses ``owner``, ``conn``, ``proxy_client``, and
        ``close_bounded`` to close an endpoint and its exact owned jump
        connection. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. If the function
        cannot close an endpoint and its exact owned jump connection, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            owner: Owner object whose ``_release_raw_ssh_connection_capacity``
                state is read while performing close an endpoint and its exact
                owned jump connection.
            conn: Connection consumed while the function attempts to close an
                endpoint and its exact owned jump connection.
            proxy_client: Proxy client consumed while the function attempts to
                close an endpoint and its exact owned jump connection.
            close_bounded: Close bounded consumed while the function attempts to
                close an endpoint and its exact owned jump connection.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to close an endpoint and its exact owned jump
                connection.
        """

        self.bind(owner)
        ownership_key: Optional[int] = None
        if conn is not None:
            ownership_key = id(conn)
            self.orphaned_ssh_connections.setdefault(ownership_key, conn)
            owned_proxy = self.owned_proxy_connections.get(ownership_key)
            if proxy_client is None:
                proxy_client = owned_proxy
            elif owned_proxy is None:
                self.owned_proxy_connections[ownership_key] = proxy_client
        elif proxy_client is not None:
            ownership_key = id(proxy_client)
            self.owned_proxy_connections.setdefault(ownership_key, proxy_client)

        cleanup_errors: List[BaseException] = []
        if conn is not None:
            try:
                await close_bounded(conn)
            except BaseException as error:
                cleanup_errors.append(error)
            else:
                self.orphaned_ssh_connections.pop(id(conn), None)
                owner._release_raw_ssh_connection_capacity(conn)

        if proxy_client is not None and proxy_client is not conn:
            try:
                await close_bounded(proxy_client)
            except BaseException as error:
                cleanup_errors.append(error)
            else:
                owner._release_raw_ssh_connection_capacity(proxy_client)
                if ownership_key is not None:
                    self.owned_proxy_connections.pop(ownership_key, None)
        elif proxy_client is conn and ownership_key is not None and not cleanup_errors:
            owner._release_raw_ssh_connection_capacity(proxy_client)
            self.owned_proxy_connections.pop(ownership_key, None)

        if cleanup_errors:
            raise authoritative_cleanup_error(cleanup_errors)
        if ownership_key is not None:
            self.owned_proxy_connections.pop(ownership_key, None)

    async def close_connection_chain_after_failure(
        self,
        owner: Any,
        primary_error: BaseException,
        conn: Optional[asyncssh.SSHClientConnection],
        proxy_client: Optional[asyncssh.SSHClientConnection],
    ) -> None:
        """
        Retain cleanup failures without replacing ordinary operation errors.

        The implementation uses ``owner``, ``primary_error``, ``conn``, and
        ``proxy_client`` to retain cleanup failures without replacing ordinary
        operation errors. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. If the function
        cannot retain cleanup failures without replacing ordinary operation
        errors, its exception reaches the caller instead of being converted into
        a successful result.

        Args:
            owner: Owner object whose ``_close_ssh_connection_chain`` state is
                read while performing retain cleanup failures without replacing
                ordinary operation errors.
            primary_error: Primary error consumed while the function attempts to
                retain cleanup failures without replacing ordinary operation
                errors.
            conn: Connection consumed while the function attempts to retain
                cleanup failures without replacing ordinary operation errors.
            proxy_client: Proxy client consumed while the function attempts to
                retain cleanup failures without replacing ordinary operation
                errors.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to retain cleanup failures without replacing ordinary
                operation errors.
        """

        try:
            await owner._close_ssh_connection_chain(conn, proxy_client)
        except BaseException as cleanup_error:
            authoritative = authoritative_cleanup_error([primary_error, cleanup_error])
            if isinstance(
                authoritative,
                (asyncio.CancelledError, KeyboardInterrupt, SystemExit),
            ):
                raise authoritative

    async def close_ssh_connection(
        self, owner: Any, dut_id: str, hmc: bool = False
    ) -> None:
        """
        Close every cached route matching one DUT transport.

        The implementation uses ``owner``, ``dut_id``, and ``hmc`` to close
        every cached route matching one DUT transport. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind. If the function cannot close every cached route matching
        one DUT transport, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            owner: Owner object whose ``_close_ssh_connection_chain``,
                ``_ssh_connection_key_matches``, ``_ssh_connection_label``,
                ``logger``, and ``write_to_dut_runtime_log`` state is read while
                performing close every cached route matching one DUT transport.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to close every cached route matching one DUT transport.
        """

        self.bind(owner)
        connection_keys = [
            key
            for key in list(self.ssh_connections)
            if owner._ssh_connection_key_matches(key, dut_id, hmc)
        ]
        cleanup_errors: List[BaseException] = []
        for connection_key in connection_keys:
            conn = self.ssh_connections.get(connection_key)
            if conn is None:
                self._release_connection_lock(connection_key)
                continue
            try:
                await owner._close_ssh_connection_chain(conn)
                self.ssh_connections.pop(connection_key, None)
                self._release_connection_lock(connection_key)
                await owner.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    f"Closed SSH connection for {owner._ssh_connection_label(connection_key)}",
                )
            except BaseException as error:
                cleanup_errors.append(error)
                if id(conn) not in self.orphaned_ssh_connections:
                    self.ssh_connections.pop(connection_key, None)
                    self._release_connection_lock(connection_key)
                try:
                    await owner.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DUTManager",
                        "Error closing SSH connection for "
                        f"{owner._ssh_connection_label(connection_key)}: "
                        f"{type(error).__name__}",
                    )
                except BaseException as logging_error:
                    cleanup_errors.append(logging_error)
        if cleanup_errors:
            raise authoritative_cleanup_error(cleanup_errors)

    async def close_all_ssh_connections(self, owner: Any) -> None:
        """
        Drain host pool, BMC/HMC routes, orphans, and exact proxy owners.

        The implementation uses ``owner`` to drain host pool, BMC/HMC routes,
        orphans, and exact proxy owners. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        If the function cannot drain host pool, BMC/HMC routes, orphans, and
        exact proxy owners, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            owner: Owner object whose ``_close_ssh_connection_bounded_facade``,
                ``_close_ssh_connection_chain``, ``_ssh_connection_label``,
                ``log_runtime``, and ``logger`` state is read while performing
                drain host pool, BMC/HMC routes, orphans, and exact proxy
                owners.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to drain host pool, BMC/HMC routes, orphans, and exact
                proxy owners.
        """

        self.bind(owner)
        cleanup_errors: List[BaseException] = []
        host_pool = getattr(owner, "_host_ssh_pool", None)
        pool_cleanup_ownership_ids: set[int] = set()
        if host_pool is not None:
            metrics = host_pool.claim_metrics_summary()
            if metrics is not None:
                try:
                    await owner.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        "Host SSH pool teardown snapshot: "
                        f"normalized_endpoints={metrics['normalized_endpoints']} "
                        f"active_sessions={metrics['active_sessions']} "
                        f"active_channels={metrics['active_channels']} "
                        f"queued_commands={metrics['queued_commands']} "
                        f"connections_created={metrics['connections_created']} "
                        f"connection_reuses={metrics['connection_reuses']} "
                        f"commands_started={metrics['commands_started']} "
                        f"command_failures={metrics['command_failures']} "
                        f"backpressure_waits={metrics['backpressure_waits']} "
                        f"backpressure_timeouts={metrics['backpressure_timeouts']} "
                        f"peak_active_sessions={metrics['peak_active_sessions']} "
                        f"peak_active_channels={metrics['peak_active_channels']} "
                        f"peak_queued_commands={metrics['peak_queued_commands']}",
                    )
                except BaseException as error:
                    cleanup_errors.append(error)
            try:
                await host_pool.close()
            except BaseException as error:
                cleanup_errors.append(error)
            pool_cleanup_ownership_ids = host_pool.cleanup_ownership_ids()

        for connection_key in list(self.ssh_connections):
            conn = self.ssh_connections.get(connection_key)
            if conn is None:
                self._release_connection_lock(connection_key)
                continue
            try:
                await owner._close_ssh_connection_chain(conn)
                self.ssh_connections.pop(connection_key, None)
                self._release_connection_lock(connection_key)
                await owner.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Closed SSH connection for {owner._ssh_connection_label(connection_key)}",
                )
            except BaseException as error:
                cleanup_errors.append(error)
                if id(conn) not in self.orphaned_ssh_connections:
                    self.ssh_connections.pop(connection_key, None)
                    self._release_connection_lock(connection_key)
                try:
                    await owner.logger.log_runtime(
                        "ERROR",
                        "DUTManager",
                        "Error closing SSH connection for "
                        f"{owner._ssh_connection_label(connection_key)}: "
                        f"{type(error).__name__}",
                    )
                except BaseException as logging_error:
                    cleanup_errors.append(logging_error)

        active_connection_ids = {id(conn) for conn in self.ssh_connections.values()}
        for owner_id, conn in list(self.orphaned_ssh_connections.items()):
            if (
                owner_id in active_connection_ids
                or owner_id in pool_cleanup_ownership_ids
            ):
                continue
            try:
                await owner._close_ssh_connection_chain(conn)
            except BaseException as error:
                cleanup_errors.append(error)

        raw_leases = getattr(owner, "_raw_ssh_connection_leases", {})
        for owner_id, lease in list(raw_leases.items()):
            conn = lease[0]
            if (
                owner_id in active_connection_ids
                or owner_id in self.orphaned_ssh_connections
            ):
                continue
            try:
                await owner._close_ssh_connection_chain(conn)
            except BaseException as error:
                cleanup_errors.append(error)

        active_connection_ids = {id(conn) for conn in self.ssh_connections.values()}
        orphaned_proxies: Dict[int, Tuple[Any, List[int]]] = {}
        for owner_id, proxy in list(self.owned_proxy_connections.items()):
            if (
                owner_id in active_connection_ids
                or owner_id in pool_cleanup_ownership_ids
                or proxy is None
            ):
                continue
            _, owner_ids = orphaned_proxies.setdefault(id(proxy), (proxy, []))
            owner_ids.append(owner_id)

        for proxy, owner_ids in orphaned_proxies.values():
            try:
                await owner._close_ssh_connection_bounded_facade(proxy)
            except BaseException as error:
                cleanup_errors.append(error)
            else:
                for owner_id in owner_ids:
                    if self.owned_proxy_connections.get(owner_id) is proxy:
                        self.owned_proxy_connections.pop(owner_id, None)

        live_lock_keys = {
            self._lock_key_for_connection_key(connection_key)
            for connection_key in list(self.ssh_connections)
        }
        for lock_key in list(self.ssh_connection_locks):
            if lock_key in live_lock_keys:
                continue
            self._release_connection_lock(lock_key)
        if cleanup_errors:
            raise authoritative_cleanup_error(cleanup_errors)

    async def cleanup_all_ssh_proxy_tunnels(self, owner: Any) -> None:
        """
        Drain every DUT-owned proxy service with interruption-safe accounting.

        The implementation uses ``owner`` to drain every DUT-owned proxy service
        with interruption-safe accounting. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        If the function cannot drain every DUT-owned proxy service with
        interruption-safe accounting, its exception reaches the caller instead
        of being converted into a successful result.

        Args:
            owner: Owner object whose ``duts``, ``items``, ``log_runtime``, and
                ``logger`` state is read while performing drain every DUT-owned
                proxy service with interruption-safe accounting.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to drain every DUT-owned proxy service with
                interruption-safe accounting.
            RuntimeError: If the function cannot drain every DUT-owned proxy
                service with interruption-safe accounting safely.
        """

        async def cleanup_one(
            dut_id: str, dut: Any
        ) -> Tuple[str, Optional[BaseException]]:
            """
            Clean up one.

            The implementation uses ``dut_id`` and ``dut`` to clean up one.
            Owned asynchronous work is awaited before return, so completion does
            not leave an unobserved task behind. If the function cannot clean up
            one, its exception reaches the caller instead of being converted
            into a successful result.

            Args:
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.
                dut: Stable DUT used to correlate configuration, logs, and
                    results.

            Returns:
                A tuple containing ``DUT identifier`` and ``optional[base
                exception]`` in that order.

            Raises:
                RuntimeError: If DUT proxy cleanup returned malformed success
                    evidence.
            """
            try:
                if await dut.cleanup_ssh_proxy_tunnels() is not True:
                    raise RuntimeError(
                        "DUT proxy cleanup returned malformed success evidence"
                    )
            except Exception as error:
                return dut_id, error
            return dut_id, None

        cleanup_coroutines = [
            cleanup_one(dut_id, dut)
            for dut_id, dut in owner.duts.items()
            if getattr(dut, "ssh_proxy_service", None)
        ]
        tasks = [
            asyncio.create_task(capture_owned_awaitable(coroutine))
            for coroutine in cleanup_coroutines
        ]
        outcomes = await drain_owned_tasks(
            tasks,
            cancel_on_error=lambda error: not isinstance(error, Exception),
        )
        wrapper_errors = [
            outcome.error
            for outcome in outcomes
            if outcome.error is not None and not outcome.owner_cancelled
        ]
        if wrapper_errors:
            raise select_authoritative_exception(wrapper_errors)
        results = [outcome.value for outcome in outcomes]
        failures = [(dut_id, error) for dut_id, error in results if error is not None]
        if failures:
            authoritative = authoritative_cleanup_error(
                [error for _dut_id, error in failures]
            )
            if isinstance(
                authoritative,
                (asyncio.CancelledError, KeyboardInterrupt, SystemExit),
            ):
                raise authoritative
            failed_duts = ", ".join(dut_id for dut_id, _error in failures)
            raise RuntimeError(
                "SSH proxy tunnel cleanup failed for DUT(s): " + failed_duts
            ) from authoritative

        if cleanup_coroutines:
            await owner.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Cleaned up SSH proxy tunnels for {len(cleanup_coroutines)} DUT(s)",
            )

    def cleanup_all_ssh_proxy_tunnels_sync(self, owner: Any) -> None:
        """
        Synchronously ask every exact proxy owner to clean up.

        The implementation uses ``owner`` to synchronously ask every exact proxy
        owner to clean up.

        Args:
            owner: Owner object whose ``duts`` and ``items`` state is read while
                performing synchronously ask every exact proxy owner to clean
                up.
        """

        for dut_id, dut in owner.duts.items():
            proxy_service = getattr(dut, "ssh_proxy_service", None)
            if not proxy_service:
                continue
            try:
                if not proxy_service.cleanup_tunnels_sync(dut_id):
                    logger.warning(
                        "Exact synchronous SSH proxy cleanup was incomplete for DUT %s",
                        dut_id,
                    )
            except Exception as error:
                logger.warning(
                    "Exact synchronous SSH proxy cleanup failed for DUT %s: %s",
                    dut_id,
                    error,
                )
