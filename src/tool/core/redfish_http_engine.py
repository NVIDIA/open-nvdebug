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
Bounded async execution for DUTManager's Redfish HTTP facade.

The engine owns request-attempt and response control flow only. Its owner
continues to own DUT lookup, connection/session lifecycle, TLS policy, caches,
private response spooling, HMC recovery, and request/response capture. Owner
methods are resolved at each boundary call so existing tests and extensions can
continue to monkeypatch the established ``DUTManager`` seams.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Tuple, Union

import aiohttp

from ..utils.redfish_download import StreamedRedfishBody, TruncatedRedfishErrorBody
from .redfish_controller import request_controller_dut
from .redfish_request import NonReplayableJSONBody, SensitiveMultipartBody
from .redfish_session_auth import (
    RedfishSessionAuthenticationError,
    redfish_authentication_origin,
)

RedfishResponsePayload = Union[str, dict, bytes, StreamedRedfishBody]
RedfishResult = Tuple[bool, RedfishResponsePayload, dict, dict]


@dataclass(frozen=True)
class RedfishHttpLimits:
    """
    Compatibility defaults used by the response-policy boundary.

    The immutable record keeps ``structured_response_max_bytes``,
    ``error_response_max_bytes``, ``error_evidence_max_bytes``,
    ``error_evidence_aggregate_max_bytes``, and ``error_evidence_max_responses``
    together so consumers observe one Redfish HTTP state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        structured_response_max_bytes: Byte count recorded for structured
            response max.
        error_response_max_bytes: Byte count recorded for error response max.
        error_evidence_max_bytes: Byte count recorded for error evidence max.
        error_evidence_aggregate_max_bytes: Byte count recorded for error
            evidence aggregate max.
        error_evidence_max_responses: Number of error evidence max responses
            represented by this record.
        transport_content_length_max_bytes: Byte count recorded for transport
            content length max.
        safe_response_headers: Collection of safe response headers entries
            retained by this record.
    """

    structured_response_max_bytes: int
    error_response_max_bytes: int
    error_evidence_max_bytes: int
    error_evidence_aggregate_max_bytes: int
    error_evidence_max_responses: int
    transport_content_length_max_bytes: int
    safe_response_headers: FrozenSet[str]


@dataclass(frozen=True)
class RedfishHttpPrimitives:
    """
    Bounded body/evidence primitives retained by the owning module.

    The immutable record keeps ``resolve_limit``,
    ``read_error_body_with_evidence``, ``decode_body``, ``read_body_bounded``,
    and ``attach_oversized_error_evidence`` together so consumers observe one
    Redfish HTTP primitives state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        resolve_limit: Maximum resolve admitted by this record.
        read_error_body_with_evidence: Read error body with evidence retained as
            part of the record's public state.
        decode_body: Canonical text used as decode body.
        read_body_bounded: Bounded byte sequence retained as read body bounded.
        attach_oversized_error_evidence: Mapping that retains the attach
            oversized error evidence fields for this record.
        oversized_error_evidence_from_metadata: Oversized error evidence from
            metadata retained as part of the record's public state.
        response_too_large: Response too large retained as part of the record's
            public state.
    """

    resolve_limit: Callable[[Any, str, int], int]
    read_error_body_with_evidence: Callable[..., Awaitable[Any]]
    decode_body: Callable[[aiohttp.ClientResponse, bytes], str]
    read_body_bounded: Callable[..., Awaitable[bytes]]
    attach_oversized_error_evidence: Callable[..., Dict[str, Any]]
    oversized_error_evidence_from_metadata: Callable[..., Any]
    response_too_large: type[Exception]


@dataclass(frozen=True)
class RedfishHttpEngine:
    """
    Execute one logical Redfish request without owning transport resources.

    The immutable record keeps ``owner``, ``primitives``, and ``limits``
    together so consumers observe one Redfish HTTP engine state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        owner: Owner retained as part of the record's public state.
        primitives: Primitives retained as part of the record's public state.
        limits: Limits retained as part of the record's public state.
    """

    owner: Any
    primitives: RedfishHttpPrimitives
    limits: RedfishHttpLimits

    async def execute_request(
        self,
        dut_id: str,
        method: str,
        url: str,
        body: Any = None,
        timeout: int = 300,
        get_raw_content: bool = False,
        bypass_cache: bool = False,
        retry_count: int = 3,
        expected_http_statuses: Any = None,
        multipart_parts: Optional[List[Dict[str, Any]]] = None,
        persistent_post_reservation: Any = None,
        raw_content_max_bytes: Optional[int] = None,
    ) -> RedfishResult:
        """
        Execute the facade's cache, retry, and HMC-recovery policy.

        Preserve the request path's own validation while ensuring HMC recovery
        accounting cannot raise before the request boundary.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            method: Text supplied as method in the format accepted by this
                function.
            url: Validated remote resource identifier used for URL.
            body: Optional body; ``None`` selects the function's default
                behavior.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            get_raw_content: Whether get raw content is enabled or required for
                this operation.
            bypass_cache: Whether bypass cache is enabled or required for this
                operation.
            retry_count: Numeric retry count used by the operation's bounded
                accounting.
            expected_http_statuses: Optional expected HTTP statuses; ``None``
                selects the function's default behavior.
            multipart_parts: Optional multipart parts; ``None`` selects the
                function's default behavior.
            persistent_post_reservation: Optional persistent post reservation;
                ``None`` selects the function's default behavior.
            raw_content_max_bytes: Upper bound enforced for raw content max
                bytes; the consuming boundary rejects or truncates values that
                exceed it.

        Returns:
            A tuple containing ``success flag``, ``execute request value 2``,
            ``metadata mapping``, and ``metadata mapping`` in that order.

        Raises:
            AssertionError: If redfish retry loop exited without a result.
        """

        try:
            recovery_timeout_budget = max(0.0, float(timeout))
        except (TypeError, ValueError):
            # Preserve the request path's own validation while ensuring HMC
            # recovery accounting cannot raise before the request boundary.
            recovery_timeout_budget = 0.0
        request_deadline = asyncio.get_running_loop().time() + recovery_timeout_budget
        configured_dut = self.owner.get_dut(dut_id)
        dut = request_controller_dut(configured_dut)
        enforcing_persistent_post = persistent_post_reservation is not None

        normalized_url = self.owner._validate_persistent_post_request(
            dut=dut,
            dut_id=dut_id,
            method=method,
            url=url,
            body=body,
            retry_count=retry_count,
            reservation=persistent_post_reservation,
        )

        if dut is configured_dut:
            success, message = await self.owner._ensure_connection(
                dut_id, "redfish", "test_redfish_connection"
            )
        else:
            # The collector scope owns and validates this controller's session;
            # do not consult the unrelated default/HMC connection state.
            success, message = True, "Collector controller session initialized"
        if not success:
            return (
                False,
                message,
                {"error": "connection_failed", "message": message},
                {},
            )

        if method.upper() == "GET" and not bypass_cache:
            cached_response = None
            presence_check = getattr(type(dut), "_has_cached_response", None)
            if callable(presence_check):
                cache_hit = bool(presence_check(dut, normalized_url))
                if cache_hit:
                    cached_response = dut._get_cached_response(normalized_url)
            else:
                cached_response = dut._get_cached_response(normalized_url)
                cache_hit = cached_response is not None

            if cache_hit:
                await dut._log_runtime(
                    "DEBUG", f"Using cached response for {normalized_url}"
                )
                return True, cached_response, {"cache_hit": True}, {}
        elif method.upper() == "GET" and bypass_cache:
            await dut._log_runtime("DEBUG", f"Bypassing cache for {normalized_url}")

        connection_info = dut.get_redfish_connection_info()
        is_hmc_forwarded = bool(connection_info.get("is_hmc_forwarded"))
        failed_hmc_service = dut.hmc_service if is_hmc_forwarded else None

        protocol = "https" if connection_info["use_https"] else "http"
        url_host = self.owner._format_redfish_url_host(connection_info["host"])
        full_url = f"{protocol}://{url_host}:{connection_info['port']}{normalized_url}"

        username = connection_info["username"]
        password = connection_info["password"]
        request_auth = (
            self.owner._encode_redfish_auth_header(username, password)
            if connection_info.get("auth_enabled", True) and username and password
            else None
        )

        max_retries = 0 if not getattr(body, "replay_safe", True) else retry_count
        base_delay = 1
        max_delay = 30
        retryable_status_codes = {502, 503, 504, 520, 521, 522, 523, 524}
        limited_retry_status_codes = {500}
        max_retries_for_500 = 1

        await dut._log_runtime(
            "DEBUG",
            f"Starting {method} request to {normalized_url} "
            f"(timeout={timeout}s, max_retries={max_retries})",
        )

        evidence_aggregate_max_bytes = self.primitives.resolve_limit(
            dut,
            "error_evidence_aggregate_max_bytes",
            self.limits.error_evidence_aggregate_max_bytes,
        )
        evidence_max_responses = self.primitives.resolve_limit(
            dut,
            "error_evidence_max_responses",
            self.limits.error_evidence_max_responses,
        )
        oversized_error_history: List[TruncatedRedfishErrorBody] = []
        oversized_error_retained_bytes = 0
        oversized_error_dropped = 0

        def retain_oversized_error_evidence(metadata: Any) -> None:
            """
            Keep the first and newest evidence inside both configured caps.

            The implementation uses ``metadata`` to keep the first and newest
            evidence inside both configured caps.

            Args:
                metadata: Metadata consumed while the function attempts to keep
                    the first and newest evidence inside both configured caps.
            """

            nonlocal oversized_error_dropped, oversized_error_retained_bytes
            evidence, already_dropped, _, _ = (
                self.primitives.oversized_error_evidence_from_metadata(metadata)
            )
            oversized_error_dropped += already_dropped
            for item in evidence:
                oversized_error_history.append(item)
                oversized_error_retained_bytes += item.retained_size_bytes
                while (
                    len(oversized_error_history) > evidence_max_responses
                    or oversized_error_retained_bytes > evidence_aggregate_max_bytes
                ):
                    removal_index = 1 if len(oversized_error_history) > 2 else 0
                    removed = oversized_error_history.pop(removal_index)
                    oversized_error_retained_bytes -= removed.retained_size_bytes
                    oversized_error_dropped += 1

        def finalize_response_evidence(result: RedfishResult) -> RedfishResult:
            """
            Finalize response evidence.

            The implementation uses ``result`` to finalize response evidence.

            Args:
                result: Result evaluated while performing finalize response
                    evidence.

            Returns:
                A tuple containing ``success``, ``data``, ``attach oversized
                error evidence``, and ``auxiliary`` in that order.
            """
            success, data, metadata, auxiliary = result
            retain_oversized_error_evidence(metadata)
            if not oversized_error_history:
                return result
            return (
                success,
                data,
                self.primitives.attach_oversized_error_evidence(
                    dict(metadata or {}),
                    list(oversized_error_history),
                    dropped_response_count=oversized_error_dropped,
                    aggregate_max_bytes=evidence_aggregate_max_bytes,
                    max_responses=evidence_max_responses,
                ),
                auxiliary,
            )

        for attempt in range(max_retries + 1):
            current_delay = min(base_delay * (2**attempt), max_delay)

            try:
                if attempt > 0:
                    await dut._log_runtime(
                        "INFO",
                        f"Retry attempt {attempt}/{max_retries} for {method} "
                        f"{normalized_url} (delay={current_delay}s)",
                    )
                result = await self.owner._execute_redfish_http_attempt(
                    dut=dut,
                    method=method,
                    full_url=full_url,
                    normalized_url=normalized_url,
                    body=body,
                    request_auth=request_auth,
                    timeout=timeout,
                    get_raw_content=get_raw_content,
                    attempt=attempt,
                    max_retries=max_retries,
                    current_delay=current_delay,
                    retryable_status_codes=retryable_status_codes,
                    limited_retry_status_codes=limited_retry_status_codes,
                    max_retries_for_limited=max_retries_for_500,
                    allow_session_conflict_retry=True,
                    expected_http_statuses=expected_http_statuses,
                    multipart_parts=multipart_parts,
                    raw_content_max_bytes=raw_content_max_bytes,
                )
                success, data, metadata, _ = result
                if not success and data == "retry":
                    retain_oversized_error_evidence(metadata)
                    continue
                return finalize_response_evidence(result)

            except (asyncio.TimeoutError, aiohttp.ClientConnectionError) as error:
                await dut._log_runtime(
                    "WARNING",
                    f"Connection error on attempt {attempt + 1}/{max_retries + 1} "
                    f"for {method} {normalized_url}: {str(error)}",
                )

                if attempt < max_retries:
                    await dut._log_runtime(
                        "INFO",
                        f"Waiting {current_delay}s before retry "
                        f"{attempt + 2}/{max_retries + 1}",
                    )
                    await asyncio.sleep(current_delay)
                    continue

                await dut._log_runtime(
                    "ERROR",
                    f"All {max_retries + 1} attempts failed for {method} "
                    f"{normalized_url}: {str(error)}",
                )
                failure_result: RedfishResult = (
                    False,
                    f"Redfish connection error after {max_retries + 1} attempts: "
                    f"{str(error)}",
                    {
                        "error": "connection_failed",
                        "message": str(error),
                        "attempts": max_retries + 1,
                    },
                    {},
                )
                if (
                    is_hmc_forwarded
                    and not enforcing_persistent_post
                    and getattr(body, "replay_safe", True)
                ):
                    return finalize_response_evidence(
                        await self.owner._recover_and_replay_forwarded_hmc_request(
                            dut=dut,
                            failed_hmc_service=failed_hmc_service,
                            method=method,
                            normalized_url=normalized_url,
                            body=body,
                            multipart_parts=multipart_parts,
                            get_raw_content=get_raw_content,
                            raw_content_max_bytes=raw_content_max_bytes,
                            request_deadline=request_deadline,
                            original_failure=failure_result,
                        )
                    )
                if not getattr(body, "replay_safe", True):
                    failure_result[2]["outcome_indeterminate"] = True
                    failure_result[2]["replay_suppressed"] = True
                return finalize_response_evidence(failure_result)
            except self.primitives.response_too_large as error:
                await dut._log_runtime(
                    "ERROR",
                    f"Raw Redfish response rejected for {method} "
                    f"{normalized_url}: {error}",
                )
                return finalize_response_evidence(
                    (
                        False,
                        str(error),
                        {
                            "error": "raw_content_too_large",
                            "message": str(error),
                            "max_content_bytes": raw_content_max_bytes,
                        },
                        {},
                    )
                )
            except Exception as error:
                await dut._log_runtime(
                    "ERROR",
                    f"Non-retryable error on attempt {attempt + 1}/"
                    f"{max_retries + 1} for {method} {normalized_url}: {str(error)}",
                )
                return finalize_response_evidence(
                    (
                        False,
                        f"Redfish request error: {str(error)}",
                        {"error": "exception", "message": str(error)},
                        {},
                    )
                )

        raise AssertionError("Redfish retry loop exited without a result")

    @staticmethod
    def _pooled_credential_is_stale(
        session_obj: Any,
        request_auth: Optional[str],
        request_url: Optional[str] = None,
    ) -> bool:
        """
        Report whether a cached session carries a different credential.

        The pooled credential is bound once, at pool initialization, while the
        destination URL and its matching credential are re-derived from the
        connection info on every request. Any difference, including a
        credential being present on only one side, means the cached session
        belongs to a different endpoint binding and must not be used for this
        request. This also prevents a credential from being sent after
        authentication has been disabled for the current endpoint.

        Args:
            session_obj: Session mapping returned by the pool, or ``None``.
            request_auth: Credential derived for the destination of this
                request, or ``None`` when authentication is disabled.
            request_url: Complete request URL used to bind an optional token to
                its exact HTTPS authority. Token-bearing mappings require it.

        Returns:
            ``True`` when the cached and request credentials differ, otherwise
            ``False``.
        """
        if type(session_obj) is not dict:
            return False
        if session_obj.get("auth") != request_auth:
            return True
        if session_obj.get("auth_token") is not None:
            try:
                return not request_auth or session_obj.get(
                    "auth_origin"
                ) != redfish_authentication_origin(request_url)
            except RedfishSessionAuthenticationError:
                return True
        return False

    async def _rebind_redfish_session_pool(
        self,
        dut: Any,
        request_auth: Optional[str],
        request_url: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Rebuild the DUT session pool after a credential/endpoint mismatch.

        The rebuild uses the DUT's own close/initialize lifecycle, which is the
        same reset sequence the forwarded-HMC recovery path performs. A failed
        or still-mismatched rebuild is degraded rather than fatal: the caller
        falls back to the single-session and temporary-session paths, which
        present the freshly derived credential, so one collector request is
        never aborted by a pool-rebuild failure.

        Args:
            dut: DUT owning the Redfish session pool being rebuilt.
            request_auth: Credential derived for the destination of this
                request.
            request_url: Complete destination URL for session-token authority
                checks; legacy Basic-only callers may omit it.

        Returns:
            The rebuilt session mapping when it matches this request's
            endpoint, otherwise ``None``.
        """
        await dut._log_runtime(
            "WARNING",
            "Pooled Redfish credential does not match the credential derived "
            "for this request's endpoint; rebuilding the session pool",
        )
        try:
            await dut.close_redfish_session()
            if not await dut.initialize_redfish_session_pool():
                return None
            pool = dut.redfish_session_pool
            if not pool:
                return None
            rebuilt = await pool.get_session()
        except Exception as error:
            await dut._log_runtime(
                "WARNING",
                "Redfish session pool rebuild failed "
                f"({type(error).__name__}); falling back to a per-request session",
            )
            return None
        if self._pooled_credential_is_stale(rebuilt, request_auth, request_url):
            await dut._log_runtime(
                "WARNING",
                "Rebuilt Redfish session pool still presents a credential that "
                "does not match this request's endpoint; falling back to a "
                "per-request session",
            )
            return None
        return rebuilt

    async def execute_http_attempt(
        self,
        dut: Any,
        method: str,
        full_url: str,
        normalized_url: str,
        body: Any,
        request_auth: Optional[str],
        timeout: Union[int, float],
        get_raw_content: bool,
        attempt: int,
        max_retries: int,
        current_delay: float,
        retryable_status_codes: set,
        limited_retry_status_codes: set,
        max_retries_for_limited: int,
        allow_session_conflict_retry: bool,
        expected_http_statuses: Any = None,
        multipart_parts: Optional[List[Dict[str, Any]]] = None,
        raw_content_max_bytes: Optional[int] = None,
    ) -> RedfishResult:
        """
        Execute one attempt through an owner-managed Redfish session.

        The implementation uses ``dut``, ``method``, ``full_url``,
        ``normalized_url``, and ``body`` to execute one attempt through an
        owner-managed Redfish session. Terminal status is emitted only after one
        attempt through an owner-managed Redfish session and its owned cleanup
        have completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Remote I/O uses the
        configured transport policy and returns only after its response or
        failure has been observed. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            method: Text supplied as method in the format accepted by this
                function.
            full_url: Validated remote resource identifier used for full URL.
            normalized_url: Validated remote resource identifier used for
                normalized URL.
            body: Body consumed while the function attempts to execute one
                attempt through an owner-managed Redfish session.
            request_auth: Request auth consumed while the function attempts to
                execute one attempt through an owner-managed Redfish session.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            get_raw_content: Whether get raw content is enabled or required for
                this operation.
            attempt: Numeric attempt used while the operation performs bounded
                accounting.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            current_delay: Numeric current delay used while the operation
                performs bounded accounting.
            retryable_status_codes: Entries supplied as
                ``retryable_status_codes`` without transferring container
                ownership.
            limited_retry_status_codes: Entries supplied as
                ``limited_retry_status_codes`` without transferring container
                ownership.
            max_retries_for_limited: Upper bound enforced for max retries for
                limited; the consuming boundary rejects or truncates values that
                exceed it.
            allow_session_conflict_retry: Whether allow session conflict retry
                is enabled or required for this operation.
            expected_http_statuses: Optional expected HTTP statuses; ``None``
                selects the function's default behavior.
            multipart_parts: Optional multipart parts; ``None`` selects the
                function's default behavior.
            raw_content_max_bytes: Upper bound enforced for raw content max
                bytes; the consuming boundary rejects or truncates values that
                exceed it.

        Returns:
            A tuple containing ``success flag``, ``status text``, ``metadata
            mapping``, and ``metadata mapping`` in that order.

        Raises:
            RedfishSessionAuthenticationError: If the selected session policy
                cannot authenticate and does not permit a Basic fallback.
            BaseException: If transport, cleanup, or caller interruption prevents
                completion of the owned request.
        """

        async def handle_response(response: aiohttp.ClientResponse) -> RedfishResult:
            """
            Handle response.

            After applying local validation, the function forwards ``response``
            to ``self.owner._handle_redfish_response`` and preserves its return
            and exception contract. Terminal status is emitted only after
            response and its owned cleanup have completed. Owned asynchronous
            work is awaited before return, so completion does not leave an
            unobserved task behind.

            Args:
                response: Transport response governed by the configured
                    authentication and trust policy.

            Returns:
                A ``RedfishResult`` representing handle response.
            """
            return await self.owner._handle_redfish_response(
                dut,
                response,
                normalized_url,
                method,
                attempt,
                max_retries,
                current_delay,
                retryable_status_codes,
                get_raw_content,
                limited_retry_status_codes,
                max_retries_for_limited,
                expected_http_statuses,
                sensitive_response=bool(getattr(body, "sensitive", False)),
                raw_content_max_bytes=raw_content_max_bytes,
            )

        async def execute_with_session(
            session: aiohttp.ClientSession,
            auth_header: Optional[str],
            auth_token: Optional[str] = None,
            auth_pool: Any = None,
        ) -> RedfishResult:
            """
            Execute with session.

            After applying local validation, the function forwards ``session``
            and ``auth_header`` to ``handle_response`` and preserves its return and
            exception contract. Terminal status is emitted only after with
            session and its owned cleanup have completed. Owned asynchronous
            work is awaited before return, so completion does not leave an
            unobserved task behind. Remote I/O uses the configured transport
            policy and returns only after its response or failure has been
            observed. Cleanup in the ``finally`` path runs for successful,
            failed, and cancelled execution.

            Args:
                session: Transport session governed by the configured
                    authentication and trust policy.
                auth_header: Encoded Basic authorization header, or ``None``
                    when authentication is disabled.
                auth_token: Endpoint-bound token snapshot that replaces the Basic
                    header for this attempt, or ``None`` for legacy transport.
                auth_pool: Exact pool that issued the token snapshot; later
                    endpoint rebinding must not invalidate a replacement owner.

            Returns:
                A ``RedfishResult`` representing execute with session.
            """
            request_options: Dict[str, Any] = {}
            opened_files: List[Any] = []
            if isinstance(body, SensitiveMultipartBody):
                form, payload_handle = body.build()
                opened_files.append(payload_handle)
                request_options["data"] = form
            elif multipart_parts:
                form, opened_files = self.owner._build_redfish_multipart_form(
                    multipart_parts
                )
                request_options["data"] = form
            elif isinstance(body, NonReplayableJSONBody):
                request_options["json"] = dict(body.payload)
            elif body:
                request_options["json"] = body
            try:
                authentication_options = (
                    {"auth_token": auth_token} if auth_token is not None else {}
                )
                with (
                    auth_pool.use_authentication(auth_token)
                    if auth_token is not None
                    else nullcontext()
                ):
                    async with session.request(
                        method,
                        full_url,
                        timeout=request_timeout,
                        allow_redirects=False,
                        auto_decompress=False,
                        headers=self.owner._build_redfish_request_headers(
                            auth_header,
                            {"Accept-Encoding": "gzip, deflate"},
                            **authentication_options,
                        ),
                        **dut.redfish_tls_request_kwargs(
                            use_https=full_url.lower().startswith("https://")
                        ),
                        **request_options,
                    ) as response:
                        result = await handle_response(response)
                        if auth_token is not None and response.status == 401:
                            await auth_pool.invalidate_authentication(auth_token)
                            if (
                                method.upper() in {"GET", "HEAD"}
                                and allow_session_conflict_retry
                                and attempt == 0
                                and attempt < max_retries
                            ):
                                metadata = dict(result[2])
                                metadata["session_authentication_expired"] = True
                                return False, "retry", metadata, result[3]
                        return result
            finally:
                for handle in opened_files:
                    handle.close()

        request_timeout = aiohttp.ClientTimeout(total=timeout)

        session_config = getattr(dut, "redfish_session_config", {})
        authentication_mode = (
            session_config.get("authentication_mode", "auto")
            if isinstance(session_config, dict)
            else "auto"
        )
        session_auth_selected = bool(
            request_auth
            and authentication_mode in {"auto", "session"}
            and (
                authentication_mode == "session"
                or full_url.lower().startswith("https://")
            )
        )
        if session_auth_selected and not dut.redfish_session_pool:
            if not await dut.initialize_redfish_session_pool():
                raise RedfishSessionAuthenticationError("pool initialization")

        if dut.redfish_session_pool:
            await dut._log_runtime(
                "DEBUG",
                f"Using high-performance session pool for request (timeout={timeout}s)",
            )
            request_pool = dut.redfish_session_pool
            session_obj = await request_pool.get_session()
            if self._pooled_credential_is_stale(session_obj, request_auth, full_url):
                session_obj = await self._rebind_redfish_session_pool(
                    dut,
                    request_auth,
                    full_url,
                )
                request_pool = dut.redfish_session_pool
            if (
                session_obj
                and session_obj.get("session")
                and not session_obj["session"].closed
            ):
                try:
                    return await execute_with_session(
                        session_obj["session"],
                        session_obj.get("auth"),
                        session_obj.get("auth_token"),
                        request_pool,
                    )
                except Exception as error:
                    if (
                        allow_session_conflict_retry
                        and request_pool
                        and dut.redfish_session_pool is request_pool
                        and await request_pool.handle_session_conflict(error)
                        and attempt < max_retries
                    ):
                        await dut._log_runtime(
                            "INFO",
                            "Session conflict detected, retrying request after "
                            "session reinitialization "
                            f"(attempt {attempt + 1}/{max_retries + 1})",
                        )
                        await asyncio.sleep(current_delay)
                        return False, "retry", {"session_conflict": True}, {}
                    raise
            if (
                getattr(dut.redfish_session_pool, "allows_basic_fallback", True)
                is False
            ):
                raise RedfishSessionAuthenticationError("required pool authentication")
            await dut._log_runtime(
                "WARNING",
                "Session pool not available, falling back to single session",
            )

        if session_auth_selected and (
            not dut.redfish_session_pool
            or getattr(dut.redfish_session_pool, "allows_basic_fallback", None)
            is not True
        ):
            raise RedfishSessionAuthenticationError("required pool authentication")

        if dut.redfish_session and dut.redfish_auth:
            single_session_auth = dut.redfish_auth
            if request_auth != single_session_auth:
                await dut._log_runtime(
                    "WARNING",
                    "Stored single-session Redfish credential does not match the "
                    "credential derived for this request's endpoint; using the "
                    "derived credential",
                )
                single_session_auth = request_auth
            await dut._log_runtime(
                "DEBUG", f"Using single session for request (timeout={timeout}s)"
            )
            return await execute_with_session(dut.redfish_session, single_session_auth)

        await dut._log_runtime(
            "DEBUG", f"Creating temporary session for request (timeout={timeout}s)"
        )
        async with aiohttp.ClientSession(
            auto_decompress=False,
            headers={"Accept-Encoding": "gzip, deflate"},
        ) as session:
            return await execute_with_session(session, request_auth)

    async def handle_response(
        self,
        dut: Any,
        response: aiohttp.ClientResponse,
        uri: str,
        method: str,
        attempt: int,
        max_retries: int,
        current_delay: float,
        retryable_status_codes: set,
        get_raw_content: bool = False,
        limited_retry_status_codes: Optional[set] = None,
        max_retries_for_limited: int = 1,
        expected_http_statuses: Any = None,
        sensitive_response: bool = False,
        raw_content_max_bytes: Optional[int] = None,
    ) -> RedfishResult:
        """
        Parse one response and return the facade's stable result tuple.

        The implementation uses ``dut``, ``response``, ``uri``, ``method``, and
        ``attempt`` to parse one response and return the facade's stable result
        tuple. Parsing or I/O must finish before the validated representation is
        made available to the caller. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            response: Transport response governed by the configured
                authentication and trust policy.
            uri: Validated remote resource identifier used for URI.
            method: Text supplied as method in the format accepted by this
                function.
            attempt: Numeric attempt used while the operation performs bounded
                accounting.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            current_delay: Numeric current delay used while the operation
                performs bounded accounting.
            retryable_status_codes: Entries supplied as
                ``retryable_status_codes`` without transferring container
                ownership.
            get_raw_content: Whether get raw content is enabled or required for
                this operation.
            limited_retry_status_codes: Optional limited retry status codes;
                ``None`` selects the function's default behavior.
            max_retries_for_limited: Upper bound enforced for max retries for
                limited; the consuming boundary rejects or truncates values that
                exceed it.
            expected_http_statuses: Optional expected HTTP statuses; ``None``
                selects the function's default behavior.
            sensitive_response: Whether sensitive response is enabled or
                required for this operation.
            raw_content_max_bytes: Upper bound enforced for raw content max
                bytes; the consuming boundary rejects or truncates values that
                exceed it.

        Returns:
            A tuple containing ``success flag``, ``handle response value 2``,
            ``handle response value 3``, and ``handle response value 4`` in that
            order.
        """

        if limited_retry_status_codes is None:
            limited_retry_status_codes = {500}
        raw_headers = getattr(response, "headers", None)
        safe_headers = (
            {
                name: value
                for name, value in raw_headers.items()
                if name.lower() in self.limits.safe_response_headers
            }
            if isinstance(raw_headers, Mapping)
            else {}
        )
        await dut._log_runtime(
            "DEBUG",
            f"Response for {method} {uri}: HTTP {response.status} "
            f"(attempt {attempt + 1}/{max_retries + 1})",
        )

        async def read_error_response() -> (
            Tuple[str, Optional[TruncatedRedfishErrorBody]]
        ):
            """
            Read error response.

            The implementation uses current instance state to read error
            response. Parsing or I/O must finish before the validated
            representation is made available to the caller. Owned asynchronous
            work is awaited before return, so completion does not leave an
            unobserved task behind.

            Returns:
                A tuple containing ``status or message text`` and
                ``optional[truncated Redfish error body]`` in that order.
            """
            body, evidence = await self.primitives.read_error_body_with_evidence(
                response,
                self.primitives.resolve_limit(
                    dut,
                    "error_response_max_bytes",
                    self.limits.error_response_max_bytes,
                ),
                evidence_max_bytes=self.primitives.resolve_limit(
                    dut,
                    "error_evidence_max_bytes",
                    self.limits.error_evidence_max_bytes,
                ),
                http_status=response.status,
                attempt_number=attempt + 1,
            )
            if evidence is not None:
                return evidence.safe_summary_text(), evidence
            return self.primitives.decode_body(response, body or b""), None

        def error_metadata_with_evidence(
            values: Dict[str, Any],
            evidence: Optional[TruncatedRedfishErrorBody],
        ) -> Dict[str, Any]:
            """
            Return the error metadata with evidence.

            After applying local validation, the function forwards ``values``
            and ``evidence`` to
            ``self.primitives.attach_oversized_error_evidence`` and preserves
            its return and exception contract.

            Args:
                values: Mapping supplying fields for error metadata with
                    evidence.
                evidence: Evidence consumed while the function attempts to
                    produce the error metadata with evidence.

            Returns:
                A mapping containing error metadata with evidence.
            """
            return self.primitives.attach_oversized_error_evidence(
                values,
                [evidence] if evidence is not None else [],
                aggregate_max_bytes=self.primitives.resolve_limit(
                    dut,
                    "error_evidence_aggregate_max_bytes",
                    self.limits.error_evidence_aggregate_max_bytes,
                ),
                max_responses=self.primitives.resolve_limit(
                    dut,
                    "error_evidence_max_responses",
                    self.limits.error_evidence_max_responses,
                ),
            )

        if 300 <= response.status < 400:
            await dut._log_runtime(
                "ERROR",
                f"Rejected redirect HTTP {response.status} for {method} {uri}",
            )
            return (
                False,
                f"HTTP {response.status}: Redfish redirects are not allowed",
                {
                    "http_status": response.status,
                    "uri": uri,
                    "method": method,
                    "redirect_rejected": True,
                },
                {},
            )
        if response.status < 300:
            if get_raw_content:
                content = await self.owner._stream_redfish_body_to_spool(
                    response,
                    max_bytes=raw_content_max_bytes,
                )
                await dut._log_runtime(
                    "DEBUG",
                    f"Successfully streamed {content.size_bytes} bytes for "
                    f"{method} {uri} (sha256={content.sha256})",
                )
                return (
                    True,
                    content,
                    self.owner._safe_redfish_transport_metadata(
                        response,
                        content_length_bytes=content.size_bytes,
                        max_content_length_bytes=(
                            self.limits.transport_content_length_max_bytes
                        ),
                        sha256=content.sha256,
                        body_storage="private_spool",
                    ),
                    safe_headers,
                )

            content_bytes = await self.primitives.read_body_bounded(
                response,
                self.primitives.resolve_limit(
                    dut,
                    "structured_response_max_bytes",
                    self.limits.structured_response_max_bytes,
                ),
                category="structured response",
            )
            content = self.primitives.decode_body(response, content_bytes)
            try:
                result = json.loads(content)
                await dut._log_runtime(
                    "DEBUG",
                    f"Successfully parsed JSON response for {method} {uri} "
                    f"({len(content)} chars)",
                )
            # JSONDecodeError is only one ValueError shape: an integer literal
            # longer than sys.get_int_max_str_digits() raises the parent type.
            except ValueError:
                result = content
                await dut._log_runtime(
                    "DEBUG",
                    f"Response is not JSON for {method} {uri} ({len(content)} chars)",
                )

            if method.upper() == "GET":
                if dut._cache_response(uri, result, size_bytes=len(content_bytes)):
                    await dut._log_runtime("DEBUG", f"Cached response for {uri}")
                else:
                    await dut._log_runtime(
                        "DEBUG",
                        f"Response for {uri} exceeded the Redfish cache budget",
                    )

            return (
                True,
                result,
                self.owner._safe_redfish_transport_metadata(
                    response,
                    content_length_bytes=len(content_bytes),
                    max_content_length_bytes=self.primitives.resolve_limit(
                        dut,
                        "structured_response_max_bytes",
                        self.limits.structured_response_max_bytes,
                    ),
                ),
                safe_headers,
            )

        if (
            response.status in retryable_status_codes
            or response.status in limited_retry_status_codes
        ):
            response_text, oversized_error_evidence = await read_error_response()

            parsed_response: Any = response_text
            try:
                parsed_response = json.loads(response_text)
                await dut._log_runtime(
                    "DEBUG",
                    f"Parsed JSON from HTTP {response.status} response for "
                    f"{method} {uri}",
                )
            # JSONDecodeError is only one ValueError shape: an integer literal
            # longer than sys.get_int_max_str_digits() raises the parent type.
            except ValueError:
                await dut._log_runtime(
                    "DEBUG",
                    f"Could not parse HTTP {response.status} response as JSON "
                    f"for {method} {uri}",
                )

            compact_text = (
                "<sensitive response omitted>"
                if sensitive_response
                else " ".join(response_text.split())[:200]
            )
            await dut._log_runtime(
                "WARNING",
                f"Server error HTTP {response.status} for {method} {uri}: "
                f"{compact_text}",
            )

            effective_max_retries = max_retries
            if response.status in limited_retry_status_codes:
                effective_max_retries = min(max_retries, max_retries_for_limited)
                if attempt == 0:
                    await dut._log_runtime(
                        "INFO",
                        f"HTTP {response.status} uses limited retries "
                        f"({effective_max_retries}) - persistent server errors "
                        "typically don't resolve with more retries",
                    )

            if attempt < effective_max_retries:
                await dut._log_runtime(
                    "INFO",
                    f"Retrying due to server error HTTP {response.status} "
                    f"(attempt {attempt + 1}/{effective_max_retries + 1})",
                )
                await asyncio.sleep(current_delay)
                return (
                    False,
                    "retry",
                    error_metadata_with_evidence(
                        {
                            "http_status": response.status,
                            "error_message": response_text,
                            "uri": uri,
                            "method": method,
                        },
                        oversized_error_evidence,
                    ),
                    {
                        "attempt": attempt + 1,
                        "max_retries": effective_max_retries,
                        "current_delay": current_delay,
                    },
                )

            await dut._log_runtime(
                "WARNING",
                f"Max retries ({effective_max_retries}) exceeded for server "
                f"error HTTP {response.status} on {method} {uri}, returning "
                "parsed response if available",
            )
            return (
                False,
                parsed_response,
                error_metadata_with_evidence(
                    {
                        "http_status": response.status,
                        "error_message": response_text,
                        "uri": uri,
                        "method": method,
                        "max_retries_exceeded": True,
                        "limited_retries_used": response.status
                        in limited_retry_status_codes,
                    },
                    oversized_error_evidence,
                ),
                {
                    "attempt": attempt + 1,
                    "max_retries": effective_max_retries,
                },
            )

        response_text, oversized_error_evidence = await read_error_response()
        compact_text = (
            "<sensitive response omitted>"
            if sensitive_response
            else " ".join(response_text.split())[:200]
        )
        raw_expected_statuses = expected_http_statuses
        if raw_expected_statuses is None:
            raw_expected_statuses = []
        elif not isinstance(raw_expected_statuses, (list, tuple, set)):
            raw_expected_statuses = [raw_expected_statuses]
        normalized_expected_statuses = set()
        for expected_status in raw_expected_statuses:
            try:
                normalized_expected_statuses.add(int(expected_status))
            except (TypeError, ValueError):
                continue
        expected_http_miss = response.status in normalized_expected_statuses
        await dut._log_runtime(
            "INFO" if expected_http_miss else "ERROR",
            (
                f"Expected optional Redfish probe miss HTTP {response.status} "
                f"for {method} {uri}: {compact_text}"
                if expected_http_miss
                else f"Client error HTTP {response.status} for {method} {uri}: "
                f"{compact_text}"
            ),
        )
        return (
            False,
            f"HTTP {response.status}: {response_text}",
            error_metadata_with_evidence(
                {
                    "http_status": response.status,
                    "error_message": response_text,
                    "uri": uri,
                    "method": method,
                    "client_error": True,
                    **({"expected_http_status": True} if expected_http_miss else {}),
                },
                oversized_error_evidence,
            ),
            {},
        )
