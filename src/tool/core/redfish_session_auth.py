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
Own bounded Redfish login, token renewal, and logout for one pooled endpoint.

Session endpoints are discovered from Redfish links, never from platform names.
The owner retains the exact created resource and endpoint binding, observes an
in-flight login before propagating cancellation, and never replays a collector
request. Authentication values and protocol bodies remain in memory.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import aiohttp

from ..utils.redfish_tls import RedfishTLSPolicy
from ..utils.redfish_topology_profile import validate_redfish_uri_path
from ..utils.redfish_transport import (
    build_redfish_request_headers,
    format_redfish_url_host,
)
from .finalization_receipt import capture_owned_awaitable, drain_owned_tasks

AUTH_RESPONSE_MAX_BYTES = 1024 * 1024
AUTH_REQUEST_TIMEOUT_SECONDS = 15.0
LOGOUT_MAX_REQUESTS = 3  # One token fallback and one timeout retry, shared.
_UNSUPPORTED_HTTP_STATUSES = frozenset({404, 405, 501})


class RedfishSessionAuthenticationError(RuntimeError):
    """
    Report an authentication failure without retaining remote bodies or secrets.

    Callers supply only fixed operation labels and an optional numeric status;
    untrusted exception messages, response headers, and credentials are excluded.
    """

    def __init__(self, operation: str, status: int | None = None) -> None:
        """
        Build a credential-free failure at the protocol boundary.

        The message identifies the failed operation without retaining a response
        body, token, credential, or potentially sensitive transport exception.

        Args:
            operation: Fixed label describing the failed authentication phase.
            status: HTTP status when a response was received, otherwise ``None``.
        """

        suffix = "" if status is None else f" (HTTP {status})"
        super().__init__(f"Redfish session authentication {operation} failed{suffix}")
        self.status = status


async def _read_authentication_body(response: aiohttp.ClientResponse) -> bytes:
    """
    Consume a bounded protocol body using the existing Redfish response reader.

    The deferred facade import avoids a module cycle and preserves the existing
    reader seam, including bounded decompression and malformed-content handling.

    Args:
        response: Owned HTTP response whose body must be consumed before reuse.

    Returns:
        Bounded decoded response bytes, including non-JSON error/logout bodies.

    Raises:
        RedfishSessionAuthenticationError: If the body is invalid or oversized.
        TimeoutError: If transport reading times out; the message excludes
            potentially sensitive transport exception details.
        BaseException: If the caller interrupts bounded reading.
    """

    from .dut_manager import _read_redfish_body_bounded

    try:
        return await _read_redfish_body_bounded(
            response, AUTH_RESPONSE_MAX_BYTES, category="session authentication"
        )
    except TimeoutError:
        raise TimeoutError("Redfish authentication response timed out") from None
    except Exception:
        raise RedfishSessionAuthenticationError("response validation") from None


async def read_authentication_document(response: aiohttp.ClientResponse) -> dict:
    """
    Decode a bounded Redfish object without exposing malformed remote content.

    Empty bodies represent an empty object; non-object JSON is rejected because
    discovery and login callers require named protocol fields.

    Args:
        response: Owned HTTP response carrying a protocol document.

    Returns:
        The decoded object, or an empty object for an empty body.

    Raises:
        RedfishSessionAuthenticationError: If bounded reading or decoding fails.
        TimeoutError: If transport reading exceeds the authentication deadline.
        BaseException: If the caller interrupts reading.
    """

    body = await _read_authentication_body(response)
    try:
        document = json.loads(body) if body else {}
        if type(document) is not dict:
            raise ValueError("Expected a protocol object")
        return document
    except Exception:
        raise RedfishSessionAuthenticationError("response validation") from None


def redfish_authentication_origin(url: str) -> tuple[str, str, int]:
    """
    Canonicalize an HTTPS authority without accepting userinfo or fragments.

    Explicit and default HTTPS ports compare equally. Resource-path validation
    remains separate so this helper can also check a collector's complete URL.

    Args:
        url: Endpoint or request URL whose authority binds a session token.

    Returns:
        The normalized scheme, hostname, and effective port.

    Raises:
        RedfishSessionAuthenticationError: If the authority is unsafe or invalid.
    """

    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or "\\" in url
            or any(
                character.isspace() or ord(character) < 32 or ord(character) == 127
                for character in url
            )
        ):
            raise ValueError("Invalid authentication authority")
        port = 443 if parsed.port is None else parsed.port
        if not 1 <= port <= 65535:
            raise ValueError("Invalid authentication port")
        try:
            host = str(ipaddress.ip_address(parsed.hostname))
        except ValueError:
            host = parsed.hostname.encode("idna").decode("ascii").lower()
        return "https", host, port
    except (TypeError, ValueError):
        raise RedfishSessionAuthenticationError("endpoint validation") from None


class RedfishSessionAuthentication:
    """
    Retain one created session until confirmed logout or explicit cleanup failure.

    The surrounding pool serializes discovery, login, renewal, and logout. Token
    snapshots may be used concurrently by requests; invalidation checks the exact
    snapshot so an old unauthorized response cannot invalidate a newer login.
    """

    def __init__(
        self,
        connection_info: Mapping[str, Any],
        binding_auth: str,
        tls_policy: RedfishTLSPolicy,
        ssl_parameter: Any,
    ) -> None:
        """
        Pin credentials, endpoint, service root, and the existing TLS policy.

        Every login and logout uses this captured binding, including cleanup
        after the surrounding DUT has changed its active endpoint or credentials.

        Args:
            connection_info: Validated pool endpoint and credential fields.
            binding_auth: Basic credential identity retained by the pool.
            tls_policy: Existing endpoint trust policy, preserved for every call.
            ssl_parameter: Existing connector verification parameter.

        Raises:
            RedfishSessionAuthenticationError: If the endpoint is not HTTPS or
                its root/authority cannot safely bind a session token.
        """

        try:
            if connection_info.get("use_https") is not True or not binding_auth:
                raise ValueError("Session authentication requires HTTPS and auth")
            host = connection_info["host"]
            port = connection_info["port"]
            if type(host) is not str or type(port) is not int:
                raise ValueError("Invalid authentication host or port")
            host = format_redfish_url_host(host)
            self._base_url = urlunsplit(("https", f"{host}:{port}", "", "", ""))
            parsed = urlsplit(self._base_url)
            if parsed.path or parsed.query:
                raise ValueError("Invalid authentication authority")
            self.origin = redfish_authentication_origin(self._base_url)
            self._root = validate_redfish_uri_path(connection_info["service_root"])
            self._username = connection_info["username"]
            self._password = connection_info["password"]
        except (KeyError, TypeError, ValueError):
            raise RedfishSessionAuthenticationError("endpoint validation") from None
        self._binding_auth = binding_auth
        self._tls_kwargs = tls_policy.request_kwargs(ssl_parameter, use_https=True)
        self._collection_path: str | None = None
        self._resource_path: str | None = None
        self.token: str | None = None
        self._idle_timeout: float | None = None
        self._last_use = 0.0
        self._invalidated = False
        self.logins = 0
        self.creation_uncertain = False

    def _resource_link(self, value: Any, parent: str) -> str:
        """
        Resolve an advertised path or same-origin URL beneath its exact parent.

        Authority checks precede path normalization so an absolute link cannot
        redirect credentials or exact-resource cleanup to another endpoint.

        Args:
            value: Untrusted Redfish link or Location header.
            parent: Validated root or collection path that advertised the link.

        Returns:
            The validated absolute resource path without a query or fragment.

        Raises:
            RedfishSessionAuthenticationError: If the link escapes its binding.
        """

        try:
            if type(value) is not str or len(value) > 4096:
                raise ValueError("Invalid resource link")
            parsed = urlsplit(value)
            if parsed.scheme or parsed.netloc:
                if redfish_authentication_origin(value) != self.origin:
                    raise ValueError("Resource link changed authority")
                if parsed.query or parsed.fragment:
                    raise ValueError("Resource link contains a query or fragment")
                value = parsed.path
            return validate_redfish_uri_path(value, service_root=parent)
        except (TypeError, ValueError):
            raise RedfishSessionAuthenticationError("resource validation") from None

    async def discover(self, session: aiohttp.ClientSession, root: dict) -> bool:
        """
        Discover an advertised Sessions collection without creating a login.

        Missing advertisements, an explicitly disabled service, and unsupported
        HTTP statuses permit an automatic-mode caller to retain Basic
        authentication. Malformed links, authentication rejection, and other
        failures do not permit a downgrade.

        Args:
            session: Pool-owned HTTP transport with its existing connector.
            root: Bounded service-root document read during pool initialization.

        Returns:
            Whether a usable Sessions collection was advertised.

        Raises:
            RedfishSessionAuthenticationError: If discovery fails or is malformed.
            BaseException: If the caller interrupts the read-only operation.
        """

        direct_path = None
        try:
            root_links = root.get("Links", {})
            if root_links is None:
                root_links = {}
            direct_link = root_links.get("Sessions")
            if direct_link is not None:
                direct_path = self._resource_link(direct_link["@odata.id"], self._root)
        except (AttributeError, KeyError, TypeError):
            raise RedfishSessionAuthenticationError("discovery validation") from None

        advertised = root.get("SessionService")
        if advertised is None:
            self._collection_path = direct_path
            return direct_path is not None
        try:
            service_path = self._resource_link(advertised["@odata.id"], self._root)
        except (KeyError, TypeError):
            raise RedfishSessionAuthenticationError("discovery validation") from None
        async with session.get(
            self._base_url + service_path,
            headers=build_redfish_request_headers(
                self._binding_auth, {"Accept-Encoding": "identity"}
            ),
            timeout=aiohttp.ClientTimeout(total=AUTH_REQUEST_TIMEOUT_SECONDS),
            allow_redirects=False,
            auto_decompress=False,
            **self._tls_kwargs,
        ) as response:
            if response.status in _UNSUPPORTED_HTTP_STATUSES:
                await _read_authentication_body(response)
                self._collection_path = direct_path
                return direct_path is not None
            if response.status != 200:
                raise RedfishSessionAuthenticationError("discovery", response.status)
            document = await read_authentication_document(response)
        if document.get("ServiceEnabled") is False:
            self._collection_path = None
            return False
        advertised = document.get("Sessions")
        if advertised is None:
            self._collection_path = direct_path
            return direct_path is not None
        try:
            self._collection_path = self._resource_link(
                advertised["@odata.id"], service_path
            )
        except (KeyError, TypeError):
            raise RedfishSessionAuthenticationError("discovery validation") from None
        if direct_path is not None and direct_path != self._collection_path:
            raise RedfishSessionAuthenticationError("discovery link consistency")
        idle_timeout = document.get("SessionTimeout")
        if type(idle_timeout) is int and 0 < idle_timeout <= 2**31 - 1:
            self._idle_timeout = float(idle_timeout)
        return True

    async def login(self, session: aiohttp.ClientSession) -> None:
        """
        Create and own exactly one session before propagating owner cancellation.

        Login uses its existing finite request timeout. An interrupted owner
        drains that operation without cancelling it so a completed login can be
        logged out by the pool's cleanup before the interruption propagates.

        Args:
            session: Pool-owned HTTP transport used for this exact endpoint.

        Raises:
            RedfishSessionAuthenticationError: If discovery is absent, an old
                created resource remains owned, or the login response is invalid.
            BaseException: The observed login failure or caller interruption.
        """

        if (
            self._collection_path is None
            or self._resource_path is not None
            or self.creation_uncertain
        ):
            raise RedfishSessionAuthenticationError("login ownership")
        task = asyncio.create_task(capture_owned_awaitable(self._login(session)))
        outcomes = await drain_owned_tasks((task,), cancel_on_wait_error=False)
        if outcomes[0].error is not None:
            raise outcomes[0].error

    async def _login(self, session: aiohttp.ClientSession) -> None:
        """
        Publish the returned resource before consuming its bounded response body.

        Once the server identifies a created resource, cleanup owns it even if
        token validation or body reading fails. A lost response retains an
        explicit indeterminate-creation state that prevents another login.

        Args:
            session: Pool transport retained until this login has completed.

        Raises:
            RedfishSessionAuthenticationError: If the server rejects the login or
                returns an unsafe resource/token. A known resource stays owned
                even when token validation or subsequent body reading fails.
        """

        assert self._collection_path is not None
        # A lost POST response can leave a server-side session whose identifier
        # is unknown. Never hide that ambiguity or create another session on top.
        self.creation_uncertain = True
        async with session.post(
            self._base_url + self._collection_path,
            json={"UserName": self._username, "Password": self._password},
            headers={"Accept-Encoding": "identity"},
            timeout=aiohttp.ClientTimeout(total=AUTH_REQUEST_TIMEOUT_SECONDS),
            allow_redirects=False,
            auto_decompress=False,
            **self._tls_kwargs,
        ) as response:
            if response.status != 201:
                self.creation_uncertain = response.status >= 500
                raise RedfishSessionAuthenticationError("login", response.status)
            resource = self._resource_link(
                response.headers.get("Location"), self._collection_path
            )
            if resource.count("/") != self._collection_path.count("/") + 1:
                raise RedfishSessionAuthenticationError("login resource validation")
            self._resource_path = resource
            self.creation_uncertain = False
            token = response.headers.get("X-Auth-Token")
            try:
                if token is None:
                    raise ValueError("Missing session token")
                build_redfish_request_headers(self._binding_auth, auth_token=token)
            except ValueError:
                raise RedfishSessionAuthenticationError(
                    "login token validation"
                ) from None
            self.token = token
            await read_authentication_document(response)
        self._last_use = time.monotonic()
        self._invalidated = False
        self.logins += 1

    def needs_renewal(self) -> bool:
        """
        Check invalidation or idle expiry without performing remote operations.

        Unknown server timeouts rely on explicit unauthorized responses. Known
        timeouts include an idle margin; active requests keep using one token.

        Returns:
            Whether the next request must obtain a fresh token. A small margin
            refreshes before an advertised idle timeout rather than after it.
        """

        return (
            self.token is None
            or self._invalidated
            or (
                self._idle_timeout is not None
                and time.monotonic() - self._last_use
                >= max(1.0, self._idle_timeout * 0.8)
            )
        )

    def mark_used(self) -> None:
        """
        Record request admission without extending an already invalidated token.

        The pool calls this only after checking renewal under its lifecycle lock.
        """

        self._last_use = time.monotonic()

    def invalidate(self, observed_token: str) -> None:
        """
        Invalidate only the token that produced an unauthorized response.

        Concurrent requests may finish after another request has renewed the
        session. Comparing snapshots prevents those late failures from forcing
        another renewal of the replacement session.

        Args:
            observed_token: Snapshot sent on the completed request. A response
                using an older snapshot cannot invalidate a later successful login.
        """

        if self.token == observed_token:
            self._invalidated = True

    async def logout(self, session: aiohttp.ClientSession) -> None:
        """
        Delete only the exact created resource and retain ownership on failure.

        An expired token may be rejected before resource lookup. In that case a
        single Basic-authenticated fallback DELETE of the same owned resource
        confirms removal or absence. One timeout retry is shared across both
        authentication modes, for at most three individually bounded requests.
        A lost DELETE response can mean deletion already succeeded, so the retry
        accepts confirmed absence without creating a replacement session.

        Recovery completes inside this owner before the broader cleanup phase
        can fail and skip its remaining metadata work. Other failures and caller
        cancellation remain visible; ownership is cleared only after confirmed
        removal or absence.

        Args:
            session: Pool transport still bound to the original endpoint.

        Raises:
            RedfishSessionAuthenticationError: If logout is not confirmed.
            TimeoutError: If logout times out again after the single retry.
            BaseException: If transport or caller interruption prevents cleanup.
        """

        if self._resource_path is None:
            if self.creation_uncertain:
                raise RedfishSessionAuthenticationError("indeterminate login cleanup")
            self.token = None
            return
        use_token = self.token is not None
        timeout_retried = False
        for _ in range(LOGOUT_MAX_REQUESTS):
            try:
                async with session.delete(
                    self._base_url + self._resource_path,
                    headers=build_redfish_request_headers(
                        self._binding_auth,
                        {"Accept-Encoding": "identity"},
                        auth_token=self.token if use_token else None,
                    ),
                    timeout=aiohttp.ClientTimeout(total=AUTH_REQUEST_TIMEOUT_SECONDS),
                    allow_redirects=False,
                    auto_decompress=False,
                    **self._tls_kwargs,
                ) as response:
                    if response.status == 401 and use_token:
                        use_token = False
                        await _read_authentication_body(response)
                        continue
                    if response.status not in {200, 204, 404}:
                        raise RedfishSessionAuthenticationError(
                            "logout", response.status
                        )
                    await _read_authentication_body(response)
            except TimeoutError:
                if timeout_retried:
                    raise TimeoutError(
                        "Redfish session logout timed out after one retry"
                    ) from None
                timeout_retried = True
                logging.getLogger(__name__).warning(
                    "Redfish session logout timed out; retrying the same owned "
                    "session once"
                )
                continue
            self._resource_path = None
            self.token = None
            self._invalidated = False
            return
        raise RedfishSessionAuthenticationError("logout")
