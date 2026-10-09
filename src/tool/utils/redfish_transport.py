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
Shared helpers for bounded Redfish HTTP transport behavior.

This module owns the redfish transport boundary and exposes
``encode_basic_auth_header``, ``build_redfish_request_headers``, and
``normalize_redfish_content_type``. Keeping those contracts together gives
importers one source of truth for authentication, validation, and compatibility
behavior.
"""

import base64
import ipaddress
import re
from collections.abc import Mapping
from typing import Any, Optional

REDFISH_CONTENT_TYPE_MAX_INPUT_LENGTH = 512
REDFISH_CONTENT_TYPE_MAX_LENGTH = 127
# Transport metadata may describe a streamed artifact larger than the old
# in-memory 500 MiB ceiling.  Keep the JSON-safe value within signed 64-bit
# bounds; actual raw-body safety is enforced by private spool free-space checks.
REDFISH_TRANSPORT_CONTENT_LENGTH_MAX_BYTES = (1 << 63) - 1
_REDFISH_CONTENT_TYPE_PATTERN = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+*-]*/[a-z0-9][a-z0-9!#$&^_.+*-]*"
)


def format_redfish_url_host(host: str) -> str:
    """
    Bracket IPv6 literals at the HTTP URL boundary without changing socket hosts.

    Bare and already bracketed literals produce the same URL host. Preserve a
    link-local scope such as ``%eth0`` verbatim: aiohttp passes that identifier
    to the local resolver, so URL-escaping it would select another interface.
    DNS names and IPv4 addresses retain their existing spelling. This formatter
    does not replace the endpoint or request-path validation owned by callers.

    Args:
        host: Configured host without a port, optionally bracketed for IPv6.

    Returns:
        A bracketed IPv6 literal or the unchanged non-IPv6 input.
    """

    address = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.IPv6Address(address)
    except ValueError:
        return host
    return f"[{address}]"


def encode_basic_auth_header(username: str, password: str) -> str:
    """
    Encode Redfish credentials as an HTTP ``Authorization`` header value.

    Build the header with the standard library instead of depending on an
    aiohttp authentication helper. The legacy ``latin1`` encoding preserves
    the byte-level behavior of ``aiohttp.BasicAuth`` used by earlier NVDebug
    releases.

    Args:
        username: Redfish account name supplied to HTTP Basic authentication.
        password: Redfish password retained only long enough to encode the
            request header.

    Returns:
        A value suitable for the HTTP ``Authorization`` header.

    Raises:
        ValueError: If the username contains a colon and cannot be represented
            by HTTP Basic authentication.
        UnicodeEncodeError: If either credential cannot be encoded as latin-1.
    """

    if username is None:
        raise ValueError("None is not allowed as username value")
    if password is None:
        raise ValueError("None is not allowed as password value")
    if ":" in username:
        raise ValueError('A ":" is not allowed in username')

    credentials = f"{username}:{password}".encode("latin1")
    encoded_credentials = base64.b64encode(credentials).decode("ascii")
    return f"Basic {encoded_credentials}"


def build_redfish_request_headers(
    auth_header: Optional[str],
    base_headers: Optional[Mapping[str, str]] = None,
    *,
    auth_token: Optional[str] = None,
) -> dict[str, str]:
    """
    Build per-request headers from the endpoint's explicit authentication state.

    The returned mapping is always a copy. Every case variant of a caller's
    ``Authorization`` and ``X-Auth-Token`` entries are removed. An owned token
    replaces Basic authentication only while the endpoint still has an enabled
    credential binding. A stale base mapping cannot select different credentials
    or silently re-enable authentication.

    Args:
        auth_header: Encoded authorization value, or ``None`` for anonymous
            Redfish access. It also binds an optional token to enabled
            authentication; the Basic value is not sent alongside a token.
        base_headers: Optional non-authentication request headers to preserve.
        auth_token: Validated pool-owned session token, or ``None`` to retain
            Basic or anonymous authentication.

    Returns:
        A new mutable header mapping for one aiohttp request.

    Raises:
        ValueError: If a token is supplied without an enabled credential binding,
            is empty or oversized, or contains non-printable header characters.
    """

    headers = {
        name: value
        for name, value in (base_headers or {}).items()
        if name.lower() not in {"authorization", "x-auth-token"}
    }
    if auth_token is not None:
        if (
            not auth_header
            or type(auth_token) is not str
            or not 0 < len(auth_token) <= 8192
            or any(not 33 <= ord(character) <= 126 for character in auth_token)
        ):
            raise ValueError("Invalid Redfish session authentication state")
        headers["X-Auth-Token"] = auth_token
    elif auth_header is not None:
        headers["Authorization"] = auth_header
    return headers


def normalize_redfish_content_type(value: Any) -> Optional[str]:
    """
    Return a bounded normalized media type, or ``None`` when invalid.

    The implementation uses ``value`` to produce a bounded normalized media
    type, or ``None`` when invalid.

    Args:
        value: Value object whose ``split`` state is read while performing
            bounded normalized media type, or ``None`` when invalid.

    Returns:
        The validated ``content_type``, or ``None`` when no value qualifies.
    """
    if (
        not isinstance(value, str)
        or not value
        or len(value) > REDFISH_CONTENT_TYPE_MAX_INPUT_LENGTH
    ):
        return None

    content_type = value.split(";", 1)[0].strip().lower()
    if (
        not content_type
        or len(content_type) > REDFISH_CONTENT_TYPE_MAX_LENGTH
        or _REDFISH_CONTENT_TYPE_PATTERN.fullmatch(content_type) is None
    ):
        return None
    return content_type
