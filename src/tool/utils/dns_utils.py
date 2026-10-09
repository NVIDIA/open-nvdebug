#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
DNS and hostname helpers.

These helpers are intentionally side-effect free and return the original input
when forward DNS is unavailable, which lets dry-run and offline parsing paths
continue to produce usable hostnames.
"""

import ipaddress
import socket
from functools import lru_cache
from typing import Any, Optional


def is_ip_literal(value: Any) -> bool:
    """
    Return True when value is an IPv4 or IPv6 address literal.

    The implementation uses ``value`` to produce True when value is an IPv4 or
    IPv6 address literal.

    Args:
        value: Value evaluated while performing true when value is an IPv4 or
            IPv6 address literal.

    Returns:
        Whether the true when value is an IPv4 or IPv6 address literal operation
        succeeds.
    """
    try:
        ipaddress.ip_address(str(value).strip().strip("[]"))
        return True
    except ValueError:
        return False


def short_hostname_from_fqdn(value: Any) -> Optional[str]:
    """
    Return the first DNS label for a hostname, or None for IP literals.

    The implementation uses ``value`` to produce the first DNS label for a
    hostname, or None for IP literals.

    Args:
        value: Value evaluated while performing first DNS label for a hostname,
            or None for IP literals.

    Returns:
        The canonical short hostname from fqdn text, or ``None`` when the
        requested value is unavailable.
    """
    hostname = str(value or "").strip()
    if not hostname or is_ip_literal(hostname):
        return None
    return hostname.split(".", 1)[0]


@lru_cache(maxsize=512)
def reverse_lookup_hostname(address: str) -> Optional[str]:
    """
    Resolve an IP address to its DNS hostname.

    The implementation uses ``address`` to resolve an IP address to its DNS
    hostname.

    Args:
        address: Text supplied as address in the format accepted by this
            function.

    Returns:
        Whether the iP address to its DNS hostname operation succeeds.
    """
    value = str(address or "").strip().strip("[]")
    if not value or not is_ip_literal(value):
        return None

    try:
        hostname, _, _ = socket.gethostbyaddr(value)
    except (OSError, socket.error, socket.herror, socket.gaierror):
        return None

    hostname = str(hostname or "").strip()
    return hostname or None


@lru_cache(maxsize=512)
def reverse_lookup_short_hostname(address: str) -> Optional[str]:
    """
    Resolve an IP address to the short DNS hostname.

    After applying local validation, the function forwards ``address`` to
    ``short_hostname_from_fqdn`` and preserves its return and exception
    contract.

    Args:
        address: Text supplied as address in the format accepted by this
            function.

    Returns:
        The canonical reverse lookup short hostname, or ``None`` when the
        requested value is unavailable.
    """
    return short_hostname_from_fqdn(reverse_lookup_hostname(address))


@lru_cache(maxsize=1024)
def resolve_hostname_to_ip(address: str, prefer_ipv4: bool = True) -> str:
    """
    Resolve a hostname to an IP address.

    If address is already an IP literal, or DNS lookup fails, return address.

    Args:
        address: Text supplied as address in the format accepted by this
            function.
        prefer_ipv4: Whether prefer ipv4 is enabled or required for this
            operation.

    Returns:
        The canonical hostname to IP text.
    """
    value = str(address or "").strip()
    if not value or is_ip_literal(value):
        return value

    try:
        results = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except (OSError, socket.error, socket.gaierror):
        return value

    first_ip: Optional[str] = None
    for family, _, _, _, sockaddr in results:
        if not sockaddr:
            continue
        resolved = str(sockaddr[0])
        if not first_ip:
            first_ip = resolved
        if prefer_ipv4 and family == socket.AF_INET:
            return resolved

    return first_ip or value
