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
Bounded transport policy and concurrency for the Redfish service facade.

The compatibility service still owns request capture, lifecycle timing, and
diagnostic logging. This module owns side-effect-free transport projections and
the small, injected boundary used to execute independent GET requests with
bounded concurrency.
"""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Set, Tuple

RedfishDispatch = Callable[..., Awaitable[Any]]
RuntimeLogger = Callable[[str, str, str, str], Awaitable[None]]
SensitiveNamePredicate = Callable[[str], bool]


@dataclass(frozen=True)
class RedfishAuxiliaryProjection:
    """
    Credential-free response headers and retry details from one request.

    The immutable record keeps ``response_headers`` and ``retry_details``
    together so consumers observe one Redfish auxiliary projection state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        response_headers: Mapping that retains the response headers fields for
            this record.
        retry_details: Mapping that retains the retry details fields for this
            record.
    """

    response_headers: Dict[str, Any]
    retry_details: Dict[str, Any]


def normalize_expected_http_statuses(value: Any) -> Set[int]:
    """
    Return the integer probe-miss statuses accepted by the facade today.

    The implementation uses ``value`` to produce the integer probe-miss statuses
    accepted by the facade today.

    Args:
        value: Value evaluated while performing integer probe-miss statuses
            accepted by the facade today.

    Returns:
        The validated ``normalized``.
    """

    candidates: Iterable[Any]
    if value is None:
        candidates = ()
    elif isinstance(value, (list, tuple, set)):
        candidates = value
    else:
        candidates = [value]

    normalized = set()
    for candidate in candidates:
        try:
            normalized.add(int(candidate))
        except (TypeError, ValueError):
            continue
    return normalized


def project_response_auxiliary(
    response_aux: Any,
    *,
    response_header_names: Set[str],
    max_scan_items: int,
    max_retry_items: int,
    max_field_name_chars: int,
    max_header_chars: int,
    max_header_integer_bits: int,
    is_sensitive_name: SensitiveNamePredicate,
) -> RedfishAuxiliaryProjection:
    """
    Project an exact dict into bounded response and retry metadata.

    Header names are compared case-insensitively. Extension mappings and
    extension scalar types are ignored so this boundary cannot invoke their
    conversion hooks while preparing diagnostic data.

    Args:
        response_aux: Entries supplied as ``response_aux`` and processed in
            caller-provided order.
        response_header_names: Entries supplied as ``response_header_names``
            without transferring container ownership.
        max_scan_items: Upper bound enforced for max scan items; the consuming
            boundary rejects or truncates values that exceed it.
        max_retry_items: Upper bound enforced for max retry items; the consuming
            boundary rejects or truncates values that exceed it.
        max_field_name_chars: Upper bound enforced for max field name chars; the
            consuming boundary rejects or truncates values that exceed it.
        max_header_chars: Upper bound enforced for max header chars; the
            consuming boundary rejects or truncates values that exceed it.
        max_header_integer_bits: Upper bound enforced for max header integer
            bits; the consuming boundary rejects or truncates values that exceed
            it.
        is_sensitive_name: Whether is sensitive name is enabled or required for
            this operation.

    Returns:
        A ``RedfishAuxiliaryProjection`` representing project response
        auxiliary.
    """

    response_headers: Dict[str, Any] = {}
    retry_details: Dict[str, Any] = {}
    if type(response_aux) is not dict:  # noqa: E721
        return RedfishAuxiliaryProjection(response_headers, retry_details)

    for index, (name, value) in enumerate(dict.items(response_aux)):
        if index >= max_scan_items:
            break
        if type(name) is not str:  # noqa: E721
            continue
        if len(name) > max_field_name_chars:
            continue
        if name.casefold() in response_header_names:
            if (
                (type(value) is str and len(value) <= max_header_chars)
                or (
                    type(value) is int
                    and int.bit_length(value) <= max_header_integer_bits
                )
                or (type(value) is float and math.isfinite(value))
            ):
                response_headers[name] = value
        elif len(retry_details) < max_retry_items and not is_sensitive_name(name):
            retry_details[name] = value

    return RedfishAuxiliaryProjection(response_headers, retry_details)


@dataclass(frozen=True)
class RedfishTransport:
    """
    Execute facade-supplied Redfish GET requests with bounded concurrency.

    The immutable record keeps ``dispatch``, ``log_runtime``, and
    ``component_name`` together so consumers observe one Redfish transport
    state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        dispatch: Dispatch retained as part of the record's public state.
        log_runtime: Log runtime retained as part of the record's public state.
        component_name: Canonical text used as component name.
    """

    dispatch: RedfishDispatch
    log_runtime: RuntimeLogger
    component_name: str = "RedfishService"

    async def concurrent_get_requests(
        self,
        dut_id: str,
        requests: List[Tuple[str, str]],
        *,
        max_concurrent: int,
        get_raw_content: bool = False,
        raw_content_max_bytes: Optional[int] = None,
    ) -> List[Any]:
        """
        Dispatch requests in input order and isolate ordinary failures.

        The implementation uses ``dut_id``, ``requests``, ``max_concurrent``,
        and ``get_raw_content`` to dispatch requests in input order and isolate
        ordinary failures. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            requests: Entries supplied as ``requests`` without transferring
                container ownership.
            max_concurrent: Upper bound enforced for max concurrent; the
                consuming boundary rejects or truncates values that exceed it.
            get_raw_content: Whether get raw content is enabled or required for
                this operation.
            raw_content_max_bytes: Optional byte ceiling enforced independently
                for each raw response body.

        Returns:
            The validated ``processed_results``.
        """

        semaphore = asyncio.Semaphore(max_concurrent)

        async def make_request(uri: str, error_context: str) -> Any:
            """
            Return the make request.

            After applying local validation, the function forwards ``uri`` and
            ``error_context`` to ``self.dispatch`` and preserves its return and
            exception contract. Owned asynchronous work is awaited before
            return, so completion does not leave an unobserved task behind.

            Args:
                uri: Validated remote resource identifier used for URI.
                error_context: Text supplied as error context in the format
                    accepted by this function.

            Returns:
                The make request selected by this operation.
            """
            async with semaphore:
                request_options = {}
                if raw_content_max_bytes is not None:
                    request_options["raw_content_max_bytes"] = raw_content_max_bytes
                return await self.dispatch(
                    dut_id,
                    "GET",
                    uri,
                    error_context=error_context,
                    bypass_cache=True,
                    get_raw_content=get_raw_content,
                    **request_options,
                )

        tasks = [make_request(uri, context) for uri, context in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results: List[Any] = []
        for index, result in enumerate(results):
            if isinstance(result, Exception):
                await self.log_runtime(
                    "ERROR",
                    self.component_name,
                    f"Request {index + 1} failed: {str(result)}",
                    dut_id,
                )
                processed_results.append((False, {"error": str(result)}))
            else:
                processed_results.append(result)
        return processed_results
