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
Strict schema for catalog-owned DGX diagnostic-log routing.

This module owns the dgx diagnostic routing profile boundary and exposes
``DgxDiagnosticRoutingProfileError``, ``_require_exact_keys``,
``_require_string``, ``_require_resource_key``, and
``validate_redfish_relative_segment``. Keeping those contracts together gives
importers one source of truth for their validation, lifecycle, and compatibility
behavior.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Collection, Mapping
from typing import Any, Dict, List
from urllib.parse import unquote

DGX_DIAGNOSTIC_ROUTING_PROFILE_KEY = "dgx_diagnostic_routing_profile"
DGX_DIAGNOSTIC_ROUTING_PROFILE_VERSION = 1

_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_RESOURCE_KEY_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@%\-]+$")
_ACTION_NAME_PATTERN = re.compile(
    r"^#[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)
_INVALID_PERCENT_ESCAPE_PATTERN = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PERCENT_ESCAPE_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")

_MAX_ROUTES = 64
_MAX_NAME_LENGTH = 128
_MAX_LIST_ITEMS = 64
_MAX_SEGMENT_LENGTH = 256


class DgxDiagnosticRoutingProfileError(ValueError):
    """
    Raised when catalog-owned DGX diagnostic routing is invalid.

    Callers receive this exception when the dgx diagnostic routing profile error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _require_exact_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    context: str,
) -> None:
    """
    Require exact keys.

    The implementation uses ``value``, ``required``, and ``context`` to require
    exact keys. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        value: Mapping supplying fields for exact keys.
        required: Entries supplied as ``required`` without transferring
            container ownership.
        context: Runtime context carrying state shared across this operation.

    Raises:
        DgxDiagnosticRoutingProfileError: If the function cannot require exact
            keys safely.
    """
    observed = set(value)
    missing = required - observed
    unsupported = observed - required
    if missing:
        raise DgxDiagnosticRoutingProfileError(
            f"{context} is missing required keys: "
            + ", ".join(sorted(str(key) for key in missing))
        )
    if unsupported:
        raise DgxDiagnosticRoutingProfileError(
            f"{context} has unsupported keys: "
            + ", ".join(sorted(str(key) for key in unsupported))
        )


def _require_string(value: Any, *, context: str, max_length: int) -> str:
    """
    Require string.

    The implementation uses ``value``, ``context``, and ``max_length`` to
    require string. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        value: Value object whose ``strip`` state is read while performing
            string.
        context: Runtime context carrying state shared across this operation.
        max_length: Upper bound enforced for max length; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The validated ``value``.

    Raises:
        DgxDiagnosticRoutingProfileError: If the ``context`` is not a non-empty
            string.
    """
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
    ):
        raise DgxDiagnosticRoutingProfileError(f"{context} must be a non-empty string")
    return value


def _require_resource_key(
    value: Any,
    *,
    context: str,
    allowed_collection_uri_keys: Collection[str] | None,
) -> str:
    """
    Require resource key.

    The implementation uses ``value``, ``context``, and
    ``allowed_collection_uri_keys`` to require resource key. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing resource key.
        context: Runtime context carrying state shared across this operation.
        allowed_collection_uri_keys: Validated remote resource identifier used
            for allowed collection URI keys.

    Returns:
        The validated ``key``.

    Raises:
        DgxDiagnosticRoutingProfileError: If the ``context`` is not a Redfish
            resource identifier; or ``context`` references unknown Redfish
            topology resource ``key``.
    """
    key = _require_string(value, context=context, max_length=_MAX_NAME_LENGTH)
    if not _RESOURCE_KEY_PATTERN.fullmatch(key):
        raise DgxDiagnosticRoutingProfileError(
            f"{context} must be a Redfish resource identifier"
        )
    if allowed_collection_uri_keys is not None and key not in set(
        allowed_collection_uri_keys
    ):
        raise DgxDiagnosticRoutingProfileError(
            f"{context} references unknown Redfish topology resource {key!r}"
        )
    return key


def validate_redfish_relative_segment(value: Any, *, context: str) -> str:
    """
    Validate one unambiguous Redfish URI path segment.

    The implementation uses ``value`` and ``context`` to validate one
    unambiguous Redfish URI path segment. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        value: Value evaluated while performing one unambiguous Redfish URI path
            segment.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``segment``.

    Raises:
        DgxDiagnosticRoutingProfileError: If the ``context`` is not one
            normalized query-free URI segment; ``context`` contains an invalid
            UTF-8 escape; or ``context`` contains an unsafe or ambiguous encoded
            segment.
    """

    segment = _require_string(
        value,
        context=context,
        max_length=_MAX_SEGMENT_LENGTH,
    )
    if (
        segment in {".", ".."}
        or "/" in segment
        or "\\" in segment
        or "?" in segment
        or "#" in segment
        or any(character.isspace() or ord(character) < 32 for character in segment)
        or not _SEGMENT_PATTERN.fullmatch(segment)
        or _INVALID_PERCENT_ESCAPE_PATTERN.search(segment)
    ):
        raise DgxDiagnosticRoutingProfileError(
            f"{context} must be one normalized query-free URI segment"
        )
    try:
        decoded = unquote(segment, errors="strict")
    except UnicodeDecodeError as error:
        raise DgxDiagnosticRoutingProfileError(
            f"{context} contains an invalid UTF-8 escape"
        ) from error
    if (
        decoded in {".", ".."}
        or "/" in decoded
        or "\\" in decoded
        or "?" in decoded
        or "#" in decoded
        or any(character.isspace() or ord(character) < 32 for character in decoded)
        or not _SEGMENT_PATTERN.fullmatch(decoded)
        or _INVALID_PERCENT_ESCAPE_PATTERN.search(decoded)
        or _PERCENT_ESCAPE_PATTERN.search(decoded)
    ):
        raise DgxDiagnosticRoutingProfileError(
            f"{context} contains an unsafe or ambiguous encoded segment"
        )
    return segment


def _require_string_list(
    value: Any,
    *,
    context: str,
    validator,
    unique: bool = True,
) -> List[str]:
    """
    Require string list.

    The implementation uses ``value``, ``context``, ``validator``, and
    ``unique`` to require string list. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.
        context: Runtime context carrying state shared across this operation.
        validator: Validator consumed while the function attempts to require
            string list.
        unique: Whether unique is enabled or required for this operation.

    Returns:
        The validated ``normalized``.

    Raises:
        DgxDiagnosticRoutingProfileError: If the ``context`` is not a non-empty
            bounded list; or ``context`` contains duplicate value
            ``normalized_item``.
    """
    if not isinstance(value, list) or not value or len(value) > _MAX_LIST_ITEMS:
        raise DgxDiagnosticRoutingProfileError(
            f"{context} must be a non-empty bounded list"
        )
    normalized: List[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        normalized_item = validator(item, context=f"{context}[{index}]")
        if unique and normalized_item in seen:
            raise DgxDiagnosticRoutingProfileError(
                f"{context} contains duplicate value {normalized_item!r}"
            )
        seen.add(normalized_item)
        normalized.append(normalized_item)
    return normalized


def _validate_action_name(value: Any, *, context: str) -> str:
    """
    Validate action name.

    The implementation uses ``value`` and ``context`` to validate action name.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing action name.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``name``.

    Raises:
        DgxDiagnosticRoutingProfileError: If the ``context`` is not a qualified
            Redfish action name.
    """
    name = _require_string(value, context=context, max_length=_MAX_SEGMENT_LENGTH)
    if not _ACTION_NAME_PATTERN.fullmatch(name):
        raise DgxDiagnosticRoutingProfileError(
            f"{context} must be a qualified Redfish action name"
        )
    return name


def validate_dgx_diagnostic_routing_profile(
    value: Any,
    *,
    allowed_collection_uri_keys: Collection[str] | None = None,
) -> Dict[str, Any]:
    """
    Validate and normalize the versioned DGX diagnostic routing profile.

    The implementation uses ``value`` and ``allowed_collection_uri_keys`` to
    validate and normalize the versioned DGX diagnostic routing profile. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        value: Mapping supplying fields for and normalize the versioned DGX
            diagnostic routing profile.
        allowed_collection_uri_keys: Validated remote resource identifier used
            for allowed collection URI keys.

    Returns:
        A mapping containing the ``version`` and ``routes`` fields.

    Raises:
        DgxDiagnosticRoutingProfileError: If the ``context`` is not a mapping;
            ``context`` has an unsupported version; the ``context``.routes are
            not a non-empty bounded mapping; or ``context``.routes route name
            ``name`` is invalid; or another input invariant is violated.
    """

    context = DGX_DIAGNOSTIC_ROUTING_PROFILE_KEY
    if not isinstance(value, Mapping):
        raise DgxDiagnosticRoutingProfileError(f"{context} must be a mapping")
    _require_exact_keys(value, required={"version", "routes"}, context=context)

    version = value["version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != DGX_DIAGNOSTIC_ROUTING_PROFILE_VERSION
    ):
        raise DgxDiagnosticRoutingProfileError(f"{context} has an unsupported version")

    raw_routes = value["routes"]
    if (
        not isinstance(raw_routes, Mapping)
        or not raw_routes
        or len(raw_routes) > _MAX_ROUTES
    ):
        raise DgxDiagnosticRoutingProfileError(
            f"{context}.routes must be a non-empty bounded mapping"
        )

    routes: Dict[str, Any] = {}
    for raw_name, raw_route in raw_routes.items():
        name = _require_string(
            raw_name,
            context=f"{context}.routes route name",
            max_length=_MAX_NAME_LENGTH,
        )
        if not _NAME_PATTERN.fullmatch(name):
            raise DgxDiagnosticRoutingProfileError(
                f"{context}.routes route name {name!r} is invalid"
            )
        route_context = f"{context}.routes.{name}"
        if not isinstance(raw_route, Mapping):
            raise DgxDiagnosticRoutingProfileError(f"{route_context} must be a mapping")
        _require_exact_keys(
            raw_route,
            required={"eligibility", "resource", "action"},
            context=route_context,
        )

        raw_eligibility = raw_route["eligibility"]
        eligibility_context = f"{route_context}.eligibility"
        if not isinstance(raw_eligibility, Mapping):
            raise DgxDiagnosticRoutingProfileError(
                f"{eligibility_context} must be a mapping"
            )
        _require_exact_keys(
            raw_eligibility,
            required={"collection_uri_key", "member_ids"},
            context=eligibility_context,
        )
        eligibility = {
            "collection_uri_key": _require_resource_key(
                raw_eligibility["collection_uri_key"],
                context=f"{eligibility_context}.collection_uri_key",
                allowed_collection_uri_keys=allowed_collection_uri_keys,
            ),
            "member_ids": _require_string_list(
                raw_eligibility["member_ids"],
                context=f"{eligibility_context}.member_ids",
                validator=validate_redfish_relative_segment,
            ),
        }

        raw_resource = raw_route["resource"]
        resource_context = f"{route_context}.resource"
        if not isinstance(raw_resource, Mapping):
            raise DgxDiagnosticRoutingProfileError(
                f"{resource_context} must be a mapping"
            )
        _require_exact_keys(
            raw_resource,
            required={"collection_uri_key", "member_id", "relative_segments"},
            context=resource_context,
        )
        resource = {
            "collection_uri_key": _require_resource_key(
                raw_resource["collection_uri_key"],
                context=f"{resource_context}.collection_uri_key",
                allowed_collection_uri_keys=allowed_collection_uri_keys,
            ),
            "member_id": validate_redfish_relative_segment(
                raw_resource["member_id"],
                context=f"{resource_context}.member_id",
            ),
            "relative_segments": _require_string_list(
                raw_resource["relative_segments"],
                context=f"{resource_context}.relative_segments",
                validator=validate_redfish_relative_segment,
                unique=False,
            ),
        }

        raw_action = raw_route["action"]
        action_context = f"{route_context}.action"
        if not isinstance(raw_action, Mapping):
            raise DgxDiagnosticRoutingProfileError(
                f"{action_context} must be a mapping"
            )
        _require_exact_keys(
            raw_action,
            required={"advertised_names", "fallback_relative_segments"},
            context=action_context,
        )
        action = {
            "advertised_names": _require_string_list(
                raw_action["advertised_names"],
                context=f"{action_context}.advertised_names",
                validator=_validate_action_name,
            ),
            "fallback_relative_segments": _require_string_list(
                raw_action["fallback_relative_segments"],
                context=f"{action_context}.fallback_relative_segments",
                validator=validate_redfish_relative_segment,
                unique=False,
            ),
        }

        routes[name] = {
            "eligibility": eligibility,
            "resource": resource,
            "action": action,
        }

    return {"version": version, "routes": routes}


def get_dgx_diagnostic_route(value: Any, route_name: Any) -> Dict[str, Any]:
    """
    Return a defensive copy of one validated named route.

    After applying local validation, the function forwards ``value`` and
    ``route_name`` to ``copy.deepcopy`` and preserves its return and exception
    contract.

    Args:
        value: Value evaluated while performing defensive copy of one validated
            named route.
        route_name: Stable route name used for lookup and operator-facing
            diagnostics.

    Returns:
        A mapping containing dgx diagnostic route.

    Raises:
        DgxDiagnosticRoutingProfileError: If DGX diagnostic route name ``name``
            is invalid; or unknown DGX diagnostic route ``name``.
    """

    name = _require_string(
        route_name,
        context="DGX diagnostic route name",
        max_length=_MAX_NAME_LENGTH,
    )
    if not _NAME_PATTERN.fullmatch(name):
        raise DgxDiagnosticRoutingProfileError(
            f"DGX diagnostic route name {name!r} is invalid"
        )
    profile = validate_dgx_diagnostic_routing_profile(value)
    try:
        return copy.deepcopy(profile["routes"][name])
    except KeyError as error:
        raise DgxDiagnosticRoutingProfileError(
            f"unknown DGX diagnostic route {name!r}"
        ) from error


def validate_dgx_diagnostic_route_hooks(
    collectors: Any,
    profile: Any,
) -> None:
    """
    Validate every execution hook that binds a catalog DGX route.

    ``collect_dgx_diagnostic_data`` owns its complete route and declares it at
    hook level. ``collect_diagnostic_data`` may opt into only the route's
    eligibility probe through ``params.eligibility_route`` while retaining its
    authored endpoint and payload. Other methods cannot bind either field.

    Args:
        collectors: Collector definitions containing execution hooks.
        profile: Catalog DGX diagnostic routing profile.

    Raises:
        DgxDiagnosticRoutingProfileError: If the collectors are not a mapping;
            a route binding is declared on an unsupported method; collector
            ``collector_id`` declares multiple collect_dgx_diagnostic_data
            hooks; a full route is nested in params; or a named route is
            unknown.
    """

    validated_profile = validate_dgx_diagnostic_routing_profile(profile)
    if not isinstance(collectors, Mapping):
        raise DgxDiagnosticRoutingProfileError("collectors must be a mapping")

    for collector_id, collector in collectors.items():
        if not isinstance(collector, Mapping):
            continue
        stages = collector.get("stages", {})
        execution = stages.get("execution", {}) if isinstance(stages, Mapping) else {}
        hooks = execution.get("hooks", []) if isinstance(execution, Mapping) else []
        if not isinstance(hooks, list):
            continue
        dgx_hook_count = 0
        for hook_index, hook in enumerate(hooks):
            if not isinstance(hook, Mapping):
                continue
            hook_context = f"collector {collector_id} execution hook {hook_index}"
            method = hook.get("method")
            route_present = "route" in hook
            params = hook.get("params", {})
            eligibility_route_present = (
                isinstance(params, Mapping) and "eligibility_route" in params
            )

            if method == "collect_diagnostic_data":
                if route_present or (
                    isinstance(params, Mapping) and "route" in params
                ):
                    raise DgxDiagnosticRoutingProfileError(
                        f"{hook_context} cannot declare a full DGX diagnostic route"
                    )
                if eligibility_route_present:
                    get_dgx_diagnostic_route(
                        validated_profile, params["eligibility_route"]
                    )
                continue

            if method != "collect_dgx_diagnostic_data":
                if route_present or eligibility_route_present:
                    raise DgxDiagnosticRoutingProfileError(
                        f"{hook_context} cannot declare a DGX diagnostic route"
                    )
                continue

            dgx_hook_count += 1
            if dgx_hook_count > 1:
                raise DgxDiagnosticRoutingProfileError(
                    f"collector {collector_id} must declare at most one "
                    "collect_dgx_diagnostic_data hook"
                )

            if isinstance(params, Mapping) and "route" in params:
                raise DgxDiagnosticRoutingProfileError(
                    f"{hook_context} must declare route at hook level, not in params"
                )
            if eligibility_route_present:
                raise DgxDiagnosticRoutingProfileError(
                    f"{hook_context} cannot combine route with eligibility_route"
                )
            if not route_present:
                raise DgxDiagnosticRoutingProfileError(
                    f"{hook_context} is missing required route"
                )
            route_name = hook["route"]
            get_dgx_diagnostic_route(validated_profile, route_name)
