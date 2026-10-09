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
Provide the ansible inventory profile implementation for the NVDebug runtime.

Provide the ansible inventory profile implementation for the NVDebug runtime.

This module owns the ansible inventory profile boundary and exposes
``AnsibleInventoryProfileError``, ``_require_exact_keys``, ``_validate_fields``,
``_validate_node_types``, and ``validate_ansible_inventory_profile``. Keeping
those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Dict

ANSIBLE_INVENTORY_PROFILE_KEY = "ansible_inventory_profile"
ANSIBLE_INVENTORY_PROFILE_VERSION = 1

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NORMALIZED_NODE_ALIAS_PATTERN = re.compile(r"^[a-z0-9]+$")
_MAX_ALIAS_LENGTH = 128
_MAX_ALIASES_PER_TIER = 64
_MAX_LOOKUP_TIERS = 8

_FIELD_KINDS = {
    "hostname": "name",
    "bmc_address": "address",
    "bmc_username": "username",
    "bmc_password": "password",
    "bmc_ssh_username": "username",
    "bmc_ssh_password": "password",
    "bmc_ssh_private_key": "private_key",
    "redfish_username": "username",
    "redfish_password": "password",
    "host_address": "address",
    "host_username": "username",
    "host_password": "password",
    "host_ssh_private_key": "private_key",
}
CANONICAL_ANSIBLE_INVENTORY_FIELDS = tuple(_FIELD_KINDS)
CANONICAL_ANSIBLE_NODE_TYPES = ("SwitchTray", "Compute", "PowerShelf")


# Pinned compatibility behavior for catalogs generated before the profile row
# existed. Runtime callers always pass this through the validator, which returns
# a fresh structure, so the process-wide compatibility constant is not mutated.
DEFAULT_ANSIBLE_INVENTORY_PROFILE: Dict[str, Any] = {
    "version": 1,
    "fields": {
        "hostname": {"lookup_tiers": [{"aliases": ["hostname"]}]},
        "bmc_address": {
            "lookup_tiers": [
                {
                    "aliases": [
                        "ansible_bmc_host",
                        "bmc_host",
                        "bmc_ip",
                        "BMC_IP",
                    ]
                }
            ]
        },
        "bmc_username": {
            "lookup_tiers": [
                {
                    "aliases": [
                        "ansible_bmc_user",
                        "bmc_user",
                        "bmc_username",
                    ]
                },
                {"aliases": ["ansible_user"]},
            ]
        },
        "bmc_password": {
            "lookup_tiers": [
                {
                    "aliases": [
                        "ansible_bmc_pass",
                        "bmc_pass",
                        "bmc_password",
                        "ansible_bmc_password",
                    ]
                },
                {"aliases": ["ansible_ssh_pass"]},
            ]
        },
        "bmc_ssh_username": {
            "lookup_tiers": [{"aliases": ["bmc_ssh_user", "bmc_ssh_username"]}],
            "fallback_field": "bmc_username",
        },
        "bmc_ssh_password": {
            "lookup_tiers": [{"aliases": ["bmc_ssh_password", "bmc_ssh_pass"]}],
            "fallback_field": "bmc_password",
        },
        "bmc_ssh_private_key": {
            "lookup_tiers": [
                {
                    "aliases": [
                        "ansible_bmc_ssh_private_key_file",
                        "ansible_bmc_ssh_key_path",
                        "bmc_ssh_key_path",
                        "BMC_SSH_KEY_PATH",
                    ]
                }
            ]
        },
        "redfish_username": {
            "lookup_tiers": [
                {
                    "aliases": [
                        "RF_User",
                        "bmc_rf_user",
                        "redfish_user",
                        "rf_user",
                    ]
                }
            ],
            "fallback_field": "bmc_username",
        },
        "redfish_password": {
            "lookup_tiers": [
                {
                    "aliases": [
                        "RF_Pass",
                        "bmc_rf_pass",
                        "redfish_password",
                        "redfish_pass",
                        "rf_pass",
                    ]
                }
            ],
            "fallback_field": "bmc_password",
        },
        "host_address": {
            "lookup_tiers": [{"aliases": ["ansible_host", "host_ip", "HOST_IP"]}]
        },
        "host_username": {
            "lookup_tiers": [
                {"aliases": ["host_user", "host_username", "ansible_user"]}
            ]
        },
        "host_password": {
            "lookup_tiers": [
                {
                    "aliases": [
                        "host_password",
                        "host_pass",
                        "ansible_password",
                        "ansible_ssh_pass",
                    ]
                }
            ]
        },
        "host_ssh_private_key": {
            "lookup_tiers": [
                {
                    "aliases": [
                        "ansible_ssh_private_key_file",
                        "host_ssh_key_path",
                        "HOST_SSH_KEY_PATH",
                    ]
                }
            ]
        },
    },
    "node_types": {
        "aliases": {
            "switch": "SwitchTray",
            "switchtray": "SwitchTray",
            "compute": "Compute",
            "singlenode": "Compute",
            "powershelf": "PowerShelf",
        },
        "order": ["SwitchTray", "Compute", "PowerShelf"],
    },
}


class AnsibleInventoryProfileError(ValueError):
    """
    Raised when catalog-owned inventory interpretation policy is invalid.

    Callers receive this exception when the ansible inventory profile error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _require_exact_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    context: str,
) -> None:
    """
    Require exact keys.

    The implementation uses ``value``, ``required``, ``optional``, and
    ``context`` to require exact keys. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        value: Mapping supplying fields for exact keys.
        required: Entries supplied as ``required`` without transferring
            container ownership.
        optional: Optional; ``None`` selects the function's default
            behavior.
        context: Runtime context carrying state shared across this operation.

    Raises:
        AnsibleInventoryProfileError: If the function cannot require exact keys
            safely.
    """
    optional = optional or set()
    observed = set(value)
    missing = required - observed
    unsupported = observed - required - optional
    if missing:
        raise AnsibleInventoryProfileError(
            f"{context} is missing required keys: "
            + ", ".join(sorted(str(key) for key in missing))
        )
    if unsupported:
        raise AnsibleInventoryProfileError(
            f"{context} has unsupported keys: "
            + ", ".join(sorted(str(key) for key in unsupported))
        )


def _validate_fields(value: Any) -> Dict[str, Dict[str, Any]]:
    """
    Validate fields.

    The implementation uses ``value`` to validate fields. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        value: Mapping supplying fields for fields.

    Returns:
        The validated ``normalized``.

    Raises:
        AnsibleInventoryProfileError: If the fields are not a mapping; the
            function cannot validate fields safely; the fields.``field_name`` is
            not a mapping; or the fields.``field_name``.lookup_tiers are not a
            non-empty list; or another input invariant is violated.
    """
    if not isinstance(value, Mapping):
        raise AnsibleInventoryProfileError("fields must be a mapping")

    expected_fields = set(CANONICAL_ANSIBLE_INVENTORY_FIELDS)
    observed_fields = set(value)
    missing = expected_fields - observed_fields
    unsupported = observed_fields - expected_fields
    if missing:
        raise AnsibleInventoryProfileError(
            "fields is missing canonical entries: "
            + ", ".join(sorted(str(key) for key in missing))
        )
    if unsupported:
        raise AnsibleInventoryProfileError(
            "fields has unsupported canonical entries: "
            + ", ".join(sorted(str(key) for key in unsupported))
        )

    normalized: Dict[str, Dict[str, Any]] = {}
    fallbacks: Dict[str, str] = {}
    for field_name in CANONICAL_ANSIBLE_INVENTORY_FIELDS:
        field_value = value[field_name]
        if not isinstance(field_value, Mapping):
            raise AnsibleInventoryProfileError(f"fields.{field_name} must be a mapping")
        _require_exact_keys(
            field_value,
            required={"lookup_tiers"},
            optional={"fallback_field"},
            context=f"fields.{field_name}",
        )

        raw_tiers = field_value["lookup_tiers"]
        if not isinstance(raw_tiers, list) or not raw_tiers:
            raise AnsibleInventoryProfileError(
                f"fields.{field_name}.lookup_tiers must be a non-empty list"
            )
        if len(raw_tiers) > _MAX_LOOKUP_TIERS:
            raise AnsibleInventoryProfileError(
                f"fields.{field_name}.lookup_tiers exceeds the supported limit"
            )

        seen_aliases: set[str] = set()
        normalized_tiers = []
        for tier_index, raw_tier in enumerate(raw_tiers):
            context = f"fields.{field_name}.lookup_tiers[{tier_index}]"
            if not isinstance(raw_tier, Mapping):
                raise AnsibleInventoryProfileError(f"{context} must be a mapping")
            _require_exact_keys(
                raw_tier,
                required={"aliases"},
                context=context,
            )
            aliases = raw_tier["aliases"]
            if not isinstance(aliases, list) or not aliases:
                raise AnsibleInventoryProfileError(
                    f"{context}.aliases must be a non-empty list"
                )
            if len(aliases) > _MAX_ALIASES_PER_TIER:
                raise AnsibleInventoryProfileError(
                    f"{context}.aliases exceeds the supported limit"
                )

            normalized_aliases = []
            for alias in aliases:
                if (
                    not isinstance(alias, str)
                    or not alias
                    or alias != alias.strip()
                    or len(alias) > _MAX_ALIAS_LENGTH
                    or not _IDENTIFIER_PATTERN.fullmatch(alias)
                ):
                    raise AnsibleInventoryProfileError(
                        f"{context}.aliases contains an invalid inventory identifier"
                    )
                if alias in seen_aliases:
                    raise AnsibleInventoryProfileError(
                        f"fields.{field_name} contains a duplicate alias"
                    )
                seen_aliases.add(alias)
                normalized_aliases.append(alias)
            normalized_tiers.append({"aliases": normalized_aliases})

        normalized_field: Dict[str, Any] = {"lookup_tiers": normalized_tiers}
        if "fallback_field" in field_value:
            fallback_field = field_value["fallback_field"]
            if (
                not isinstance(fallback_field, str)
                or fallback_field not in _FIELD_KINDS
            ):
                raise AnsibleInventoryProfileError(
                    f"fields.{field_name}.fallback_field is not a canonical field"
                )
            if fallback_field == field_name:
                raise AnsibleInventoryProfileError(
                    f"fields.{field_name}.fallback_field cannot reference itself"
                )
            if _FIELD_KINDS[fallback_field] != _FIELD_KINDS[field_name]:
                raise AnsibleInventoryProfileError(
                    f"fields.{field_name}.fallback_field has an incompatible field type"
                )
            normalized_field["fallback_field"] = fallback_field
            fallbacks[field_name] = fallback_field
        normalized[field_name] = normalized_field

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(field_name: str) -> None:
        """
        Visit the current syntax or data node.

        The implementation uses ``field_name`` to visit the current syntax or
        data node. If the function cannot visit the current syntax or data node,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            field_name: Field label included in validation failures for the
                selected input.

        Raises:
            AnsibleInventoryProfileError: If field fallback graph contains a
                cycle.
        """
        if field_name in visited:
            return
        if field_name in visiting:
            raise AnsibleInventoryProfileError("field fallback graph contains a cycle")
        visiting.add(field_name)
        fallback = fallbacks.get(field_name)
        if fallback is not None:
            visit(fallback)
        visiting.remove(field_name)
        visited.add(field_name)

    for field_name in normalized:
        visit(field_name)

    return normalized


def _validate_node_types(value: Any) -> Dict[str, Any]:
    """
    Validate node types.

    The implementation uses ``value`` to validate node types. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        value: Mapping supplying fields for node types.

    Returns:
        A mapping containing the ``aliases`` and ``order`` fields.

    Raises:
        AnsibleInventoryProfileError: If the node_types are not a mapping;
            node_types.order must contain each canonical node type exactly once;
            the node_types.aliases are not a non-empty mapping; or
            node_types.aliases exceeds the supported limit; or another input
            invariant is violated.
    """
    if not isinstance(value, Mapping):
        raise AnsibleInventoryProfileError("node_types must be a mapping")
    _require_exact_keys(
        value,
        required={"aliases", "order"},
        context="node_types",
    )

    raw_order = value["order"]
    if (
        not isinstance(raw_order, list)
        or any(not isinstance(node_type, str) for node_type in raw_order)
        or len(raw_order) != len(CANONICAL_ANSIBLE_NODE_TYPES)
        or len(set(raw_order)) != len(raw_order)
        or set(raw_order) != set(CANONICAL_ANSIBLE_NODE_TYPES)
    ):
        raise AnsibleInventoryProfileError(
            "node_types.order must contain each canonical node type exactly once"
        )

    raw_aliases = value["aliases"]
    if not isinstance(raw_aliases, Mapping) or not raw_aliases:
        raise AnsibleInventoryProfileError(
            "node_types.aliases must be a non-empty mapping"
        )
    if len(raw_aliases) > _MAX_ALIASES_PER_TIER:
        raise AnsibleInventoryProfileError(
            "node_types.aliases exceeds the supported limit"
        )

    normalized_aliases: Dict[str, str] = {}
    covered_node_types: set[str] = set()
    for alias, node_type in raw_aliases.items():
        if (
            not isinstance(alias, str)
            or not alias
            or alias != alias.strip()
            or len(alias) > _MAX_ALIAS_LENGTH
            or not _NORMALIZED_NODE_ALIAS_PATTERN.fullmatch(alias)
        ):
            raise AnsibleInventoryProfileError(
                "node_types.aliases contains an invalid normalized alias"
            )
        if (
            not isinstance(node_type, str)
            or node_type not in CANONICAL_ANSIBLE_NODE_TYPES
        ):
            raise AnsibleInventoryProfileError(
                "node_types.aliases contains an unknown canonical node type"
            )
        normalized_aliases[alias] = node_type
        covered_node_types.add(node_type)

    if covered_node_types != set(CANONICAL_ANSIBLE_NODE_TYPES):
        raise AnsibleInventoryProfileError(
            "node_types.aliases must cover every canonical node type"
        )

    return {"aliases": normalized_aliases, "order": list(raw_order)}


def validate_ansible_inventory_profile(value: Any) -> Dict[str, Any]:
    """
    Validate and normalize catalog-owned static inventory interpretation policy.

    The returned mapping is newly allocated. The profile controls ordered input
    aliases and same-kind fallbacks only; parser precedence and security
    behavior are intentionally not configurable.

    Args:
        value: Mapping supplying fields for and normalize catalog-owned static
            inventory interpretation policy.

    Returns:
        A mapping containing the ``version``, ``fields``, and ``node_types``
        fields.

    Raises:
        AnsibleInventoryProfileError: If the ``ansible_inventory_profile_key``
            is not a mapping; or ``ANSIBLE_INVENTORY_PROFILE_KEY`` has an
            unsupported version.
    """

    if not isinstance(value, Mapping):
        raise AnsibleInventoryProfileError(
            f"{ANSIBLE_INVENTORY_PROFILE_KEY} must be a mapping"
        )
    _require_exact_keys(
        value,
        required={"version", "fields", "node_types"},
        context=ANSIBLE_INVENTORY_PROFILE_KEY,
    )

    version = value["version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != ANSIBLE_INVENTORY_PROFILE_VERSION
    ):
        raise AnsibleInventoryProfileError(
            f"{ANSIBLE_INVENTORY_PROFILE_KEY} has an unsupported version"
        )

    return {
        "version": version,
        "fields": _validate_fields(value["fields"]),
        "node_types": _validate_node_types(value["node_types"]),
    }
