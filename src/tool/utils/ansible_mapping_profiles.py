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
Strict schemas for catalog-owned Ansible mapping profiles.

This module owns the ansible mapping profiles boundary and exposes
``AnsibleMappingProfileError``, ``_require_exact_keys``, ``_require_string``,
``_require_identifier``, and ``_require_boolean``. Keeping those contracts
together gives importers one source of truth for their validation, lifecycle,
and compatibility behavior.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from typing import Any, Dict, List

from .ansible_inventory_profile import CANONICAL_ANSIBLE_NODE_TYPES

ANSIBLE_BASEBOARD_MAPPING_PROFILE_KEY = "ansible_baseboard_mapping_profile"
ANSIBLE_ADDON_DEVICE_PROFILE_KEY = "ansible_addon_device_profile"
ANSIBLE_MAPPING_PROFILE_VERSION = 1
ANSIBLE_BASEBOARD_LEGACY_MAPPING_KEYS = ("ansible_mappings",)
ANSIBLE_ADDON_LEGACY_MAPPING_KEYS = (
    "ansible_addon_devices",
    "addon_devices",
    "addon_device",
    "addon_device_mappings",
)

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ACTIVATION_GLOB_PATTERN = re.compile(r"^[A-Za-z0-9_.?*\-]+$")
_DNS_SUFFIX_PATTERN = re.compile(r"^-?[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?$")
_MAX_STRING_LENGTH = 256
_MAX_MAPPINGS = 512
_MAX_DEVICES = 64
_MAX_LIST_ITEMS = 64


class AnsibleMappingProfileError(ValueError):
    """
    Raised when catalog-owned Ansible mapping policy is invalid.

    Callers receive this exception when the ansible mapping profile error
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
        AnsibleMappingProfileError: If the function cannot require exact keys
            safely.
    """
    optional = optional or set()
    observed = set(value)
    missing = required - observed
    unsupported = observed - required - optional
    if missing:
        raise AnsibleMappingProfileError(
            f"{context} is missing required keys: "
            + ", ".join(sorted(str(key) for key in missing))
        )
    if unsupported:
        raise AnsibleMappingProfileError(
            f"{context} has unsupported keys: "
            + ", ".join(sorted(str(key) for key in unsupported))
        )


def _require_string(value: Any, *, context: str) -> str:
    """
    Require string.

    The implementation uses ``value`` and ``context`` to require string. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        value: Value object whose ``strip`` state is read while performing
            string.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``value``.

    Raises:
        AnsibleMappingProfileError: If the ``context`` is not a non-empty
            string.
    """
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > _MAX_STRING_LENGTH
    ):
        raise AnsibleMappingProfileError(f"{context} must be a non-empty string")
    return value


def _require_identifier(value: Any, *, context: str) -> str:
    """
    Require identifier.

    The implementation uses ``value`` and ``context`` to require identifier.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing identifier.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``normalized``.

    Raises:
        AnsibleMappingProfileError: If the ``context`` is not an Ansible
            inventory identifier.
    """
    normalized = _require_string(value, context=context)
    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise AnsibleMappingProfileError(
            f"{context} must be an Ansible inventory identifier"
        )
    return normalized


def _require_boolean(value: Any, *, context: str) -> bool:
    """
    Require boolean.

    The implementation uses ``value`` and ``context`` to require boolean. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing boolean.
        context: Runtime context carrying state shared across this operation.

    Returns:
        Whether the boolean operation succeeds.

    Raises:
        AnsibleMappingProfileError: If the ``context`` is not a boolean.
    """
    if not isinstance(value, bool):
        raise AnsibleMappingProfileError(f"{context} must be a boolean")
    return value


def _require_string_list(
    value: Any,
    *,
    context: str,
    identifier: bool = False,
) -> List[str]:
    """
    Require string list.

    The implementation uses ``value``, ``context``, and ``identifier`` to
    require string list. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.
        context: Runtime context carrying state shared across this operation.
        identifier: Whether identifier is enabled or required for this
            operation.

    Returns:
        The validated ``normalized``.

    Raises:
        AnsibleMappingProfileError: If the ``context`` is not a non-empty
            bounded list; or ``context`` contains a duplicate value.
    """
    if not isinstance(value, list) or not value or len(value) > _MAX_LIST_ITEMS:
        raise AnsibleMappingProfileError(f"{context} must be a non-empty bounded list")
    normalized: List[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        item_context = f"{context}[{index}]"
        normalized_item = (
            _require_identifier(item, context=item_context)
            if identifier
            else _require_string(item, context=item_context)
        )
        if normalized_item in seen:
            raise AnsibleMappingProfileError(f"{context} contains a duplicate value")
        seen.add(normalized_item)
        normalized.append(normalized_item)
    return normalized


def _validate_version(value: Mapping[str, Any], *, context: str) -> int:
    """
    Validate version.

    The implementation uses ``value`` and ``context`` to validate version. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        value: Mapping supplying fields for version.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``version``.

    Raises:
        AnsibleMappingProfileError: If ``context`` has an unsupported version.
    """
    version = value["version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != ANSIBLE_MAPPING_PROFILE_VERSION
    ):
        raise AnsibleMappingProfileError(f"{context} has an unsupported version")
    return version


def _validate_baseboard_target(
    value: Any,
    *,
    context: str,
    allowed_baseboards: Collection[str] | None,
) -> str:
    """
    Validate baseboard target.

    The implementation uses ``value``, ``context``, and ``allowed_baseboards``
    to validate baseboard target. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        value: Value evaluated while performing baseboard target.
        context: Runtime context carrying state shared across this operation.
        allowed_baseboards: Optional allowed baseboards; ``None`` selects the
            function's default behavior.

    Returns:
        The validated ``baseboard``.

    Raises:
        AnsibleMappingProfileError: If ``context`` references unknown baseboard
            ``baseboard``.
    """
    baseboard = _require_string(value, context=context)
    if allowed_baseboards is not None and baseboard not in allowed_baseboards:
        raise AnsibleMappingProfileError(
            f"{context} references unknown baseboard {baseboard!r}"
        )
    return baseboard


def validate_ansible_baseboard_mapping_profile(
    value: Any,
) -> Dict[str, Any]:
    """
    Validate catalog-owned baseboard selection records.

    The implementation uses ``value`` to validate catalog-owned baseboard
    selection records. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        value: Mapping supplying fields for catalog-owned baseboard selection
            records.

    Returns:
        A mapping containing the ``version`` and ``mappings`` fields.

    Raises:
        AnsibleMappingProfileError: If the ``context`` is not a mapping; the
            ``context``.mappings are not a bounded list; the ``mapping_context``
            is not a mapping; or ``mapping_context``.node_type is not canonical;
            or another input invariant is violated.
    """

    context = ANSIBLE_BASEBOARD_MAPPING_PROFILE_KEY
    if not isinstance(value, Mapping):
        raise AnsibleMappingProfileError(f"{context} must be a mapping")
    _require_exact_keys(
        value,
        required={"version", "mappings"},
        context=context,
    )
    version = _validate_version(value, context=context)

    raw_mappings = value["mappings"]
    if not isinstance(raw_mappings, list) or len(raw_mappings) > _MAX_MAPPINGS:
        raise AnsibleMappingProfileError(f"{context}.mappings must be a bounded list")

    normalized_mappings: List[Dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for index, raw_mapping in enumerate(raw_mappings):
        mapping_context = f"{context}.mappings[{index}]"
        if not isinstance(raw_mapping, Mapping):
            raise AnsibleMappingProfileError(f"{mapping_context} must be a mapping")
        _require_exact_keys(
            raw_mapping,
            required={"product_family", "baseboard"},
            optional={"node_type"},
            context=mapping_context,
        )
        product_family = _require_string(
            raw_mapping["product_family"],
            context=f"{mapping_context}.product_family",
        )
        # Baseboard-selection targets currently include concrete baseboards,
        # semantic groups/types, and two explicitly tracked legacy aliases.
        # Referential validation therefore belongs in platform-target policy
        # rather than pretending this is a concrete-board reference like an
        # add-on target.
        baseboard = _require_string(
            raw_mapping["baseboard"], context=f"{mapping_context}.baseboard"
        )
        node_type = raw_mapping.get("node_type")
        if node_type is not None:
            node_type = _require_string(
                node_type,
                context=f"{mapping_context}.node_type",
            )
            if node_type not in CANONICAL_ANSIBLE_NODE_TYPES:
                raise AnsibleMappingProfileError(
                    f"{mapping_context}.node_type is not canonical"
                )

        identity = (
            product_family.casefold(),
            node_type.casefold() if node_type else None,
        )
        if identity in seen:
            raise AnsibleMappingProfileError(
                f"{context}.mappings contains a duplicate product-family/node-type mapping"
            )
        seen.add(identity)
        normalized_mapping: Dict[str, Any] = {
            "product_family": product_family,
            "baseboard": baseboard,
        }
        if node_type is not None:
            normalized_mapping["node_type"] = node_type
        normalized_mappings.append(normalized_mapping)

    return {
        "version": version,
        "mappings": normalized_mappings,
    }


def validate_ansible_baseboard_mapping_targets(
    mappings: Any,
    baseboard_node_types: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    """
    Validate node roles for mappings which target concrete baseboards.

    Ansible mappings may intentionally target a semantic baseboard group such
    as ``HGX``. Those selectors do not declare one node role and therefore
    remain outside this cross-field check. When a mapping names a concrete
    catalog baseboard, however, its optional ``node_type`` must agree with that
    baseboard's ``platform_detection.node_type`` declaration. This prevents an
    inventory role from selecting a physically different class of device while
    preserving legacy mappings and baseboards which omit node-role metadata.

    Args:
        mappings: Validated Ansible baseboard mapping entries in source order.
        baseboard_node_types: Mapping from concrete catalog baseboard names to
            their declared node roles. A ``None`` or blank value preserves the
            legacy absence of a role declaration.

    Returns:
        Defensive copies of the validated mapping entries in source order.

    Raises:
        AnsibleMappingProfileError: If either input has an invalid shape, a
            concrete baseboard declares a non-canonical node role, or a mapping
            node role conflicts with its concrete baseboard target.
    """

    context = f"{ANSIBLE_BASEBOARD_MAPPING_PROFILE_KEY}.mappings"
    if not isinstance(mappings, list) or len(mappings) > _MAX_MAPPINGS:
        raise AnsibleMappingProfileError(f"{context} must be a bounded list")
    if not isinstance(baseboard_node_types, Mapping):
        raise AnsibleMappingProfileError("baseboard_node_types must be a mapping")

    concrete_targets: Dict[str, tuple[str, str]] = {}
    for raw_baseboard, raw_node_type in baseboard_node_types.items():
        baseboard = _require_string(
            raw_baseboard,
            context="baseboard_node_types key",
        )
        if raw_node_type in (None, ""):
            continue
        node_type = _require_string(
            raw_node_type,
            context=f"baseboard_node_types[{baseboard!r}]",
        )
        if node_type not in CANONICAL_ANSIBLE_NODE_TYPES:
            raise AnsibleMappingProfileError(
                f"baseboard {baseboard!r} declares a non-canonical node_type"
            )
        identity = baseboard.casefold()
        prior = concrete_targets.get(identity)
        if prior is not None and prior[0] != baseboard:
            raise AnsibleMappingProfileError(
                "baseboard_node_types contains case-insensitive duplicate names"
            )
        concrete_targets[identity] = (baseboard, node_type)

    normalized: List[Dict[str, Any]] = []
    for index, raw_mapping in enumerate(mappings):
        mapping_context = f"{context}[{index}]"
        if not isinstance(raw_mapping, Mapping):
            raise AnsibleMappingProfileError(f"{mapping_context} must be a mapping")
        baseboard = _require_string(
            raw_mapping.get("baseboard"),
            context=f"{mapping_context}.baseboard",
        )
        node_type = raw_mapping.get("node_type")
        if node_type is not None:
            node_type = _require_string(
                node_type,
                context=f"{mapping_context}.node_type",
            )
            if node_type not in CANONICAL_ANSIBLE_NODE_TYPES:
                raise AnsibleMappingProfileError(
                    f"{mapping_context}.node_type is not canonical"
                )

        concrete_target = concrete_targets.get(baseboard.casefold())
        if (
            concrete_target is not None
            and node_type is not None
            and node_type != concrete_target[1]
        ):
            raise AnsibleMappingProfileError(
                f"{mapping_context} maps node_type {node_type!r} to concrete "
                f"baseboard {concrete_target[0]!r}, which declares node_type "
                f"{concrete_target[1]!r}"
            )
        normalized.append(dict(raw_mapping))

    return normalized


def _validate_activation_keys(value: Any, *, context: str) -> List[str]:
    """
    Validate activation keys.

    The implementation uses ``value`` and ``context`` to validate activation
    keys. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing activation keys.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``keys``.

    Raises:
        AnsibleMappingProfileError: If ``context`` contains an invalid
            inventory-key glob.
    """
    keys = _require_string_list(value, context=context)
    for key in keys:
        if not _ACTIVATION_GLOB_PATTERN.fullmatch(key):
            raise AnsibleMappingProfileError(
                f"{context} contains an invalid inventory-key glob"
            )
    return keys


def _validate_source_queries(value: Any, *, context: str) -> List[Dict[str, str]]:
    """
    Validate source queries.

    The implementation uses ``value`` and ``context`` to validate source
    queries. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``normalized``.

    Raises:
        AnsibleMappingProfileError: If the ``context`` is not a non-empty
            bounded list; the ``query_context`` is not a mapping;
            ``query_context``.lookup has an unsupported transform; or
            ``context`` contains a duplicate query.
    """
    if not isinstance(value, list) or not value or len(value) > _MAX_LIST_ITEMS:
        raise AnsibleMappingProfileError(f"{context} must be a non-empty bounded list")
    normalized: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, query in enumerate(value):
        query_context = f"{context}[{index}]"
        if not isinstance(query, Mapping):
            raise AnsibleMappingProfileError(f"{query_context} must be a mapping")
        _require_exact_keys(
            query,
            required={"source", "lookup"},
            context=query_context,
        )
        source = _require_identifier(query["source"], context=f"{query_context}.source")
        lookup = query["lookup"]
        if lookup not in {"hostname", "value"}:
            raise AnsibleMappingProfileError(
                f"{query_context}.lookup has an unsupported transform"
            )
        identity = (source, lookup)
        if identity in seen:
            raise AnsibleMappingProfileError(f"{context} contains a duplicate query")
        seen.add(identity)
        normalized.append({"source": source, "lookup": lookup})
    return normalized


def _validate_ip_suffix(value: Any, *, context: str) -> Dict[str, List[str]]:
    """
    Validate IP suffix.

    The implementation uses ``value`` and ``context`` to validate IP suffix.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path.

    Args:
        value: Mapping supplying fields for iP suffix.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``normalized``.

    Raises:
        AnsibleMappingProfileError: If the ``context`` is not a mapping;
            ``context``.``address_type`` must contain exactly one DNS suffix; or
            ``context``.``address_type`` contains an invalid DNS suffix.
    """
    if not isinstance(value, Mapping):
        raise AnsibleMappingProfileError(f"{context} must be a mapping")
    _require_exact_keys(
        value,
        required={"host", "bmc"},
        context=context,
    )
    normalized: Dict[str, List[str]] = {}
    for address_type in ("host", "bmc"):
        suffixes = _require_string_list(
            value[address_type], context=f"{context}.{address_type}"
        )
        if len(suffixes) != 1:
            raise AnsibleMappingProfileError(
                f"{context}.{address_type} must contain exactly one DNS suffix"
            )
        for suffix in suffixes:
            if (
                not _DNS_SUFFIX_PATTERN.fullmatch(suffix)
                or ".." in suffix
                or "/" in suffix
                or "\\" in suffix
            ):
                raise AnsibleMappingProfileError(
                    f"{context}.{address_type} contains an invalid DNS suffix"
                )
        normalized[address_type] = suffixes
    return normalized


def _validate_address_keys(value: Any, *, context: str) -> Dict[str, List[str]]:
    """
    Validate inventory keys which may provide direct add-on addresses.

    The mapping must declare bounded host and BMC key lists. Each entry is an
    Ansible inventory identifier; runtime parsing resolves the first non-empty
    value and retains suffix-based addressing as a compatibility fallback.

    Args:
        value: Mapping containing the direct-address inventory key lists.
        context: Field label included in validation failures.

    Returns:
        A defensively copied mapping containing validated ``host`` and ``bmc``
        identifier lists.

    Raises:
        AnsibleMappingProfileError: If the mapping shape or an inventory key is
            invalid.
    """
    if not isinstance(value, Mapping):
        raise AnsibleMappingProfileError(f"{context} must be a mapping")
    _require_exact_keys(value, required={"host", "bmc"}, context=context)
    return {
        address_type: _require_string_list(
            value[address_type],
            context=f"{context}.{address_type}",
            identifier=True,
        )
        for address_type in ("host", "bmc")
    }


def _validate_credentials(value: Any, *, context: str) -> Dict[str, Any]:
    """
    Validate credentials.

    The implementation uses ``value`` and ``context`` to validate credentials.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path.

    Args:
        value: Mapping supplying fields for credentials.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``normalized``.

    Raises:
        AnsibleMappingProfileError: If the ``context`` is not a mapping; or the
            ``credential_context`` is not a mapping.
    """
    if not isinstance(value, Mapping):
        raise AnsibleMappingProfileError(f"{context} must be a mapping")
    _require_exact_keys(
        value,
        required={"host", "bmc", "bmc_ssh"},
        context=context,
    )
    normalized: Dict[str, Any] = {}
    for target in ("host", "bmc", "bmc_ssh"):
        credential_context = f"{context}.{target}"
        credential = value[target]
        if not isinstance(credential, Mapping):
            raise AnsibleMappingProfileError(f"{credential_context} must be a mapping")
        _require_exact_keys(
            credential,
            required=(
                {"username", "password", "fallback_to_bmc"}
                if target == "bmc_ssh"
                else {"username", "password"}
            ),
            context=credential_context,
        )
        normalized[target] = {
            "username": _require_string_list(
                credential["username"],
                context=f"{credential_context}.username",
                identifier=True,
            ),
            "password": _require_string_list(
                credential["password"],
                context=f"{credential_context}.password",
                identifier=True,
            ),
        }
        if target == "bmc_ssh":
            normalized[target]["fallback_to_bmc"] = _require_boolean(
                credential["fallback_to_bmc"],
                context=f"{credential_context}.fallback_to_bmc",
            )
    return normalized


def validate_ansible_addon_device_profile(
    value: Any,
    *,
    allowed_baseboards: Collection[str] | None = None,
) -> Dict[str, Any]:
    """
    Validate catalog-owned add-on activation, addressing, and credentials.

    The implementation uses ``value`` and ``allowed_baseboards`` to validate
    catalog-owned add-on activation, addressing, and credentials. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        value: Mapping supplying fields for catalog-owned add-on activation,
            addressing, and credentials.
        allowed_baseboards: Optional allowed baseboards; ``None`` selects the
            function's default behavior.

    Returns:
        A mapping containing the ``version`` and ``devices`` fields.

    Raises:
        AnsibleMappingProfileError: If the ``context`` is not a mapping; the
            ``context``.devices are not a bounded list; the ``device_context``
            is not a mapping; or ``context``.devices contains a duplicate device
            name; or another input invariant is violated.
    """

    context = ANSIBLE_ADDON_DEVICE_PROFILE_KEY
    if not isinstance(value, Mapping):
        raise AnsibleMappingProfileError(f"{context} must be a mapping")
    _require_exact_keys(value, required={"version", "devices"}, context=context)
    version = _validate_version(value, context=context)

    raw_devices = value["devices"]
    if not isinstance(raw_devices, list) or len(raw_devices) > _MAX_DEVICES:
        raise AnsibleMappingProfileError(f"{context}.devices must be a bounded list")

    normalized_devices: List[Dict[str, Any]] = []
    seen_names: set[str] = set()
    for index, raw_device in enumerate(raw_devices):
        device_context = f"{context}.devices[{index}]"
        if not isinstance(raw_device, Mapping):
            raise AnsibleMappingProfileError(f"{device_context} must be a mapping")
        _require_exact_keys(
            raw_device,
            required={
                "name",
                "baseboard",
                "node_type",
                "parent_node_types",
                "activation_keys",
                "ip_query",
                "source_hostname_fallback",
                "ip_suffix",
                "credentials",
            },
            optional={"address_keys"},
            context=device_context,
        )
        name = _require_string(raw_device["name"], context=f"{device_context}.name")
        normalized_name = name.casefold()
        if normalized_name in seen_names:
            raise AnsibleMappingProfileError(
                f"{context}.devices contains a duplicate device name"
            )
        seen_names.add(normalized_name)

        node_type = _require_string(
            raw_device["node_type"], context=f"{device_context}.node_type"
        )
        if node_type not in CANONICAL_ANSIBLE_NODE_TYPES:
            raise AnsibleMappingProfileError(
                f"{device_context}.node_type is not canonical"
            )
        parent_node_types = _require_string_list(
            raw_device["parent_node_types"],
            context=f"{device_context}.parent_node_types",
        )
        if any(
            parent_node_type not in CANONICAL_ANSIBLE_NODE_TYPES
            for parent_node_type in parent_node_types
        ):
            raise AnsibleMappingProfileError(
                f"{device_context}.parent_node_types contains a non-canonical value"
            )

        normalized_device = {
            "name": name,
            "baseboard": _validate_baseboard_target(
                raw_device["baseboard"],
                context=f"{device_context}.baseboard",
                allowed_baseboards=allowed_baseboards,
            ),
            "node_type": node_type,
            "parent_node_types": parent_node_types,
            "activation_keys": _validate_activation_keys(
                raw_device["activation_keys"],
                context=f"{device_context}.activation_keys",
            ),
            "ip_query": _validate_source_queries(
                raw_device["ip_query"], context=f"{device_context}.ip_query"
            ),
            "source_hostname_fallback": _require_boolean(
                raw_device["source_hostname_fallback"],
                context=f"{device_context}.source_hostname_fallback",
            ),
            "ip_suffix": _validate_ip_suffix(
                raw_device["ip_suffix"], context=f"{device_context}.ip_suffix"
            ),
            "credentials": _validate_credentials(
                raw_device["credentials"],
                context=f"{device_context}.credentials",
            ),
        }
        if "address_keys" in raw_device:
            normalized_device["address_keys"] = _validate_address_keys(
                raw_device["address_keys"],
                context=f"{device_context}.address_keys",
            )
        normalized_devices.append(normalized_device)

    return {"version": version, "devices": normalized_devices}
