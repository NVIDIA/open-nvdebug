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
Ansible Inventory Parser for NVDebug Tool.

This module handles parsing of static Ansible YAML inventory files and
converting them to DUT configurations. It resolves the bounded variable
reference subset needed by connection settings without executing dynamic
inventory plugins or arbitrary controller-side Jinja code.
"""

import fnmatch
import json
import os
import re
import shlex
import shutil
import stat
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..config import DUTConfig, load_yaml_strict
from . import excel_reader
from .ansible_inventory_profile import (
    ANSIBLE_INVENTORY_PROFILE_KEY,
    DEFAULT_ANSIBLE_INVENTORY_PROFILE,
    validate_ansible_inventory_profile,
)
from .ansible_mapping_profiles import (
    ANSIBLE_ADDON_DEVICE_PROFILE_KEY,
    ANSIBLE_ADDON_LEGACY_MAPPING_KEYS,
    ANSIBLE_BASEBOARD_LEGACY_MAPPING_KEYS,
    ANSIBLE_BASEBOARD_MAPPING_PROFILE_KEY,
    validate_ansible_addon_device_profile,
    validate_ansible_baseboard_mapping_profile,
)
from .catalog_snapshot import CatalogSnapshot
from .dns_utils import (
    is_ip_literal,
    resolve_hostname_to_ip,
    reverse_lookup_short_hostname,
    short_hostname_from_fqdn,
)
from .run_limits import MAX_DUTS
from .spreadsheet_utils import auto_detect_spreadsheet, decode_long_cell


class _StrictAddonMapping(dict):
    """
    Internal provenance marker that catalog JSON cannot forge.

    The type gives the strict addon mapping responsibility a stable runtime
    boundary. Callers use the declared Python protocol instead of depending on
    its representation.
    """


_GENERATED_DUT_TOOL_CONFIG_DIR = "dut_tool_configs"

_ANSIBLE_SIMPLE_REFERENCE = re.compile(
    r"\{\{\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\}\}"
)
_ANSIBLE_WHOLE_REFERENCE = re.compile(
    r"\A\s*\{\{\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\}\}\s*\Z"
)
_ANSIBLE_TEMPLATE_OPENERS = ("{{", "{%", "{#")
_ANSIBLE_MAX_REFERENCE_DEPTH = 64
# Keep both accepted inventory syntaxes and the YAML auto-repair path within
# the same byte boundary as the canonical configuration loader. The repair
# path runs after YAML parsing fails, including when the strict loader rejects
# an oversized inventory.
_ANSIBLE_INVENTORY_MAX_YAML_BYTES = 8 * 1024 * 1024
_ANSIBLE_INVENTORY_MAX_INI_LINES = 100_000
_ANSIBLE_INVENTORY_MAX_INI_LINE_BYTES = 64 * 1024
_ANSIBLE_INVENTORY_MAX_INI_SECTIONS = 2_048
_ANSIBLE_INVENTORY_MAX_INI_HOSTS = MAX_DUTS
_ANSIBLE_INVENTORY_MAX_INI_VARIABLES_PER_SCOPE = 512
_ANSIBLE_INVENTORY_MAX_INI_VARIABLES = 100_000
_ANSIBLE_INI_GROUP_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}")
_ANSIBLE_INI_VARIABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_ANSIBLE_INI_BMC_GROUPS = frozenset({"bmc", "bmcs"})
# These literals are inventory schema field names; they never contain values.
_ANSIBLE_INI_BMC_VARIABLES = {
    "ansible_host": "ansible_bmc_host",
    "ansible_user": "ansible_bmc_user",
    "ansible_password": "ansible_bmc_password",  # pragma: allowlist secret
    "ansible_ssh_pass": "ansible_bmc_pass",
    "ansible_ssh_private_key_file": "ansible_bmc_ssh_private_key_file",  # pragma: allowlist secret
}

CatalogSource = Path | CatalogSnapshot

_ANSIBLE_PROFILE_FIELD_LABELS = {
    "hostname": "hostname",
    "bmc_address": "BMC address",
    "bmc_username": "BMC username",
    "bmc_password": "BMC password",
    "bmc_ssh_username": "BMC SSH username",
    "bmc_ssh_password": "BMC SSH password",
    "bmc_ssh_private_key": "BMC SSH key path",
    "redfish_username": "Redfish username",
    "redfish_password": "Redfish password",
    "host_address": "host address",
    "host_username": "host username",
    "host_password": "host password",
    "host_ssh_private_key": "host SSH key path",
}


class _AnsibleInventoryResolutionError(ValueError):
    """
    Raised when a consumed static-inventory value cannot be resolved safely.

    Callers receive this exception when the ansible inventory resolution error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _select_catalog_source(
    spreadsheet: Optional[CatalogSource],
) -> Optional[CatalogSource]:
    """
    Resolve legacy path discovery without re-reading a captured snapshot.

    The implementation uses ``spreadsheet`` to resolve legacy path discovery
    without re-reading a captured snapshot.

    Args:
        spreadsheet: Spreadsheet consumed while the function attempts to resolve
            legacy path discovery without re-reading a captured snapshot.

    Returns:
        A ``CatalogSource`` representing catalog source, or ``None`` when the
        requested value is unavailable.
    """

    if isinstance(spreadsheet, CatalogSnapshot):
        return spreadsheet
    selected = auto_detect_spreadsheet(spreadsheet, suppress_print=True)
    return None if selected is None else Path(selected)


def _catalog_source_label(source: CatalogSource) -> str:
    """
    Return an error-safe label, never a source path for captured bytes.

    The implementation uses ``source`` to produce an error-safe label, never a
    source path for captured bytes.

    Args:
        source: Source object whose ``catalog_name`` and ``facts`` state is read
            while performing error-safe label, never a source path for captured
            bytes.

    Returns:
        The canonical catalog source label.
    """

    if isinstance(source, CatalogSnapshot):
        return source.facts.catalog_name
    return str(source)


def _read_catalog_sheet(source: CatalogSource, sheet_name: str) -> Any:
    """
    Read a sheet from either legacy filesystem input or captured bytes.

    The implementation uses ``source`` and ``sheet_name`` to read a sheet from
    either legacy filesystem input or captured bytes. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        source: Source object whose ``read_excel`` state is read while
            performing sheet from either legacy filesystem input or captured
            bytes.
        sheet_name: Stable sheet name used for lookup and operator-facing
            diagnostics.

    Returns:
        The catalog sheet value selected by the operation.
    """

    if isinstance(source, CatalogSnapshot):
        return source.read_excel(sheet_name=sheet_name)
    return excel_reader.read_excel(source, sheet_name=sheet_name)


class _AnsibleInventoryResolver:
    """
    Resolve bounded Ansible-style references against one host's variables.

    Ansible defers templating until a value is consumed. This resolver mirrors
    that behavior for the static-YAML subset accepted by this module: host
    variables override group/all variables, whole-value references retain their
    native YAML type, and simple references may be embedded in strings. General
    Jinja statements, filters, lookups, and calls are deliberately rejected
    instead of being executed on the controller.
    """

    def __init__(
        self,
        host_name: str,
        host_data: Dict[str, Any],
        vars_section: Dict[str, Any],
    ) -> None:
        """
        Initialize an ``_AnsibleInventoryResolver`` instance.

        The initializer records ``_cache``, ``host_data``, ``host_name``,
        ``variables``, and ``vars_section`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            host_name: Stable host name used for lookup and operator-facing
                diagnostics.
            host_data: Mapping supplying fields for initialize an
                ``_AnsibleInventoryResolver`` instance.
            vars_section: Mapping supplying fields for initialize an
                ``_AnsibleInventoryResolver`` instance.
        """
        self.host_name = host_name
        self.host_data = host_data
        self.vars_section = vars_section
        self.variables = {
            **vars_section,
            **host_data,
            "inventory_hostname": host_name,
        }
        self._cache: Dict[str, Any] = {}

    def _error(
        self,
        field_name: str,
        reason: str,
        variable_name: Optional[str] = None,
    ) -> _AnsibleInventoryResolutionError:
        """
        Return the error.

        After applying local validation, the function forwards ``field_name``,
        ``reason``, and ``variable_name`` to
        ``_AnsibleInventoryResolutionError`` and preserves its return and
        exception contract.

        Args:
            field_name: Field label included in validation failures for the
                selected input.
            reason: Text supplied as reason in the format accepted by this
                function.
            variable_name: Stable variable name used for lookup and
                operator-facing diagnostics.

        Returns:
            A ``_AnsibleInventoryResolutionError`` describing error.
        """
        variable_detail = (
            f"; referenced variable '{variable_name}'" if variable_name else ""
        )
        return _AnsibleInventoryResolutionError(
            f"Unable to resolve Ansible inventory field '{field_name}' for host "
            f"'{self.host_name}': {reason}{variable_detail}"
        )

    def _resolve_variable(
        self,
        variable_name: str,
        field_name: str,
        stack: Tuple[str, ...],
        container_stack: Tuple[int, ...],
    ) -> Any:
        """
        Resolve variable.

        The implementation uses ``variable_name``, ``field_name``, ``stack``,
        and ``container_stack`` to resolve variable. If the function cannot
        resolve variable, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            variable_name: Stable variable name used for lookup and
                operator-facing diagnostics.
            field_name: Field label included in validation failures for the
                selected input.
            stack: Entries supplied as ``stack`` without transferring container
                ownership.
            container_stack: Entries supplied as ``container_stack`` without
                transferring container ownership.

        Returns:
            The variable value selected by the operation.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to resolve variable.
        """
        if len(stack) >= _ANSIBLE_MAX_REFERENCE_DEPTH:
            raise self._error(
                field_name,
                "variable reference depth limit exceeded",
                variable_name,
            )
        if variable_name in stack:
            raise self._error(
                field_name,
                "variable reference cycle detected",
                variable_name,
            )
        if variable_name in self._cache:
            return self._cache[variable_name]
        if variable_name not in self.variables:
            raise self._error(field_name, "variable is undefined", variable_name)

        resolved = self._resolve_value(
            self.variables[variable_name],
            field_name,
            (*stack, variable_name),
            container_stack,
        )
        self._cache[variable_name] = resolved
        return resolved

    def _resolve_value(
        self,
        value: Any,
        field_name: str,
        stack: Tuple[str, ...] = (),
        container_stack: Tuple[int, ...] = (),
    ) -> Any:
        """
        Resolve value.

        The implementation uses ``value``, ``field_name``, ``stack``, and
        ``container_stack`` to resolve value. If the function cannot resolve
        value, its exception reaches the caller instead of being converted into
        a successful result.

        Args:
            value: Value object whose ``items`` state is read while performing
                value.
            field_name: Field label included in validation failures for the
                selected input.
            stack: Entries supplied as ``stack`` without transferring container
                ownership.
            container_stack: Entries supplied as ``container_stack`` without
                transferring container ownership.

        Returns:
            The value selected by the operation.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to resolve value.
        """
        if isinstance(value, (dict, list, tuple, set)):
            container_id = id(value)
            if container_id in container_stack:
                raise self._error(field_name, "recursive YAML container detected")
            if len(container_stack) >= _ANSIBLE_MAX_REFERENCE_DEPTH:
                raise self._error(field_name, "YAML container depth limit exceeded")
            next_container_stack = (*container_stack, container_id)
        else:
            next_container_stack = container_stack

        if isinstance(value, dict):
            return {
                key: self._resolve_value(item, field_name, stack, next_container_stack)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                self._resolve_value(item, field_name, stack, next_container_stack)
                for item in value
            ]
        if isinstance(value, tuple):
            return tuple(
                self._resolve_value(item, field_name, stack, next_container_stack)
                for item in value
            )
        if isinstance(value, set):
            return {
                self._resolve_value(item, field_name, stack, next_container_stack)
                for item in value
            }
        if not isinstance(value, str):
            return value

        whole_reference = _ANSIBLE_WHOLE_REFERENCE.fullmatch(value)
        if whole_reference:
            return self._resolve_variable(
                whole_reference.group("name"), field_name, stack, container_stack
            )

        if not any(marker in value for marker in _ANSIBLE_TEMPLATE_OPENERS):
            return value

        matches = list(_ANSIBLE_SIMPLE_REFERENCE.finditer(value))
        if not matches or "{{{" in value or "{%" in value or "{#" in value:
            raise self._error(
                field_name,
                "unsupported template expression; only simple variable references "
                "are supported",
            )

        fragments: List[str] = []
        cursor = 0
        for match in matches:
            fragments.append(value[cursor : match.start()])
            resolved = self._resolve_variable(
                match.group("name"), field_name, stack, container_stack
            )
            if not isinstance(resolved, (str, bool, int, float)):
                raise self._error(
                    field_name,
                    "embedded variable reference must resolve to a scalar",
                    match.group("name"),
                )
            fragments.append(str(resolved))
            cursor = match.end()
        fragments.append(value[cursor:])
        rendered = "".join(fragments)

        if any(marker in rendered for marker in _ANSIBLE_TEMPLATE_OPENERS):
            raise self._error(
                field_name,
                "unsupported or unresolved template expression",
            )
        return rendered

    def lookup(
        self,
        keys: Any,
        default: Any = "",
        field_name: str = "inventory value",
        *,
        reject_conflicts: bool = False,
    ) -> Any:
        """
        Return the first alias from the highest-precedence inventory scope.

        The implementation uses ``keys``, ``default``, ``field_name``, and
        ``reject_conflicts`` to produce the first alias from the
        highest-precedence inventory scope. If the function cannot produce the
        first alias from the highest-precedence inventory scope, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            keys: Entries supplied as ``keys`` and processed in caller-provided
                order.
            default: Fallback used when the requested value is absent or
                invalid.
            field_name: Field label included in validation failures for the
                selected input.
            reject_conflicts: Whether reject conflicts is enabled or required
                for this operation.

        Returns:
            The first alias from the highest-precedence inventory scope.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to produce the first alias from the highest-precedence
                inventory scope.
        """

        if isinstance(keys, str):
            keys = [keys]
        for source in (self.host_data, self.vars_section):
            candidates: List[Tuple[str, Any]] = []
            for key in keys:
                raw_value = source.get(key)
                if not _is_non_empty_ansible_value(raw_value):
                    continue
                resolved = self._resolve_value(raw_value, field_name, (str(key),))
                if _is_non_empty_ansible_value(resolved):
                    candidates.append((str(key), resolved))

            if not candidates:
                continue
            if reject_conflicts:
                first_value = candidates[0][1]
                if any(
                    type(candidate_value) is not type(first_value)
                    or candidate_value != first_value
                    for _, candidate_value in candidates[1:]
                ):
                    raise self._error(
                        field_name,
                        "conflicting inventory aliases are defined",
                    )
            return candidates[0][1]
        return default

    def lookup_string(
        self,
        keys: Any,
        default: str = "",
        field_name: str = "inventory value",
        *,
        reject_conflicts: bool = False,
    ) -> str:
        """
        Resolve a connection value and enforce a non-disclosing scalar boundary.

        The implementation uses ``keys``, ``default``, ``field_name``, and
        ``reject_conflicts`` to resolve a connection value and enforce a
        non-disclosing scalar boundary. If the function cannot resolve a
        connection value and enforce a non-disclosing scalar boundary, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            keys: Keys consumed while the function attempts to resolve a
                connection value and enforce a non-disclosing scalar boundary.
            default: Fallback used when the requested value is absent or
                invalid.
            field_name: Field label included in validation failures for the
                selected input.
            reject_conflicts: Whether reject conflicts is enabled or required
                for this operation.

        Returns:
            The canonical string text.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to resolve a connection value and enforce a
                non-disclosing scalar boundary.
        """

        value = self.lookup(
            keys,
            default,
            field_name,
            reject_conflicts=reject_conflicts,
        )
        if isinstance(value, str):
            return value
        if isinstance(value, (bool, int, float)):
            return str(value)
        raise self._error(field_name, "value must resolve to a scalar")


def _resolve_ansible_inventory_value(
    value: Any,
    variables: Dict[str, Any],
    *,
    host_name: str,
    field_name: str,
) -> Any:
    """
    Resolve a standalone value using the static-inventory reference rules.

    After applying local validation, the function forwards ``value``,
    ``variables``, ``host_name``, and ``field_name`` to
    ``resolver._resolve_value`` and preserves its return and exception contract.

    Args:
        value: Value evaluated while performing standalone value using the
            static-inventory reference rules.
        variables: Mapping supplying fields for standalone value using the
            static-inventory reference rules.
        host_name: Stable host name used for lookup and operator-facing
            diagnostics.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        The ansible inventory value selected by the operation.
    """

    resolver = _AnsibleInventoryResolver(host_name, {}, variables)
    return resolver._resolve_value(value, field_name)


def _normalize_string_list(value: Any) -> List[str]:
    """
    Normalize a string/list scalar into a list of non-empty strings.

    The implementation uses ``value`` to normalize a string/list scalar into a
    list of non-empty strings. The source value keeps its ownership while the
    normalized representation is returned separately.

    Args:
        value: Value object whose ``strip`` state is read while performing
            string/list scalar into a list of non-empty strings.

    Returns:
        The string list returned in operation-defined order.
    """
    if value is None:
        return []
    if isinstance(value, str):
        stripped_value = value.strip()
        return [stripped_value] if stripped_value else []
    if isinstance(value, (list, tuple, set)):
        normalized: List[str] = []
        for item in value:
            normalized.extend(_normalize_string_list(item))
        return normalized
    return [str(value)]


def _load_mapping_list_from_data(
    data: Any,
    keys: Tuple[str, ...],
) -> List[Dict[str, Any]]:
    """
    Extract a mapping list from a config dictionary.

    The implementation uses ``data`` and ``keys`` to extract a mapping list from
    a config dictionary.

    Args:
        data: Data object whose ``get`` state is read while performing extract a
            mapping list from a config dictionary.
        keys: Entries supplied as ``keys`` without transferring container
            ownership.

    Returns:
        The mapping list from data returned in operation-defined order.
    """
    if isinstance(data, list):
        return [entry for entry in data if isinstance(entry, dict)]

    if not isinstance(data, dict):
        return []

    for key in keys:
        value = data.get(key)
        if value is not None:
            return _load_mapping_list_from_data(value, keys)

    if data.get("name"):
        return [data]

    return []


def _parse_serialized_mapping_list(value: Any) -> List[Dict[str, Any]]:
    """
    Parse JSON/YAML serialized mapping data from a spreadsheet cell.

    The implementation uses ``value`` to parse JSON/YAML serialized mapping data
    from a spreadsheet cell. Parsing or I/O must finish before the validated
    representation is made available to the caller.

    Args:
        value: Value object whose ``strip`` state is read while performing
            JSON/YAML serialized mapping data from a spreadsheet cell.

    Returns:
        The serialized mapping list returned in operation-defined order.
    """
    if not isinstance(value, str) or not value.strip():
        return []

    value = decode_long_cell(value)
    for parser in (json.loads, load_yaml_strict):
        try:
            parsed = parser(value)
        except Exception:
            continue
        mappings = _load_mapping_list_from_data(
            parsed, ANSIBLE_ADDON_LEGACY_MAPPING_KEYS
        )
        if mappings:
            return mappings

    return []


def _normalize_ip_query_config(value: Any) -> List[Dict[str, Any]]:
    """
    Normalize add-on source query config from YAML or spreadsheet data.

    The implementation uses ``value`` to normalize add-on source query config
    from YAML or spreadsheet data. The source value keeps its ownership while
    the normalized representation is returned separately.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.

    Returns:
        The IP query config returned in operation-defined order.
    """
    if isinstance(value, dict):
        return [dict(value)]

    if not isinstance(value, list):
        return []

    queries: List[Dict[str, Any]] = []
    current: Dict[str, Any] = {}
    for item in value:
        if isinstance(item, dict):
            if (
                item.get("source")
                and current.get("source")
                and not current.get("lookup")
            ):
                queries.append(current)
                current = {}
            current.update(item)
            if current.get("source") and (current.get("lookup") or len(item) > 1):
                queries.append(current)
                current = {}
        elif isinstance(item, str) and item.strip():
            queries.append({"source": item.strip()})

    if current:
        queries.append(current)

    return queries


def _normalize_addon_device_mapping(mapping: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize add-on mapping aliases while keeping the schema data-driven.

    The implementation uses ``mapping`` to normalize add-on mapping aliases
    while keeping the schema data-driven. The source value keeps its ownership
    while the normalized representation is returned separately.

    Args:
        mapping: Mapping supplying fields for add-on mapping aliases while
            keeping the schema data-driven.

    Returns:
        The validated ``normalized``.
    """
    normalized = dict(mapping)

    parent_node_types = (
        normalized.get("parent_node_types")
        or normalized.get("source_node_types")
        or normalized.get("attach_to_node_types")
        or normalized.get("parent_node_type")
        or normalized.get("source_node_type")
    )
    normalized["parent_node_types"] = _normalize_string_list(
        parent_node_types or ["Compute"]
    )

    if "search_patterns" not in normalized:
        normalized["search_patterns"] = _normalize_string_list(
            normalized.get("search_pattern")
        )
    else:
        normalized["search_patterns"] = _normalize_string_list(
            normalized.get("search_patterns")
        )

    ip_suffix = normalized.get("ip_suffix")
    if isinstance(ip_suffix, dict):
        normalized["ip_suffix"] = {
            key: _normalize_string_list(value) for key, value in ip_suffix.items()
        }

    address_keys = normalized.get("address_keys")
    if isinstance(address_keys, dict):
        normalized["address_keys"] = {
            key: _normalize_string_list(value) for key, value in address_keys.items()
        }

    ip_query = _normalize_ip_query_config(normalized.get("ip_query"))
    normalized["ip_query"] = ip_query or [
        {"source": "ansible_host", "lookup": "hostname"}
    ]

    return normalized


def _normalize_addon_device_mappings(
    mappings: List[Dict[str, Any]],
    *,
    strict_profile: bool = False,
) -> List[Dict[str, Any]]:
    """
    Normalize addon device mappings.

    The implementation uses ``mappings`` and ``strict_profile`` to normalize
    addon device mappings. The source value keeps its ownership while the
    normalized representation is returned separately.

    Args:
        mappings: Mapping supplying fields for addon device mappings.
        strict_profile: Whether strict profile is enabled or required for this
            operation.

    Returns:
        The addon device mappings returned in operation-defined order.
    """
    normalized_mappings = [
        _normalize_addon_device_mapping(mapping)
        for mapping in mappings
        if isinstance(mapping, dict) and mapping.get("name")
    ]
    if strict_profile:
        return [_StrictAddonMapping(mapping) for mapping in normalized_mappings]
    return normalized_mappings


def _load_mapping_profile_from_dataframe(
    df: Any,
    catalog_label: str,
    *,
    profile_key: str,
    validator: Any,
    validator_kwargs: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Load one exact, authoritative mapping-profile row when present.

    After applying local validation, the function forwards ``df``,
    ``catalog_label``, ``profile_key``, ``validator``, and ``validator_kwargs``
    to ``validator`` and preserves its return and exception contract. Parsing or
    I/O must finish before the validated representation is made available to the
    caller.

    Args:
        df: Df object whose ``iterrows`` state is read while performing one
            exact, authoritative mapping-profile row when present.
        catalog_label: Text supplied as catalog label in the format accepted by
            this function.
        profile_key: Stable profile key used for lookup and operator-facing
            diagnostics.
        validator: Validator consumed while the function attempts to load one
            exact, authoritative mapping-profile row when present.
        validator_kwargs: Optional validator kwargs; ``None`` selects the
            function's default behavior.

    Returns:
        A mapping containing mapping profile from dataframe, or ``None`` when
        the requested value is unavailable.

    Raises:
        ValueError: If catalog '``catalog_label``' contains a malformed
            ``profile_key`` row; catalog '``catalog_label``' contains duplicate
            ``profile_key`` rows; catalog '``catalog_label``' contains a blank
            ``profile_key`` row; or catalog '``catalog_label``' contains an
            invalid ``profile_key``: ``error``.
    """

    matching_rows = []
    for _, row in df.iterrows():
        raw_section = row.get("Section", "")
        raw_field_name = row.get("Configuration Item", "")
        field_name = str(raw_field_name).strip()
        if field_name != profile_key:
            continue
        if raw_section != "Global Constants" or raw_field_name != profile_key:
            raise ValueError(
                f"Catalog '{catalog_label}' contains a malformed " f"{profile_key} row"
            )
        matching_rows.append(row)

    if not matching_rows:
        return None
    if len(matching_rows) != 1:
        raise ValueError(
            f"Catalog '{catalog_label}' contains duplicate {profile_key} rows"
        )

    value = matching_rows[0].get("Value", "")
    if not excel_reader.notna(value) or not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Catalog '{catalog_label}' contains a blank {profile_key} row"
        )

    try:
        profile = json.loads(
            decode_long_cell(value),
            object_pairs_hook=_json_object_without_duplicate_keys,
        )
        return validator(profile, **(validator_kwargs or {}))
    except Exception as error:
        raise ValueError(
            f"Catalog '{catalog_label}' contains an invalid " f"{profile_key}: {error}"
        ) from error


def _load_transitional_mapping_row(
    df: Any,
    catalog_label: str,
    *,
    field_name: str,
    legacy_field_names: tuple[str, ...] | None = None,
) -> Optional[List[Dict[str, Any]]]:
    """
    Load the one canonical row visible to older catalog runtimes.

    The implementation uses ``df``, ``catalog_label``, ``field_name``, and
    ``legacy_field_names`` to load the one canonical row visible to older
    catalog runtimes. Parsing or I/O must finish before the validated
    representation is made available to the caller. If the function cannot load
    the one canonical row visible to older catalog runtimes, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        df: Df object whose ``iterrows`` state is read while performing one
            canonical row visible to older catalog runtimes.
        catalog_label: Text supplied as catalog label in the format accepted by
            this function.
        field_name: Field label included in validation failures for the selected
            input.
        legacy_field_names: Optional legacy field names; ``None`` selects the
            function's default behavior.

    Returns:
        The transitional mapping row returned in operation-defined order, or
        ``None`` when the requested value is unavailable.

    Raises:
        ValueError: If catalog '``catalog_label``' contains a non-canonical
            legacy mapping row ``raw_field_name``; strict profiles require
            exactly ``field_name``; catalog '``catalog_label``' contains
            duplicate ``field_name`` rows; catalog '``catalog_label``'
            ``field_name`` must contain JSON text; or catalog
            '``catalog_label``' contains invalid ``field_name``: ``error``; or
            another input invariant is violated.
    """

    matching_rows = []
    recognized_names = {
        name.casefold() for name in (legacy_field_names or (field_name,))
    }
    for _, row in df.iterrows():
        raw_section = row.get("Section", "")
        raw_field_name = row.get("Configuration Item", "")
        normalized_field_name = str(raw_field_name).strip().casefold()
        if normalized_field_name not in recognized_names:
            continue
        if raw_section != "Ansible Mappings" or raw_field_name != field_name:
            raise ValueError(
                f"Catalog '{catalog_label}' contains a non-canonical legacy "
                f"mapping row {raw_field_name!r}; strict profiles require exactly "
                f"{field_name!r}"
            )
        matching_rows.append(row)

    if not matching_rows:
        return None
    if len(matching_rows) != 1:
        raise ValueError(
            f"Catalog '{catalog_label}' contains duplicate {field_name} rows"
        )

    value = matching_rows[0].get("Value", "")
    if not excel_reader.notna(value):
        return []
    if not isinstance(value, str):
        raise ValueError(
            f"Catalog '{catalog_label}' {field_name} must contain JSON text"
        )
    if not value.strip():
        return []
    try:
        parsed = json.loads(
            decode_long_cell(value),
            object_pairs_hook=_json_object_without_duplicate_keys,
        )
    except Exception as error:
        raise ValueError(
            f"Catalog '{catalog_label}' contains invalid {field_name}: {error}"
        ) from error
    if not isinstance(parsed, list) or any(
        not isinstance(mapping, dict) for mapping in parsed
    ):
        raise ValueError(
            f"Catalog '{catalog_label}' {field_name} must contain a JSON list "
            "of mappings"
        )
    return parsed


@lru_cache(maxsize=16)
def _load_spreadsheet_ansible_addon_device_mappings(
    spreadsheet: Optional[CatalogSource] = None,
) -> List[Dict[str, Any]]:
    """
    Load add-on mappings from the selected Telemetry Catalog spreadsheet.

    The implementation uses ``spreadsheet`` to load add-on mappings from the
    selected Telemetry Catalog spreadsheet. Parsing or I/O must finish before
    the validated representation is made available to the caller. If the
    function cannot load add-on mappings from the selected Telemetry Catalog
    spreadsheet, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        spreadsheet: Optional spreadsheet; ``None`` selects the function's
            default behavior.

    Returns:
        The spreadsheet ansible addon device mappings returned in
        operation-defined order.

    Raises:
        ValueError: If catalog '``catalog_label``' ansible_addon_devices does
            not match ``ANSIBLE_ADDON_DEVICE_PROFILE_KEY``.
    """
    catalog_source = _select_catalog_source(spreadsheet)
    if catalog_source is None:
        return []

    if isinstance(catalog_source, Path) and not catalog_source.exists():
        return []

    try:
        df = _read_catalog_sheet(
            catalog_source, sheet_name="Log Collection Configuration"
        )
    except Exception:
        return []

    catalog_label = _catalog_source_label(catalog_source)
    profile = _load_mapping_profile_from_dataframe(
        df,
        catalog_label,
        profile_key=ANSIBLE_ADDON_DEVICE_PROFILE_KEY,
        validator=validate_ansible_addon_device_profile,
        validator_kwargs={
            "allowed_baseboards": {
                str(column)
                for column in df.columns
                if str(column)
                not in {"Section", "Configuration Item", "Value", "Description"}
            }
        },
    )
    if profile is not None:
        transitional_devices = _load_transitional_mapping_row(
            df,
            catalog_label,
            field_name="ansible_addon_devices",
            legacy_field_names=ANSIBLE_ADDON_LEGACY_MAPPING_KEYS,
        )
        if transitional_devices != profile["devices"]:
            raise ValueError(
                f"Catalog '{catalog_label}' ansible_addon_devices does not match "
                f"{ANSIBLE_ADDON_DEVICE_PROFILE_KEY}"
            )
        return _normalize_addon_device_mappings(profile["devices"], strict_profile=True)

    mappings: List[Dict[str, Any]] = []
    filtered_rows = df[df["Section"] == "Ansible Mappings"]
    for _, row in filtered_rows.iterrows():
        field_name = str(row.get("Configuration Item", "")).strip().lower()
        if field_name not in ANSIBLE_ADDON_LEGACY_MAPPING_KEYS:
            continue
        mappings.extend(_parse_serialized_mapping_list(row.get("Value", "")))

    return _normalize_addon_device_mappings(mappings)


@lru_cache(maxsize=16)
def _load_ansible_addon_device_mappings(
    spreadsheet: Optional[CatalogSource] = None,
) -> List[Dict[str, Any]]:
    """
    Load add-on device mappings from the selected Telemetry Catalog.

    The implementation uses ``spreadsheet`` to load add-on device mappings from
    the selected Telemetry Catalog. Parsing or I/O must finish before the
    validated representation is made available to the caller.

    Args:
        spreadsheet: Optional spreadsheet; ``None`` selects the function's
            default behavior.

    Returns:
        The ansible addon device mappings returned in operation-defined order.
    """
    if spreadsheet is None:
        return _load_spreadsheet_ansible_addon_device_mappings()
    return _load_spreadsheet_ansible_addon_device_mappings(spreadsheet)


@lru_cache(maxsize=16)
def _load_ansible_baseboard_mappings(
    spreadsheet: Optional[CatalogSource] = None,
) -> List[Dict[str, Any]]:
    """
    Load ansible baseboard mappings from the Telemetry Catalog spreadsheet.

    The implementation uses ``spreadsheet`` to load ansible baseboard mappings
    from the Telemetry Catalog spreadsheet. Parsing or I/O must finish before
    the validated representation is made available to the caller. If the
    function cannot load ansible baseboard mappings from the Telemetry Catalog
    spreadsheet, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        spreadsheet: Optional spreadsheet; ``None`` selects the function's
            default behavior.

    Returns:
        The ansible baseboard mappings returned in operation-defined order.

    Raises:
        ValueError: If catalog '``catalog_label``' ansible_mappings does not
            match ``ANSIBLE_BASEBOARD_MAPPING_PROFILE_KEY``.
    """

    catalog_source = _select_catalog_source(spreadsheet)
    if catalog_source is None:
        return []

    if isinstance(catalog_source, Path) and not catalog_source.exists():
        return []

    try:
        df = _read_catalog_sheet(
            catalog_source, sheet_name="Log Collection Configuration"
        )
    except Exception:
        return []

    catalog_label = _catalog_source_label(catalog_source)
    profile = _load_mapping_profile_from_dataframe(
        df,
        catalog_label,
        profile_key=ANSIBLE_BASEBOARD_MAPPING_PROFILE_KEY,
        validator=validate_ansible_baseboard_mapping_profile,
    )
    if profile is not None:
        transitional_mappings = _load_transitional_mapping_row(
            df,
            catalog_label,
            field_name="ansible_mappings",
            legacy_field_names=ANSIBLE_BASEBOARD_LEGACY_MAPPING_KEYS,
        )
        if transitional_mappings != profile["mappings"]:
            raise ValueError(
                f"Catalog '{catalog_label}' ansible_mappings does not match "
                f"{ANSIBLE_BASEBOARD_MAPPING_PROFILE_KEY}"
            )
        return [dict(mapping) for mapping in profile["mappings"]]

    mappings: List[Dict[str, Any]] = []

    filtered_rows = df[df["Section"] == "Ansible Mappings"]
    for _, row in filtered_rows.iterrows():
        field_name = str(row.get("Configuration Item", "")).strip().lower()
        if field_name != "ansible_mappings":
            continue

        value = row.get("Value", "")
        if not isinstance(value, str) or not value.strip():
            continue

        try:
            raw_entries = json.loads(decode_long_cell(value))
        except (TypeError, json.JSONDecodeError):
            continue

        if not isinstance(raw_entries, list):
            continue

        for entry in raw_entries:
            if not isinstance(entry, dict):
                continue
            baseboard = entry.get("baseboard")
            product_family = entry.get("product_family")
            if not baseboard or not product_family:
                continue
            node_type = entry.get("node_type")
            mappings.append(
                {
                    "baseboard": str(baseboard),
                    "product_family": str(product_family).lower(),
                    "node_type": (
                        str(node_type).lower()
                        if node_type is not None and str(node_type).strip()
                        else None
                    ),
                }
            )

    return mappings


def _json_object_without_duplicate_keys(
    pairs: List[Tuple[str, Any]],
) -> Dict[str, Any]:
    """
    Reject ambiguous catalog JSON instead of keeping the last duplicate key.

    The implementation uses ``pairs`` to reject ambiguous catalog JSON instead
    of keeping the last duplicate key. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        pairs: Entries supplied as ``pairs`` without transferring container
            ownership.

    Returns:
        The validated ``result``.

    Raises:
        ValueError: If duplicate JSON key: ``key``.
    """

    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


@lru_cache(maxsize=16)
def _load_ansible_inventory_profile(
    spreadsheet: Optional[CatalogSource] = None,
) -> Dict[str, Any]:
    """
    Load and validate the selected catalog's inventory interpretation profile.

    Catalogs created before the profile was introduced use the pinned default. A
    profile row that is present is authoritative: blank, duplicate, malformed,
    or invalid rows fail closed rather than silently changing credential lookup.

    Args:
        spreadsheet: Optional spreadsheet; ``None`` selects the function's
            default behavior.

    Returns:
        A mapping containing ansible inventory profile.

    Raises:
        ValueError: If unable to read Ansible inventory profile from catalog
            '``catalog_label``': file does not exist; unable to read Ansible
            inventory profile from catalog '``catalog_label``'; catalog
            '``catalog_label``' contains a malformed
            ``ANSIBLE_INVENTORY_PROFILE_KEY`` row; or catalog
            '``catalog_label``' contains duplicate
            ``ANSIBLE_INVENTORY_PROFILE_KEY`` rows; or another input invariant
            is violated.
    """

    catalog_source = _select_catalog_source(spreadsheet)
    if catalog_source is None:
        return validate_ansible_inventory_profile(DEFAULT_ANSIBLE_INVENTORY_PROFILE)

    catalog_label = _catalog_source_label(catalog_source)
    if isinstance(catalog_source, Path) and not catalog_source.exists():
        raise ValueError(
            f"Unable to read Ansible inventory profile from catalog "
            f"'{catalog_label}': file does not exist"
        )

    try:
        df = _read_catalog_sheet(
            catalog_source, sheet_name="Log Collection Configuration"
        )
    except Exception as error:
        raise ValueError(
            f"Unable to read Ansible inventory profile from catalog "
            f"'{catalog_label}'"
        ) from error

    matching_rows = []
    for _, row in df.iterrows():
        raw_section = row.get("Section", "")
        raw_field_name = row.get("Configuration Item", "")
        field_name = str(raw_field_name).strip()
        if field_name != ANSIBLE_INVENTORY_PROFILE_KEY:
            continue
        if (
            raw_section != "Global Constants"
            or raw_field_name != ANSIBLE_INVENTORY_PROFILE_KEY
        ):
            raise ValueError(
                f"Catalog '{catalog_label}' contains a malformed "
                f"{ANSIBLE_INVENTORY_PROFILE_KEY} row"
            )
        matching_rows.append(row)

    if not matching_rows:
        return validate_ansible_inventory_profile(DEFAULT_ANSIBLE_INVENTORY_PROFILE)
    if len(matching_rows) != 1:
        raise ValueError(
            f"Catalog '{catalog_label}' contains duplicate "
            f"{ANSIBLE_INVENTORY_PROFILE_KEY} rows"
        )

    value = matching_rows[0].get("Value", "")
    if not excel_reader.notna(value) or not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Catalog '{catalog_label}' contains a blank "
            f"{ANSIBLE_INVENTORY_PROFILE_KEY} row"
        )

    try:
        decoded_value = decode_long_cell(value)
        profile = json.loads(
            decoded_value,
            object_pairs_hook=_json_object_without_duplicate_keys,
        )
        return validate_ansible_inventory_profile(profile)
    except Exception as error:
        raise ValueError(
            f"Catalog '{catalog_label}' contains an invalid "
            f"{ANSIBLE_INVENTORY_PROFILE_KEY}: {error}"
        ) from error


def _read_bounded_ansible_inventory(file_path: Path) -> str:
    """
    Read one UTF-8 inventory within the shared static-input byte ceiling.

    The file is opened in binary mode so the limit applies to exact input bytes
    rather than decoded character count. A UTF-8 byte-order mark is accepted,
    but other encodings fail before either the YAML or INI parser receives the
    source.

    Args:
        file_path: Filesystem path for the static Ansible inventory.

    Returns:
        The decoded inventory source.

    Raises:
        ValueError: If the inventory exceeds the configured byte ceiling.
        UnicodeDecodeError: If the inventory is not valid UTF-8 text.
        OSError: If the inventory cannot be opened or read.
    """

    with file_path.open("rb") as inventory_file:
        source = inventory_file.read(_ANSIBLE_INVENTORY_MAX_YAML_BYTES + 1)
    if len(source) > _ANSIBLE_INVENTORY_MAX_YAML_BYTES:
        raise ValueError(
            "Ansible inventory exceeds "
            f"{_ANSIBLE_INVENTORY_MAX_YAML_BYTES} bytes"
        )
    return source.decode("utf-8-sig")


def _is_ansible_ini_inventory(file_path: Path, source: str) -> bool:
    """
    Return whether a bounded inventory must use the static INI parser.

    An explicit ``.ini`` suffix is authoritative even for malformed content,
    which prevents an INI failure from reaching the mutating YAML repair path.
    Extensionless or differently named inventories are also recognized when
    their first meaningful line is an INI section header.

    Args:
        file_path: Filesystem path whose suffix participates in format choice.
        source: Already bounded and decoded inventory text.

    Returns:
        ``True`` when the source must be parsed as INI; otherwise ``False``.
    """

    if file_path.suffix.lower() == ".ini":
        return True
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        return stripped.startswith("[")
    return False


def _tokenize_ansible_ini_line(line: str, line_number: int) -> List[str]:
    """
    Tokenize one bounded static-inventory line without executing shell syntax.

    ``shlex`` is used only as a lexer for Ansible's quoted ``key=value`` form;
    no token is evaluated or passed to a shell. Both standard INI comment
    prefixes terminate the remaining line.

    Args:
        line: One source line after the file-level byte bound was enforced.
        line_number: One-based line number used in input diagnostics.

    Returns:
        Tokens in source order with quoting removed.

    Raises:
        ValueError: If quoting or escaping is malformed.
    """

    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#;"
    try:
        return list(lexer)
    except ValueError as error:
        raise ValueError(
            f"Invalid Ansible INI quoting on line {line_number}"
        ) from error


def _parse_ansible_ini_variables(
    tokens: List[str],
    *,
    line_number: int,
    scope: str,
) -> Dict[str, str]:
    """
    Parse duplicate-free ``key=value`` tokens for one INI variable scope.

    Values remain opaque strings for the existing catalog-owned resolver. The
    parser validates only bounded assignment syntax and ownership, so it cannot
    accidentally evaluate inventory expressions or expose a value in an error.

    Args:
        tokens: Variable tokens retained in source order.
        line_number: One-based line number used in input diagnostics.
        scope: Non-secret host or group label used in diagnostics.

    Returns:
        A new mapping containing the parsed string values.

    Raises:
        ValueError: If the scope exceeds its variable bound, a token is not an
            assignment, a name is invalid, or a name occurs more than once.
    """

    if len(tokens) > _ANSIBLE_INVENTORY_MAX_INI_VARIABLES_PER_SCOPE:
        raise ValueError(
            f"Ansible INI {scope} exceeds the per-scope variable limit"
        )

    variables: Dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise ValueError(
                f"Invalid Ansible INI variable on line {line_number}: "
                "expected key=value"
            )
        name, value = token.split("=", 1)
        if _ANSIBLE_INI_VARIABLE_NAME.fullmatch(name) is None:
            raise ValueError(
                f"Invalid Ansible INI variable name on line {line_number}"
            )
        if name in variables:
            raise ValueError(
                f"Duplicate Ansible INI variable '{name}' in {scope}"
            )
        variables[name] = value
    return variables


def _project_ansible_ini_bmc_variables(
    variables: Dict[str, str],
    *,
    scope: str,
) -> Dict[str, str]:
    """
    Project generic Ansible connection names onto one BMC-only target.

    The retained baseline uses ``ansible_host``, ``ansible_user``, and
    ``ansible_password`` in a ``[bmcs]`` group. Mapping those names at the
    format boundary prevents them from being mistaken for host-OS credentials
    while preserving explicit BMC-prefixed names unchanged.

    Args:
        variables: Duplicate-free variables parsed from one BMC scope.
        scope: Non-secret host or group label used in diagnostics.

    Returns:
        A new mapping using canonical BMC-oriented Ansible aliases.

    Raises:
        ValueError: If generic and explicit aliases collapse onto the same
            effective BMC variable.
    """

    projected: Dict[str, str] = {}
    for name, value in variables.items():
        projected_name = _ANSIBLE_INI_BMC_VARIABLES.get(name, name)
        if projected_name in projected:
            raise ValueError(
                f"Duplicate effective Ansible INI variable '{projected_name}' "
                f"in {scope}"
            )
        projected[projected_name] = value
    return projected


def _parse_ansible_ini_inventory(source: str) -> Dict[str, Any]:
    """
    Parse the bounded static INI inventory subset consumed by NVDebug.

    Host sections and ``group:vars`` sections are supported. Dynamic plugins,
    ranges, and child-group inheritance are deliberately rejected rather than
    partially interpreted. Duplicate sections, host identities, and variable
    names fail closed so no last-wins configuration reaches a transport.

    Args:
        source: UTF-8 inventory text already checked against the byte ceiling.

    Returns:
        The YAML-shaped mapping consumed by the existing inventory resolver.

    Raises:
        ValueError: If syntax is unsupported or malformed, a structural limit
            is exceeded, a duplicate is present, or no hosts are declared.
    """

    inventory: Dict[str, Any] = {"all": {"vars": {}}}
    section: Optional[Tuple[str, str]] = None
    seen_sections: set[str] = set()
    seen_hosts: set[str] = set()
    total_variables = 0
    lines = source.splitlines()
    if len(lines) > _ANSIBLE_INVENTORY_MAX_INI_LINES:
        raise ValueError(
            "Ansible INI inventory exceeds "
            f"{_ANSIBLE_INVENTORY_MAX_INI_LINES} lines"
        )

    for line_number, line in enumerate(lines, start=1):
        if len(line.encode("utf-8")) > _ANSIBLE_INVENTORY_MAX_INI_LINE_BYTES:
            raise ValueError(
                f"Ansible INI line {line_number} exceeds "
                f"{_ANSIBLE_INVENTORY_MAX_INI_LINE_BYTES} bytes"
            )
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue

        if stripped.startswith("["):
            closing = stripped.find("]")
            trailing = stripped[closing + 1 :].strip() if closing >= 0 else ""
            if closing <= 1 or (
                trailing and not trailing.startswith(("#", ";"))
            ):
                raise ValueError(
                    f"Invalid Ansible INI section header on line {line_number}"
                )
            section_name = stripped[1:closing].strip()
            if section_name in seen_sections:
                raise ValueError(
                    f"Duplicate Ansible INI section '[{section_name}]'"
                )
            seen_sections.add(section_name)
            if len(seen_sections) > _ANSIBLE_INVENTORY_MAX_INI_SECTIONS:
                raise ValueError(
                    "Ansible INI inventory exceeds "
                    f"{_ANSIBLE_INVENTORY_MAX_INI_SECTIONS} sections"
                )

            group_name, separator, section_kind = section_name.partition(":")
            group_name = group_name.strip()
            section_kind = section_kind.strip() if separator else "hosts"
            if _ANSIBLE_INI_GROUP_NAME.fullmatch(group_name) is None:
                raise ValueError(
                    f"Invalid Ansible INI group name on line {line_number}"
                )
            if section_kind not in {"hosts", "vars"}:
                raise ValueError(
                    f"Unsupported Ansible INI section '[{section_name}]'"
                )
            if group_name == "all" and section_kind == "hosts":
                raise ValueError(
                    "Ansible INI host declarations must use a named group"
                )
            inventory.setdefault(group_name, {"hosts": {}, "vars": {}})
            section = (group_name, section_kind)
            continue

        if section is None:
            raise ValueError(
                f"Ansible INI content before the first section on line {line_number}"
            )

        group_name, section_kind = section
        tokens = _tokenize_ansible_ini_line(line, line_number)
        if not tokens:
            continue
        group_data = inventory[group_name]
        bmc_group = group_name.lower() in _ANSIBLE_INI_BMC_GROUPS

        if section_kind == "vars":
            variables = _parse_ansible_ini_variables(
                tokens,
                line_number=line_number,
                scope=f"group '{group_name}'",
            )
            if bmc_group:
                variables = _project_ansible_ini_bmc_variables(
                    variables,
                    scope=f"group '{group_name}'",
                )
            group_variables = group_data["vars"]
            duplicates = set(group_variables).intersection(variables)
            if duplicates:
                duplicate = sorted(duplicates)[0]
                raise ValueError(
                    f"Duplicate Ansible INI variable '{duplicate}' "
                    f"in group '{group_name}'"
                )
            if (
                len(group_variables) + len(variables)
                > _ANSIBLE_INVENTORY_MAX_INI_VARIABLES_PER_SCOPE
            ):
                raise ValueError(
                    f"Ansible INI group '{group_name}' exceeds the "
                    "per-scope variable limit"
                )
            group_variables.update(variables)
        else:
            host_name = tokens[0]
            if host_name in seen_hosts:
                raise ValueError(f"Duplicate Ansible INI host '{host_name}'")
            seen_hosts.add(host_name)
            if len(seen_hosts) > _ANSIBLE_INVENTORY_MAX_INI_HOSTS:
                raise ValueError(
                    "Ansible INI inventory exceeds "
                    f"{_ANSIBLE_INVENTORY_MAX_INI_HOSTS} hosts"
                )
            variables = _parse_ansible_ini_variables(
                tokens[1:],
                line_number=line_number,
                scope=f"host '{host_name}'",
            )
            if bmc_group:
                variables = _project_ansible_ini_bmc_variables(
                    variables,
                    scope=f"host '{host_name}'",
                )
            group_data["hosts"][host_name] = variables

        total_variables += len(variables)
        if total_variables > _ANSIBLE_INVENTORY_MAX_INI_VARIABLES:
            raise ValueError(
                "Ansible INI inventory exceeds "
                f"{_ANSIBLE_INVENTORY_MAX_INI_VARIABLES} variables"
            )

    if not seen_hosts:
        raise ValueError("Ansible INI inventory does not declare any hosts")
    return inventory


def _display_yaml_error(file_path: Path, error_message: str, error_type: str) -> None:
    """
    Display YAML error.

    The implementation uses ``file_path``, ``error_message``, and ``error_type``
    to display YAML error.

    Args:
        file_path: filesystem location used as the file path for this operation.
        error_message: Text supplied as error message in the format accepted by
            this function.
        error_type: Text supplied as error type in the format accepted by this
            function.
    """
    console = Console()

    # Create error details table
    error_table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        show_edge=False,
        border_style="red",
    )

    error_table.add_column("Label", style="bold red", width=12)
    error_table.add_column("Details", style="red")

    # Add file path
    error_table.add_row("File:", str(file_path))

    # Add error type
    error_table.add_row("Error Type:", error_type)

    # Parse error message for better display
    if "mapping values are not allowed here" in error_message:
        error_table.add_row("Issue:", "YAML encoding/header corruption")
        error_table.add_row("", "")
        error_table.add_row("Common Causes:", "")
        error_table.add_row(
            "", "• File header corruption (e.g., 'D---' instead of '---')"
        )
        error_table.add_row("", "• Invalid characters in the file")
        error_table.add_row("", "• File encoding issues")
        error_table.add_row("", "")
        error_table.add_row("Suggested Fixes:", "")
        error_table.add_row("", "1. Check the first line - should start with '---'")
        error_table.add_row("", "2. Ensure file is valid UTF-8 encoded")
        error_table.add_row("", "3. Try recreating from original source")
    elif "expected '<document start>'" in error_message:
        error_table.add_row("Issue:", "Missing YAML document start marker")
        error_table.add_row("", "")
        error_table.add_row("Fix:", "Add '---' as the first line of the file")
    elif "while parsing a block mapping" in error_message:
        error_table.add_row("Issue:", "YAML structure/indentation problem")
        error_table.add_row("", "")
        error_table.add_row("Check For:", "")
        error_table.add_row("", "• Incorrect indentation (use spaces, not tabs)")
        error_table.add_row("", "• Missing colons after keys")
        error_table.add_row("", "• Unquoted strings with special characters")
    else:
        error_table.add_row("Issue:", "YAML parsing error")

    error_table.add_row("", "")
    error_table.add_row(
        "Technical Details:",
        "Source excerpts omitted to protect inventory credentials.",
    )

    # Create the main error panel
    error_panel = Panel(
        error_table,
        title="[bold red]🚫 Ansible Inventory YAML Error[/bold red]",
        subtitle="[dim]Please review and fix the YAML file[/dim]",
        border_style="red",
        padding=(1, 2),
        highlight=True,
        title_align="center",
    )

    # Display the error
    console.print(error_panel)

    # Exit with error code
    import sys

    sys.exit(1)


def _fix_common_yaml_issues(file_path: Path) -> str | bool:
    """
    Return an in-memory repair of a bounded YAML document header.

    Pin one regular, single-link inode for reading with O_NOFOLLOW. The source
    file is never rewritten, including when the proposed repair still fails
    YAML validation.

    Args:
        file_path: filesystem location used as the file path for this operation.

    Returns:
        Repaired YAML text, or ``False`` when no bounded repair is available.
    """
    descriptor = -1
    try:
        # Pin one regular, single-link inode before reading it.
        # O_NOFOLLOW prevents a repair request from crossing a symlink.
        descriptor = os.open(
            file_path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        with os.fdopen(descriptor, "rb") as inventory_file:
            descriptor = -1
            metadata = os.fstat(inventory_file.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                return False
            raw_content = inventory_file.read(_ANSIBLE_INVENTORY_MAX_YAML_BYTES + 1)
            if len(raw_content) > _ANSIBLE_INVENTORY_MAX_YAML_BYTES:
                return False
            content = raw_content.decode("utf-8")

            fixes_applied = False

            # Repair the historical single-byte header corruption accepted by
            # this compatibility path; do not attempt general YAML rewriting.
            if content.startswith("D---"):
                content = content.replace("D---", "---", 1)
                fixes_applied = True

            # Preserve an existing document marker. Otherwise add only the
            # missing marker which the legacy repair contract promises.
            if content.startswith("---\n") == False and content.startswith("---"):
                pass
            elif not content.startswith("---"):
                content = "---\n" + content
                fixes_applied = True

            # Keep the repaired representation bounded and in memory.
            if fixes_applied:
                repaired_content = content.encode("utf-8")
                if len(repaired_content) > _ANSIBLE_INVENTORY_MAX_YAML_BYTES:
                    return False
                return content

    except Exception:
        # If we can't fix it, that's okay - let the original error handling take over
        pass
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    return False


def parse_ansible_inventory_to_dut_configs(
    ansible_inventory_path: Path,
    baseboard: Optional[str] = None,
    spreadsheet_path: Optional[CatalogSource] = None,
    *,
    resolve_addon_dns: bool = True,
) -> Tuple[List[DUTConfig], Dict[str, Any]]:
    """
    Parse a static Ansible YAML or INI inventory into DUT configurations.

    YAML retains the bounded strict-loader and narrow compatibility-repair
    behavior. INI is selected before YAML parsing and uses a bounded,
    duplicate-rejecting static subset; it never enters the YAML repair path.

    Args:
        ansible_inventory_path: filesystem location used as the ansible
            inventory path for this operation.
        baseboard: Optional baseboard; ``None`` selects the function's default
            behavior.
        spreadsheet_path: Optional filesystem location used as the spreadsheet
            path for this operation.
        resolve_addon_dns: Whether add-on hostname derivation may perform DNS
            lookups. Disable this for transport-free planning.

    Returns:
        A tuple containing ``DUT configs`` and ``node type configs`` in that
        order.

    Raises:
        FileNotFoundError: If ansible inventory file not found:
            ``ansible_inventory_path``.
        ValueError: If the supplied input cannot be parsed safely, the inventory
            is empty or invalid, an INI bound or uniqueness rule is violated,
            or ansible inventory host '``host_name``' must map to variables or
            null.
    """
    if not ansible_inventory_path.exists():
        raise FileNotFoundError(
            f"Ansible inventory file not found: {ansible_inventory_path}"
        )

    inventory_is_ini = False
    # Load the ansible inventory file with comprehensive error handling.
    try:
        source = _read_bounded_ansible_inventory(ansible_inventory_path)
        inventory_is_ini = _is_ansible_ini_inventory(
            ansible_inventory_path,
            source,
        )
        if inventory_is_ini:
            ansible_data = _parse_ansible_ini_inventory(source)
        else:
            ansible_data = load_yaml_strict(source)
    except FileNotFoundError as e:
        _display_yaml_error(ansible_inventory_path, str(e), "YAML parsing failed")
    except yaml.YAMLError as e:
        # Try to automatically fix common YAML issues
        repaired_source = _fix_common_yaml_issues(ansible_inventory_path)
        if repaired_source:
            try:
                ansible_data = load_yaml_strict(repaired_source)
            except yaml.YAMLError as retry_e:
                # If it still fails after fixes, show the original error with helpful message
                _display_yaml_error(
                    ansible_inventory_path,
                    f"Attempted to fix common YAML issues but parsing still failed.\nRetry error: {str(retry_e)}\nOriginal error: {str(e)}",
                    "Auto-fix failed",
                )
        else:
            # Couldn't auto-fix, show helpful error message
            _display_yaml_error(ansible_inventory_path, str(e), "YAML parsing failed")
    except UnicodeDecodeError as e:
        error_msg = f"Failed to read Ansible inventory file: {ansible_inventory_path}\n"
        error_msg += f"File encoding error: {str(e)}\n"
        error_msg += (
            "The file may not be UTF-8 encoded or may contain invalid characters.\n"
        )
        error_msg += "Please ensure the file is saved as UTF-8."
        raise ValueError(error_msg)
    except ValueError:
        # INI syntax, bounds, and duplicate diagnostics are already sanitized
        # and specific. Preserve them instead of relabeling them as YAML or an
        # unexpected read error.
        raise
    except Exception as e:
        error_msg = f"Unexpected error reading Ansible inventory file: {ansible_inventory_path}\n"
        error_msg += f"Error: {str(e)}"
        raise ValueError(error_msg)

    if not ansible_data:
        raise ValueError("Ansible inventory file is empty or invalid")

    dut_configs = []
    node_type_configs = {}
    inventory_profile = _load_ansible_inventory_profile(spreadsheet_path)

    # Get cluster information from ansible data
    cluster_info = ansible_data.get("all", {}).get("vars", {})
    product_family = cluster_info.get("product_family", "")

    # Parse inventory groups into canonical node types while supporting
    # ansible aliases such as "singlenode" for compute inventories.
    node_type_profile = inventory_profile["node_types"]
    group_order = {
        node_type: index for index, node_type in enumerate(node_type_profile["order"])
    }
    parsed_groups = []

    for group_name, group_data in ansible_data.items():
        if group_name == "all" or not isinstance(group_data, dict):
            continue

        hosts = group_data.get("hosts")
        if not isinstance(hosts, dict):
            continue

        vars_section = group_data.get("vars", {})
        if not isinstance(vars_section, dict):
            vars_section = {}

        node_type = _resolve_ansible_node_type(
            group_name, vars_section, inventory_profile
        )
        if not node_type and inventory_is_ini:
            # Static INI inventories traditionally use site-specific group
            # names and cannot attach YAML's node_type mapping. Preserve
            # recognized switch/power aliases; otherwise use the baseline
            # compute interpretation selected by the explicit CLI baseboard.
            node_type = "Compute"
        if not node_type:
            continue

        parsed_groups.append(
            (
                group_order.get(node_type, len(group_order)),
                len(parsed_groups),
                group_name,
                hosts,
                vars_section,
                node_type,
            )
        )

    for _, _, _group_name, hosts, vars_section, node_type in sorted(parsed_groups):
        # Detect baseboard from ansible data if not provided
        detected_baseboard = _detect_baseboard_from_ansible_data(
            product_family,
            node_type,
            baseboard,
            spreadsheet_path,
        )

        # Group inheritance was resolved during inventory parsing. A previous
        # sibling with the same node type is not a source of host defaults.
        merged_vars = {**cluster_info, **vars_section}
        node_type_configs[node_type] = {
            "platform": "unknown",  # Platform is no longer configurable
            "baseboard": detected_baseboard,
            "vars": merged_vars,
        }

        # Create DUT configs for each host
        for host_name, host_data in hosts.items():
            if host_data is None:
                host_data = {}
            elif not isinstance(host_data, dict):
                raise ValueError(
                    f"Ansible inventory host '{host_name}' must map to variables or null"
                )
            dut_config = _create_dut_config_from_ansible_host(
                host_name,
                host_data,
                merged_vars,
                node_type,
                detected_baseboard,
                inventory_profile,
            )
            dut_configs.append(dut_config)
            dut_configs.extend(
                _create_addon_dut_configs_from_ansible_host(
                    host_name,
                    host_data,
                    merged_vars,
                    node_type,
                    spreadsheet_path,
                    resolve_dns=resolve_addon_dns,
                )
            )

    return dut_configs, node_type_configs


def _resolve_ansible_node_type(
    group_name: str,
    vars_section: Dict[str, Any],
    inventory_profile: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Resolve ansible inventory groups to the tool's canonical node types.

    Group aliases such as "singlenode" are treated as Compute so they flow
    through the same parsing path as standard compute groups.

    Args:
        group_name: Stable group name used for lookup and operator-facing
            diagnostics.
        vars_section: Mapping supplying fields for ansible inventory groups to
            the tool's canonical node types.
        inventory_profile: Optional inventory profile; ``None`` selects the
            function's default behavior.

    Returns:
        The canonical ansible node type text, or ``None`` when the requested
        value is unavailable.
    """

    if inventory_profile is None:
        inventory_profile = validate_ansible_inventory_profile(
            DEFAULT_ANSIBLE_INVENTORY_PROFILE
        )
    normalized_mapping = inventory_profile["node_types"]["aliases"]

    candidates = [
        vars_section.get("host_type"),
        group_name,
    ]

    for candidate in candidates:
        normalized_candidate = "".join(
            char for char in str(candidate).strip().lower() if char.isalnum()
        )
        if normalized_candidate in normalized_mapping:
            return normalized_mapping[normalized_candidate]

    return None


def _detect_baseboard_from_ansible_data(
    product_family: str,
    node_type: str,
    provided_baseboard: Optional[str] = None,
    spreadsheet_path: Optional[CatalogSource] = None,
) -> str:
    """
    Detect baseboard from ansible inventory data.

    The implementation uses ``product_family``, ``node_type``,
    ``provided_baseboard``, and ``spreadsheet_path`` to detect baseboard from
    ansible inventory data. If the function cannot detect baseboard from ansible
    inventory data, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        product_family: Text supplied as product family in the format accepted
            by this function.
        node_type: Text supplied as node type in the format accepted by this
            function.
        provided_baseboard: Optional provided baseboard; ``None`` selects the
            function's default behavior.
        spreadsheet_path: Optional filesystem location used as the spreadsheet
            path for this operation.

    Returns:
        The canonical baseboard from ansible data text.

    Raises:
        ValueError: If the supplied input cannot be used to detect baseboard
            from ansible inventory data.
    """
    # If baseboard is explicitly provided, use it
    if provided_baseboard:
        return provided_baseboard

    product_family_lower = product_family.lower() if product_family else ""
    node_type_lower = node_type.lower()

    mappings = (
        _load_ansible_baseboard_mappings()
        if spreadsheet_path is None
        else _load_ansible_baseboard_mappings(spreadsheet_path)
    )
    best_match: Optional[str] = None
    best_score: Tuple[int, int, int] = (-1, -1, -1)

    for mapping in mappings:
        mapped_pf = mapping.get("product_family")
        mapped_node = mapping.get("node_type")
        baseboard_name = mapping.get("baseboard")

        if not mapped_pf or not baseboard_name:
            continue

        if not product_family_lower:
            continue

        # Normalize mapped values to lowercase for case-insensitive comparison
        # (defensive - mappings should already be normalized when loaded, but this ensures robustness)
        mapped_pf_lower = str(mapped_pf).lower() if mapped_pf else ""
        mapped_node_lower = (
            str(mapped_node).lower()
            if mapped_node is not None and str(mapped_node).strip()
            else None
        )

        # Check for exact match first (preferred)
        pf_exact = product_family_lower == mapped_pf_lower
        # Check for substring match (less preferred, but only if no exact match found)
        # Note: We check if mapped_pf is contained in product_family to handle cases like
        # "gb200 cluster" matching "gb200"
        pf_contains = mapped_pf_lower in product_family_lower if not pf_exact else False

        if not pf_exact and not pf_contains:
            continue

        node_score = -1
        if mapped_node_lower:
            if mapped_node_lower == node_type_lower:
                node_score = 1
            elif mapped_node_lower in node_type_lower:
                node_score = 0
            else:
                continue

        # Prioritize exact product-family matches, then node specificity, then
        # the longest matching product-family token. The final component makes
        # substring matching order-independent: for example, ``vru`` or
        # ``vru-nvl72`` must beat the legacy broad ``vr`` token.
        pf_score = 2 if pf_exact else 1
        score = (pf_score, node_score, len(mapped_pf_lower))
        if score > best_score:
            best_score = score
            best_match = baseboard_name

    if best_match:
        return best_match

    # No mapping found in spreadsheet - this is a configuration error
    # The spreadsheet must be updated to include the mapping for this product_family/node_type combination
    error_msg = (
        f"No baseboard mapping found in spreadsheet for product_family='{product_family}' "
        f"and node_type='{node_type}'. "
        f"Please ensure the spreadsheet includes an Ansible Mapping entry for this combination. "
        f"Found {len(mappings)} mapping(s) in spreadsheet."
    )
    raise ValueError(error_msg)


def _is_non_empty_ansible_value(value: Any) -> bool:
    """
    Return True when an inventory value should be treated as present.

    The implementation uses ``value`` to produce True when an inventory value
    should be treated as present.

    Args:
        value: Value object whose ``strip`` state is read while performing true
            when an inventory value should be treated as present.

    Returns:
        Whether the true when an inventory value should be treated as present
        operation succeeds.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _lookup_inventory_value(
    host_data: Dict[str, Any],
    vars_section: Dict[str, Any],
    keys: Any,
    default: str = "",
    *,
    host_name: str = "",
    field_name: str = "inventory value",
) -> str:
    """
    Look up and resolve the first non-empty host/group inventory alias.

    After applying local validation, the function forwards ``host_data``,
    ``vars_section``, ``keys``, ``default``, and ``host_name`` to
    ``resolver.lookup_string`` and preserves its return and exception contract.

    Args:
        host_data: Mapping supplying fields for look up and resolve the first
            non-empty host/group inventory alias.
        vars_section: Mapping supplying fields for look up and resolve the first
            non-empty host/group inventory alias.
        keys: Keys consumed while the function attempts to look up and resolve
            the first non-empty host/group inventory alias.
        default: Fallback used when the requested value is absent or invalid.
        host_name: Stable host name used for lookup and operator-facing
            diagnostics.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        The canonical inventory value.
    """

    resolver = _AnsibleInventoryResolver(host_name, host_data, vars_section)
    return resolver.lookup_string(keys, default, field_name)


def _contains_matching_inventory_key(
    host_data: Dict[str, Any],
    vars_section: Dict[str, Any],
    pattern: str,
) -> bool:
    """
    Check host/group vars for a non-empty key matching an Ansible pattern.

    The implementation uses ``host_data``, ``vars_section``, and ``pattern`` to
    check host/group vars for a non-empty key matching an Ansible pattern. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        host_data: Mapping supplying fields for host/group vars for a non-empty
            key matching an Ansible pattern.
        vars_section: Mapping supplying fields for host/group vars for a
            non-empty key matching an Ansible pattern.
        pattern: Text supplied as pattern in the format accepted by this
            function.

    Returns:
        Whether the host/group vars for a non-empty key matching an Ansible
        pattern operation succeeds.
    """
    normalized_pattern = pattern.lower()
    for source in (host_data, vars_section):
        for key, value in source.items():
            if fnmatch.fnmatch(str(key).lower(), normalized_pattern) and (
                _is_non_empty_ansible_value(value)
            ):
                return True
    return False


def _short_hostname_from_inventory_value(
    value: Any, *, resolve_dns: bool = True
) -> Optional[str]:
    """
    Return the short hostname from inventory value.

    The implementation uses ``value`` to produce the short hostname from
    inventory value.

    Args:
        value: Value evaluated while performing short hostname from inventory
            value.
        resolve_dns: Whether an IP literal may be reverse-resolved before
            falling back to the supplied inventory value.

    Returns:
        The canonical short hostname from inventory value, or ``None`` when the
        requested value is unavailable.
    """
    value_str = str(value or "").strip()
    if not value_str:
        return None

    if resolve_dns:
        reverse_short_name = reverse_lookup_short_hostname(value_str)
        if reverse_short_name:
            return reverse_short_name

    return short_hostname_from_fqdn(value_str)


def _resolve_addon_source_short_hostname(
    addon_mapping: Dict[str, Any],
    host_name: str,
    host_data: Dict[str, Any],
    vars_section: Dict[str, Any],
    *,
    resolve_dns: bool = True,
) -> Optional[str]:
    """
    Resolve the parent short hostname used to derive add-on addresses.

    DNS reverse lookup of the configured source IP is preferred. Inventory
    hostnames are only fallbacks for local/offline parsing.

    Args:
        addon_mapping: Mapping supplying fields for parent short hostname used
            to derive add-on addresses.
        host_name: Stable host name used for lookup and operator-facing
            diagnostics.
        host_data: Mapping supplying fields for parent short hostname used to
            derive add-on addresses.
        vars_section: Mapping supplying fields for parent short hostname used to
            derive add-on addresses.
        resolve_dns: Whether inventory addresses may be reverse-resolved while
            deriving the add-on hostname.

    Returns:
        The canonical addon source short hostname, or ``None`` when the
        requested value is unavailable.
    """
    for query in addon_mapping.get("ip_query", []):
        if not isinstance(query, dict):
            continue

        source = str(query.get("source", "")).strip()
        lookup = str(query.get("lookup", "hostname")).strip().lower()
        if not source:
            continue

        normalized_source = source.lower()
        if normalized_source in {"compute_ip", "host_ip", "ansible_host"}:
            value = _lookup_inventory_value(
                host_data,
                vars_section,
                "ansible_host",
                host_name=host_name,
                field_name="add-on source address",
            )
        elif normalized_source in {
            "compute_hostname",
            "host_name",
            "hostname",
            "inventory_hostname",
        }:
            value = _lookup_inventory_value(
                host_data,
                vars_section,
                "hostname",
                host_name,
                host_name=host_name,
                field_name="add-on source hostname",
            )
        else:
            value = _lookup_inventory_value(
                host_data,
                vars_section,
                source,
                host_name=host_name,
                field_name="add-on source value",
            )

        if not value:
            continue

        if lookup in {"value", "literal"}:
            return str(value).strip()

        short_name = _short_hostname_from_inventory_value(
            value, resolve_dns=resolve_dns
        )
        if short_name:
            return short_name

    if isinstance(addon_mapping, _StrictAddonMapping) and not addon_mapping.get(
        "source_hostname_fallback"
    ):
        return None

    for candidate in (host_data.get("hostname"), host_name):
        short_name = short_hostname_from_fqdn(str(candidate or ""))
        if short_name:
            return short_name

    return None


def _addon_address_from_suffix(
    short_hostname: str,
    suffixes: List[str],
) -> str:
    """
    Build an add-on DNS address from the parent short hostname.

    The implementation uses ``short_hostname`` and ``suffixes`` to build an
    add-on DNS address from the parent short hostname.

    Args:
        short_hostname: Text supplied as short hostname in the format accepted
            by this function.
        suffixes: Entries supplied as ``suffixes`` without transferring
            container ownership.

    Returns:
        The canonical addon address from suffix text.
    """
    suffix = suffixes[0] if suffixes else ""
    if not suffix:
        return short_hostname
    if short_hostname.endswith(suffix):
        return short_hostname
    suffix_label = suffix.split(".", 1)[0]
    if suffix_label and short_hostname.endswith(suffix_label):
        return f"{short_hostname}{suffix[len(suffix_label):]}"
    return f"{short_hostname}{suffix}"


def _addon_dut_name(short_hostname: str, addon_mapping: Dict[str, Any]) -> str:
    """
    Return the addon DUT name.

    The implementation uses ``short_hostname`` and ``addon_mapping`` to produce
    the addon DUT name.

    Args:
        short_hostname: Text supplied as short hostname in the format accepted
            by this function.
        addon_mapping: Mapping supplying fields for addon DUT name.

    Returns:
        The canonical addon DUT name.
    """
    host_suffixes = addon_mapping.get("ip_suffix", {}).get("host", [])
    suffix = host_suffixes[0] if host_suffixes else ""
    if suffix.startswith("-"):
        label = suffix[1:].split(".", 1)[0]
        if label and not short_hostname.endswith(f"-{label}"):
            return f"{short_hostname}-{label}"
    return f"{short_hostname}-{str(addon_mapping.get('name', 'addon')).lower()}"


def _lookup_addon_address_value(
    addon_mapping: Dict[str, Any],
    address_type: str,
    host_name: str,
    host_data: Dict[str, Any],
    vars_section: Dict[str, Any],
    *,
    resolve_dns: bool = True,
) -> str:
    """
    Look up a direct add-on address when mappings provide inventory keys.

    The implementation uses ``addon_mapping``, ``address_type``, ``host_name``,
    ``host_data``, and ``vars_section`` to look up a direct add-on address when
    mappings provide inventory keys.

    Args:
        addon_mapping: Mapping supplying fields for look up a direct add-on
            address when mappings provide inventory keys.
        address_type: Text supplied as address type in the format accepted by
            this function.
        host_name: Stable host name used for lookup and operator-facing
            diagnostics.
        host_data: Mapping supplying fields for look up a direct add-on address
            when mappings provide inventory keys.
        vars_section: Mapping supplying fields for look up a direct add-on
            address when mappings provide inventory keys.
        resolve_dns: Whether a configured add-on hostname may be forward
            resolved before it is returned.

    Returns:
        The canonical addon address value.
    """
    direct_values: List[str] = []

    for field_name in ("addresses", "address"):
        configured_addresses = addon_mapping.get(field_name)
        if isinstance(configured_addresses, dict):
            direct_values.extend(
                _normalize_string_list(configured_addresses.get(address_type))
            )

    inventory_keys: List[str] = []
    for field_name in ("ip_keys", "address_keys"):
        configured_keys = addon_mapping.get(field_name)
        if isinstance(configured_keys, dict):
            inventory_keys.extend(
                _normalize_string_list(configured_keys.get(address_type))
            )

    inventory_keys.extend(
        _normalize_string_list(addon_mapping.get(f"{address_type}_ip_keys"))
    )
    inventory_keys.extend(
        _normalize_string_list(addon_mapping.get(f"{address_type}_address_keys"))
    )

    if inventory_keys:
        direct_value = _lookup_inventory_value(
            host_data,
            vars_section,
            inventory_keys,
            host_name=host_name,
            field_name=f"add-on {address_type} address",
        )
        if direct_value:
            direct_values.append(direct_value)

    for value in direct_values:
        if not value:
            continue
        resolved = resolve_hostname_to_ip(value) if resolve_dns else value
        if not isinstance(addon_mapping, _StrictAddonMapping):
            return resolved

        # Strict catalog profiles use unresolved single-label values only as
        # legacy activation markers. Valid IP literals, dotted hostnames, and
        # short names which resolve locally remain authoritative addresses.
        if (
            is_ip_literal(value)
            or is_ip_literal(resolved)
            or "." in str(value).strip().rstrip(".")
        ):
            return resolved

    return ""


def _resolve_addon_address(
    addon_mapping: Dict[str, Any],
    address_type: str,
    source_short_hostname: str,
    host_name: str,
    host_data: Dict[str, Any],
    vars_section: Dict[str, Any],
    *,
    resolve_dns: bool = True,
) -> str:
    """
    Resolve an add-on address from direct mapping keys or DNS suffix rules.

    The implementation uses ``addon_mapping``, ``address_type``,
    ``source_short_hostname``, ``host_name``, and ``host_data`` to resolve an
    add-on address from direct mapping keys or DNS suffix rules.

    Args:
        addon_mapping: Mapping supplying fields for add-on address from direct
            mapping keys or DNS suffix rules.
        address_type: Text supplied as address type in the format accepted by
            this function.
        source_short_hostname: Text supplied as source short hostname in the
            format accepted by this function.
        host_name: Stable host name used for lookup and operator-facing
            diagnostics.
        host_data: Mapping supplying fields for add-on address from direct
            mapping keys or DNS suffix rules.
        vars_section: Mapping supplying fields for add-on address from direct
            mapping keys or DNS suffix rules.
        resolve_dns: Whether the derived add-on hostname may be forward
            resolved before it is returned.

    Returns:
        The canonical addon address text.
    """
    direct_address = _lookup_addon_address_value(
        addon_mapping,
        address_type,
        host_name,
        host_data,
        vars_section,
        resolve_dns=resolve_dns,
    )
    if direct_address:
        return direct_address

    suffixes = addon_mapping.get("ip_suffix", {}).get(address_type, [])
    if not suffixes:
        return ""

    derived_address = _addon_address_from_suffix(source_short_hostname, suffixes)
    return resolve_hostname_to_ip(derived_address) if resolve_dns else derived_address


def _should_create_addon_dut(
    addon_mapping: Dict[str, Any],
    host_data: Dict[str, Any],
    vars_section: Dict[str, Any],
    node_type: str,
) -> bool:
    """
    Return whether ``addon_mapping`` should create addon DUT.

    The implementation uses ``addon_mapping``, ``host_data``, ``vars_section``,
    and ``node_type`` to determine whether ``addon_mapping`` should create addon
    DUT.

    Args:
        addon_mapping: Mapping supplying fields for ``addon_mapping`` should
            create addon DUT.
        host_data: Mapping supplying fields for ``addon_mapping`` should create
            addon DUT.
        vars_section: Mapping supplying fields for ``addon_mapping`` should
            create addon DUT.
        node_type: Text supplied as node type in the format accepted by this
            function.

    Returns:
        Whether ``addon_mapping`` should create addon DUT.
    """
    parent_node_types = [
        node_type_value.lower()
        for node_type_value in _normalize_string_list(
            addon_mapping.get("parent_node_types")
        )
    ]
    if parent_node_types and not any(
        parent_node_type in {"*", "all"} or parent_node_type == node_type.lower()
        for parent_node_type in parent_node_types
    ):
        return False

    for search_pattern in _normalize_string_list(
        addon_mapping.get("search_patterns") or addon_mapping.get("search_pattern")
    ):
        if _contains_matching_inventory_key(host_data, vars_section, search_pattern):
            return True

    for key_pattern in _normalize_string_list(
        addon_mapping.get("activation_keys")
        or addon_mapping.get("detect_keys")
        or addon_mapping.get("presence_keys")
    ):
        if _contains_matching_inventory_key(host_data, vars_section, key_pattern):
            return True

    if isinstance(addon_mapping, _StrictAddonMapping):
        return False

    addon_name = str(addon_mapping.get("name", "")).strip().lower()
    if addon_name:
        prefix = f"{addon_name.lower()}_"
        for source in (host_data, vars_section):
            for key, value in source.items():
                if str(key).lower().startswith(prefix) and _is_non_empty_ansible_value(
                    value
                ):
                    return True

    return False


def _create_addon_dut_config_from_mapping(
    addon_mapping: Dict[str, Any],
    host_name: str,
    host_data: Dict[str, Any],
    vars_section: Dict[str, Any],
    *,
    resolve_dns: bool = True,
) -> Optional[DUTConfig]:
    """
    Create addon DUT config from mapping.

    After applying local validation, the function forwards ``addon_mapping``,
    ``host_name``, ``host_data``, and ``vars_section`` to ``DUTConfig`` and
    preserves its return and exception contract.

    Args:
        addon_mapping: Mapping supplying fields for addon DUT config from
            mapping.
        host_name: Stable host name used for lookup and operator-facing
            diagnostics.
        host_data: Mapping supplying fields for addon DUT config from mapping.
        vars_section: Mapping supplying fields for addon DUT config from
            mapping.
        resolve_dns: Whether add-on endpoint construction may perform DNS
            lookups.

    Returns:
        A ``DUTConfig`` representing addon DUT config from mapping, or ``None``
        when the requested value is unavailable.
    """
    short_hostname = _resolve_addon_source_short_hostname(
        addon_mapping,
        host_name,
        host_data,
        vars_section,
        resolve_dns=resolve_dns,
    )
    if not short_hostname:
        return None

    host_ip = _resolve_addon_address(
        addon_mapping,
        "host",
        short_hostname,
        host_name,
        host_data,
        vars_section,
        resolve_dns=resolve_dns,
    )
    bmc_ip = _resolve_addon_address(
        addon_mapping,
        "bmc",
        short_hostname,
        host_name,
        host_data,
        vars_section,
        resolve_dns=resolve_dns,
    )

    credentials = addon_mapping.get("credentials", {})
    host_creds = credentials.get("host", {})
    bmc_creds = credentials.get("bmc", {})
    bmc_ssh_creds = credentials.get("bmc_ssh", {})
    strict_profile = isinstance(addon_mapping, _StrictAddonMapping)
    bmc_ssh_fallback = (
        not strict_profile or bmc_ssh_creds.get("fallback_to_bmc") is True
    )

    bmc_user = _lookup_inventory_value(
        host_data,
        vars_section,
        bmc_creds.get("username", []),
        host_name=host_name,
        field_name="add-on BMC username",
    )
    bmc_pass = _lookup_inventory_value(
        host_data,
        vars_section,
        bmc_creds.get("password", []),
        host_name=host_name,
        field_name="add-on BMC password",
    )
    bmc_ssh_user = _lookup_inventory_value(
        host_data,
        vars_section,
        bmc_ssh_creds.get("username", []),
        bmc_user if bmc_ssh_fallback else "",
        host_name=host_name,
        field_name="add-on BMC SSH username",
    )
    bmc_ssh_pass = _lookup_inventory_value(
        host_data,
        vars_section,
        bmc_ssh_creds.get("password", []),
        bmc_pass if bmc_ssh_fallback else "",
        host_name=host_name,
        field_name="add-on BMC SSH password",
    )

    return DUTConfig(
        name=_addon_dut_name(short_hostname, addon_mapping),
        baseboard=addon_mapping.get("baseboard"),
        NodeType=(
            addon_mapping["node_type"]
            if strict_profile
            else addon_mapping.get("node_type", "Compute")
        ),
        bmc_ip=bmc_ip,
        bmc_user=bmc_user,
        bmc_pass=bmc_pass,
        bmc_ssh_user=bmc_ssh_user,
        bmc_ssh_pass=bmc_ssh_pass,
        host_ip=host_ip,
        host_user=_lookup_inventory_value(
            host_data,
            vars_section,
            host_creds.get("username", []),
            host_name=host_name,
            field_name="add-on host username",
        ),
        host_pass=_lookup_inventory_value(
            host_data,
            vars_section,
            host_creds.get("password", []),
            host_name=host_name,
            field_name="add-on host password",
        ),
        bmc_rf_user=bmc_user,
        bmc_rf_pass=bmc_pass,
        local=False,
        non_interactive=False,
    )


def _create_addon_dut_configs_from_ansible_host(
    host_name: str,
    host_data: Dict[str, Any],
    vars_section: Dict[str, Any],
    node_type: str,
    spreadsheet_path: Optional[CatalogSource] = None,
    *,
    resolve_dns: bool = True,
) -> List[DUTConfig]:
    """
    Create configured add-on DUTs attached to an inventory host.

    The implementation uses ``host_name``, ``host_data``, ``vars_section``,
    ``node_type``, and ``spreadsheet_path`` to create configured add-on DUTs
    attached to an inventory host.

    Args:
        host_name: Stable host name used for lookup and operator-facing
            diagnostics.
        host_data: Mapping supplying fields for configured add-on DUTs attached
            to an inventory host.
        vars_section: Mapping supplying fields for configured add-on DUTs
            attached to an inventory host.
        node_type: Text supplied as node type in the format accepted by this
            function.
        spreadsheet_path: Optional filesystem location used as the spreadsheet
            path for this operation.
        resolve_dns: Whether add-on endpoint construction may perform DNS
            lookups.

    Returns:
        The validated ``addon_configs``.
    """
    addon_configs: List[DUTConfig] = []
    addon_mappings = (
        _load_ansible_addon_device_mappings()
        if spreadsheet_path is None
        else _load_ansible_addon_device_mappings(spreadsheet_path)
    )
    for addon_mapping in addon_mappings:
        if not _should_create_addon_dut(
            addon_mapping, host_data, vars_section, node_type
        ):
            continue
        addon_config = _create_addon_dut_config_from_mapping(
            addon_mapping,
            host_name,
            host_data,
            vars_section,
            resolve_dns=resolve_dns,
        )
        if addon_config:
            addon_configs.append(addon_config)
    return addon_configs


def _resolve_profile_connection_fields(
    resolver: _AnsibleInventoryResolver,
    inventory_profile: Dict[str, Any],
) -> Dict[str, str]:
    """
    Resolve catalog-defined aliases one tier at a time for one host.

    Each tier preserves Ansible's host-over-group precedence. Only when an
    entire protocol-specific tier is empty do we consider the next, more generic
    tier. This prevents a host's generic ``ansible_user`` from replacing
    group-scoped BMC credentials.

    Args:
        resolver: Resolver consumed while the function attempts to resolve
            catalog-defined aliases one tier at a time for one host.
        inventory_profile: Mapping supplying fields for catalog-defined aliases
            one tier at a time for one host.

    Returns:
        The validated ``resolved_fields``.
    """

    field_profiles = inventory_profile["fields"]
    resolved_fields: Dict[str, str] = {}
    resolving_fields: List[str] = []

    def resolve_field(field_name: str) -> str:
        """
        Resolve field.

        The implementation uses ``field_name`` to resolve field. If the function
        cannot resolve field, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            field_name: Field label included in validation failures for the
                selected input.

        Returns:
            The canonical field text.

        Raises:
            ValueError: If ansible inventory profile contains a fallback field
                cycle.
        """
        if field_name in resolved_fields:
            return resolved_fields[field_name]
        if field_name in resolving_fields:
            raise ValueError(
                "Ansible inventory profile contains a fallback field cycle"
            )

        resolving_fields.append(field_name)
        field_profile = field_profiles[field_name]
        field_label = _ANSIBLE_PROFILE_FIELD_LABELS[field_name]
        value = ""

        for tier in field_profile["lookup_tiers"]:
            value = resolver.lookup_string(
                tier["aliases"],
                "",
                field_label,
                reject_conflicts=True,
            )
            if _is_non_empty_ansible_value(value):
                break

        fallback_field = field_profile.get("fallback_field")
        if not _is_non_empty_ansible_value(value) and fallback_field:
            value = resolve_field(fallback_field)

        if field_name == "hostname" and not _is_non_empty_ansible_value(value):
            value = resolver.host_name

        resolving_fields.pop()
        resolved_fields[field_name] = value
        return value

    for field_name in field_profiles:
        resolve_field(field_name)

    return resolved_fields


def _create_dut_config_from_ansible_host(
    host_name: str,
    host_data: Dict[str, Any],
    vars_section: Dict[str, Any],
    node_type: str,
    baseboard: Optional[str] = None,
    inventory_profile: Optional[Dict[str, Any]] = None,
) -> DUTConfig:
    """
    Create a DUTConfig object from Ansible host data.

    The implementation uses ``host_name``, ``host_data``, ``vars_section``,
    ``node_type``, and ``baseboard`` to create a DUTConfig object from Ansible
    host data.

    Args:
        host_name: Stable host name used for lookup and operator-facing
            diagnostics.
        host_data: Mapping supplying fields for DUTConfig object from Ansible
            host data.
        vars_section: Mapping supplying fields for DUTConfig object from Ansible
            host data.
        node_type: Text supplied as node type in the format accepted by this
            function.
        baseboard: Optional baseboard; ``None`` selects the function's default
            behavior.
        inventory_profile: Optional inventory profile; ``None`` selects the
            function's default behavior.

    Returns:
        The validated ``dut_config``.
    """
    host_data = host_data or {}
    resolver = _AnsibleInventoryResolver(host_name, host_data, vars_section)
    if inventory_profile is None:
        inventory_profile = validate_ansible_inventory_profile(
            DEFAULT_ANSIBLE_INVENTORY_PROFILE
        )
    connection_fields = _resolve_profile_connection_fields(resolver, inventory_profile)

    # Create DUTConfig with Ansible data
    dut_config = DUTConfig(
        name=connection_fields["hostname"],
        baseboard=baseboard,
        NodeType=node_type,
        # BMC Configuration
        bmc_ip=connection_fields["bmc_address"],
        bmc_user=connection_fields["bmc_username"],
        bmc_pass=connection_fields["bmc_password"],
        bmc_ssh_user=connection_fields["bmc_ssh_username"],
        bmc_ssh_pass=connection_fields["bmc_ssh_password"],
        bmc_ssh_key_path=connection_fields["bmc_ssh_private_key"],
        # Host Configuration
        host_ip=connection_fields["host_address"],
        host_user=connection_fields["host_username"],
        host_pass=connection_fields["host_password"],
        host_ssh_key_path=connection_fields["host_ssh_private_key"],
        # Redfish Configuration (use BMC credentials as fallback)
        bmc_rf_user=connection_fields["redfish_username"],
        bmc_rf_pass=connection_fields["redfish_password"],
        # Additional configuration
        local=False,  # Default to remote mode
        non_interactive=False,
    )

    return dut_config


def generate_config_files_from_ansible(
    ansible_inventory_path: Path,
    baseboard: Optional[str] = None,
    spreadsheet_path: Optional[CatalogSource] = None,
    *,
    resolve_addon_dns: bool = True,
) -> Tuple[Path, Path]:
    """
    Generate tool_config.yaml and dut_config.yaml files from Ansible inventory.

    The implementation uses ``ansible_inventory_path``, ``baseboard``, and
    ``spreadsheet_path`` to generate tool_config.yaml and dut_config.yaml files
    from Ansible inventory. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        ansible_inventory_path: filesystem location used as the ansible
            inventory path for this operation.
        baseboard: Optional baseboard; ``None`` selects the function's default
            behavior.
        spreadsheet_path: Optional filesystem location used as the spreadsheet
            path for this operation.
        resolve_addon_dns: Whether add-on hostname derivation may perform DNS
            lookups. Disable this for transport-free planning.

    Returns:
        A tuple containing ``config file path`` and ``DUT config file path`` in
        that order.
    """
    # Parse ansible inventory
    dut_configs, _node_type_configs = parse_ansible_inventory_to_dut_configs(
        ansible_inventory_path,
        baseboard,
        spreadsheet_path,
        resolve_addon_dns=resolve_addon_dns,
    )

    # Create temporary directory for generated files
    temp_dir = tempfile.mkdtemp(prefix="nvdebug_ansible_")

    detected_baseboards = list(
        dict.fromkeys(dut.baseboard or "Unknown" for dut in dut_configs)
    )
    if not detected_baseboards:
        detected_baseboards = ["Unknown"]

    # Generate the run-wide config.yaml. TargetBaseboard is safe at this scope
    # only when every target has the same baseboard. Heterogeneous inventories
    # receive isolated per-DUT tool configs below.
    config_data = {
        "LogSanitization": True,
        "GENERATE_HTML_REPORTS": True,
        # Ensure SSH collectors are not skipped by default for ansible-generated configs
        "SKIP_BMC_SSH_LOGS": False,
    }
    if len(detected_baseboards) == 1:
        config_data = {
            "TargetBaseboard": detected_baseboards[0],
            **config_data,
        }

    def _write_generated_yaml(path: Path, data: Dict[str, Any]) -> None:
        """
        Write one private YAML file and erase the temp tree on failure.

        These files contain credentials. A partial generation must not leave the
        first file behind when a later write fails.

        Args:
            path: filesystem location used as the path for this operation.
            data: Mapping supplying fields for one private YAML file and erase
                the temp tree on failure.
        """

        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as stream:
                yaml.dump(data, stream, default_flow_style=False, sort_keys=False)
        except BaseException:
            # These files contain credentials. A partial generation must not
            # leave the first file behind when a later write fails.
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    config_file_path = Path(temp_dir) / "config.yaml"
    _write_generated_yaml(config_file_path, config_data)

    # Generate dut_config.yaml
    dut_config_data = {}

    # Do not copy arbitrary Ansible group vars into DUT_Defaults. Inventory
    # names (for example product_family/ansible_user) are not DUTConfig fields;
    # each host has already been projected through the explicit mapping above.

    heterogeneous_baseboards = len(detected_baseboards) > 1
    per_dut_config_dir = Path(temp_dir) / _GENERATED_DUT_TOOL_CONFIG_DIR
    if heterogeneous_baseboards:
        try:
            per_dut_config_dir.mkdir(mode=0o700)
        except BaseException:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    # Add each DUT. ConfigFileToUse must never be shared across differing
    # baseboards because TargetBaseboard is consumed by runtime services and is
    # archived as the effective per-DUT tool configuration. Preserve the
    # established shared config for homogeneous inventories.
    for index, dut_config in enumerate(dut_configs):
        target_baseboard = dut_config.baseboard or "Unknown"
        effective_config_path = config_file_path
        if heterogeneous_baseboards:
            effective_config_path = per_dut_config_dir / f"{index:04d}.yaml"
            _write_generated_yaml(
                effective_config_path,
                {**config_data, "TargetBaseboard": target_baseboard},
            )
        dut_dict = {
            "NodeType": getattr(dut_config, "NodeType", "Compute"),
            "baseboard": dut_config.baseboard,
            "TargetBaseboard": target_baseboard,
            "BMC_IP": dut_config.bmc_ip,
            "BMC_USERNAME": dut_config.bmc_user,
            "BMC_PASSWORD": dut_config.bmc_pass,
            "BMC_SSH_USERNAME": dut_config.bmc_ssh_user,
            "BMC_SSH_PASSWORD": dut_config.bmc_ssh_pass,
            "HOST_IP": dut_config.host_ip,
            "HOST_USERNAME": dut_config.host_user,
            "HOST_PASSWORD": dut_config.host_pass,
            "RF_User": dut_config.bmc_rf_user,
            "RF_Pass": dut_config.bmc_rf_pass,
            "ConfigFileToUse": str(effective_config_path),
            "ExecutionMode": "RemoteClient",
        }
        dut_config_data[dut_config.name] = dut_dict

    dut_config_file_path = Path(temp_dir) / "dut_config.yaml"
    _write_generated_yaml(dut_config_file_path, dut_config_data)

    return config_file_path, dut_config_file_path


def cleanup_temp_config_files(
    config_file_path: Path, dut_config_file_path: Path
) -> None:
    """
    Clean up temporary configuration files generated from Ansible inventory.

    The implementation uses ``config_file_path`` and ``dut_config_file_path`` to
    clean up temporary configuration files generated from Ansible inventory.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        config_file_path: filesystem location used as the config file path for
            this operation.
        dut_config_file_path: filesystem location used as the DUT config file
            path for this operation.

    Raises:
        OSError: If a generated file or its empty directory cannot be removed.
            Callers own the user-facing warning because they know whether stdout
            is reserved for machine-readable output.
    """
    if config_file_path.exists():
        config_file_path.unlink()
    if dut_config_file_path.exists():
        dut_config_file_path.unlink()

    per_dut_config_dir = config_file_path.parent / _GENERATED_DUT_TOOL_CONFIG_DIR
    if per_dut_config_dir.exists():
        shutil.rmtree(per_dut_config_dir)

    # Remove the parent directory if it's empty.
    temp_dir = config_file_path.parent
    if temp_dir.exists() and not any(temp_dir.iterdir()):
        temp_dir.rmdir()
