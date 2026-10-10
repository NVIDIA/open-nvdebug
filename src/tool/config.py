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
Configuration management for NVDebug Tool.

This module handles loading and validation of configuration files.
"""

import copy
import getpass
import ipaddress
import json
import logging
import math
import os
import re
import tempfile
from functools import wraps
from pathlib import Path
from typing import Annotated, Any, Dict, List, Literal, Optional, Set, Union

import pydantic
import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .services.redfish_pagination import DEFAULT_MAX_PAGINATION_PAGES
from .utils import excel_reader
from .utils.catalog_snapshot import CatalogSnapshot
from .utils.enums import CollectionLevel
from .utils.enums import DutExecutionMode as ExecutionMode
from .utils.enums import NetworkType
from .utils.linked_dut_projection import project_linked_tool_dut_values
from .utils.redfish_limits import (
    DEFAULT_REDFISH_ATTACHMENT_MAX_BYTES,
    DEFAULT_REDFISH_CACHE_ENTRY_MAX_BYTES,
    DEFAULT_REDFISH_CACHE_MAX_BYTES,
    DEFAULT_REDFISH_ERROR_EVIDENCE_AGGREGATE_MAX_BYTES,
    DEFAULT_REDFISH_ERROR_EVIDENCE_MAX_BYTES,
    DEFAULT_REDFISH_ERROR_EVIDENCE_MAX_RESPONSES,
    DEFAULT_REDFISH_ERROR_RESPONSE_MAX_BYTES,
    DEFAULT_REDFISH_PREFLIGHT_RESPONSE_MAX_BYTES,
    DEFAULT_REDFISH_STRUCTURED_RESPONSE_MAX_BYTES,
    MAX_SIGNED_64_BIT_INTEGER,
    REDFISH_RESPONSE_LIMIT_ENVIRONMENT,
    RedfishRequestCaptureLimits,
    RedfishResponseLimits,
)
from .utils.redfish_tls import normalize_sha256_fingerprint
from .utils.sanitizer import create_sanitizer_from_config
from .utils.ssh_security import (
    DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS,
    DEFAULT_SSH_TUNNEL_PREFIX,
    infer_legacy_ssh_host_key_policy,
    infer_legacy_ssh_known_hosts_file,
    normalize_ssh_tunnel_prefix,
)
from .utils.trusted_extensions import call_optional_config_hook

# Global variable to track sanitization setting for early print statements
_global_sanitization_enabled = True

# One declared default is shared by config loading, the CLI boundary, and the
# execution engine.  The configured value remains the authoritative runtime
# limit; no lower hidden cap is applied later.
DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT = 8

# One user-facing HMC transport domain is shared by CLI parsing, DUT model
# validation, qualification contracts, and the packaged configuration example.
HMC_ACCESS_METHODS = (
    "HostBmcTcpPortForwarding",
    "HostBmcTcp",
    "HmcTcpPortForwarding",
    "HmcTcp",
)
HMC_ACCESS_METHOD_HELP = f"HMC access method ({', '.join(HMC_ACCESS_METHODS)})"


def _validate_hmc_access_method(value: Any) -> Optional[str]:
    """
    Validate an explicitly supplied public HMC transport value.

    Omitted values preserve automatic route selection. Explicit CLI and DUT
    configuration values must match the shared transport domain exactly so an
    unsupported route cannot reach configuration resolution or collection.

    Args:
        value: Candidate HMC access method from a CLI or DUT configuration
            source.

    Returns:
        The validated method, or ``None`` when the value was omitted.

    Raises:
        ValueError: If an explicit value is not a supported HMC access method.
    """

    if value is None:
        return None
    if not isinstance(value, str) or value not in HMC_ACCESS_METHODS:
        raise ValueError(
            "HMC access method must be one of: " + ", ".join(HMC_ACCESS_METHODS)
        )
    return value


_MAX_ENTITY_SKIP_PATTERN_LENGTH = 256
_CANONICAL_NODE_TYPES = {
    value.casefold(): value for value in ("Compute", "SwitchTray", "PowerShelf")
}


def _validate_entity_skip_patterns(value: Any) -> List[str]:
    """
    Validate bounded case-sensitive regular expressions for Redfish ID skips.

    Each entry is compiled without case-folding and is later applied as a full
    match to one discovered Redfish identifier. Bounding pattern length keeps
    malformed configuration from creating an unbounded parsing surface before
    collection begins.

    Args:
        value: Candidate list of regular-expression strings supplied by a tool
            or DUT configuration source.

    Returns:
        The validated list without changing order or expression text.

    Raises:
        ValueError: If an entry is empty, exceeds the supported length, or is
            not a valid regular expression.
    """

    if not isinstance(value, list):
        return value
    for pattern in value:
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("Redfish ID skip patterns must be non-empty strings")
        if len(pattern) > _MAX_ENTITY_SKIP_PATTERN_LENGTH:
            raise ValueError(
                "Redfish ID skip patterns must not exceed "
                f"{_MAX_ENTITY_SKIP_PATTERN_LENGTH} characters"
            )
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(
                f"Invalid Redfish ID skip regular expression {pattern!r}: {error}"
            ) from error
    return value


def _normalize_node_type(value: str) -> str:
    """
    Normalize one owner-approved node type to its canonical catalog spelling.

    Matching is case-insensitive at the configuration boundary so downstream
    applicability logic sees only the three stable catalog spellings. Unknown
    values fail before any collector plan or transport is created.

    Args:
        value: Node type supplied by a DUT configuration layer.

    Returns:
        One of ``Compute``, ``SwitchTray``, or ``PowerShelf``.

    Raises:
        ValueError: If the value is not one of the approved node types.
    """

    canonical = (
        _CANONICAL_NODE_TYPES.get(value.casefold()) if isinstance(value, str) else None
    )
    if canonical is None:
        allowed = ", ".join(_CANONICAL_NODE_TYPES.values())
        raise ValueError(f"NodeType must be one of: {allowed}")
    return canonical


_CONFIG_ENV_FIELDS = {
    "baseboard",
    "collection_level",
    "concurrency_mode",
    "execution_scheduler",
    "initial_io_oversubscription",
    "minimum_collector_operations",
    "maximum_collector_operations",
    "max_concurrent_duts",
    "max_concurrent_collectors_per_dut",
    "NVOS_TECH_DUMP_TIMEOUT",
    "REDFISH_DUMP_TIMEOUT",
    "REDFISH_DEVICE_DUMP_SLEEP_DURATION",
    "REDFISH_R31_PAYLOAD",
}


REMOVED_ATTACHMENT_LIMIT_MESSAGE = (
    "additional_data_attachment_limits is no longer supported because "
    "NVDebug collects every advertised AdditionalDataURI attachment"
)


class RemovedAttachmentLimitError(ValueError):
    """
    Raised when obsolete attachment-omission configuration is present.

    Callers receive this exception when the removed attachment limit error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def reject_removed_attachment_limit_setting(values: Any) -> Any:
    """
    Fail closed when a configuration still requests attachment omission.

    The implementation uses ``values`` to fail closed when a configuration still
    requests attachment omission. If the function cannot fail closed when a
    configuration still requests attachment omission, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        values: Values consumed while the function attempts to fail closed when
            a configuration still requests attachment omission.

    Returns:
        The validated ``values``.

    Raises:
        RemovedAttachmentLimitError: If the function cannot fail closed when a
            configuration still requests attachment omission safely.
    """

    if isinstance(values, dict) and "additional_data_attachment_limits" in values:
        raise RemovedAttachmentLimitError(REMOVED_ATTACHMENT_LIMIT_MESSAGE)
    return values


class _FilteredConfigSettingsSource:
    """
    Expose only environment fields declared by the configuration contract.

    The type gives the filtered config settings source responsibility a stable
    runtime boundary. Callers use the declared Python protocol instead of
    depending on its representation.
    """

    def __init__(
        self, source: Any, higher_priority: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize a ``_FilteredConfigSettingsSource`` instance.

        The initializer records ``higher_priority`` and ``source`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            source: Source consumed while the function attempts to initialize a
                ``_FilteredConfigSettingsSource`` instance.
            higher_priority: Optional higher priority; ``None`` selects the
                function's default behavior.
        """
        self.source = source
        self.higher_priority = higher_priority or {}

    def __call__(self) -> Dict[str, Any]:
        """
        Apply the _FilteredConfigSettingsSource operation to the supplied input.

        Environment variables necessarily arrive as text. Convert only the
        declared integer concurrency fallbacks before strict model validation.

        Returns:
            The validated ``filtered``.
        """
        raw = self.source()
        filtered = {
            key: value for key, value in raw.items() if key in _CONFIG_ENV_FIELDS
        }

        # Environment variables necessarily arrive as text. Convert only the
        # declared numeric concurrency fallbacks before model validation and
        # leave the governed mode string unchanged.
        initial_oversubscription = filtered.get("initial_io_oversubscription")
        if isinstance(initial_oversubscription, str):
            try:
                filtered["initial_io_oversubscription"] = float(
                    initial_oversubscription
                )
            except ValueError:
                pass
        for field_name in (
            "minimum_collector_operations",
            "maximum_collector_operations",
            "max_concurrent_duts",
            "max_concurrent_collectors_per_dut",
        ):
            value = filtered.get(field_name)
            if isinstance(value, str):
                try:
                    filtered[field_name] = int(value, 10)
                except ValueError:
                    pass

        # Read only the documented response/evidence/cache Redfish limit
        # variables from the source's raw environment mapping. A global nested
        # delimiter changes unrelated Config environment behavior, so it is
        # deliberately not enabled on the model.
        source_environment = getattr(self.source, "env_vars", {})
        recognized_environment = {
            variable_name.lower(): field_name
            for field_name, variable_name in REDFISH_RESPONSE_LIMIT_ENVIRONMENT.items()
        }
        redfish_prefix = "redfish_session_config__"
        redfish_session: Dict[str, Any] = {}
        if isinstance(source_environment, dict):
            for variable_name, value in source_environment.items():
                normalized_name = str(variable_name).lower()
                field_name = recognized_environment.get(normalized_name)
                if field_name is not None:
                    redfish_session[field_name] = value
                    continue

                # Ignore unrelated nested spellings (for example TLS_MODE),
                # preserving exact-dev environment behavior. Names which look
                # like limit controls must fail closed instead of silently
                # accepting a typo such as MAX_BYTE or RESPONSe/MAX_BYTES.
                if normalized_name.startswith(redfish_prefix):
                    nested_name = normalized_name[len(redfish_prefix) :]
                    if nested_name.startswith(
                        "error_evidence_"
                    ) or nested_name.endswith(
                        (
                            "_max_byte",
                            "_max_bytes",
                            "_max_response",
                            "_max_responses",
                        )
                    ):
                        redfish_session[nested_name] = value

        if redfish_session:
            explicitly_configured_fields: Set[str] = set()
            for holder_name in ("redfish_session_config", "redfish_sessions"):
                higher_session = self.higher_priority.get(holder_name)
                if isinstance(higher_session, dict):
                    explicitly_configured_fields.update(higher_session)
                else:
                    explicitly_configured_fields.update(
                        getattr(higher_session, "model_fields_set", set())
                    )
            for field_name in explicitly_configured_fields:
                redfish_session.pop(field_name, None)
            for field_name, value in tuple(redfish_session.items()):
                if isinstance(value, str):
                    try:
                        redfish_session[field_name] = int(value, 10)
                    except ValueError:
                        # Leave malformed text intact so strict model
                        # validation fails closed with the field name.
                        pass
            if redfish_session:
                filtered["redfish_session_config"] = redfish_session

        # Environment aliases are a lower source, not contradictory spellings
        # in the same tool-YAML layer. Suppress their canonical destination when
        # any accepted higher-priority YAML spelling was supplied.
        if any(key in self.higher_priority for key in ("baseboard", "TargetBaseboard")):
            filtered.pop("baseboard", None)
        if any(
            key in self.higher_priority
            for key in ("execution_scheduler", "execution", "execution_config")
        ):
            filtered.pop("execution_scheduler", None)
        for field_name in (
            "concurrency_mode",
            "initial_io_oversubscription",
            "minimum_collector_operations",
            "maximum_collector_operations",
            "max_concurrent_duts",
            "max_concurrent_collectors_per_dut",
        ):
            nested_field_present = any(
                isinstance(self.higher_priority.get(section_name), dict)
                and field_name in self.higher_priority[section_name]
                for section_name in ("execution", "execution_config")
            )
            if field_name in self.higher_priority or nested_field_present:
                filtered.pop(field_name, None)
        return filtered


_BOOLEAN_ADAPTER = pydantic.TypeAdapter(bool)
MIN_ZIP_SPLIT_THRESHOLD_MB = 0.001


def _normalize_redfish_diagnostic_payload(
    value: Any,
) -> Optional[Dict[str, Any]]:
    """
    Validate one optional, single-operation Redfish diagnostic payload.

    After applying local validation, the function forwards ``value`` to ``dict``
    and preserves its return and exception contract. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        value: Value object whose ``get`` state is read while performing one
            optional, single-operation Redfish diagnostic payload.

    Returns:
        A mapping containing Redfish diagnostic payload, or ``None`` when the
        requested value is unavailable.

    Raises:
        ValueError: If the redfish diagnostic payload is not a non-empty object;
            the redfish diagnostic payload keys are not non-empty strings;
            redfish diagnostic payload lacks a non-empty DiagnosticDataType; or
            oem redfish diagnostic payload lacks a non-empty
            OEMDiagnosticDataType.
    """

    if value is None:
        return None
    if not isinstance(value, dict) or not value:
        raise ValueError("Redfish diagnostic payload must be a non-empty object")
    if any(not isinstance(key, str) or not key.strip() for key in value):
        raise ValueError("Redfish diagnostic payload keys must be non-empty strings")
    diagnostic_type = value.get("DiagnosticDataType")
    if not isinstance(diagnostic_type, str) or not diagnostic_type.strip():
        raise ValueError(
            "Redfish diagnostic payload requires a non-empty DiagnosticDataType"
        )
    if diagnostic_type.strip().upper() == "OEM":
        oem_type = value.get("OEMDiagnosticDataType")
        if not isinstance(oem_type, str) or not oem_type.strip():
            raise ValueError(
                "OEM Redfish diagnostic payload requires a non-empty "
                "OEMDiagnosticDataType"
            )
    return dict(value)


_DEPRECATED_EMBEDDED_DUTS_MESSAGE = (
    "tool_config.yaml field 'duts' is deprecated and unsupported; "
    "define DUTs in dut_config.yaml and use --dut-config"
)


class _DeprecatedEmbeddedDutsError(Exception):
    """
    Internal control flow for a rejected linked tool configuration.

    Callers receive this exception when the deprecated embedded duts error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _has_embedded_tool_duts(data: Any) -> bool:
    """
    Check for the retired root key without reading values or custom mappings.

    The implementation uses ``data`` to check for the retired root key without
    reading values or custom mappings. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        data: Data consumed while the function attempts to check for the retired
            root key without reading values or custom mappings.

    Returns:
        Whether the for the retired root key without reading values or custom
        mappings operation succeeds.
    """

    if type(data) is not dict:  # noqa: E721 - reject custom mapping side effects
        return False
    return any(
        type(key) is str and key == "duts"  # noqa: E721 - exact key type required
        for key in dict.keys(data)
    )


def _normalize_boolean_alias(value: Any) -> Optional[bool]:
    """
    Normalize one boolean spelling exactly as Pydantic model fields do.

    After applying local validation, the function forwards ``value`` to
    ``_BOOLEAN_ADAPTER.validate_python`` and preserves its return and exception
    contract. The source value keeps its ownership while the normalized
    representation is returned separately.

    Args:
        value: Value evaluated while performing one boolean spelling exactly as
            Pydantic model fields do.

    Returns:
        Whether the one boolean spelling exactly as Pydantic model fields do
        operation succeeds, or ``None`` when the decision is unavailable.
    """
    if value is None:
        return None
    return _BOOLEAN_ADAPTER.validate_python(value)


def _validate_report_skip_aliases(values: Any) -> Any:
    """
    Reject null or contradictory report-generation aliases by presence.

    Assignment validation supplies a materialized output holder and root
    defaults. Those values no longer represent one explicit source.

    Args:
        values: Values object whose ``get`` state is read while performing null
            or contradictory report-generation aliases by presence.

    Returns:
        The report skip aliases value selected by the operation.

    Raises:
        ValueError: If ``path`` cannot be null; or ``path`` conflicts with
            ``resolved_path``.
    """

    if not isinstance(values, dict):
        return values

    output = values.get("output")
    if isinstance(output, BaseModel):
        # Assignment validation supplies a materialized output holder and root
        # defaults. Those values no longer represent one explicit source.
        return values

    candidates: List[tuple[str, Any, bool]] = []
    if isinstance(output, dict):
        if "skip_html_reports" in output:
            candidates.append(
                (
                    "output.skip_html_reports",
                    output["skip_html_reports"],
                    False,
                )
            )
        if "generate_html" in output:
            candidates.append(("output.generate_html", output["generate_html"], True))
    if "skip_html_reports" in values:
        candidates.append(("skip_html_reports", values["skip_html_reports"], False))
    if "GENERATE_HTML_REPORTS" in values:
        candidates.append(
            ("GENERATE_HTML_REPORTS", values["GENERATE_HTML_REPORTS"], True)
        )

    resolved: Optional[bool] = None
    resolved_path: Optional[str] = None
    for path, raw_value, invert in candidates:
        if raw_value is None:
            raise ValueError(f"{path} cannot be null")
        value = _normalize_boolean_alias(raw_value)
        canonical_skip = not value if invert else value
        if resolved_path is not None and canonical_skip != resolved:
            raise ValueError(f"{path} conflicts with {resolved_path}")
        resolved = canonical_skip
        resolved_path = path

    return values


_MAX_CONFIG_YAML_BYTES = 8 * 1024 * 1024
_MAX_CONFIG_YAML_ALIASES = 10_000
_MAX_CONFIG_YAML_NODES = 100_000
_MAX_CONFIG_YAML_DEPTH = 128


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """
    Safe YAML loader that rejects duplicate literal mapping keys.

    The type coordinates ``compose_node``, ``get_single_data``,
    ``_node_children``, ``_validate_expanded_node_graph``, and
    ``construct_mapping`` and retains the state those operations share between
    calls. Resource ownership remains inside the instance until the matching
    close, exit, or cleanup operation completes.
    """

    def __init__(self, stream: Any) -> None:
        """
        Initialize an ``_UniqueKeySafeLoader`` instance.

        The initializer records ``_alias_count``, ``_compose_depth``, and
        ``_node_count`` for later operations and establishes the instance
        invariants before any public method runs.

        Args:
            stream: Stream consumed while the function attempts to initialize an
                ``_UniqueKeySafeLoader`` instance.
        """
        super().__init__(stream)
        self._alias_count = 0
        self._node_count = 0
        self._compose_depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        """
        Compose node.

        The implementation uses ``parent`` and ``index`` to compose node. It
        updates ``_alias_count``, ``_compose_depth``, and ``_node_count`` on the
        instance as part of that state transition. If the function cannot
        compose node, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            parent: Parent consumed while the function attempts to compose node.
            index: Zero-based position within the containing sequence.

        Returns:
            The compose node value selected by the operation.

        Raises:
            yaml.composer.ComposerError: If while composing a configuration
                document.
        """
        if self.check_event(yaml.events.AliasEvent):
            self._alias_count += 1
            if self._alias_count > _MAX_CONFIG_YAML_ALIASES:
                event = self.peek_event()
                raise yaml.composer.ComposerError(
                    "while composing a configuration document",
                    None,
                    f"YAML alias count exceeds {_MAX_CONFIG_YAML_ALIASES}",
                    event.start_mark,
                )
            return super().compose_node(parent, index)

        event = self.peek_event()
        self._node_count += 1
        if self._node_count > _MAX_CONFIG_YAML_NODES:
            raise yaml.composer.ComposerError(
                "while composing a configuration document",
                None,
                f"YAML node count exceeds {_MAX_CONFIG_YAML_NODES}",
                event.start_mark,
            )
        self._compose_depth += 1
        try:
            if self._compose_depth > _MAX_CONFIG_YAML_DEPTH:
                raise yaml.composer.ComposerError(
                    "while composing a configuration document",
                    None,
                    f"YAML nesting depth exceeds {_MAX_CONFIG_YAML_DEPTH}",
                    event.start_mark,
                )
            return super().compose_node(parent, index)
        finally:
            self._compose_depth -= 1

    def get_single_data(self) -> Any:
        """
        Construct one document only after bounding its expanded node graph.

        After applying local validation, the function forwards current instance
        state to ``self.construct_document`` and preserves its return and
        exception contract.

        Returns:
            The single data value selected by the operation.
        """

        node = self.get_single_node()
        if node is None:
            return None
        self._validate_expanded_node_graph(node)
        return self.construct_document(node)

    @staticmethod
    def _node_children(node: yaml.Node) -> List[yaml.Node]:
        """
        Return the node children.

        The implementation uses ``node`` to produce the node children.

        Args:
            node: Node object whose ``value`` state is read while performing
                node children.

        Returns:
            The node children returned in operation-defined order.
        """
        if isinstance(node, yaml.MappingNode):
            return [child for pair in node.value for child in pair]
        if isinstance(node, yaml.SequenceNode):
            return list(node.value)
        return []

    def _validate_expanded_node_graph(self, root: yaml.Node) -> None:
        """
        Reject recursive or alias-expanded graphs beyond config limits.

        Composer counters bound the syntax parsed from disk. Aliases can make
        the logical value graph much larger or deeper than that syntax, and a
        self-reference can create a recursive Python container. Walk every
        logical alias occurrence before construction, stopping at the same
        node/depth ceilings so downstream validators never receive such data.

        Args:
            root: filesystem location used as the root for this operation.
        """

        expanded_node_count = 0
        active_nodes: Set[int] = set()

        def visit(node: yaml.Node, depth: int) -> None:
            """
            Visit the current syntax or data node.

            The implementation uses ``node`` and ``depth`` to visit the current
            syntax or data node. If the function cannot visit the current syntax
            or data node, its exception reaches the caller instead of being
            converted into a successful result. Cleanup in the ``finally`` path
            runs for successful, failed, and cancelled execution.

            Args:
                node: Node object whose ``start_mark`` state is read while
                    performing visit the current syntax or data node.
                depth: Numeric depth used while the operation performs bounded
                    accounting.

            Raises:
                yaml.composer.ComposerError: If while composing a configuration
                    document.
            """
            nonlocal expanded_node_count
            expanded_node_count += 1
            if expanded_node_count > _MAX_CONFIG_YAML_NODES:
                raise yaml.composer.ComposerError(
                    "while composing a configuration document",
                    None,
                    f"expanded YAML node count exceeds {_MAX_CONFIG_YAML_NODES}",
                    node.start_mark,
                )
            if depth > _MAX_CONFIG_YAML_DEPTH:
                raise yaml.composer.ComposerError(
                    "while composing a configuration document",
                    None,
                    f"expanded YAML nesting depth exceeds {_MAX_CONFIG_YAML_DEPTH}",
                    node.start_mark,
                )

            children = self._node_children(node)
            if not children:
                return

            node_identity = id(node)
            if node_identity in active_nodes:
                raise yaml.composer.ComposerError(
                    "while composing a configuration document",
                    None,
                    "recursive YAML aliases are not supported",
                    node.start_mark,
                )
            active_nodes.add(node_identity)
            try:
                for child in children:
                    visit(child, depth + 1)
            finally:
                active_nodes.remove(node_identity)

        visit(root, 1)

    def construct_mapping(self, node: Any, deep: bool = False) -> Dict[Any, Any]:
        # Check the mapping before SafeLoader flattens ``<<`` merges. Explicit
        # keys are allowed to override an inherited anchor, but spelling the
        # same key twice in one mapping is always ambiguous and rejected.
        """
        Return the construct mapping.

        After applying local validation, the function forwards ``node`` and
        ``deep`` to ``construct_mapping`` and preserves its return and exception
        contract.

        Args:
            node: Node object whose ``start_mark`` and ``value`` state is read
                while performing construct mapping.
            deep: Whether deep is enabled or required for this operation.

        Returns:
            A mapping containing construct mapping.

        Raises:
            yaml.constructor.ConstructorError: If while constructing a mapping.
        """
        seen: Set[Any] = set()
        merge_key_seen = False
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                if merge_key_seen:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        "found duplicate key '<<'",
                        key_node.start_mark,
                    )
                merge_key_seen = True
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
            except TypeError as error:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from error
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def load_yaml_strict(stream: Any) -> Any:
    """
    Load one bounded YAML document with safe tags and unique mapping keys.

    Construct once so duplicate-key and alias limits cannot be bypassed by a
    second, differently configured YAML pass. Bandit cannot infer that this
    project loader subclasses yaml.SafeLoader; keep the suppression scoped to
    this bounded safe-loader call.

    Args:
        stream: Stream object whose ``read`` state is read while performing one
            bounded YAML document with safe tags and unique mapping keys.

    Returns:
        The YAML strict value selected by the operation.

    Raises:
        TypeError: If the yaml source is not text or bytes.
        yaml.constructor.ConstructorError: If while loading a configuration
            document.
    """

    source = (
        stream.read(_MAX_CONFIG_YAML_BYTES + 1) if hasattr(stream, "read") else stream
    )
    if not isinstance(source, (str, bytes)):
        raise TypeError("YAML source must be text or bytes")
    source_size = (
        len(source.encode("utf-8")) if isinstance(source, str) else len(source)
    )
    if source_size > _MAX_CONFIG_YAML_BYTES:
        raise yaml.constructor.ConstructorError(
            "while loading a configuration document",
            None,
            f"configuration document exceeds {_MAX_CONFIG_YAML_BYTES} bytes",
            None,
        )
    # Construct once so duplicate-key and alias limits cannot be bypassed by a
    # second, differently configured YAML pass.
    # Bandit cannot infer that this project loader subclasses yaml.SafeLoader;
    # keep the suppression scoped to this bounded safe-loader call.
    return yaml.load(source, Loader=_UniqueKeySafeLoader)  # nosec B506


_EXECUTION_CONTROL_FIELDS = (
    "timeout",
    "retry_count",
    "concurrency_mode",
    "initial_io_oversubscription",
    "minimum_collector_operations",
    "maximum_collector_operations",
    "max_concurrent_duts",
    "max_concurrent_collectors_per_dut",
)


def _normalize_execution_control(field_name: str, value: Any) -> Any:
    """
    Normalize one value through the accepted nested execution model.

    The implementation uses ``field_name`` and ``value`` to normalize one value
    through the accepted nested execution model. The source value keeps its
    ownership while the normalized representation is returned separately.

    Args:
        field_name: Field label included in validation failures for the selected
            input.
        value: Value evaluated while performing one value through the accepted
            nested execution model.

    Returns:
        The execution control value selected by the operation.
    """

    if value is None:
        return None
    try:
        section = ExecutionSectionConfig.model_validate({field_name: value})
    except (TypeError, ValueError):
        return value
    return getattr(section, field_name)


def _reject_conflicting_execution_control_aliases(
    values: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Reject contradictory explicitly supplied execution-control aliases.

    The implementation uses ``values`` to reject contradictory explicitly
    supplied execution-control aliases. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        values: Mapping supplying fields for contradictory explicitly supplied
            execution-control aliases.

    Returns:
        The validated ``values``.

    Raises:
        ValueError: If ``first_path`` conflicts with ``path``.
    """

    for field_name in _EXECUTION_CONTROL_FIELDS:
        candidates: List[tuple[str, Any]] = []
        if field_name in values:
            candidates.append((field_name, values[field_name]))
        for section_name in ("execution", "execution_config"):
            section = values.get(section_name)
            if isinstance(section, dict) and field_name in section:
                candidates.append((f"{section_name}.{field_name}", section[field_name]))

        if not candidates:
            continue

        first_path, first_value = candidates[0]
        first_value = _normalize_execution_control(field_name, first_value)
        for path, value in candidates[1:]:
            if _normalize_execution_control(field_name, value) != first_value:
                raise ValueError(f"{first_path} conflicts with {path}")
    return values


_CONFIG_LOCATION_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_ConfigLocationSortKey = tuple[tuple[int, Union[str, int]], ...]


def _render_config_error_location(
    location: Any,
) -> Optional[tuple[_ConfigLocationSortKey, str]]:
    """
    Render a Pydantic location without conflating component types.

    The implementation uses ``location`` to render a Pydantic location without
    conflating component types. The source value keeps its ownership while the
    normalized representation is returned separately.

    Args:
        location: Entries supplied as ``location`` and processed in
            caller-provided order.

    Returns:
        A tuple containing ``tuple`` and ``join`` in that order.
    """

    if type(location) is not tuple or not location:  # noqa: E721 - strict shape
        return None

    sort_key: List[tuple[int, Union[str, int]]] = []
    rendered: List[str] = []
    for component in location:
        if type(component) is str:  # noqa: E721 - strict error-location shape
            sort_key.append((0, component))
            if _CONFIG_LOCATION_IDENTIFIER.fullmatch(component):
                separator = "" if not rendered else "."
                rendered.append(f"{separator}{component}")
            else:
                rendered.append(f"[{json.dumps(component, ensure_ascii=True)}]")
        elif type(component) is int:  # noqa: E721 - bool must not be accepted
            sort_key.append((1, component))
            rendered.append(f"[{component}]")
        else:
            return None

    return tuple(sort_key), "".join(rendered)


def _extra_forbidden_config_paths(
    error: pydantic.ValidationError,
) -> Optional[List[str]]:
    """
    Return sorted, value-free paths when every error is an unknown key.

    The implementation uses ``error`` to produce sorted, value-free paths when
    every error is an unknown key.

    Args:
        error: Exception or failure detail associated with the operation.

    Returns:
        The extra forbidden config paths returned in operation-defined order, or
        ``None`` when the requested value is unavailable.
    """

    locations: List[tuple[_ConfigLocationSortKey, str]] = []
    for detail in error.errors():
        if (
            type(detail) is not dict  # noqa: E721 - reject custom mappings
            or detail.get("type") != "extra_forbidden"
        ):
            return None
        rendered = _render_config_error_location(detail.get("loc"))
        if rendered is None:
            return None
        locations.append(rendered)

    if not locations:
        return None
    locations.sort(key=lambda item: item[0])
    return [rendered for _, rendered in locations]


def _mapping_paths(value: Any, prefix: str = "") -> Set[str]:
    """
    Return dotted paths which were present in an input mapping.

    The implementation uses ``value`` and ``prefix`` to produce dotted paths
    which were present in an input mapping.

    Args:
        value: Value object whose ``items`` state is read while performing
            dotted paths which were present in an input mapping.
        prefix: Text supplied as prefix in the format accepted by this function.

    Returns:
        The unique mapping paths returned by the operation.
    """

    paths: Set[str] = set()
    if not isinstance(value, dict):
        return paths
    for key, child in value.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        paths.add(path)
        paths.update(_mapping_paths(child, path))
    return paths


def _reject_conflicting_execution_scheduler_aliases(
    values: Dict[str, Any],
) -> None:
    """
    Reject contradictory scheduler spellings which share one input source.

    The implementation uses ``values`` to reject contradictory scheduler
    spellings which share one input source. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        values: Mapping supplying fields for contradictory scheduler spellings
            which share one input source.

    Raises:
        ValueError: If ``first_path`` conflicts with ``path``.
    """

    candidates: List[tuple[str, Any]] = []
    if "execution_scheduler" in values:
        candidates.append(("execution_scheduler", values["execution_scheduler"]))
    for section_name in ("execution", "execution_config"):
        section = values.get(section_name)
        if isinstance(section, dict) and "scheduler" in section:
            candidates.append((f"{section_name}.scheduler", section["scheduler"]))

    if not candidates:
        return

    first_path, first_value = candidates[0]
    first_value = (
        first_value.strip().lower() if isinstance(first_value, str) else first_value
    )
    for path, value in candidates[1:]:
        normalized = value.strip().lower() if isinstance(value, str) else value
        if normalized != first_value:
            raise ValueError(f"{first_path} conflicts with {path}")


def _reject_conflicting_baseboard_aliases(values: Dict[str, Any]) -> None:
    """
    Reject contradictory tool-level baseboard aliases from one source.

    The implementation uses ``values`` to reject contradictory tool-level
    baseboard aliases from one source. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        values: Mapping supplying fields for contradictory tool-level baseboard
            aliases from one source.

    Raises:
        ValueError: If baseboard and TargetBaseboard conflict when exactly one
            is null; or baseboard conflicts with TargetBaseboard.
    """

    if "baseboard" not in values or "TargetBaseboard" not in values:
        return

    modern = values["baseboard"]
    legacy = values["TargetBaseboard"]
    if (modern is None) != (legacy is None):
        raise ValueError(
            "baseboard and TargetBaseboard conflict when exactly one is null"
        )
    if modern is None:
        return

    def canonical(value: Any) -> Any:
        """
        Return the canonical value.

        The implementation uses ``value`` to produce the canonical value.

        Args:
            value: Value object whose ``strip`` state is read while performing
                canonical value.

        Returns:
            The canonical value.
        """
        return value.strip().casefold() if isinstance(value, str) else value

    if canonical(modern) != canonical(legacy):
        raise ValueError("baseboard conflicts with TargetBaseboard")


_DEPRECATED_TOOL_CONFIG_CONCEPTS = (
    (
        ("timeout", "execution.timeout", "execution_config.timeout"),
        "Use the Telemetry Catalog Timeout column or a collector-specific timeout setting.",
    ),
    (
        (
            "retry_count",
            "execution.retry_count",
            "execution_config.retry_count",
        ),
        "Use the Telemetry Catalog Retry Count column or a protocol-specific retry setting.",
    ),
    (
        ("execution_mode",),
        "Use --local/local for a local run or DUT ExecutionMode for a DUT-scoped mode.",
    ),
    (
        ("output.generate_json",),
        "Bundle JSON status and metadata are mandatory and cannot be disabled.",
    ),
    (
        ("output.preserve_metadata",),
        "Supported bundle metadata is always preserved.",
    ),
)


def tool_config_deprecation_messages(config: Any) -> List[str]:
    """
    Return one stable warning for each explicitly configured dead concept.

    The implementation uses ``config`` to produce one stable warning for each
    explicitly configured dead concept.

    Args:
        config: Config governing one stable warning for each explicitly
            configured dead concept.

    Returns:
        The tool config deprecation messages returned in operation-defined
        order.
    """

    if isinstance(config, dict):
        explicit_paths = _mapping_paths(config)
    else:
        yaml_paths = getattr(config, "_yaml_paths", None)
        if yaml_paths is None:
            return []
        explicit_paths = set(yaml_paths)

    messages: List[str] = []
    for aliases, replacement in _DEPRECATED_TOOL_CONFIG_CONCEPTS:
        present = [path for path in aliases if path in explicit_paths]
        if not present:
            continue
        rendered = ", ".join(present)
        messages.append(
            f"Deprecated configuration field(s) {rendered} are accepted for "
            f"compatibility but have no effect and will be removed in 3.0. {replacement}"
        )
    if "ipmi_cipher" in explicit_paths:
        messages.append(
            "Deprecated tool_config field ipmi_cipher is accepted as a per-DUT "
            "default for compatibility. Move ipmi_cipher to dut_config.yaml."
        )
    return messages


def set_global_sanitization_enabled(enabled: bool) -> None:
    """
    Set the global sanitization setting for early print statements.

    The implementation uses ``enabled`` to set the global sanitization setting
    for early print statements.

    Args:
        enabled: Whether enabled is enabled or required for this operation.
    """
    global _global_sanitization_enabled
    _global_sanitization_enabled = enabled


def _sanitize_print_message(message: str) -> str:
    """
    Sanitize print messages to avoid exposing usernames in paths.

    The implementation uses ``message`` to sanitize print messages to avoid
    exposing usernames in paths.

    Args:
        message: Operator-facing text carried by the reported event or failure.

    Returns:
        The canonical print message.
    """
    try:
        current_username = getpass.getuser()
        sanitizer = create_sanitizer_from_config(
            {},
            enabled=_global_sanitization_enabled,
            username_strings=[current_username] if current_username else [],
        )
        return sanitizer.sanitize(message)
    except Exception:
        # If sanitization fails, return original message
        return message


def _validate_ip_network_fields(values: Dict[str, Any]) -> None:
    """
    Validate IP network fields.

    The implementation uses ``values`` to validate IP network fields. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        values: Mapping supplying fields for iP network fields.

    Raises:
        ValueError: If the supplied input cannot be used to validate IP network
            fields; or ``field_name``=``value`` is IPv``version``, but
            IP_NETWORK is '``network``'.
    """
    network = str(values.get("IP_NETWORK") or NetworkType.IPV4.value).strip().lower()
    valid_networks = {NetworkType.IPV4.value, NetworkType.IPV6.value}
    if network not in valid_networks:
        raise ValueError(
            f"IP_NETWORK must be one of {sorted(valid_networks)}, got '{network}'"
        )

    values["IP_NETWORK"] = network
    expected_version = 6 if network == NetworkType.IPV6.value else 4

    for field_name in (
        "BMC_IP",
        "HOST_IP",
        "HMC_IP",
        "SSH_PROXY_HOST",
        "bmc_ip",
        "host_ip",
        "hmc_ip",
        "ssh_proxy_host",
    ):
        value = values.get(field_name)
        if value in (None, ""):
            continue

        address = str(value).strip().strip("[]")
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            # Hostnames are still valid here; the selected family is enforced
            # by ping/connection behavior at runtime.
            continue

        if parsed.version != expected_version:
            raise ValueError(
                f"{field_name}={value!r} is IPv{parsed.version}, "
                f"but IP_NETWORK is '{network}'"
            )


def _sync_collector_skip_aliases(
    values: Dict[str, Any], explicit_fields: Optional[Set[str]] = None
) -> Dict[str, Any]:
    """
    Synchronize the list-valued per-DUT collector skip aliases.

    The implementation uses ``values`` and ``explicit_fields`` to synchronize
    the list-valued per-DUT collector skip aliases.

    Args:
        values: Mapping supplying fields for synchronize the list-valued per-DUT
            collector skip aliases.
        explicit_fields: Optional explicit fields; ``None`` selects the
            function's default behavior.

    Returns:
        A mapping containing sync collector skip aliases.
    """

    if not isinstance(values, dict):
        return values

    if explicit_fields is None:
        explicit_fields = set(values)

    if "skip_collectors" in explicit_fields:
        values["COLLECTOR_TO_SKIP"] = values.get("skip_collectors")
    elif "COLLECTOR_TO_SKIP" in explicit_fields:
        values["skip_collectors"] = values.get("COLLECTOR_TO_SKIP")

    return values


def _normalize_collector_skip_source(values: Any) -> Any:
    """
    Copy and normalize one DUT precedence source before it is merged.

    The implementation uses ``values`` to copy and normalize one DUT precedence
    source before it is merged.

    Args:
        values: Values consumed while the function attempts to copy and
            normalize one DUT precedence source before it is merged.

    Returns:
        The collector skip source value selected by the operation.
    """

    if not isinstance(values, dict):
        return values

    normalized = dict(values)
    return _sync_collector_skip_aliases(
        normalized,
        explicit_fields=set(normalized),
    )


def _normalize_collector_skip_document(values: Any) -> Any:
    """
    Normalize every mapping layer in one DUT configuration document.

    The implementation uses ``values`` to normalize every mapping layer in one
    DUT configuration document. The source value keeps its ownership while the
    normalized representation is returned separately.

    Args:
        values: Values object whose ``items`` state is read while performing
            every mapping layer in one DUT configuration document.

    Returns:
        The collector skip document value selected by the operation.
    """

    if not isinstance(values, dict):
        return values

    return {
        key: _normalize_collector_skip_source(layer) for key, layer in values.items()
    }


LEGACY_FIELD_MAPPINGS: Dict[str, str] = {
    # BMC fields
    "bmc_ip": "BMC_IP",
    "bmc_user": "BMC_USERNAME",
    "bmc_pass": "BMC_PASSWORD",
    "bmc_ssh_user": "BMC_SSH_USERNAME",
    "bmc_ssh_pass": "BMC_SSH_PASSWORD",
    "bmc_ssh_port": "BMC_SSH_PORT",
    "bmc_ssh_key_path": "BMC_SSH_KEY_PATH",
    "bmc_ssh_passwordless": "BMC_SSH_PASSWORDLESS",
    "bmc_ssh_max_retries": "BMC_SSH_MAX_RETRIES",
    "bmc_rf_user": "RF_User",
    "bmc_rf_pass": "RF_Pass",
    "bmc_rf_port": "BMC_RF_PORT",
    "bmc_use_https": "BMC_USE_HTTPS",
    # Host fields
    "host_ip": "HOST_IP",
    "host_user": "HOST_USERNAME",
    "host_pass": "HOST_PASSWORD",
    "host_ssh_port": "HOST_SSH_PORT",
    "host_ssh_key_path": "HOST_SSH_KEY_PATH",
    "host_ssh_passwordless": "HOST_SSH_PASSWORDLESS",
    "host_ssh_max_retries": "HOST_SSH_MAX_RETRIES",
    # HMC fields
    "hmc_ip": "HMC_IP",
    "hmc_user": "HMC_USERNAME",
    "hmc_pass": "HMC_PASSWORD",
    "hmc_ssh_user": "HMC_SSH_USERNAME",
    "hmc_ssh_pass": "HMC_SSH_PASSWORD",
    "hmc_ssh_port": "HMC_SSH_PORT",
    "hmc_ssh_key_path": "HMC_SSH_KEY_PATH",
    "hmc_ssh_passwordless": "HMC_SSH_PASSWORDLESS",
    "hmc_ssh_max_retries": "HMC_SSH_MAX_RETRIES",
    "hmc_http_port": "HMC_HTTP_PORT",
    "hmc_https_port": "HMC_HTTPS_PORT",
    "hmc_use_https": "HMC_USE_HTTPS",
    "hmc_access_method": "RF_HMC_ACCESS_METHOD",
    "use_port_forwarding": "USE_PORT_FORWARDING",
    "setup_port_forwarding": "SETUP_PORT_FORWARDING",
    "force_port_fw": "FORCE_PORT_FW",
    "tunnel_tcp_port": "TUNNEL_TCP_PORT",
    # SSH Proxy fields
    "ssh_proxy_host": "SSH_PROXY_HOST",
    "ssh_proxy_port": "SSH_PROXY_PORT",
    "ssh_proxy_user": "SSH_PROXY_USERNAME",
    "ssh_proxy_pass": "SSH_PROXY_PASSWORD",
    "ssh_proxy_key_path": "SSH_PROXY_KEY_PATH",
    "ssh_proxy_passwordless": "SSH_PROXY_PASSWORDLESS",
    "ssh_proxy_max_retries": "SSH_PROXY_MAX_RETRIES",
}

# These aliases represent one semantic field with different value types and
# therefore cannot use the ordinary same-value legacy synchronizer below.
TRANSFORMED_DUT_FIELD_MAPPINGS: Dict[str, str] = {
    "local": "ExecutionMode",
}


def sync_execution_mode_fields(values: Any) -> Any:
    """
    Canonicalize ``local`` / ``ExecutionMode`` by source presence.

    ``local`` itself is non-nullable. Preserve the value so Pydantic emits its
    normal validation error instead of inventing a mode.

    Args:
        values: Values object whose ``get`` state is read while performing
            ``local`` / ``ExecutionMode`` by source presence.

    Returns:
        The sync execution mode fields value selected by the operation.

    Raises:
        ValueError: If the executionmode is not LOCAL, REMOTE, or RemoteClient.
    """

    if not isinstance(values, dict):
        return values

    if "local" in values:
        local = _normalize_boolean_alias(values.get("local"))
        if local is None:
            # ``local`` itself is non-nullable. Preserve the value so Pydantic
            # emits its normal validation error instead of inventing a mode.
            values["ExecutionMode"] = None
            return values
    elif "ExecutionMode" in values:
        raw_mode = values.get("ExecutionMode")
        if hasattr(raw_mode, "value"):
            raw_mode = raw_mode.value
        normalized = str(raw_mode or "remote").strip().lower()
        compact = normalized.replace("_", "").replace("-", "").replace(" ", "")
        if compact == "local":
            local = True
        elif compact in {"remote", "remoteclient"}:
            local = False
        else:
            raise ValueError("ExecutionMode must be LOCAL, REMOTE, or RemoteClient")
    else:
        return values

    values["local"] = local
    values["ExecutionMode"] = ExecutionMode.LOCAL.value if local else "REMOTE"
    return values


def _normalize_execution_mode_source_layer(values: Any) -> Dict[str, Any]:
    """
    Copy and canonicalize one DUT precedence layer.

    TargetBaseboard is a legacy tool/DUT-file input coordinate, not a runtime
    DUTConfig field. Consume it at the file boundary so strict model extras do
    not reject generated Ansible inventories which intentionally emit both
    spellings for compatibility. Presence-aware conflict checks keep a
    contradictory legacy value from being silently discarded.

    Args:
        values: Values consumed while the function attempts to copy and
            canonicalize one DUT precedence layer.

    Returns:
        A mapping containing execution mode source layer.

    Raises:
        ValueError: If the dut execution-mode source layer is not a mapping.
    """

    if values is None:
        return {}
    if not isinstance(values, dict):
        raise ValueError("DUT execution-mode source layer must be a mapping")
    normalized = dict(values)

    # TargetBaseboard is a legacy tool/DUT-file input coordinate, not a runtime
    # DUTConfig field.  Consume it at the file boundary so strict model extras
    # do not reject generated Ansible inventories which intentionally emit both
    # spellings for compatibility.  Presence-aware conflict checks keep a
    # contradictory legacy value from being silently discarded.
    _reject_conflicting_baseboard_aliases(normalized)
    if "TargetBaseboard" in normalized:
        legacy_baseboard = normalized.pop("TargetBaseboard")
        if "baseboard" not in normalized:
            normalized["baseboard"] = legacy_baseboard

    return sync_execution_mode_fields(normalized)


def _deep_merge_mapping(
    base: Dict[str, Any], override: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Recursively merge mappings while replacing scalar and list values.

    The implementation uses ``base`` and ``override`` to recursively merge
    mappings while replacing scalar and list values.

    Args:
        base: Mapping supplying fields for recursively merge mappings while
            replacing scalar and list values.
        override: Mapping supplying fields for recursively merge mappings while
            replacing scalar and list values.

    Returns:
        The validated ``merged``.
    """
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_mapping(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def merge_dut_config_layers(*layers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge DUT layers and deep-merge generic extension namespaces.

    Existing DUT configuration precedence remains shallow for compatibility.
    Trusted-package adapters may translate bounded legacy aliases before the
    generic ``COLLECTOR_EXTENSION_CONFIG`` mapping is merged. Lists are always
    replaced by a later layer rather than concatenated.

    Args:
        layers: Additional positional values forwarded in caller-provided order.

    Returns:
        The validated ``merged``.
    """
    merged: Dict[str, Any] = {}
    extension_config: Any = {}
    saw_extension_config = False
    missing = object()
    for layer in layers:
        if not isinstance(layer, dict):
            continue
        layer_copy = call_optional_config_hook("normalize_dut_config", layer)
        raw_extension_config = layer_copy.pop("COLLECTOR_EXTENSION_CONFIG", missing)
        merged.update(layer_copy)
        if raw_extension_config is missing:
            continue
        if isinstance(raw_extension_config, dict):
            if not isinstance(extension_config, dict):
                extension_config = {}
            extension_config = _deep_merge_mapping(
                extension_config, raw_extension_config
            )
            saw_extension_config = True
        else:
            # Let Pydantic report the useful type-validation error later.
            extension_config = raw_extension_config
            saw_extension_config = True
    if saw_extension_config:
        merged["COLLECTOR_EXTENSION_CONFIG"] = extension_config
    return merged


def sync_legacy_fields(
    values: Dict[str, Any], explicit_fields: Optional[Set[str]] = None
) -> Dict[str, Any]:
    """
    Synchronize new/legacy field pairs with explicit precedence.

    Alias precedence is based on source presence, not truthiness. An explicit
    nullable clear or empty string is still a value and must not be replaced by
    the conflicting spelling from the same source.

    Args:
        values: Mapping supplying fields for synchronize new/legacy field pairs
            with explicit precedence.
        explicit_fields: Optional explicit fields; ``None`` selects the
            function's default behavior.

    Returns:
        A mapping containing sync legacy fields.
    """
    if not isinstance(values, dict):
        return values

    if explicit_fields is None:
        explicit_fields = set(values.keys())

    _sync_collector_skip_aliases(values, explicit_fields=explicit_fields)

    for new_field, legacy_field in LEGACY_FIELD_MAPPINGS.items():
        new_is_explicit = new_field in explicit_fields
        legacy_is_explicit = legacy_field in explicit_fields

        new_value = values.get(new_field)
        legacy_value = values.get(legacy_field)

        # Alias precedence is based on source presence, not truthiness. An
        # explicit nullable clear or empty string is still a value and must not
        # be replaced by the conflicting spelling from the same source.
        if new_is_explicit:
            values[legacy_field] = new_value
        elif legacy_is_explicit:
            values[new_field] = legacy_value

    return values


class DUTConfig(BaseModel):
    """
    DUT (Device Under Test) configuration with consistent field naming.

    This class represents the configuration for a single device under test,
    including connection parameters, credentials, and execution settings.

    Attributes:
        name: Canonical text used as name.
        baseboard: Canonical text used as baseboard.
        description: Canonical text used as description.
        openbmc_analyzer_machine: Canonical text used as openbmc analyzer
            machine.
        openbmc_commit: Canonical text used as openbmc commit.
        local: Whether local applies to this record.
        non_interactive: Whether non interactive applies to this record.
        bmc_ip: Canonical text used as BMC IP.
        bmc_user: Canonical text used as BMC user.
        bmc_pass: Canonical text used as BMC pass.
        bmc_ssh_user: Canonical text used as BMC SSH user.
        bmc_ssh_pass: Canonical text used as BMC SSH pass.
        bmc_ssh_port: Numeric BMC SSH port retained by this record.
        bmc_ssh_key_path: Validated filesystem location associated with BMC SSH
            key path.
        bmc_ssh_passwordless: Whether BMC SSH passwordless applies to this
            record.
        bmc_ssh_max_retries: Number of BMC SSH max retries represented by this
            record.
        bmc_rf_user: Canonical text used as BMC Redfish user.
        bmc_rf_pass: Canonical text used as BMC Redfish pass.
        bmc_rf_port: Numeric BMC Redfish port retained by this record.
        bmc_use_https: Whether BMC use HTTPS applies to this record.
        bmc_rf_verify_ssl: Whether BMC Redfish verify ssl applies to this
            record.
        bmc_rf_tls_mode: Numeric BMC Redfish TLS mode retained by this record.
        bmc_rf_ca_file: Canonical text used as BMC Redfish ca file.
        bmc_rf_fingerprint_sha256: Lowercase SHA-256 digest binding the BMC
            Redfish fingerprint content.
        bmc_rf_tls_server_name: Canonical text used as BMC Redfish TLS server
            name.
        bmc_rf_authentication_mode: Optional per-DUT auto, basic, or session
            authentication policy. Null and omission inherit the tool policy.
        host_ip: Canonical text used as host IP.
        host_user: Canonical text used as host user.
        host_pass: SSH login password or local private-key passphrase.
        host_sudo_password: Optional remote sudo credential, separate from SSH
            authentication and omitted from the model representation.
        host_ssh_port: Numeric host SSH port retained by this record.
        host_ssh_key_path: Validated filesystem location associated with host
            SSH key path.
        host_ssh_passwordless: Whether host SSH passwordless applies to this
            record.
        host_ssh_max_retries: Number of host SSH max retries represented by this
            record.
        hmc_ip: Canonical text used as HMC IP.
        hmc_user: Canonical text used as HMC user.
        hmc_pass: Canonical text used as HMC pass.
        hmc_ssh_user: Canonical text used as HMC SSH user.
        hmc_ssh_pass: Canonical text used as HMC SSH pass.
        hmc_ssh_port: Numeric HMC SSH port retained by this record.
        hmc_ssh_key_path: Validated filesystem location associated with HMC SSH
            key path.
        hmc_ssh_passwordless: Whether HMC SSH passwordless applies to this
            record.
        hmc_ssh_max_retries: Number of HMC SSH max retries represented by this
            record.
        hmc_http_port: Numeric HMC HTTP port retained by this record.
        hmc_https_port: Numeric HMC HTTPS port retained by this record.
        hmc_use_https: Whether HMC use HTTPS applies to this record.
        hmc_access_method: Canonical text used as HMC access method.
        use_port_forwarding: Whether use port forwarding applies to this record.
        setup_port_forwarding: Whether setup port forwarding applies to this
            record.
        force_port_fw: Whether force port firmware applies to this record.
        tunnel_tcp_port: Canonical text used as tunnel TCP port.
        ssh_proxy_host: Canonical text used as SSH proxy host.
        ssh_proxy_port: Numeric SSH proxy port retained by this record.
        ssh_proxy_user: Canonical text used as SSH proxy user.
        ssh_proxy_pass: Canonical text used as SSH proxy pass.
        ssh_proxy_key_path: Validated filesystem location associated with SSH
            proxy key path.
        ssh_proxy_passwordless: Whether SSH proxy passwordless applies to this
            record.
        ssh_proxy_max_retries: Number of SSH proxy max retries represented by
            this record.
        ssh_host_key_policy: Canonical text used as SSH host key policy.
        ssh_known_hosts_file: Canonical text used as SSH known hosts file.
        skip_collectors: Collection of skip collectors entries retained by this
            record.
        include_collectors: Collection of include collectors entries retained by
            this record.
        SKIP_PORT_FW: Whether skip port firmware applies to this record.
        SKIP_BMC_SSH_LOGS: Whether skip BMC SSH logs applies to this record.
        SKIP_HOST_LOGS: Whether skip host logs applies to this record.
        SKIP_IPMI_LOGS: Whether skip IPMI logs applies to this record.
        SKIP_REDFISH_OOB_LOGS: Whether skip Redfish oob logs applies to this
            record.
        COLLECTOR_TO_SKIP: Collection of collector to skip entries retained by
            this record.
        SYSTEM_ID_TO_SKIP: Collection of system identifier to skip entries
            retained by this record.
        CHASSIS_ID_TO_SKIP: Collection of chassis identifier to skip entries
            retained by this record.
        MANAGER_ID_TO_SKIP: Collection of manager identifier to skip entries
            retained by this record.
        SYSTEM_ID_OVERRIDE: Collection of system identifier override entries
            retained by this record.
        MANAGER_ID_OVERRIDE: Collection of manager identifier override entries
            retained by this record.
        CHASSIS_ID_OVERRIDE: Collection of chassis identifier override entries
            retained by this record.
        EXPAND_QUERY_CHASSIS_LEVEL: Numeric expand query chassis level retained
            by this record.
        EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL: Numeric expand query firmware
            inventory level retained by this record.
        EXPAND_QUERY_MANAGER_LEVEL: Numeric expand query manager level retained
            by this record.
        EXPAND_QUERY_SYSTEM_LEVEL: Numeric expand query system level retained by
            this record.
        EXPAND_FALLBACK_MODE: Canonical text used as expand fallback mode.
        NVOS_TECH_DUMP_TIMEOUT: Numeric nvos tech dump timeout retained by this
            record.
        REDFISH_DUMP_TIMEOUT: Numeric Redfish dump timeout retained by this
            record.
        REDFISH_DEVICE_DUMP_SLEEP_DURATION: Numeric Redfish device dump sleep
            duration retained by this record.
        COLLECTOR_EXTENSION_CONFIG: Mapping that retains the collector extension
            config fields for this record.
        EXTRA_LOG_COLLECTION: Whether extra log collection applies to this
            record.
        sysinfo_snapshot_mode: H24 command profile, with fast disabling firmware
            dumps and full explicitly enabling the longer firmware collection.
        BMC_TEMP_DIR: Canonical text used as BMC temp dir.
        TASK_ID_PREFIX: Canonical text used as task identifier prefix.
        TOOL_TEMP_DIR: Canonical text used as tool temp dir.
        i2c_config: Mapping that retains the i2c config fields for this record.
        FW_INVENTORY_TABLE_PROPERTIES: Collection of firmware inventory table
            properties entries retained by this record.
        ADDITIONAL_OOB_URI_COLLECTION: Collection of additional oob URI
            collection entries retained by this record.
        NVLINK_OOB_URI: Collection of nvlink oob URI entries retained by this
            record.
        CUSTOM_DUMP_SERVICES: Mapping that retains the custom dump services
            fields for this record.
        REDFISH_R31_PAYLOAD: Mapping that retains the Redfish r31 payload fields
            for this record.
        POST_CODES_URI: Collection of post codes URI entries retained by this
            record.
        BMC_IP: Canonical text used as BMC IP.
        BMC_USERNAME: Canonical text used as BMC username.
        BMC_PASSWORD: Canonical text used as BMC password.
        BMC_SSH_USERNAME: Canonical text used as BMC SSH username.
        BMC_SSH_PASSWORD: Canonical text used as BMC SSH password.
        BMC_SSH_PORT: Numeric BMC SSH port retained by this record.
        BMC_SSH_KEY_PATH: Validated filesystem location associated with BMC SSH
            key path.
        BMC_SSH_PASSWORDLESS: Whether BMC SSH passwordless applies to this
            record.
        BMC_SSH_MAX_RETRIES: Number of BMC SSH max retries represented by this
            record.
        BMC_RF_PORT: Numeric BMC Redfish port retained by this record.
        BMC_USE_HTTPS: Whether BMC use HTTPS applies to this record.
        RF_User: Canonical text used as Redfish user.
        RF_Pass: Canonical text used as Redfish pass.
        RF_DEFAULT_PREFIX: Canonical text used as Redfish default prefix.
        RF_HMC_DEFAULT_PREFIX: Canonical text used as Redfish HMC default
            prefix.
        RF_AUTH: Whether Redfish auth applies to this record.
        RF_HMC_ACCESS_METHOD: Canonical text used as Redfish HMC access method.
        HMC_RF_PROTOCOL: Canonical text used as HMC Redfish protocol.
        TUNNEL_TCP_PORT: Canonical text used as tunnel TCP port.
        SETUP_PORT_FORWARDING: Whether setup port forwarding applies to this
            record.
        FORCE_PORT_FW: Whether force port firmware applies to this record.
        IP_NETWORK: Canonical text used as IP network.
        HOST_IP: Canonical text used as host IP.
        HOST_USERNAME: Canonical text used as host username.
        HOST_PASSWORD: Canonical text used as host password.
        HOST_SSH_PORT: Numeric host SSH port retained by this record.
        HOST_SSH_KEY_PATH: Validated filesystem location associated with host
            SSH key path.
        HOST_SSH_PASSWORDLESS: Whether host SSH passwordless applies to this
            record.
        HOST_SSH_MAX_RETRIES: Number of host SSH max retries represented by this
            record.
        SSH_PROXY_HOST: Canonical text used as SSH proxy host.
        SSH_PROXY_PORT: Numeric SSH proxy port retained by this record.
        SSH_PROXY_USERNAME: Canonical text used as SSH proxy username.
        SSH_PROXY_PASSWORD: Canonical text used as SSH proxy password.
        SSH_PROXY_KEY_PATH: Validated filesystem location associated with SSH
            proxy key path.
        SSH_PROXY_PASSWORDLESS: Whether SSH proxy passwordless applies to this
            record.
        SSH_PROXY_MAX_RETRIES: Number of SSH proxy max retries represented by
            this record.
        HMC_IP: Canonical text used as HMC IP.
        HMC_USERNAME: Canonical text used as HMC username.
        HMC_PASSWORD: Canonical text used as HMC password.
        HMC_SSH_USERNAME: Canonical text used as HMC SSH username.
        HMC_SSH_PASSWORD: Canonical text used as HMC SSH password.
        HMC_SSH_PORT: Numeric HMC SSH port retained by this record.
        HMC_SSH_KEY_PATH: Validated filesystem location associated with HMC SSH
            key path.
        HMC_SSH_PASSWORDLESS: Whether HMC SSH passwordless applies to this
            record.
        HMC_SSH_MAX_RETRIES: Number of HMC SSH max retries represented by this
            record.
        HMC_HTTP_PORT: Numeric HMC HTTP port retained by this record.
        HMC_HTTPS_PORT: Numeric HMC HTTPS port retained by this record.
        HMC_USE_HTTPS: Whether HMC use HTTPS applies to this record.
        HMC_TCP_PORT: Numeric HMC TCP port retained by this record.
        USE_PORT_FORWARDING: Whether use port forwarding applies to this record.
        TUNNEL_LOCAL_HOST: Canonical text used as tunnel local host.
        SSH_TUNNEL_OPTIONS: Canonical text used as SSH tunnel options.
        SSH_TUNNEL_PREFIX: Canonical text used as SSH tunnel prefix.
        ipmi_cipher: Canonical text used as IPMI cipher.
        NodeType: Canonical text used as node type.
        ConfigFileToUse: Canonical text used as config file to use.
        ExecutionMode: Canonical text used as execution mode.
    """

    model_config = ConfigDict(extra="forbid")

    # Basic Configuration
    name: str

    @pydantic.field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        """
        Require a portable single-component DUT output identity.

        The implementation uses ``value`` to require a portable single-component
        DUT output identity. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The validated ``value``.

        Raises:
            ValueError: If invalid DUT name: expected one portable path
                component containing only letters, digits, spaces,
                apostrophes, '.', '_', or '-'.
        """

        normalized = value.strip().replace("/", "_").replace("\\", "_")
        normalized = re.sub(r"[^A-Za-z0-9._ '\-]+", "_", normalized).strip(" .")
        while ".." in normalized:
            normalized = normalized.replace("..", "_")
        if not normalized or normalized != value:
            raise ValueError(
                "Invalid DUT name: expected one portable path component containing "
                "only letters, digits, spaces, apostrophes, '.', '_', or '-'"
            )
        return value

    baseboard: Optional[str] = (
        None  # Dynamic baseboard name from spreadsheet (auto-detected if not provided)
    )
    description: Optional[str] = None
    # Optional manual-handoff metadata for collected OpenBMC service cores.
    # Collected OpenBMC OS metadata remains authoritative when available.
    openbmc_analyzer_machine: Optional[str] = None
    openbmc_commit: Optional[str] = None

    # Local Configuration
    local: bool = False
    non_interactive: bool = False

    # BMC Configuration
    bmc_ip: Optional[str] = None
    bmc_user: Optional[str] = None
    bmc_pass: Optional[str] = None
    bmc_ssh_user: Optional[str] = None
    bmc_ssh_pass: Optional[str] = None
    bmc_ssh_port: Optional[int] = 22
    bmc_ssh_key_path: Optional[str] = None
    bmc_ssh_passwordless: bool = False
    bmc_ssh_max_retries: int = 3
    bmc_rf_user: Optional[str] = ""  # Empty string for fallback to BMC credentials
    bmc_rf_pass: Optional[str] = ""  # Empty string for fallback to BMC credentials
    bmc_rf_port: Optional[int] = 443  # Default HTTPS port for Redfish
    bmc_use_https: bool = True  # Use HTTPS for BMC Redfish connections
    # Canonical Redfish TLS trust policy. The legacy verification boolean is
    # retained as an input alias and projected to system_ca/insecure. Omission
    # preserves the v2.1 password-only workflow on trusted management networks;
    # system_ca, custom_ca, and fingerprint remain explicit verifying modes.
    bmc_rf_verify_ssl: bool = False
    bmc_rf_tls_mode: Optional[
        Literal["system_ca", "custom_ca", "fingerprint", "insecure"]
    ] = None
    bmc_rf_ca_file: Optional[str] = None
    bmc_rf_fingerprint_sha256: Optional[str] = None
    bmc_rf_tls_server_name: Optional[str] = None
    bmc_rf_authentication_mode: Optional[Literal["auto", "basic", "session"]] = Field(
        default=None,
        description="Per-DUT Redfish authentication policy; null or omission inherits the tool policy.",
    )

    # Host Configuration
    host_ip: Optional[str] = None
    host_user: Optional[str] = None
    host_pass: Optional[str] = None
    host_sudo_password: Optional[str] = Field(default=None, repr=False)
    host_ssh_port: Optional[int] = None
    host_ssh_key_path: Optional[str] = None
    host_ssh_passwordless: bool = False
    host_ssh_max_retries: int = 3

    # HMC Configuration
    hmc_ip: Optional[str] = None
    hmc_user: Optional[str] = None
    hmc_pass: Optional[str] = None
    hmc_ssh_user: Optional[str] = None
    hmc_ssh_pass: Optional[str] = None
    hmc_ssh_port: Optional[int] = 22
    hmc_ssh_key_path: Optional[str] = None
    hmc_ssh_passwordless: bool = False
    hmc_ssh_max_retries: int = 3
    hmc_http_port: Optional[int] = 80
    hmc_https_port: Optional[int] = 443
    hmc_use_https: bool = False
    hmc_access_method: Optional[str] = None
    # Port forwarding configuration
    use_port_forwarding: bool = False
    setup_port_forwarding: bool = False
    force_port_fw: bool = False
    tunnel_tcp_port: Optional[Union[int, str]] = None

    # SSH Proxy Configuration
    ssh_proxy_host: Optional[str] = None
    ssh_proxy_port: int = 22
    ssh_proxy_user: Optional[str] = None
    ssh_proxy_pass: Optional[str] = None
    ssh_proxy_key_path: Optional[str] = None
    ssh_proxy_passwordless: bool = False
    ssh_proxy_max_retries: int = 3
    # Password-only compatibility is the accepted default on trusted management
    # networks. Operators can opt into strict OpenSSH/AsyncSSH known-hosts trust.
    ssh_host_key_policy: Literal["strict", "insecure"] = "insecure"
    ssh_known_hosts_file: Optional[str] = None

    # Per-DUT Collector Configuration
    skip_collectors: List[str] = Field(default_factory=list)
    include_collectors: List[str] = Field(default_factory=list)

    # Skip Flags
    SKIP_PORT_FW: bool = False
    SKIP_BMC_SSH_LOGS: bool = True
    SKIP_HOST_LOGS: bool = False
    SKIP_IPMI_LOGS: bool = False
    SKIP_REDFISH_OOB_LOGS: bool = False

    # New Skip Fields
    COLLECTOR_TO_SKIP: List[str] = Field(default_factory=list)
    SYSTEM_ID_TO_SKIP: List[str] = Field(default_factory=list)
    CHASSIS_ID_TO_SKIP: List[str] = Field(default_factory=list)
    MANAGER_ID_TO_SKIP: List[str] = Field(default_factory=list)

    @pydantic.field_validator(
        "SYSTEM_ID_TO_SKIP", "CHASSIS_ID_TO_SKIP", "MANAGER_ID_TO_SKIP"
    )
    @classmethod
    def validate_entity_skip_patterns(cls, value: Any) -> List[str]:
        """
        Validate case-sensitive Redfish ID skip regular expressions.

        Tool- or DUT-authored patterns share one validation boundary so a
        malformed expression cannot survive precedence resolution and fail only
        after collection has started.

        Args:
            value: Candidate pattern list supplied for one entity family.

        Returns:
            The validated pattern list in source order.

        Raises:
            ValueError: If any entry is malformed or exceeds its bound.
        """

        return _validate_entity_skip_patterns(value)

    # Entity ID Overrides — bypasses dynamic discovery and uses these values directly
    SYSTEM_ID_OVERRIDE: List[str] = Field(default_factory=list)
    MANAGER_ID_OVERRIDE: List[str] = Field(default_factory=list)
    CHASSIS_ID_OVERRIDE: List[str] = Field(default_factory=list)

    # Expand Query Fields
    EXPAND_QUERY_CHASSIS_LEVEL: int = 1
    EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL: int = 1
    EXPAND_QUERY_MANAGER_LEVEL: int = 1
    EXPAND_QUERY_SYSTEM_LEVEL: int = 1
    # Behavior when the BMC does not support $expand. Per-DUT override; if
    # left as None, the tool-level Config.EXPAND_FALLBACK_MODE applies (which
    # itself defaults to "auto").
    #   "auto"   — probe ServiceRoot.ProtocolFeaturesSupported.ExpandQuery,
    #              detect rejections reactively, and emulate via a per-member walk.
    #   "never"  — error on $expand failure (useful for diagnosing BMC bugs).
    #   "always" — skip the $expand attempt entirely and go straight to the
    #              per-member walk.
    EXPAND_FALLBACK_MODE: Optional[str] = None

    # Timeout Fields
    NVOS_TECH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DEVICE_DUMP_SLEEP_DURATION: Optional[int] = None

    # Namespaced configuration consumed only by trusted catalog extensions.
    COLLECTOR_EXTENSION_CONFIG: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    # Feature Flags
    EXTRA_LOG_COLLECTION: Optional[bool] = None
    sysinfo_snapshot_mode: Optional[Literal["fast", "full"]] = None

    # Directory Fields
    BMC_TEMP_DIR: str = "/tmp"
    TASK_ID_PREFIX: str = ""
    TOOL_TEMP_DIR: str = "/tmp"

    # I2C Configuration
    i2c_config: Dict[str, Any] = Field(default_factory=dict)

    # Firmware Inventory Configuration
    FW_INVENTORY_TABLE_PROPERTIES: List[str] = Field(default_factory=list)

    # Additional OOB URI Collection Configuration
    ADDITIONAL_OOB_URI_COLLECTION: List[str] = Field(default_factory=list)

    # NVLink OOB URI Collection Configuration
    NVLINK_OOB_URI: List[str] = Field(default_factory=list)

    # Custom Dump Services Configuration
    CUSTOM_DUMP_SERVICES: List[Dict[str, Any]] = Field(default_factory=list)

    # R31 FDR diagnostic payload override. None preserves the catalog default.
    REDFISH_R31_PAYLOAD: Optional[Dict[str, Any]] = None

    # Post Codes URI Configuration
    POST_CODES_URI: List[str] = Field(default_factory=list)

    # Legacy field mappings for backward compatibility
    BMC_IP: Optional[str] = None
    BMC_USERNAME: Optional[str] = None
    BMC_PASSWORD: Optional[str] = None
    BMC_SSH_USERNAME: Optional[str] = None
    BMC_SSH_PASSWORD: Optional[str] = None
    BMC_SSH_PORT: Optional[int] = None  # Will be set to 22 in validator
    BMC_SSH_KEY_PATH: Optional[str] = None
    BMC_SSH_PASSWORDLESS: Optional[bool] = False
    BMC_SSH_MAX_RETRIES: Optional[int] = 3
    BMC_RF_PORT: Optional[int] = None  # Will be set to 443 in validator
    BMC_USE_HTTPS: Optional[bool] = None
    RF_User: Optional[str] = None  # Will fall back to BMC_USERNAME in validator
    RF_Pass: Optional[str] = None  # Will fall back to BMC_PASSWORD in validator
    # Omitted values are materialized from the catalog service root by
    # DUTManager. Keeping this unset preserves source provenance and prevents a
    # model default from overriding a changed catalog root.
    RF_DEFAULT_PREFIX: Optional[str] = None
    RF_HMC_DEFAULT_PREFIX: Optional[str] = (
        None  # HMC-specific prefix for HGX_* resource URIs (arm64 aggregation). Overrides RF_DEFAULT_PREFIX for HMC collectors only.
    )
    RF_AUTH: bool = True
    RF_HMC_ACCESS_METHOD: Optional[str] = (
        None  # Omission becomes the internal NOTAPPLICABLE sentinel below.
    )
    HMC_RF_PROTOCOL: Optional[str] = "http"
    TUNNEL_TCP_PORT: Optional[Union[int, str]] = None  # Can be int, string, or None
    SETUP_PORT_FORWARDING: bool = False
    FORCE_PORT_FW: bool = False
    IP_NETWORK: str = "ipv4"
    HOST_IP: Optional[str] = None
    HOST_USERNAME: Optional[str] = None  # Will be set to current user in validator
    HOST_PASSWORD: Optional[str] = None
    HOST_SSH_PORT: Optional[int] = None  # Will be set to 22 in validator
    HOST_SSH_KEY_PATH: Optional[str] = None
    HOST_SSH_PASSWORDLESS: Optional[bool] = False
    HOST_SSH_MAX_RETRIES: Optional[int] = 3
    SSH_PROXY_HOST: Optional[str] = None
    SSH_PROXY_PORT: Optional[int] = 22
    SSH_PROXY_USERNAME: Optional[str] = None
    SSH_PROXY_PASSWORD: Optional[str] = None
    SSH_PROXY_KEY_PATH: Optional[str] = None
    SSH_PROXY_PASSWORDLESS: Optional[bool] = False
    SSH_PROXY_MAX_RETRIES: Optional[int] = 3
    HMC_IP: Optional[str] = None
    HMC_USERNAME: Optional[str] = None
    HMC_PASSWORD: Optional[str] = None
    HMC_SSH_USERNAME: Optional[str] = None
    HMC_SSH_PASSWORD: Optional[str] = None
    HMC_SSH_PORT: Optional[int] = None  # Will be set to 22 in validator
    HMC_SSH_KEY_PATH: Optional[str] = None
    HMC_SSH_PASSWORDLESS: Optional[bool] = False
    HMC_SSH_MAX_RETRIES: Optional[int] = 3
    HMC_HTTP_PORT: Optional[int] = 80
    HMC_HTTPS_PORT: Optional[int] = 443
    HMC_USE_HTTPS: bool = False
    HMC_TCP_PORT: Optional[int] = (
        None  # Will be set based on HMC_RF_PROTOCOL in validator
    )
    USE_PORT_FORWARDING: bool = False
    # SSH tunnel configuration
    TUNNEL_LOCAL_HOST: str = "localhost"
    # The execution boundary appends host-key controls from
    # ssh_host_key_policy. Password authentication uses descriptor-zero input
    # so the password is never placed in argv.
    SSH_TUNNEL_OPTIONS: Optional[str] = DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS
    SSH_TUNNEL_PREFIX: str = DEFAULT_SSH_TUNNEL_PREFIX
    ipmi_cipher: str = "-C17"
    NodeType: str = "Compute"

    @pydantic.field_validator("NodeType")
    @classmethod
    def validate_node_type(cls, value: str) -> str:
        """
        Normalize the approved node-type domain before applicability checks.

        The normalized spelling is stored on the model, keeping runtime
        applicability comparisons deterministic while accepting harmless case
        variants at the input boundary.

        Args:
            value: Node type supplied by the selected DUT source.

        Returns:
            The canonical catalog spelling for the node type.

        Raises:
            ValueError: If the node type is outside the approved domain.
        """

        return _normalize_node_type(value)

    ConfigFileToUse: Optional[str] = None
    ExecutionMode: Optional[str] = "REMOTE"

    @pydantic.field_validator("REDFISH_R31_PAYLOAD")
    @classmethod
    def validate_redfish_r31_payload(cls, value: Any) -> Optional[Dict[str, Any]]:
        """
        Validate Redfish r31 payload.

        After applying local validation, the function forwards ``value`` to
        ``_normalize_redfish_diagnostic_payload`` and preserves its return and
        exception contract. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path.

        Args:
            value: Value evaluated while performing redfish r31 payload.

        Returns:
            A mapping containing Redfish r31 payload, or ``None`` when the
            requested value is unavailable.
        """
        return _normalize_redfish_diagnostic_payload(value)

    @pydantic.field_validator("SSH_TUNNEL_PREFIX", mode="before")
    @classmethod
    def migrate_ssh_tunnel_prefix(cls, value: Any) -> str:
        """
        Map the exact legacy prefix to descriptor-safe password input.

        After applying local validation, the function forwards ``value`` to
        ``normalize_ssh_tunnel_prefix`` and preserves its return and exception
        contract.

        Args:
            value: Value evaluated while performing map the exact legacy prefix
                to descriptor-safe password input.

        Returns:
            The canonical migrate SSH tunnel prefix text.
        """

        return normalize_ssh_tunnel_prefix(value)

    @pydantic.field_validator("bmc_rf_fingerprint_sha256")
    @classmethod
    def validate_bmc_rf_fingerprint(cls, value: Optional[str]) -> Optional[str]:
        """
        Validate BMC Redfish fingerprint.

        After applying local validation, the function forwards ``value`` to
        ``normalize_sha256_fingerprint`` and preserves its return and exception
        contract. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The canonical BMC Redfish fingerprint text, or ``None`` when the
            requested value is unavailable.
        """
        return normalize_sha256_fingerprint(value)

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_redfish_tls(cls, values: Any) -> Any:
        """
        Migrate legacy Redfish TLS.

        The implementation uses ``values`` to migrate legacy Redfish TLS. If the
        function cannot migrate legacy Redfish TLS, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            values: Values consumed while the function attempts to migrate
                legacy Redfish TLS.

        Returns:
            The migrate legacy Redfish TLS value selected by the operation.

        Raises:
            ValueError: If bmc_rf_verify_ssl cannot be null; or
                bmc_rf_verify_ssl conflicts with bmc_rf_tls_mode.
        """
        if not isinstance(values, dict):
            return values
        normalized = dict(values)
        legacy_verify = None
        if (
            "bmc_rf_verify_ssl" in normalized
            and normalized["bmc_rf_verify_ssl"] is not None
        ):
            legacy_verify = _normalize_boolean_alias(normalized["bmc_rf_verify_ssl"])
            if legacy_verify is None:
                raise ValueError("bmc_rf_verify_ssl cannot be null")
            normalized["bmc_rf_verify_ssl"] = legacy_verify
        if normalized.get("bmc_rf_tls_mode") is not None:
            mode_verifies = normalized["bmc_rf_tls_mode"] != "insecure"
            if legacy_verify is not None and legacy_verify != mode_verifies:
                raise ValueError("bmc_rf_verify_ssl conflicts with bmc_rf_tls_mode")
        return normalized

    @model_validator(mode="after")
    def validate_bmc_redfish_tls_policy(self) -> "DUTConfig":
        # Keep the deprecated boolean and canonical mode readable in both
        # directions without claiming that the compatibility projection was
        # present in the source. Runtime precedence relies on model_fields_set
        # to treat bmc_rf_verify_ssl as a fallback behind explicit trust
        # material such as a private CA or pinned fingerprint.
        """
        Validate BMC Redfish TLS policy.

        The implementation uses current instance state to validate BMC Redfish
        TLS policy. Every required invariant is checked before a successful
        value is returned; invalid input follows the function's explicit
        exception path.

        Returns:
            The validated ``self``.

        Raises:
            ValueError: If bmc_rf custom_ca tls mode lacks bmc_rf_ca_file;
                bmc_rf fingerprint tls mode lacks bmc_rf_fingerprint_sha256;
                bmc_rf_ca_file lacks bmc_rf custom_ca TLS mode; or
                bmc_rf_fingerprint_sha256 lacks bmc_rf fingerprint TLS mode; or
                another input invariant is violated.
        """
        fields_set = self.model_fields_set
        if "bmc_rf_tls_mode" in fields_set:
            object.__setattr__(
                self,
                "bmc_rf_verify_ssl",
                self.bmc_rf_tls_mode != "insecure",
            )
        elif "bmc_rf_verify_ssl" in fields_set:
            object.__setattr__(
                self,
                "bmc_rf_tls_mode",
                "system_ca" if self.bmc_rf_verify_ssl else "insecure",
            )

        if self.bmc_rf_tls_mode == "custom_ca" and not self.bmc_rf_ca_file:
            raise ValueError("bmc_rf custom_ca TLS mode requires bmc_rf_ca_file")
        if self.bmc_rf_tls_mode == "fingerprint" and not self.bmc_rf_fingerprint_sha256:
            raise ValueError(
                "bmc_rf fingerprint TLS mode requires bmc_rf_fingerprint_sha256"
            )
        if self.bmc_rf_ca_file and self.bmc_rf_tls_mode != "custom_ca":
            raise ValueError("bmc_rf_ca_file requires bmc_rf custom_ca TLS mode")
        if self.bmc_rf_fingerprint_sha256 and self.bmc_rf_tls_mode != "fingerprint":
            raise ValueError(
                "bmc_rf_fingerprint_sha256 requires bmc_rf fingerprint TLS mode"
            )
        if self.bmc_rf_tls_mode is None and self.bmc_rf_tls_server_name:
            raise ValueError(
                "bmc_rf TLS parameters require an explicit bmc_rf_tls_mode"
            )
        if self.bmc_rf_tls_mode not in (None, "insecure") and not self.bmc_use_https:
            raise ValueError(
                "bmc_rf_tls_mode requires bmc_use_https=true; verification "
                "cannot be applied to plaintext HTTP"
            )
        if (
            self.hmc_ip
            and self.bmc_rf_tls_mode not in (None, "insecure")
            and not self.hmc_use_https
        ):
            raise ValueError(
                "a verifying Redfish TLS policy requires hmc_use_https=true "
                "when an HMC endpoint is configured"
            )
        return self

    @model_validator(mode="before")
    @classmethod
    def validate_legacy_fields(cls, values: Any) -> Any:
        """
        Validate legacy fields.

        The implementation uses ``values`` to validate legacy fields. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            values: Values object whose ``get`` and ``keys`` state is read while
                performing legacy fields.

        Returns:
            The validated ``values``.

        Raises:
            ValueError: If the supplied input cannot be used to validate legacy
                fields.
        """
        if isinstance(values, dict):
            values = call_optional_config_hook("validate_dut_config", values)
            known_keys = set(cls.model_fields)
            if values.get("ConfigFileToUse"):
                known_keys.update(Config.model_fields)
            unknown_keys = sorted(str(key) for key in values if key not in known_keys)
            if unknown_keys:
                raise ValueError(
                    f"unknown key '{unknown_keys[0]}' in DUT configuration"
                )

            explicit_fields = set(values.keys())
            for field_name in ("hmc_access_method", "RF_HMC_ACCESS_METHOD"):
                if field_name in explicit_fields:
                    _validate_hmc_access_method(values[field_name])
            if "ssh_host_key_policy" not in explicit_fields:
                inferred_policy = infer_legacy_ssh_host_key_policy(
                    values.get("SSH_TUNNEL_OPTIONS")
                )
                if inferred_policy is not None:
                    values["ssh_host_key_policy"] = inferred_policy
            if (
                values.get("ssh_host_key_policy") == "strict"
                and "ssh_known_hosts_file" not in explicit_fields
            ):
                inferred_known_hosts = infer_legacy_ssh_known_hosts_file(
                    values.get("SSH_TUNNEL_OPTIONS")
                )
                if inferred_known_hosts is not None:
                    values["ssh_known_hosts_file"] = inferred_known_hosts
            if (
                values.get("ssh_host_key_policy") == "strict"
                and "SSH_TUNNEL_OPTIONS" not in explicit_fields
            ):
                # A strict policy must not inherit legacy insecure host-key
                # controls at execution.
                values["SSH_TUNNEL_OPTIONS"] = DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS

            # Sync legacy/new fields (new fields take precedence when explicit)
            sync_legacy_fields(values, explicit_fields=explicit_fields)
            _validate_ip_network_fields(values)

            sync_execution_mode_fields(values)

            # Handle credential fallbacks (matching legacy dut.py behavior)
            # Replace RF credentials with BMC credentials if not provided
            if not values.get("RF_User") and values.get("BMC_USERNAME"):
                values["RF_User"] = values["BMC_USERNAME"]
            if not values.get("RF_Pass") and values.get("BMC_PASSWORD"):
                values["RF_Pass"] = values["BMC_PASSWORD"]

            # Replace BMC SSH credentials with BMC credentials if not provided
            if not values.get("BMC_SSH_USERNAME") and values.get("BMC_USERNAME"):
                values["BMC_SSH_USERNAME"] = values["BMC_USERNAME"]
            if not values.get("BMC_SSH_PASSWORD") and values.get("BMC_PASSWORD"):
                values["BMC_SSH_PASSWORD"] = values["BMC_PASSWORD"]

            # Set default ports if not provided
            if values.get("BMC_SSH_PORT") is None:
                values["BMC_SSH_PORT"] = 22
            if values.get("HMC_SSH_PORT") is None:
                values["HMC_SSH_PORT"] = 22
            if values.get("HOST_SSH_PORT") is None:
                values["HOST_SSH_PORT"] = 22
            if values.get("BMC_RF_PORT") is None:
                values["BMC_RF_PORT"] = 443

            # Normalize legacy HMC Redfish protocol/TCP port fields into the
            # newer HMC_HTTP_PORT/HMC_HTTPS_PORT/HMC_USE_HTTPS fields consumed
            # by HMCService.
            hmc_protocol_explicit = "HMC_RF_PROTOCOL" in explicit_fields
            hmc_use_https_explicit = (
                "HMC_USE_HTTPS" in explicit_fields or "hmc_use_https" in explicit_fields
            )
            hmc_tcp_port_explicit = "HMC_TCP_PORT" in explicit_fields and values.get(
                "HMC_TCP_PORT"
            ) not in (None, "")
            hmc_http_port_explicit = (
                "HMC_HTTP_PORT" in explicit_fields or "hmc_http_port" in explicit_fields
            ) and (values.get("HMC_HTTP_PORT") not in (None, ""))
            hmc_https_port_explicit = (
                "HMC_HTTPS_PORT" in explicit_fields
                or "hmc_https_port" in explicit_fields
            ) and (values.get("HMC_HTTPS_PORT") not in (None, ""))

            hmc_protocol = values.get("HMC_RF_PROTOCOL")
            hmc_https_requested = any(
                _normalize_boolean_alias(values.get(field)) is True
                for field in ("HMC_USE_HTTPS", "hmc_use_https")
                if field in values
            )
            if not hmc_protocol_explicit and hmc_https_requested:
                hmc_protocol = "https"
            if hmc_protocol in (None, ""):
                hmc_protocol = "http"
            hmc_protocol = str(hmc_protocol).strip().lower()
            values["HMC_RF_PROTOCOL"] = hmc_protocol

            if values.get("HMC_TCP_PORT") in (None, ""):
                if hmc_protocol == "https" and hmc_https_port_explicit:
                    values["HMC_TCP_PORT"] = values["HMC_HTTPS_PORT"]
                elif hmc_protocol == "http" and hmc_http_port_explicit:
                    values["HMC_TCP_PORT"] = values["HMC_HTTP_PORT"]
                else:
                    values["HMC_TCP_PORT"] = 443 if hmc_protocol == "https" else 80

            try:
                hmc_tcp_port = int(values["HMC_TCP_PORT"])
            except (TypeError, ValueError):
                hmc_tcp_port = values["HMC_TCP_PORT"]

            if hmc_protocol == "https":
                if hmc_tcp_port_explicit or values.get("HMC_HTTPS_PORT") in (
                    None,
                    "",
                ):
                    values["HMC_HTTPS_PORT"] = hmc_tcp_port
                    values["hmc_https_port"] = hmc_tcp_port
                if not hmc_use_https_explicit:
                    values["HMC_USE_HTTPS"] = True
                    values["hmc_use_https"] = True
            else:
                if hmc_tcp_port_explicit or values.get("HMC_HTTP_PORT") in (
                    None,
                    "",
                ):
                    values["HMC_HTTP_PORT"] = hmc_tcp_port
                    values["hmc_http_port"] = hmc_tcp_port
                if not hmc_use_https_explicit:
                    values["HMC_USE_HTTPS"] = False
                    values["hmc_use_https"] = False

            # Preserve the established internal sentinel for DUTs without HMC.
            # It is not a user-selectable access method and therefore is not part
            # of HMC_ACCESS_METHODS or the public CLI/config value contract.
            if not values.get("RF_HMC_ACCESS_METHOD"):
                values["RF_HMC_ACCESS_METHOD"] = "NOTAPPLICABLE"

            # Set HOST_USERNAME to current user if not provided
            if not values.get("HOST_USERNAME"):
                values["HOST_USERNAME"] = getpass.getuser()

            # Ensure passwordless flags are booleans
            if values.get("HOST_SSH_PASSWORDLESS") is None:
                values["HOST_SSH_PASSWORDLESS"] = False
            if values.get("BMC_SSH_PASSWORDLESS") is None:
                values["BMC_SSH_PASSWORDLESS"] = False
            if values.get("HMC_SSH_PASSWORDLESS") is None:
                values["HMC_SSH_PASSWORDLESS"] = False

            # Set SSH key paths to None if not provided
            if not values.get("BMC_SSH_KEY_PATH"):
                values["BMC_SSH_KEY_PATH"] = None
            if not values.get("HOST_SSH_KEY_PATH"):
                values["HOST_SSH_KEY_PATH"] = None

            # Handle TUNNEL_TCP_PORT - convert empty string to None, set default to 18888 if None
            if values.get("TUNNEL_TCP_PORT") == "":
                values["TUNNEL_TCP_PORT"] = None
            if values.get("TUNNEL_TCP_PORT") is None:
                values["TUNNEL_TCP_PORT"] = 18888

            # Also handle new field names for consistency
            if not values.get("bmc_ssh_user") and values.get("bmc_user"):
                values["bmc_ssh_user"] = values["bmc_user"]
            if not values.get("bmc_ssh_pass") and values.get("bmc_pass"):
                values["bmc_ssh_pass"] = values["bmc_pass"]
            if not values.get("bmc_rf_user") and values.get("bmc_user"):
                values["bmc_rf_user"] = values["bmc_user"]
            if not values.get("bmc_rf_pass") and values.get("bmc_pass"):
                values["bmc_rf_pass"] = values["bmc_pass"]

        return values

    _source_fields: Optional[Set[str]] = PrivateAttr(default=None)
    _validation_fields: Optional[Set[str]] = PrivateAttr(default=None)

    @model_validator(mode="wrap")
    @classmethod
    def preserve_authored_fields(cls, values: Any, handler: Any) -> Any:
        """
        Retain input provenance before aliases and credential defaults expand.

        Empty protocol credentials request generic fallback and are therefore
        excluded from the retained source fields. The private field set is not
        serialized into DUT configuration or reports and stores no credentials.
        A second field-name snapshot distinguishes validation-generated fields
        from policies assigned by CLI/config resolution after model loading.

        Args:
            values: Authored input mapping or an existing validated model.
            handler: Pydantic validator that owns normal field normalization.

        Returns:
            The validated model with its authored-field provenance retained.

        Raises:
            ValueError: If normal DUT validation rejects the supplied input.
        """
        source = dict(values) if isinstance(values, dict) else None
        result = handler(values)
        if source is not None:
            fields = set(source)
            for canonical in (
                "bmc_rf_user",
                "bmc_rf_pass",
                "bmc_ssh_user",
                "bmc_ssh_pass",
            ):
                legacy = LEGACY_FIELD_MAPPINGS[canonical]
                value = (
                    source.get(canonical) if canonical in source else source.get(legacy)
                )
                if not value:
                    fields.difference_update({canonical, legacy})
            result._source_fields = fields
            result._validation_fields = set(result.model_fields_set)
        return result

    def with_cli_overrides(self, overrides: Dict[str, Any]) -> "DUTConfig":
        """
        Revalidate CLI winners without treating inherited credentials as authored.

        Canonical fields and later explicit assignments are projected from the
        current model, while derived legacy aliases and credential fallbacks
        are recomputed by validation. This preserves trust, local-mode, and
        platform policies resolved after loading. An unchanged linked-config
        path retains a private copy of its already validated snapshot, so later
        consumers do not reopen mutable input. The original model remains
        unchanged, including its credential values and retained snapshot.

        Args:
            overrides: Explicit CLI field winners using canonical model names.

        Returns:
            A new DUT model with aliases and generic credential fallbacks synced.

        Raises:
            ValueError: If an override violates DUT configuration validation.
        """
        fields = set(
            self._source_fields
            if self._source_fields is not None
            else self.model_fields_set
        )
        fields.update(self.model_fields_set - (self._validation_fields or set()))
        fields.add("name")
        for canonical, legacy in LEGACY_FIELD_MAPPINGS.items():
            if canonical in fields or legacy in fields:
                fields.add(canonical)
            fields.discard(legacy)
        if "HMC_RF_PROTOCOL" in fields:
            fields.add("hmc_use_https")
        if "HMC_TCP_PORT" in fields:
            fields.update({"hmc_use_https", "hmc_http_port", "hmc_https_port"})
        fields.difference_update({"HMC_RF_PROTOCOL", "HMC_TCP_PORT"})
        values = self.model_dump(include=fields, mode="python")
        values.update(overrides)
        resolved = type(self).model_validate(values)
        referenced = getattr(self, "_referenced_config_data", None)
        if (
            isinstance(referenced, dict)
            and resolved.ConfigFileToUse == self.ConfigFileToUse
        ):
            object.__setattr__(
                resolved, "_referenced_config_data", copy.deepcopy(referenced)
            )
        return resolved


_SUPPORTED_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_LOG_FORMAT_DIRECTIVE = re.compile(
    r"%\([^)]+\)[#0\- +]*(?P<width>\d+)?" r"(?:\.(?P<precision>\d+))?[diouxXeEfFgGcrsa]"
)


def _normalize_log_level(value: Any) -> Optional[str]:
    """
    Validate and canonicalize a configured diagnostic log level.

    The implementation uses ``value`` to validate and canonicalize a configured
    diagnostic log level. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        value: Value object whose ``strip`` state is read while performing and
            canonicalize a configured diagnostic log level.

    Returns:
        The validated ``normalized``, or ``None`` when no value qualifies.

    Raises:
        ValueError: If the log level is not a string; or the log level is not
            one of DEBUG, INFO, WARNING, ERROR, or CRITICAL.
    """

    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("log level must be a string")
    normalized = value.strip().upper()
    if normalized == "WARN":
        normalized = "WARNING"
    if normalized not in _SUPPORTED_LOG_LEVELS:
        raise ValueError(
            "log level must be one of DEBUG, INFO, WARNING, ERROR, or CRITICAL"
        )
    return normalized


def _normalize_log_format(value: Any) -> Optional[str]:
    """
    Validate a bounded, single-line percent-style logging format.

    The implementation uses ``value`` to validate a bounded, single-line
    percent-style logging format. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.

    Returns:
        The validated ``value``, or ``None`` when no value qualifies.

    Raises:
        ValueError: If the log format is not a string; log format must contain
            between 1 and 4096 characters; the log format is not a single line
            without NUL characters; or log format must contain %(message)s; or
            another input invariant is violated.
    """

    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("log format must be a string")
    if not value or len(value) > 4096:
        raise ValueError("log format must contain between 1 and 4096 characters")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise ValueError("log format must be a single line without NUL characters")
    if "%(message)s" not in value:
        raise ValueError("log format must contain %(message)s")

    for directive in _LOG_FORMAT_DIRECTIVE.finditer(value):
        for component in ("width", "precision"):
            raw_limit = directive.group(component)
            if raw_limit is not None and int(raw_limit) > 4096:
                raise ValueError(
                    f"log format {component} must not exceed 4096 characters"
                )

    record = logging.LogRecord(
        name="nvdebug",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="message",
        args=(),
        exc_info=None,
    )
    try:
        logging.Formatter(value, style="%").format(record)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"unsupported log format: {error}") from error
    return value


def _reject_populated_logging_alias_conflicts(values: Dict[str, Any]) -> None:
    """
    Reject contradictory explicitly populated flat and nested logging aliases.

    The implementation uses ``values`` to reject contradictory explicitly
    populated flat and nested logging aliases. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        values: Mapping supplying fields for contradictory explicitly populated
            flat and nested logging aliases.

    Raises:
        ValueError: If ``root_name`` conflicts with logging.``nested_name``.
    """

    logging_section = values.get("logging")
    if not isinstance(logging_section, dict):
        return

    aliases = (
        ("log_level", "level", _normalize_log_level),
        ("log_format", "format", _normalize_log_format),
    )
    for root_name, nested_name, normalizer in aliases:
        if root_name not in values or nested_name not in logging_section:
            continue

        root_value = values[root_name]
        nested_value = logging_section[nested_name]
        if root_value is None or nested_value is None:
            continue

        if normalizer(root_value) != normalizer(nested_value):
            raise ValueError(f"{root_name} conflicts with logging.{nested_name}")


def _validate_populated_alias_conflicts_on_init(initializer: Any) -> Any:
    """
    Validate explicit aliases before BaseSettings adds environment values.

    The implementation uses ``initializer`` to validate explicit aliases before
    BaseSettings adds environment values. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        initializer: Initializer consumed while the function attempts to
            validate explicit aliases before BaseSettings adds environment
            values.

    Returns:
        The validated ``validated_initializer``.
    """

    @wraps(initializer)
    def validated_initializer(self: Any, **values: Any) -> None:
        """
        Validate state produced by the wrapped model initializer.

        The implementation uses ``values`` to validate state produced by the
        wrapped model initializer. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path.

        Args:
            values: Additional named values forwarded without changing their
                keys.

        Raises:
            pydantic.ValidationError: If input or state violates constraints
                required to validate state produced by the wrapped model
                initializer.
        """
        try:
            _reject_populated_logging_alias_conflicts(values)
            _reject_conflicting_execution_control_aliases(values)
        except ValueError as error:
            raise pydantic.ValidationError.from_exception_data(
                self.__class__.__name__,
                [
                    {
                        "type": "value_error",
                        "loc": (),
                        "input": values,
                        "ctx": {"error": error},
                    }
                ],
            ) from error
        initializer(self, **values)

    return validated_initializer


class LoggingSectionConfig(BaseModel):
    """
    Represent logging section config data exchanged by the runtime.

    The coherent record keeps ``level``, ``format``, ``debug``, and ``verbose``
    together so consumers observe one logging section config state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        level: Canonical text used as level.
        format: Canonical text used as format.
        debug: Whether debug applies to this record.
        verbose: Whether verbose applies to this record.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    level: Optional[str] = None
    format: Optional[str] = None
    debug: bool = False
    verbose: bool = False

    @pydantic.field_validator("level")
    @classmethod
    def validate_level(cls, value: Optional[str]) -> Optional[str]:
        """
        Validate level.

        After applying local validation, the function forwards ``value`` to
        ``_normalize_log_level`` and preserves its return and exception
        contract. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The canonical level text, or ``None`` when the requested value is
            unavailable.
        """
        return _normalize_log_level(value)

    @pydantic.field_validator("format")
    @classmethod
    def validate_format(cls, value: Optional[str]) -> Optional[str]:
        """
        Validate format.

        After applying local validation, the function forwards ``value`` to
        ``_normalize_log_format`` and preserves its return and exception
        contract. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The canonical result text, or ``None`` when the requested value is
            unavailable.
        """
        return _normalize_log_format(value)


_ARCHIVE_BOOLEAN_ALIASES = (
    ("skip_zip", "create_zip"),
    ("skip_zip_split", "create_split_zip"),
)


def _resolve_archive_boolean_aliases(
    candidates: List[tuple[str, Any, bool]],
) -> Optional[bool]:
    """
    Resolve present positive/negative archive spellings to one skip value.

    The implementation uses ``candidates`` to resolve present positive/negative
    archive spellings to one skip value. If the function cannot resolve present
    positive/negative archive spellings to one skip value, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        candidates: Entries supplied as ``candidates`` without transferring
            container ownership.

    Returns:
        Whether the present positive/negative archive spellings to one skip
        value operation succeeds, or ``None`` when the decision is unavailable.

    Raises:
        ValueError: If ``path`` cannot be null; or ``resolved_path`` conflicts
            with ``path``.
    """

    resolved: Optional[bool] = None
    resolved_path: Optional[str] = None
    for path, raw_value, invert in candidates:
        if raw_value is None:
            raise ValueError(f"{path} cannot be null")
        value = _normalize_boolean_alias(raw_value)
        canonical = not value if invert else value
        if resolved_path is not None and canonical != resolved:
            raise ValueError(f"{resolved_path} conflicts with {path}")
        resolved = canonical
        resolved_path = path
    return resolved


def _normalize_output_archive_aliases(values: Any) -> Any:
    """
    Normalize archive aliases inside one raw ``output`` holder.

    The implementation uses ``values`` to normalize archive aliases inside one
    raw ``output`` holder. The source value keeps its ownership while the
    normalized representation is returned separately.

    Args:
        values: Mapping supplying fields for archive aliases inside one raw
            ``output`` holder.

    Returns:
        The output archive aliases value selected by the operation.
    """

    if not isinstance(values, dict):
        return values

    normalized = dict(values)
    for skip_name, create_name in _ARCHIVE_BOOLEAN_ALIASES:
        candidates = []
        if skip_name in values:
            candidates.append((f"output.{skip_name}", values[skip_name], False))
        if create_name in values:
            candidates.append((f"output.{create_name}", values[create_name], True))
        resolved = _resolve_archive_boolean_aliases(candidates)
        if resolved is not None:
            normalized[skip_name] = resolved
            normalized[create_name] = not resolved
    return normalized


def _normalize_config_archive_aliases(values: Any) -> Any:
    """
    Merge root and nested archive aliases before Config materializes defaults.

    Assignment validation supplies a fully materialized holder and every root
    default. Those values are not same-source aliases.

    Args:
        values: Values object whose ``get`` state is read while performing merge
            root and nested archive aliases before Config materializes defaults.

    Returns:
        The config archive aliases value selected by the operation.
    """

    if not isinstance(values, dict):
        return values

    output_value = values.get("output")
    if isinstance(output_value, BaseModel):
        # Assignment validation supplies a fully materialized holder and every
        # root default. Those values are not same-source aliases.
        return values
    if output_value is None and "output" in values:
        return values
    if output_value is not None and not isinstance(output_value, dict):
        return values

    normalized = dict(values)
    output = dict(output_value or {})
    changed = False
    for skip_name, create_name in _ARCHIVE_BOOLEAN_ALIASES:
        candidates = []
        if skip_name in values:
            candidates.append((skip_name, values[skip_name], False))
        if skip_name in output:
            candidates.append((f"output.{skip_name}", output[skip_name], False))
        if create_name in output:
            candidates.append((f"output.{create_name}", output[create_name], True))
        resolved = _resolve_archive_boolean_aliases(candidates)
        if resolved is None:
            continue
        normalized[skip_name] = resolved
        output[skip_name] = resolved
        output[create_name] = not resolved
        changed = True

    if changed:
        normalized["output"] = output
    return normalized


class OutputConfig(BaseModel):
    """
    Output configuration.

    The coherent record keeps ``skip_html_reports``, ``directory``,
    ``create_zip``, ``create_split_zip``, and ``skip_zip`` together so consumers
    observe one output config state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        skip_html_reports: Whether skip HTML reports applies to this record.
        directory: Validated filesystem location associated with directory.
        create_zip: Whether create ZIP applies to this record.
        create_split_zip: Whether create split ZIP applies to this record.
        skip_zip: Whether skip ZIP applies to this record.
        skip_zip_split: Whether skip ZIP split applies to this record.
        zip_split_threshold: Numeric ZIP split threshold retained by this
            record.
        zip_split_threshold_mb: Numeric ZIP split threshold mb retained by this
            record.
        generate_html: Whether generate HTML applies to this record.
        generate_json: Whether generate JSON applies to this record.
        report_format: Report format retained as part of the record's public
            state.
        preserve_metadata: Whether preserve metadata applies to this record.
        max_json_tree_depth: Maximum nested JSON depth rendered inline by the
            legacy HTML report.
    """

    skip_html_reports: bool = False
    directory: Path = Path("/tmp/nvdebug")
    model_config = ConfigDict(extra="forbid")
    create_zip: bool = True
    create_split_zip: bool = True
    skip_zip: Optional[bool] = None
    skip_zip_split: Optional[bool] = None
    zip_split_threshold: float = Field(
        default=200.0,
        ge=MIN_ZIP_SPLIT_THRESHOLD_MB,
        allow_inf_nan=False,
    )  # MB
    zip_split_threshold_mb: Optional[float] = Field(
        default=None,
        ge=MIN_ZIP_SPLIT_THRESHOLD_MB,
        allow_inf_nan=False,
    )

    @pydantic.field_validator("zip_split_threshold", "zip_split_threshold_mb")
    @classmethod
    def validate_zip_split_threshold(cls, value: Optional[float]) -> Optional[float]:
        """
        Validate ZIP split threshold.

        The implementation uses ``value`` to validate ZIP split threshold. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            value: Numeric value used while the operation performs bounded
                accounting.

        Returns:
            The validated ``value``, or ``None`` when no value qualifies.

        Raises:
            ValueError: If the zip split threshold is not finite and at least
                ``MIN_ZIP_SPLIT_THRESHOLD_MB`` MB.
        """
        if value is not None and (
            not math.isfinite(value) or value < MIN_ZIP_SPLIT_THRESHOLD_MB
        ):
            raise ValueError(
                "zip split threshold must be finite and at least "
                f"{MIN_ZIP_SPLIT_THRESHOLD_MB:g} MB"
            )
        return value

    @model_validator(mode="after")
    def normalize_zip_split_threshold_alias(self) -> "OutputConfig":
        """
        Project the explicit ``_mb`` alias without masking contradictions.

        The implementation uses current instance state to project the explicit
        ``_mb`` alias without masking contradictions. If the function cannot
        project the explicit ``_mb`` alias without masking contradictions, its
        exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            An ``OutputConfig`` representing ZIP split threshold alias.

        Raises:
            ValueError: If output.zip_split_threshold_mb conflicts with
                output.zip_split_threshold.
        """

        fields_set = self.model_fields_set
        if "zip_split_threshold_mb" not in fields_set:
            return self

        alias_value = self.zip_split_threshold_mb
        if alias_value is None:
            if "zip_split_threshold" in fields_set:
                raise ValueError(
                    "output.zip_split_threshold_mb conflicts with "
                    "output.zip_split_threshold"
                )
            return self

        if (
            "zip_split_threshold" in fields_set
            and self.zip_split_threshold != alias_value
        ):
            raise ValueError(
                "output.zip_split_threshold_mb conflicts with "
                "output.zip_split_threshold"
            )

        object.__setattr__(self, "zip_split_threshold", alias_value)
        return self

    generate_html: bool = True
    generate_json: bool = True
    report_format: Literal["spa", "legacy", "both"] = "spa"
    preserve_metadata: bool = True
    max_json_tree_depth: int = Field(default=64, strict=True, ge=1, le=512)

    @model_validator(mode="before")
    @classmethod
    def normalize_archive_aliases(cls, values: Any) -> Any:
        """
        Normalize archive aliases.

        After applying local validation, the function forwards ``values`` to
        ``_normalize_output_archive_aliases`` and preserves its return and
        exception contract. The source value keeps its ownership while the
        normalized representation is returned separately.

        Args:
            values: Values consumed while the function attempts to normalize
                archive aliases.

        Returns:
            The archive aliases value selected by the operation.
        """
        return _normalize_output_archive_aliases(values)

    @property
    def output_dir(self) -> str:
        """
        Set output directory from string (backward compatibility setter).

        Each access computes the value from ``directory`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The canonical output dir text.
        """
        return str(self.directory)

    @output_dir.setter
    def output_dir(self, value: str) -> None:
        """
        Set output directory from string (backward compatibility setter).

        The implementation uses ``value`` to set output directory from string
        (backward compatibility setter). It updates ``directory`` on the
        instance as part of that state transition.

        Args:
            value: Text supplied as value in the format accepted by this
                function.
        """
        self.directory = Path(value)

    @model_validator(mode="before")
    @classmethod
    def project_skip_html_reports(cls, values: Any) -> Any:
        """
        Project the positive skip spelling onto the runtime generate flag.

        The implementation uses ``values`` to project the positive skip spelling
        onto the runtime generate flag.

        Args:
            values: Mapping supplying fields for project the positive skip
                spelling onto the runtime generate flag.

        Returns:
            The validated ``values``.
        """
        if isinstance(values, dict) and "skip_html_reports" in values:
            skip_html_reports = _normalize_boolean_alias(values["skip_html_reports"])
            if skip_html_reports is not None and "generate_html" not in values:
                values["generate_html"] = not skip_html_reports
        return values


class RedfishSessionConfig(BaseModel):
    """
    Redfish session configuration for connection pooling and timeouts.

    The coherent record keeps ``connection_pool_limit``,
    ``connection_pool_limit_per_host``, ``session_timeout``,
    ``keepalive_timeout``, and ``structured_response_max_bytes`` together so
    consumers observe one Redfish session config state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        connection_pool_limit: Maximum connection pool admitted by this record.
        connection_pool_limit_per_host: Numeric connection pool limit per host
            retained by this record.
        authentication_mode: Prefer advertised HTTPS token sessions with ``auto``;
            require them with ``session`` or explicitly retain ``basic``.
        session_timeout: Numeric session timeout retained by this record.
        keepalive_timeout: Numeric keepalive timeout retained by this record.
        structured_response_max_bytes: Byte count recorded for structured
            response max.
        attachment_max_bytes: Byte count recorded for attachment max.
        error_response_max_bytes: Byte count recorded for error response max.
        error_evidence_max_bytes: Byte count recorded for error evidence max.
        error_evidence_aggregate_max_bytes: Byte count recorded for error
            evidence aggregate max.
        error_evidence_max_responses: Number of error evidence max responses
            represented by this record.
        preflight_response_max_bytes: Byte count recorded for preflight response
            max.
        cache_max_bytes: Byte count recorded for cache max.
        cache_entry_max_bytes: Byte count recorded for cache entry max.
        tls_mode: Numeric TLS mode retained by this record.
        ca_file: Canonical text used as ca file.
        fingerprint_sha256: Lowercase SHA-256 digest binding the fingerprint
            content.
        server_name: Canonical text used as server name.
        ssl_verify: Whether ssl verify applies to this record.
        ttl_dns_cache: Numeric ttl dns cache retained by this record.
        use_dns_cache: Whether use dns cache applies to this record.
        force_close: Whether force close applies to this record.
        enable_cleanup_closed: Whether cleanup closed applies to this record.
        fallback_connection_pool_limit: Maximum fallback connection pool
            admitted by this record.
        fallback_connection_pool_limit_per_host: Numeric fallback connection
            pool limit per host retained by this record.
        handle_session_conflicts: Whether handle session conflicts applies to
            this record.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    # Connection pool settings
    connection_pool_limit: int = 20
    connection_pool_limit_per_host: int = 8
    authentication_mode: Literal["auto", "basic", "session"] = "auto"

    # Timeout settings
    session_timeout: int = 300  # 5 minutes
    keepalive_timeout: int = 300  # 5 minutes

    # Finite response/evidence/cache ceilings. Raw binary responses stream
    # to private disk staging and are bounded by available space plus reserve,
    # rather than an operator-selected truncation/omission threshold.
    structured_response_max_bytes: int = Field(
        default=DEFAULT_REDFISH_STRUCTURED_RESPONSE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
        exclude=True,
    )
    attachment_max_bytes: int = Field(
        default=DEFAULT_REDFISH_ATTACHMENT_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
        exclude=True,
    )
    error_response_max_bytes: int = Field(
        default=DEFAULT_REDFISH_ERROR_RESPONSE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
        exclude=True,
    )
    error_evidence_max_bytes: int = Field(
        default=DEFAULT_REDFISH_ERROR_EVIDENCE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
        exclude=True,
    )
    error_evidence_aggregate_max_bytes: int = Field(
        default=DEFAULT_REDFISH_ERROR_EVIDENCE_AGGREGATE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
        exclude=True,
    )
    error_evidence_max_responses: int = Field(
        default=DEFAULT_REDFISH_ERROR_EVIDENCE_MAX_RESPONSES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
        exclude=True,
    )
    preflight_response_max_bytes: int = Field(
        default=DEFAULT_REDFISH_PREFLIGHT_RESPONSE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
        exclude=True,
    )
    cache_max_bytes: int = Field(
        default=DEFAULT_REDFISH_CACHE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
        exclude=True,
    )
    cache_entry_max_bytes: int = Field(
        default=DEFAULT_REDFISH_CACHE_ENTRY_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
        exclude=True,
    )

    @model_validator(mode="after")
    def validate_response_limits(self) -> "RedfishSessionConfig":
        """
        Validate response limits.

        The implementation uses current instance state to validate response
        limits. Every required invariant is checked before a successful value is
        returned; invalid input follows the function's explicit exception path.

        Returns:
            The validated ``self``.
        """
        RedfishResponseLimits.from_session_config(self)
        return self

    # TLS server-authentication settings
    tls_mode: Literal["system_ca", "custom_ca", "fingerprint", "insecure"] = "insecure"
    ca_file: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    server_name: Optional[str] = None
    # Deprecated compatibility projection. Runtime code consumes tls_mode.
    ssl_verify: bool = False

    @model_validator(mode="before")
    @classmethod
    def _migrate_ssl_field(cls, values):
        """
        Normalize legacy booleans without obscuring source provenance.

        The implementation uses ``values`` to normalize legacy booleans without
        obscuring source provenance. The source value keeps its ownership while
        the normalized representation is returned separately. If the function
        cannot normalize legacy booleans without obscuring source provenance,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            values: Values consumed while the function attempts to normalize
                legacy booleans without obscuring source provenance.

        Returns:
            The input mapping with legacy TLS aliases normalized, or the
            original non-mapping value.

        Raises:
            ValueError: If ssl cannot be null; ssl_verify cannot be null; ssl
                conflicts with ssl_verify; or ssl_verify conflicts with
                tls_mode.
        """
        if not isinstance(values, dict):
            return values
        normalized = dict(values)
        if "ssl" in normalized:
            legacy_ssl = normalized.pop("ssl")
            legacy_ssl = _normalize_boolean_alias(legacy_ssl)
            if legacy_ssl is None:
                raise ValueError("ssl cannot be null")
            if "ssl_verify" in normalized:
                explicit_verify = _normalize_boolean_alias(normalized["ssl_verify"])
                if explicit_verify is None:
                    raise ValueError("ssl_verify cannot be null")
                if legacy_ssl != explicit_verify:
                    raise ValueError("ssl conflicts with ssl_verify")
            else:
                normalized["ssl_verify"] = legacy_ssl
        legacy_verify = None
        if "ssl_verify" in normalized:
            legacy_verify = _normalize_boolean_alias(normalized["ssl_verify"])
            if legacy_verify is None:
                raise ValueError("ssl_verify cannot be null")
            normalized["ssl_verify"] = legacy_verify
        if normalized.get("tls_mode") is not None:
            mode_verifies = normalized["tls_mode"] != "insecure"
            if legacy_verify is not None and legacy_verify != mode_verifies:
                raise ValueError("ssl_verify conflicts with tls_mode")
        return normalized

    @pydantic.field_validator("fingerprint_sha256")
    @classmethod
    def validate_fingerprint(cls, value: Optional[str]) -> Optional[str]:
        """
        Validate fingerprint.

        After applying local validation, the function forwards ``value`` to
        ``normalize_sha256_fingerprint`` and preserves its return and exception
        contract. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The canonical fingerprint text, or ``None`` when the requested value
            is unavailable.
        """
        return normalize_sha256_fingerprint(value)

    @model_validator(mode="after")
    def validate_tls_policy(self) -> "RedfishSessionConfig":
        # As with DUTConfig, compatibility projections remain available to
        # callers but are deliberately absent from model_fields_set. This lets
        # an explicitly configured private trust policy outrank a legacy
        # verification fallback without pool-only settings looking TLS-explicit.
        """
        Validate TLS policy.

        The implementation uses current instance state to validate TLS policy.
        Every required invariant is checked before a successful value is
        returned; invalid input follows the function's explicit exception path.

        Returns:
            The validated ``self``.

        Raises:
            ValueError: If custom_ca tls mode lacks ca_file; fingerprint tls
                mode lacks fingerprint_sha256; ca_file lacks custom_ca TLS mode;
                or fingerprint_sha256 lacks fingerprint TLS mode.
        """
        fields_set = self.model_fields_set
        if "tls_mode" in fields_set:
            object.__setattr__(self, "ssl_verify", self.tls_mode != "insecure")
        elif "ssl_verify" in fields_set:
            object.__setattr__(
                self,
                "tls_mode",
                "system_ca" if self.ssl_verify else "insecure",
            )

        if self.tls_mode == "custom_ca" and not self.ca_file:
            raise ValueError("custom_ca TLS mode requires ca_file")
        if self.tls_mode == "fingerprint" and not self.fingerprint_sha256:
            raise ValueError("fingerprint TLS mode requires fingerprint_sha256")
        if self.ca_file and self.tls_mode != "custom_ca":
            raise ValueError("ca_file requires custom_ca TLS mode")
        if self.fingerprint_sha256 and self.tls_mode != "fingerprint":
            raise ValueError("fingerprint_sha256 requires fingerprint TLS mode")
        return self

    ttl_dns_cache: int = 300  # DNS cache TTL in seconds
    use_dns_cache: bool = True  # Enable DNS caching
    force_close: bool = False  # Keep connections alive
    enable_cleanup_closed: bool = True  # Clean up closed connections

    # Fallback session settings (more conservative)
    fallback_connection_pool_limit: int = 15
    fallback_connection_pool_limit_per_host: int = 6
    handle_session_conflicts: bool = True


def _explicit_redfish_session_aliases(
    section: Any,
) -> Dict[str, tuple[str, Any]]:
    """
    Return recognized effective fields without validating a legacy holder.

    The implementation uses ``section`` to produce recognized effective fields
    without validating a legacy holder.

    Args:
        section: Section object whose ``items`` state is read while performing
            recognized effective fields without validating a legacy holder.

    Returns:
        A mapping containing explicit Redfish session aliases.
    """

    if not isinstance(section, dict):
        return {}

    aliases: Dict[str, tuple[str, Any]] = {}
    for raw_field, value in section.items():
        effective_field = "ssl_verify" if raw_field == "ssl" else raw_field
        if effective_field in RedfishSessionConfig.model_fields:
            aliases[effective_field] = (raw_field, value)
    return aliases


def _reject_conflicting_redfish_session_holders(
    values: Dict[str, Any],
) -> None:
    """
    Reject contradictory canonical and legacy Redfish holder values.

    The implementation uses ``values`` to reject contradictory canonical and
    legacy Redfish holder values. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        values: Mapping supplying fields for contradictory canonical and legacy
            Redfish holder values.

    Raises:
        ValueError: If redfish_session_config.``field_name`` conflicts with
            redfish_sessions.``field_name``.
    """

    if "redfish_session_config" not in values or "redfish_sessions" not in values:
        return

    canonical = _explicit_redfish_session_aliases(values["redfish_session_config"])
    legacy = _explicit_redfish_session_aliases(values["redfish_sessions"])

    for field_name in sorted(canonical.keys() & legacy.keys()):
        canonical_raw_field, canonical_value = canonical[field_name]
        legacy_raw_field, legacy_value = legacy[field_name]
        if field_name == "ssl_verify":
            canonical_normalized = _normalize_boolean_alias(canonical_value)
            legacy_normalized = _normalize_boolean_alias(legacy_value)
        elif field_name == "fingerprint_sha256":
            canonical_normalized = normalize_sha256_fingerprint(canonical_value)
            legacy_normalized = normalize_sha256_fingerprint(legacy_value)
        else:
            annotation = RedfishSessionConfig.model_fields[field_name].annotation
            adapter = pydantic.TypeAdapter(annotation)
            canonical_normalized = adapter.validate_python(canonical_value)
            legacy_normalized = adapter.validate_python(legacy_value)
        if canonical_normalized != legacy_normalized:
            raise ValueError(
                f"redfish_session_config.{field_name} conflicts with "
                f"redfish_sessions.{field_name}"
            )


class AdaptiveConcurrencyConfig(BaseModel):
    """
    Represent bounded AIMD pressure and lifecycle policy.

    These fields tune only opt-in adaptive mode.  Conservative and fixed modes
    retain the same resolved values in metadata for comparison but do not start
    a pressure-sampling task.

    Attributes:
        sample_interval_seconds: Seconds between adaptive pressure windows.
        healthy_windows_required: Consecutive healthy windows before increase.
        increase_step: Largest additive capacity increase in one decision.
        decrease_ratio: Capacity multiplier for sustained pressure.
        hard_decrease_ratio: Capacity multiplier for immediate safety pressure.
        cooldown_seconds: Recovery delay after a decrease.
        endpoint_cooldown_seconds: Pause applied only to a throttled endpoint.
        cpu_utilization_threshold: Process CPU pressure threshold.
        process_memory_utilization_threshold: Process RSS pressure threshold.
        cgroup_throttling_ratio_threshold: Cgroup throttled-period threshold.
        memory_headroom_threshold: Minimum acceptable memory headroom.
        file_descriptor_utilization_threshold: Descriptor pressure threshold.
        pid_utilization_threshold: Cgroup task pressure threshold.
        event_loop_lag_threshold_seconds: Event-loop scheduling-lag threshold.
        remote_throttle_rate_threshold: Remote pressure events per operation.
        remote_throttle_minimum_events: Minimum events for global reduction.
        remote_throttle_minimum_endpoints: Distinct pressured endpoints needed
            before a remote signal may reduce the global budget.
        maximum_consecutive_sampler_errors: Transient observation failures
            tolerated before adaptive sampling stops.
        maximum_resident_bytes: Optional operator-authorized process RSS bound
            used when neither RLIMIT_AS nor a finite cgroup limit is visible.
        maximum_decision_events: Bounded retained decision history.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    sample_interval_seconds: float = Field(default=20.0, strict=True, ge=10.0, le=30.0)
    healthy_windows_required: int = Field(default=3, strict=True, ge=1, le=100)
    increase_step: int = Field(default=8, strict=True, ge=1, le=256)
    decrease_ratio: float = Field(default=0.75, strict=True, ge=0.5, le=0.75)
    hard_decrease_ratio: float = Field(default=0.5, strict=True, ge=0.5, le=0.75)
    cooldown_seconds: float = Field(default=60.0, strict=True, ge=0.0, le=3600.0)
    endpoint_cooldown_seconds: float = Field(
        default=30.0, strict=True, ge=0.0, le=3600.0
    )
    cpu_utilization_threshold: float = Field(default=0.90, strict=True, ge=0.1, le=1.0)
    process_memory_utilization_threshold: float = Field(
        default=0.90, strict=True, ge=0.1, le=1.0
    )
    cgroup_throttling_ratio_threshold: float = Field(
        default=0.10, strict=True, ge=0.0, le=1.0
    )
    memory_headroom_threshold: float = Field(default=0.10, strict=True, ge=0.0, le=1.0)
    file_descriptor_utilization_threshold: float = Field(
        default=0.80, strict=True, ge=0.1, le=1.0
    )
    pid_utilization_threshold: float = Field(default=0.90, strict=True, ge=0.1, le=1.0)
    event_loop_lag_threshold_seconds: float = Field(
        default=0.25, strict=True, ge=0.001, le=60.0
    )
    remote_throttle_rate_threshold: float = Field(
        default=0.10, strict=True, ge=0.0, le=1.0
    )
    remote_throttle_minimum_events: int = Field(default=2, strict=True, ge=1, le=10_000)
    remote_throttle_minimum_endpoints: int = Field(
        default=2, strict=True, ge=1, le=10_000
    )
    maximum_consecutive_sampler_errors: int = Field(
        default=3, strict=True, ge=1, le=100
    )
    maximum_resident_bytes: Optional[int] = Field(
        default=None, strict=True, ge=1, le=(1 << 63) - 1
    )
    maximum_decision_events: int = Field(default=10_000, strict=True, ge=1, le=10_000)


class ExecutionSectionConfig(BaseModel):
    """
    Represent execution section config data exchanged by the runtime.

    The coherent record keeps scheduler selection, global admission policy,
    whole-DUT and per-DUT bounds, timeouts, and retry policy together so
    consumers observe one execution state rather than assembling partial data.

    Attributes:
        scheduler: Scheduler retained as part of the record's public state.
        concurrency_mode: Conservative, fixed, or adaptive global admission.
        initial_io_oversubscription: Optional configured CPU multiplier.
        minimum_collector_operations: Adaptive weighted-capacity floor.
        maximum_collector_operations: Optional explicit hard capacity ceiling.
        adaptive: Bounded AIMD pressure and lifecycle settings.
        max_concurrent_duts: Maximum concurrent duts admitted by this record.
        max_concurrent_collectors_per_dut: Maximum concurrent collectors per DUT
            admitted by this record.
        timeout: Numeric timeout retained by this record.
        retry_count: Number of retry entries represented by the record.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    scheduler: Literal["per_dut", "legacy_global"] = "per_dut"
    concurrency_mode: Literal["conservative", "adaptive", "fixed"] = "conservative"
    initial_io_oversubscription: Optional[float] = Field(
        default=None, strict=True, gt=0.0, le=64.0
    )
    minimum_collector_operations: int = Field(default=1, strict=True, gt=0, le=4096)
    maximum_collector_operations: Optional[int] = Field(
        default=None, strict=True, gt=0, le=4096
    )
    adaptive: AdaptiveConcurrencyConfig = Field(
        default_factory=AdaptiveConcurrencyConfig
    )
    max_concurrent_duts: Optional[int] = Field(default=None, strict=True, gt=0)
    max_concurrent_collectors_per_dut: Optional[int] = Field(
        default=None, strict=True, gt=0
    )
    timeout: Optional[int] = None
    retry_count: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def reject_null_concurrency_limits(cls, values: Any) -> Any:
        """
        Reject null concurrency limits.

        The implementation uses ``values`` to reject null concurrency limits.
        Every required invariant is checked before a successful value is
        returned; invalid input follows the function's explicit exception path.

        Args:
            values: Mapping supplying fields for null concurrency limits.

        Returns:
            The validated ``values``.

        Raises:
            ValueError: If execution.``field_name`` cannot be null.
        """
        if isinstance(values, dict):
            for field_name in (
                "max_concurrent_duts",
                "max_concurrent_collectors_per_dut",
            ):
                if field_name in values and values[field_name] is None:
                    raise ValueError(f"execution.{field_name} cannot be null")
        return values


def _normalize_preflight_aliases(values: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge the accepted preflight holders into their canonical fields.

    The implementation uses ``values`` to merge the accepted preflight holders
    into their canonical fields.

    Args:
        values: Mapping supplying fields for merge the accepted preflight
            holders into their canonical fields.

    Returns:
        The validated ``normalized``.
    """

    normalized = dict(values)
    merged: Dict[str, Any] = {}
    source_by_field: Dict[str, str] = {}

    def merge_fields(source: str, fields: Dict[str, Any]) -> None:
        """
        Merge fields.

        The implementation uses ``source`` and ``fields`` to merge fields. If
        the function cannot merge fields, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            source: Text supplied as source in the format accepted by this
                function.
            fields: Mapping supplying fields for merge fields.

        Raises:
            ValueError: If the supplied input cannot be used to merge fields.
        """
        for field_name, value in fields.items():
            field_path = (
                "skip_preflight"
                if source == "skip_preflight"
                else f"{source}.{field_name}"
            )
            if field_name in merged and merged[field_name] != value:
                raise ValueError(
                    f"{field_path} conflicts with {source_by_field[field_name]}"
                )
            merged[field_name] = value
            source_by_field.setdefault(field_name, field_path)

    for holder in ("preflight", "preflight_config"):
        if holder not in values or values[holder] is None:
            continue
        parsed = PreflightConfig.model_validate(values[holder])
        merge_fields(holder, parsed.model_dump(exclude_unset=True))

    if "skip_preflight" in values:
        parsed_skip = PreflightConfig.model_validate({"skip": values["skip_preflight"]})
        merge_fields(
            "skip_preflight",
            parsed_skip.model_dump(include={"skip"}, exclude_unset=True),
        )

    if merged:
        normalized["preflight_config"] = merged
        if "skip" in merged:
            normalized["skip_preflight"] = merged["skip"]

    return normalized


class PreflightConfig(BaseModel):
    """
    Preflight credential validation configuration.

    The coherent record keeps ``skip``, ``validate_credentials_in_preflight``,
    and ``credential_validation_uri`` together so consumers observe one
    preflight config state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        skip: Whether skip applies to this record.
        validate_credentials_in_preflight: Whether validate credentials in
            preflight applies to this record.
        credential_validation_uri: Canonical text used as credential validation
            URI.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    skip: bool = False
    validate_credentials_in_preflight: bool = True
    credential_validation_uri: Optional[str] = None


class StreamingConfig(BaseModel):
    """
    Strict nested aliases for the streaming runtime configuration.

    The coherent record keeps ``only``, ``begin``, ``end``, ``destination``, and
    ``append`` together so consumers observe one streaming config state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        only: Whether only applies to this record.
        begin: Canonical text used as begin.
        end: Canonical text used as end.
        destination: Destination retained as part of the record's public state.
        append: Whether append applies to this record.
        rack_id: Canonical text used as rack identifier.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    only: bool = False
    begin: str = "24"
    end: str = "0"
    destination: Optional[Path] = None
    append: bool = False
    rack_id: Optional[str] = None


class SSHProxyConfig(BaseModel):
    """
    Represent SSH proxy config data exchanged by the runtime.

    The coherent record keeps ``host``, ``port``, ``username``, ``password``,
    and ``key_path`` together so consumers observe one SSH proxy config state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        host: Canonical text used as host.
        port: Numeric port retained by this record.
        username: Canonical text used as username.
        password: Canonical text used as password.
        key_path: Validated filesystem location associated with key path.
        passwordless: Whether passwordless applies to this record.
        max_retries: Maximum retries admitted by this record.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    host: Optional[str] = None
    port: int = 22
    username: Optional[str] = None
    password: Optional[str] = None
    key_path: Optional[Path] = None
    passwordless: bool = False
    max_retries: int = 3


class SSHConnectionPoolConfig(BaseModel):
    """
    Validated limits for reusable Host SSH endpoint connections.

    The coherent record keeps ``max_sessions_per_endpoint``,
    ``max_channels_per_session``, ``max_commands_per_session``,
    ``backpressure_timeout_seconds``, ``connect_timeout_seconds``,
    ``retry_backoff_cap_seconds``, and ``shutdown_timeout_seconds`` together so
    consumers observe one SSH connection pool config state. Consumers receive
    the fields as one unit instead of assembling partial state.

    Attributes:
        max_sessions_per_endpoint: Maximum sessions per endpoint admitted by
            this record.
        max_channels_per_session: Maximum channels per session admitted by this
            record.
        max_commands_per_session: Maximum remote process starts admitted on one
            reusable session before retirement.
        backpressure_timeout_seconds: Maximum endpoint-capacity admission wait,
            separate from connect and command execution budgets.
        connect_timeout_seconds: Number of connect timeout seconds represented
            by this record.
        retry_backoff_cap_seconds: Number of retry backoff cap seconds
            represented by this record.
        shutdown_timeout_seconds: Number of shutdown timeout seconds represented
            by this record.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    # Serialize commands per endpoint by default. Some production SSH servers
    # accept several transports or channels but close them under mixed,
    # long-running workloads. DUTs still execute concurrently with each other.
    max_sessions_per_endpoint: int = Field(default=1, strict=True, ge=1, le=8)
    max_channels_per_session: int = Field(default=1, strict=True, ge=1, le=32)
    max_commands_per_session: int = Field(default=1, strict=True, ge=1, le=10000)
    backpressure_timeout_seconds: float = Field(
        default=900.0,
        strict=True,
        gt=0,
        le=7200,
        allow_inf_nan=False,
    )
    connect_timeout_seconds: float = Field(
        default=30.0,
        strict=True,
        gt=0,
        le=300,
        allow_inf_nan=False,
    )
    retry_backoff_cap_seconds: float = Field(
        default=8.0,
        strict=True,
        ge=0,
        le=60,
        allow_inf_nan=False,
    )
    shutdown_timeout_seconds: float = Field(
        default=10.0,
        strict=True,
        gt=0,
        le=60,
        allow_inf_nan=False,
    )


class SanitizationConfig(BaseModel):
    """
    Strict sanitization settings accepted by the tool configuration.

    The coherent record keeps ``enabled``, ``skip``, and
    ``apply_post_collection`` together so consumers observe one sanitization
    config state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        enabled: Whether enabled applies to this record.
        skip: Whether skip applies to this record.
        apply_post_collection: Whether to run the completed-bundle backstop.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    enabled: bool = True
    skip: Optional[bool] = None
    apply_post_collection: bool = False

    @model_validator(mode="before")
    @classmethod
    def normalize_skip(cls, values: Any) -> Any:
        """
        Normalize skip.

        The implementation uses ``values`` to normalize skip. The source value
        keeps its ownership while the normalized representation is returned
        separately. If the function cannot normalize skip, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            values: Values consumed while the function attempts to normalize
                skip.

        Returns:
            The skip value selected by the operation.

        Raises:
            ValueError: If sanitization.skip cannot be null;
                sanitization.enabled cannot be null; or sanitization.skip
                conflicts with sanitization.enabled.
        """
        if not isinstance(values, dict) or "skip" not in values:
            return values

        normalized = dict(values)
        if normalized["skip"] is None:
            raise ValueError("sanitization.skip cannot be null")
        if "enabled" in normalized and normalized["enabled"] is None:
            raise ValueError("sanitization.enabled cannot be null")

        enabled = not _normalize_boolean_alias(normalized["skip"])
        if (
            "enabled" in normalized
            and _normalize_boolean_alias(normalized["enabled"]) != enabled
        ):
            raise ValueError("sanitization.skip conflicts with sanitization.enabled")
        normalized["enabled"] = enabled
        return normalized


class Config(BaseSettings):
    """
    Main configuration class.

    The coherent record keeps ``baseboard``, ``collection_level``,
    ``skip_validation``, ``execution_mode``, and ``non_interactive`` together so
    consumers observe one config state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        baseboard: Canonical text used as baseboard.
        collection_level: Collection level retained as part of the record's
            public state.
        skip_validation: Whether skip validation applies to this record.
        execution_mode: Execution mode retained as part of the record's public
            state.
        non_interactive: Whether non interactive applies to this record.
        local: Whether local applies to this record.
        duts: Collection of duts entries retained by this record.
        output: Output retained as part of the record's public state.
        logging: Logging retained as part of the record's public state.
        redfish_session_config: Redfish session config retained as part of the
            record's public state.
        redfish_sessions: Redfish sessions retained as part of the record's
            public state.
        redfish_request_capture: Redfish request capture retained as part of the
            record's public state.
        preflight_config: Preflight config retained as part of the record's
            public state.
        ssh_proxy: SSH proxy retained as part of the record's public state.
        ssh_host_key_policy: Canonical text used as SSH host key policy.
        ssh_known_hosts_file: Canonical text used as SSH known hosts file.
        ssh_connection_pool: SSH connection pool retained as part of the
            record's public state.
        TargetBaseboard: Canonical text used as target baseboard.
        LogSanitization: Whether log sanitization applies to this record.
        GENERATE_HTML_REPORTS: Whether generate HTML reports applies to this
            record.
        FW_INVENTORY_TABLE_PROPERTIES: Collection of firmware inventory table
            properties entries retained by this record.
        ADDITIONAL_OOB_URI_COLLECTION: Collection of additional oob URI
            collection entries retained by this record.
        NVLINK_OOB_URI: Collection of nvlink oob URI entries retained by this
            record.
        CUSTOM_DUMP_SERVICES: Mapping that retains the custom dump services
            fields for this record.
        REDFISH_R31_PAYLOAD: Mapping that retains the Redfish r31 payload fields
            for this record.
        POST_CODES_URI: Collection of post codes URI entries retained by this
            record.
        skip_html_reports: Whether skip HTML reports applies to this record.
        skip_zip: Whether skip ZIP applies to this record.
        skip_preflight: Whether skip preflight applies to this record.
        zip_split_threshold: Numeric ZIP split threshold retained by this
            record.
        skip_collectors: Collection of skip collectors entries retained by this
            record.
        include_collectors: Collection of include collectors entries retained by
            this record.
        SKIP_PORT_FW: Whether skip port firmware applies to this record.
        SKIP_BMC_SSH_LOGS: Whether skip BMC SSH logs applies to this record.
        SKIP_HOST_LOGS: Whether skip host logs applies to this record.
        SKIP_IPMI_LOGS: Whether skip IPMI logs applies to this record.
        SKIP_REDFISH_OOB_LOGS: Whether skip Redfish oob logs applies to this
            record.
        COLLECTOR_TO_SKIP: Collection of collector to skip entries retained by
            this record.
        SYSTEM_ID_TO_SKIP: Collection of system identifier to skip entries
            retained by this record.
        CHASSIS_ID_TO_SKIP: Collection of chassis identifier to skip entries
            retained by this record.
        MANAGER_ID_TO_SKIP: Collection of manager identifier to skip entries
            retained by this record.
        expand_level: Numeric expand level retained by this record.
        EXPAND_QUERY_CHASSIS_LEVEL: Numeric expand query chassis level retained
            by this record.
        EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL: Numeric expand query firmware
            inventory level retained by this record.
        EXPAND_QUERY_MANAGER_LEVEL: Numeric expand query manager level retained
            by this record.
        EXPAND_QUERY_SYSTEM_LEVEL: Numeric expand query system level retained by
            this record.
        EXPAND_FALLBACK_MODE: Expand fallback mode retained as part of the
            record's public state.
        expand_fallback_mode: Expand fallback mode retained as part of the
            record's public state.
        NVOS_TECH_DUMP_TIMEOUT: Numeric nvos tech dump timeout retained by this
            record.
        REDFISH_DUMP_TIMEOUT: Numeric Redfish dump timeout retained by this
            record.
        REDFISH_DEVICE_DUMP_SLEEP_DURATION: Numeric Redfish device dump sleep
            duration retained by this record.
        COLLECTOR_EXTENSION_CONFIG: Mapping that retains the collector extension
            config fields for this record.
        EXTRA_LOG_COLLECTION: Whether extra log collection applies to this
            record.
        sysinfo_snapshot_mode: H24 command profile, with fast disabling firmware
            dumps and full explicitly enabling the longer firmware collection.
        streaming_only: Whether streaming only applies to this record.
        stream_begin: Canonical text used as stream begin.
        stream_end: Canonical text used as stream end.
        stream_destination: Canonical text used as stream destination.
        append: Whether append applies to this record.
        rack_id: Canonical text used as rack identifier.
        streaming: Streaming retained as part of the record's public state.
        sanitization: Sanitization retained as part of the record's public
            state.
        execution: Execution retained as part of the record's public state.
        execution_config: Execution config retained as part of the record's
            public state.
        preflight: Preflight retained as part of the record's public state.
        uri_overrides: Mapping that retains the URI overrides fields for this
            record.
        verbose: Whether verbose applies to this record.
        debug: Whether debug applies to this record.
        concurrency_mode: Conservative, fixed, or adaptive global admission.
        initial_io_oversubscription: Optional configured CPU multiplier.
        minimum_collector_operations: Adaptive weighted-capacity floor.
        maximum_collector_operations: Optional hard weighted-capacity ceiling.
        max_concurrent_duts: Maximum concurrent duts admitted by this record.
        max_concurrent_collectors_per_dut: Maximum concurrent collectors per DUT
            admitted by this record.
        timeout: Numeric timeout retained by this record.
        retry_count: Number of retry entries represented by the record.
        execution_scheduler: Canonical text used as execution scheduler.
        PARALLEL_DUT_SEQUENTIAL_COLLECTORS: Whether parallel DUT sequential
            collectors applies to this record.
        SERVICE_GROUPED_SEQUENTIAL_COLLECTORS: Whether service grouped
            sequential collectors applies to this record.
        TASK_ID_PREFIX: Canonical text used as task identifier prefix.
        TOOL_TEMP_DIR: Canonical text used as tool temp dir.
        i2c_config: Mapping that retains the i2c config fields for this record.
        ipmi_cipher: Optional legacy IPMI cipher projected as a per-DUT default.
        max_pagination_pages: Maximum pagination pages admitted by this record.
        max_duplicate_url_retries: Maximum duplicate URL retries admitted by
            this record.
        log_level: Canonical text used as log level.
        log_format: Canonical text used as log format.
        output_directory: Canonical text used as output directory.
        report_format: Report format retained as part of the record's public
            state.
        skip_zip_split: Whether skip ZIP split applies to this record.
    """

    @model_validator(mode="before")
    @classmethod
    def project_nested_logging_aliases(cls, values: Any) -> Any:
        """
        Project explicitly supplied nested logging controls.

        The implementation uses ``values`` to project explicitly supplied nested
        logging controls.

        Args:
            values: Values consumed while the function attempts to project
                explicitly supplied nested logging controls.

        Returns:
            The project nested logging aliases value selected by the operation.
        """

        if isinstance(values, dict):
            reject_removed_attachment_limit_setting(values)
            return _normalize_logging_aliases(values)
        return values

    model_config = SettingsConfigDict(
        # The CLI owns dotenv discovery and applies its path, ownership,
        # permission, and key-allowlist checks before constructing Config.
        # BaseSettings must not independently read a CWD-relative ``.env``.
        env_file=None,
        case_sensitive=False,
        extra="forbid",
        validate_assignment=True,
    )

    def __new__(cls, **values: Any) -> "Config":
        """
        Validate caller values before BaseSettings adds environment values.

        After applying local validation, the function forwards ``values`` to
        ``__new__`` and preserves its return and exception contract. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            values: Additional named values forwarded without changing their
                keys.

        Returns:
            A ``Config`` representing new.
        """

        execution_values = {
            field_name: values[field_name]
            for field_name in (
                "concurrency_mode",
                "initial_io_oversubscription",
                "minimum_collector_operations",
                "maximum_collector_operations",
                "max_concurrent_duts",
                "max_concurrent_collectors_per_dut",
            )
            if field_name in values
        }
        if execution_values:
            ExecutionSectionConfig.model_validate(execution_values)
        return super().__new__(cls)

    @model_validator(mode="before")
    @classmethod
    def reject_conflicting_report_formats(cls, values: Any) -> Any:
        """
        Reject explicitly supplied flat and nested report formats that differ.

        The implementation uses ``values`` to reject explicitly supplied flat
        and nested report formats that differ. Every required invariant is
        checked before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            values: Values object whose ``get`` state is read while performing
                explicitly supplied flat and nested report formats that differ.

        Returns:
            The reject conflicting report formats value selected by the
            operation.

        Raises:
            ValueError: If conflicting report format aliases: report_format and
                output.report_format.
        """
        if not isinstance(values, dict) or "report_format" not in values:
            return values

        output = values.get("output")
        if not isinstance(output, dict) or "report_format" not in output:
            return values

        if values["report_format"] != output["report_format"]:
            raise ValueError(
                "Conflicting report format aliases: "
                "report_format and output.report_format"
            )
        return values

    # Preserve exact YAML presence separately from BaseSettings environment
    # fallbacks so only fields written in the file produce deprecation warnings.
    _yaml_paths: Optional[Set[str]] = None

    @pydantic.field_validator("zip_split_threshold")
    @classmethod
    def validate_zip_split_threshold(cls, value: float) -> float:
        """
        Validate ZIP split threshold.

        The implementation uses ``value`` to validate ZIP split threshold. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            value: Numeric value used while the operation performs bounded
                accounting.

        Returns:
            The validated ``value``.

        Raises:
            ValueError: If the zip split threshold is not finite and at least
                ``MIN_ZIP_SPLIT_THRESHOLD_MB`` MB.
        """
        if not math.isfinite(value) or value < MIN_ZIP_SPLIT_THRESHOLD_MB:
            raise ValueError(
                "zip split threshold must be finite and at least "
                f"{MIN_ZIP_SPLIT_THRESHOLD_MB:g} MB"
            )
        return value

    @model_validator(mode="after")
    def normalize_zip_split_threshold_aliases(self) -> "Config":
        """
        Keep root and nested threshold spellings presence-aware and equivalent.

        The implementation uses current instance state to keep root and nested
        threshold spellings presence-aware and equivalent. If the function
        cannot keep root and nested threshold spellings presence-aware and
        equivalent, its exception reaches the caller instead of being converted
        into a successful result.

        Returns:
            A ``Config`` representing ZIP split threshold aliases.

        Raises:
            ValueError: If output.zip_split_threshold_mb conflicts with
                zip_split_threshold; or output.zip_split_threshold conflicts
                with zip_split_threshold.
        """

        root_explicit = "zip_split_threshold" in self.model_fields_set
        output_fields_set = self.output.model_fields_set
        nested_explicit = "zip_split_threshold" in output_fields_set
        nested_alias_explicit = "zip_split_threshold_mb" in output_fields_set

        if nested_alias_explicit and self.output.zip_split_threshold_mb is None:
            if root_explicit:
                raise ValueError(
                    "output.zip_split_threshold_mb conflicts with zip_split_threshold"
                )
            return self

        nested_explicit = nested_explicit or nested_alias_explicit
        if (
            root_explicit
            and nested_explicit
            and self.zip_split_threshold != self.output.zip_split_threshold
        ):
            raise ValueError(
                "output.zip_split_threshold conflicts with zip_split_threshold"
            )

        if root_explicit and not nested_explicit:
            object.__setattr__(
                self.output, "zip_split_threshold", self.zip_split_threshold
            )
        elif nested_explicit and not root_explicit:
            object.__setattr__(
                self, "zip_split_threshold", self.output.zip_split_threshold
            )
        return self

    # Basic configuration
    baseboard: str = "compute"
    collection_level: CollectionLevel = CollectionLevel.L1
    skip_validation: bool = False
    execution_mode: ExecutionMode = ExecutionMode.LOCAL
    non_interactive: bool = False
    local: bool = False

    # BaseSettings materializes environment fallbacks into the same model as
    # values loaded from YAML. Preserve the YAML source boundary so downstream
    # precedence code can distinguish those layers.
    _yaml_fields: Optional[Set[str]] = None

    # DUT configurations
    duts: List[DUTConfig] = Field(default_factory=list)

    # Output configuration
    output: OutputConfig = Field(default_factory=OutputConfig)

    @model_validator(mode="before")
    @classmethod
    def reject_conflicting_output_directories(cls, values: Any) -> Any:
        """
        Reject contradictory flat and nested output-directory aliases.

        The implementation uses ``values`` to reject contradictory flat and
        nested output-directory aliases. Every required invariant is checked
        before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            values: Values object whose ``get`` state is read while performing
                contradictory flat and nested output-directory aliases.

        Returns:
            The reject conflicting output directories value selected by the
            operation.

        Raises:
            ValueError: If output_directory conflicts with output.directory.
        """

        if not isinstance(values, dict) or "output_directory" not in values:
            return values

        output = values.get("output")
        if not isinstance(output, dict) or "directory" not in output:
            return values

        flat_directory = values["output_directory"]
        nested_directory = output["directory"]
        if flat_directory is None or nested_directory is None:
            equivalent = flat_directory is nested_directory
        else:
            try:
                equivalent = Path(flat_directory) == Path(nested_directory)
            except TypeError:
                return values

        if not equivalent:
            raise ValueError("output_directory conflicts with output.directory")
        return values

    # Logging configuration
    logging: LoggingSectionConfig = Field(default_factory=LoggingSectionConfig)

    # Redfish session configuration
    redfish_session_config: RedfishSessionConfig = Field(
        default_factory=RedfishSessionConfig
    )
    redfish_sessions: Optional[RedfishSessionConfig] = None

    # Active run-wide limits for private request capture, canonical publication,
    # and rollback-pending artifacts awaiting durable collector-status adoption.
    redfish_request_capture: RedfishRequestCaptureLimits = Field(
        default_factory=RedfishRequestCaptureLimits
    )

    @model_validator(mode="before")
    @classmethod
    def project_legacy_redfish_sessions(cls, values: Any) -> Any:
        """
        Project the legacy holder onto the canonical runtime boundary.

        The implementation uses ``values`` to project the legacy holder onto the
        canonical runtime boundary.

        Args:
            values: Values object whose ``get`` state is read while performing
                project the legacy holder onto the canonical runtime boundary.

        Returns:
            The project legacy Redfish sessions value selected by the operation.
        """

        if not isinstance(values, dict) or values.get("redfish_sessions") is None:
            return values

        _reject_conflicting_redfish_session_holders(values)
        normalized = dict(values)
        legacy = values["redfish_sessions"]
        canonical = values.get("redfish_session_config")

        def explicit_mapping(holder: Any) -> Optional[Dict[str, Any]]:
            """
            Return the explicit mapping.

            The implementation uses ``holder`` to produce the explicit mapping.

            Args:
                holder: Holder object whose ``model_dump`` state is read while
                    performing explicit mapping.

            Returns:
                A mapping containing explicit mapping, or ``None`` when the
                requested value is unavailable.
            """
            if isinstance(holder, dict):
                return dict(holder)
            if hasattr(holder, "model_dump"):
                explicit_values = holder.model_dump(exclude_unset=True)
                fields_set = set(getattr(holder, "model_fields_set", set()))
                for field_name in RedfishResponseLimits.model_fields:
                    if field_name in fields_set:
                        explicit_values[field_name] = getattr(holder, field_name)
                return explicit_values
            return None

        legacy_values = explicit_mapping(legacy)
        canonical_values = explicit_mapping(canonical)
        if "redfish_session_config" not in values or canonical is None:
            normalized["redfish_session_config"] = legacy
        elif legacy_values is not None and canonical_values is not None:
            # The canonical spelling wins on overlap (already checked above);
            # complementary fields remain part of one validated runtime policy.
            merged = {
                **legacy_values,
                **canonical_values,
            }
            normalized["redfish_session_config"] = merged
            normalized["redfish_sessions"] = merged
        return normalized

    # Preflight configuration
    preflight_config: PreflightConfig = Field(default_factory=PreflightConfig)

    # SSH proxy configuration
    ssh_proxy: Optional[SSHProxyConfig] = None
    ssh_host_key_policy: Literal["strict", "insecure"] = "insecure"
    ssh_known_hosts_file: Optional[str] = None
    ssh_connection_pool: SSHConnectionPoolConfig = Field(
        default_factory=SSHConnectionPoolConfig
    )

    # Legacy fields for backward compatibility
    TargetBaseboard: Optional[str] = None
    LogSanitization: bool = True
    GENERATE_HTML_REPORTS: bool = True

    # Firmware Inventory Configuration
    FW_INVENTORY_TABLE_PROPERTIES: List[str] = Field(default_factory=list)

    # Additional OOB URI Collection Configuration
    ADDITIONAL_OOB_URI_COLLECTION: List[str] = Field(default_factory=list)

    # NVLink OOB URI Collection Configuration
    NVLINK_OOB_URI: List[str] = Field(default_factory=list)

    # Custom Dump Services Configuration
    CUSTOM_DUMP_SERVICES: List[Dict[str, Any]] = Field(default_factory=list)

    # R31 FDR diagnostic payload override. None preserves the catalog default.
    REDFISH_R31_PAYLOAD: Optional[Dict[str, Any]] = None

    @pydantic.field_validator("REDFISH_R31_PAYLOAD")
    @classmethod
    def validate_redfish_r31_payload(cls, value: Any) -> Optional[Dict[str, Any]]:
        """
        Validate Redfish r31 payload.

        After applying local validation, the function forwards ``value`` to
        ``_normalize_redfish_diagnostic_payload`` and preserves its return and
        exception contract. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path.

        Args:
            value: Value evaluated while performing redfish r31 payload.

        Returns:
            A mapping containing Redfish r31 payload, or ``None`` when the
            requested value is unavailable.
        """
        return _normalize_redfish_diagnostic_payload(value)

    # Post Codes URI Configuration
    POST_CODES_URI: List[str] = Field(default_factory=list)

    # Skip flags for orchestrator
    skip_html_reports: bool = False
    skip_zip: bool = False
    skip_preflight: bool = False
    zip_split_threshold: float = Field(
        default=200.0,
        ge=MIN_ZIP_SPLIT_THRESHOLD_MB,
        allow_inf_nan=False,
    )

    # Per-DUT Collector Configuration
    skip_collectors: List[str] = Field(default_factory=list)
    include_collectors: List[str] = Field(default_factory=list)

    # Legacy Skip Flags (from legacy NVDebug)
    SKIP_PORT_FW: bool = False
    SKIP_BMC_SSH_LOGS: bool = True
    SKIP_HOST_LOGS: bool = False
    SKIP_IPMI_LOGS: bool = False
    SKIP_REDFISH_OOB_LOGS: bool = False

    # New Skip Fields
    COLLECTOR_TO_SKIP: List[str] = Field(default_factory=list)
    SYSTEM_ID_TO_SKIP: List[str] = Field(default_factory=list)
    CHASSIS_ID_TO_SKIP: List[str] = Field(default_factory=list)
    MANAGER_ID_TO_SKIP: List[str] = Field(default_factory=list)

    @pydantic.field_validator(
        "SYSTEM_ID_TO_SKIP", "CHASSIS_ID_TO_SKIP", "MANAGER_ID_TO_SKIP"
    )
    @classmethod
    def validate_entity_skip_patterns(cls, value: Any) -> List[str]:
        """
        Validate case-sensitive Redfish ID skip regular expressions.

        Tool- or DUT-authored patterns share one validation boundary so a
        malformed expression cannot survive precedence resolution and fail only
        after collection has started.

        Args:
            value: Candidate pattern list supplied for one entity family.

        Returns:
            The validated pattern list in source order.

        Raises:
            ValueError: If any entry is malformed or exceeds its bound.
        """

        return _validate_entity_skip_patterns(value)

    expand_level: Optional[int] = Field(default=None, strict=True, ge=0)

    # Expand Query Fields
    EXPAND_QUERY_CHASSIS_LEVEL: int = 1
    EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL: int = 1
    EXPAND_QUERY_MANAGER_LEVEL: int = 1
    EXPAND_QUERY_SYSTEM_LEVEL: int = 1
    # See DUTConfig.EXPAND_FALLBACK_MODE — tool-level default; per-DUT
    # config takes precedence.
    EXPAND_FALLBACK_MODE: Literal["auto", "never", "always"] = "auto"
    expand_fallback_mode: Optional[Literal["auto", "never", "always"]] = None

    # Timeout Fields
    NVOS_TECH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DEVICE_DUMP_SLEEP_DURATION: Optional[int] = None

    # Namespaced configuration consumed only by trusted catalog extensions.
    COLLECTOR_EXTENSION_CONFIG: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    # Feature Flags
    EXTRA_LOG_COLLECTION: Optional[bool] = None
    sysinfo_snapshot_mode: Literal["fast", "full"] = "fast"

    # Streaming configuration
    streaming_only: bool = False
    stream_begin: str = "24"
    stream_end: str = "0"
    stream_destination: Optional[str] = None
    append: bool = False
    rack_id: Optional[str] = None
    streaming: Optional[StreamingConfig] = None

    # Sanitization configuration
    sanitization: Optional[SanitizationConfig] = None

    # Execution configuration
    execution: Optional[ExecutionSectionConfig] = None
    execution_config: Optional[ExecutionSectionConfig] = None

    # Preflight configuration
    preflight: Optional[PreflightConfig] = None

    # New configuration fields for enhanced functionality
    # URI configuration
    uri_overrides: Optional[Dict[str, Any]] = None

    verbose: bool = False

    # Debug configuration
    debug: bool = False

    # Execution configuration with defaults
    # Keep BaseSettings' numeric environment parsing; explicit root/YAML values
    # are checked through the strict nested model in __new__.
    concurrency_mode: Literal["conservative", "adaptive", "fixed"] = "conservative"
    initial_io_oversubscription: Optional[float] = Field(default=None, gt=0.0, le=64.0)
    minimum_collector_operations: int = Field(default=1, gt=0, le=4096)
    maximum_collector_operations: Optional[int] = Field(default=None, gt=0, le=4096)
    max_concurrent_duts: Optional[int] = Field(default=None, gt=0)
    max_concurrent_collectors_per_dut: int = Field(
        default=DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT, gt=0
    )
    timeout: int = 300
    retry_count: int = 3

    # Parallelization configuration
    execution_scheduler: str = "per_dut"
    PARALLEL_DUT_SEQUENTIAL_COLLECTORS: bool = True
    SERVICE_GROUPED_SEQUENTIAL_COLLECTORS: bool = True

    # Global Directory and Prefix Fields
    TASK_ID_PREFIX: str = ""  # Empty by default, only used if user specifies
    TOOL_TEMP_DIR: str = "/tmp"

    # Global I2C overrides for spreadsheet/baseboard defaults
    i2c_config: Dict[str, Any] = Field(default_factory=dict)

    # v2.1 accepted this per-DUT transport setting at the tool root. Retain it
    # only as an input-boundary compatibility source; collection projects it
    # onto DUTs which do not define their own value.
    ipmi_cipher: Optional[str] = None

    # Pagination configuration
    # A finite default prevents an endpoint from emitting distinct next links
    # forever. Reaching the limit is surfaced as Partial rather than success.
    max_pagination_pages: int = Field(default=DEFAULT_MAX_PAGINATION_PAGES, gt=0)
    max_duplicate_url_retries: int = (
        3  # Maximum consecutive duplicate URLs before stopping pagination
    )
    # Logging configuration with defaults
    log_level: Annotated[str, pydantic.BeforeValidator(_normalize_log_level)] = "INFO"
    log_format: Annotated[str, pydantic.BeforeValidator(_normalize_log_format)] = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Output configuration with defaults
    output_directory: str = "/tmp/nvdebug"
    report_format: Literal["spa", "legacy", "both"] = "spa"
    skip_zip_split: bool = False

    @model_validator(mode="after")
    def project_nested_execution_scheduler(self) -> "Config":
        """
        Project an explicitly configured nested scheduler to its canonical field.

        The implementation uses current instance state to project an explicitly
        configured nested scheduler to its canonical field.

        Returns:
            The validated ``self``.
        """
        for section_name in ("execution_config", "execution"):
            section = getattr(self, section_name, None)
            fields_set = getattr(section, "model_fields_set", set())
            if section is not None and "scheduler" in fields_set:
                object.__setattr__(self, "execution_scheduler", section.scheduler)
        return self

    def __init__(self, **values: Any) -> None:
        """
        Preserve caller-provided keys before BaseSettings adds environment values.

        The initializer records ``_yaml_fields`` for later operations and
        establishes the instance invariants before any public method runs. If
        the function cannot preserve caller-provided keys before BaseSettings
        adds environment values, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            values: Additional named values forwarded without changing their
                keys.

        Raises:
            pydantic.ValidationError: If input or state violates constraints
                required to preserve caller-provided keys before BaseSettings
                adds environment values.
            ValueError: If expand_fallback_mode conflicts with
                EXPAND_FALLBACK_MODE.
        """

        try:
            _reject_conflicting_baseboard_aliases(values)
        except ValueError as error:
            raise pydantic.ValidationError.from_exception_data(
                self.__class__.__name__,
                [
                    {
                        "type": "value_error",
                        "loc": (),
                        "input": values,
                        "ctx": {"error": error},
                    }
                ],
            ) from error
        _reject_conflicting_execution_scheduler_aliases(values)
        yaml_fields = set(values)
        normalized_values = dict(values)
        missing_expand_mode = object()
        contracted_expand_mode = normalized_values.pop(
            "expand_fallback_mode", missing_expand_mode
        )
        if contracted_expand_mode is not missing_expand_mode:
            runtime_expand_mode = normalized_values.get(
                "EXPAND_FALLBACK_MODE", missing_expand_mode
            )
            if (
                runtime_expand_mode is not missing_expand_mode
                and runtime_expand_mode != contracted_expand_mode
            ):
                raise ValueError(
                    "expand_fallback_mode conflicts with EXPAND_FALLBACK_MODE"
                )
            # BaseSettings is intentionally case-insensitive for documented
            # environment variables.  Pydantic-settings 2.15 therefore folds
            # these two accepted YAML spellings onto the uppercase runtime
            # field before model validators run.  Canonicalize the raw init
            # layer explicitly, then restore the contracted field below.
            normalized_values["EXPAND_FALLBACK_MODE"] = contracted_expand_mode

        super().__init__(**_normalize_preflight_aliases(normalized_values))
        self._yaml_fields = yaml_fields
        if contracted_expand_mode is not missing_expand_mode:
            object.__setattr__(self, "expand_fallback_mode", contracted_expand_mode)
            self.__pydantic_fields_set__.add("expand_fallback_mode")
            if "EXPAND_FALLBACK_MODE" not in yaml_fields:
                self.__pydantic_fields_set__.discard("EXPAND_FALLBACK_MODE")

    def __setattr__(self, name: str, value: Any) -> None:
        """
        Reject conflicting expand aliases before assignment mutates state.

        Validate the mutable alias pair before delegating to Pydantic so a
        rejected assignment cannot leave the model in a contradictory state.

        Args:
            name: Attribute name requested by the caller.
            value: Candidate value for the attribute.

        Raises:
            ValueError: If the assignment is null or conflicts with the other
                explicitly configured expand fallback alias.
        """

        fields_set = getattr(self, "__pydantic_fields_set__", set())
        if name == "expand_fallback_mode" and fields_set:
            if value is None:
                raise ValueError("expand_fallback_mode cannot be null")
            if (
                "EXPAND_FALLBACK_MODE" in fields_set
                and getattr(self, "EXPAND_FALLBACK_MODE", None) != value
            ):
                raise ValueError(
                    "expand_fallback_mode conflicts with EXPAND_FALLBACK_MODE"
                )
        elif (
            name == "EXPAND_FALLBACK_MODE"
            and "expand_fallback_mode" in fields_set
            and getattr(self, "expand_fallback_mode", None) is not None
            and getattr(self, "expand_fallback_mode") != value
        ):
            raise ValueError("EXPAND_FALLBACK_MODE conflicts with expand_fallback_mode")
        super().__setattr__(name, value)

    @model_validator(mode="after")
    def project_expand_level(self) -> "Config":
        """
        Fan out the contracted compact spelling to all runtime fields.

        Avoid recursive assignment validation while keeping subsequent
        ``expand_level`` assignments safe.

        Returns:
            A ``Config`` representing project expand level.

        Raises:
            ValueError: If expand_level cannot be null; or expand_level
                conflicts with ``field_name``.
        """

        if "expand_level" not in self.model_fields_set:
            return self
        if self.expand_level is None:
            raise ValueError("expand_level cannot be null")

        expand_fields = (
            "EXPAND_QUERY_CHASSIS_LEVEL",
            "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL",
            "EXPAND_QUERY_MANAGER_LEVEL",
            "EXPAND_QUERY_SYSTEM_LEVEL",
        )
        for field_name in expand_fields:
            if (
                field_name in self.model_fields_set
                and getattr(self, field_name) != self.expand_level
            ):
                raise ValueError(f"expand_level conflicts with {field_name}")
        for field_name in expand_fields:
            # Avoid recursive assignment validation while keeping subsequent
            # ``expand_level`` assignments safe.
            object.__setattr__(self, field_name, self.expand_level)
        return self

    @model_validator(mode="before")
    @classmethod
    def validate_legacy_fields(cls, values: Any) -> Any:
        """
        Convert legacy fields to new format.

        Baseboard mapping - handle precedence: baseboard > TargetBaseboard If
        baseboard is not set but TargetBaseboard is, use TargetBaseboard.

        Args:
            values: Values object whose ``get``, ``lower``, and ``setdefault``
                state is read while performing legacy fields to new format.

        Returns:
            The validated ``values``.

        Raises:
            ValueError: If invalid execution_scheduler value ``scheduler``;
                expected 'per_dut' or 'legacy_global'; ``root_name`` conflicts
                with streaming.``nested_name``; or logSanitization conflicts
                with sanitization.``nested_name``.
        """
        if isinstance(values, dict):
            values = _normalize_config_archive_aliases(values)

            scheduler = (
                str(values.get("execution_scheduler", "per_dut")).strip().lower()
            )
            if scheduler not in {"per_dut", "legacy_global"}:
                raise ValueError(
                    "Invalid execution_scheduler value "
                    f"{scheduler!r}; expected 'per_dut' or 'legacy_global'"
                )
            values["execution_scheduler"] = scheduler

            # Baseboard mapping - handle precedence: baseboard > TargetBaseboard
            # If baseboard is not set but TargetBaseboard is, use TargetBaseboard
            if values.get("TargetBaseboard") and not values.get("baseboard"):
                values["baseboard"] = values["TargetBaseboard"].lower()
            # If both are present, baseboard takes precedence (no change needed)
            # If neither is present, that's fine - auto-detection will be used

            # Project explicitly supplied nested streaming aliases onto the
            # flat runtime fields. Empty nested sections must not promote model
            # defaults, and contradictory same-source aliases fail closed.
            streaming_section = values.get("streaming")
            if isinstance(streaming_section, dict):
                streaming_names = {
                    "only": "streaming_only",
                    "begin": "stream_begin",
                    "end": "stream_end",
                    "destination": "stream_destination",
                    "append": "append",
                    "rack_id": "rack_id",
                }
                for nested_name, root_name in streaming_names.items():
                    if nested_name not in streaming_section:
                        continue

                    root_value = values.get(root_name)
                    nested_value = streaming_section[nested_name]
                    if nested_name in {"only", "append"}:
                        root_value = _normalize_boolean_alias(root_value)
                        nested_value = _normalize_boolean_alias(nested_value)
                    if nested_name == "destination":
                        root_value = (
                            None if root_value is None else os.fspath(root_value)
                        )
                        nested_value = (
                            None if nested_value is None else os.fspath(nested_value)
                        )
                    if root_name in values and root_value != nested_value:
                        raise ValueError(
                            f"{root_name} conflicts with streaming.{nested_name}"
                        )
                    values.setdefault(root_name, streaming_section[nested_name])

            # Output settings
            if values.get("GENERATE_HTML_REPORTS") is not None:
                output_setting = values.get("output")
                if output_setting is None:
                    values["output"] = {
                        "generate_html": values["GENERATE_HTML_REPORTS"]
                    }
                elif isinstance(output_setting, dict):
                    output_setting["generate_html"] = values["GENERATE_HTML_REPORTS"]
                else:
                    # Handle already-initialized OutputConfig instances during assignment validation
                    output_setting.generate_html = values["GENERATE_HTML_REPORTS"]

            sanitization_setting = values.get("sanitization")
            if isinstance(sanitization_setting, dict) and "LogSanitization" in values:
                nested_enabled = None
                nested_name = None
                if "enabled" in sanitization_setting:
                    nested_enabled = _normalize_boolean_alias(
                        sanitization_setting["enabled"]
                    )
                    nested_name = "enabled"
                elif "skip" in sanitization_setting:
                    nested_enabled = (
                        None
                        if sanitization_setting["skip"] is None
                        else not _normalize_boolean_alias(sanitization_setting["skip"])
                    )
                    nested_name = "skip"

                if (
                    nested_name is not None
                    and _normalize_boolean_alias(values["LogSanitization"])
                    != nested_enabled
                ):
                    raise ValueError(
                        f"LogSanitization conflicts with sanitization.{nested_name}"
                    )

        return values

    @model_validator(mode="after")
    def project_expand_fallback_mode(self) -> "Config":
        """
        Project the contracted tool spelling onto the runtime field.

        The implementation uses current instance state to project the contracted
        tool spelling onto the runtime field. If the function cannot project the
        contracted tool spelling onto the runtime field, its exception reaches
        the caller instead of being converted into a successful result.

        Returns:
            A ``Config`` representing project expand fallback mode.

        Raises:
            ValueError: If expand_fallback_mode cannot be null; or
                expand_fallback_mode conflicts with EXPAND_FALLBACK_MODE.
        """

        if "expand_fallback_mode" not in self.model_fields_set:
            return self
        if self.expand_fallback_mode is None:
            raise ValueError("expand_fallback_mode cannot be null")
        if (
            "EXPAND_FALLBACK_MODE" in self.model_fields_set
            and self.EXPAND_FALLBACK_MODE != self.expand_fallback_mode
        ):
            raise ValueError("expand_fallback_mode conflicts with EXPAND_FALLBACK_MODE")
        object.__setattr__(self, "EXPAND_FALLBACK_MODE", self.expand_fallback_mode)
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Any,
        init_settings: Any,
        env_settings: Any,
        dotenv_settings: Any,
        file_secret_settings: Any,
    ) -> tuple[Any, ...]:
        """
        Return the settings customise sources.

        The implementation uses ``settings_cls``, ``init_settings``,
        ``env_settings``, ``dotenv_settings``, and ``file_secret_settings`` to
        produce the settings customise sources.

        Args:
            settings_cls: Settings cls governing settings customise sources.
            init_settings: Init settings governing settings customise sources.
            env_settings: Environment settings governing settings customise
                sources.
            dotenv_settings: Dotenv configuration settings governing settings
                customise sources.
            file_secret_settings: Sensitive value supplied through the approved
                input boundary and never logged.

        Returns:
            A tuple containing ``init settings``, ``filtered config settings
            source``, ``filtered config settings source``, and ``file secret
            settings`` in that order.
        """
        del settings_cls
        return (
            init_settings,
            _FilteredConfigSettingsSource(
                env_settings,
                init_settings.init_kwargs,
            ),
            _FilteredConfigSettingsSource(
                dotenv_settings,
                init_settings.init_kwargs,
            ),
            file_secret_settings,
        )

    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> "Config":
        """
        Load configuration from file.

        Handle case where YAML file is mostly commented out and returns None.

        Args:
            file_path: filesystem location used as the file path for this
                operation.

        Returns:
            The validated ``config``.

        Raises:
            FileNotFoundError: If configuration file not found: ``file_path``.
            ValueError: If duts in tool configuration is deprecated and
                unsupported; define targets with --dut-config; malformed YAML
                (Invalid YAML) in configuration file: ``error_msg``; error
                loading configuration: ``e``; or error loading configuration:
                unknown ``label`` ``rendered_paths``.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        unknown_key_paths: Optional[List[str]] = None
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = load_yaml_strict(f)
                yaml_paths = _mapping_paths(data)
                if isinstance(data, dict):
                    _reject_conflicting_baseboard_aliases(data)
                    modern_present = "baseboard" in data
                    legacy_present = "TargetBaseboard" in data
                    if not modern_present and legacy_present:
                        data = dict(data)
                        legacy_value = data["TargetBaseboard"]
                        data["baseboard"] = (
                            legacy_value.lower()
                            if isinstance(legacy_value, str)
                            else legacy_value
                        )

            # Handle case where YAML file is mostly commented out and returns None
            if data is None:
                data = {}
            if isinstance(data, dict) and "duts" in data:
                raise ValueError(
                    "duts in tool configuration is deprecated and unsupported; "
                    "define targets with --dut-config"
                )

            if isinstance(data, dict):
                _reject_conflicting_redfish_session_holders(data)

            try:
                config = cls(**data)
            except pydantic.ValidationError as e:
                unknown_key_paths = _extra_forbidden_config_paths(e)
                if unknown_key_paths is None:
                    raise
            else:
                config._yaml_paths = yaml_paths
                return config
        except yaml.YAMLError as e:
            from .utils.yaml_manager import YAMLManager

            error_msg = YAMLManager._format_yaml_error(e)
            raise ValueError(
                f"Malformed YAML (Invalid YAML) in configuration file: {error_msg}"
            )
        except Exception as e:
            raise ValueError(f"Error loading configuration: {e}")

        # Raise after leaving the validation handler so the value-bearing
        # Pydantic exception is not retained as context on this safe diagnostic.
        assert unknown_key_paths is not None
        label = "key" if len(unknown_key_paths) == 1 else "keys"
        rendered_paths = ", ".join(repr(path) for path in unknown_key_paths)
        raise ValueError(
            f"Error loading configuration: unknown {label} {rendered_paths}"
        )

    @model_validator(mode="before")
    @classmethod
    def validate_report_skip_aliases(cls, values: Any) -> Any:
        """
        Validate report aliases before legacy projection can overwrite them.

        After applying local validation, the function forwards ``values`` to
        ``_validate_report_skip_aliases`` and preserves its return and exception
        contract. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Args:
            values: Values consumed while the function attempts to validate
                report aliases before legacy projection can overwrite them.

        Returns:
            The report skip aliases value selected by the operation.
        """
        return _validate_report_skip_aliases(values)


Config.__init__ = _validate_populated_alias_conflicts_on_init(Config.__init__)


def load_config(
    config_file: Optional[Path] = None,
    baseboard: Optional[str] = None,
    collection_level: Optional[str] = None,
) -> Config:
    """
    Load configuration with optional overrides.

    The implementation uses ``config_file``, ``baseboard``, and
    ``collection_level`` to load configuration with optional overrides. Parsing
    or I/O must finish before the validated representation is made available to
    the caller.

    Args:
        config_file: Optional filesystem location used as the config file for
            this operation.
        baseboard: Optional baseboard; ``None`` selects the function's default
            behavior.
        collection_level: Optional collection level; ``None`` selects the
            function's default behavior.

    Returns:
        The validated ``config``.
    """
    # Load configuration
    if config_file and config_file.exists():
        config = Config.from_file(config_file)
    else:
        config = Config()
        config._yaml_paths = set()

    # Apply overrides
    if baseboard:
        config.baseboard = baseboard
    if collection_level:
        config.collection_level = CollectionLevel(collection_level)

    return config


def _nested_config_model(annotation: Any) -> Optional[type[BaseModel]]:
    """
    Return the nested Pydantic model, if one is present in an annotation.

    The implementation uses ``annotation`` to produce the nested Pydantic model,
    if one is present in an annotation.

    Args:
        annotation: Entries supplied as ``annotation`` and processed in
            caller-provided order.

    Returns:
        The validated ``candidate``, or ``None`` when no value qualifies.
    """

    for candidate in (annotation, *getattr(annotation, "__args__", ())):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
    return None


def _unknown_config_paths(
    values: Dict[str, Any],
    model: type[BaseModel],
    prefix: str = "",
    allow_unknown: bool = False,
) -> List[str]:
    """
    Return unknown paths without changing the model's global extra policy.

    The implementation uses ``values``, ``model``, ``prefix``, and
    ``allow_unknown`` to produce unknown paths without changing the model's
    global extra policy.

    Args:
        values: Mapping supplying fields for unknown paths without changing the
            model's global extra policy.
        model: Model object whose ``get`` and ``model_fields`` state is read
            while performing unknown paths without changing the model's global
            extra policy.
        prefix: Text supplied as prefix in the format accepted by this function.
        allow_unknown: Whether allow unknown is enabled or required for this
            operation.

    Returns:
        The validated ``unknown``.
    """

    unknown: List[str] = []
    for key, child in values.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        field = model.model_fields.get(key)
        if field is None:
            if not allow_unknown:
                unknown.append(path)
            continue
        nested_model = _nested_config_model(field.annotation)
        if nested_model is not None and isinstance(child, dict):
            unknown.extend(_unknown_config_paths(child, nested_model, path))
    return unknown


def _validate_referenced_tool_config(values: Dict[str, Any]) -> None:
    """
    Validate one ConfigFileToUse document before projecting any fields.

    Linked documents accept the union of strict tool fields and DUT projection
    fields. Validate each namespace with its owning model while refusing any
    root key which belongs to neither surface.

    Args:
        values: Mapping supplying fields for one ConfigFileToUse document before
            projecting any fields.

    Raises:
        ValueError: If duts in ConfigFileToUse is deprecated; define targets
            with --dut-config; or the supplied input cannot be used to validate
            one ConfigFileToUse document before projecting any fields.
    """

    if "duts" in values:
        raise ValueError(
            "duts in ConfigFileToUse is deprecated; define targets with --dut-config"
        )

    # Linked documents accept the union of strict tool fields and DUT projection
    # fields. Validate each namespace with its owning model while refusing any
    # root key which belongs to neither surface.
    tool_fields = set(Config.model_fields)
    dut_fields = set(DUTConfig.model_fields) - {"name"}
    unknown = sorted(str(key) for key in values if key not in tool_fields | dut_fields)
    if unknown:
        raise ValueError(f"unknown key '{unknown[0]}' in ConfigFileToUse")

    tool_values = {key: value for key, value in values.items() if key in tool_fields}
    public_tool_values = {
        key: value for key, value in tool_values.items() if key in Config.model_fields
    }
    unknown = sorted(_unknown_config_paths(public_tool_values, Config))
    if unknown:
        raise ValueError(f"unknown key '{unknown[0]}' in ConfigFileToUse")

    execution_values = {
        field_name: values[field_name]
        for field_name in (
            "concurrency_mode",
            "initial_io_oversubscription",
            "minimum_collector_operations",
            "maximum_collector_operations",
            "max_concurrent_duts",
            "max_concurrent_collectors_per_dut",
        )
        if field_name in values
    }
    if execution_values:
        ExecutionSectionConfig.model_validate(execution_values)

    Config(**copy.deepcopy(tool_values))

    dut_only_values = {
        key: value
        for key, value in values.items()
        if key in dut_fields and key not in tool_fields
    }
    if dut_only_values:
        DUTConfig(name="linked-config", **copy.deepcopy(dut_only_values))


def _project_referenced_dut_values(values: Dict[Any, Any]) -> Dict[Any, Any]:
    """
    Project only DUT-owned fields from one validated linked document.

    The implementation uses ``values`` to project only DUT-owned fields from one
    validated linked document.

    Args:
        values: Mapping supplying fields for project only DUT-owned fields from
            one validated linked document.

    Returns:
        A mapping containing project referenced DUT values.
    """

    accepted = set(DUTConfig.model_fields) - {"name"}
    return {key: value for key, value in values.items() if key in accepted}


def load_dut_config(
    file_path: Union[str, Path], quiet_mode: bool = False
) -> List[DUTConfig]:
    """
    Load DUT configuration from file with proper DUT_Defaults handling.

    The implementation uses ``file_path`` and ``quiet_mode`` to load DUT
    configuration from file with proper DUT_Defaults handling. Parsing or I/O
    must finish before the validated representation is made available to the
    caller. Filesystem effects remain confined to the caller-selected paths and
    the owning resource lifecycle. If the function cannot load DUT configuration
    from file with proper DUT_Defaults handling, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        file_path: filesystem location used as the file path for this operation.
        quiet_mode: Whether quiet mode is enabled or required for this
            operation.

    Returns:
        The DUT config returned in operation-defined order.

    Raises:
        FileNotFoundError: If DUT configuration file not found: ``file_path``;
            or configFileToUse '``config_file_path``' for DUT '``name``' does
            not exist. ValueError: If invalid DUT configuration content: The
            file contains only text '``data``' but DUT configuration files must
            contain YAML mappings (key-value pairs). Please ensure your DUT
            config file contains proper YAML structure with DUT definitions;
            invalid DUT configuration format: The file contains a list but DUT
            configuration files must contain YAML mappings (key-value pairs).
            Please restructure your config file to use dictionary format with
            DUT definitions; invalid DUT configuration format: Expected YAML
            mapping (dictionary) but found ``__name__``. DUT configuration files
            must contain key-value pairs defining DUTs and their settings; or
            DUT must contain a YAML mapping; or another input invariant is
            violated.
        BaseException: If a delegated failure occurs while the function attempts
            to load DUT configuration from file with proper DUT_Defaults
            handling.
    """

    def overlay_layer_aliases(
        merged_values: Dict[str, Any], layer_values: Dict[str, Any]
    ) -> None:
        """
        Reapply one source layer across equivalent modern/legacy fields.

        The implementation uses ``merged_values`` and ``layer_values`` to
        reapply one source layer across equivalent modern/legacy fields.

        Args:
            merged_values: Mapping supplying fields for reapply one source layer
                across equivalent modern/legacy fields.
            layer_values: Mapping supplying fields for reapply one source layer
                across equivalent modern/legacy fields.
        """

        projected = sync_legacy_fields({**layer_values})
        for modern_field, legacy_field in LEGACY_FIELD_MAPPINGS.items():
            if modern_field in layer_values or legacy_field in layer_values:
                merged_values[modern_field] = projected[modern_field]
                merged_values[legacy_field] = projected[legacy_field]

    def build_dut_config(
        source_values: Dict[str, Any],
        *,
        referenced_config_data: Optional[Dict[Any, Any]] = None,
    ) -> DUTConfig:
        """
        Validate one DUT while retaining source-presence provenance.

        Pydantic validators materialize compatibility aliases and defaults, but
        those derived fields must not become new configuration-precedence
        winners. The helper therefore restores the set of fields that were
        actually present in this source layer after model validation.

        Transport-trust values the validator derives from an operator-authored
        legacy key are the one deliberate exception. ``SSH_TUNNEL_OPTIONS`` is
        the only supported spelling in older documents, so a host-key policy or
        known-hosts path inferred from it is operator intent and keeps
        source-present status; otherwise the DUT merge discards it and the
        transport falls back to the insecure default.

        Args:
            source_values: Authored DUT fields from one configuration source.
            referenced_config_data: Optional immutable-by-convention snapshot
                of the already validated ``ConfigFileToUse`` document.

        Returns:
            A validated DUT model whose field-set metadata names the fields
            supplied by the selected source plus any transport-trust field the
            validator derived from a source-present legacy key.
        """

        source_fields = set(source_values).intersection(DUTConfig.model_fields)
        dut = DUTConfig(**source_values)
        if "SSH_TUNNEL_OPTIONS" in source_fields:
            # A value the validator derived from an operator-authored legacy
            # key is operator intent, not a materialized model default. Restore
            # its source-present status so the DUT merge cannot discard a
            # verifying host-key choice expressed only in the legacy spelling
            # and silently fall back to the insecure transport default. The
            # legacy inference already rejects ambiguous forms, so only a
            # well-formed derivation reaches this point.
            for derived_field in (
                "ssh_host_key_policy",
                "ssh_known_hosts_file",
            ):
                if derived_field in source_fields:
                    continue
                if (
                    getattr(dut, derived_field, None)
                    != DUTConfig.model_fields[derived_field].default
                ):
                    source_fields.add(derived_field)
        # Before validators project compatibility aliases and runtime defaults
        # into their returned mapping. Pydantic otherwise reports those
        # generated keys as source-present, which can turn an omitted secure
        # transport choice into explicit plaintext intent.
        object.__setattr__(dut, "__pydantic_fields_set__", source_fields)
        if referenced_config_data is not None:
            object.__setattr__(
                dut,
                "_referenced_config_data",
                copy.deepcopy(referenced_config_data),
            )
        return dut

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"DUT configuration file not found: {file_path}")

    rejected_embedded_duts = False
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = _normalize_collector_skip_document(load_yaml_strict(f))

        # Handle fully commented out YAML files (yaml.safe_load returns None)
        if data is None:
            data = {}

        if not isinstance(data, dict):
            # Provide more specific error message based on the actual data type
            if isinstance(data, str):
                raise ValueError(
                    f"Invalid DUT configuration content: The file contains only text '{data}' "
                    f"but DUT configuration files must contain YAML mappings (key-value pairs).\n"
                    f"Please ensure your DUT config file contains proper YAML structure with DUT definitions."
                )
            elif isinstance(data, list):
                raise ValueError(
                    "Invalid DUT configuration format: The file contains a list but DUT configuration files "
                    "must contain YAML mappings (key-value pairs).\n"
                    "Please restructure your config file to use dictionary format with DUT definitions."
                )
            else:
                raise ValueError(
                    f"Invalid DUT configuration format: Expected YAML mapping (dictionary) but found {type(data).__name__}.\n"
                    f"DUT configuration files must contain key-value pairs defining DUTs and their settings."
                )

        if (
            "DUT" in data
            and len([key for key in data if key != "DUT_Defaults"]) == 1
            and not isinstance(data["DUT"], dict)
        ):
            raise ValueError("DUT must contain a YAML mapping")

        # Extract defaults if they exist
        defaults = data.get("DUT_Defaults", {})
        if "DUT_Defaults" in data and not isinstance(defaults, dict):
            raise ValueError("DUT_Defaults must be a mapping")
        defaults = _normalize_execution_mode_source_layer(defaults)

        legacy_single_dut = (
            "DUT" in data and len([key for key in data if key != "DUT_Defaults"]) == 1
        )
        legacy_uses_linked_config = legacy_single_dut and bool(
            merge_dut_config_layers(defaults, data["DUT"]).get("ConfigFileToUse")
        )

        # Preserve the historical fast path when no referenced document needs
        # processing. Linked legacy envelopes use the same validated path as
        # named DUTs so the envelope spelling cannot change source precedence.
        if legacy_single_dut and not legacy_uses_linked_config:
            # Legacy single DUT format
            direct_values = _normalize_execution_mode_source_layer(data["DUT"])
            dut_data = merge_dut_config_layers(defaults, direct_values)
            dut_data["name"] = "DUT"
            overlay_layer_aliases(dut_data, defaults)
            overlay_layer_aliases(dut_data, direct_values)
            return [build_dut_config(dut_data)]
        else:
            # Multi-DUT format
            duts = []
            for name, dut_data in data.items():
                if name != "DUT_Defaults":
                    if dut_data is None:
                        dut_data = {}
                    if not isinstance(dut_data, dict):
                        raise ValueError(
                            f"Invalid DUT configuration for '{name}': expected a YAML mapping"
                        )
                    direct_values = _normalize_execution_mode_source_layer(dut_data)

                    # Merge defaults with individual DUT data first so
                    # ConfigFileToUse can be inherited from DUT_Defaults.
                    merged_data = merge_dut_config_layers(defaults, direct_values)
                    referenced_config_data: Optional[Dict[Any, Any]] = None

                    config_file_path = merged_data.get("ConfigFileToUse")
                    overlay_layer_aliases(merged_data, defaults)
                    overlay_layer_aliases(merged_data, direct_values)
                    if config_file_path:
                        dut_layer_data = merged_data.copy()
                        resolved_config_file = Path(str(config_file_path))
                        if not resolved_config_file.is_absolute():
                            resolved_config_file = (
                                file_path.parent / resolved_config_file
                            )
                        resolved_config_file = resolved_config_file.resolve()
                        merged_data["ConfigFileToUse"] = str(resolved_config_file)

                        try:
                            if resolved_config_file.exists():
                                with open(
                                    resolved_config_file, "r", encoding="utf-8"
                                ) as f:
                                    config_data = load_yaml_strict(f) or {}

                                if not isinstance(config_data, dict):
                                    raise ValueError(
                                        "referenced config must contain a YAML mapping"
                                    )
                                if _has_embedded_tool_duts(config_data):
                                    # Do not retain the rejected value in the
                                    # sentinel traceback or later public error.
                                    config_data = None
                                    raise _DeprecatedEmbeddedDutsError
                                _validate_referenced_tool_config(config_data)
                                referenced_config_data = config_data
                                linked_values = _normalize_execution_mode_source_layer(
                                    _project_referenced_dut_values(config_data)
                                )
                                projected_tool_values = project_linked_tool_dut_values(
                                    config_data
                                )

                                # Repointing the proxy host in a higher layer
                                # must not carry credentials paired with the
                                # linked document's different bastion. Treat the
                                # host selector as owner of the complete proxy
                                # credential set.
                                if any(
                                    selector in layer
                                    for layer in (defaults, direct_values)
                                    for selector in (
                                        "ssh_proxy_host",
                                        "SSH_PROXY_HOST",
                                    )
                                ):
                                    for credential_field in (
                                        "ssh_proxy_user",
                                        "SSH_PROXY_USERNAME",
                                        "ssh_proxy_pass",
                                        "SSH_PROXY_PASSWORD",
                                        "ssh_proxy_key_path",
                                        "SSH_PROXY_KEY_PATH",
                                        "ssh_proxy_passwordless",
                                        "SSH_PROXY_PASSWORDLESS",
                                    ):
                                        projected_tool_values.pop(
                                            credential_field, None
                                        )
                                        linked_values.pop(credential_field, None)

                                # A higher explicit policy selector owns the
                                # complete trust policy. Keep the linked server
                                # name as an independent overlay, but leave the
                                # linked policy document available to the
                                # runtime resolver for deprecated boolean
                                # fallback semantics.
                                if any(
                                    selector in layer
                                    for layer in (defaults, direct_values)
                                    for selector in (
                                        "bmc_rf_tls_mode",
                                        "bmc_rf_verify_ssl",
                                    )
                                ):
                                    for policy_field in (
                                        "bmc_rf_tls_mode",
                                        "bmc_rf_ca_file",
                                        "bmc_rf_fingerprint_sha256",
                                        "bmc_rf_verify_ssl",
                                    ):
                                        projected_tool_values.pop(policy_field, None)
                                        linked_values.pop(policy_field, None)

                                linked_values = merge_dut_config_layers(
                                    projected_tool_values, linked_values
                                )
                                overlay_layer_aliases(linked_values, config_data)

                                # Effective precedence after the direct/default
                                # overlay below is linked < defaults < direct.
                                merged_data = merge_dut_config_layers(
                                    linked_values, defaults, direct_values
                                )
                                merged_data["ConfigFileToUse"] = str(
                                    resolved_config_file
                                )
                            else:
                                raise FileNotFoundError(
                                    f"ConfigFileToUse '{config_file_path}' for DUT "
                                    f"'{name}' does not exist"
                                )
                        except _DeprecatedEmbeddedDutsError:
                            raise
                        except yaml.YAMLError as e:
                            from .utils.yaml_manager import YAMLManager

                            error_msg = YAMLManager._format_yaml_error(e)
                            raise ValueError(
                                f"ConfigFileToUse '{config_file_path}' for DUT "
                                f"'{name}' contains malformed YAML: {error_msg}"
                            ) from e
                        except Exception as e:
                            raise ValueError(
                                f"Invalid ConfigFileToUse '{config_file_path}' "
                                f"for DUT '{name}': {e}"
                            ) from e

                        # Override the intermediate merge above; effective
                        # precedence is linked < DUT defaults < direct DUT.
                        merged_data.update(dut_layer_data)
                        merged_data["ConfigFileToUse"] = str(resolved_config_file)

                    merged_data["name"] = name

                    # Use baseboard from defaults if not specified in individual DUT
                    if "baseboard" not in merged_data and "baseboard" in defaults:
                        merged_data["baseboard"] = defaults["baseboard"]

                    # If DUT has ConfigFileToUse but no baseboard, try to load baseboard from the config file
                    if (
                        referenced_config_data is not None
                        and merged_data.get("ConfigFileToUse")
                        and "baseboard" not in merged_data
                    ):
                        config_file_path = merged_data["ConfigFileToUse"]
                        # Reuse the already validated snapshot rather than
                        # reopening a mutable linked pathname. Check both
                        # accepted tool-config spellings and normalize the
                        # legacy spelling at the same boundary as Config does.
                        config_data = referenced_config_data or {}
                        baseboard_value = config_data.get("baseboard")
                        if baseboard_value is None:
                            legacy_baseboard = config_data.get("TargetBaseboard")
                            baseboard_value = (
                                legacy_baseboard.lower()
                                if isinstance(legacy_baseboard, str)
                                else legacy_baseboard
                            )
                        if baseboard_value is not None:
                            merged_data["baseboard"] = baseboard_value
                            if not quiet_mode:
                                print(
                                    _sanitize_print_message(
                                        f"Loaded baseboard '{baseboard_value}' from config file '{config_file_path}' for DUT '{name}'"
                                    )
                                )
                        else:
                            if not quiet_mode:
                                print(
                                    _sanitize_print_message(
                                        f"Warning: No baseboard found in config file '{config_file_path}' for DUT '{name}'"
                                    )
                                )

                    # Note: If no baseboard is specified after all attempts, auto-detection will handle it

                    duts.append(
                        build_dut_config(
                            merged_data,
                            referenced_config_data=referenced_config_data,
                        )
                    )

            if not duts:
                # If quiet_mode is enabled, return empty list for fallback to CLI mode
                # Otherwise, raise an error to inform the user
                if quiet_mode:
                    return []
                else:
                    raise ValueError(
                        "No DUT configurations found in the file. "
                        "The DUT config file appears to be empty or fully commented out. "
                        "Please either:\n"
                        "  • Define at least one DUT in the config file, or\n"
                        "  • Use CLI credentials instead of a config file, or\n"
                        "  • Use --local flag if running locally"
                    )

            return duts

    except _DeprecatedEmbeddedDutsError:
        rejected_embedded_duts = True
    except yaml.YAMLError as e:
        from .utils.yaml_manager import YAMLManager

        error_msg = YAMLManager._format_yaml_error(e)
        raise ValueError(
            f"Malformed YAML (Invalid YAML) in DUT configuration file: {error_msg}"
        )
    except Exception as e:
        raise ValueError(f"Error loading DUT configuration: {e}")

    if rejected_embedded_duts:
        raise ValueError(
            f"Error loading DUT configuration: {_DEPRECATED_EMBEDDED_DUTS_MESSAGE}"
        )


CatalogSpreadsheetSource = Union[str, Path, CatalogSnapshot]


def get_available_baseboards(
    spreadsheet_path: CatalogSpreadsheetSource,
) -> List[str]:
    """
    Get available baseboards from the collector spreadsheet (Excel only).

    Retain path compatibility for callers that have not captured the
    authoritative catalog bytes yet.

    Args:
        spreadsheet_path: filesystem location used as the spreadsheet path for
            this operation.

    Returns:
        The validated ``baseboards``.

    Raises:
        ValueError: If only Excel files (.xlsx, .xls) are supported, got:
            ``suffix``; or error reading baseboards from spreadsheet: ``e``.
    """
    try:
        if isinstance(spreadsheet_path, CatalogSnapshot):
            df = spreadsheet_path.read_excel(sheet_name="Log Collection Catalog")
        else:
            catalog_path = Path(spreadsheet_path)
            if catalog_path.suffix.lower() not in [".xlsx", ".xls"]:
                raise ValueError(
                    "Only Excel files (.xlsx, .xls) are supported, got: "
                    f"{catalog_path.suffix}"
                )

            # Retain path compatibility for callers that have not captured the
            # authoritative catalog bytes yet.
            df = excel_reader.read_excel(
                catalog_path, sheet_name="Log Collection Catalog"
            )

        # Find columns that start with various applicable prefixes
        baseboard_columns = []
        for col in df.columns:
            if any(
                col.startswith(prefix)
                for prefix in [
                    "applicable_for_",
                    "available_for_",
                    "Applicable for",
                    "Available for",
                ]
            ):
                baseboard_columns.append(col)

        # Extract baseboard names from column names
        baseboards = []
        for col in baseboard_columns:
            # Remove various prefixes
            baseboard_name = col
            for prefix in [
                "applicable_for_",
                "available_for_",
                "Applicable for",
                "Available for",
            ]:
                if col.startswith(prefix):
                    baseboard_name = col.replace(prefix, "").strip().strip("\n")
                    break

            if baseboard_name:  # Only add if we found a valid name
                baseboards.append(baseboard_name)

        return baseboards
    except Exception as e:
        raise ValueError(f"Error reading baseboards from spreadsheet: {e}")


def validate_baseboard(
    baseboard: str,
    spreadsheet_path: Optional[CatalogSpreadsheetSource],
) -> bool:
    """
    Validate one physical or semantic baseboard selector from the catalog.

    Physical names come from applicability columns. Baseboard types, explicit
    groups, and platform node types come from the same captured configuration
    sheet through :class:`BaseboardManager`. Semantic selectors remain groups;
    validation never rewrites an ambiguous selector to one member platform.

    Args:
        baseboard: Operator-selected physical baseboard or semantic group.
        spreadsheet_path: Catalog path or immutable captured catalog snapshot.

    Returns:
        ``True`` when the selector is declared by the selected catalog;
        otherwise ``False``.
    """
    if not spreadsheet_path:
        return False

    try:
        available_baseboards = get_available_baseboards(spreadsheet_path)
        normalized = baseboard.casefold()
        if normalized in {name.casefold() for name in available_baseboards}:
            return True

        # Import lazily so configuration-model initialization does not create a
        # module cycle. The manager reads only the already selected catalog.
        from .core.baseboard_manager import BaseboardManager

        manager = (
            BaseboardManager(catalog_snapshot=spreadsheet_path)
            if isinstance(spreadsheet_path, CatalogSnapshot)
            else BaseboardManager(spreadsheet_path=spreadsheet_path)
        )
        semantic_selectors = manager.get_all_baseboard_types()
        return normalized in {
            selector.casefold()
            for selector in semantic_selectors
            if isinstance(selector, str)
        }
    except Exception:
        return False


def auto_assign_config_file_to_use(
    dut_config_file: Path, config_files: List[Optional[Path]]
) -> Path:
    """
    Return the auto assign config file to use.

    Find the first config file that has baseboard information.

    Args:
        dut_config_file: filesystem location used as the DUT config file for
            this operation.
        config_files: filesystem location used as the config files for this
            operation.

    Returns:
        The validated auto assign config file to use filesystem path.
    """
    # Read existing DUT config
    try:
        with open(dut_config_file, "r", encoding="utf-8") as f:
            dut_data = load_yaml_strict(f)
    except Exception as e:
        print(
            _sanitize_print_message(
                f"Warning: Could not read DUT config file '{dut_config_file}': {e}"
            )
        )
        return dut_config_file

    if not dut_data or not isinstance(dut_data, dict):
        return dut_config_file

    # Find the first config file that has baseboard information
    config_file_to_use = None
    for config_file in config_files:
        if config_file and config_file.exists():
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    config_data = load_yaml_strict(f)

                # Check for baseboard (new format) or TargetBaseboard (legacy)
                baseboard = config_data.get("baseboard") or config_data.get(
                    "TargetBaseboard"
                )
                if baseboard:
                    config_file_to_use = str(config_file)
                    print(
                        _sanitize_print_message(
                            f"Auto-detected baseboard '{baseboard}' from config file: {config_file}"
                        )
                    )
                    break
            except Exception as e:
                print(
                    _sanitize_print_message(
                        f"Warning: Could not read config file '{config_file}': {e}"
                    )
                )
                continue

    # If we found a config file, assign it to DUTs that need it
    if config_file_to_use:
        modified = False

        defaults = dut_data.get("DUT_Defaults", {}) or {}
        if not isinstance(defaults, dict):
            return dut_config_file

        # Check each DUT
        for dut_name, dut_config in dut_data.items():
            if dut_name != "DUT_Defaults" and isinstance(dut_config, dict):
                effective_dut = {**defaults, **dut_config}
                # ONLY assign if:
                # 1. Neither direct DUT nor DUT_Defaults supplies a baseboard.
                # 2. Neither direct DUT nor DUT_Defaults supplies ConfigFileToUse.
                if (
                    "baseboard" not in effective_dut
                    and "ConfigFileToUse" not in effective_dut
                ):
                    dut_config["ConfigFileToUse"] = config_file_to_use
                    modified = True
                    print(
                        _sanitize_print_message(
                            f"Auto-assigned ConfigFileToUse '{config_file_to_use}' to DUT '{dut_name}' (no baseboard or ConfigFileToUse defined)"
                        )
                    )

        # If we made changes, write to temporary file
        if modified:
            try:
                # Create temporary file in proper temp directory with unique name
                temp_fd, temp_path = tempfile.mkstemp(
                    prefix="dut_config_", suffix=".yaml", text=True
                )
                # Restrict permissions immediately for credential-containing file
                os.chmod(temp_path, 0o600)
                temp_file = Path(temp_path)

                # Write the modified config to the temp file
                with open(temp_file, "w", encoding="utf-8") as f:
                    yaml.dump(dut_data, f, default_flow_style=False, sort_keys=False)

                # Close the file descriptor (tempfile.mkstemp keeps it open)
                os.close(temp_fd)

                print(
                    _sanitize_print_message(
                        f"Created temporary DUT config file: {temp_file}"
                    )
                )
                return temp_file
            except Exception:
                print("Warning: Could not create temporary DUT config file")
                return dut_config_file

    return dut_config_file


def _normalize_logging_aliases(
    values: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Reconcile explicitly supplied flat and nested logging spellings.

    The implementation uses ``values`` to reconcile explicitly supplied flat and
    nested logging spellings. If the function cannot reconcile explicitly
    supplied flat and nested logging spellings, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        values: Mapping supplying fields for reconcile explicitly supplied flat
            and nested logging spellings.

    Returns:
        The validated ``normalized``.

    Raises:
        ValueError: If ``root_name`` conflicts with logging.``nested_name``.
    """

    normalized = dict(values)
    logging_section = normalized.get("logging")
    if not isinstance(logging_section, dict):
        logging_section = {}
    else:
        logging_section = dict(logging_section)
        normalized["logging"] = logging_section

    aliases = (
        ("log_level", "level", _normalize_log_level),
        ("log_format", "format", _normalize_log_format),
    )
    for root_name, nested_name, normalizer in aliases:
        root_present = root_name in normalized
        nested_present = nested_name in logging_section
        root_value = normalizer(normalized[root_name]) if root_present else None
        nested_value = (
            normalizer(logging_section[nested_name]) if nested_present else None
        )

        if root_present:
            normalized[root_name] = root_value
        if nested_present:
            logging_section[nested_name] = nested_value

        if nested_present and nested_value is None and root_present:
            raise ValueError(f"{root_name} conflicts with logging.{nested_name}")
        if nested_present and nested_value is not None:
            normalized[root_name] = nested_value

    return normalized


# Internal builds retain legacy model imports through a trusted package.  The
# public source tree has no provider-specific schema or field declarations.
