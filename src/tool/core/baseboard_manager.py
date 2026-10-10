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
Manage baseboard configuration and collector applicability.

The manager reads the generated spreadsheet catalog, resolves baseboard groups
and runtime profiles, and applies those authored relationships during collector
filtering. Spreadsheet data remains the sole platform source of truth.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..utils import excel_reader
from ..utils.ansible_mapping_profiles import (
    validate_ansible_baseboard_mapping_targets,
)
from ..utils.catalog_snapshot import CatalogSnapshot
from ..utils.redfish_diagnostic_capacity import (
    DIAGNOSTIC_CAPACITY_POOLS_KEY,
    validate_diagnostic_capacity_pools,
)
from ..utils.collector_workload_profile import (
    COLLECTOR_WORKLOAD_PROFILES_KEY,
    validate_collector_workload_profiles,
)
from ..utils.platform_detection_profile import (
    PLATFORM_DETECTION_PROFILE_KEY,
    validate_platform_detection_profile,
)
from ..utils.runtime_boundary_profile import (
    DEFAULT_RUNTIME_BOUNDARIES,
    RUNTIME_BOUNDARIES_KEY,
    RUNTIME_BOUNDARY_OVERRIDES_KEY,
    RUNTIME_BOUNDARY_PROFILE_KEY,
    RUNTIME_BOUNDARY_PROFILE_VERSION,
    resolve_runtime_boundaries,
    validate_runtime_boundary_overrides,
    validate_runtime_boundary_profile,
)
from .async_logger import AsyncSafeLogger


def _json_object_without_duplicate_keys(
    pairs: List[tuple[str, Any]],
) -> Dict[str, Any]:
    """
    Reject ambiguous JSON objects instead of silently keeping the last key.

    The implementation uses ``pairs`` to reject ambiguous JSON objects instead
    of silently keeping the last key. Every required invariant is checked before
    a successful value is returned; invalid input follows the function's
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


def reconcile_baseboard_node_type(
    baseboard_name: str,
    configured_node_type: Any,
    catalog_node_type: Any,
    *,
    configured_explicitly: bool,
) -> Optional[str]:
    """
    Reconcile one DUT node role with its concrete catalog baseboard.

    A source-explicit node role is authoritative only when it agrees with the
    selected concrete baseboard. A model default is not source evidence, so an
    implicit value is replaced by the catalog declaration. Baseboards without
    a catalog node-role declaration retain the established configuration
    behavior for compatibility.

    Args:
        baseboard_name: Concrete baseboard selected for the DUT.
        configured_node_type: Node role present after configuration precedence
            is resolved, or ``None`` when no layer supplied one.
        catalog_node_type: Node role declared by the concrete baseboard's
            ``platform_detection`` metadata, or ``None`` for a legacy board.
        configured_explicitly: Whether the winning configured role came from a
            source rather than a model default.

    Returns:
        The catalog spelling when a role is declared; otherwise the stripped
        configured value or ``None``.

    Raises:
        ValueError: If the catalog declaration is malformed, an explicit
            configured value is malformed, or the two declared roles conflict.
    """

    if not isinstance(baseboard_name, str) or not baseboard_name.strip():
        raise ValueError("baseboard name must be a non-empty string")
    if not isinstance(configured_explicitly, bool):
        raise ValueError("configured_explicitly must be boolean")

    if catalog_node_type is None:
        if configured_node_type is None:
            return None
        if not isinstance(configured_node_type, str):
            raise ValueError("configured NodeType must be a string")
        return configured_node_type.strip() or None

    if not isinstance(catalog_node_type, str) or not catalog_node_type.strip():
        raise ValueError(
            f"baseboard {baseboard_name!r} has an invalid catalog node_type"
        )
    expected = catalog_node_type.strip()

    if not configured_explicitly:
        return expected
    if not isinstance(configured_node_type, str) or not configured_node_type.strip():
        raise ValueError("explicit NodeType must be a non-empty string")
    configured = configured_node_type.strip()
    if configured.casefold() != expected.casefold():
        raise ValueError(
            f"NodeType {configured!r} is incompatible with baseboard "
            f"{baseboard_name!r}; the catalog declares {expected!r}"
        )
    return expected


class BaseboardManager:
    """
    Manages baseboard definitions and provides lookup functionality.

    Supports only spreadsheet-based configurations.

    The type coordinates ``drain_pending_logs``, ``_queue_runtime_log``,
    ``_validate_redfish_entity_defaults``,
    ``_has_spreadsheet_baseboard_definitions``, and ``_catalog_source_label``
    and retains the state those operations share between calls. Resource
    ownership remains inside the instance until the matching close, exit, or
    cleanup operation completes.
    """

    def __init__(
        self,
        spreadsheet_path: Optional[Union[str, Path]] = None,
        logger: Optional[AsyncSafeLogger] = None,
        catalog_snapshot: Optional[CatalogSnapshot] = None,
    ):
        """
        Initialize the BaseboardManager.

        The initializer records ``_pending_log_tasks``, ``ansible_mappings``,
        ``baseboard_groups``, ``baseboard_name_lookup``, and
        ``baseboard_type_lookup`` for later operations and establishes the
        instance invariants before any public method runs.

        Args:
            spreadsheet_path: Optional filesystem location used as the
                spreadsheet path for this operation.
            logger: Sanitized logger used for operator-visible diagnostics.
            catalog_snapshot: Optional catalog snapshot; ``None`` selects the
                function's default behavior.
        """
        self.baseboards: Dict[str, Any] = {}
        self.baseboard_types: Dict[str, str] = {}  # baseboard_name -> type
        self.baseboard_groups: Dict[str, List[str]] = (
            {}
        )  # group_name -> [baseboard_names]
        self.explicit_baseboard_groups: Dict[str, List[str]] = {}
        self.baseboard_name_lookup: Dict[str, str] = {}
        self.baseboard_type_lookup: Dict[str, str] = {}
        self.ansible_mappings: List[Dict[str, Any]] = []
        self.redfish_entity_defaults: Dict[str, Dict[str, List[str]]] = {}
        self.redfish_entity_defaults_configured = False
        self.platform_detection_profile: Optional[Dict[str, Any]] = None
        self.runtime_boundary_profile: Dict[str, Any] = {
            "version": RUNTIME_BOUNDARY_PROFILE_VERSION,
            "defaults": dict(DEFAULT_RUNTIME_BOUNDARIES),
        }
        self.logger = logger
        self._pending_log_tasks: List[asyncio.Task] = []

        catalog_source: Optional[Union[str, Path, CatalogSnapshot]] = (
            catalog_snapshot if catalog_snapshot is not None else spreadsheet_path
        )
        if catalog_source is not None:
            if self._has_spreadsheet_baseboard_definitions(catalog_source):
                self._load_from_spreadsheet(catalog_source)
            else:
                if self.logger:
                    self._pending_log_tasks.append(
                        asyncio.create_task(
                            self.logger.log_runtime(
                                "WARNING",
                                "BaseboardManager",
                                "No baseboard definitions found in spreadsheet: "
                                f"{self._catalog_source_label(catalog_source)}",
                            )
                        )
                    )
                # Initialize with empty baseboards if no definitions found
                self.baseboards = {}
        else:
            if self.logger:
                self._pending_log_tasks.append(
                    asyncio.create_task(
                        self.logger.log_runtime(
                            "WARNING",
                            "BaseboardManager",
                            "No spreadsheet path provided - initializing with empty baseboards",
                        )
                    )
                )
            self.baseboards = {}

    async def drain_pending_logs(self) -> None:
        """
        Await all pending log tasks to prevent resource leaks.

        The implementation uses current instance state to await all pending log
        tasks to prevent resource leaks. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        """
        if self._pending_log_tasks:
            await asyncio.gather(*self._pending_log_tasks, return_exceptions=True)
            self._pending_log_tasks.clear()

    async def __aenter__(self):
        """
        Enter the BaseboardManager context.

        Entering the scope acquires or validates its owned resources and returns
        the value used until the matching exit method completes cleanup. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Returns:
            The validated ``self``.
        """
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Exit the BaseboardManager context.

        Leaving the scope releases resources owned by the context while
        preserving the exception-propagation behavior declared by the
        context-manager protocol. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            exc_type: Exception type consumed while the function attempts to
                exit the BaseboardManager context.
            exc_val: Exception val consumed while the function attempts to exit
                the BaseboardManager context.
            exc_tb: Exception tb consumed while the function attempts to exit
                the BaseboardManager context.

        Returns:
            Whether the exit the BaseboardManager context operation succeeds.
        """
        await self.drain_pending_logs()
        return False

    def _queue_runtime_log(self, level: str, message: str) -> None:
        """
        Queue a loader diagnostic when construction happens in an event loop.

        The implementation uses ``level`` and ``message`` to queue a loader
        diagnostic when construction happens in an event loop.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        if not self.logger:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._pending_log_tasks.append(
            loop.create_task(
                self.logger.log_runtime(level, "BaseboardManager", message)
            )
        )

    @staticmethod
    def _validate_redfish_entity_defaults(
        value: Any,
    ) -> Dict[str, Dict[str, List[str]]]:
        """
        Validate and copy the spreadsheet's Redfish entity-pattern mapping.

        The implementation uses ``value`` to validate and copy the spreadsheet's
        Redfish entity-pattern mapping. Every required invariant is checked
        before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            value: Value object whose ``items`` state is read while performing
                and copy the spreadsheet's Redfish entity-pattern mapping.

        Returns:
            The validated ``normalized``.

        Raises:
            ValueError: If the redfish_entity_defaults are not a JSON object;
                the redfish_entity_defaults selectors are not non-empty strings;
                redfish_entity_defaults selectors must not have outer
                whitespace; or the redfish_entity_defaults[``selector``] is not
                an object; or another input invariant is violated.
        """
        if not isinstance(value, dict):
            raise ValueError("redfish_entity_defaults must be a JSON object")

        allowed_entity_keys = {"systems", "managers", "chassis"}
        normalized: Dict[str, Dict[str, List[str]]] = {}
        for selector, entity_patterns in value.items():
            if not isinstance(selector, str) or not selector.strip():
                raise ValueError(
                    "redfish_entity_defaults selectors must be non-empty strings"
                )
            if selector != selector.strip():
                raise ValueError(
                    "redfish_entity_defaults selectors must not have outer whitespace"
                )
            if not isinstance(entity_patterns, dict):
                raise ValueError(
                    f"redfish_entity_defaults[{selector!r}] must be an object"
                )

            unknown_keys = set(entity_patterns) - allowed_entity_keys
            if unknown_keys:
                raise ValueError(
                    f"redfish_entity_defaults[{selector!r}] has unsupported keys: "
                    + ", ".join(sorted(str(key) for key in unknown_keys))
                )

            normalized_entry: Dict[str, List[str]] = {}
            for entity_key, patterns in entity_patterns.items():
                if not isinstance(patterns, list):
                    raise ValueError(
                        f"redfish_entity_defaults[{selector!r}]"
                        f"[{entity_key!r}] must be a list"
                    )
                if any(
                    not isinstance(pattern, str) or not pattern.strip()
                    for pattern in patterns
                ):
                    raise ValueError(
                        f"redfish_entity_defaults[{selector!r}]"
                        f"[{entity_key!r}] patterns must be non-empty strings"
                    )
                normalized_entry[entity_key] = list(patterns)
            normalized[selector] = normalized_entry

        return normalized

    def _has_spreadsheet_baseboard_definitions(
        self, spreadsheet_path: Union[str, Path, CatalogSnapshot]
    ) -> bool:
        """
        Check if spreadsheet has baseboard definitions.

        The implementation uses ``spreadsheet_path`` to check if spreadsheet has
        baseboard definitions. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path.

        Args:
            spreadsheet_path: filesystem location used as the spreadsheet path
                for this operation.

        Returns:
            Whether the if spreadsheet has baseboard definitions operation
            succeeds.
        """
        try:
            df = self._read_configuration_sheet(spreadsheet_path)

            # Check if there are baseboard definition rows
            baseboard_rows = df[df["Section"] == "Baseboard Definitions"]
            return len(baseboard_rows) > 0

        except Exception:
            return False

    @staticmethod
    def _catalog_source_label(
        spreadsheet_path: Union[str, Path, CatalogSnapshot],
    ) -> str:
        """
        Return the catalog source label.

        The implementation uses ``spreadsheet_path`` to produce the catalog
        source label.

        Args:
            spreadsheet_path: filesystem location used as the spreadsheet path
                for this operation.

        Returns:
            The canonical catalog source label.
        """
        if isinstance(spreadsheet_path, CatalogSnapshot):
            return spreadsheet_path.facts.catalog_name
        return str(spreadsheet_path)

    @staticmethod
    def _read_configuration_sheet(
        spreadsheet_path: Union[str, Path, CatalogSnapshot],
    ) -> excel_reader.SheetData:
        """
        Read configuration sheet.

        The implementation uses ``spreadsheet_path`` to read configuration
        sheet. Parsing or I/O must finish before the validated representation is
        made available to the caller. If the function cannot read configuration
        sheet, its exception reaches the caller instead of being converted into
        a successful result.

        Args:
            spreadsheet_path: filesystem location used as the spreadsheet path
                for this operation.

        Returns:
            A ``SheetData`` representing configuration sheet.

        Raises:
            FileNotFoundError: If telemetry Catalog spreadsheet does not exist.
        """
        if isinstance(spreadsheet_path, CatalogSnapshot):
            return spreadsheet_path.read_excel("Log Collection Configuration")
        catalog_path = Path(spreadsheet_path)
        if not catalog_path.exists():
            raise FileNotFoundError("Telemetry Catalog spreadsheet does not exist")
        return excel_reader.read_excel(
            catalog_path,
            sheet_name="Log Collection Configuration",
        )

    def _load_from_spreadsheet(
        self,
        spreadsheet_path: Union[str, Path, CatalogSnapshot],
    ) -> None:
        """
        Load baseboard definitions from spreadsheet.

        The implementation uses ``spreadsheet_path`` to load baseboard
        definitions from spreadsheet. Parsing or I/O must finish before the
        validated representation is made available to the caller. It updates
        ``ansible_mappings``, ``baseboards``, ``explicit_baseboard_groups``,
        ``platform_detection_profile``, and ``redfish_entity_defaults`` on the
        instance as part of that state transition. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Args:
            spreadsheet_path: filesystem location used as the spreadsheet path
                for this operation.
        """
        try:
            self.platform_detection_profile = None
            self.runtime_boundary_profile = {
                "version": RUNTIME_BOUNDARY_PROFILE_VERSION,
                "defaults": dict(DEFAULT_RUNTIME_BOUNDARIES),
            }
            spreadsheet_label = self._catalog_source_label(spreadsheet_path)
            if (
                not isinstance(spreadsheet_path, CatalogSnapshot)
                and not Path(spreadsheet_path).exists()
            ):
                if self.logger:
                    self._pending_log_tasks.append(
                        asyncio.create_task(
                            self.logger.log_runtime(
                                "ERROR",
                                "BaseboardManager",
                                f"Spreadsheet file not found: {spreadsheet_label}",
                            )
                        )
                    )
                return

            # Read the configuration sheet
            df = self._read_configuration_sheet(spreadsheet_path)

            # Extract global constants
            global_constants = {}
            global_rows = df[df["Section"] == "Global Constants"]
            redfish_defaults_rows = global_rows[
                global_rows["Configuration Item"] == "redfish_entity_defaults"
            ]
            if len(redfish_defaults_rows) == 1:
                _, defaults_row = next(redfish_defaults_rows.iterrows())
                value = defaults_row.get("Value", "")
                if excel_reader.notna(value) and str(value).strip():
                    try:
                        parsed_defaults = json.loads(
                            str(value),
                            object_pairs_hook=_json_object_without_duplicate_keys,
                        )
                        self.redfish_entity_defaults = (
                            self._validate_redfish_entity_defaults(parsed_defaults)
                        )
                        self.redfish_entity_defaults_configured = True
                    except (json.JSONDecodeError, ValueError) as error:
                        self.redfish_entity_defaults = {}
                        self._queue_runtime_log(
                            "WARNING",
                            "Ignoring invalid redfish_entity_defaults in spreadsheet: "
                            f"{error}",
                        )
                else:
                    self._queue_runtime_log(
                        "WARNING",
                        "Ignoring blank redfish_entity_defaults in spreadsheet",
                    )
            elif len(redfish_defaults_rows) > 1:
                self._queue_runtime_log(
                    "WARNING",
                    "Ignoring duplicate redfish_entity_defaults rows in spreadsheet",
                )

            profile_rows = global_rows[
                global_rows["Configuration Item"] == PLATFORM_DETECTION_PROFILE_KEY
            ]
            if len(profile_rows) == 1:
                _, profile_row = next(profile_rows.iterrows())
                value = profile_row.get("Value", "")
                if excel_reader.notna(value) and str(value).strip():
                    try:
                        parsed_profile = json.loads(
                            str(value),
                            object_pairs_hook=_json_object_without_duplicate_keys,
                        )
                        self.platform_detection_profile = (
                            validate_platform_detection_profile(parsed_profile)
                        )
                    except (json.JSONDecodeError, ValueError) as error:
                        self.platform_detection_profile = None
                        self._queue_runtime_log(
                            "WARNING",
                            "Ignoring invalid platform_detection_profile in "
                            f"spreadsheet: {error}",
                        )
                else:
                    self._queue_runtime_log(
                        "WARNING",
                        "Ignoring blank platform_detection_profile in spreadsheet",
                    )
            elif len(profile_rows) > 1:
                self._queue_runtime_log(
                    "WARNING",
                    "Ignoring duplicate platform_detection_profile rows in spreadsheet",
                )

            runtime_profile_rows = global_rows[
                global_rows["Configuration Item"] == RUNTIME_BOUNDARY_PROFILE_KEY
            ]
            if len(runtime_profile_rows) == 1:
                _, runtime_profile_row = next(runtime_profile_rows.iterrows())
                value = runtime_profile_row.get("Value", "")
                if excel_reader.notna(value) and str(value).strip():
                    try:
                        parsed_runtime_profile = json.loads(
                            str(value),
                            object_pairs_hook=_json_object_without_duplicate_keys,
                        )
                        self.runtime_boundary_profile = (
                            validate_runtime_boundary_profile(parsed_runtime_profile)
                        )
                    except (json.JSONDecodeError, ValueError) as error:
                        self._queue_runtime_log(
                            "WARNING",
                            f"Ignoring invalid {RUNTIME_BOUNDARY_PROFILE_KEY} in "
                            f"spreadsheet: {error}",
                        )
                else:
                    self._queue_runtime_log(
                        "WARNING",
                        f"Ignoring blank {RUNTIME_BOUNDARY_PROFILE_KEY} in spreadsheet",
                    )
            elif len(runtime_profile_rows) > 1:
                self._queue_runtime_log(
                    "WARNING",
                    f"Ignoring duplicate {RUNTIME_BOUNDARY_PROFILE_KEY} rows in "
                    "spreadsheet",
                )

            for _, row in global_rows.iterrows():
                config_item = row.get("Configuration Item", "")
                value = row.get("Value", "")
                if config_item not in {
                    "redfish_entity_defaults",
                    PLATFORM_DETECTION_PROFILE_KEY,
                    RUNTIME_BOUNDARY_PROFILE_KEY,
                }:
                    global_constants[config_item] = value

            # Extract baseboard definitions
            baseboards = {}
            baseboard_rows = df[df["Section"] == "Baseboard Definitions"]
            group_rows = df[df["Section"] == "Baseboard Groups"]
            ansible_rows = df[df["Section"] == "Ansible Mappings"]

            self.explicit_baseboard_groups = {}
            for _, row in group_rows.iterrows():
                field_name = str(row.get("Configuration Item", "")).strip()
                if not field_name.startswith("Group: "):
                    continue
                group_name = field_name.replace("Group: ", "", 1).strip()
                value = row.get("Value", "")
                try:
                    members = (
                        json.loads(str(value))
                        if excel_reader.notna(value) and value
                        else []
                    )
                except json.JSONDecodeError:
                    members = []
                if group_name and isinstance(members, list):
                    self.explicit_baseboard_groups[group_name] = [
                        str(member).strip() for member in members if str(member).strip()
                    ]

            self.ansible_mappings = []
            for _, row in ansible_rows.iterrows():
                field_name = row.get("Configuration Item", "")
                if str(field_name).strip().lower() != "ansible_mappings":
                    continue
                value = row.get("Value", "")
                if excel_reader.notna(value) and value:
                    try:
                        self.ansible_mappings = json.loads(str(value))
                    except json.JSONDecodeError:
                        self.ansible_mappings = []
                else:
                    self.ansible_mappings = []

            if self.logger:
                self._pending_log_tasks.append(
                    asyncio.create_task(
                        self.logger.log_runtime(
                            "INFO",
                            "BaseboardManager",
                            f"Parsed {len(self.ansible_mappings)} ansible baseboard "
                            f"mappings from spreadsheet {spreadsheet_label}",
                        )
                    )
                )

            # Get all baseboard columns (skip Section, Configuration Item, Value, Description)
            baseboard_columns = [
                col
                for col in df.columns
                if col
                not in [
                    "Section",
                    "Configuration Item",
                    "Value",
                    "Description",
                ]
            ]

            # Initialize baseboard dictionaries
            for baseboard_name in baseboard_columns:
                baseboards[baseboard_name] = {}

            # Process each field row
            for _, row in baseboard_rows.iterrows():
                field_name = row.get("Configuration Item", "")

                for baseboard_name in baseboard_columns:
                    value = row.get(baseboard_name, "")

                    # Handle different field types
                    if field_name in ["type", "platform", "description"]:
                        baseboards[baseboard_name][field_name] = (
                            str(value) if excel_reader.notna(value) else ""
                        )
                    elif field_name in [
                        "embargoed",
                        "external_github_allowed",
                        "supports_redfish",
                        "supports_ipmi",
                        "supports_bmc_ssh",
                        "supports_hmc",
                    ]:
                        baseboards[baseboard_name][field_name] = (
                            bool(value) if excel_reader.notna(value) else None
                        )
                    elif field_name == "i2c_config":
                        try:
                            if excel_reader.notna(value) and value:
                                baseboards[baseboard_name][field_name] = json.loads(
                                    str(value)
                                )
                            else:
                                baseboards[baseboard_name][field_name] = {}
                        except json.JSONDecodeError:
                            baseboards[baseboard_name][field_name] = {}
                    elif field_name == "platform_detection":
                        try:
                            if excel_reader.notna(value) and value:
                                platform_detection = json.loads(str(value))
                                # Resolve YAML anchors for HMC IP
                                if isinstance(platform_detection.get("hmc_ip"), str):
                                    hmc_ip_value = platform_detection["hmc_ip"]
                                    if hmc_ip_value.startswith("*"):
                                        anchor_name = hmc_ip_value[
                                            1:
                                        ]  # Remove the * prefix
                                        # Get the value from global constants (these should have the correct defaults)
                                        resolved_value = global_constants.get(
                                            anchor_name, hmc_ip_value
                                        )
                                        platform_detection["hmc_ip"] = resolved_value

                                        # Log the resolution for debugging
                                        if self.logger:
                                            self._pending_log_tasks.append(
                                                asyncio.create_task(
                                                    self.logger.log_runtime(
                                                        "DEBUG",
                                                        "BaseboardManager",
                                                        f"Resolved YAML anchor {hmc_ip_value} -> {resolved_value} for baseboard {baseboard_name}",
                                                    )
                                                )
                                            )
                                        else:
                                            # Fallback logging if logger not available
                                            print(
                                                f"[DEBUG] Resolved YAML anchor {hmc_ip_value} -> {resolved_value} for baseboard {baseboard_name}"
                                            )
                                    else:
                                        # Log when no anchor resolution is needed
                                        if self.logger:
                                            self._pending_log_tasks.append(
                                                asyncio.create_task(
                                                    self.logger.log_runtime(
                                                        "DEBUG",
                                                        "BaseboardManager",
                                                        f"No YAML anchor resolution needed for {baseboard_name}.hmc_ip = {hmc_ip_value}",
                                                    )
                                                )
                                            )
                                baseboards[baseboard_name][
                                    field_name
                                ] = platform_detection
                            else:
                                baseboards[baseboard_name][field_name] = {}
                        except json.JSONDecodeError:
                            baseboards[baseboard_name][field_name] = {}
                    elif field_name == RUNTIME_BOUNDARY_OVERRIDES_KEY:
                        try:
                            if excel_reader.notna(value) and str(value).strip():
                                parsed_overrides = json.loads(
                                    str(value),
                                    object_pairs_hook=(
                                        _json_object_without_duplicate_keys
                                    ),
                                )
                                baseboards[baseboard_name][field_name] = (
                                    validate_runtime_boundary_overrides(
                                        parsed_overrides
                                    )
                                )
                            else:
                                baseboards[baseboard_name][field_name] = {}
                        except (json.JSONDecodeError, ValueError) as error:
                            baseboards[baseboard_name][field_name] = {}
                            self._queue_runtime_log(
                                "WARNING",
                                f"Ignoring invalid {RUNTIME_BOUNDARY_OVERRIDES_KEY} "
                                f"for {baseboard_name}: {error}",
                            )
                    elif field_name == DIAGNOSTIC_CAPACITY_POOLS_KEY:
                        try:
                            parsed_pools = (
                                json.loads(
                                    str(value),
                                    object_pairs_hook=_json_object_without_duplicate_keys,
                                )
                                if excel_reader.notna(value) and str(value).strip()
                                else {}
                            )
                            baseboards[baseboard_name][field_name] = (
                                validate_diagnostic_capacity_pools(parsed_pools)
                            )
                        except (ValueError, TypeError) as error:
                            baseboards[baseboard_name][field_name] = {}
                            self._queue_runtime_log(
                                "WARNING",
                                f"Ignoring invalid {field_name} for {baseboard_name}: {error}",
                            )
                    elif field_name == COLLECTOR_WORKLOAD_PROFILES_KEY:
                        try:
                            if excel_reader.notna(value) and str(value).strip():
                                parsed_profiles = json.loads(
                                    str(value),
                                    object_pairs_hook=(
                                        _json_object_without_duplicate_keys
                                    ),
                                )
                                baseboards[baseboard_name][field_name] = (
                                    validate_collector_workload_profiles(
                                        parsed_profiles
                                    )
                                )
                            else:
                                baseboards[baseboard_name][field_name] = {}
                        except (json.JSONDecodeError, ValueError) as error:
                            baseboards[baseboard_name][field_name] = {}
                            self._queue_runtime_log(
                                "WARNING",
                                f"Ignoring invalid {COLLECTOR_WORKLOAD_PROFILES_KEY} "
                                f"for {baseboard_name}: {error}",
                            )
                    else:
                        # Preserve any additional metadata fields as strings
                        if excel_reader.notna(value) and value != "":
                            baseboards[baseboard_name][field_name] = str(value)

            # Add global constants to each baseboard
            for baseboard_name in baseboards:
                baseboards[baseboard_name].update(global_constants)
                try:
                    resolved_boundaries = resolve_runtime_boundaries(
                        self.runtime_boundary_profile,
                        baseboards[baseboard_name].get(
                            RUNTIME_BOUNDARY_OVERRIDES_KEY, {}
                        ),
                    )
                except ValueError as error:
                    baseboards[baseboard_name][RUNTIME_BOUNDARY_OVERRIDES_KEY] = {}
                    resolved_boundaries = resolve_runtime_boundaries(
                        self.runtime_boundary_profile
                    )
                    self._queue_runtime_log(
                        "WARNING",
                        f"Ignoring inconsistent {RUNTIME_BOUNDARY_OVERRIDES_KEY} "
                        f"for {baseboard_name}: {error}",
                    )
                baseboards[baseboard_name][RUNTIME_BOUNDARIES_KEY] = resolved_boundaries

            self.baseboards = baseboards
            self._build_lookup_tables()
            if self.ansible_mappings:
                baseboard_node_types = {
                    baseboard_name: self.get_baseboard_node_type(baseboard_name)
                    for baseboard_name in self.baseboards
                }
                self.ansible_mappings = validate_ansible_baseboard_mapping_targets(
                    self.ansible_mappings,
                    baseboard_node_types,
                )

            if self.logger:
                self._pending_log_tasks.append(
                    asyncio.create_task(
                        self.logger.log_runtime(
                            "INFO",
                            "BaseboardManager",
                            f"Loaded {len(baseboards)} baseboards from spreadsheet: "
                            f"{spreadsheet_label}",
                        )
                    )
                )

        except Exception as e:
            if self.logger:
                self._pending_log_tasks.append(
                    asyncio.create_task(
                        self.logger.log_runtime(
                            "ERROR",
                            "BaseboardManager",
                            f"Failed to load baseboards from spreadsheet: {e}",
                        )
                    )
                )
            # Reset every catalog-owned field so callers cannot observe a
            # mixture of rejected workbook globals and empty baseboard tables.
            self.baseboards = {}
            self.redfish_entity_defaults = {}
            self.redfish_entity_defaults_configured = False
            self.platform_detection_profile = None
            self.runtime_boundary_profile = {
                "version": RUNTIME_BOUNDARY_PROFILE_VERSION,
                "defaults": dict(DEFAULT_RUNTIME_BOUNDARIES),
            }
            self.ansible_mappings = []
            self.explicit_baseboard_groups = {}
            self._build_lookup_tables()

    def _build_lookup_tables(self) -> None:
        """
        Build lookup tables for efficient baseboard queries.

        The implementation uses current instance state to build lookup tables
        for efficient baseboard queries.
        """
        self.baseboard_types.clear()
        self.baseboard_groups.clear()
        self.baseboard_name_lookup.clear()
        self.baseboard_type_lookup.clear()

        # Build baseboard_name -> type mapping
        for baseboard_name, baseboard_config in self.baseboards.items():
            self.baseboard_name_lookup[baseboard_name.lower()] = baseboard_name
            baseboard_type = baseboard_config.get("type", "unknown")
            self.baseboard_types[baseboard_name] = baseboard_type
            if baseboard_type:
                self.baseboard_type_lookup.setdefault(
                    baseboard_type.lower(), baseboard_type
                )

            # Build group -> baseboard_names mapping
            if baseboard_type not in self.baseboard_groups:
                self.baseboard_groups[baseboard_type] = []
            self.baseboard_groups[baseboard_type].append(baseboard_name)

            # Platform node types are catalog-owned semantic selectors, not
            # aliases for any one physical baseboard. Build overlapping groups
            # so inputs such as ``SwitchTray`` retain their identity while
            # selecting every declared switch-tray platform.
            platform_detection = baseboard_config.get("platform_detection")
            node_type = (
                platform_detection.get("node_type")
                if isinstance(platform_detection, dict)
                else None
            )
            if isinstance(node_type, str) and node_type.strip():
                node_type = node_type.strip()
                canonical_node_type = next(
                    (
                        group_name
                        for group_name in self.baseboard_groups
                        if group_name.casefold() == node_type.casefold()
                    ),
                    node_type,
                )
                node_group = self.baseboard_groups.setdefault(canonical_node_type, [])
                if baseboard_name not in node_group:
                    node_group.append(baseboard_name)

        # A baseboard can belong to semantic groups in addition to its primary
        # ``type`` (for example, MGX Vera C2 is both MGX and MGX_NO_GPU).  Keep
        # those overlapping memberships when loading the packaged workbook.
        for group_name, members in self.explicit_baseboard_groups.items():
            group = self.baseboard_groups.setdefault(group_name, [])
            for member in members:
                normalized_member = self._normalize_baseboard_name(member)
                if (
                    normalized_member in self.baseboards
                    and normalized_member not in group
                ):
                    group.append(normalized_member)

        for group_name in self.baseboard_groups:
            self.baseboard_type_lookup.setdefault(group_name.lower(), group_name)

    def _normalize_baseboard_name(self, baseboard_name: Optional[str]) -> Optional[str]:
        """
        Normalize baseboard name.

        The implementation uses ``baseboard_name`` to normalize baseboard name.
        The source value keeps its ownership while the normalized representation
        is returned separately.

        Args:
            baseboard_name: Stable baseboard name used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical baseboard name, or ``None`` when the requested value
            is unavailable.
        """
        if not baseboard_name:
            return baseboard_name
        if baseboard_name in self.baseboards:
            return baseboard_name
        key = baseboard_name.strip().lower()
        return self.baseboard_name_lookup.get(key, baseboard_name)

    def _normalize_group_name(self, group_name: Optional[str]) -> Optional[str]:
        """
        Normalize group name.

        The implementation uses ``group_name`` to normalize group name. The
        source value keeps its ownership while the normalized representation is
        returned separately.

        Args:
            group_name: Stable group name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical group name, or ``None`` when the requested value is
            unavailable.
        """
        if not group_name:
            return group_name
        if group_name in self.baseboard_groups:
            return group_name
        key = group_name.strip().lower()
        return self.baseboard_type_lookup.get(key, group_name)

    def get_baseboard_type(self, baseboard_name: str) -> Optional[str]:
        """
        Get the type of a baseboard.

        The implementation uses ``baseboard_name`` to get the type of a
        baseboard.

        Args:
            baseboard_name: Stable baseboard name used for lookup and
                operator-facing diagnostics.

        Returns:
            The validated ``baseboard_type``, or ``None`` when no value
            qualifies.
        """
        normalized_name = self._normalize_baseboard_name(baseboard_name)
        baseboard_type = self.baseboard_types.get(normalized_name)
        return baseboard_type

    def get_baseboard_node_type(self, baseboard_name: str) -> Optional[str]:
        """
        Return the operational node type declared by the runtime catalog.

        A baseboard's family ``type`` (for example ``HGX`` or ``Workstation``)
        is distinct from its node role (for example ``Compute`` or
        ``SwitchTray``). The node role is read from the generated workbook's
        ``platform_detection.node_type`` value so callers do not reconstruct
        authored platform metadata.

        Args:
            baseboard_name: Stable baseboard name used for a case-insensitive
                catalog lookup.

        Returns:
            The stripped node-type value, or ``None`` when the baseboard or its
            node-type declaration is unavailable.
        """
        baseboard_config = self.get_baseboard_config(baseboard_name)
        if not isinstance(baseboard_config, dict):
            return None
        platform_detection = baseboard_config.get("platform_detection")
        if not isinstance(platform_detection, dict):
            return None
        node_type = platform_detection.get("node_type")
        if not isinstance(node_type, str) or not node_type.strip():
            return None
        return node_type.strip()

    async def log_baseboard_info(self, dut_id: str) -> None:
        """
        Log baseboard information for debugging.

        The implementation uses ``dut_id`` to log baseboard information for
        debugging. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "BaseboardManager",
            f"Loaded {len(self.baseboards)} baseboards: {list(self.baseboards.keys())}",
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "BaseboardManager",
            f"Baseboard types: {self.baseboard_types}",
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "BaseboardManager",
            f"Baseboard groups: {self.baseboard_groups}",
        )

    def get_baseboard_group(self, baseboard_name: str) -> Optional[str]:
        """
        Get the primary family group of a baseboard for filtering purposes.

        The generated workbook stores the authored family group in the
        baseboard definition's ``type`` field. Operational node roles are
        independently available through :meth:`get_baseboard_node_type`.

        Args:
            baseboard_name: Stable baseboard name used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical baseboard group text, or ``None`` when the requested
            value is unavailable.
        """
        return self.get_baseboard_type(baseboard_name)

    def get_baseboards_in_group(self, group_name: str) -> List[str]:
        """
        Get all baseboards that belong to a specific group.

        After applying local validation, the function forwards ``group_name`` to
        ``self.baseboard_groups.get`` and preserves its return and exception
        contract.

        Args:
            group_name: Stable group name used for lookup and operator-facing
                diagnostics.

        Returns:
            The baseboards in group returned in operation-defined order.
        """
        normalized_group = self._normalize_group_name(group_name)
        return self.baseboard_groups.get(normalized_group, [])

    def get_equivalent_baseboard_groups(self, group_name: str) -> List[str]:
        """
        Return semantic groups with the exact same catalog membership.

        Equivalence is deliberately stricter than overlap. This lets a
        catalog-authored node type such as ``SwitchTray`` interoperate with an
        existing primary type such as ``NVSwitch`` without allowing a broad
        selector to activate collectors qualified for only one member family.
        Group names and member names are compared case-insensitively, while
        returned names retain their catalog spelling and declaration order.

        Args:
            group_name: Catalog semantic group whose equivalents are requested.

        Returns:
            Every nonempty catalog group with exactly the same member set, or
            an empty list when ``group_name`` is unavailable or has no members.
        """
        normalized_group = self._normalize_group_name(group_name)
        selected_members = self.baseboard_groups.get(normalized_group, [])
        normalized_members = {
            member.strip().casefold()
            for member in selected_members
            if isinstance(member, str) and member.strip()
        }
        if not normalized_members:
            return []

        equivalent_groups = []
        for candidate_name, candidate_members in self.baseboard_groups.items():
            normalized_candidate_members = {
                member.strip().casefold()
                for member in candidate_members
                if isinstance(member, str) and member.strip()
            }
            if normalized_candidate_members == normalized_members:
                equivalent_groups.append(candidate_name)
        return equivalent_groups

    def get_all_baseboard_names(self) -> List[str]:
        """
        Get all baseboard names.

        After applying local validation, the function forwards current instance
        state to ``list`` and preserves its return and exception contract.

        Returns:
            The all baseboard names returned in operation-defined order.
        """
        return list(self.baseboards.keys())

    def get_all_baseboard_types(self) -> List[str]:
        """
        Get all baseboard types.

        After applying local validation, the function forwards current instance
        state to ``list`` and preserves its return and exception contract.

        Returns:
            The all baseboard types returned in operation-defined order.
        """
        return list(self.baseboard_groups.keys())

    def get_baseboard_config(self, baseboard_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the full configuration for a baseboard.

        After applying local validation, the function forwards
        ``baseboard_name`` to ``self.baseboards.get`` and preserves its return
        and exception contract.

        Args:
            baseboard_name: Stable baseboard name used for lookup and
                operator-facing diagnostics.

        Returns:
            A mapping containing baseboard config, or ``None`` when the
            requested value is unavailable.
        """
        normalized_name = self._normalize_baseboard_name(baseboard_name)
        return self.baseboards.get(normalized_name)

    def get_entity_patterns(
        self, baseboard_name: str, entity_type: str
    ) -> Optional[List[str]]:
        """
        Get the default Redfish entity ID patterns for a baseboard and entity type.

        Resolution order: exact baseboard name > baseboard group/type >
        "default".

        Args:
            baseboard_name: Stable baseboard name used for lookup and
                operator-facing diagnostics.
            entity_type: Text supplied as entity type in the format accepted by
                this function.

        Returns:
            The entity patterns returned in operation-defined order, or ``None``
            when the requested value is unavailable.
        """
        if not self.redfish_entity_defaults:
            return None

        pattern_key = {
            "Systems": "systems",
            "Managers": "managers",
            "Chassis": "chassis",
        }.get(entity_type)
        if not pattern_key:
            return None

        normalized_name = (
            self._normalize_baseboard_name(baseboard_name) or baseboard_name
        )

        def configured_patterns(
            selector: Optional[str],
        ) -> Optional[List[str]]:
            """
            Return the configured patterns.

            Presence is authoritative. An explicit [] intentionally matches no
            entities and must not fall through to a broader default.

            Args:
                selector: Text supplied as selector in the format accepted by
                    this function.

            Returns:
                The configured patterns returned in operation-defined order, or
                ``None`` when the requested value is unavailable.
            """
            if not selector:
                return None
            entry = self.redfish_entity_defaults.get(selector)
            if not isinstance(entry, dict) or pattern_key not in entry:
                return None
            # Presence is authoritative. An explicit [] intentionally matches
            # no entities and must not fall through to a broader default.
            return list(entry[pattern_key])

        # 1. Exact baseboard name match
        patterns = configured_patterns(normalized_name)
        if patterns is not None:
            return patterns

        # 2. Baseboard group/type match
        baseboard_type = self.get_baseboard_type(baseboard_name)
        patterns = configured_patterns(baseboard_type)
        if patterns is not None:
            return patterns

        # 3. "default" fallback
        return configured_patterns("default")

    async def apply_baseboard_filtering(
        self,
        dut_id: str,
        dut_baseboard: str,
        filtering_rules: Dict[str, str],
        default_filter_mode: str = "all_platforms",
    ) -> str:
        """
        Apply baseboard filtering rules to determine the effective filter mode.

        Priority order: exact baseboard match > group match > default.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut_baseboard: Text supplied as DUT baseboard in the format accepted
                by this function.
            filtering_rules: Mapping supplying fields for apply baseboard
                filtering rules to determine the effective filter mode.
            default_filter_mode: Text supplied as default filter mode in the
                format accepted by this function.

        Returns:
            The canonical baseboard filtering text.
        """
        if not filtering_rules:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "BaseboardManager",
                f"No filtering rules provided, using default: {default_filter_mode}",
            )
            return default_filter_mode

        # Priority order: exact baseboard match > group match > default
        normalized_dut_baseboard = self._normalize_baseboard_name(dut_baseboard)
        dut_type = self.get_baseboard_type(dut_baseboard)
        normalized_rules: Dict[str, str] = {}
        for rule_key, filter_mode in filtering_rules.items():
            if rule_key == "default":
                normalized_rules[rule_key] = filter_mode
                continue
            normalized_baseboard = self._normalize_baseboard_name(rule_key)
            normalized_group = self._normalize_group_name(rule_key)
            if normalized_baseboard in self.baseboards:
                normalized_rules[normalized_baseboard] = filter_mode
            elif normalized_group in self.baseboard_groups:
                normalized_rules[normalized_group] = filter_mode
            else:
                normalized_rules[rule_key] = filter_mode

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "BaseboardManager",
            f"Applying baseboard filtering: dut_baseboard='{normalized_dut_baseboard}', dut_type='{dut_type}', rules={normalized_rules}",
        )

        # 1. Check for exact baseboard match (highest priority)
        if normalized_dut_baseboard in normalized_rules:
            effective_filter = normalized_rules[normalized_dut_baseboard]
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "BaseboardManager",
                f"Exact baseboard match '{normalized_dut_baseboard}' -> filter_mode='{effective_filter}'",
            )
            return effective_filter

        # 2. Check for group/type match (medium priority)
        if dut_type and dut_type in normalized_rules:
            effective_filter = normalized_rules[dut_type]
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "BaseboardManager",
                f"Group match '{dut_type}' -> filter_mode='{effective_filter}'",
            )
            return effective_filter

        # A baseboard can also belong to overlapping semantic groups that are
        # independent of its primary type. Preserve rule order when more than
        # one such group applies.
        for group_name, filter_mode in normalized_rules.items():
            if group_name in {"default", dut_type}:
                continue
            if normalized_dut_baseboard in self.baseboard_groups.get(group_name, []):
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "BaseboardManager",
                    f"Semantic group match '{group_name}' -> filter_mode='{filter_mode}'",
                )
                return filter_mode

        # 3. Check for "default" rule (lowest priority)
        if "default" in normalized_rules:
            effective_filter = normalized_rules["default"]
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "BaseboardManager",
                f"Default rule -> filter_mode='{effective_filter}'",
            )
            return effective_filter

        # 4. Use provided default
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "BaseboardManager",
            f"No rules matched, using provided default: {default_filter_mode}",
        )
        return default_filter_mode
