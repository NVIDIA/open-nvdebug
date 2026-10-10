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
Configuration Manager for NVDebug Tool.

Handles loading and management of all configuration files including tool config,
DUT config, collector definitions, and service initialization.
"""

import asyncio
import copy
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..config import (
    AdaptiveConcurrencyConfig,
    RemovedAttachmentLimitError,
    merge_dut_config_layers,
    reject_removed_attachment_limit_setting,
    sync_legacy_fields,
)
from ..services.base_service import BaseService
from ..services.bmc_ssh_service import BMCSSHService
from ..services.health_check_service import HealthCheckService
from ..services.host_service import HostService
from ..services.ipmi_service import IPMIService
from ..services.redfish_pagination import DEFAULT_MAX_PAGINATION_PAGES
from ..services.redfish_service import RedfishService
from ..utils import excel_reader
from ..utils.catalog_global_profile import load_catalog_global_profile
from ..utils.catalog_snapshot import (
    CatalogSnapshot,
    CatalogSnapshotFacts,
    read_catalog_snapshot,
)
from ..utils.collector_resource_profile import parse_collector_resource_profile
from ..utils.dgx_diagnostic_routing_profile import (
    DGX_DIAGNOSTIC_ROUTING_PROFILE_KEY,
    get_dgx_diagnostic_route,
    validate_dgx_diagnostic_route_hooks,
    validate_dgx_diagnostic_routing_profile,
)
from ..utils.enums import CollectorServiceMapping
from ..utils.redfish_diagnostic_concurrency import (
    diagnostic_concurrency_profile_for_collector,
)
from ..utils.redfish_limits import RedfishRequestCaptureLimits, RedfishResponseLimits
from ..utils.redfish_topology_profile import (
    REDFISH_TOPOLOGY_PROFILE_KEY,
    build_redfish_resource_uri_lookup,
    validate_redfish_topology_profile,
)
from ..utils.resources import find_config_directory
from ..utils.spreadsheet_utils import decode_long_cell
from ..utils.timeout_config import TIMEOUT_CONFIG_OVERRIDE_KEYS
from ..utils.uri_config_manager import URIConfigManager
from ..utils.yaml_manager import YAMLManager

# Standard logger for fallback
logger = logging.getLogger(__name__)


def _decode_catalog_json_object(
    raw_value: Any,
    *,
    collector_id: Any,
    column_name: str,
    excel_row: int,
) -> Dict[str, Any]:
    """
    Decode one optional JSON-object cell without consulting another source.

    The implementation uses ``raw_value``, ``collector_id``, ``column_name``,
    and ``excel_row`` to decode one optional JSON-object cell without consulting
    another source. Parsing or I/O must finish before the validated
    representation is made available to the caller. If the function cannot
    decode one optional JSON-object cell without consulting another source, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        raw_value: Raw value consumed while the function attempts to decode one
            optional JSON-object cell without consulting another source.
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        column_name: Stable column name used for lookup and operator-facing
            diagnostics.
        excel_row: Numeric excel row used while the operation performs bounded
            accounting.

    Returns:
        A mapping containing catalog JSON object.

    Raises:
        ValueError: If ``location``: cannot decode a JSON object (``exc``); or
            ``location``: expected a JSON object, got ``__name__``.
    """
    if not excel_reader.notna(raw_value) or not str(raw_value).strip():
        return {}

    location = (
        f"Log Collection Catalog row {excel_row}, collector {collector_id}, "
        f"column {column_name}"
    )
    try:
        value = json.loads(decode_long_cell(str(raw_value)))
    except (TypeError, ValueError, OSError, UnicodeError) as exc:
        raise ValueError(f"{location}: cannot decode a JSON object ({exc})") from exc
    if not isinstance(value, dict):
        raise ValueError(
            f"{location}: expected a JSON object, got {type(value).__name__}"
        )
    return value


class ConfigurationManager:
    """
    Manages all configuration loading and service initialization.

    Handles loading of tool configuration, DUT configuration, collector
    definitions, and initializes services for each DUT.
    """

    def __init__(
        self,
        tool_config_path: str = None,
        dut_config_path: str = None,
        sanitized_console=None,
        quiet_mode: bool = False,
    ):
        """
        Initialize configuration manager.

        The initializer records ``_catalog_snapshot``,
        ``_catalog_snapshot_prebound``, ``_catalog_snapshot_source``,
        ``collector_definitions``, and ``dgx_diagnostic_routing_profile`` for
        later operations and establishes the instance invariants before any
        public method runs.

        Args:
            tool_config_path: Optional filesystem location used as the tool
                config path for this operation.
            dut_config_path: Optional filesystem location used as the DUT config
                path for this operation.
            sanitized_console: Optional sanitized console; ``None`` selects the
                function's default behavior.
            quiet_mode: Whether quiet mode is enabled or required for this
                operation.
        """
        self.tool_config_path = tool_config_path
        self.dut_config_path = dut_config_path
        self.sanitized_console = sanitized_console
        self.quiet_mode = quiet_mode

        # Configuration storage
        self.tool_config: Dict[str, Any] = {}
        self.dut_config: Dict[str, Any] = {}
        self.collector_definitions: Dict[str, Any] = {}
        self._catalog_snapshot: Optional[CatalogSnapshot] = None
        self._catalog_snapshot_source: Optional[str] = None
        self._catalog_snapshot_prebound = False

        # Service instances
        self.services: Dict[str, BaseService] = {}

        # Collector categorization
        self.sequential_collectors: Set[str] = set()
        self.parallel_collectors: Set[str] = set()

        # URI configuration manager
        self.uri_config_manager: Optional[URIConfigManager] = None
        self.dgx_diagnostic_routing_profile: Optional[Dict[str, Any]] = None

        # Load all configurations
        if tool_config_path and dut_config_path:
            # Note: These will be called in async_init() after logger is assigned
            pass

    async def _log_runtime(self, level: str, message: str) -> None:
        """
        Log runtime.

        The implementation uses ``level`` and ``message`` to log runtime. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        if hasattr(self, "logger") and self.logger:
            # Use async logger if available
            await self.logger.log_runtime(level, "ConfigManager", message)
        else:
            # Fallback to standard logger
            if level == "ERROR":
                logger.error(message)
            elif level == "WARNING":
                logger.warning(message)
            elif level == "DEBUG":
                logger.debug(message)
            else:
                logger.info(message)

    @classmethod
    def from_objects(
        cls,
        tool_config,
        dut_configs,
        sanitized_console=None,
        quiet_mode: bool = False,
        catalog_snapshot: Optional[CatalogSnapshot] = None,
    ):
        """
        Create ConfigurationManager from ToolConfig and DUTConfig objects.

        Convert ToolConfig object to dictionary format expected by the system.

        Args:
            tool_config: Tool config governing configurationManager from
                ToolConfig and DUTConfig objects.
            dut_configs: DUT configs governing configurationManager from
                ToolConfig and DUTConfig objects.
            sanitized_console: Optional sanitized console; ``None`` selects the
                function's default behavior.
            quiet_mode: Whether quiet mode is enabled or required for this
                operation.
            catalog_snapshot: Optional catalog snapshot; ``None`` selects the
                function's default behavior.

        Returns:
            The validated ``instance``.

        Raises:
            ValueError: If an authoritative catalog snapshot lacks a configured
                Telemetry Catalog path.
        """
        instance = cls(sanitized_console=sanitized_console, quiet_mode=quiet_mode)

        # Convert ToolConfig object to dictionary format expected by the system
        if hasattr(tool_config, "__dict__"):
            config_dir = instance._find_config_directory()

            execution_config = {
                "max_concurrent_collectors_per_dut": tool_config.max_concurrent_collectors_per_dut,
                "timeout": getattr(
                    tool_config, "timeout", 300
                ),  # Default timeout of 300 seconds
                "retry_count": tool_config.retry_count,
            }
            if tool_config.max_concurrent_duts is not None:
                execution_config["max_concurrent_duts"] = (
                    tool_config.max_concurrent_duts
                )

            tool_config_dict = {
                "execution_config": execution_config,
                "collector_definitions": {
                    "spreadsheet_path": (
                        tool_config.spreadsheet
                        if hasattr(tool_config, "spreadsheet")
                        else None
                    ),
                },
                "logging": {
                    "level": tool_config.log_level,
                    "format": tool_config.log_format,
                },
                "output": {
                    "directory": tool_config.output_directory,
                    "skipzip": tool_config.skip_zip,
                    "skipzipsplit": tool_config.skip_zip_split,
                    "zip_split_threshold": tool_config.zip_split_threshold,
                },
                # Include all other ToolConfig fields that might be accessed via .get()
                "collection_level": getattr(tool_config, "collection_level", "L1"),
                "dry_run": getattr(tool_config, "dry_run", False),
                "debug": getattr(tool_config, "debug", False),
                "verbose": getattr(tool_config, "verbose", False),
                "skip_preflight": getattr(tool_config, "skip_preflight", False),
                "skip_sanitization": getattr(tool_config, "skip_sanitization", False),
                "caller_output_was_explicit": getattr(
                    tool_config,
                    "caller_output_was_explicit",
                    False,
                ),
                "apply_sanitization": getattr(tool_config, "apply_sanitization", False),
                "skip_html_reports": getattr(tool_config, "skip_html_reports", False),
                "report_format": getattr(tool_config, "report_format", "spa"),
                "collector_id": getattr(tool_config, "collector_id", None),
                "collector_group": getattr(tool_config, "collector_group", None),
                "skip_collectors": getattr(tool_config, "skip_collectors", None),
                "include_collectors": getattr(tool_config, "include_collectors", None),
                "streaming_only": getattr(tool_config, "streaming_only", False),
                "stream_begin": getattr(tool_config, "stream_begin", "24"),
                "stream_end": getattr(tool_config, "stream_end", "0"),
                "stream_destination": getattr(tool_config, "stream_destination", None),
                "append": getattr(tool_config, "append", False),
                "rack_id": getattr(tool_config, "rack_id", None),
                "enable_status_tracking": getattr(
                    tool_config, "enable_status_tracking", True
                ),
                "disable_live_display": getattr(
                    tool_config, "disable_live_display", False
                ),
                "execution_scheduler": getattr(
                    tool_config, "execution_scheduler", "per_dut"
                ),
                "parallel_dut_sequential_collectors": getattr(
                    tool_config, "parallel_dut_sequential_collectors", True
                ),
                "service_grouped_sequential_collectors": getattr(
                    tool_config, "service_grouped_sequential_collectors", True
                ),
                "uri_overrides": getattr(tool_config, "uri_overrides", None),
                "max_pagination_pages": getattr(
                    tool_config, "max_pagination_pages", DEFAULT_MAX_PAGINATION_PAGES
                ),
                "max_duplicate_url_retries": getattr(
                    tool_config, "max_duplicate_url_retries", 3
                ),
                "redfish_request_capture": (
                    RedfishRequestCaptureLimits.from_tool_config(tool_config).as_dict()
                ),
                # Legacy field names for backward compatibility
                "skip_zip": getattr(tool_config, "skip_zip", False),
                "skip_zip_split": getattr(tool_config, "skip_zip_split", False),
                "zip_split_threshold": getattr(
                    tool_config, "zip_split_threshold", 200.0
                ),
                "GENERATE_HTML_REPORTS": not getattr(
                    tool_config, "skip_html_reports", False
                ),
                # Legacy Skip Flags (from legacy NVDebug)
                "SKIP_PORT_FW": getattr(tool_config, "SKIP_PORT_FW", False),
                "SKIP_BMC_SSH_LOGS": getattr(tool_config, "SKIP_BMC_SSH_LOGS", True),
                "SKIP_HOST_LOGS": getattr(tool_config, "SKIP_HOST_LOGS", False),
                "SKIP_IPMI_LOGS": getattr(tool_config, "SKIP_IPMI_LOGS", False),
                "SKIP_REDFISH_OOB_LOGS": getattr(
                    tool_config, "SKIP_REDFISH_OOB_LOGS", False
                ),
                # New Skip Fields
                "COLLECTOR_TO_SKIP": getattr(tool_config, "COLLECTOR_TO_SKIP", None),
                "SYSTEM_ID_TO_SKIP": getattr(tool_config, "SYSTEM_ID_TO_SKIP", None),
                "CHASSIS_ID_TO_SKIP": getattr(tool_config, "CHASSIS_ID_TO_SKIP", None),
                "MANAGER_ID_TO_SKIP": getattr(tool_config, "MANAGER_ID_TO_SKIP", None),
                # Entity ID Overrides
                "SYSTEM_ID_OVERRIDE": getattr(tool_config, "SYSTEM_ID_OVERRIDE", None),
                "MANAGER_ID_OVERRIDE": getattr(
                    tool_config, "MANAGER_ID_OVERRIDE", None
                ),
                "CHASSIS_ID_OVERRIDE": getattr(
                    tool_config, "CHASSIS_ID_OVERRIDE", None
                ),
                # Expand Query Fields
                "EXPAND_QUERY_CHASSIS_LEVEL": getattr(
                    tool_config, "EXPAND_QUERY_CHASSIS_LEVEL", 1
                ),
                "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL": getattr(
                    tool_config, "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL", 1
                ),
                "EXPAND_QUERY_MANAGER_LEVEL": getattr(
                    tool_config, "EXPAND_QUERY_MANAGER_LEVEL", 1
                ),
                "EXPAND_QUERY_SYSTEM_LEVEL": getattr(
                    tool_config, "EXPAND_QUERY_SYSTEM_LEVEL", 1
                ),
                "__explicit_tool_config_fields": sorted(
                    key
                    for key, value in getattr(
                        tool_config, "explicit_tool_config_keys", {}
                    ).items()
                    if value
                ),
                "__explicit_cli_config_fields": sorted(
                    key
                    for key, value in getattr(
                        tool_config, "explicit_cli_config_keys", {}
                    ).items()
                    if value
                ),
                "EXPAND_FALLBACK_MODE": getattr(
                    tool_config, "EXPAND_FALLBACK_MODE", "auto"
                ),
                # Timeout Fields
                "NVOS_TECH_DUMP_TIMEOUT": getattr(
                    tool_config, "NVOS_TECH_DUMP_TIMEOUT", 600
                ),
                "REDFISH_DUMP_TIMEOUT": getattr(
                    tool_config, "REDFISH_DUMP_TIMEOUT", 300
                ),
                "REDFISH_DEVICE_DUMP_SLEEP_DURATION": getattr(
                    tool_config, "REDFISH_DEVICE_DUMP_SLEEP_DURATION", 60
                ),
                "COLLECTOR_EXTENSION_CONFIG": getattr(
                    tool_config, "COLLECTOR_EXTENSION_CONFIG", {}
                ),
                # Directory Fields
                "BMC_TEMP_DIR": getattr(tool_config, "BMC_TEMP_DIR", "/tmp"),
                # Firmware Inventory Configuration
                "FW_INVENTORY_TABLE_PROPERTIES": getattr(
                    tool_config, "FW_INVENTORY_TABLE_PROPERTIES", []
                ),
                # Additional OOB URI Collection Configuration
                "ADDITIONAL_OOB_URI_COLLECTION": getattr(
                    tool_config, "ADDITIONAL_OOB_URI_COLLECTION", []
                ),
                # NVLink OOB URI Collection Configuration
                "NVLINK_OOB_URI": getattr(tool_config, "NVLINK_OOB_URI", []),
                # Custom Dump Services Configuration
                "CUSTOM_DUMP_SERVICES": getattr(
                    tool_config, "CUSTOM_DUMP_SERVICES", []
                ),
                # Post Codes URI Configuration
                "POST_CODES_URI": getattr(tool_config, "POST_CODES_URI", []),
                # Global Directory and Prefix Fields
                "TASK_ID_PREFIX": getattr(tool_config, "task_id_prefix", ""),
                "TOOL_TEMP_DIR": getattr(tool_config, "tool_temp_dir", "/tmp"),
                # Global feature flags / passthroughs
                "EXTRA_LOG_COLLECTION": getattr(
                    tool_config, "EXTRA_LOG_COLLECTION", None
                ),
                "sysinfo_snapshot_mode": getattr(
                    tool_config, "sysinfo_snapshot_mode", "fast"
                ),
            }
            concurrency_mode = getattr(tool_config, "concurrency_mode", "conservative")
            initial_io_oversubscription = getattr(
                tool_config, "initial_io_oversubscription", None
            )
            minimum_collector_operations = getattr(
                tool_config, "minimum_collector_operations", 1
            )
            maximum_collector_operations = getattr(
                tool_config, "maximum_collector_operations", None
            )
            adaptive_concurrency = dict(
                getattr(tool_config, "adaptive_concurrency", {}) or {}
            )
            default_adaptive_concurrency = AdaptiveConcurrencyConfig().model_dump()
            if concurrency_mode != "conservative":
                execution_config["concurrency_mode"] = concurrency_mode
            if initial_io_oversubscription is not None:
                execution_config["initial_io_oversubscription"] = (
                    initial_io_oversubscription
                )
            if minimum_collector_operations != 1:
                execution_config["minimum_collector_operations"] = (
                    minimum_collector_operations
                )
            if maximum_collector_operations is not None:
                execution_config["maximum_collector_operations"] = (
                    maximum_collector_operations
                )
            if adaptive_concurrency != default_adaptive_concurrency:
                execution_config["adaptive"] = adaptive_concurrency
            # Include i2c_config overrides if present (avoid inserting None)
            _i2c = getattr(tool_config, "i2c_config", None)
            if _i2c is not None:
                tool_config_dict["i2c_config"] = _i2c
            # Include preflight_config if present (credential validation settings)
            _preflight = getattr(tool_config, "preflight_config", None)
            if _preflight:
                tool_config_dict["preflight_config"] = (
                    _preflight.model_dump()
                    if hasattr(_preflight, "model_dump")
                    else _preflight
                )
            # Include redfish_session_config if present (connection pool settings)
            _redfish_session = getattr(tool_config, "redfish_session_config", None)
            if _redfish_session:
                if hasattr(_redfish_session, "model_dump"):
                    redfish_session_values = _redfish_session.model_dump()
                    fields_set = set(
                        getattr(_redfish_session, "model_fields_set", set())
                    )
                    for field_name in RedfishResponseLimits.model_fields:
                        if field_name in fields_set:
                            redfish_session_values[field_name] = getattr(
                                _redfish_session,
                                field_name,
                            )
                    tool_config_dict["redfish_session_config"] = redfish_session_values
                else:
                    tool_config_dict["redfish_session_config"] = _redfish_session
            _ssh_connection_pool = getattr(tool_config, "ssh_connection_pool", None)
            if _ssh_connection_pool is not None:
                tool_config_dict["ssh_connection_pool"] = (
                    _ssh_connection_pool.model_dump()
                    if hasattr(_ssh_connection_pool, "model_dump")
                    else dict(_ssh_connection_pool)
                )
            # Carry the tool-wide SSH trust policy so an operator-configured
            # 'strict' is not silently discarded on the way to the runtime.
            _ssh_policy = getattr(tool_config, "ssh_host_key_policy", None)
            if _ssh_policy is not None:
                tool_config_dict["ssh_host_key_policy"] = _ssh_policy
            _ssh_known_hosts = getattr(tool_config, "ssh_known_hosts_file", None)
            if _ssh_known_hosts is not None:
                tool_config_dict["ssh_known_hosts_file"] = _ssh_known_hosts
        else:
            tool_config_dict = dict(tool_config)
            tool_config_dict["redfish_request_capture"] = (
                RedfishRequestCaptureLimits.from_tool_config(tool_config_dict).as_dict()
            )

        instance.tool_config = tool_config_dict

        if catalog_snapshot is not None:
            spreadsheet_path = tool_config_dict.get("collector_definitions", {}).get(
                "spreadsheet_path"
            )
            if not spreadsheet_path:
                raise ValueError(
                    "an authoritative catalog snapshot requires a configured "
                    "Telemetry Catalog path"
                )
            instance._bind_catalog_snapshot(spreadsheet_path, catalog_snapshot)

        # Log skip flag values for debugging (print to console since logger may not be initialized yet)
        # print(
        #     f"DEBUG: Skip flags loaded from tool config: SKIP_BMC_SSH_LOGS={tool_config_dict.get('SKIP_BMC_SSH_LOGS')}, SKIP_HOST_LOGS={tool_config_dict.get('SKIP_HOST_LOGS')}, SKIP_REDFISH_OOB_LOGS={tool_config_dict.get('SKIP_REDFISH_OOB_LOGS')}, SKIP_IPMI_LOGS={tool_config_dict.get('SKIP_IPMI_LOGS')}"
        # )

        # Convert DUTConfig objects to dictionary format expected by the system
        if dut_configs:
            dut_config_dict = {}
            # Handle both list of objects and dictionary of configs
            if isinstance(dut_configs, dict):
                # dut_configs is already a dictionary of {dut_name: config}
                for dut_name, dut_config in dut_configs.items():
                    if hasattr(dut_config, "__dict__"):
                        if hasattr(dut_config, "model_dump"):
                            dut_values = dut_config.model_dump()
                            explicit = getattr(dut_config, "model_fields_set", set())
                            normalized = sync_legacy_fields(
                                dut_values, explicit_fields=explicit
                            )
                            normalized["__explicit_fields"] = sorted(explicit)
                            referenced = getattr(
                                dut_config, "_referenced_config_data", None
                            )
                            if isinstance(referenced, dict):
                                normalized["__referenced_config_data"] = copy.deepcopy(
                                    referenced
                                )
                            dut_config_dict[dut_name] = normalized
                        else:
                            dut_config_dict[dut_name] = sync_legacy_fields(
                                dict(dut_config.__dict__)
                            )
                    else:
                        dut_config_dict[dut_name] = sync_legacy_fields(dut_config)
            else:
                # dut_configs is a list of objects
                for dut in dut_configs:
                    if hasattr(dut, "__dict__"):
                        if hasattr(dut, "model_dump"):
                            dut_values = dut.model_dump()
                            explicit = getattr(dut, "model_fields_set", set())
                            normalized = sync_legacy_fields(
                                dut_values, explicit_fields=explicit
                            )
                            normalized["__explicit_fields"] = sorted(explicit)
                            referenced = getattr(dut, "_referenced_config_data", None)
                            if isinstance(referenced, dict):
                                normalized["__referenced_config_data"] = copy.deepcopy(
                                    referenced
                                )
                            dut_config_dict[dut.name] = normalized
                        else:
                            dut_config_dict[dut.name] = sync_legacy_fields(
                                dict(dut.__dict__)
                            )
                    else:
                        dut_config_dict[dut.name] = sync_legacy_fields(dut)
            instance.dut_config = dut_config_dict
        else:
            instance.dut_config = {}

        # Load collector definitions and initialize services
        # Note: These will be called in async_init() after logger is assigned
        pass

        return instance

    def _find_config_directory(self) -> Path:
        """
        Find the config directory using the shared utility function.

        After applying local validation, the function forwards current instance
        state to ``find_config_directory`` and preserves its return and
        exception contract.

        Returns:
            The validated config directory filesystem path.
        """
        return find_config_directory()

    async def _load_tool_config(self) -> Dict[str, Any]:
        """
        Load tool configuration from YAML file.

        Ensure additional fields are included with default values if not
        present.

        Returns:
            A mapping containing tool config.
        """
        try:
            self.tool_config = YAMLManager.load_yaml(
                self.tool_config_path, "Tool configuration"
            )
            reject_removed_attachment_limit_setting(self.tool_config)
            explicit_tool_config_fields = {
                key
                for key in self.tool_config.keys()
                if (key.startswith("EXPAND_QUERY_") and key.endswith("_LEVEL"))
                or key in TIMEOUT_CONFIG_OVERRIDE_KEYS
            }
            execution_config = self.tool_config.get("execution_config")
            if "max_concurrent_duts" in self.tool_config or (
                isinstance(execution_config, dict)
                and "max_concurrent_duts" in execution_config
            ):
                explicit_tool_config_fields.add("max_concurrent_duts")

            # Ensure additional fields are included with default values if not present
            additional_fields_defaults = {
                "SKIP_PORT_FW": False,
                "SKIP_BMC_SSH_LOGS": True,
                "SKIP_HOST_LOGS": False,
                "SKIP_IPMI_LOGS": False,
                "SKIP_REDFISH_OOB_LOGS": False,
                "COLLECTOR_TO_SKIP": None,
                "SYSTEM_ID_TO_SKIP": None,
                "CHASSIS_ID_TO_SKIP": None,
                "MANAGER_ID_TO_SKIP": None,
                "EXPAND_QUERY_CHASSIS_LEVEL": 1,
                "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL": 1,
                "EXPAND_QUERY_MANAGER_LEVEL": 1,
                "EXPAND_QUERY_SYSTEM_LEVEL": 1,
                "NVOS_TECH_DUMP_TIMEOUT": 600,
                "REDFISH_DUMP_TIMEOUT": 1500,
                "REDFISH_DEVICE_DUMP_SLEEP_DURATION": 60,
                "BMC_TEMP_DIR": "/tmp",
                "TASK_ID_PREFIX": "",
                "TOOL_TEMP_DIR": "/tmp",
                "FW_INVENTORY_TABLE_PROPERTIES": [],
                "ADDITIONAL_OOB_URI_COLLECTION": [],
                "NVLINK_OOB_URI": [],
                "CUSTOM_DUMP_SERVICES": [],
                "POST_CODES_URI": [],
                "max_pagination_pages": DEFAULT_MAX_PAGINATION_PAGES,
                "max_duplicate_url_retries": 3,
            }

            # Add default values for any missing skip fields
            for field, default_value in additional_fields_defaults.items():
                if field not in self.tool_config:
                    self.tool_config[field] = default_value
                    await self._log_runtime(
                        "DEBUG",
                        f"ConfigManager: Added default value for {field}: {default_value}",
                    )
                else:
                    await self._log_runtime(
                        "DEBUG",
                        f"ConfigManager: {field} already exists in tool_config: {self.tool_config[field]}",
                    )

            self.tool_config["__explicit_tool_config_fields"] = sorted(
                explicit_tool_config_fields
            )

            # Auto-detect spreadsheet path if not already configured
            if "collector_definitions" not in self.tool_config:
                try:
                    from ..utils.spreadsheet_utils import auto_detect_spreadsheet

                    detected_spreadsheet = auto_detect_spreadsheet(
                        None, suppress_print=True
                    )
                    if detected_spreadsheet:
                        self.tool_config["collector_definitions"] = {
                            "spreadsheet_path": str(detected_spreadsheet)
                        }
                        await self._log_runtime(
                            "DEBUG",
                            f"Auto-detected spreadsheet: {detected_spreadsheet}",
                        )
                except Exception as e:
                    await self._log_runtime(
                        "WARNING", f"Could not auto-detect spreadsheet: {e}"
                    )

            return self.tool_config
        except Exception as e:
            await self._log_runtime("ERROR", f"Failed to load tool config: {e}")
            if isinstance(e, RemovedAttachmentLimitError):
                raise
            return {}

    async def _load_dut_config(self) -> None:
        """
        Load DUT configuration with robust error handling and format conversion.

        The implementation uses current instance state to load DUT configuration
        with robust error handling and format conversion. Parsing or I/O must
        finish before the validated representation is made available to the
        caller. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind. It updates ``dut_config`` on
        the instance as part of that state transition. If the function cannot
        load DUT configuration with robust error handling and format conversion,
        its exception reaches the caller instead of being converted into a
        successful result.

        Raises:
            ValueError: If tool configuration baseboard conflicts with
                TargetBaseboard.
        """
        try:
            # Load and validate YAML
            dut_config_data = YAMLManager.load_yaml(
                self.dut_config_path, "DUT configuration"
            )

            # Validate DUT configuration structure
            is_valid, issues = YAMLManager.validate_dut_config(dut_config_data)
            if not is_valid:
                await self._log_runtime(
                    "WARNING", f"DUT configuration validation issues: {issues}"
                )

            # Legacy DUT files kept their baseboard in the tool configuration.
            # Preserve that explicit identity; never invent a replacement
            # platform when neither configuration layer provides one.
            configured_baseboard = self.tool_config.get("baseboard")
            legacy_configured_baseboard = self.tool_config.get("TargetBaseboard")
            if (
                configured_baseboard is not None
                and legacy_configured_baseboard is not None
                and str(configured_baseboard).strip().casefold()
                != str(legacy_configured_baseboard).strip().casefold()
            ):
                raise ValueError(
                    "tool configuration baseboard conflicts with TargetBaseboard"
                )
            if configured_baseboard is None:
                configured_baseboard = legacy_configured_baseboard
            converted_config = YAMLManager.convert_legacy_dut_format(
                dut_config_data,
                default_baseboard=configured_baseboard,
            )

            # Store the converted config in memory (don't write back to original file)
            self.dut_config = converted_config
            await self._log_runtime(
                "INFO", f"Loaded DUT config from {self.dut_config_path}"
            )

        except Exception as e:
            await self._log_runtime("ERROR", f"Failed to load DUT config: {e}")
            self.dut_config = {}

    async def _load_collector_definitions(self) -> None:
        """
        Load collector definitions from Telemetry Catalog spreadsheet.

        Always require a valid spreadsheet path in spreadsheet-only mode.

        Raises:
            FileNotFoundError: If the function cannot load collector definitions
                from Telemetry Catalog spreadsheet safely.
        """
        # Check if spreadsheet path is configured
        spreadsheet_path = self.tool_config.get("collector_definitions", {}).get(
            "spreadsheet_path"
        )

        # Always require a valid spreadsheet path in spreadsheet-only mode
        if not spreadsheet_path or (
            self._catalog_snapshot is None and not Path(spreadsheet_path).exists()
        ):
            error_msg = "No valid Telemetry Catalog spreadsheet found. Please provide a spreadsheet via --spreadsheet argument."
            if self.sanitized_console:
                self.sanitized_console.print_error(error_msg)
            elif (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "logger")
            ):
                asyncio.create_task(
                    self.orchestrator.logger.log_runtime(
                        "ERROR", "ConfigurationManager", error_msg
                    )
                )
            raise FileNotFoundError(error_msg)

        try:
            catalog_snapshot = self._catalog_snapshot_for_path(spreadsheet_path)
        except FileNotFoundError:
            error_msg = "No valid Telemetry Catalog spreadsheet found. Please provide a spreadsheet via --spreadsheet argument."
            if self.sanitized_console:
                self.sanitized_console.print_error(error_msg)
            raise FileNotFoundError(error_msg) from None

        # Use the provided spreadsheet path
        if not self.quiet_mode:
            if self.sanitized_console:
                self.sanitized_console.print_debug(
                    f"Loading from provided spreadsheet: {spreadsheet_path}"
                )
            elif (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "logger")
            ):
                asyncio.create_task(
                    self.orchestrator.logger.log_runtime(
                        "DEBUG",
                        "ConfigurationManager",
                        f"Loading from provided spreadsheet: {spreadsheet_path}",
                    )
                )
        await self._load_from_spreadsheet(
            spreadsheet_path,
            catalog_snapshot=catalog_snapshot,
        )

    def _catalog_snapshot_for_path(self, spreadsheet_path: str) -> CatalogSnapshot:
        """
        Capture or return this manager's one authoritative catalog snapshot.

        The implementation uses ``spreadsheet_path`` to capture or return this
        manager's one authoritative catalog snapshot. It updates
        ``_catalog_snapshot`` and ``_catalog_snapshot_source`` on the instance
        as part of that state transition. If the function cannot capture or
        return this manager's one authoritative catalog snapshot, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            spreadsheet_path: filesystem location used as the spreadsheet path
                for this operation.

        Returns:
            A ``CatalogSnapshot`` representing catalog snapshot for path.

        Raises:
            ValueError: If telemetry Catalog path changed after its runtime
                snapshot was captured.
        """

        source_key = str(Path(spreadsheet_path).absolute())
        if self._catalog_snapshot is not None:
            if self._catalog_snapshot_source != source_key:
                raise ValueError(
                    "Telemetry Catalog path changed after its runtime snapshot "
                    "was captured"
                )
            return self._catalog_snapshot

        snapshot = read_catalog_snapshot(spreadsheet_path)
        self._catalog_snapshot = snapshot
        self._catalog_snapshot_source = source_key
        return snapshot

    def _bind_catalog_snapshot(
        self,
        spreadsheet_path: str | Path,
        catalog_snapshot: CatalogSnapshot,
    ) -> None:
        """
        Bind the exact snapshot already consumed during CLI resolution.

        The implementation uses ``spreadsheet_path`` and ``catalog_snapshot`` to
        bind the exact snapshot already consumed during CLI resolution. It
        updates ``_catalog_snapshot``, ``_catalog_snapshot_prebound``, and
        ``_catalog_snapshot_source`` on the instance as part of that state
        transition. If the function cannot bind the exact snapshot already
        consumed during CLI resolution, its exception reaches the caller instead
        of being converted into a successful result.

        Args:
            spreadsheet_path: filesystem location used as the spreadsheet path
                for this operation.
            catalog_snapshot: Catalog snapshot consumed while the function
                attempts to bind the exact snapshot already consumed during CLI
                resolution.

        Raises:
            TypeError: If the catalog_snapshot is not an immutable
                CatalogSnapshot.
            ValueError: If telemetry Catalog snapshot authority cannot be
                replaced.
        """

        if not isinstance(catalog_snapshot, CatalogSnapshot):
            raise TypeError("catalog_snapshot must be an immutable CatalogSnapshot")
        source_key = str(Path(spreadsheet_path).absolute())
        if self._catalog_snapshot is not None:
            if (
                self._catalog_snapshot_source != source_key
                or self._catalog_snapshot is not catalog_snapshot
            ):
                raise ValueError(
                    "Telemetry Catalog snapshot authority cannot be replaced"
                )
            self._catalog_snapshot_prebound = True
            return
        self._catalog_snapshot = catalog_snapshot
        self._catalog_snapshot_source = source_key
        self._catalog_snapshot_prebound = True

    async def _initialize_uri_config_manager(self) -> None:
        """
        Initialize URI configuration manager with tool and DUT-specific overrides.

        The implementation uses current instance state to initialize URI
        configuration manager with tool and DUT-specific overrides. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. It updates ``dgx_diagnostic_routing_profile``
        and ``uri_config_manager`` on the instance as part of that state
        transition. If the function cannot initialize URI configuration manager
        with tool and DUT-specific overrides, its exception reaches the caller
        instead of being converted into a successful result.

        Raises:
            ValueError: If cannot initialize Redfish URI policy without a
                Telemetry Catalog; or configure either uri_overrides or
                uri_config_file, not both.
        """
        # Reinitialization is transactional at the manager boundary: never let
        # callers continue with a stale instance after a new policy fails.
        self.uri_config_manager = None
        self.dgx_diagnostic_routing_profile = None
        try:
            spreadsheet_path = self.tool_config.get("collector_definitions", {}).get(
                "spreadsheet_path"
            )
            if not spreadsheet_path:
                raise ValueError(
                    "Cannot initialize Redfish URI policy without a Telemetry Catalog"
                )

            catalog_snapshot = self._catalog_snapshot_for_path(spreadsheet_path)
            topology_profile = load_catalog_global_profile(
                catalog_snapshot,
                REDFISH_TOPOLOGY_PROFILE_KEY,
                validate_redfish_topology_profile,
            )
            topology_resource_uris = build_redfish_resource_uri_lookup(topology_profile)
            routing_profile = load_catalog_global_profile(
                catalog_snapshot,
                DGX_DIAGNOSTIC_ROUTING_PROFILE_KEY,
                lambda value: validate_dgx_diagnostic_routing_profile(
                    value,
                    allowed_collection_uri_keys=topology_resource_uris,
                ),
            )
            validate_dgx_diagnostic_route_hooks(
                self.collector_definitions.get("collectors", {}),
                routing_profile,
            )
            uri_overrides = self.tool_config.get("uri_overrides")
            uri_config_file = self.tool_config.get("uri_config_file")
            uri_overrides_supplied = (
                "uri_overrides" in self.tool_config and uri_overrides is not None
            )
            uri_config_file_supplied = uri_config_file not in (None, "")

            if uri_overrides_supplied and uri_config_file_supplied:
                raise ValueError(
                    "Configure either uri_overrides or uri_config_file, not both"
                )

            if uri_overrides_supplied:
                await self._log_runtime(
                    "INFO",
                    "Initializing URI config manager with inline tool config overrides",
                )
            elif uri_config_file_supplied:
                await self._log_runtime(
                    "INFO",
                    f"Initializing URI config manager with file: {uri_config_file}",
                )
            else:
                await self._log_runtime(
                    "INFO",
                    "Initializing URI config manager from the Telemetry Catalog",
                )

            self.uri_config_manager = URIConfigManager(
                uri_config_file,
                topology_profile=topology_profile,
                tool_uri_overrides=uri_overrides,
            )
            self.dgx_diagnostic_routing_profile = routing_profile
            await self._load_dut_uri_configs()
        except Exception as error:
            self.uri_config_manager = None
            self.dgx_diagnostic_routing_profile = None
            await self._log_runtime(
                "ERROR", f"Failed to initialize URI config manager: {error}"
            )
            raise

    async def _load_dut_uri_configs(self) -> None:
        """
        Load URI configurations for all DUTs from their individual configurations.

        Load DUT-specific config file if ConfigFileToUse is specified.

        Raises:
            Exception: If the URI configurations cannot be loaded.
        """
        if not self.uri_config_manager:
            return

        try:
            for dut_id, dut_config in self.dut_config.items():
                if dut_id != "DUT_Defaults":
                    # Load DUT-specific config file if ConfigFileToUse is specified
                    dut_config_with_overrides = await self._load_dut_specific_config(
                        dut_id, dut_config
                    )
                    self.uri_config_manager.load_dut_uri_config(
                        dut_id, dut_config_with_overrides
                    )

        except Exception as error:
            await self._log_runtime("ERROR", f"Failed to load DUT URI configs: {error}")
            raise

    async def _load_dut_specific_config(
        self, dut_id: str, dut_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Load DUT-specific configuration file if ConfigFileToUse is specified.

        The implementation uses ``dut_id`` and ``dut_config`` to load
        DUT-specific configuration file if ConfigFileToUse is specified. Parsing
        or I/O must finish before the validated representation is made available
        to the caller. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut_config: DUT config governing DUT-specific configuration file if
                ConfigFileToUse is specified.

        Returns:
            A mapping containing DUT specific config.
        """
        try:
            config_file_to_use = dut_config.get("ConfigFileToUse")
            if not config_file_to_use:
                return dut_config

            # Load the DUT-specific config file
            await self._log_runtime(
                "INFO",
                f"Loading DUT-specific config for {dut_id}: {config_file_to_use}",
            )
            retained_snapshot = dut_config.get("__referenced_config_data")
            if isinstance(retained_snapshot, dict):
                dut_specific_config = copy.deepcopy(retained_snapshot)
            else:
                dut_specific_config = YAMLManager.load_yaml(
                    config_file_to_use, f"DUT-specific config for {dut_id}"
                )

            # Merge configurations: DUT config overrides DUT-specific config
            merged_config = merge_dut_config_layers(dut_specific_config, dut_config)

            await self._log_runtime(
                "INFO", f"Successfully loaded DUT-specific config for {dut_id}"
            )
            return merged_config

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                f"Failed to load DUT-specific config for {dut_id}: {e}",
            )
            raise

    async def _load_from_spreadsheet(
        self,
        spreadsheet_path: str,
        *,
        catalog_snapshot: Optional[CatalogSnapshot] = None,
    ) -> None:
        """
        Load collector definitions from Excel spreadsheet.

        Read the spreadsheet Don't treat "N/A" as NaN since it's a valid value
        meaning "not applicable".

        Args:
            spreadsheet_path: filesystem location used as the spreadsheet path
                for this operation.
            catalog_snapshot: Optional catalog snapshot; ``None`` selects the
                function's default behavior.

        Raises:
            Exception: If the spreadsheet cannot be loaded.
        """
        try:
            # Read the spreadsheet
            # Don't treat "N/A" as NaN since it's a valid value meaning "not applicable"
            if catalog_snapshot is None:
                # Direct/lightweight callers retain path compatibility.  The
                # production loader always supplies its pinned snapshot.
                df = excel_reader.read_excel(
                    spreadsheet_path,
                    sheet_name="Log Collection Catalog",
                    keep_default_na=False,
                )
            else:
                df = catalog_snapshot.read_excel(
                    "Log Collection Catalog",
                    keep_default_na=False,
                )
            if self.sanitized_console and not self.quiet_mode:
                self.sanitized_console.print_debug(
                    f"Read spreadsheet with {len(df)} rows"
                )

            catalog_columns = list(df.columns)
            if catalog_columns.count("ID") != 1:
                if "ID" not in catalog_columns:
                    raise ValueError(
                        "Telemetry Catalog is missing required columns: ID"
                    )
                raise ValueError("Telemetry Catalog has duplicate required columns: ID")

            # Convert to dictionary format
            collectors = {}
            for row_index, row in df.iterrows():
                collector_id = row.get("ID", "")
                if collector_id:
                    excel_row = int(row_index) + 2
                    if collector_id in collectors:
                        raise ValueError(
                            "Telemetry Catalog has duplicate collector ID "
                            f"{collector_id!r} at Excel row {excel_row}"
                        )
                    dependencies = _decode_catalog_json_object(
                        row.get("Dependencies"),
                        collector_id=collector_id,
                        column_name="Dependencies",
                        excel_row=excel_row,
                    )
                    redfish_capability = _decode_catalog_json_object(
                        row.get("Redfish Capability"),
                        collector_id=collector_id,
                        column_name="Redfish Capability",
                        excel_row=excel_row,
                    )
                    outcome_policy = _decode_catalog_json_object(
                        row.get("Outcome Policy"),
                        collector_id=collector_id,
                        column_name="Outcome Policy",
                        excel_row=excel_row,
                    )
                    runtime_budget = _decode_catalog_json_object(
                        row.get("Runtime Budget"),
                        collector_id=collector_id,
                        column_name="Runtime Budget",
                        excel_row=excel_row,
                    )
                    resource_profile = _decode_catalog_json_object(
                        row.get("Resource Profile"),
                        collector_id=collector_id,
                        column_name="Resource Profile",
                        excel_row=excel_row,
                    )
                    parse_collector_resource_profile(
                        resource_profile,
                        context=(
                            f"Log Collection Catalog row {excel_row}, "
                            f"collector {collector_id}"
                        ),
                    )
                    debug_capture = _decode_catalog_json_object(
                        row.get("Debug Capture"),
                        collector_id=collector_id,
                        column_name="Debug Capture",
                        excel_row=excel_row,
                    )
                    stages = _decode_catalog_json_object(
                        row.get("Stages"),
                        collector_id=collector_id,
                        column_name="Stages",
                        excel_row=excel_row,
                    )
                    diagnostic_concurrency_profile_for_collector(
                        {"stages": stages},
                        collector_id=str(collector_id),
                    )

                    # Parse applicable baseboards
                    applicable_baseboards = []

                    # First try the single column format. Blank strings are
                    # common in catalog sheets that use per-baseboard columns,
                    # so only treat the single column as authoritative when it
                    # contains at least one baseboard name.
                    applicable_str = ""
                    raw_applicable = row.get("applicable_baseboards")
                    if (
                        not excel_reader.notna(raw_applicable)
                        or not str(raw_applicable).strip()
                    ):
                        raw_applicable = row.get("Applicable Baseboards")
                    if excel_reader.notna(raw_applicable):
                        applicable_str = str(raw_applicable).strip()

                    if applicable_str:
                        if applicable_str.lower() == "all":
                            applicable_baseboards = ["all"]
                        else:
                            applicable_baseboards = [
                                b.strip()
                                for b in applicable_str.split(",")
                                if b.strip()
                            ]
                    else:
                        # Try the individual column format (e.g., "Applicable for Blackwell-HGX-8-GPU")
                        for col in df.columns:
                            if col.startswith("Applicable for "):
                                value = row.get(col)
                                # Skip if cell is empty (NaN) or contains "N/A" (not applicable)
                                if (
                                    excel_reader.notna(value)
                                    and str(value).strip().upper() != "N/A"
                                ):
                                    value_str = str(value).strip().lower()
                                    if value_str in ["yes", "true", "1"]:
                                        baseboard_name = col.replace(
                                            "Applicable for ", ""
                                        )
                                        applicable_baseboards.append(baseboard_name)

                    # Add default use_sudo for host collectors that need it
                    use_sudo = False
                    if row.get("Collection Group", "").lower() == "host":
                        # Check if the stages contain execution hooks that need sudo
                        if stages and "execution" in stages:
                            execution_hooks = stages["execution"].get("hooks", [])
                            for hook in execution_hooks:
                                if hook.get("method") == "collect_host_unified":
                                    # Host collectors with collect_host_unified
                                    # default to sudo, but an explicit false is
                                    # part of the collector contract and must
                                    # survive spreadsheet round-trips.
                                    params = hook.get("params")
                                    if isinstance(params, dict):
                                        params.setdefault("use_sudo", True)
                                        use_sudo = bool(params["use_sudo"])
                                    else:
                                        use_sudo = True
                                    break

                    exclude_baseboards = []
                    raw_excluded = row.get("exclude_baseboards")
                    if (
                        not excel_reader.notna(raw_excluded)
                        or not str(raw_excluded).strip()
                    ):
                        raw_excluded = row.get("Exclude Baseboards")
                    if excel_reader.notna(raw_excluded) and str(raw_excluded).strip():
                        exclude_baseboards = [
                            baseboard.strip()
                            for baseboard in str(raw_excluded).split(",")
                            if baseboard.strip()
                        ]

                    raw_tags = row.get("Tags", "")
                    tags = []
                    if excel_reader.notna(raw_tags) and str(raw_tags).strip():
                        tags = [
                            tag.strip()
                            for tag in str(raw_tags).replace("|", ",").split(",")
                            if tag.strip()
                        ]

                    raw_family = row.get("Family", "")
                    family = (
                        str(raw_family).strip()
                        if excel_reader.notna(raw_family)
                        else ""
                    )
                    raw_category = row.get("Category", "")
                    category = (
                        str(raw_category).strip()
                        if excel_reader.notna(raw_category)
                        else ""
                    )

                    collectors[collector_id] = {
                        "collector_id": collector_id,
                        "name": row.get("Collector Name", ""),
                        "group": row.get("Collection Group", ""),
                        "family": family,
                        "category": category,
                        "tags": tags,
                        "description": row.get("Description", ""),
                        "action_type": row.get("Action Type", ""),
                        "report_role": (
                            str(row.get("Report Role", "")).strip().lower()
                            if excel_reader.notna(row.get("Report Role", ""))
                            else ""
                        ),
                        "collection_level": row.get("Collection Level", "L1"),
                        "timeout": row.get("Timeout", 300),
                        "retry_count": row.get("Retry Count", 3),
                        "sequential_execution": row.get("Sequential Execution", False),
                        "enforce_wall_timeout": str(
                            row.get("Enforce Wall Timeout", False)
                        )
                        .strip()
                        .lower()
                        in {"true", "1", "yes"},
                        "applicable_baseboards": applicable_baseboards,
                        "exclude_baseboards": exclude_baseboards,
                        "dependencies": dependencies,
                        "redfish_capability": redfish_capability,
                        "outcome_policy": outcome_policy,
                        "runtime_budget": runtime_budget,
                        "resource_profile": resource_profile,
                        "debug_capture": debug_capture,
                        "stages": stages,
                        "enabled": row.get("Enabled", True),
                        "streaming_candidate": bool(
                            row.get("Streaming Candidate", False)
                        ),
                        "use_sudo": use_sudo,
                    }
                    execution_phase = row.get("Execution Phase", "")
                    if (
                        excel_reader.notna(execution_phase)
                        and str(execution_phase).strip()
                    ):
                        collectors[collector_id]["execution_phase"] = str(
                            execution_phase
                        ).strip()
                    execution_order = row.get("Execution Order", "")
                    if (
                        excel_reader.notna(execution_order)
                        and str(execution_order).strip()
                    ):
                        try:
                            collectors[collector_id]["execution_order"] = int(
                                execution_order
                            )
                        except (TypeError, ValueError):
                            collectors[collector_id]["execution_order"] = str(
                                execution_order
                            ).strip()

            self.collector_definitions = {"collectors": collectors}
            if not self.quiet_mode:
                if self.sanitized_console:
                    self.sanitized_console.print_debug(
                        f"Loaded {len(collectors)} collectors from spreadsheet: {spreadsheet_path}"
                    )
                elif (
                    hasattr(self, "orchestrator")
                    and self.orchestrator
                    and hasattr(self.orchestrator, "logger")
                ):
                    asyncio.create_task(
                        self.orchestrator.logger.log_runtime(
                            "DEBUG",
                            "ConfigurationManager",
                            f"Loaded {len(collectors)} collectors from spreadsheet: {spreadsheet_path}",
                        )
                    )
            # Only log debug info if not in quiet mode
            if not self.quiet_mode:
                await self._log_runtime(
                    "INFO",
                    f"Loaded {len(collectors)} collectors from spreadsheet: {spreadsheet_path}",
                )

        except Exception as e:
            if self.sanitized_console:
                self.sanitized_console.print_error(
                    f"Failed to load collector definitions from spreadsheet: {e}"
                )
                self.sanitized_console.print_error(
                    f"Spreadsheet path: {spreadsheet_path}"
                )
                self.sanitized_console.print_error(
                    f"Exception details: {type(e).__name__}: {str(e)}"
                )
            self.collector_definitions = {"collectors": {}}
            raise

    async def _initialize_services(self) -> None:
        """
        Initialize service instances.

        The implementation uses current instance state to initialize service
        instances. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. It updates
        ``services`` on the instance as part of that state transition.

        Raises:
            Exception: If the services cannot be initialized.
        """
        self.services = {
            "redfish": RedfishService("redfish", None),
            "ipmi": IPMIService("ipmi", None),
            "host": HostService("host", None),
            "ssh": BMCSSHService("ssh", None),
            "health_check": HealthCheckService("health_check", None),
        }
        await self._log_runtime("INFO", f"Initialized {len(self.services)} services")

    async def set_orchestrator_reference(self, orchestrator: Any) -> None:
        """
        Set orchestrator reference.

        The implementation uses ``orchestrator`` to set orchestrator reference.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            orchestrator: Orchestrator consumed while the function attempts to
                set orchestrator reference.
        """
        for service_name, service in self.services.items():
            if hasattr(service, "set_orchestrator"):
                service.set_orchestrator(orchestrator)
                await self._log_runtime(
                    "DEBUG",
                    f"ConfigManager: Set orchestrator reference for {service_name} service",
                )

    async def _categorize_collectors(self) -> None:
        """
        Categorize collectors as sequential or parallel.

        The implementation uses current instance state to categorize collectors
        as sequential or parallel. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Raises:
            Exception: If the collectors cannot be categorized.
        """
        collectors = self.collector_definitions.get("collectors", {})

        for collector_id, collector_info in collectors.items():
            is_sequential = collector_info.get("sequential_execution", False)
            if is_sequential:
                self.sequential_collectors.add(collector_id)
                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} categorized as SEQUENTIAL",
                )
            else:
                self.parallel_collectors.add(collector_id)
                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} categorized as PARALLEL",
                )

        # Log categorization summary
        await self._log_runtime(
            "INFO",
            f"Categorized collectors: {len(self.sequential_collectors)} sequential, {len(self.parallel_collectors)} parallel",
        )

        # Log some examples for debugging
        sequential_examples = list(self.sequential_collectors)[:5]
        parallel_examples = list(self.parallel_collectors)[:5]
        await self._log_runtime("INFO", f"Sequential examples: {sequential_examples}")
        await self._log_runtime("INFO", f"Parallel examples: {parallel_examples}")

    async def initialize_collector_categorization(self) -> None:
        """
        Initialize collector categorization after logger is assigned.

        The implementation uses current instance state to initialize collector
        categorization after logger is assigned. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Raises:
            Exception: If the collectors cannot be categorized.
        """
        if not self.sequential_collectors and not self.parallel_collectors:
            # Only categorize if not already done
            await self._categorize_collectors()

        # Test logging to see if it's working
        await self._log_runtime(
            "INFO", "ConfigManager: Collector categorization initialized"
        )

    async def initialize_minimal(self) -> None:
        """
        Minimal initialization for validation - only loads collector definitions.

        The implementation uses current instance state to minimal initialization
        for validation - only loads collector definitions. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.
        """
        # Only load collector definitions for validation
        await self._load_collector_definitions()

    async def async_init(self) -> None:
        """
        Async initialization - called after sync __init__.

        Loads all configurations, initializes services, and categorizes
        collectors.
        """
        # Load all configurations if not already loaded
        if (
            hasattr(self, "tool_config_path")
            and self.tool_config_path
            and hasattr(self, "dut_config_path")
            and self.dut_config_path
        ):
            # File-based initialization
            await self._load_tool_config()
            # Skip DUT config loading in simple mode (when sanitized_console is available)
            if not hasattr(self, "sanitized_console") or not self.sanitized_console:
                await self._load_dut_config()
            await self._load_collector_definitions()
            await self._initialize_uri_config_manager()
            await self._initialize_services()
        else:
            # Object-based initialization
            await self._load_collector_definitions()
            await self._initialize_uri_config_manager()
            await self._initialize_services()

        # Initialize collector categorization
        await self.initialize_collector_categorization()

    def get_all_collectors(self) -> Dict[str, Any]:
        """
        Get all collector definitions.

        After applying local validation, the function forwards current instance
        state to ``self.collector_definitions.get`` and preserves its return and
        exception contract.

        Returns:
            A mapping containing all collectors.
        """
        return self.collector_definitions.get("collectors", {})

    def get_catalog_snapshot_facts(self) -> Optional[CatalogSnapshotFacts]:
        """
        Return bounded facts for the exact catalog consumed by this run.

        The implementation uses current instance state to produce bounded facts
        for the exact catalog consumed by this run.

        Returns:
            A ``CatalogSnapshotFacts`` representing catalog snapshot facts, or
            ``None`` when the requested value is unavailable.
        """

        if self._catalog_snapshot is None:
            return None
        return self._catalog_snapshot.facts

    def get_catalog_snapshot(self) -> Optional[CatalogSnapshot]:
        """
        Return the opaque runtime catalog capability to workbook consumers.

        The implementation uses current instance state to produce the opaque
        runtime catalog capability to workbook consumers.

        Returns:
            A ``CatalogSnapshot`` representing catalog snapshot, or ``None``
            when the requested value is unavailable.
        """

        return self._catalog_snapshot

    def has_prebound_catalog_snapshot(self) -> bool:
        """
        Return whether external resolution and runtime share one byte authority.

        The implementation uses current instance state to determine whether
        external resolution and runtime share one byte authority.

        Returns:
            Whether external resolution and runtime share one byte authority.
        """

        return self._catalog_snapshot_prebound

    def get_sequential_collectors(self) -> Set[str]:
        """
        Get set of sequential collector IDs.

        The implementation uses current instance state to get set of sequential
        collector IDs.

        Returns:
            The unique sequential collectors returned by the operation.
        """
        return self.sequential_collectors

    def get_parallel_collectors(self) -> Set[str]:
        """
        Get set of parallel collector IDs.

        The implementation uses current instance state to get set of parallel
        collector IDs.

        Returns:
            The unique parallel collectors returned by the operation.
        """
        return self.parallel_collectors

    def get_uri_config_manager(self) -> Optional[URIConfigManager]:
        """
        Get the URI configuration manager.

        The implementation uses current instance state to get the URI
        configuration manager.

        Returns:
            An ``URIConfigManager`` representing URI config manager, or ``None``
            when the requested value is unavailable.
        """
        return self.uri_config_manager

    def get_collector_info(self, collector_id: str) -> Dict[str, Any]:
        """
        Get collector information by ID.

        After applying local validation, the function forwards ``collector_id``
        to ``collectors.get`` and preserves its return and exception contract.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A mapping containing collector info.
        """
        collectors = self.collector_definitions.get("collectors", {})
        return collectors.get(collector_id, {})

    def get_collectors_for_group(self, group: str) -> Dict[str, Any]:
        """
        Get all collectors for a specific group based on service mappings.

        Use service mapping to determine group membership This ensures
        consistency with how groups are used throughout the system.

        Args:
            group: Text supplied as group in the format accepted by this
                function.

        Returns:
            The validated ``collectors``.
        """
        collectors = {}
        all_collectors = self.collector_definitions.get("collectors", {})
        for collector_id, collector_info in all_collectors.items():
            # Use service mapping to determine group membership
            # This ensures consistency with how groups are used throughout the system
            service_name = CollectorServiceMapping.get_service_from_collector_id(
                collector_id
            )
            if service_name == group:
                collectors[collector_id] = collector_info
        return collectors

    def get_all_collector_groups(self) -> List[str]:
        """
        Get all unique collector groups based on service mappings.

        Use service mapping instead of group name from definition This ensures
        consistency between initialization and updates.

        Returns:
            The all collector groups returned in operation-defined order.
        """
        from ..utils.enums import CollectorServiceMapping

        groups = set()
        all_collectors = self.collector_definitions.get("collectors", {})
        for collector_id in all_collectors.keys():
            # Use service mapping instead of group name from definition
            # This ensures consistency between initialization and updates
            service_name = CollectorServiceMapping.get_service_from_collector_id(
                collector_id
            )
            if service_name and service_name != "unknown":
                groups.add(service_name)
        return list(groups)

    def get_services(self) -> Dict[str, BaseService]:
        """
        Get all service instances.

        The implementation uses current instance state to get all service
        instances.

        Returns:
            A mapping containing services.
        """
        return self.services

    def get_tool_config(self) -> Dict[str, Any]:
        """
        Get tool configuration.

        The implementation uses current instance state to get tool
        configuration.

        Returns:
            A mapping containing tool config.
        """
        return self.tool_config

    async def get_dut_specific_tool_config(self, dut_id: str) -> Dict[str, Any]:
        """
        Get tool configuration with DUT-specific overrides.

        This method merges the global tool config with any DUT-specific tool
        config options found in the DUT's ConfigFileToUse.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing DUT specific tool config.
        """
        # Start with the global tool config
        merged_tool_config = self.tool_config.copy()

        try:
            # Get the DUT config
            dut_config = self.dut_config.get(dut_id, {})
            if not dut_config:
                return merged_tool_config

            # Only source-present DUT values may override the global tool config.
            dut_tool_fields = ("TASK_ID_PREFIX", "TOOL_TEMP_DIR")
            explicit_fields = dut_config.get("__explicit_fields")
            if explicit_fields is None:
                explicit_fields = dut_config
            for field in dut_tool_fields:
                if field in explicit_fields and field in dut_config:
                    merged_tool_config[field] = dut_config[field]

            # Check if DUT has a ConfigFileToUse
            config_file_to_use = dut_config.get("ConfigFileToUse")
            if not config_file_to_use:
                return merged_tool_config

            # Load the DUT-specific config file
            await self._log_runtime(
                "INFO",
                f"Loading DUT-specific tool config for {dut_id}: {config_file_to_use}",
            )
            retained_snapshot = dut_config.get("__referenced_config_data")
            if isinstance(retained_snapshot, dict):
                dut_specific_config = copy.deepcopy(retained_snapshot)
            else:
                dut_specific_config = YAMLManager.load_yaml(
                    config_file_to_use, f"DUT-specific config for {dut_id}"
                )

            # Extract tool config sections from DUT-specific config
            # Look for tool config sections that might override global settings
            tool_config_sections = [
                "execution_config",
                "output",
                "logging",
                "collection_config",
                "skip_zip",
                "skip_zip_split",
                "zip_split_threshold",
                "timeout",
                "retry_count",
                "collection_level",
                "skip_preflight",
                "skip_sanitization",
                "skip_html_reports",
                "redfish_session_config",
                "preflight_config",
                # Global fields that can be overridden per-DUT
                "TASK_ID_PREFIX",
                "TOOL_TEMP_DIR",
                "max_pagination_pages",
                # Streaming configuration
                "streaming_only",
                "stream_begin",
                "stream_end",
                "stream_destination",
                "append",
                "rack_id",
                # I2C configuration (device addresses, bus numbers, etc.)
                "i2c_config",
            ]

            # Merge tool config sections from DUT-specific config
            for section in tool_config_sections:
                if section in dut_tool_fields and section in explicit_fields:
                    continue
                if section in dut_specific_config:
                    if section in merged_tool_config:
                        # Merge nested sections
                        if isinstance(merged_tool_config[section], dict) and isinstance(
                            dut_specific_config[section], dict
                        ):
                            merged_tool_config[section] = {
                                **merged_tool_config[section],
                                **dut_specific_config[section],
                            }
                        else:
                            # Override simple values
                            merged_tool_config[section] = dut_specific_config[section]
                    else:
                        # Add new section
                        merged_tool_config[section] = dut_specific_config[section]

            await self._log_runtime(
                "INFO",
                f"Successfully merged DUT-specific tool config for {dut_id}",
            )
            return merged_tool_config

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                f"Failed to load DUT-specific tool config for {dut_id}: {e}",
            )
            raise

    def get_dut_config(self) -> Dict[str, Any]:
        """
        Get DUT configuration.

        The implementation uses current instance state to get DUT configuration.

        Returns:
            A mapping containing DUT config.
        """
        return self.dut_config

    def get_collector_definitions(self) -> Dict[str, Any]:
        """
        Get collector definitions.

        The implementation uses current instance state to get collector
        definitions.

        Returns:
            A mapping containing collector definitions.
        """
        return self.collector_definitions

    def get_dgx_diagnostic_routing_profile(self) -> Dict[str, Any]:
        """
        Return a defensive validated copy of catalog-owned DGX routing.

        After applying local validation, the function forwards current instance
        state to ``validate_dgx_diagnostic_routing_profile`` and preserves its
        return and exception contract.

        Returns:
            A mapping containing dgx diagnostic routing profile.

        Raises:
            RuntimeError: If DGX diagnostic routing profile is not initialized.
        """

        if self.dgx_diagnostic_routing_profile is None:
            raise RuntimeError("DGX diagnostic routing profile is not initialized")
        return validate_dgx_diagnostic_routing_profile(
            self.dgx_diagnostic_routing_profile
        )

    def get_dgx_diagnostic_route(self, route_name: str) -> Dict[str, Any]:
        """
        Return one defensive validated catalog-owned DGX route.

        After applying local validation, the function forwards ``route_name`` to
        ``get_dgx_diagnostic_route`` and preserves its return and exception
        contract.

        Args:
            route_name: Stable route name used for lookup and operator-facing
                diagnostics.

        Returns:
            A mapping containing dgx diagnostic route.
        """

        return get_dgx_diagnostic_route(
            self.get_dgx_diagnostic_routing_profile(),
            route_name,
        )

    def set_orchestrator(self, orchestrator) -> None:
        """
        Set the orchestrator reference in all services.

        Use setter to ensure dependent refs are populated safely.

        Args:
            orchestrator: Orchestrator consumed while the function attempts to
                set the orchestrator reference in all services.
        """
        for service in self.services.values():
            # Use setter to ensure dependent refs are populated safely
            if hasattr(service, "set_orchestrator"):
                service.set_orchestrator(orchestrator)
            else:
                service.orchestrator = orchestrator
