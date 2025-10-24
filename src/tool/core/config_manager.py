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
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pandas as pd
import yaml

from ..services.base_service import BaseService
from ..services.bmc_ssh_service import BMCSSHService
from ..services.health_check_service import HealthCheckService
from ..services.host_service import HostService
from ..services.ipmi_service import IPMIService
from ..services.redfish_service import RedfishService
from ..utils import get_tool_resource, get_tool_resource_content
from ..utils.dependency_checker import DependencyChecker
from ..utils.enums import CollectorServiceMapping
from ..utils.resources import find_config_directory
from ..utils.uri_config_manager import URIConfigManager
from ..utils.yaml_manager import YAMLManager

# Standard logger for fallback
logger = logging.getLogger(__name__)


class ConfigurationManager:
    """
    Manages all configuration loading and service initialization.

    Handles loading of tool configuration, DUT configuration, collector definitions,
    and initializes services for each DUT.

    Attributes:
        tool_config_path: Path to tool configuration file.
        dut_config_path: Path to DUT configuration file.
        sanitized_console: Console for output.
        quiet_mode: Whether to suppress output.
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

        Args:
            tool_config_path (str): Path to tool config file.
            dut_config_path (str): Path to DUT config file.
            sanitized_console: Sanitized console instance.
            quiet_mode (bool): Suppress output messages.
        """
        self.tool_config_path = tool_config_path
        self.dut_config_path = dut_config_path
        self.sanitized_console = sanitized_console
        self.quiet_mode = quiet_mode

        # Configuration storage
        self.tool_config: Dict[str, Any] = {}
        self.dut_config: Dict[str, Any] = {}
        self.collector_definitions: Dict[str, Any] = {}

        # Service instances
        self.services: Dict[str, BaseService] = {}

        # Collector categorization
        self.sequential_collectors: Set[str] = set()
        self.parallel_collectors: Set[str] = set()

        # URI configuration manager
        self.uri_config_manager: Optional[URIConfigManager] = None

        # Load all configurations
        if tool_config_path and dut_config_path:
            # Note: These will be called in async_init() after logger is assigned
            pass

    async def _log_runtime(self, level: str, message: str) -> None:
        """
        Log message using async logger if available, otherwise fall back to standard logger.

        Args:
            level: Log level (ERROR, WARNING, DEBUG, INFO).
            message: Message to log.
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
    ):
        """
        Create ConfigurationManager from ToolConfig and DUTConfig objects.

        Args:
            tool_config: ToolConfig object or dictionary.
            dut_configs: DUTConfig objects (list or dictionary).
            sanitized_console: Optional sanitized console for output.
            quiet_mode: Whether to suppress output.

        Returns:
            ConfigurationManager instance.
        """
        instance = cls(sanitized_console=sanitized_console, quiet_mode=quiet_mode)

        # Convert ToolConfig object to dictionary format expected by the system
        if hasattr(tool_config, "__dict__"):

            config_dir = instance._find_config_directory()

            tool_config_dict = {
                "execution_config": {
                    "max_concurrent_duts": tool_config.max_concurrent_duts,
                    "max_concurrent_collectors_per_dut": tool_config.max_concurrent_collectors_per_dut,
                    "timeout": getattr(
                        tool_config, "timeout", 300
                    ),  # Default timeout of 300 seconds
                    "retry_count": tool_config.retry_count,
                },
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
                "skip_html_reports": getattr(tool_config, "skip_html_reports", False),
                "skip_auto_parse": getattr(tool_config, "skip_auto_parse", False),
                "collector_id": getattr(tool_config, "collector_id", None),
                "collector_group": getattr(tool_config, "collector_group", None),
                "skip_collectors": getattr(tool_config, "skip_collectors", None),
                "include_collectors": getattr(tool_config, "include_collectors", None),
                "enable_status_tracking": getattr(
                    tool_config, "enable_status_tracking", True
                ),
                "disable_live_display": getattr(
                    tool_config, "disable_live_display", False
                ),
                "parallel_dut_sequential_collectors": getattr(
                    tool_config, "parallel_dut_sequential_collectors", True
                ),
                "service_grouped_sequential_collectors": getattr(
                    tool_config, "service_grouped_sequential_collectors", True
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
                # Skip Flags
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
                # Timeout Fields
                "NVOS_TECH_DUMP_TIMEOUT": getattr(
                    tool_config, "NVOS_TECH_DUMP_TIMEOUT", 450
                ),
                "REDFISH_DUMP_TIMEOUT": getattr(
                    tool_config, "REDFISH_DUMP_TIMEOUT", 300
                ),
                "REDFISH_DEVICE_DUMP_SLEEP_DURATION": getattr(
                    tool_config, "REDFISH_DEVICE_DUMP_SLEEP_DURATION", 60
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
            }
        else:
            tool_config_dict = tool_config

        instance.tool_config = tool_config_dict

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
                        dut_config_dict[dut_name] = dut_config.__dict__
                    else:
                        dut_config_dict[dut_name] = dut_config
            else:
                # dut_configs is a list of objects
                for dut in dut_configs:
                    if hasattr(dut, "__dict__"):
                        dut_config_dict[dut.name] = dut.__dict__
                    else:
                        dut_config_dict[dut.name] = dut
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

        Returns:
            Path to configuration directory.
        """
        return find_config_directory()

    async def _load_tool_config(self) -> Dict[str, Any]:
        """
        Load tool configuration from YAML file.

        Returns:
            Tool configuration dictionary.
        """
        try:
            self.tool_config = YAMLManager.load_yaml(
                self.tool_config_path, "Tool configuration"
            )

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
                "NVOS_TECH_DUMP_TIMEOUT": 450,
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
            return {}

    async def _load_dut_config(self) -> None:
        """
        Load DUT configuration with robust error handling and format conversion.
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

            # Convert legacy format if needed
            converted_config = YAMLManager.convert_legacy_dut_format(dut_config_data)

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

        Raises:
            FileNotFoundError: If no valid spreadsheet is found.
        """
        # Check if spreadsheet path is configured
        spreadsheet_path = self.tool_config.get("collector_definitions", {}).get(
            "spreadsheet_path"
        )

        # Always require a valid spreadsheet path in spreadsheet-only mode
        if not spreadsheet_path or not Path(spreadsheet_path).exists():
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
        await self._load_from_spreadsheet(spreadsheet_path)

    async def _initialize_uri_config_manager(self) -> None:
        """
        Initialize URI configuration manager with tool and DUT-specific overrides.

        Raises:
            Exception: If the URI configurations cannot be loaded.
        """
        try:
            # Check for URI overrides directly in tool config
            uri_overrides = self.tool_config.get("uri_overrides")
            uri_config_file = self.tool_config.get("uri_config_file")

            if uri_overrides:
                await self._log_runtime(
                    "INFO",
                    "Initializing URI config manager with inline tool config overrides",
                )
                # Create a temporary config structure for the URI manager
                temp_uri_config = {
                    "prefix_override": uri_overrides.get("prefix_override"),
                    "default_uris": uri_overrides.get("default_uris", {}),
                    "baseboard_overrides": uri_overrides.get("baseboard_overrides", {}),
                    "platform_overrides": uri_overrides.get("platform_overrides", {}),
                }
                self.uri_config_manager = URIConfigManager()
                self.uri_config_manager.tool_uris = temp_uri_config

                # Load DUT-specific URI configurations
                await self._load_dut_uri_configs()
            elif uri_config_file:
                await self._log_runtime(
                    "INFO",
                    f"Initializing URI config manager with file: {uri_config_file}",
                )
                self.uri_config_manager = URIConfigManager(uri_config_file)

                # Load DUT-specific URI configurations
                await self._load_dut_uri_configs()
            else:
                await self._log_runtime(
                    "INFO",
                    "No URI configuration specified - using default URIs",
                )
                self.uri_config_manager = URIConfigManager()

        except Exception as e:
            await self._log_runtime(
                "ERROR", f"Failed to initialize URI config manager: {e}"
            )
            self.uri_config_manager = URIConfigManager()

    async def _load_dut_uri_configs(self) -> None:
        """
        Load URI configurations for all DUTs from their individual configurations.

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

        except Exception as e:
            await self._log_runtime("ERROR", f"Failed to load DUT URI configs: {e}")

    async def _load_dut_specific_config(
        self, dut_id: str, dut_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Load DUT-specific configuration file if ConfigFileToUse is specified.

        Args:
            dut_id: The DUT identifier
            dut_config: The DUT configuration

        Returns:
            dict: Merged configuration with DUT-specific overrides
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
            dut_specific_config = YAMLManager.load_yaml(
                config_file_to_use, f"DUT-specific config for {dut_id}"
            )

            # Merge configurations: DUT config overrides DUT-specific config
            merged_config = {**dut_specific_config, **dut_config}

            await self._log_runtime(
                "INFO", f"Successfully loaded DUT-specific config for {dut_id}"
            )
            return merged_config

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                f"Failed to load DUT-specific config for {dut_id}: {e}",
            )
            return dut_config

    async def _load_from_spreadsheet(self, spreadsheet_path: str) -> None:
        """
        Load collector definitions from Excel spreadsheet.

        Args:
            spreadsheet_path: Path to the spreadsheet file

        Raises:
            Exception: If the spreadsheet cannot be loaded.
        """
        try:

            # Read the spreadsheet
            # Don't treat "N/A" as NaN since it's a valid value meaning "not applicable"
            df = pd.read_excel(
                spreadsheet_path,
                sheet_name="Log Collection Catalog",
                keep_default_na=False,
            )
            if self.sanitized_console and not self.quiet_mode:
                self.sanitized_console.print_debug(
                    f"Read spreadsheet with {len(df)} rows"
                )

            # Convert to dictionary format
            collectors = {}
            for _, row in df.iterrows():
                collector_id = row.get("ID", "")
                if collector_id:
                    # Parse JSON fields
                    dependencies = {}
                    stages = {}
                    try:
                        if pd.notna(row.get("Dependencies")):
                            dependencies = json.loads(str(row.get("Dependencies")))
                    except (json.JSONDecodeError, TypeError):
                        dependencies = {}

                    try:
                        if pd.notna(row.get("Stages")):
                            stages = json.loads(str(row.get("Stages")))
                    except (json.JSONDecodeError, TypeError):
                        stages = {}

                    # Parse applicable baseboards
                    applicable_baseboards = []

                    # First try the single column format
                    if pd.notna(row.get("applicable_baseboards")):
                        applicable_str = str(row.get("applicable_baseboards"))
                        if applicable_str:
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
                                    pd.notna(value)
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
                                    # Host collectors with collect_host_unified typically need sudo
                                    use_sudo = True
                                    # Add use_sudo to the execution stage params
                                    if "params" not in hook:
                                        hook["params"] = {}
                                    hook["params"]["use_sudo"] = True
                                    break

                    collectors[collector_id] = {
                        "collector_id": collector_id,  # Add the collector_id field for compatibility
                        "name": row.get("Collector Name", ""),
                        "group": row.get("Collection Group", ""),
                        "description": row.get("Description", ""),
                        "action_type": row.get("Action Type", ""),
                        "parser_type": row.get("Parser Type", ""),
                        "collection_level": row.get("Collection Level", "L1"),
                        "timeout": row.get("Timeout", 300),
                        "retry_count": row.get("Retry Count", 3),
                        "sequential_execution": row.get("Sequential Execution", False),
                        "applicable_baseboards": applicable_baseboards,
                        "dependencies": dependencies,
                        "stages": stages,
                        "enabled": row.get("Enabled", True),
                        "use_sudo": use_sudo,  # Add use_sudo parameter
                    }

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

    async def _initialize_services(self) -> None:
        """
        Initialize service instances.

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
        Set orchestrator reference for all services after orchestrator is fully initialized

        Args:
            orchestrator: WorkflowOrchestrator instance.
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
        """
        # Only load collector definitions for validation
        await self._load_collector_definitions()

    async def async_init(self) -> None:
        """
        Async initialization - called after sync __init__.

        Loads all configurations, initializes services, and categorizes collectors.
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

        Returns:
            Dictionary of all collector definitions.
        """
        return self.collector_definitions.get("collectors", {})

    def get_sequential_collectors(self) -> Set[str]:
        """
        Get set of sequential collector IDs.

        Returns:
            Set of collector IDs marked for sequential execution.
        """
        return self.sequential_collectors

    def get_parallel_collectors(self) -> Set[str]:
        """
        Get set of parallel collector IDs.

        Returns:
            Set of collector IDs marked for parallel execution.
        """
        return self.parallel_collectors

    def get_uri_config_manager(self) -> Optional[URIConfigManager]:
        """
        Get the URI configuration manager.

        Returns:
            URIConfigManager instance or None.
        """
        return self.uri_config_manager

    def get_collector_info(self, collector_id: str) -> Dict[str, Any]:
        """
        Get collector information by ID.

        Args:
            collector_id: Collector ID.

        Returns:
            Dictionary of collector information.
        """
        collectors = self.collector_definitions.get("collectors", {})
        return collectors.get(collector_id, {})

    def get_collectors_for_group(self, group: str) -> Dict[str, Any]:
        """
        Get all collectors for a specific group based on service mappings.

        Args:
            group: Collector group name (service mapping, e.g., "health_check").

        Returns:
            Dictionary of collectors in the specified group.
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

        Returns:
            List of all unique collector group names (service mappings).
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

        Returns:
            Dictionary of service instances by name.
        """
        return self.services

    def get_tool_config(self) -> Dict[str, Any]:
        """
        Get tool configuration.

        Returns:
            Tool configuration dictionary.
        """
        return self.tool_config

    async def get_dut_specific_tool_config(self, dut_id: str) -> Dict[str, Any]:
        """
        Get tool configuration with DUT-specific overrides.

        This method merges the global tool config with any DUT-specific tool config
        options found in the DUT's ConfigFileToUse.

        Args:
            dut_id: The DUT identifier

        Returns:
            dict: Merged tool configuration with DUT-specific overrides
        """
        # Start with the global tool config
        merged_tool_config = self.tool_config.copy()

        try:
            # Get the DUT config
            dut_config = self.dut_config.get(dut_id, {})
            if not dut_config:
                return merged_tool_config

            # Check if DUT has a ConfigFileToUse
            config_file_to_use = dut_config.get("ConfigFileToUse")
            if not config_file_to_use:
                return merged_tool_config

            # Load the DUT-specific config file
            await self._log_runtime(
                "INFO",
                f"Loading DUT-specific tool config for {dut_id}: {config_file_to_use}",
            )
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
            ]

            # Merge tool config sections from DUT-specific config
            for section in tool_config_sections:
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
            return merged_tool_config

    def get_dut_config(self) -> Dict[str, Any]:
        """
        Get DUT configuration.

        Returns:
            DUT configuration dictionary.
        """
        return self.dut_config

    def get_collector_definitions(self) -> Dict[str, Any]:
        """
        Get collector definitions.

        Returns:
            Collector definitions dictionary.
        """
        return self.collector_definitions

    def set_orchestrator(self, orchestrator) -> None:
        """
        Set the orchestrator reference in all services.

        Args:
            orchestrator: WorkflowOrchestrator instance.
        """
        for service in self.services.values():
            # Use setter to ensure dependent refs are populated safely
            if hasattr(service, "set_orchestrator"):
                service.set_orchestrator(orchestrator)
            else:
                service.orchestrator = orchestrator
