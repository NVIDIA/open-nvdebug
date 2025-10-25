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
CLI Handler Module for nvdebugtool

This module contains the CLI handlers for various commands:
- CLIListCollectors: Handles list-collectors command
- CLIDefaultCollectors: Handles default-collectors command
- CLIPreflight: Handles preflight command
- CLICollector: Handles collect command
- BaseCLICommand: Base class for common CLI functionality
"""

import gc
import getpass
import json
import os
import re
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import aiohttp
import yaml
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from .config import (
    DUTConfig,
    load_config,
    load_dut_config,
    set_global_sanitization_enabled,
)
from .core.async_logger import AsyncSafeLogger
from .core.baseboard_manager import BaseboardManager
from .core.workflow_orchestrator import WorkflowOrchestrator
from .utils import get_tool_resource_content
from .utils.console_output import create_sanitized_console
from .utils.constants import ASCII_HEADER
from .utils.logging import create_timestamped_log_dir
from .utils.output_formatter import OutputFormatter
from .utils.resources import find_config_directory
from .utils.sanitizer import (
    create_sanitizer_from_config,
    patch_print_with_sanitizer,
)
from .utils.spreadsheet_utils import auto_detect_spreadsheet
from .utils.validation import display_dut_config_error, run_comprehensive_validation


@dataclass
class ToolConfig:
    """
    Global tool configuration that applies to all DUTs.

    This dataclass contains all tool-level settings that control execution,
    output, logging, and collection behavior across all Device Under Test (DUT)
    instances.

    Attributes:
        max_concurrent_duts (int): Maximum number of DUTs to process concurrently.
        max_concurrent_collectors_per_dut (int): Maximum collectors per DUT.
        timeout (int): Default timeout in seconds for operations.
        retry_count (int): Number of retry attempts for failed operations.
        output_directory (str): Base directory for output files.
        skip_zip (bool): Skip zip archive creation.
        skip_zip_split (bool): Skip splitting large zip archives.
        zip_split_threshold (float): Size threshold in MB for splitting zips.
        log_level (str): Logging level (DEBUG, INFO, WARNING, ERROR).
        log_format (str): Format string for log messages.
        collection_level (str): Collection level (L1, L2, L3).
        dry_run (bool): Show what would be executed without running.
        debug (bool): Enable debug output.
        verbose (bool): Enable verbose output.
        skip_preflight (bool): Skip preflight connectivity checks.
        skip_sanitization (bool): Skip log sanitization.
        skip_html_reports (bool): Skip HTML report generation.
        skip_auto_parse (bool): Skip automatic log parsing.
        collector_id (Optional[str]): Specific collector IDs to run.
        collector_group (Optional[List[str]]): Specific collector groups to run.
        skip_collectors (Optional[List[str]]): Collector IDs to skip.
        include_collectors (Optional[List[str]]): Collector IDs to include exclusively.
        spreadsheet (Optional[str]): Path to collector definitions spreadsheet.
        enable_status_tracking (bool): Enable real-time status tracking.
        disable_live_display (bool): Disable live status display.
        parallel_dut_sequential_collectors (bool): Run DUTs in parallel, collectors sequential.
        service_grouped_sequential_collectors (bool): Group collectors by service.
        task_id_prefix (str): Prefix for task IDs.
        tool_temp_dir (str): Temporary directory for tool operations.
    """

    # Execution Configuration
    max_concurrent_duts: int = 1
    max_concurrent_collectors_per_dut: int = 1
    timeout: int = 300
    retry_count: int = 1

    # Output Configuration
    output_directory: str = "/tmp"
    skip_zip: bool = False
    skip_zip_split: bool = False
    zip_split_threshold: float = 200.0

    # Logging Configuration
    log_level: str = "INFO"
    log_format: str = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"

    # Collection Configuration
    collection_level: str = "L1"
    dry_run: bool = False
    debug: bool = False
    verbose: bool = False

    # Preflight and Sanitization
    skip_preflight: bool = False
    skip_sanitization: bool = False
    skip_html_reports: bool = False
    skip_auto_parse: bool = False

    # Collector Configuration
    collector_id: Optional[str] = None
    collector_group: Optional[List[str]] = None

    # Collector Skip Configuration
    skip_collectors: Optional[List[str]] = None
    include_collectors: Optional[List[str]] = None

    # Configuration files
    spreadsheet: Optional[str] = None

    # Status Tracking Configuration
    enable_status_tracking: bool = True
    disable_live_display: bool = False

    # Parallelization Configuration
    parallel_dut_sequential_collectors: bool = True
    service_grouped_sequential_collectors: bool = True

    # Global Directory and Prefix Configuration
    task_id_prefix: str = ""  # Empty by default, only used if user specifies
    tool_temp_dir: str = "/tmp"

    # Global feature flags / passthroughs
    # H11: Enable nvidia-bug-report extra mode globally when true
    EXTRA_LOG_COLLECTION: Optional[bool] = None

    # Skip Flags - Global tool-level settings
    SKIP_PORT_FW: bool = False
    SKIP_BMC_SSH_LOGS: bool = True
    SKIP_HOST_LOGS: bool = False
    SKIP_IPMI_LOGS: bool = False
    SKIP_REDFISH_OOB_LOGS: bool = False

    # New Skip Fields - Global tool-level settings
    COLLECTOR_TO_SKIP: Optional[List[str]] = None
    SYSTEM_ID_TO_SKIP: Optional[List[str]] = None
    CHASSIS_ID_TO_SKIP: Optional[List[str]] = None
    MANAGER_ID_TO_SKIP: Optional[List[str]] = None

    # Expand Query Fields - Global tool-level settings
    EXPAND_QUERY_CHASSIS_LEVEL: int = 1
    EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL: int = 1
    EXPAND_QUERY_MANAGER_LEVEL: int = 1
    EXPAND_QUERY_SYSTEM_LEVEL: int = 1

    # Timeout Fields - Global tool-level settings
    NVOS_TECH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DEVICE_DUMP_SLEEP_DURATION: Optional[int] = None

    # Directory Fields - Global tool-level settings
    BMC_TEMP_DIR: str = "/tmp"

    # Firmware Inventory Configuration - Global tool-level settings
    FW_INVENTORY_TABLE_PROPERTIES: List[str] = field(default_factory=list)

    # Additional OOB URI Collection Configuration - Global tool-level settings
    ADDITIONAL_OOB_URI_COLLECTION: List[str] = field(default_factory=list)

    # NVLink OOB URI Collection Configuration - Global tool-level settings
    NVLINK_OOB_URI: List[str] = field(default_factory=list)

    # Custom Dump Services Configuration - Global tool-level settings
    CUSTOM_DUMP_SERVICES: List[str] = field(default_factory=list)

    # Post Codes URI Configuration - Global tool-level settings
    POST_CODES_URI: List[str] = field(default_factory=list)


@dataclass
class CLIConfig:
    """
    Configuration object for CLI arguments to avoid long parameter lists.

    This dataclass encapsulates all CLI-provided arguments for DUT configuration,
    making it easier to pass configuration data without long parameter lists.

    Attributes:
        baseboard (str): Target baseboard name.
        local (bool): Run in local mode (no remote access).
        collector_id (Optional[str]): Specific collector IDs to run.
        collector_group (Optional[List[str]]): Specific collector groups to run.
        collection_level (str): Collection level (L1, L2, L3).
        dry_run (bool): Show what would be executed without running.
        debug (bool): Enable debug output.
        verbose (bool): Enable verbose output.
    """

    # Required arguments (can be provided via CLI or config files)
    baseboard: str

    # Local Configuration
    local: bool = False

    # Collector Configuration
    collector_id: Optional[str] = None
    collector_group: Optional[List[str]] = None
    collection_level: str = "L1"
    dry_run: bool = False

    # Logging Configuration
    debug: bool = False
    verbose: bool = False

    # BMC Configuration
    bmc_ip: Optional[str] = None
    bmc_user: Optional[str] = None
    bmc_pass: Optional[str] = None
    bmc_ssh_user: Optional[str] = None
    bmc_ssh_pass: Optional[str] = None
    bmc_ssh_port: Optional[int] = None
    bmc_ssh_key_path: Optional[str] = None
    bmc_ssh_passwordless: bool = False
    bmc_ssh_max_retries: Optional[int] = 3
    bmc_rf_user: Optional[str] = None
    bmc_rf_pass: Optional[str] = None
    bmc_rf_port: Optional[int] = None

    # Host Configuration
    host_ip: Optional[str] = None
    host_user: Optional[str] = None
    host_pass: Optional[str] = None
    host_ssh_port: Optional[str] = None
    host_ssh_key_path: Optional[str] = None
    host_ssh_passwordless: bool = False
    host_ssh_max_retries: Optional[int] = 3

    # HMC Configuration
    hmc_ip: Optional[str] = None
    hmc_user: Optional[str] = None
    hmc_pass: Optional[str] = None
    hmc_ssh_user: Optional[str] = None
    hmc_ssh_pass: Optional[str] = None
    hmc_ssh_port: Optional[int] = None
    hmc_ssh_key_path: Optional[str] = None
    hmc_ssh_passwordless: bool = False
    hmc_ssh_max_retries: Optional[int] = 3
    hmc_http_port: Optional[int] = None
    hmc_https_port: Optional[int] = None
    hmc_use_https: bool = False
    hmc_use_port_forwarding: bool = False
    use_port_forwarding: bool = False
    tunnel_tcp_port: Optional[int] = None
    setup_port_forwarding: Optional[bool] = None
    force_port_fw: Optional[bool] = None
    hmc_access_method: Optional[str] = None

    # SSH Proxy Configuration
    ssh_proxy_host: Optional[str] = None
    ssh_proxy_port: Optional[int] = 22
    ssh_proxy_user: Optional[str] = None
    ssh_proxy_pass: Optional[str] = None
    ssh_proxy_key: Optional[str] = None
    ssh_proxy_passwordless: bool = False
    ssh_proxy_max_retries: Optional[int] = 3

    # Archive Configuration
    skip_zip: bool = False
    skip_zip_split: bool = False
    zip_split_threshold: float = 200.0

    # Common Configuration
    non_interactive: bool = False
    skip_preflight: bool = False
    skip_sanitization: bool = False
    skip_html_reports: bool = False


class CLICollector:
    """
    Handles the collect command logic.

    This class orchestrates the log collection process, managing DUT configurations,
    validation, and execution of the collection workflow.

    Attributes:
        tool_config (ToolConfig): Global tool configuration.
        dut_configs (List[DUTConfig]): List of DUT configurations to process.
        enable_status_tracking (bool): Enable real-time status tracking.
        disable_live_display (bool): Disable live status display.
        skip_validation (bool): Skip validation checks.
        orchestrator: Workflow orchestrator instance.
        sanitized_console: Sanitized console for safe output.
        sanitizer: Log sanitizer instance.
        tool_start_time (float): Tool initialization timestamp.
        init_start_time (float): Initialization start timestamp.
    """

    def __init__(
        self,
        tool_config: ToolConfig,
        dut_configs: List["DUTConfig"],
        enable_status_tracking: bool = True,
        disable_live_display: bool = False,
        skip_validation: bool = False,
    ):
        """
        Initialize the CLI collector.

        Args:
            tool_config (ToolConfig): Global tool configuration.
            dut_configs (List[DUTConfig]): List of DUT configurations.
            enable_status_tracking (bool): Enable status tracking.
            disable_live_display (bool): Disable live display.
            skip_validation (bool): Skip validation checks.
        """
        self.tool_config = tool_config
        self.dut_configs = dut_configs
        self.enable_status_tracking = enable_status_tracking
        self.disable_live_display = disable_live_display
        self.skip_validation = skip_validation
        self.orchestrator = None
        self.sanitized_console = None  # Will be set when sanitizer is available
        self.sanitizer = None

        # Start overall runtime timing from tool initialization
        self.tool_start_time = time.time()

        # Start timing for tool initialization
        self.init_start_time = time.time()

    def create_cli_dut_config(self, config: "CLIConfig") -> Path:
        """
        Create a temporary DUT config file from CLI arguments.

        Args:
            config (CLIConfig): CLI configuration object containing DUT parameters.

        Returns:
            Path: Path to the created temporary DUT config file.
        """

        dut_config_data = {
            "duts": {
                "cli-dut": {
                    "hostname": config.host_ip or "localhost",
                    "host_username": config.host_user,
                    "host_password": config.host_pass,
                    "ipmi_hostname": config.bmc_ip,
                    "ipmi_username": config.bmc_user,
                    "ipmi_password": config.bmc_pass,
                    "redfish_username": config.bmc_rf_user,
                    "redfish_password": config.bmc_rf_pass,
                    "ssh_username": config.bmc_ssh_user,
                    "ssh_password": config.bmc_ssh_pass,
                    "baseboard": config.baseboard,
                    "collection_level": config.collection_level,
                    # BMC SSH Configuration
                    "bmc_ssh_port": config.bmc_ssh_port,
                    "bmc_ssh_key_path": config.bmc_ssh_key_path,
                    "bmc_ssh_passwordless": config.bmc_ssh_passwordless,
                    "bmc_ssh_max_retries": config.bmc_ssh_max_retries,
                    "bmc_rf_port": config.bmc_rf_port,
                    # Host SSH Configuration
                    "host_ssh_port": config.host_ssh_port,
                    "host_ssh_key_path": config.host_ssh_key_path,
                    "host_ssh_passwordless": config.host_ssh_passwordless,
                    "host_ssh_max_retries": config.host_ssh_max_retries,
                    # HMC Configuration
                    "hmc_ip": config.hmc_ip,
                    "hmc_username": config.hmc_user,
                    "hmc_password": config.hmc_pass,
                    "hmc_ssh_username": config.hmc_ssh_user,
                    "hmc_ssh_password": config.hmc_ssh_pass,
                    "hmc_ssh_port": config.hmc_ssh_port,
                    "hmc_ssh_key_path": config.hmc_ssh_key_path,
                    "hmc_ssh_passwordless": config.hmc_ssh_passwordless,
                    "hmc_ssh_max_retries": config.hmc_ssh_max_retries,
                    "hmc_http_port": config.hmc_http_port,
                    "hmc_https_port": config.hmc_https_port,
                    "hmc_use_https": config.hmc_use_https,
                    "use_port_forwarding": config.use_port_forwarding
                    or config.hmc_use_port_forwarding,
                    "tunnel_tcp_port": config.tunnel_tcp_port,
                    "setup_port_forwarding": config.setup_port_forwarding,
                    "force_port_fw": config.force_port_fw,
                    "rf_hmc_access_method": config.hmc_access_method,
                    # SSH Proxy Configuration
                    "ssh_proxy_host": config.ssh_proxy_host,
                    "ssh_proxy_port": config.ssh_proxy_port,
                    "ssh_proxy_username": config.ssh_proxy_user,
                    "ssh_proxy_password": config.ssh_proxy_pass,
                    "ssh_proxy_key_path": config.ssh_proxy_key,
                    "ssh_proxy_passwordless": config.ssh_proxy_passwordless,
                    "ssh_proxy_max_retries": config.ssh_proxy_max_retries,
                    # Execution mode
                    "execution_mode": "local" if config.local else "remote",
                }
            }
        }

        # Create temporary DUT config file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as tmp_file:
            # Note: Temporary files don't need sanitization as they're cleaned up
            yaml.dump(dut_config_data, tmp_file)
            dut_config = Path(tmp_file.name)

        sanitized_console = create_sanitized_console()
        sanitized_console.print_warning(
            "Created temporary DUT config from CLI arguments"
        )
        return dut_config

    def create_tool_config_from_object(self, tool_config: ToolConfig) -> Path:
        """
        Create a temporary tool config file from a ToolConfig object.

        Args:
            tool_config (ToolConfig): Tool configuration object.

        Returns:
            Path: Path to the created temporary tool config file.
        """

        tool_config_data = {
            "execution_config": {
                "max_concurrent_duts": tool_config.max_concurrent_duts,
                "max_concurrent_collectors_per_dut": tool_config.max_concurrent_collectors_per_dut,
                "timeout": tool_config.timeout,
                "retry_count": tool_config.retry_count,
            },
            "collector_definitions": self._get_collector_definitions_config(),
            "logging": {
                "level": tool_config.log_level,
                "format": tool_config.log_format,
            },
            "output": {
                "directory": tool_config.output_directory,
                "skipzip": tool_config.skip_zip,
                "skipzipsplit": tool_config.skip_zip_split,
                "create_zip": not tool_config.skip_zip,
                "create_split_zip": not tool_config.skip_zip_split,
                "zip_split_threshold": tool_config.zip_split_threshold,
                "generate_html": not tool_config.skip_html_reports,
            },
            # New structured format fields
            "sanitization": {
                "enabled": not tool_config.skip_sanitization,
            },
            "auto_parse": not tool_config.skip_auto_parse,
            # Collection level
            "collection_level": tool_config.collection_level,
            # Add critical parallelization settings
            "PARALLEL_DUT_SEQUENTIAL_COLLECTORS": tool_config.parallel_dut_sequential_collectors,
            "SERVICE_GROUPED_SEQUENTIAL_COLLECTORS": tool_config.service_grouped_sequential_collectors,
            # Add skip flags for orchestrator
            "skip_html_reports": tool_config.skip_html_reports,
            "skip_zip": tool_config.skip_zip,
            "skip_zip_split": tool_config.skip_zip_split,
            "zip_split_threshold": tool_config.zip_split_threshold,
            "skip_auto_parse": tool_config.skip_auto_parse,
        }

        # Create temporary tool config file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as tmp_file:
            # Note: Temporary files don't need sanitization as they're cleaned up
            yaml.dump(tool_config_data, tmp_file)
            tool_config = Path(tmp_file.name)

        # Note: This is a static method, so we create a temporary sanitized console
        sanitized_console = create_sanitized_console()
        sanitized_console.print_warning(
            "Created temporary tool config from CLI arguments"
        )
        return tool_config

    def validate_cli_mode(self, baseboard: Optional[str], cli_args: List[Any]) -> bool:
        """
        Validate CLI mode requirements.

        Args:
            baseboard (Optional[str]): Baseboard name.
            cli_args (List[Any]): List of CLI arguments.

        Returns:
            bool: True if validation passes, False otherwise.
        """
        if not baseboard:
            # Note: This is a static method, so we create a temporary sanitized console
            sanitized_console = create_sanitized_console()
            sanitized_console.print_error(
                "Error: --baseboard is required when using CLI arguments"
            )
            return False
        return True

    def _sanitize_config_dict(self, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively sanitize all string values in a configuration dictionary.

        Args:
            config_dict (Dict[str, Any]): Configuration dictionary to sanitize.

        Returns:
            Dict[str, Any]: Sanitized configuration dictionary.
        """
        if not hasattr(self, "sanitizer") or not self.sanitizer:
            return config_dict

        sanitized = {}
        for key, value in config_dict.items():
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_config_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    (
                        self._sanitize_config_dict(item)
                        if isinstance(item, dict)
                        else (
                            self.sanitizer.sanitize(str(item))
                            if isinstance(item, str)
                            else item
                        )
                    )
                    for item in value
                ]
            elif isinstance(value, str):
                sanitized[key] = self.sanitizer.sanitize(value)
            else:
                sanitized[key] = value
        return sanitized

    @staticmethod
    def create_cli_config_from_args(**kwargs) -> "CLIConfig":
        """
        Create a CLIConfig object from keyword arguments.

        Args:
            **kwargs: Keyword arguments matching CLIConfig fields.

        Returns:
            CLIConfig: Constructed CLI configuration object.
        """
        return CLIConfig(**kwargs)

    def _find_config_directory(self) -> Path:
        """
        Find the config directory using the shared utility function.

        Returns:
            Path: Path to the configuration directory.
        """
        return find_config_directory()

    def _get_collector_definitions_config(self) -> Dict[str, str]:
        """
        Get collector definitions configuration based on spreadsheet path.

        Returns:
            Dict[str, str]: Dictionary containing collector definitions config.
        """
        if not self.tool_config.spreadsheet:
            # Auto-detect spreadsheet using existing logic
            try:
                from .utils.spreadsheet_utils import auto_detect_spreadsheet

                detected_spreadsheet = auto_detect_spreadsheet(
                    None, suppress_print=True
                )
                if detected_spreadsheet:
                    return {"spreadsheet_path": str(detected_spreadsheet)}
            except Exception:
                pass
            # No fallback - let the system handle missing spreadsheet
            return {}

        spreadsheet_path = Path(self.tool_config.spreadsheet)
        if not spreadsheet_path.exists():
            # Try auto-detection if provided path doesn't exist
            try:
                from .utils.spreadsheet_utils import auto_detect_spreadsheet

                detected_spreadsheet = auto_detect_spreadsheet(
                    None, suppress_print=True
                )
                if detected_spreadsheet:
                    return {"spreadsheet_path": str(detected_spreadsheet)}
            except Exception:
                pass
            # No fallback - let the system handle missing spreadsheet
            return {}

        # Detect file type based on extension
        if spreadsheet_path.suffix.lower() in [".xlsx", ".xls"]:
            return {"spreadsheet_path": str(spreadsheet_path)}
        else:
            # Try auto-detection for unsupported file types
            try:
                from .utils.spreadsheet_utils import auto_detect_spreadsheet

                detected_spreadsheet = auto_detect_spreadsheet(
                    None, suppress_print=True
                )
                if detected_spreadsheet:
                    return {"spreadsheet_path": str(detected_spreadsheet)}
            except Exception:
                pass
            # No fallback - let the system handle missing spreadsheet
            return {}

    def validate_config_mode(self, dut_config: Optional[Path]) -> bool:
        """
        Validate config mode requirements.

        Args:
            dut_config (Optional[Path]): Path to DUT configuration file.

        Returns:
            bool: True if validation passes, False otherwise.
        """
        if not dut_config:
            # Note: This is a static method, so we create a temporary sanitized console
            sanitized_console = create_sanitized_console()
            sanitized_console.print_error(
                "Error: --dut-config is required when not using CLI arguments"
            )
            return False

        if not dut_config.exists():
            # Note: This is a static method, so we create a temporary sanitized console
            sanitized_console = create_sanitized_console()
            sanitized_console.print_error(
                f"Error: DUT config file '{dut_config}' does not exist"
            )
            return False

        return True

    async def run_collection(self) -> Dict[str, Any]:
        """
        Run the collection workflow using the WorkflowOrchestrator.

        This method orchestrates the entire log collection process including
        validation, initialization, collection execution, and cleanup.

        Returns:
            Dict[str, Any]: Collection results and statistics.

        Raises:
            Exception: Various exceptions may be raised during collection.
        """
        # Use the tool start time for overall runtime tracking
        start_time = self.tool_start_time

        # Create early sanitizer for validation messages to avoid exposing usernames
        current_username = getpass.getuser()
        early_sanitizer = create_sanitizer_from_config(
            {},
            enabled=True,
            extra_strings=[current_username] if current_username else [],
        )

        try:
            # Run final validation with config manager before starting collection (only if not skipped)
            if not self.skip_validation:

                # Prepare CLI credentials for validation
                cli_credentials = {}
                if self.dut_configs:
                    # Validate each DUT separately to ensure all configurations are valid
                    validation_errors = []
                    for dut_config in self.dut_configs:
                        dut_credentials = {
                            "bmc_ip": dut_config.bmc_ip,
                            "bmc_user": dut_config.bmc_user,
                            "bmc_pass": dut_config.bmc_pass,
                            "host_ip": dut_config.host_ip,
                            "host_user": dut_config.host_user,
                            "host_pass": dut_config.host_pass,
                        }

                        # Validate this DUT's configuration
                        is_valid, errors = run_comprehensive_validation(
                            dut_config=dut_config,
                            local=getattr(dut_config, "local", False),
                            cli_credentials=dut_credentials,
                            collector_ids=self.tool_config.collector_id,
                            collector_groups=self.tool_config.collector_group,
                            collection_level=self.tool_config.collection_level,
                            output_dir=Path(self.tool_config.output_directory),
                            config_manager=None,
                        )

                        if not is_valid:
                            validation_errors.extend(
                                [f"DUT {dut_config.name}: {error}" for error in errors]
                            )

                    # Validate credentials for all DUTs to ensure they're complete
                    all_validation_errors = []

                    for dut_config in self.dut_configs:
                        cli_credentials = {
                            "bmc_ip": dut_config.bmc_ip,
                            "bmc_user": dut_config.bmc_user,
                            "bmc_pass": dut_config.bmc_pass,
                            "host_ip": dut_config.host_ip,
                            "host_user": dut_config.host_user,
                            "host_pass": dut_config.host_pass,
                        }

                        # Run validation for this DUT's credentials
                        is_valid, validation_errors = run_comprehensive_validation(
                            dut_config=None,  # Already validated
                            local=getattr(
                                dut_config, "local", False
                            ),  # Use DUT's local setting
                            cli_credentials=cli_credentials,
                            collector_ids=self.tool_config.collector_id,
                            collector_groups=self.tool_config.collector_group,
                            collection_level=self.tool_config.collection_level,
                            output_dir=Path(self.tool_config.output_directory),
                            config_manager=None,  # Will be set after orchestrator initialization
                        )

                        if not is_valid:
                            all_validation_errors.extend(
                                [
                                    f"DUT {dut_config.name}: {error}"
                                    for error in validation_errors
                                ]
                            )

                    # Report any DUT-specific validation errors
                    if validation_errors:
                        for error in validation_errors:
                            sanitized_error = early_sanitizer.sanitize(str(error))
                            print(f"Validation error: {sanitized_error}")

                    # Report any credential validation errors
                    if all_validation_errors:
                        for error in all_validation_errors:
                            sanitized_error = early_sanitizer.sanitize(str(error))
                            print(f"Credential validation error: {sanitized_error}")

                # Note: We don't exit here as this is just a final validation check
                # The main validation should have already been done in main.py
                if not is_valid:
                    # Log validation errors but continue (they should have been caught earlier)
                    for error in validation_errors:
                        sanitized_error = early_sanitizer.sanitize(str(error))
                        print(f"Validation warning: {sanitized_error}")

        except Exception as e:
            # If validation fails, log but continue
            sanitized_error = early_sanitizer.sanitize(str(e))
            print(f"Validation check failed: {sanitized_error}")

        try:
            # Create tool config file from ToolConfig object
            config_file = self.create_tool_config_from_object(self.tool_config)

            # Create timestamped log directory
            timestamped_log_dir = create_timestamped_log_dir(
                self.tool_config.output_directory
            )
            log_dir = Path(timestamped_log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)

            # Load tool config to check sanitization settings first
            tool_config_obj = load_config(config_file) if config_file else None

            # Determine sanitization setting (sanitize by default, CLI can disable)
            sanitization_enabled = True  # Default: always sanitize
            if self.tool_config.skip_sanitization:
                sanitization_enabled = False
            elif (
                tool_config_obj
                and hasattr(tool_config_obj, "sanitization")
                and tool_config_obj.sanitization
            ):
                # Check new sanitization format
                if (
                    isinstance(tool_config_obj.sanitization, dict)
                    and "enabled" in tool_config_obj.sanitization
                ):
                    sanitization_enabled = tool_config_obj.sanitization["enabled"]
            elif tool_config_obj and hasattr(tool_config_obj, "LogSanitization"):
                # Check legacy LogSanitization format
                sanitization_enabled = tool_config_obj.LogSanitization

            # Set global sanitization setting for early print statements in config.py
            set_global_sanitization_enabled(sanitization_enabled)

            # Note: This is before sanitized_console is initialized, so we create a temporary one
            # Create a basic sanitizer for early messages that respects the sanitization setting
            current_username = getpass.getuser()
            extra_strings = [current_username] if current_username else []
            early_sanitizer = create_sanitizer_from_config(
                {}, enabled=sanitization_enabled, extra_strings=extra_strings
            )

            sanitized_console = create_sanitized_console(early_sanitizer)
            sanitized_console.print_success(
                f"Created timestamped log directory: {log_dir}"
            )
            # Note: --sanitize flag is redundant since sanitization is enabled by default

            # Always create a sanitizer, but with enabled=False if sanitization is disabled
            # Load DUT config for sanitization
            # Convert DUT config objects to dictionary format for sanitizer
            dut_config_data = {}
            for dut in self.dut_configs:
                dut_config_data[dut.name] = dut.__dict__

            # Add current username to sanitizer to mask paths
            current_username = getpass.getuser()
            extra_strings = [current_username] if current_username else []

            # Create sanitizer (enabled or disabled based on setting)
            self.sanitizer = create_sanitizer_from_config(
                dut_config_data,
                enabled=sanitization_enabled,
                extra_strings=extra_strings,
            )

            # Patch print function
            patch_print_with_sanitizer(self.sanitizer)

            self.sanitized_console = create_sanitized_console(self.sanitizer)
            if sanitization_enabled:
                self.sanitized_console.print_warning("Log sanitization enabled")
            else:
                self.sanitized_console.print_warning("Log sanitization disabled")

            # Print ASCII header to console
            self.sanitized_console.print_info(ASCII_HEADER)

            # Start timing for configuration loading
            if (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "timing_manager")
                and self.orchestrator.timing_manager
            ):
                self.orchestrator.timing_manager.start_component(
                    "configuration_loading"
                )

            # Create orchestrator with ToolConfig object
            self.orchestrator = WorkflowOrchestrator(
                tool_config=self.tool_config,
                dut_configs=self.dut_configs,
                log_dir=str(log_dir),
                enable_status_tracking=self.enable_status_tracking,
                disable_live_display=self.disable_live_display,
            )

            # Set sanitizer in orchestrator (always pass sanitizer, it handles enabled/disabled internally)
            self.orchestrator.set_sanitizer(self.sanitizer)

            # End timing for configuration loading
            if (
                hasattr(self.orchestrator, "timing_manager")
                and self.orchestrator.timing_manager
            ):
                self.orchestrator.timing_manager.end_component("configuration_loading")

            # Start timing for overall runtime (from tool start)
            if (
                hasattr(self.orchestrator, "timing_manager")
                and self.orchestrator.timing_manager
            ):
                self.orchestrator.timing_manager.start_component("overall_runtime")

            # Start logging system first
            await self.orchestrator.logger.start()

            # Log startup information
            await self.orchestrator.logger.log_runtime(
                "INFO", "CLICollector", "Starting NVDebug Tool collection"
            )
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"DUT configs: {[dut.name for dut in self.dut_configs]}",
            )
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Output directory: {self.tool_config.output_directory}",
            )
            await self.orchestrator.logger.log_runtime(
                "INFO", "CLICollector", f"Log directory: {log_dir}"
            )
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Collection level: {self.tool_config.collection_level}",
            )

            # Initialize orchestrator
            await self.orchestrator.initialize()

            # End timing for tool initialization
            if (
                hasattr(self.orchestrator, "timing_manager")
                and self.orchestrator.timing_manager
            ):
                self.orchestrator.timing_manager.end_component("tool_initialization")

            # Handle baseboard detection
            # Check if all DUTs have baseboard configured
            duts_without_baseboard = []
            duts_with_cli_baseboard = []

            for dut in self.dut_configs:
                if dut.baseboard and dut.baseboard.strip():
                    # This DUT has a baseboard specified (either via CLI or config file)
                    duts_with_cli_baseboard.append(dut.name)

                    # Ensure the baseboard is set in the orchestrator
                    if self.orchestrator.dut_manager.duts.get(dut.name):
                        self.orchestrator.dut_manager.duts[dut.name].config[
                            "baseboard"
                        ] = dut.baseboard
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            f"Set baseboard '{dut.baseboard}' for DUT {dut.name}",
                        )
                else:
                    # No baseboard specified - auto-detection will handle it
                    duts_without_baseboard.append(dut.name)

            # If we have DUTs with baseboards, use them directly
            if duts_with_cli_baseboard:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"DUTs with baseboard configured: {duts_with_cli_baseboard}",
                )
                self.sanitized_console.print_success(
                    f"\n\nUsing configured baseboard for DUT(s): {', '.join(duts_with_cli_baseboard)}"
                )

            if duts_without_baseboard:
                await self.orchestrator.logger.log_runtime(
                    "WARN",
                    "CLICollector",
                    f"DUTs without baseboard configured: {duts_without_baseboard}",
                )
                self.sanitized_console.print_warning(
                    f"\n\nWarning: DUTs without baseboard configured: {', '.join(duts_without_baseboard)}"
                )

            if duts_without_baseboard:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    "Some DUTs have no baseboard specified - will attempt auto-detection after preflight checks",
                )
                self.sanitized_console.print_info(
                    "Some DUTs have no baseboard specified - will attempt auto-detection from hardware/system information after preflight checks"
                )

            # Process collector IDs and groups
            processed_cids = []
            group_cids = []
            specific_cids = []
            current_level = self.tool_config.collection_level
            await self.orchestrator.logger.log_runtime(
                "DEBUG",
                "CLICollector",
                f"Collection level from tool config: {current_level}",
            )

            # Process include_collectors from CLI arguments
            # Note: include_collectors are added to the final list, not processed as specific_cids
            include_collectors = self.tool_config.include_collectors or []

            # Get baseboard information for filtering
            baseboard_info = None
            if self.orchestrator.dut_manager:
                dut_ids_for_baseboard = self.orchestrator.dut_manager.get_all_dut_ids()
                if dut_ids_for_baseboard:
                    # Get baseboard info from all DUTs for logging purposes
                    baseboards = set()
                    for dut_id in dut_ids_for_baseboard:
                        dut = self.orchestrator.dut_manager.get_dut(dut_id)
                        if dut and dut.config:
                            baseboard = dut.config.get("baseboard", "Unknown")
                            baseboards.add(baseboard)

                    # Log baseboard information for transparency
                    if len(baseboards) == 1:
                        baseboard_info = list(baseboards)[0]
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            f"Single baseboard detected: {baseboard_info}",
                        )
                    elif len(baseboards) > 1:
                        # Multiple baseboards detected - no global filtering, per-DUT filtering will occur during execution
                        baseboard_list = list(baseboards)
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            f"Multiple baseboards detected ({', '.join(baseboard_list)}). No global baseboard filtering applied - each DUT will filter collectors based on its own baseboard during execution.",
                        )
                        self.sanitized_console.print_info(
                            f"\n\nMultiple baseboards detected ({', '.join(baseboard_list)}). Each DUT will filter collectors based on its own baseboard during execution."
                        )
                        # Set baseboard_info to None to indicate no global filtering
                        # Per-DUT filtering will occur during execution for each DUT's specific baseboard
                        baseboard_info = None
                    else:
                        baseboard_info = "Unknown"
                        # This is a critical error - all DUTs must have baseboard configured
                        raise ValueError(
                            f"CRITICAL ERROR: All DUTs must have baseboard configured. Found DUTs with unknown baseboard. Please configure baseboard in DUT config for all DUTs."
                        )

            # Handle collector groups first - filter by collection level and baseboard
            if self.tool_config.collector_group:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"Processing collector groups: {self.tool_config.collector_group} for level {current_level}",
                )
                self.sanitized_console.print_info(
                    f"Processing collector groups: {', '.join(self.tool_config.collector_group)} for level {current_level}"
                )

                for group in self.tool_config.collector_group:
                    group_collectors = (
                        self.orchestrator.config_manager.get_collectors_for_group(group)
                    )
                    if group_collectors:
                        # Filter collectors by collection level and baseboard
                        level_filtered_collectors = []
                        baseboard_filtered_collectors = []

                        for (
                            collector_id,
                            collector_info,
                        ) in group_collectors.items():
                            collector_level = collector_info.get(
                                "collection_level", "L1"
                            )
                            if self.orchestrator._is_collector_level_applicable(
                                collector_level, current_level
                            ):
                                level_filtered_collectors.append(collector_id)

                                # Apply baseboard filtering only if we have a single baseboard
                                if baseboard_info is None:
                                    # No global filtering - include all collectors, per-DUT baseboard filtering will occur during execution
                                    baseboard_filtered_collectors.append(collector_id)
                                elif self.orchestrator.is_collector_applicable_for_baseboard(
                                    collector_info, baseboard_info
                                ):
                                    baseboard_filtered_collectors.append(collector_id)
                                else:
                                    await self.orchestrator.logger.log_runtime(
                                        "WARN",
                                        "CLICollector",
                                        f"Collector {collector_id} in group '{group}' is not applicable for baseboard {baseboard_info} - skipping",
                                    )

                        group_cids.extend(baseboard_filtered_collectors)
                        if baseboard_info is None:
                            await self.orchestrator.logger.log_runtime(
                                "INFO",
                                "CLICollector",
                                f"Found {len(baseboard_filtered_collectors)} collectors in group '{group}' for level {current_level} (no global baseboard filtering - per-DUT filtering will occur during execution): {baseboard_filtered_collectors}",
                            )
                            self.sanitized_console.print_info(
                                f"Found {len(baseboard_filtered_collectors)} collectors in group '{group}' for level {current_level} (per-DUT baseboard filtering during execution): {', '.join(baseboard_filtered_collectors)}"
                            )
                        else:
                            await self.orchestrator.logger.log_runtime(
                                "INFO",
                                "CLICollector",
                                f"Found {len(baseboard_filtered_collectors)} collectors in group '{group}' for level {current_level} and baseboard {baseboard_info}: {baseboard_filtered_collectors}",
                            )
                            self.sanitized_console.print_info(
                                f"Found {len(baseboard_filtered_collectors)} collectors in group '{group}' for level {current_level} and baseboard {baseboard_info}: {', '.join(baseboard_filtered_collectors)}"
                            )

                        # Log if some collectors were filtered out due to level or baseboard
                        total_in_group = len(group_collectors)
                        level_filtered_out = total_in_group - len(
                            level_filtered_collectors
                        )
                        baseboard_filtered_out = len(level_filtered_collectors) - len(
                            baseboard_filtered_collectors
                        )

                        if level_filtered_out > 0:
                            await self.orchestrator.logger.log_runtime(
                                "INFO",
                                "CLICollector",
                                f"Filtered out {level_filtered_out} collectors from group '{group}' that don't match level {current_level}",
                            )
                            self.sanitized_console.print_info(
                                f"Filtered out {level_filtered_out} collectors from group '{group}' that don't match level {current_level}"
                            )

                        if baseboard_filtered_out > 0:
                            if baseboard_info is None:
                                await self.orchestrator.logger.log_runtime(
                                    "INFO",
                                    "CLICollector",
                                    f"Note: {baseboard_filtered_out} collectors from group '{group}' may be filtered out during execution based on individual DUT baseboards",
                                )
                                self.sanitized_console.print_info(
                                    f"Note: {baseboard_filtered_out} collectors from group '{group}' may be filtered out during execution based on individual DUT baseboards"
                                )
                            else:
                                await self.orchestrator.logger.log_runtime(
                                    "INFO",
                                    "CLICollector",
                                    f"Filtered out {baseboard_filtered_out} collectors from group '{group}' that don't match baseboard {baseboard_info}",
                                )
                                self.sanitized_console.print_info(
                                    f"Filtered out {baseboard_filtered_out} collectors from group '{group}' that don't match baseboard {baseboard_info}"
                                )
                    else:
                        await self.orchestrator.logger.log_runtime(
                            "WARN",
                            "CLICollector",
                            f"No collectors found for group '{group}'",
                        )
                        self.sanitized_console.print_warning(
                            f"No collectors found for group '{group}'"
                        )

            # Handle specific collector IDs (these are added regardless of level since user explicitly wants them)
            cids = self.tool_config.collector_id
            if cids:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"Processing specific collector IDs: {cids}",
                )
                self.sanitized_console.print_info(
                    f"\n\nProcessing specific collector IDs: {cids}"
                )

                # Split by spaces first, then handle commas within each item
                cid_items = cids.split()
                for cid_item in cid_items:
                    if "," in cid_item:
                        # Handle comma-separated items: "R1,R2" or "I4,I5"
                        split_items = [item.strip() for item in cid_item.split(",")]
                        specific_cids.extend(split_items)
                    else:
                        # Handle space-separated items: "I2" or "I3"
                        specific_cids.append(cid_item.strip())

            # Combine group and specific collectors, with specific collectors taking precedence
            if specific_cids and group_cids:
                # Start with group collectors
                processed_cids = group_cids.copy()

                # Add specific collectors (they will override any duplicates from groups)
                for cid in specific_cids:
                    if cid in processed_cids:
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            f"Specific collector ID '{cid}' overrides group selection",
                        )
                        self.sanitized_console.print_info(
                            f"Specific collector ID '{cid}' overrides group selection"
                        )
                    processed_cids.append(cid)

                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"Combined group and specific collectors: {processed_cids}",
                )
                self.sanitized_console.print_info(
                    f"Combined group and specific collectors: {', '.join(processed_cids)}"
                )

            elif specific_cids:
                # Only specific IDs specified
                processed_cids = specific_cids
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"Using specific collector IDs: {specific_cids}",
                )
                self.sanitized_console.print_info(
                    f"Using specific collector IDs: {', '.join(specific_cids)}"
                )

            elif group_cids:
                # Only groups specified
                processed_cids = group_cids
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"Using collectors from groups for level {current_level}: {group_cids}",
                )
                self.sanitized_console.print_info(
                    f"Using collectors from groups for level {current_level}: {', '.join(group_cids)}"
                )

            else:
                # Neither specified - will run all applicable collectors
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"No specific collectors or groups specified - will run all applicable collectors for level {current_level}",
                )
                self.sanitized_console.print_info(
                    f"\nNo specific collectors or groups specified - will run all applicable collectors for level {current_level}\n"
                )
                # Get all collectors for the current level
                all_collectors = self.orchestrator.get_all_collectors(current_level)
                processed_cids = list(all_collectors.keys())
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"Using all {len(processed_cids)} collectors for level {current_level}",
                )

            # Apply include_collectors as a filter (only these collectors will run)
            # This overrides any previous selection (groups, specific collectors, etc.)
            if include_collectors:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"Applying --include-collectors filter (only these collectors will run): {include_collectors}",
                )

                # If other collectors were selected (via -g or -S), take the intersection
                # Otherwise, use include_collectors as the full list
                if processed_cids:
                    # Intersection: only include collectors that are in BOTH lists
                    original_count = len(processed_cids)
                    processed_cids = [
                        cid for cid in processed_cids if cid in include_collectors
                    ]
                    filtered_out = original_count - len(processed_cids)

                    if filtered_out > 0:
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            f"Filtered out {filtered_out} collectors that were not in --include-collectors list",
                        )
                        self.sanitized_console.print_info(
                            f"Applied --include-collectors filter: {filtered_out} collectors from groups/selection were filtered out"
                        )

                    # Add any include_collectors that weren't in the original list
                    # (this allows including collectors outside of selected groups)
                    for cid in include_collectors:
                        if cid not in processed_cids:
                            # Verify collector exists before adding
                            collector_info = (
                                self.orchestrator.config_manager.get_collector_info(cid)
                            )
                            if collector_info:
                                processed_cids.append(cid)
                                await self.orchestrator.logger.log_runtime(
                                    "INFO",
                                    "CLICollector",
                                    f"Added collector {cid} from --include-collectors (not in original selection)",
                                )
                else:
                    # No other selection was made, use include_collectors as the full list
                    processed_cids = list(include_collectors)

                # Check for baseboard compatibility warnings for include_collectors
                if baseboard_info:
                    # Single baseboard environment
                    for collector_id in include_collectors:
                        collector_info = (
                            self.orchestrator.config_manager.get_collector_info(
                                collector_id
                            )
                        )
                        if collector_info:
                            supported_baseboards = collector_info.get(
                                "applicable_baseboards", []
                            )
                            if (
                                supported_baseboards
                                and baseboard_info not in supported_baseboards
                            ):
                                supported_str = ", ".join(supported_baseboards)
                                self.sanitized_console.print_warning(
                                    f"Warning: Collector {collector_id} in --include-collectors is not supported on baseboard '{baseboard_info}'. Supported baseboards: {supported_str}"
                                )
                        else:
                            self.sanitized_console.print_warning(
                                f"Warning: Collector {collector_id} in --include-collectors not found in collector catalog"
                            )
                else:
                    # Multi-DUT environment - check against all baseboards
                    if self.orchestrator.dut_manager:
                        all_baseboards = set()
                        for dut_id in self.orchestrator.dut_manager.get_all_dut_ids():
                            dut_config = self.orchestrator.dut_manager.duts[
                                dut_id
                            ].config
                            baseboard = dut_config.get("baseboard", "Unknown")
                            all_baseboards.add(baseboard)

                        for collector_id in include_collectors:
                            collector_info = (
                                self.orchestrator.config_manager.get_collector_info(
                                    collector_id
                                )
                            )
                            if collector_info:
                                supported_baseboards = collector_info.get(
                                    "applicable_baseboards", []
                                )
                                if supported_baseboards:
                                    # Check if collector is supported on ANY of the baseboards
                                    unsupported_baseboards = all_baseboards - set(
                                        supported_baseboards
                                    )
                                    if unsupported_baseboards:
                                        supported_str = ", ".join(supported_baseboards)
                                        unsupported_str = ", ".join(
                                            sorted(unsupported_baseboards)
                                        )
                                        self.sanitized_console.print_warning(
                                            f"Warning: Collector {collector_id} in --include-collectors is not supported on baseboard(s) '{unsupported_str}'. Supported baseboards: {supported_str}"
                                        )
                            else:
                                self.sanitized_console.print_warning(
                                    f"Warning: Collector {collector_id} in --include-collectors not found in collector catalog"
                                )

            # Remove duplicates while preserving order (specific collectors should come after group collectors)
            if processed_cids:
                seen = set()
                unique_cids = []
                for cid in processed_cids:
                    if cid not in seen:
                        seen.add(cid)
                        unique_cids.append(cid)
                processed_cids = unique_cids

                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"Final processed CIDs: {processed_cids}",
                )
                # self.sanitized_console.print_info(
                #     f"Processed collector selection: {', '.join(processed_cids)}"
                # )

            # Get all DUTs for filtering
            dut_ids = self.orchestrator.dut_manager.get_all_dut_ids()

            await self.orchestrator.logger.log_runtime(
                "INFO", "CLICollector", f"Found {len(dut_ids)} DUT(s): {dut_ids}"
            )
            await self.orchestrator.logger.log_runtime(
                "INFO", "CLICollector", f"Input processed_cids: {processed_cids}"
            )

            # Check if any DUTs need autodetection before filtering
            duts_needing_autodetection = []
            for dut_id in dut_ids:
                dut = self.orchestrator.dut_manager.get_dut(dut_id)
                if dut and dut.config:
                    baseboard = dut.config.get("baseboard") or dut.config.get(
                        "TargetBaseboard"
                    )
                    if not baseboard:
                        duts_needing_autodetection.append(dut_id)

            if duts_needing_autodetection:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"DUTs needing autodetection: {duts_needing_autodetection} - running autodetection before filtering",
                )

                # Run autodetection for DUTs that need it
                for dut_id in duts_needing_autodetection:
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        f"Running autodetection for DUT: {dut_id}",
                    )

                    # Get non_interactive flag from DUT config
                    dut = self.orchestrator.dut_manager.get_dut(dut_id)
                    non_interactive = dut.config.get("non_interactive", False)

                    # Simple console output for autodetection
                    autodetection_start_time = time.time()

                    self.orchestrator.sanitized_console.console.print(
                        f"[bold blue]Auto-detecting platform and baseboard for {dut_id}...[/bold blue]"
                    )

                    # Run autodetection
                    success, detected_info = (
                        await self.orchestrator.dut_manager.detect_platform_and_baseboard(
                            dut_id, {}, non_interactive
                        )
                    )

                    # Show completion message with elapsed time
                    elapsed_time = time.time() - autodetection_start_time
                    self.orchestrator.sanitized_console.console.print(
                        f"[green]Auto-detection completed in {elapsed_time:.1f}s![/green]"
                    )

                    if success:
                        detected_baseboard = detected_info.get("baseboard")
                        detected_platform = detected_info.get("platform")
                        detected_node_type = detected_info.get("node_type")

                        # Validate that we have actual detected values, not None
                        if not detected_baseboard or not detected_platform:
                            await self.orchestrator.logger.log_runtime(
                                "WARNING",
                                "CLICollector",
                                f"Autodetection returned success but with invalid values for DUT {dut_id}: Baseboard={detected_baseboard}, Platform={detected_platform}",
                            )
                            # Treat this as a detection failure
                            success = False
                        else:
                            await self.orchestrator.logger.log_runtime(
                                "INFO",
                                "CLICollector",
                                f"Autodetection successful for DUT {dut_id}: Baseboard={detected_baseboard}, Platform={detected_platform}, NodeType={detected_node_type}",
                            )

                            # Update DUT config
                            dut = self.orchestrator.dut_manager.get_dut(dut_id)
                            dut.config["baseboard"] = detected_baseboard
                            dut.config["platform"] = detected_platform
                            if detected_node_type:
                                dut.config["node_type"] = detected_node_type

                            # Update the signature files with the newly detected values
                            await self.orchestrator.logger.create_log_signature(
                                dut_id, detected_platform, detected_baseboard
                            )
                            await self.orchestrator.logger.log_runtime(
                                "INFO",
                                "CLICollector",
                                f"Updated signature files with detected values for DUT {dut_id}",
                            )

                    if not success:
                        await self.orchestrator.logger.log_runtime(
                            "WARNING",
                            "CLICollector",
                            f"Autodetection failed for DUT {dut_id} - will continue with unknown baseboard",
                        )

            # Step 1: Apply all filtering to get final collectors
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                "Applying all filtering (level, baseboard, skip flags, include/exclude)...",
            )

            filtering_results = await self.orchestrator.execution_engine.get_filtered_collectors_per_dut(
                processed_cids, dut_ids
            )

            filtered_collectors_per_dut = filtering_results["filtered_collectors"]
            skipped_collectors_per_dut = filtering_results["skipped_collectors"]

            # Store pre-filtered results in orchestrator to avoid double filtering
            self.orchestrator._pre_filtered_results = {
                "filtered_collectors": filtered_collectors_per_dut,
                "skipped_collectors": skipped_collectors_per_dut,
            }

            # Get union of all filtered collectors
            all_filtered_collectors = set()
            for dut_collectors in filtered_collectors_per_dut.values():
                all_filtered_collectors.update(dut_collectors)
            all_filtered_collectors = list(all_filtered_collectors)

            # Step 2: Print final filtered collectors (regardless of dry run or not)
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Final filtering complete. {len(all_filtered_collectors)} collectors will run.",
            )

            def natural_sort_key(text):
                return [
                    int(c) if c.isdigit() else c.lower()
                    for c in re.split(r"(\d+)", text)
                ]

            # Create a Rich table to display filtered collectors per DUT
            table = Table(title="Filtered Collectors by DUT")
            table.add_column("DUT Name", style="cyan", no_wrap=True)
            table.add_column("Baseboard", style="magenta", no_wrap=True)
            table.add_column("Filtered Collectors", style="green", overflow="fold")
            table.add_column("Count", style="yellow", justify="right")

            # Sort DUT IDs for consistent display
            sorted_dut_ids = sorted(filtered_collectors_per_dut.keys())

            for dut_id in sorted_dut_ids:
                dut_collectors = filtered_collectors_per_dut[dut_id]
                sorted_collectors = sorted(dut_collectors, key=natural_sort_key)

                # Get baseboard info for this DUT
                dut_config = self.orchestrator.dut_manager.duts[dut_id].config
                baseboard = dut_config.get("baseboard", "Unknown")

                # Group collectors by their collection group for better readability
                collector_groups = {}
                for collector_id in sorted_collectors:
                    collector_info = (
                        self.orchestrator.config_manager.get_collector_info(
                            collector_id
                        )
                    )
                    if collector_info:
                        group = collector_info.get("group", "Unknown")
                        if group not in collector_groups:
                            collector_groups[group] = []
                        collector_groups[group].append(collector_id)
                    else:
                        # Fallback for collectors not found in config
                        if "Unknown" not in collector_groups:
                            collector_groups["Unknown"] = []
                        collector_groups["Unknown"].append(collector_id)

                # Format collectors by group, one group per line
                group_lines = []
                for group in sorted(collector_groups.keys()):
                    group_collectors = sorted(
                        collector_groups[group], key=natural_sort_key
                    )
                    group_line = f"{group}: {', '.join(group_collectors)}"
                    group_lines.append(group_line)

                collectors_str = "\n".join(group_lines)

                table.add_row(
                    dut_id, baseboard, collectors_str, str(len(dut_collectors))
                )

            # Display the table
            self.sanitized_console.console.print(table)

            # Also show summary statistics
            total_unique_collectors = len(all_filtered_collectors)
            total_duts = len(filtered_collectors_per_dut)
            avg_collectors_per_dut = (
                sum(
                    len(collectors)
                    for collectors in filtered_collectors_per_dut.values()
                )
                / total_duts
            )

            self.sanitized_console.print_info(
                f"\nSummary: {total_duts} DUT(s), {total_unique_collectors} unique collectors, "
                f"{avg_collectors_per_dut:.1f} avg collectors per DUT\n"
            )

            # Step 3: Choose between dry run or actual execution
            if self.tool_config.dry_run:
                await self.orchestrator.logger.log_runtime(
                    "INFO", "CLICollector", "DRY RUN MODE - simulation complete"
                )
                self.sanitized_console.print_warning(
                    "DRY RUN MODE - No actual execution"
                )
                return {
                    "dry_run": True,
                    "filtered_collectors_per_dut": filtered_collectors_per_dut,
                    "all_filtered_collectors": all_filtered_collectors,
                    "total_collectors": len(all_filtered_collectors),
                }
            else:
                # Preflight checks, platform info gathering, and dynamic discovery
                # are now handled in the new execution flow
                preflight_results = None

                # Check if this is a multi-DUT operation
                dut_ids = self.orchestrator.dut_manager.get_all_dut_ids()
                is_multi_dut = len(dut_ids) > 1

                if is_multi_dut:
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        f"Multi-DUT operation detected ({len(dut_ids)} DUTs). Skipping baseboard detection.",
                    )
                    self.sanitized_console.print_info(
                        f"Multi-DUT operation detected ({len(dut_ids)} DUTs). Skipping baseboard detection."
                    )
                    self.sanitized_console.print_info(
                        "Please ensure baseboard is properly configured in config files."
                    )

                    # Validate that baseboard is set in config files for all DUTs
                    missing_configs = []
                    for dut_id in dut_ids:
                        dut_config = self.orchestrator.dut_manager.duts[dut_id].config
                        if not dut_config.get("baseboard"):
                            missing_configs.append(f"{dut_id}: missing baseboard")

                    if missing_configs:
                        await self.orchestrator.logger.log_runtime(
                            "ERROR",
                            "CLICollector",
                            f"Multi-DUT validation failed: {', '.join(missing_configs)}",
                        )
                        self.sanitized_console.print_error(
                            "Error: Baseboard must be configured in config files for multi-DUT operations."
                        )
                        self.sanitized_console.print_error(
                            "Please set baseboard in your DUT configuration files."
                        )
                        self.sanitized_console.print_error(
                            "For multi-DUT operations, detection is disabled to ensure consistency across all DUTs."
                        )
                        raise ValueError("Multi-DUT configuration validation failed")
                    else:
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            "✓ Baseboard configuration verified in config files.",
                        )
                        self.sanitized_console.print_success(
                            "✓ Baseboard configuration verified in config files."
                        )
                else:
                    # Single DUT operation - auto-detection will be handled by the orchestrator
                    # during its execution flow (after preflight checks)
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        "Single DUT operation - auto-detection will be handled during execution flow",
                    )
                    self.sanitized_console.print_info(
                        "Single DUT operation - auto-detection will be handled during execution flow"
                    )

                # Platform info gathering and dynamic discovery are now handled in the new execution flow

                # Show what collectors were requested (before baseboard filtering)
                if processed_cids:
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        f"Requested collectors: {processed_cids}",
                    )
                    # self.sanitized_console.print_info(
                    #     f"Requested collectors: {', '.join(processed_cids)}"
                    # )

                    # Log comprehensive collector selection table
                    await self.orchestrator.log_collector_selection_table(
                        processed_cids
                    )

                # Execute collectors
                await self.orchestrator.logger.log_runtime(
                    "INFO", "CLICollector", "Executing collectors..."
                )
                self.sanitized_console.print_info("\nExecuting collectors...\n")

                # Use the new execution flow with the already-filtered collectors
                # Pass original collector list for status tracker initialization
                results = await self.orchestrator.execute_collectors(
                    collector_ids=all_filtered_collectors,
                    collection_level=self.tool_config.collection_level,
                    cli_start_time=start_time,
                    dry_run=False,
                    original_collector_ids=processed_cids,
                )

                # Get the actual executed collectors from results
                executed_collectors = set()
                sequential_results = results.get("sequential_results", {})
                parallel_results = results.get("parallel_results", {})
                for collector_id in sequential_results:
                    executed_collectors.add(collector_id)
                for collector_id in parallel_results:
                    executed_collectors.add(collector_id)

                # Check if shutdown was requested during execution
                if self.orchestrator.is_shutdown_requested():
                    await self.orchestrator.logger.log_runtime(
                        "WARN",
                        "CLICollector",
                        "Collection was interrupted by user. Continuing with post-collection flows...",
                    )
                    self.sanitized_console.print_warning(
                        "Collection interrupted. Finishing up..."
                    )
                else:
                    # Log the collectors that were executed (after baseboard filtering)
                    if executed_collectors:
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            f"Executed collectors: {sorted(list(executed_collectors))}",
                        )
                        self.sanitized_console.print_info(
                            f"Executed collectors: {', '.join(sorted(executed_collectors))}"
                        )
                    else:
                        await self.orchestrator.logger.log_runtime(
                            "WARN",
                            "CLICollector",
                            "No collectors were executed (all were filtered out)",
                        )
                        self.sanitized_console.print_warning(
                            "No collectors were executed (all were filtered out)"
                        )

                    # Log completion
                    await self.orchestrator.logger.log_runtime(
                        "INFO", "CLICollector", "Collection completed successfully"
                    )

                return results

        except Exception as e:
            error_msg = f"Collection failed: {str(e)}"
            if self.orchestrator and self.orchestrator.logger:
                await self.orchestrator.logger.log_runtime(
                    "ERROR", "CLICollector", error_msg
                )

            # Safely handle console output - create one if not available
            if self.sanitized_console is None:
                self.sanitized_console = create_sanitized_console()

            self.sanitized_console.print_error(f"{error_msg}")
            if self.tool_config.debug:
                self.sanitized_console.print_error("Exception details:")
                # Note: console.print_exception() is a Rich method, we'll keep it for now
                Console().print_exception()
            raise
        finally:
            # Ensure cleanup happens
            if self.orchestrator:
                try:
                    # Calculate total runtime for HTML reports
                    total_runtime = time.time() - start_time if start_time else None

                    # Print total execution time
                    if total_runtime is not None:
                        human_readable_time = OutputFormatter.format_time(total_runtime)
                        # Only show seconds in parentheses if time is over a minute
                        if total_runtime >= 60:
                            execution_time_msg = f"\nTotal execution time: {human_readable_time} ({total_runtime:.2f} seconds)"
                        else:
                            execution_time_msg = (
                                f"\nTotal execution time: {human_readable_time}"
                            )
                        self.sanitized_console.print_success(execution_time_msg)

                        # Log total execution time to runtime logs
                        if self.orchestrator and self.orchestrator.logger:
                            await self.orchestrator.logger.log_runtime(
                                "INFO", "CLICollector", execution_time_msg
                            )

                    # End timing for overall runtime
                    if (
                        hasattr(self, "orchestrator")
                        and self.orchestrator
                        and hasattr(self.orchestrator, "timing_manager")
                        and self.orchestrator.timing_manager
                    ):
                        self.orchestrator.timing_manager.end_component(
                            "overall_runtime"
                        )

                    await self.orchestrator.cleanup(total_runtime, processed_cids)

                    # Display final console output after cleanup is complete (including zip creation)
                    final_console = create_sanitized_console()
                    final_console.print_success("Collection completed successfully!")

                    # Check if zip archive was created and display its location
                    if (
                        hasattr(self.orchestrator, "zip_archive_path")
                        and self.orchestrator.zip_archive_path
                    ):
                        # Handle both single file and split files cases
                        if isinstance(self.orchestrator.zip_archive_path, list):
                            # Files were split - display all files
                            final_console.print_success("Split zip archive created:")
                            for file_path in self.orchestrator.zip_archive_path:
                                final_console.print_success(f"  {file_path}")

                            # Show recombine instructions like
                            base_name = (
                                os.path.basename(self.orchestrator.zip_archive_path[0])
                                .replace(".z01", "")
                                .replace(".zip", "")
                            )
                            base_dir = os.path.dirname(
                                self.orchestrator.zip_archive_path[0]
                            )
                            final_console.print_info("\nTo recombine the files:")
                            final_console.print_info("On Linux/macOS:")
                            final_console.print_info(
                                f"  cat {base_name}.z* > {base_name}_combined.zip"
                            )
                            final_console.print_info("\nOn Windows (Command Prompt):")
                            final_console.print_info(
                                f"  copy /b {base_name}.z* {base_name}_combined.zip"
                            )
                            final_console.print_info("\nOn Windows (PowerShell):")
                            final_console.print_info(
                                f"  Get-Content {base_name}.z* -Raw -Encoding Byte | Set-Content {base_name}_combined.zip -Encoding Byte"
                            )
                        else:
                            # Single file
                            final_console.print_success(
                                f"\nLogs saved to: {self.orchestrator.zip_archive_path}"
                            )
                    else:
                        final_console.print_success(f"\nLogs saved to: {log_dir}")

                except Exception as e:
                    # Safely handle console output - create one if not available
                    if self.sanitized_console is None:
                        self.sanitized_console = create_sanitized_console()
                    self.sanitized_console.print_warning(f"Warning: Cleanup error: {e}")

                # Always perform emergency cleanup to ensure no ClientSessions are left open
                try:
                    await self._emergency_cleanup()
                except Exception as e:
                    if self.sanitized_console is None:
                        self.sanitized_console = create_sanitized_console()
                    self.sanitized_console.print_warning(
                        f"Warning: Emergency cleanup error: {e}"
                    )

    async def _emergency_cleanup(self) -> None:
        """
        Emergency cleanup to close all ClientSessions when interrupted.

        This method performs garbage collection and forcefully closes any
        remaining open aiohttp ClientSession objects to prevent resource leaks.
        """
        try:
            # Force garbage collection to find any unclosed sessions
            gc.collect()

            # Find any remaining ClientSession objects and close them
            closed_count = 0
            for obj in gc.get_objects():
                if isinstance(obj, aiohttp.ClientSession):
                    if not obj.closed:
                        try:
                            await obj.close()
                            closed_count += 1
                            if self.sanitized_console:
                                self.sanitized_console.print_warning(
                                    f"Emergency cleanup: closed ClientSession {obj}"
                                )
                        except Exception as e:
                            if self.sanitized_console:
                                self.sanitized_console.print_warning(
                                    f"Error closing ClientSession {obj}: {str(e)}"
                                )

            if closed_count > 0 and self.sanitized_console:
                self.sanitized_console.print_warning(
                    f"Emergency cleanup completed: closed {closed_count} ClientSession(s)"
                )

        except Exception as e:
            if self.sanitized_console:
                self.sanitized_console.print_warning(
                    f"Error during emergency cleanup: {str(e)}"
                )


class BaseCLICommand:
    """
    Base class for CLI commands with common functionality.

    This class provides shared utilities for all CLI command implementations,
    including configuration management and output handling.

    Attributes:
        sanitized_console: Sanitized console for safe output.
        orchestrator (Optional[WorkflowOrchestrator]): Workflow orchestrator instance.
    """

    def __init__(self):
        """
        Initialize the base CLI command.
        """
        self.sanitized_console = create_sanitized_console()
        self.orchestrator: Optional[WorkflowOrchestrator] = None

    def _find_config_directory(self) -> Path:
        """
        Find the config directory using the shared utility function.

        Returns:
            Path: Path to the configuration directory.
        """
        return find_config_directory()

    def _create_tool_config_object(
        self,
        spreadsheet: Optional[Path],
        quiet_mode: bool = False,
        config_file: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Create tool config as object instead of YAML file.
        Will attempt to load from tool_config.yaml if it exists, otherwise uses defaults.

        Args:
            spreadsheet (Optional[Path]): Path to spreadsheet file.
            quiet_mode (bool): Suppress console output.
            config_file (Optional[Path]): Path to tool configuration file (overrides auto-detection).

        Returns:
            Dict[str, Any]: Tool configuration dictionary.
        """
        # Try to load from tool_config.yaml first if it exists
        tool_config_from_file = {}
        try:
            # Use provided config_file if specified, otherwise auto-detect
            if config_file and config_file.exists():
                tool_config_path = config_file
            else:
                config_dir = self._find_config_directory()
                tool_config_path = config_dir / "tool_config.yaml"

            if tool_config_path.exists():
                from .utils.yaml_manager import YAMLManager

                tool_config_from_file = YAMLManager.load_yaml(
                    str(tool_config_path), "tool_config"
                )
        except Exception:
            # If loading fails, just use defaults
            pass

        # Auto-detect spreadsheet path and add to tool config
        spreadsheet_path = None
        try:
            from .utils.spreadsheet_utils import auto_detect_spreadsheet

            detected_spreadsheet = auto_detect_spreadsheet(None, suppress_print=True)
            if detected_spreadsheet:
                spreadsheet_path = str(detected_spreadsheet)
        except Exception:
            pass

        # Start with default config
        tool_config = {
            "execution_config": {
                "max_concurrent_duts": 1,
                "max_concurrent_collectors_per_dut": 1,
                "retry_count": 1,
            },
            "collector_definitions": (
                {"spreadsheet_path": spreadsheet_path} if spreadsheet_path else {}
            ),
            "logging": {
                "level": "INFO",
                "format": "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            },
            # Preflight credential validation configuration (defaults)
            "preflight_config": {
                "validate_credentials_in_preflight": True,  # Default: validate credentials
                "credential_validation_uri": "/redfish/v1/Systems",  # Default auth URI
            },
            # Add critical parallelization settings
            "PARALLEL_DUT_SEQUENTIAL_COLLECTORS": True,
            "SERVICE_GROUPED_SEQUENTIAL_COLLECTORS": True,
            # Global directory and prefix fields
            "TASK_ID_PREFIX": "",  # Empty by default, only used if user specifies
            "TOOL_TEMP_DIR": "/tmp",
        }

        # Merge with values from tool_config.yaml if loaded
        if tool_config_from_file:
            # Merge preflight_config if present in file
            if "preflight_config" in tool_config_from_file:
                tool_config["preflight_config"].update(
                    tool_config_from_file["preflight_config"]
                )
            # Merge other sections as needed
            if "redfish_session_config" in tool_config_from_file:
                tool_config["redfish_session_config"] = tool_config_from_file[
                    "redfish_session_config"
                ]
            if "uri_overrides" in tool_config_from_file:
                tool_config["uri_overrides"] = tool_config_from_file["uri_overrides"]

        # Add spreadsheet configuration if provided
        if spreadsheet:
            tool_config["collector_definitions"]["spreadsheet_path"] = str(spreadsheet)

        # Quiet mode flags - disable unnecessary operations
        if quiet_mode:
            tool_config["skip_preflight"] = True
            tool_config["skip_html_reports"] = True
            tool_config["skip_zip"] = True
            tool_config["skip_zip_split"] = True

        return tool_config

    def _create_minimal_dut_config(
        self, baseboard: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create minimal DUT config for commands that don't need full DUT validation.

        Args:
            baseboard (Optional[str]): Baseboard name to include in config.

        Returns:
            Dict[str, Any]: Minimal DUT configuration dictionary.
        """
        return {
            "DUT_Defaults": {},
            "duts": {
                "temp-dut": {
                    "hostname": "localhost",
                    "baseboard": baseboard if baseboard else "generic",
                }
            },
        }

    async def _initialize_orchestrator(
        self,
        tool_config: Dict[str, Any],
        dut_config: Dict[str, Any],
        quiet_mode: bool = False,
    ) -> WorkflowOrchestrator:
        """
        Initialize the workflow orchestrator with common configuration.

        Args:
            tool_config (Dict[str, Any]): Tool configuration dictionary.
            dut_config (Dict[str, Any]): DUT configuration dictionary.
            quiet_mode (bool): Enable quiet mode (suppress output).

        Returns:
            WorkflowOrchestrator: Initialized orchestrator instance.
        """

        # For quiet mode operations, use a temporary directory that will be cleaned up
        if quiet_mode:
            # Create a temporary directory for logging
            temp_dir = tempfile.mkdtemp(prefix="nvdebug_quiet_")
            log_dir = temp_dir

            # Store the temporary directory path in tool config for global access
            tool_config["temp_log_dir"] = temp_dir
        else:
            # For non-quiet mode (like collect command), use the default log directory
            log_dir = None

        orchestrator = WorkflowOrchestrator(
            tool_config=tool_config,
            dut_configs=dut_config,
            quiet_mode=quiet_mode,
            sanitized_console=self.sanitized_console,
            log_dir=log_dir,
        )

        await orchestrator.initialize()
        self.orchestrator = orchestrator
        return orchestrator

    async def _cleanup_orchestrator(self):
        """
        Clean up the orchestrator if it exists.

        Performs cleanup of the workflow orchestrator and any temporary
        directories created during execution.
        """
        if self.orchestrator:
            await self.orchestrator.cleanup()

            # Clean up temporary log directory if it was created for quiet mode
            if self.orchestrator and hasattr(self.orchestrator, "config_manager"):
                tool_config = self.orchestrator.config_manager.get_tool_config()
                temp_log_dir = tool_config.get("temp_log_dir")

                if temp_log_dir:
                    try:
                        if os.path.exists(temp_log_dir):
                            shutil.rmtree(temp_log_dir)
                            # Don't print cleanup messages when JSON output is requested
                            # as it corrupts the JSON stream
                    except Exception as e:
                        # Log cleanup failure but don't fail the command
                        # Use stderr for debug messages to avoid corrupting JSON output

                        print(
                            f"Failed to cleanup temp dir {temp_log_dir}: {e}",
                            file=sys.stderr,
                        )

            self.orchestrator = None

    def _handle_output(
        self,
        data: Any,
        json_output: bool = False,
        output_file: Optional[str] = None,
        output_type: str = "collectors",
    ) -> None:
        """
        Handle output formatting using OutputFormatter.

        Args:
            data (Any): Data to output.
            json_output (bool): Output in JSON format.
            output_file (Optional[str]): File path for output.
            output_type (str): Type of output ("collectors", "preflight", etc.).
        """
        output_formatter = OutputFormatter(self.sanitized_console)

        if output_type == "collectors":
            filtered_collectors, sequential_collectors = data
            if filtered_collectors:
                output_formatter.output_collectors(
                    filtered_collectors,
                    sequential_collectors,
                    json_output=json_output,
                    output_file=output_file,
                )
            else:
                if json_output:
                    output_formatter.output_collectors(
                        [],
                        sequential_collectors,
                        json_output=True,
                        output_file=output_file,
                    )
                else:
                    if output_file:
                        output_formatter.output_collectors(
                            [],
                            sequential_collectors,
                            json_output=False,
                            output_file=output_file,
                        )
                    else:
                        self.sanitized_console.print_warning(
                            "No collectors found matching the criteria"
                        )
        elif output_type == "preflight":
            output_formatter.output_preflight_results(
                data, json_output=json_output, output_file=output_file
            )
        elif output_type == "baseboards":
            if json_output:
                if output_file:
                    output_formatter._output_baseboards_json_to_file(
                        data, Path(output_file)
                    )
                else:
                    output_formatter._output_baseboards_json_to_stdout(data)
            else:
                if output_file:
                    output_formatter._output_baseboards_table_to_file(
                        data, Path(output_file)
                    )
                else:
                    output_formatter._output_baseboards_table_to_stdout(data)

    async def _run_with_error_handling(self, operation_func, *args, **kwargs):
        """
        Run an operation with common error handling.

        Args:
            operation_func: Async function to execute.
            *args: Positional arguments for operation_func.
            **kwargs: Keyword arguments for operation_func.

        Returns:
            Result from operation_func.

        Raises:
            SystemExit: Exits with code 1 on error.
        """
        try:
            return await operation_func(*args, **kwargs)
        except Exception as e:
            self.sanitized_console.print_error(f"Error: {e}")
            await self._cleanup_orchestrator()
            sys.exit(1)


class CLIListCollectors(BaseCLICommand):
    """
    Handles the list-collectors command logic.

    This class implements the list-collectors CLI command which displays
    available log collectors, optionally filtered by baseboard or group.
    """

    def __init__(self):
        """
        Initialize the list-collectors command handler.
        """
        super().__init__()

    async def run(
        self,
        baseboard: Optional[str],
        group: Optional[str],
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
    ) -> None:
        """
        Run the list collectors command using the WorkflowOrchestrator.

        Args:
            baseboard (Optional[str]): Filter by baseboard name.
            group (Optional[str]): Filter by collector group.
            spreadsheet (Optional[Path]): Path to collector definitions spreadsheet.
            json_output (bool): Output in JSON format.
            output_file (Optional[str]): File path for output.
        """
        await self._run_collector_command(
            baseboard=baseboard,
            group=group,
            spreadsheet=spreadsheet,
            json_output=json_output,
            output_file=output_file,
            filter_default_only=False,
        )

    async def _run_collector_command(
        self,
        baseboard: Optional[str],
        group: Optional[str],
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
        filter_default_only: bool = False,
    ) -> None:
        """
        Shared method for running collector listing commands.

        Args:
            baseboard (Optional[str]): Filter by baseboard name.
            group (Optional[str]): Filter by collector group.
            spreadsheet (Optional[Path]): Path to collector definitions spreadsheet.
            json_output (bool): Output in JSON format.
            output_file (Optional[str]): File path for output.
            filter_default_only (bool): Show only default collectors.
        """
        return await self._run_with_error_handling(
            self._execute_collector_command,
            baseboard,
            group,
            spreadsheet,
            json_output,
            output_file,
            filter_default_only,
        )

    async def _execute_collector_command(
        self,
        baseboard: Optional[str],
        group: Optional[str],
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
        filter_default_only: bool = False,
    ) -> None:
        """
        Execute the collector command logic.

        Args:
            baseboard (Optional[str]): Filter by baseboard name.
            group (Optional[str]): Filter by collector group.
            spreadsheet (Optional[Path]): Path to collector definitions spreadsheet.
            json_output (bool): Output in JSON format.
            output_file (Optional[str]): File path for output.
            filter_default_only (bool): Show only default collectors.
        """
        # Create tool config as object instead of YAML file
        tool_config_obj = self._create_tool_config_object(spreadsheet, quiet_mode=True)
        # Create minimal DUT config for quiet mode (needed for BaseboardManager initialization)
        dut_config = self._create_minimal_dut_config(baseboard)

        # Create orchestrator in quiet mode for listing collectors
        orchestrator = await self._initialize_orchestrator(
            tool_config_obj, dut_config, quiet_mode=True
        )

        # Get all collectors
        all_collectors = orchestrator.get_all_collectors()

        sequential_collectors = orchestrator.get_sequential_collectors()
        parallel_collectors = orchestrator.get_parallel_collectors()

        # Apply filters
        filtered_collectors = []
        for collector_id in all_collectors:
            collector_info = orchestrator.get_collector_info(collector_id)

            # Baseboard filter
            if baseboard and not orchestrator._is_collector_applicable(
                collector_info, baseboard
            ):
                continue

            # Group filter
            if group and collector_info.get("group") != group:
                continue

            # Default collectors filter (only for default-collectors command)
            if filter_default_only:
                if not (
                    collector_info.get("collection_level") == "L1"
                    or collector_info.get("enabled", True)
                ):
                    continue

            filtered_collectors.append((collector_id, collector_info))

        # Use shared output handling
        self._handle_output(
            (filtered_collectors, sequential_collectors),
            json_output=json_output,
            output_file=output_file,
            output_type="collectors",
        )

        # Cleanup
        await self._cleanup_orchestrator()

    def _format_supported_baseboards(
        self, applicable_baseboards, orchestrator=None
    ) -> str:
        """
        Format supported baseboards for display, expanding groups to specific baseboards.

        Args:
            applicable_baseboards: Baseboard or list of baseboards/groups.
            orchestrator: Optional orchestrator instance for group lookup.

        Returns:
            str: Formatted string of baseboard names.
        """
        if applicable_baseboards == "all":
            return "All"
        elif not applicable_baseboards:
            return "None"

        # Load baseboard groups mapping
        baseboard_groups = self._get_baseboard_groups(orchestrator)

        expanded_baseboards = set()

        if isinstance(applicable_baseboards, list):
            for item in applicable_baseboards:
                if item in baseboard_groups:
                    # Expand group to specific baseboards
                    expanded_baseboards.update(baseboard_groups[item])
                else:
                    # It's already a specific baseboard
                    expanded_baseboards.add(item)
        elif isinstance(applicable_baseboards, str):
            if applicable_baseboards in baseboard_groups:
                # Expand group to specific baseboards
                expanded_baseboards.update(baseboard_groups[applicable_baseboards])
            else:
                # It's already a specific baseboard
                expanded_baseboards.add(applicable_baseboards)

        # Sort for consistent display
        return (
            ", ".join(sorted(expanded_baseboards)) if expanded_baseboards else "Unknown"
        )

    def _get_baseboard_groups(self, orchestrator=None) -> dict:
        """
        Get baseboard groups mapping from spreadsheet.

        Args:
            orchestrator: Optional orchestrator instance for group lookup.

        Returns:
            dict: Dictionary mapping group names to list of baseboards.
        """
        try:
            # Try to get baseboard groups from the orchestrator's baseboard manager
            if orchestrator and hasattr(orchestrator, "config_manager"):
                baseboard_manager = orchestrator.config_manager.get_baseboard_manager()
                if baseboard_manager:
                    return baseboard_manager.get_baseboard_groups()
        except Exception:
            pass

        # Return empty dict if no baseboard manager available
        return {}

    def _output_table(
        self, filtered_collectors: List[tuple], sequential_collectors: Set[str]
    ) -> None:
        """
        Output collectors in table format.

        Args:
            filtered_collectors (List[tuple]): List of (collector_id, collector_info) tuples.
            sequential_collectors (Set[str]): Set of sequential collector IDs.
        """
        table = Table(title="Available Collectors")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Group", style="blue")
        table.add_column("Type", style="yellow")
        table.add_column("Level", style="magenta")
        table.add_column("Supported Baseboards", style="white")

        for collector_id, collector_info in filtered_collectors:
            collector_type = (
                "Sequential" if collector_id in sequential_collectors else "Parallel"
            )

            # Format supported baseboards
            baseboards_display = self._format_supported_baseboards(
                collector_info.get("applicable_baseboards", "all"),
                self.orchestrator,
            )

            table.add_row(
                collector_id,
                collector_info.get("name", "Unknown"),
                collector_info.get("group", "Unknown"),
                collector_type,
                collector_info.get("collection_level", "Unknown"),
                baseboards_display,
            )

        # Note: table printing doesn't need sanitization as it's just collector info

        Console().print(table)
        self.sanitized_console.print_success(
            f"Total collectors: {len(filtered_collectors)}"
        )

    def _output_json_to_file(
        self,
        filtered_collectors: List[tuple],
        sequential_collectors: Set[str],
        output_path: Path,
    ) -> None:
        """
        Output collectors in JSON format to file.

        Args:
            filtered_collectors (List[tuple]): List of (collector_id, collector_info) tuples.
            sequential_collectors (Set[str]): Set of sequential collector IDs.
            output_path (Path): Output file path.
        """

        # Validate output path
        if output_path.exists():
            # Check if it's a directory
            if output_path.is_dir():
                output_path = output_path / "collectors.json"
            else:
                # File exists, check if it's writable
                if not output_path.is_file():
                    self.sanitized_console.print_error(
                        f"Error: {output_path} exists but is not a file"
                    )
                    sys.exit(1)
                # File exists and is writable, we'll overwrite it
        else:
            # Path doesn't exist, check if parent directory exists and is writable
            parent_dir = output_path.parent
            if parent_dir.exists() and not parent_dir.is_dir():
                self.sanitized_console.print_error(
                    f"Error: {parent_dir} exists but is not a directory"
                )
                sys.exit(1)
            elif not parent_dir.exists():
                try:
                    parent_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    self.sanitized_console.print_error(
                        f"Error: Cannot create directory {parent_dir}: {e}"
                    )
                    sys.exit(1)

        # Prepare JSON data
        collectors_data = []
        for collector_id, collector_info in filtered_collectors:
            collector_type = (
                "Sequential" if collector_id in sequential_collectors else "Parallel"
            )

            # Format supported baseboards
            baseboards_display = self._format_supported_baseboards(
                collector_info.get("applicable_baseboards", "all")
            )

            collector_data = {
                "id": collector_id,
                "name": collector_info.get("name", "Unknown"),
                "group": collector_info.get("group", "Unknown"),
                "type": collector_type,
                "level": collector_info.get("collection_level", "Unknown"),
                "supported_baseboards": baseboards_display,
                "description": collector_info.get("description", ""),
                "action_type": collector_info.get("action_type", ""),
                "parser_type": collector_info.get("parser_type", ""),
                "timeout": collector_info.get("timeout", 300),
                "retry_count": collector_info.get("retry_count", 3),
                "enabled": collector_info.get("enabled", True),
                "dependencies": collector_info.get("dependencies", []),
                "stages": collector_info.get("stages", []),
            }
            collectors_data.append(collector_data)

        # Create final JSON structure
        output_data = {
            "total_collectors": len(filtered_collectors),
            "collectors": collectors_data,
        }

        # Write JSON to file
        try:
            # Sanitize output data if sanitizer is available
            sanitized_output_data = output_data.copy()
            if hasattr(self, "sanitizer") and self.sanitizer:
                sanitized_output_data = self._sanitize_config_dict(output_data)

            with open(output_path, "w") as f:
                json.dump(sanitized_output_data, f, indent=2)

            self.sanitized_console.print_success(
                f"JSON output written to: {output_path}"
            )
            self.sanitized_console.print_success(
                f"Total collectors: {len(filtered_collectors)}"
            )
        except Exception as e:
            self.sanitized_console.print_error(
                f"Error writing JSON to {output_path}: {e}"
            )
            sys.exit(1)

    def _output_json_to_stdout(
        self, filtered_collectors: List[tuple], sequential_collectors: Set[str]
    ) -> None:
        """
        Output collectors in JSON format to stdout.

        Args:
            filtered_collectors (List[tuple]): List of (collector_id, collector_info) tuples.
            sequential_collectors (Set[str]): Set of sequential collector IDs.
        """

        # Prepare JSON data
        collectors_data = []
        for collector_id, collector_info in filtered_collectors:
            collector_type = (
                "Sequential" if collector_id in sequential_collectors else "Parallel"
            )

            # Format supported baseboards
            baseboards_display = self._format_supported_baseboards(
                collector_info.get("applicable_baseboards", "all")
            )

            collector_data = {
                "id": collector_id,
                "name": collector_info.get("name", "Unknown"),
                "group": collector_info.get("group", "Unknown"),
                "type": collector_type,
                "level": collector_info.get("collection_level", "Unknown"),
                "supported_baseboards": baseboards_display,
                "description": collector_info.get("description", ""),
                "action_type": collector_info.get("action_type", ""),
                "parser_type": collector_info.get("parser_type", ""),
                "timeout": collector_info.get("timeout", 300),
                "retry_count": collector_info.get("retry_count", 3),
                "enabled": collector_info.get("enabled", True),
                "dependencies": collector_info.get("dependencies", []),
                "stages": collector_info.get("stages", []),
            }
            collectors_data.append(collector_data)

        # Create final JSON structure
        output_data = {
            "total_collectors": len(filtered_collectors),
            "collectors": collectors_data,
        }

        # Output JSON to stdout
        print(json.dumps(output_data, indent=2))

    def _output_table_to_stdout(
        self, filtered_collectors: List[tuple], sequential_collectors: Set[str]
    ) -> None:
        """
        Output collectors in table format to stdout.

        Args:
            filtered_collectors (List[tuple]): List of (collector_id, collector_info) tuples.
            sequential_collectors (Set[str]): Set of sequential collector IDs.
        """

        table = Table(title="Available Collectors")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Group", style="blue")
        table.add_column("Type", style="yellow")
        table.add_column("Level", style="magenta")
        table.add_column("Supported Baseboards", style="white")

        for collector_id, collector_info in filtered_collectors:
            collector_type = (
                "Sequential" if collector_id in sequential_collectors else "Parallel"
            )

            # Format supported baseboards
            baseboards_display = self._format_supported_baseboards(
                collector_info.get("applicable_baseboards", "all")
            )

            table.add_row(
                collector_id,
                collector_info.get("name", "Unknown"),
                collector_info.get("group", "Unknown"),
                collector_type,
                collector_info.get("collection_level", "Unknown"),
                baseboards_display,
            )

        # Note: table printing doesn't need sanitization as it's just collector info

        Console().print(table)
        self.sanitized_console.print_success(
            f"Total collectors: {len(filtered_collectors)}"
        )

    def _output_table_to_file(
        self,
        filtered_collectors: List[tuple],
        sequential_collectors: Set[str],
        output_path: Path,
    ) -> None:
        """
        Output collectors in table format to file.

        Args:
            filtered_collectors (List[tuple]): List of (collector_id, collector_info) tuples.
            sequential_collectors (Set[str]): Set of sequential collector IDs.
            output_path (Path): Output file path.
        """
        # Validate output path
        if output_path.exists():
            # Check if it's a directory
            if output_path.is_dir():
                output_path = output_path / "collectors.txt"
            else:
                # File exists, check if it's writable
                if not output_path.is_file():
                    self.sanitized_console.print_error(
                        f"Error: {output_path} exists but is not a file"
                    )
                    sys.exit(1)
                # File exists and is writable, we'll overwrite it
        else:
            # Path doesn't exist, check if parent directory exists and is writable
            parent_dir = output_path.parent
            if parent_dir.exists() and not parent_dir.is_dir():
                self.sanitized_console.print_error(
                    f"Error: {parent_dir} exists but is not a directory"
                )
                sys.exit(1)
            elif not parent_dir.exists():
                try:
                    parent_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    self.sanitized_console.print_error(
                        f"Error: Cannot create directory {parent_dir}: {e}"
                    )
                    sys.exit(1)

        # Create table content as text
        lines = []
        lines.append("Available Collectors")
        lines.append("=" * 80)
        lines.append(
            f"{'ID':<8} {'Name':<30} {'Group':<12} {'Type':<10} {'Level':<6} {'Supported Baseboards'}"
        )
        lines.append("-" * 80)

        for collector_id, collector_info in filtered_collectors:
            collector_type = (
                "Sequential" if collector_id in sequential_collectors else "Parallel"
            )

            # Format supported baseboards
            baseboards_display = self._format_supported_baseboards(
                collector_info.get("applicable_baseboards", "all")
            )

            lines.append(
                f"{collector_id:<8} {collector_info.get('name', 'Unknown'):<30} "
                f"{collector_info.get('group', 'Unknown'):<12} {collector_type:<10} "
                f"{collector_info.get('collection_level', 'Unknown'):<6} {baseboards_display}"
            )

        lines.append("-" * 80)
        lines.append(f"Total collectors: {len(filtered_collectors)}")

        # Write to file
        try:
            # Sanitize lines if sanitizer is available
            sanitized_lines = lines.copy()
            if hasattr(self, "sanitizer") and self.sanitizer:
                sanitized_lines = [self.sanitizer.sanitize(line) for line in lines]

            with open(output_path, "w") as f:
                f.write("\n".join(sanitized_lines))

            self.sanitized_console.print_success(
                f"Table output written to: {output_path}"
            )
            self.sanitized_console.print_success(
                f"Total collectors: {len(filtered_collectors)}"
            )
        except Exception as e:
            self.sanitized_console.print_error(
                f"Error writing table to {output_path}: {e}"
            )
            sys.exit(1)


class CLIDefaultCollectors(BaseCLICommand):
    """
    Handles the default-collectors command logic.

    This class implements the default-collectors CLI command which shows
    collectors that are enabled by default for a given baseboard.
    """

    def __init__(self):
        """
        Initialize the default-collectors command handler.
        """
        super().__init__()

    async def run(
        self,
        baseboard: str,
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
    ) -> None:
        """
        Run the default collectors command using the shared collector logic.

        Args:
            baseboard (str): Baseboard name to filter by.
            spreadsheet (Optional[Path]): Path to collector definitions spreadsheet.
            json_output (bool): Output in JSON format.
            output_file (Optional[str]): File path for output.
        """
        # Create a CLIListCollectors instance to use the shared method
        list_collectors_handler = CLIListCollectors()
        await list_collectors_handler._run_collector_command(
            baseboard=baseboard,
            group=None,  # No group filter for default collectors
            spreadsheet=spreadsheet,
            json_output=json_output,
            output_file=output_file,
            filter_default_only=True,  # Enable default collectors filtering
        )


class CLIListBaseboards(BaseCLICommand):
    """
    Handles the list-baseboards command logic.

    This class implements the list-baseboards CLI command which displays
    all available baseboard platforms from the collector definitions.
    """

    def __init__(self):
        """
        Initialize the list-baseboards command handler.
        """
        super().__init__()

    async def run(
        self,
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
    ) -> None:
        """
        Run the list baseboards command using the BaseboardManager.

        Args:
            spreadsheet (Optional[Path]): Path to collector definitions spreadsheet.
            json_output (bool): Output in JSON format.
            output_file (Optional[str]): File path for output.
        """
        return await self._run_with_error_handling(
            self._execute_list_baseboards,
            spreadsheet,
            json_output,
            output_file,
        )

    async def _execute_list_baseboards(
        self,
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
    ) -> None:
        """
        Execute the list baseboards command logic.

        Args:
            spreadsheet (Optional[Path]): Path to collector definitions spreadsheet.
            json_output (bool): Output in JSON format.
            output_file (Optional[str]): File path for output.
        """
        # Create tool config as object instead of YAML file
        tool_config_obj = self._create_tool_config_object(spreadsheet, quiet_mode=True)

        # Debug: Check if spreadsheet path is set correctly
        spreadsheet_path = tool_config_obj.get("collector_definitions", {}).get(
            "spreadsheet_path"
        )
        if not spreadsheet_path or not Path(spreadsheet_path).exists():
            from .utils.spreadsheet_utils import (
                show_spreadsheet_requirement_message,
            )

            show_spreadsheet_requirement_message()
            return

        # Create BaseboardManager directly

        # Create a temporary directory that will be cleaned up automatically
        with tempfile.TemporaryDirectory(prefix="nvdebug_quiet_") as temp_dir:
            # Store the temporary directory path in tool config for global access
            tool_config_obj["temp_log_dir"] = temp_dir

            # Create a temporary logger for the baseboard manager
            temp_logger = AsyncSafeLogger(temp_dir)

            baseboard_manager = BaseboardManager(
                spreadsheet_path=spreadsheet_path,
                logger=temp_logger,
            )

            # Get all baseboards from the manager
            baseboards = baseboard_manager.get_all_baseboard_names()

            if not baseboards:
                if json_output:
                    # Output empty JSON
                    self._handle_output(
                        {"baseboards": [], "total_baseboards": 0},
                        json_output=True,
                        output_file=output_file,
                        output_type="baseboards",
                    )
                else:
                    if output_file:
                        # Write empty result to file
                        self._handle_output(
                            {"baseboards": [], "total_baseboards": 0},
                            json_output=False,
                            output_file=output_file,
                            output_type="baseboards",
                        )
                    else:
                        self.sanitized_console.print_warning("No baseboards found")
                return

            # Prepare baseboard data with descriptions
            baseboard_data = []
            for baseboard in sorted(baseboards):
                # Get baseboard type and group information
                baseboard_type = baseboard_manager.get_baseboard_type(baseboard)
                baseboard_group = baseboard_manager.get_baseboard_group(baseboard)

                description = f"Type: {baseboard_type}"
                if baseboard_group:
                    description += f", Group: {baseboard_group}"

                baseboard_data.append(
                    {
                        "name": baseboard,
                        "type": baseboard_type,
                        "group": baseboard_group,
                        "description": description,
                    }
                )

            # Use shared output handling
            self._handle_output(
                {
                    "baseboards": baseboard_data,
                    "total_baseboards": len(baseboard_data),
                },
                json_output=json_output,
                output_file=output_file,
                output_type="baseboards",
            )


class CLIPreflight(BaseCLICommand):
    """
    Handles the preflight command logic.

    This class implements the preflight CLI command which performs
    connectivity and configuration checks without collecting logs.
    """

    def __init__(self):
        """
        Initialize the preflight command handler.
        """
        super().__init__()

    async def run(
        self,
        config_file: Optional[Path],
        dut_config: Optional[Path],
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
        local: bool = False,
        # BMC Configuration
        bmc_ip: Optional[str] = None,
        bmc_user: Optional[str] = None,
        bmc_pass: Optional[str] = None,
        bmc_ssh_user: Optional[str] = None,
        bmc_ssh_pass: Optional[str] = None,
        bmc_ssh_port: Optional[int] = None,
        bmc_ssh_key_path: Optional[str] = None,
        bmc_ssh_passwordless: bool = False,
        bmc_ssh_max_retries: Optional[int] = None,
        bmc_rf_user: Optional[str] = None,
        bmc_rf_pass: Optional[str] = None,
        bmc_rf_port: Optional[int] = None,
        # Host Configuration
        host_ip: Optional[str] = None,
        host_user: Optional[str] = None,
        host_pass: Optional[str] = None,
        host_ssh_port: Optional[str] = None,
        host_ssh_key_path: Optional[str] = None,
        host_ssh_passwordless: bool = False,
        host_ssh_max_retries: Optional[int] = None,
    ) -> None:
        """
        Run the preflight command using the WorkflowOrchestrator.

        Args:
            config_file (Optional[Path]): Tool configuration file path.
            dut_config (Optional[Path]): DUT configuration file path.
            spreadsheet (Optional[Path]): Collector definitions spreadsheet path.
            json_output (bool): Output in JSON format.
            output_file (Optional[str]): File path for output.
            local (bool): Run in local mode.
            bmc_ip (Optional[str]): BMC IP address.
            bmc_user (Optional[str]): BMC username.
            bmc_pass (Optional[str]): BMC password.
            bmc_ssh_user (Optional[str]): BMC SSH username.
            bmc_ssh_pass (Optional[str]): BMC SSH password.
            bmc_ssh_port (Optional[int]): BMC SSH port.
            bmc_ssh_key_path (Optional[str]): BMC SSH key path.
            bmc_ssh_passwordless (bool): Use passwordless SSH for BMC.
            bmc_ssh_max_retries (Optional[int]): BMC SSH max retry attempts.
            bmc_rf_user (Optional[str]): Redfish username.
            bmc_rf_pass (Optional[str]): Redfish password.
            bmc_rf_port (Optional[int]): Redfish port.
            host_ip (Optional[str]): Host IP address.
            host_user (Optional[str]): Host username.
            host_pass (Optional[str]): Host password.
            host_ssh_port (Optional[str]): Host SSH port.
            host_ssh_key_path (Optional[str]): Host SSH key path.
            host_ssh_passwordless (bool): Use passwordless SSH for Host.
            host_ssh_max_retries (Optional[int]): Host SSH max retry attempts.
        """
        return await self._run_with_error_handling(
            self._execute_preflight,
            config_file,
            dut_config,
            spreadsheet,
            json_output,
            output_file,
            local,
            # BMC Configuration
            bmc_ip,
            bmc_user,
            bmc_pass,
            bmc_ssh_user,
            bmc_ssh_pass,
            bmc_ssh_port,
            bmc_ssh_key_path,
            bmc_ssh_passwordless,
            bmc_ssh_max_retries,
            bmc_rf_user,
            bmc_rf_pass,
            bmc_rf_port,
            # Host Configuration
            host_ip,
            host_user,
            host_pass,
            host_ssh_port,
            host_ssh_key_path,
            host_ssh_passwordless,
            host_ssh_max_retries,
        )

    async def _execute_preflight(
        self,
        config_file: Optional[Path],
        dut_config: Optional[Path],
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
        local: bool = False,
        # BMC Configuration
        bmc_ip: Optional[str] = None,
        bmc_user: Optional[str] = None,
        bmc_pass: Optional[str] = None,
        bmc_ssh_user: Optional[str] = None,
        bmc_ssh_pass: Optional[str] = None,
        bmc_ssh_port: Optional[int] = None,
        bmc_ssh_key_path: Optional[str] = None,
        bmc_ssh_passwordless: bool = False,
        bmc_ssh_max_retries: Optional[int] = None,
        bmc_rf_user: Optional[str] = None,
        bmc_rf_pass: Optional[str] = None,
        bmc_rf_port: Optional[int] = None,
        # Host Configuration
        host_ip: Optional[str] = None,
        host_user: Optional[str] = None,
        host_pass: Optional[str] = None,
        host_ssh_port: Optional[str] = None,
        host_ssh_key_path: Optional[str] = None,
        host_ssh_passwordless: bool = False,
        host_ssh_max_retries: Optional[int] = None,
    ) -> None:
        """
        Execute the preflight command logic.

        Performs connectivity checks and validates configuration without
        actually collecting any logs.

        Args:
            config_file (Optional[Path]): Tool configuration file path.
            dut_config (Optional[Path]): DUT configuration file path.
            spreadsheet (Optional[Path]): Collector definitions spreadsheet path.
            json_output (bool): Output in JSON format.
            output_file (Optional[str]): File path for output.
            local (bool): Run in local mode.
            bmc_ip, bmc_user, bmc_pass, etc.: BMC configuration parameters.
            host_ip, host_user, host_pass, etc.: Host configuration parameters.
        """
        # Determine if we're in CLI mode or config file mode
        # Only trigger CLI mode if actual values are provided (not None or default values)
        cli_mode = (
            local  # Local mode always triggers CLI mode
            or any(
                [
                    # BMC Configuration
                    bmc_ip,
                    bmc_user,
                    bmc_pass,
                    bmc_ssh_user,
                    bmc_ssh_pass,
                    bmc_ssh_port,
                    bmc_ssh_key_path,
                    bmc_ssh_passwordless,
                    bmc_ssh_max_retries,
                    bmc_rf_user,
                    bmc_rf_pass,
                    bmc_rf_port,
                    # Host Configuration
                    host_ip,
                    host_user,
                    host_pass,
                    host_ssh_port,
                    host_ssh_key_path,
                    host_ssh_passwordless,
                    host_ssh_max_retries,
                ]
            )
            and any(
                [
                    # Check that at least one meaningful value is provided
                    bmc_ip,
                    bmc_user,
                    bmc_pass,
                    host_ip,
                    host_user,
                    host_pass,
                ]
            )
        )

        if cli_mode and dut_config:
            # Use stderr for warnings to avoid corrupting JSON output

            print(
                "Warning: Both CLI credentials and DUT config file are provided.",
                file=sys.stderr,
            )
            print(
                "CLI credentials will be used, ignoring the DUT config file.",
                file=sys.stderr,
            )

        if cli_mode:
            # Create DUT config from CLI arguments

            # Create DUTConfig object first
            dut_config_obj = DUTConfig(
                name="dut-1",
                baseboard=None,  # Allow auto-detection
                local=local,  # Set local mode
                # BMC Configuration - use uppercase field names
                BMC_IP=bmc_ip,
                BMC_USERNAME=bmc_user,
                BMC_PASSWORD=bmc_pass,
                BMC_SSH_USERNAME=bmc_ssh_user,
                BMC_SSH_PASSWORD=bmc_ssh_pass,
                BMC_SSH_PORT=bmc_ssh_port,
                BMC_SSH_KEY_PATH=bmc_ssh_key_path,
                BMC_SSH_PASSWORDLESS=bmc_ssh_passwordless,
                BMC_SSH_MAX_RETRIES=bmc_ssh_max_retries,
                RF_User=bmc_rf_user,
                RF_Pass=bmc_rf_pass,
                BMC_RF_PORT=bmc_rf_port,
                # Host Configuration - use uppercase field names
                HOST_IP=host_ip,
                HOST_USERNAME=host_user,
                HOST_PASSWORD=host_pass,
                HOST_SSH_PORT=host_ssh_port,
                HOST_SSH_KEY_PATH=host_ssh_key_path,
                HOST_SSH_PASSWORDLESS=host_ssh_passwordless,
                HOST_SSH_MAX_RETRIES=host_ssh_max_retries,
            )

            # Convert to dictionary format expected by DUTManager
            dut_configs = {
                "DUT_Defaults": {},
                "dut-1": dut_config_obj.model_dump(),
            }
        else:
            # Load DUT configs from file
            if not dut_config:
                # Try auto-detection like the collect command does
                from .utils.resources import find_all_config_files

                self.sanitized_console.print_info(
                    "No DUT config file provided - attempting auto-detection..."
                )

                # Auto-detect configuration files in the same directory as the executable
                auto_dut_config, auto_config, auto_tool_config = find_all_config_files()

                if auto_dut_config:
                    dut_config = auto_dut_config
                    if not json_output:
                        self.sanitized_console.print_info(
                            f"Auto-detected DUT config file: {dut_config}"
                        )
                else:
                    self.sanitized_console.print_error(
                        "Auto-detection did not find dut_config.yaml in executable directory. "
                        "Please provide one of the following:\n"
                        "  • --dut-config <file> - Use a DUT configuration file\n"
                        "  • --local - Run in local mode (no remote access needed)\n"
                        "  • BMC credentials - Provide --bmc-ip, --bmc-user, --bmc-pass\n"
                        "  • Host credentials - Provide --host-ip, --host-user, --host-pass"
                    )
                    return

            # Load DUT configs (same as collect command)
            try:
                dut_configs = load_dut_config(dut_config, quiet_mode=json_output)
                if not json_output:
                    self.sanitized_console.print_success(
                        f"Loaded DUT config from: {dut_config}"
                    )
            except Exception as e:
                if json_output:
                    # For JSON output, use simple error message
                    self.sanitized_console.print_error(
                        f"Error loading DUT config file: {e}"
                    )
                else:
                    # For regular output, use pretty formatted error
                    display_dut_config_error(str(e))
                return

        # Create tool config specifically for preflight (no spreadsheet needed)
        # Create tool config specifically for preflight (use same logic as collect command)
        # Auto-detect spreadsheet if not provided
        if spreadsheet:
            spreadsheet = Path(spreadsheet)
        else:
            # Try to auto-detect spreadsheet like the collect command does
            spreadsheet = self._auto_detect_spreadsheet()

        # Use the same configuration logic as the collect command
        # For JSON output, use quiet mode to suppress initialization messages
        # For non-JSON output, use full mode to get DUT manager
        tool_config_obj = self._create_tool_config_object(
            spreadsheet=spreadsheet,
            quiet_mode=json_output,
            config_file=config_file,
        )

        # Preflight command should skip HTML reports and zip generation
        tool_config_obj["skip_html_reports"] = True
        tool_config_obj["skip_zip"] = True
        tool_config_obj["skip_zip_split"] = True

        # Create log directory
        log_dir = Path("logs/preflight")
        log_dir.mkdir(parents=True, exist_ok=True)

        # Create orchestrator using the newer pattern
        try:
            orchestrator = WorkflowOrchestrator(
                tool_config=tool_config_obj,
                dut_configs=dut_configs,
                log_dir=str(log_dir),
                sanitized_console=self.sanitized_console,
                quiet_mode=json_output,  # Use quiet mode for JSON output to suppress messages
            )

            # Set sanitizer in orchestrator (required for engine initialization)
            orchestrator.set_sanitizer(None)  # Preflight doesn't need sanitization

        except Exception as e:
            self.sanitized_console.print_error(f"Error creating orchestrator: {e}")
            raise

        # Initialize orchestrator
        try:
            await orchestrator.initialize()

            # For JSON output, manually initialize DUT manager since quiet mode doesn't do it
            if json_output and not orchestrator.dut_manager:
                from src.tool.core.dut_manager import DUTManager
                from src.tool.utils.uri_config_manager import URIConfigManager

                # Create URI config manager
                uri_config_manager = (
                    orchestrator.config_manager.get_uri_config_manager()
                )

                # Get spreadsheet configuration
                tool_config = orchestrator.config_manager.get_tool_config()
                spreadsheet_path = tool_config.get("collector_definitions", {}).get(
                    "spreadsheet_path"
                )

                # Create and initialize DUT manager
                orchestrator.dut_manager = DUTManager(
                    orchestrator.config_manager.get_dut_config(),
                    str(orchestrator.log_dir),
                    uri_config_manager,
                    spreadsheet_path=spreadsheet_path,
                    sanitized_console=orchestrator.sanitized_console,
                    tool_config=orchestrator.config_manager.get_tool_config(),
                    debug_mode=orchestrator.debug_mode,
                    redfish_session_config=tool_config.get(
                        "redfish_session_config", {}
                    ),
                )

                await orchestrator.dut_manager.initialize()

                # Update engines with DUT manager
                orchestrator.execution_engine.dut_manager = orchestrator.dut_manager
                orchestrator.reporting_engine.dut_manager = orchestrator.dut_manager

        except Exception as e:
            self.sanitized_console.print_error(f"Error initializing orchestrator: {e}")
            raise

        # Run preflight checks (suppress progress bar for JSON output)
        show_progress = not json_output
        results = await orchestrator.run_preflight_checks(show_progress=show_progress)

        # Check if results contain an error
        if results and "error" in results:
            self.sanitized_console.print_error(
                f"Preflight checks failed: {results['error']}"
            )
            return

        # Handle output - only use CLI output handling for JSON output or file output
        # The orchestrator already displays the table results to console for non-JSON output
        if json_output or output_file:
            # Use shared output handling for JSON output or file output
            if results and len(results) > 0:
                self._handle_output(
                    results,
                    json_output=json_output,
                    output_file=output_file,
                    output_type="preflight",
                )
            else:
                if json_output:
                    # Output empty JSON
                    self._handle_output(
                        {},
                        json_output=True,
                        output_file=output_file,
                        output_type="preflight",
                    )
                else:
                    # Write empty result to file
                    self._handle_output(
                        {},
                        json_output=False,
                        output_file=output_file,
                        output_type="preflight",
                    )
        else:
            # For non-JSON console output, the orchestrator already displayed the results
            # Only show a message if there are no results
            if not results or len(results) == 0:
                self.sanitized_console.print_warning("No preflight results to display")

        # Cleanup
        await orchestrator.cleanup()

    def _auto_detect_spreadsheet(self) -> Optional[Path]:
        """
        Auto-detect the latest Telemetry Catalog spreadsheet in config directory.

        Returns:
            Optional[Path]: Path to detected spreadsheet, or None if not found.
        """
        return auto_detect_spreadsheet(None, suppress_print=True)
