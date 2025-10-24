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
Open-NVDebug Tool - Main Entry Point

This tool collects system logs and debug information from NVIDIA platforms.
"""

import asyncio
import concurrent.futures
import os
import sys
from pathlib import Path
from typing import List, Optional

import click
import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from .cli_handler import (
    CLICollector,
    CLIDefaultCollectors,
    CLIListBaseboards,
    CLIListCollectors,
    CLIPreflight,
    ToolConfig,
)
from .config import (
    DUTConfig,
    auto_assign_config_file_to_use,
    get_available_baseboards,
    load_config,
    load_dut_config,
    validate_baseboard,
)
from .core.workflow_orchestrator import WorkflowOrchestrator
from .utils.ansible_inventory import (
    cleanup_temp_config_files,
    generate_config_files_from_ansible,
)
from .utils.console_output import create_sanitized_console
from .utils.logging import setup_logging
from .utils.resources import (
    find_all_config_files,
    find_config_directory,
    find_config_files,
)
from .utils.spreadsheet_utils import (
    auto_detect_spreadsheet,
    validate_spreadsheet_requirement,
)
from .utils.validation import (
    display_dut_config_error,
    display_validation_errors,
    run_comprehensive_validation,
    validate_collection_level,
    validate_collector_groups,
    validate_collector_ids,
)
from .utils.yaml_validator import YAMLValidator
from .version import __build_hash__, __build_time__, __version__

# Create Typer app
app = typer.Typer(
    name="nvdebug",
    help="NVDebug - NVIDIA Log Collection Tool",
    add_completion=False,
    context_settings={
        "help_option_names": ["-h", "--help"],
        "max_content_width": 120,
    },
)


# Rich console for output (sanitized wrapper used for strings)

console = Console()
sanitized_console = create_sanitized_console()


def version_callback(value: bool) -> None:
    """
    Print version information and exit the application.

    Args:
        value (bool): If True, print version and exit.

    Raises:
        typer.Exit: Always raises Exit after printing version info.
    """
    if value:
        sanitized_console.print_info(
            f"nvdebug {__version__}  (build {__build_hash__} @ {__build_time__})"
        )
        raise typer.Exit()


def get_collection_level_from_v_count(count: int) -> str:
    """
    Convert verbosity count (-V flags) to collection level.

    Args:
        count (int): Number of -V flags provided.

    Returns:
        str: Collection level ("L1", "L2", or "L3").
            - 0: L1
            - 1: L2
            - 2+: L3
    """
    if count == 1:
        return "L2"
    elif count >= 2:
        return "L3"  # Any number of V's >= 2 maps to L3
    else:
        return "L1"


def get_higher_collection_level(level1: str, level2: str) -> str:
    """
    Get the higher collection level between two levels.

    Args:
        level1 (str): First collection level (L1, L2, or L3).
        level2 (str): Second collection level (L1, L2, or L3).

    Returns:
        str: The higher collection level.
    """
    level_mapping = {"L1": 1, "L2": 2, "L3": 3}
    level1_num = level_mapping.get(level1.upper(), 1)
    level2_num = level_mapping.get(level2.upper(), 1)
    return (
        "L3"
        if max(level1_num, level2_num) == 3
        else "L2" if max(level1_num, level2_num) == 2 else "L1"
    )


@app.callback(
    help="NVIDIA Debug Collection Tool\n\nEach command has dedicated COMMAND OPTIONS/ARGS. Run 'nvdebug COMMAND --help' to see them.\n\nExamples:\n\n -  nvdebug collect --dut-config dut_config.yaml\n\n -  nvdebug preflight --dut-config dut_config.yaml\n\n -  nvdebug --version",
    invoke_without_command=True,
)
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=version_callback,
        help="Show version and exit",
    ),
) -> None:
    """
    Main entry point callback for the NVDebug CLI application.

    This function is invoked when the CLI is called without a subcommand,
    displaying help information to guide the user.

    Args:
        version (Optional[bool]): Flag to display version information.

    Raises:
        typer.Exit: Exits with code 0 after showing help.
    """

    ctx = click.get_current_context()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(0)


@app.command(
    help='Collect system logs and debug information.\n\nExamples:\n\n -  nvdebug collect --dut-config dut_config.yaml\n\n -  nvdebug collect -i 10.0.0.1 -u admin -p pass -S "R1 R2 H4"'
)
def collect(
    # Required arguments (can be provided via CLI or config files)
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file path (auto-detected if not provided)",
    ),
    dut_config: Optional[Path] = typer.Option(
        None,
        "--dut-config",
        "-d",
        help="DUT configuration file (auto-detected if not provided)",
    ),
    spreadsheet: Optional[Path] = typer.Option(
        None, "--spreadsheet", help="Collector spreadsheet path"
    ),
    baseboard: Optional[str] = typer.Option(
        None, "--baseboard", "-b", help="Target baseboard"
    ),
    ansible_inventory: Optional[Path] = typer.Option(
        None, "--ansible-inventory", help="Ansible inventory file path"
    ),
    # Local Configuration
    local: bool = typer.Option(False, "--local", help="Run in local mode"),
    # Optional arguments
    output_dir: Path = typer.Option(
        Path("/tmp"), "--output", "-o", help="Output directory"
    ),
    skip_validation: bool = typer.Option(
        False, "--skip-validation", help="Skip all validation checks"
    ),
    # Collector Configuration
    collector_id: Optional[str] = typer.Option(
        None,
        "--collector-id",
        "-S",
        help="Specific collector IDs to run (space or comma separated)",
    ),
    collector_group: Optional[List[str]] = typer.Option(
        None, "--collector-group", "-g", help="Specific log groups to run"
    ),
    collection_level: Optional[str] = typer.Option(
        None, "--level", help="Collection level (L1, L2, L3)"
    ),
    collection_level_v: int = typer.Option(
        0,
        "-V",
        count=True,
        help="Collection level: -V for L2, -VV or more for L3",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be executed"
    ),
    # Logging Configuration
    debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print detailed output"
    ),
    # BMC Configuration
    bmc_ip: Optional[str] = typer.Option(None, "--bmc-ip", "-i", help="BMC IP address"),
    bmc_user: Optional[str] = typer.Option(
        None, "--bmc-user", "-u", help="BMC username"
    ),
    bmc_pass: Optional[str] = typer.Option(
        None, "--bmc-pass", "-p", help="BMC password"
    ),
    bmc_ssh_user: Optional[str] = typer.Option(
        None, "--bmc-ssh-user", "-r", help="BMC SSH username"
    ),
    bmc_ssh_pass: Optional[str] = typer.Option(
        None, "--bmc-ssh-pass", "-w", help="BMC SSH password"
    ),
    bmc_ssh_port: Optional[int] = typer.Option(
        None, "--bmc-ssh-port", help="BMC SSH port"
    ),
    bmc_ssh_key_path: Optional[str] = typer.Option(
        None, "--bmc-ssh-key-path", help="BMC SSH key path"
    ),
    bmc_ssh_passwordless: bool = typer.Option(
        False, "--bmc-ssh-passwordless", help="Use passwordless SSH for BMC"
    ),
    bmc_ssh_max_retries: Optional[int] = typer.Option(
        3, "--bmc-ssh-max-retries", help="BMC SSH max retry attempts"
    ),
    bmc_rf_user: Optional[str] = typer.Option(
        None, "--bmc-rf-user", "-R", help="Redfish username"
    ),
    bmc_rf_pass: Optional[str] = typer.Option(
        None, "--bmc-rf-pass", "-W", help="Redfish password"
    ),
    bmc_rf_port: Optional[int] = typer.Option(
        None, "--bmc-rf-port", help="Redfish port"
    ),
    # Host Configuration
    host_ip: Optional[str] = typer.Option(
        None, "--host-ip", "-I", help="Host IP address"
    ),
    host_user: Optional[str] = typer.Option(
        None, "--host-user", "-U", help="Host username"
    ),
    host_pass: Optional[str] = typer.Option(
        None, "--host-pass", "-H", help="Host password"
    ),
    host_ssh_port: Optional[str] = typer.Option(
        None, "--host-ssh-port", "-P", help="Tunnel TCP port"
    ),
    host_ssh_key_path: Optional[str] = typer.Option(
        None, "--host-ssh-key-path", help="Host SSH key path"
    ),
    host_ssh_passwordless: bool = typer.Option(
        False, "--host-ssh-passwordless", help="Use passwordless SSH for Host"
    ),
    host_ssh_max_retries: Optional[int] = typer.Option(
        3, "--host-ssh-max-retries", help="Host SSH max retry attempts"
    ),
    # HMC Configuration
    hmc_ip: Optional[str] = typer.Option(None, "--hmc-ip", help="HMC IP address"),
    hmc_user: Optional[str] = typer.Option(None, "--hmc-user", help="HMC username"),
    hmc_pass: Optional[str] = typer.Option(None, "--hmc-pass", help="HMC password"),
    hmc_ssh_user: Optional[str] = typer.Option(
        None, "--hmc-ssh-user", help="HMC SSH username"
    ),
    hmc_ssh_pass: Optional[str] = typer.Option(
        None, "--hmc-ssh-pass", help="HMC SSH password"
    ),
    hmc_ssh_port: Optional[int] = typer.Option(
        None, "--hmc-ssh-port", help="HMC SSH port"
    ),
    hmc_ssh_key_path: Optional[str] = typer.Option(
        None, "--hmc-ssh-key-path", help="HMC SSH key path"
    ),
    hmc_ssh_passwordless: bool = typer.Option(
        False, "--hmc-ssh-passwordless", help="Use passwordless SSH for HMC"
    ),
    hmc_ssh_max_retries: Optional[int] = typer.Option(
        3, "--hmc-ssh-max-retries", help="HMC SSH max retry attempts"
    ),
    hmc_http_port: Optional[int] = typer.Option(
        80, "--hmc-http-port", help="HMC HTTP port"
    ),
    hmc_https_port: Optional[int] = typer.Option(
        443, "--hmc-https-port", help="HMC HTTPS port"
    ),
    hmc_use_https: bool = typer.Option(
        False, "--hmc-use-https", help="Use HTTPS for HMC"
    ),
    hmc_use_port_forwarding: bool = typer.Option(
        False, "--hmc-use-port-forwarding", help="Enable HMC port forwarding"
    ),
    use_port_forwarding: bool = typer.Option(
        False, "--use-port-forwarding", help="Enable port forwarding (general)"
    ),
    tunnel_tcp_port: Optional[int] = typer.Option(
        None, "--tunnel-tcp-port", help="Port for SSH tunnel forwarding"
    ),
    setup_port_forwarding: bool = typer.Option(
        None,
        "--setup-port-forwarding",
        help="Auto-setup port forwarding tunnels",
    ),
    force_port_fw: bool = typer.Option(
        None,
        "--force-port-fw",
        help="Force cleanup existing port forwarding tunnels",
    ),
    hmc_access_method: Optional[str] = typer.Option(
        None,
        "--hmc-access-method",
        help="HMC access method (HostBmcTcpPortForwarding, HostBmcAggregation, HostBmcSshAccess, None)",
    ),
    # SSH Proxy Configuration
    ssh_proxy_host: Optional[str] = typer.Option(
        None, "--ssh-proxy-host", help="SSH proxy hostname/IP"
    ),
    ssh_proxy_port: Optional[int] = typer.Option(
        22, "--ssh-proxy-port", help="SSH proxy port"
    ),
    ssh_proxy_user: Optional[str] = typer.Option(
        None, "--ssh-proxy-user", help="SSH proxy username"
    ),
    ssh_proxy_pass: Optional[str] = typer.Option(
        None, "--ssh-proxy-pass", help="SSH proxy password"
    ),
    ssh_proxy_key_path: Optional[str] = typer.Option(
        None, "--ssh-proxy-key-path", help="SSH proxy private key path"
    ),
    ssh_proxy_passwordless: bool = typer.Option(
        False,
        "--ssh-proxy-passwordless",
        help="Use passwordless SSH for proxy",
    ),
    ssh_proxy_max_retries: Optional[int] = typer.Option(
        3, "--ssh-proxy-max-retries", help="SSH proxy max retry attempts"
    ),
    # Archive Configuration
    skip_zip: bool = typer.Option(False, "--skip-zip", "-z", help="Skip zip creation"),
    skip_zip_split: bool = typer.Option(
        False, "--skip-zip-split", "-Z", help="Skip splitting zip archive"
    ),
    zip_split_threshold: float = typer.Option(
        200.0, "--zip-split-threshold", help="Zip archive size threshold (MB)"
    ),
    # Common Configuration
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Non-interactive mode - use detected values or exit if detection fails",
    ),
    skip_preflight: bool = typer.Option(
        False,
        "--skip-preflight",
        help="Skip preflight checks (useful for testing with unreachable DUTs)",
    ),
    skip_sanitization: bool = typer.Option(
        False,
        "--skip-sanitization",
        help="Skip log sanitization (sanitization is enabled by default)",
    ),
    skip_html_reports: bool = typer.Option(
        False, "--skip-html-reports", help="Skip HTML report generation"
    ),
    # Collector Skip Configuration
    skip_collectors: Optional[str] = typer.Option(
        None,
        "--skip-collectors",
        help="List of collector IDs to skip (comma-separated)",
    ),
    include_collectors: Optional[str] = typer.Option(
        None,
        "--include-collectors",
        help="List of collector IDs to include (comma-separated, only these will run)",
    ),
) -> None:
    """
    Collect system logs and debug information from NVIDIA platforms.

    This command collects comprehensive system logs, debug information, and diagnostic
    data from target devices (DUTs). It supports multiple collection modes: local mode,
    single-DUT CLI mode, and multi-DUT configuration file mode.

    Args:
        config_file (Optional[Path]): Tool configuration file path.
        dut_config (Optional[Path]): DUT configuration file path.
        spreadsheet (Optional[Path]): Collector definitions spreadsheet path.
        baseboard (Optional[str]): Target baseboard name.
        ansible_inventory (Optional[Path]): Ansible inventory file for multi-DUT setup.
        local (bool): Run collection in local mode (no remote access).
        output_dir (Path): Directory for output files.
        skip_validation (bool): Skip validation checks.
        collector_id (Optional[str]): Specific collector IDs to run.
        collector_group (Optional[List[str]]): Specific collector groups to run.
        collection_level (Optional[str]): Collection level (L1/L2/L3).
        collection_level_v (int): Verbosity count for collection level.
        dry_run (bool): Show what would be executed without running.
        debug (bool): Enable debug output.
        verbose (bool): Enable verbose output.
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
        hmc_ip (Optional[str]): HMC IP address.
        hmc_user (Optional[str]): HMC username.
        hmc_pass (Optional[str]): HMC password.
        hmc_ssh_user (Optional[str]): HMC SSH username.
        hmc_ssh_pass (Optional[str]): HMC SSH password.
        hmc_ssh_port (Optional[int]): HMC SSH port.
        hmc_ssh_key_path (Optional[str]): HMC SSH key path.
        hmc_ssh_passwordless (bool): Use passwordless SSH for HMC.
        hmc_ssh_max_retries (Optional[int]): HMC SSH max retry attempts.
        hmc_http_port (Optional[int]): HMC HTTP port.
        hmc_https_port (Optional[int]): HMC HTTPS port.
        hmc_use_https (bool): Use HTTPS for HMC.
        hmc_use_port_forwarding (bool): Enable HMC port forwarding.
        use_port_forwarding (bool): Enable port forwarding.
        tunnel_tcp_port (Optional[int]): Port for SSH tunnel forwarding.
        setup_port_forwarding (bool): Auto-setup port forwarding tunnels.
        force_port_fw (bool): Force cleanup existing port forwarding.
        hmc_access_method (Optional[str]): HMC access method.
        ssh_proxy_host (Optional[str]): SSH proxy hostname/IP.
        ssh_proxy_port (Optional[int]): SSH proxy port.
        ssh_proxy_user (Optional[str]): SSH proxy username.
        ssh_proxy_pass (Optional[str]): SSH proxy password.
        ssh_proxy_key_path (Optional[str]): SSH proxy private key path.
        ssh_proxy_passwordless (bool): Use passwordless SSH for proxy.
        ssh_proxy_max_retries (Optional[int]): SSH proxy max retry attempts.
        skip_zip (bool): Skip zip archive creation.
        skip_zip_split (bool): Skip splitting zip archive.
        zip_split_threshold (float): Zip archive size threshold in MB.
        non_interactive (bool): Non-interactive mode.
        skip_preflight (bool): Skip preflight checks.
        skip_sanitization (bool): Skip log sanitization.
        skip_html_reports (bool): Skip HTML report generation.
        skip_collectors (Optional[str]): Collector IDs to skip (comma-separated).
        include_collectors (Optional[str]): Collector IDs to include (comma-separated).

    Raises:
        SystemExit: Exits with code 1 on errors.
        KeyboardInterrupt: Exits with code 1 if interrupted by user.
    """

    # Default Status Tracking Configuration
    enable_status_tracking = True
    disable_live_display = False

    # Auto-detect spreadsheet if not provided
    spreadsheet = auto_detect_spreadsheet(spreadsheet)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet)

    # Determine final collection level based on --level and -V/-VV flags
    # If both are specified, take the higher level
    v_level = get_collection_level_from_v_count(collection_level_v)
    # Only use CLI level if it's explicitly provided (not None)
    if collection_level is not None or collection_level_v > 0:
        cli_level = collection_level if collection_level is not None else "L1"
        final_collection_level = get_higher_collection_level(cli_level, v_level)
    else:
        # No CLI level specified - will be determined later from config file
        final_collection_level = None

    # Create tool config from CLI arguments
    # Auto-detect spreadsheet if not provided
    if not spreadsheet:
        spreadsheet = auto_detect_spreadsheet(spreadsheet)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet)

    # Note: config_file_data will be loaded after auto-detection logic below
    config_file_data = {}

    # Initialize final_output_dir with CLI value (will be updated by config file logic if available)
    final_output_dir = str(output_dir)

    # Note: Output directory logic will be handled after config loading below

    # Load additional configuration values from config file
    # Note: CLI parameters take precedence over config file values
    # For boolean CLI parameters, we need to check if they were explicitly set vs using defaults

    # Helper function to determine if a CLI parameter should override config file
    def should_use_cli_value(cli_value, config_value, default_value):
        """
        Determine if CLI value should override config file value.

        This function implements precedence logic: explicitly set CLI values
        override config file values, but default CLI values defer to config file.

        Args:
            cli_value: Value from CLI parameter.
            config_value: Value from config file.
            default_value: Default value for the parameter.

        Returns:
            bool: True if CLI value should be used, False if config file value should be used.
        """
        # If CLI value is different from default, use CLI value
        if cli_value != default_value:
            return True
        # If CLI value equals default and config file has a different value, use config file
        if config_value != default_value:
            return False
        # Otherwise use CLI value (which equals default)
        return True

    # Execution configuration
    max_concurrent_duts = getattr(config_file_data, "max_concurrent_duts", 1)
    max_concurrent_collectors_per_dut = getattr(
        config_file_data, "max_concurrent_collectors_per_dut", 1
    )
    timeout = getattr(config_file_data, "timeout", 300)
    retry_count = getattr(config_file_data, "retry_count", 3)

    # Pagination configuration (not available as CLI parameters)
    max_pagination_pages = getattr(config_file_data, "max_pagination_pages", 100)
    max_duplicate_url_retries = getattr(
        config_file_data, "max_duplicate_url_retries", 3
    )

    # Output configuration
    # Convert create_zip/create_split_zip to skip_zip/skip_zip_split
    if hasattr(config_file_data, "output"):
        config_create_zip = getattr(config_file_data.output, "create_zip", True)
        config_create_split_zip = getattr(
            config_file_data.output, "create_split_zip", True
        )
        config_zip_split_threshold = getattr(
            config_file_data.output, "zip_split_threshold", 200.0
        )
    else:
        config_create_zip = True
        config_create_split_zip = True
        config_zip_split_threshold = 200.0

    # Convert create_* to skip_* (invert the logic)
    config_skip_zip = not config_create_zip
    config_skip_zip_split = not config_create_split_zip

    # Logging configuration
    config_log_level = getattr(config_file_data, "log_level", "INFO")
    config_log_format = getattr(
        config_file_data,
        "log_format",
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    )

    # Parallelization configuration
    parallel_dut_sequential_collectors = getattr(
        config_file_data, "PARALLEL_DUT_SEQUENTIAL_COLLECTORS", True
    )
    service_grouped_sequential_collectors = getattr(
        config_file_data, "SERVICE_GROUPED_SEQUENTIAL_COLLECTORS", True
    )

    # Other configuration - will be read after config file is loaded
    config_generate_html_reports = (
        True  # Default value, will be updated after config loading
    )
    config_auto_parse = True  # Default value, will be updated after config loading
    config_log_sanitization = (
        True  # Default value, will be updated after config loading
    )

    # URI configuration (not available as CLI parameters)
    uri_overrides = getattr(config_file_data, "uri_overrides", {})

    # Note: Configuration values are loaded from config file and will be logged
    # through the normal logging system when it becomes available later in the workflow

    # Store additional config values that aren't part of ToolConfig but are needed elsewhere
    # These will be passed to the orchestrator or other components
    # Note: These values can be logged through the normal logging system when it becomes available
    additional_config = {
        "max_pagination_pages": max_pagination_pages,
        "max_duplicate_url_retries": max_duplicate_url_retries,
        "uri_overrides": uri_overrides,
        "auto_parse": config_auto_parse,
        "log_sanitization": config_log_sanitization,
        "generate_html_reports": config_generate_html_reports,
    }

    # Add LogSanitization to tool_config for proper access
    if hasattr(config_file_data, "__dict__"):
        config_file_data.LogSanitization = config_log_sanitization

    # Prepare CLI credentials dictionary for validation
    cli_credentials = {
        "bmc_ip": bmc_ip,
        "bmc_user": bmc_user,
        "bmc_pass": bmc_pass,
        "host_ip": host_ip,
        "host_user": host_user,
        "host_pass": host_pass,
    }

    # Track reported configuration errors to prevent duplicates
    _reported_config_errors = set()

    # Handle Ansible inventory if provided
    temp_config_file = None
    temp_dut_config_file = None

    # Store original DUT config path for cleanup (in case auto-assignment creates temp file)
    original_dut_config = dut_config

    if ansible_inventory:
        if not ansible_inventory.exists():
            sanitized_console.print_error(
                f"Error: Ansible inventory file '{ansible_inventory}' does not exist"
            )
            sys.exit(1)

        # Check if both ansible inventory and dut config are provided
        if dut_config and dut_config.exists():
            sanitized_console.print_warning(
                "Warning: Both ansible inventory and DUT config files are provided."
            )
            sanitized_console.print_warning(
                "Ansible inventory will be used to generate DUT config, ignoring the provided DUT config file."
            )
            sanitized_console.print_info(f"Ansible file: {ansible_inventory}")
            sanitized_console.print_info(f"DUT config file (ignored): {dut_config}")

        try:
            sanitized_console.print_info(
                f"Parsing ansible inventory file: {ansible_inventory}"
            )

            # Generate config files from ansible inventory
            temp_config_file, temp_dut_config_file = generate_config_files_from_ansible(
                ansible_inventory, baseboard
            )

            # Use the generated files
            config_file = temp_config_file
            dut_config = temp_dut_config_file

            sanitized_console.print_info(
                f"Generated config files from ansible inventory: {temp_config_file}, {temp_dut_config_file}"
            )

        except Exception as e:
            sanitized_console.print_error(f"Error parsing ansible inventory file: {e}")
            sys.exit(1)

    # Check if CLI connection IPs are provided (only IP addresses matter for CLI mode detection)
    connection_ips = [
        ("bmc_ip", bmc_ip),
        ("host_ip", host_ip),
        ("hmc_ip", hmc_ip),
    ]

    has_cli_credentials = any(value for name, value in connection_ips)

    # Always try auto-detection if no explicit DUT config file is provided
    # This allows CLI credentials to supplement/override auto-detected configs
    if not dut_config:
        if not has_cli_credentials and not local:
            sanitized_console.print_info(
                "No CLI credentials provided - attempting auto-detection of configuration files..."
            )

        # Auto-detect configuration files in the same directory as the executable
        auto_dut_config, auto_config, auto_tool_config = find_all_config_files()

        if auto_dut_config:
            dut_config = auto_dut_config
            sanitized_console.print_info(
                f"Auto-detected DUT tool_config file: {dut_config}"
            )
        else:
            # Only error if we don't have CLI credentials or local mode
            if not has_cli_credentials and not local:
                sanitized_console.print_error(
                    "Auto-detection did not find dut_config.yaml in executable directory. "
                    "Please provide one of the following:\n"
                    "  • --dut-config <file> - Use a DUT configuration file\n"
                    "  • --local - Run in local mode (no remote access needed)\n"
                    "  • BMC credentials - Provide --bmc-ip, --bmc-user, --bmc-pass\n"
                    "  • Host credentials - Provide --host-ip, --host-user, --host-pass"
                )
                sys.exit(1)

        # Auto-detect config.yaml or tool_config.yaml if not provided
        if not config_file:
            if auto_tool_config:
                # Prefer tool_config.yaml (new format) over config.yaml (legacy)
                config_file = auto_tool_config
                sanitized_console.print_info(
                    f"Auto-detected tool_config.yaml file: {config_file}"
                )
            elif auto_config:
                # Fall back to config.yaml (legacy format)
                config_file = auto_config
                sanitized_console.print_info(
                    f"Auto-detected config.yaml file (legacy): {config_file}"
                )
            else:
                sanitized_console.print_info(
                    "No tool_config.yaml or config.yaml found via auto-detection"
                )

        # Handle output directory logic after auto-detection (if config file was found)
        tool_config_baseboard = None  # Track baseboard from tool_config for CLI mode
        if config_file and config_file.exists():
            try:
                config_file_data = load_config(config_file)
                sanitized_console.print_info(
                    f"Auto-loaded tool configuration from: {config_file}"
                )

                # Update config values after config file is loaded
                if hasattr(config_file_data, "output") and hasattr(
                    config_file_data.output, "generate_html"
                ):
                    config_generate_html_reports = config_file_data.output.generate_html
                else:
                    config_generate_html_reports = getattr(
                        config_file_data, "GENERATE_HTML_REPORTS", True
                    )
                config_auto_parse = getattr(config_file_data, "AUTO_PARSE", True)
                # Check for new sanitization format first, then fall back to legacy
                if (
                    hasattr(config_file_data, "sanitization")
                    and config_file_data.sanitization
                ):
                    config_log_sanitization = config_file_data.sanitization.get(
                        "enabled", True
                    )
                else:
                    config_log_sanitization = getattr(
                        config_file_data, "LogSanitization", True
                    )

                # Extract baseboard from tool_config for use in CLI mode
                # Check for both 'baseboard' (new format) and 'TargetBaseboard' (legacy format)
                # IMPORTANT: Only use if explicitly set in config file, not the default value
                tool_config_baseboard = None

                # Check TargetBaseboard (legacy field) - this doesn't have a default
                if (
                    hasattr(config_file_data, "TargetBaseboard")
                    and config_file_data.TargetBaseboard
                ):
                    tool_config_baseboard = config_file_data.TargetBaseboard
                # Check baseboard field - only if it's not the default value "compute"
                elif (
                    hasattr(config_file_data, "baseboard")
                    and config_file_data.baseboard
                    and config_file_data.baseboard != "compute"
                ):
                    tool_config_baseboard = config_file_data.baseboard

                if tool_config_baseboard:
                    sanitized_console.print_info(
                        f"Found baseboard '{tool_config_baseboard}' in tool_config.yaml"
                    )

                # Update output directory if config file has one and CLI didn't override it
                if (
                    hasattr(config_file_data, "output")
                    and hasattr(config_file_data.output, "directory")
                    and config_file_data.output.directory
                    and (
                        str(output_dir) == "/tmp" or output_dir == Path("/tmp")
                    )  # Only use config file when CLI uses default
                ):
                    final_output_dir = str(config_file_data.output.directory)
                    # Expand ~ to home directory if present
                    if final_output_dir.startswith("~"):
                        final_output_dir = os.path.expanduser(final_output_dir)
                    sanitized_console.print_info(
                        f"Using output directory from auto-detected tool config: {final_output_dir}"
                    )
                # Note: We don't use config file for relative paths - CLI relative paths should be honored
            except Exception as e:
                # Provide more specific error messages based on the exception type
                # Track error to prevent duplicates
                error_key = f"tool_config_{str(e)}"
                if error_key not in _reported_config_errors:
                    _reported_config_errors.add(error_key)
                    if "Invalid YAML" in str(e):
                        sanitized_console.print_warning(
                            f"Warning: Tool config file has YAML syntax errors: {e}"
                        )
                    elif "not found" in str(e).lower():
                        sanitized_console.print_warning(
                            f"Warning: Tool config file not found or inaccessible: {e}"
                        )
                    elif "Permission denied" in str(e):
                        sanitized_console.print_warning(
                            f"Warning: Permission denied reading tool config file: {e}"
                        )
                    else:
                        sanitized_console.print_warning(
                            f"Warning: Could not auto-load tool config file due to validation errors: {e}"
                        )
                    sanitized_console.print_warning(
                        "Continuing with default configuration values"
                    )
                config_file_data = {}

    # Determine if we're in single DUT CLI mode or multi-DUT config mode
    # CLI mode is triggered if:
    # 1. We have CLI connection credentials provided (overrides any auto-detected config), OR
    # 2. We're in local mode AND no explicit DUT config file was provided
    # Note: Auto-detected config files should not prevent CLI mode
    cli_mode = has_cli_credentials or (local and not original_dut_config)

    # Run early validation only for collection level (other validation happens after auto-detection)
    if not skip_validation and collection_level is not None:
        is_valid, collection_errors = validate_collection_level(collection_level)
        if not is_valid:
            display_validation_errors(collection_errors)
            sys.exit(1)

    # Handle CLI vs config file precedence
    if cli_mode:
        # Check if we have an auto-detected DUT config file from earlier
        # If so, load it and merge CLI overrides instead of creating brand new config
        has_autodetected_config = dut_config and dut_config.exists()

        if has_autodetected_config:
            # CLI mode with auto-detected config: Load config and apply CLI overrides
            try:
                # Load the auto-detected DUT config
                # Use quiet_mode=True to suppress errors if the file is empty (we'll fall back to CLI-only mode)
                loaded_dut_configs = load_dut_config(dut_config, quiet_mode=True)

                if loaded_dut_configs:
                    # Take the first DUT from the config file
                    base_dut_dict = loaded_dut_configs[0].model_dump()

                    # Apply baseboard from tool_config.yaml if DUT config doesn't have one
                    # This ensures tool_config.yaml baseboard is used as a fallback before CLI override
                    if not base_dut_dict.get("baseboard") and tool_config_baseboard:
                        base_dut_dict["baseboard"] = tool_config_baseboard
                        sanitized_console.print_info(
                            f"Using baseboard '{tool_config_baseboard}' from tool_config.yaml (DUT config has no baseboard)"
                        )

                    # Apply CLI overrides (only override if CLI value was explicitly provided)
                    cli_overrides = {}

                    # Baseboard override from CLI (highest priority)
                    if baseboard:
                        cli_overrides["baseboard"] = baseboard

                    # Local configuration
                    if local:
                        cli_overrides["local"] = local
                    if non_interactive:
                        cli_overrides["non_interactive"] = non_interactive

                    # BMC Configuration overrides
                    if bmc_ip:
                        cli_overrides["bmc_ip"] = bmc_ip
                    if bmc_user:
                        cli_overrides["bmc_user"] = bmc_user
                    if bmc_pass:
                        cli_overrides["bmc_pass"] = bmc_pass
                    if bmc_ssh_user:
                        cli_overrides["bmc_ssh_user"] = bmc_ssh_user
                    if bmc_ssh_pass:
                        cli_overrides["bmc_ssh_pass"] = bmc_ssh_pass
                    if bmc_ssh_port:
                        cli_overrides["bmc_ssh_port"] = bmc_ssh_port
                    if bmc_ssh_key_path:
                        cli_overrides["bmc_ssh_key_path"] = bmc_ssh_key_path
                    if bmc_ssh_passwordless:
                        cli_overrides["bmc_ssh_passwordless"] = bmc_ssh_passwordless
                    if bmc_ssh_max_retries:
                        cli_overrides["bmc_ssh_max_retries"] = bmc_ssh_max_retries
                    if bmc_rf_user:
                        cli_overrides["bmc_rf_user"] = bmc_rf_user
                    if bmc_rf_pass:
                        cli_overrides["bmc_rf_pass"] = bmc_rf_pass
                    if bmc_rf_port:
                        cli_overrides["bmc_rf_port"] = bmc_rf_port

                    # Host Configuration overrides
                    if host_ip:
                        cli_overrides["host_ip"] = host_ip
                    if host_user:
                        cli_overrides["host_user"] = host_user
                    if host_pass:
                        cli_overrides["host_pass"] = host_pass
                    if host_ssh_port:
                        cli_overrides["host_ssh_port"] = host_ssh_port
                    if host_ssh_key_path:
                        cli_overrides["host_ssh_key_path"] = host_ssh_key_path
                    if host_ssh_passwordless:
                        cli_overrides["host_ssh_passwordless"] = host_ssh_passwordless
                    if host_ssh_max_retries:
                        cli_overrides["host_ssh_max_retries"] = host_ssh_max_retries

                    # HMC Configuration overrides
                    if hmc_ip:
                        cli_overrides["hmc_ip"] = hmc_ip
                        # Also set legacy/uppercase key to ensure downstream consumers pick it up
                        cli_overrides["HMC_IP"] = hmc_ip
                    if hmc_user:
                        cli_overrides["hmc_user"] = hmc_user
                    if hmc_pass:
                        cli_overrides["hmc_pass"] = hmc_pass
                    if hmc_ssh_user:
                        cli_overrides["hmc_ssh_user"] = hmc_ssh_user
                    if hmc_ssh_pass:
                        cli_overrides["hmc_ssh_pass"] = hmc_ssh_pass
                    if hmc_ssh_port:
                        cli_overrides["hmc_ssh_port"] = hmc_ssh_port
                    if hmc_ssh_key_path:
                        cli_overrides["hmc_ssh_key_path"] = hmc_ssh_key_path
                    if hmc_ssh_passwordless:
                        cli_overrides["hmc_ssh_passwordless"] = hmc_ssh_passwordless
                    if hmc_ssh_max_retries:
                        cli_overrides["hmc_ssh_max_retries"] = hmc_ssh_max_retries
                    if hmc_http_port:
                        cli_overrides["hmc_http_port"] = hmc_http_port
                    if hmc_https_port:
                        cli_overrides["hmc_https_port"] = hmc_https_port
                    if hmc_use_https:
                        cli_overrides["hmc_use_https"] = hmc_use_https
                    if hmc_use_port_forwarding:
                        cli_overrides["hmc_use_port_forwarding"] = (
                            hmc_use_port_forwarding
                        )
                    if use_port_forwarding:
                        cli_overrides["use_port_forwarding"] = use_port_forwarding
                    if tunnel_tcp_port:
                        cli_overrides["tunnel_tcp_port"] = tunnel_tcp_port
                    if setup_port_forwarding is not None:
                        cli_overrides["setup_port_forwarding"] = setup_port_forwarding
                    if force_port_fw is not None:
                        cli_overrides["force_port_fw"] = force_port_fw
                    if hmc_access_method:
                        cli_overrides["hmc_access_method"] = hmc_access_method

                    # SSH Proxy Configuration overrides
                    if ssh_proxy_host:
                        cli_overrides["ssh_proxy_host"] = ssh_proxy_host
                    if (
                        ssh_proxy_port and ssh_proxy_port != 22
                    ):  # Don't override default
                        cli_overrides["ssh_proxy_port"] = ssh_proxy_port
                    if ssh_proxy_user:
                        cli_overrides["ssh_proxy_user"] = ssh_proxy_user
                    if ssh_proxy_pass:
                        cli_overrides["ssh_proxy_pass"] = ssh_proxy_pass
                    if ssh_proxy_key_path:
                        cli_overrides["ssh_proxy_key_path"] = ssh_proxy_key_path
                    if ssh_proxy_passwordless:
                        cli_overrides["ssh_proxy_passwordless"] = ssh_proxy_passwordless
                    if (
                        ssh_proxy_max_retries and ssh_proxy_max_retries != 3
                    ):  # Don't override default
                        cli_overrides["ssh_proxy_max_retries"] = ssh_proxy_max_retries

                    # Merge: base config + CLI overrides
                    merged_dict = {**base_dut_dict, **cli_overrides}
                    dut_config_obj = DUTConfig(**merged_dict)
                    dut_configs = [dut_config_obj]

                    sanitized_console.print_info(
                        f"Loaded DUT config from: {dut_config}"
                    )
                    sanitized_console.print_info(
                        f"Applied CLI credential overrides (baseboard, credentials, etc.)"
                    )
                else:
                    # Fallback: Create new config if loading failed
                    has_autodetected_config = False
            except Exception as e:
                sanitized_console.print_warning(
                    f"Could not load auto-detected config file: {e}. Creating new config from CLI args."
                )
                has_autodetected_config = False

        if not has_autodetected_config:
            # Pure CLI mode - create DUT config from ONLY CLI arguments
            # Validate CLI mode requirements
            # Use baseboard from CLI, or fall back to tool_config, or allow auto-detection
            effective_baseboard = baseboard or tool_config_baseboard

            if not local and not effective_baseboard:
                sanitized_console.print_info(
                    "No baseboard specified - auto-detection will be used to determine baseboard"
                )
            elif not baseboard and tool_config_baseboard:
                sanitized_console.print_info(
                    f"Using baseboard '{tool_config_baseboard}' from tool_config.yaml"
                )

            dut_config = DUTConfig(
                name="dut-1",
                baseboard=effective_baseboard,  # Use CLI or tool_config baseboard, or None for auto-detection
                # Local Configuration
                local=local,
                non_interactive=non_interactive,
                # BMC Configuration
                bmc_ip=bmc_ip,
                bmc_user=bmc_user,
                bmc_pass=bmc_pass,
                bmc_ssh_user=bmc_ssh_user,
                bmc_ssh_pass=bmc_ssh_pass,
                bmc_ssh_port=bmc_ssh_port,
                bmc_ssh_key_path=bmc_ssh_key_path,
                bmc_ssh_passwordless=bmc_ssh_passwordless,
                bmc_ssh_max_retries=bmc_ssh_max_retries,
                bmc_rf_user=bmc_rf_user,
                bmc_rf_pass=bmc_rf_pass,
                bmc_rf_port=bmc_rf_port,
                # Host Configuration
                host_ip=host_ip,
                host_user=host_user,
                host_pass=host_pass,
                host_ssh_port=host_ssh_port,
                host_ssh_key_path=host_ssh_key_path,
                host_ssh_passwordless=host_ssh_passwordless,
                host_ssh_max_retries=host_ssh_max_retries,
                # HMC Configuration
                hmc_ip=hmc_ip,
                hmc_user=hmc_user,
                hmc_pass=hmc_pass,
                hmc_ssh_user=bmc_ssh_user,
                hmc_ssh_pass=bmc_ssh_pass,
                hmc_ssh_port=hmc_ssh_port,
                hmc_ssh_key_path=hmc_ssh_key_path,
                hmc_ssh_passwordless=hmc_ssh_passwordless,
                hmc_ssh_max_retries=hmc_ssh_max_retries,
                hmc_http_port=hmc_http_port,
                hmc_https_port=hmc_https_port,
                hmc_use_https=hmc_use_https,
                hmc_use_port_forwarding=hmc_use_port_forwarding,
                use_port_forwarding=use_port_forwarding,
                tunnel_tcp_port=tunnel_tcp_port,
                setup_port_forwarding=setup_port_forwarding,
                force_port_fw=force_port_fw,
                hmc_access_method=hmc_access_method,
                # SSH Proxy Configuration
                ssh_proxy_host=ssh_proxy_host,
                ssh_proxy_port=ssh_proxy_port,
                ssh_proxy_user=ssh_proxy_user,
                ssh_proxy_pass=ssh_proxy_pass,
                ssh_proxy_key_path=ssh_proxy_key_path,
                ssh_proxy_passwordless=ssh_proxy_passwordless,
                ssh_proxy_max_retries=ssh_proxy_max_retries,
            )
            dut_configs = [dut_config]
            sanitized_console.print_warning(
                "Created temporary tool config from CLI arguments"
            )
    else:
        # Multi-DUT config mode - require DUT config file
        if not dut_config:
            # Auto-detect configuration files in the same directory as the executable
            # Auto-detect configuration files
            auto_dut_config, auto_config, auto_tool_config = find_all_config_files()

            if auto_dut_config:
                dut_config = auto_dut_config
                sanitized_console.print_info(
                    f"Auto-detected DUT config file: {dut_config}"
                )
            else:
                sanitized_console.print_error(
                    "Error: --dut-config is required when not using CLI arguments and no dut_config.yaml found in executable directory"
                )
                sys.exit(1)

            # Auto-detect config.yaml or tool_config.yaml if not provided
            if not config_file:
                if auto_config:
                    config_file = auto_config
                    sanitized_console.print_info(
                        f"Auto-detected config file: {config_file}"
                    )
                elif auto_tool_config:
                    config_file = auto_tool_config
                    sanitized_console.print_info(
                        f"Auto-detected tool config file: {config_file}"
                    )

            # Now load the config file if one was detected or provided
            if config_file and config_file.exists():
                try:
                    config_file_data = load_config(config_file)
                    sanitized_console.print_info(
                        f"Loaded tool configuration from: {config_file}"
                    )

                    # Update config values after config file is loaded
                    if hasattr(config_file_data, "output") and hasattr(
                        config_file_data.output, "generate_html"
                    ):
                        config_generate_html_reports = (
                            config_file_data.output.generate_html
                        )
                    else:
                        config_generate_html_reports = getattr(
                            config_file_data, "GENERATE_HTML_REPORTS", True
                        )
                    config_auto_parse = getattr(config_file_data, "AUTO_PARSE", True)
                    # Check for new sanitization format first, then fall back to legacy
                    if (
                        hasattr(config_file_data, "sanitization")
                        and config_file_data.sanitization
                    ):
                        config_log_sanitization = config_file_data.sanitization.get(
                            "enabled", True
                        )
                    else:
                        config_log_sanitization = getattr(
                            config_file_data, "LogSanitization", True
                        )
                except Exception as e:
                    # Provide more specific error messages based on the exception type
                    # Track error to prevent duplicates
                    error_key = f"tool_config_{str(e)}"
                    if error_key not in _reported_config_errors:
                        _reported_config_errors.add(error_key)
                        if "Invalid YAML" in str(e):
                            sanitized_console.print_warning(
                                f"Warning: Tool config file has YAML syntax errors: {e}"
                            )
                        elif "not found" in str(e).lower():
                            sanitized_console.print_warning(
                                f"Warning: Tool config file not found or inaccessible: {e}"
                            )
                        elif "Permission denied" in str(e):
                            sanitized_console.print_warning(
                                f"Warning: Permission denied reading tool config file: {e}"
                            )
                        else:
                            sanitized_console.print_warning(
                                f"Warning: Could not load config file due to validation errors: {e}"
                            )
                        sanitized_console.print_warning(
                            "Continuing with default configuration values"
                        )
                    config_file_data = {}

            # Handle output directory logic after config is loaded
            final_output_dir = str(output_dir)  # Start with CLI value
            if (
                hasattr(config_file_data, "output")
                and hasattr(config_file_data.output, "directory")
                and config_file_data.output.directory
                and str(output_dir)
                == "/tmp"  # Only use config file when CLI uses default
            ):
                # Use config file value if CLI didn't override it
                final_output_dir = str(config_file_data.output.directory)
                # Expand ~ to home directory if present
                if final_output_dir.startswith("~"):
                    final_output_dir = os.path.expanduser(final_output_dir)
                sanitized_console.print_info(
                    f"Using output directory from tool config: {final_output_dir}"
                )
            elif (
                hasattr(config_file_data, "output")
                and hasattr(config_file_data.output, "directory")
                and config_file_data.output.directory
                and not output_dir.is_absolute()  # Also use config file for relative paths
            ):
                # Use config file value for relative paths when available
                final_output_dir = str(config_file_data.output.directory)
                # Expand ~ to home directory if present
                if final_output_dir.startswith("~"):
                    final_output_dir = os.path.expanduser(final_output_dir)
                sanitized_console.print_info(
                    f"Using output directory from tool config for relative path: {final_output_dir}"
                )
        else:
            # DUT config provided via command line - auto-detect config files for auto-assignment
            auto_dut_config, auto_config, auto_tool_config = find_all_config_files()

            # Store original DUT config path for cleanup
            original_dut_config = dut_config

            # Auto-assign ConfigFileToUse if needed (before loading DUT configs)
            # Only use auto-detected config files if user hasn't explicitly specified -c/--config
            config_files_for_auto_assignment = [
                auto_config
            ]  # Always include config.yaml for baseboard detection
            if (
                config_file
            ):  # Only include tool_config.yaml if user explicitly specified -c
                config_files_for_auto_assignment.append(auto_tool_config)

            dut_config = auto_assign_config_file_to_use(
                dut_config, config_files_for_auto_assignment
            )

            # Load tool config file if one was provided or auto-detected
            if config_file and config_file.exists():
                try:
                    config_file_data = load_config(config_file)
                    sanitized_console.print_info(
                        f"Loaded tool configuration from: {config_file}"
                    )

                    # Update config values after config file is loaded
                    if hasattr(config_file_data, "output") and hasattr(
                        config_file_data.output, "generate_html"
                    ):
                        config_generate_html_reports = (
                            config_file_data.output.generate_html
                        )
                    else:
                        config_generate_html_reports = getattr(
                            config_file_data, "GENERATE_HTML_REPORTS", True
                        )
                    config_auto_parse = getattr(config_file_data, "AUTO_PARSE", True)
                    # Check for new sanitization format first, then fall back to legacy
                    if (
                        hasattr(config_file_data, "sanitization")
                        and config_file_data.sanitization
                    ):
                        config_log_sanitization = config_file_data.sanitization.get(
                            "enabled", True
                        )
                    else:
                        config_log_sanitization = getattr(
                            config_file_data, "LogSanitization", True
                        )
                except Exception as e:
                    # Provide more specific error messages based on the exception type
                    # Track error to prevent duplicates
                    error_key = f"tool_config_{str(e)}"
                    if error_key not in _reported_config_errors:
                        _reported_config_errors.add(error_key)
                        if "Invalid YAML" in str(e):
                            sanitized_console.print_warning(
                                f"Warning: Tool config file has YAML syntax errors: {e}"
                            )
                        elif "not found" in str(e).lower():
                            sanitized_console.print_warning(
                                f"Warning: Tool config file not found or inaccessible: {e}"
                            )
                        elif "Permission denied" in str(e):
                            sanitized_console.print_warning(
                                f"Warning: Permission denied reading tool config file: {e}"
                            )
                        else:
                            sanitized_console.print_warning(
                                f"Warning: Could not load config file due to validation errors: {e}"
                            )
                        sanitized_console.print_warning(
                            "Continuing with default configuration values"
                        )
                    config_file_data = {}
            elif auto_tool_config and not config_file:
                # Auto-load tool_config.yaml for tool-level defaults when no -c is specified
                try:
                    config_file_data = load_config(auto_tool_config)
                    sanitized_console.print_info(
                        f"Auto-loaded tool configuration from: {auto_tool_config}"
                    )

                    # Update config values after config file is loaded
                    if hasattr(config_file_data, "output") and hasattr(
                        config_file_data.output, "generate_html"
                    ):
                        config_generate_html_reports = (
                            config_file_data.output.generate_html
                        )
                    else:
                        config_generate_html_reports = getattr(
                            config_file_data, "GENERATE_HTML_REPORTS", True
                        )
                    config_auto_parse = getattr(config_file_data, "AUTO_PARSE", True)
                    # Check for new sanitization format first, then fall back to legacy
                    if (
                        hasattr(config_file_data, "sanitization")
                        and config_file_data.sanitization
                    ):
                        config_log_sanitization = config_file_data.sanitization.get(
                            "enabled", True
                        )
                    else:
                        config_log_sanitization = getattr(
                            config_file_data, "LogSanitization", True
                        )
                except Exception as e:
                    # Provide more specific error messages based on the exception type
                    # Track error to prevent duplicates
                    error_key = f"auto_tool_config_{str(e)}"
                    if error_key not in _reported_config_errors:
                        _reported_config_errors.add(error_key)
                        if "Invalid YAML" in str(e):
                            sanitized_console.print_warning(
                                f"Warning: Auto-detected tool config file has YAML syntax errors: {e}"
                            )
                        elif "not found" in str(e).lower():
                            sanitized_console.print_warning(
                                f"Warning: Auto-detected tool config file not found or inaccessible: {e}"
                            )
                        elif "Permission denied" in str(e):
                            sanitized_console.print_warning(
                                f"Warning: Permission denied reading auto-detected tool config file: {e}"
                            )
                        else:
                            sanitized_console.print_warning(
                                f"Warning: Could not auto-load tool config file due to validation errors: {e}"
                            )
                        sanitized_console.print_warning(
                            "Continuing with default configuration values"
                        )
                    config_file_data = {}

            # Handle output directory logic after config is loaded
            final_output_dir = str(output_dir)  # Start with CLI value
            if (
                hasattr(config_file_data, "output")
                and hasattr(config_file_data.output, "directory")
                and config_file_data.output.directory
                and (
                    str(output_dir) == "/tmp" or output_dir == Path("/tmp")
                )  # Only use config file when CLI uses default
            ):
                # Use config file value if CLI didn't override it
                final_output_dir = str(config_file_data.output.directory)
                # Expand ~ to home directory if present
                if final_output_dir.startswith("~"):
                    import os

                    final_output_dir = os.path.expanduser(final_output_dir)
                sanitized_console.print_info(
                    f"Using output directory from tool config: {final_output_dir}"
                )
            # Note: We don't use config file for relative paths - CLI relative paths should be honored

        if not dut_config.exists():
            sanitized_console.print_error(
                f"Error: DUT config file '{dut_config}' does not exist"
            )
            sys.exit(1)

        # Load DUT configs from file
        try:
            dut_configs = load_dut_config(dut_config)
            sanitized_console.print_success(f"Loaded DUT config from: {dut_config}")

            # Apply CLI argument overrides to loaded DUT configs
            # This allows CLI arguments to override values in the DUT config file

            # Global overrides (apply to all DUTs) - typically infrastructure settings
            global_overrides = {}
            if ssh_proxy_host:
                global_overrides["ssh_proxy_host"] = ssh_proxy_host
            if ssh_proxy_port:
                global_overrides["ssh_proxy_port"] = ssh_proxy_port
            if ssh_proxy_user:
                global_overrides["ssh_proxy_user"] = ssh_proxy_user
            if ssh_proxy_pass:
                global_overrides["ssh_proxy_pass"] = ssh_proxy_pass
            if ssh_proxy_key_path:
                global_overrides["ssh_proxy_key_path"] = ssh_proxy_key_path
            if ssh_proxy_passwordless:
                global_overrides["ssh_proxy_passwordless"] = ssh_proxy_passwordless
            if ssh_proxy_max_retries:
                global_overrides["ssh_proxy_max_retries"] = ssh_proxy_max_retries

            # Per-DUT overrides (apply only to single DUT if only one DUT exists)
            per_dut_overrides = {}
            if bmc_ip:
                per_dut_overrides["bmc_ip"] = bmc_ip
            if bmc_user:
                per_dut_overrides["bmc_user"] = bmc_user
            if bmc_pass:
                per_dut_overrides["bmc_pass"] = bmc_pass
            if bmc_ssh_user:
                per_dut_overrides["bmc_ssh_user"] = bmc_ssh_user
            if bmc_ssh_pass:
                per_dut_overrides["bmc_ssh_pass"] = bmc_ssh_pass
            if bmc_ssh_port:
                per_dut_overrides["bmc_ssh_port"] = bmc_ssh_port
            if bmc_ssh_key_path:
                per_dut_overrides["bmc_ssh_key_path"] = bmc_ssh_key_path
            if bmc_ssh_max_retries:
                per_dut_overrides["bmc_ssh_max_retries"] = bmc_ssh_max_retries
            if bmc_rf_user:
                per_dut_overrides["bmc_rf_user"] = bmc_rf_user
            if bmc_rf_pass:
                per_dut_overrides["bmc_rf_pass"] = bmc_rf_pass
            if bmc_rf_port:
                per_dut_overrides["bmc_rf_port"] = bmc_rf_port

            if host_ip:
                per_dut_overrides["host_ip"] = host_ip
            if host_user:
                per_dut_overrides["host_user"] = host_user
            if host_pass:
                per_dut_overrides["host_pass"] = host_pass
            if host_ssh_port:
                per_dut_overrides["host_ssh_port"] = host_ssh_port
            if host_ssh_key_path:
                per_dut_overrides["host_ssh_key_path"] = host_ssh_key_path
            if host_ssh_max_retries:
                per_dut_overrides["host_ssh_max_retries"] = host_ssh_max_retries

            if hmc_ip:
                per_dut_overrides["hmc_ip"] = hmc_ip
                # Also set legacy/uppercase key so DUTManager consumes it
                per_dut_overrides["HMC_IP"] = hmc_ip
            if hmc_user:
                per_dut_overrides["hmc_user"] = hmc_user
            if hmc_pass:
                per_dut_overrides["hmc_pass"] = hmc_pass
            if hmc_ssh_user:
                per_dut_overrides["hmc_ssh_user"] = hmc_ssh_user
            if hmc_ssh_pass:
                per_dut_overrides["hmc_ssh_pass"] = hmc_ssh_pass
            if hmc_ssh_port:
                per_dut_overrides["hmc_ssh_port"] = hmc_ssh_port
            if hmc_ssh_key_path:
                per_dut_overrides["hmc_ssh_key_path"] = hmc_ssh_key_path
            if hmc_ssh_max_retries:
                per_dut_overrides["hmc_ssh_max_retries"] = hmc_ssh_max_retries
            if hmc_http_port:
                per_dut_overrides["hmc_http_port"] = hmc_http_port
            if hmc_https_port:
                per_dut_overrides["hmc_https_port"] = hmc_https_port
            if hmc_access_method:
                per_dut_overrides["hmc_access_method"] = hmc_access_method

            # Apply global overrides to all DUT configs
            if global_overrides:
                # sanitized_console.print_info(
                #     f"Applying global CLI overrides: {list(global_overrides.keys())}"
                # )
                for dut_config_obj in dut_configs:
                    for key, value in global_overrides.items():
                        setattr(dut_config_obj, key, value)

            # Apply per-DUT overrides only if single DUT (to avoid confusion in multi-DUT scenarios)
            if per_dut_overrides:
                if len(dut_configs) == 1:
                    # sanitized_console.print_info(
                    #     f"Applying per-DUT CLI overrides: {list(per_dut_overrides.keys())}"
                    # )
                    for key, value in per_dut_overrides.items():
                        setattr(dut_configs[0], key, value)
                else:
                    sanitized_console.print_warning(
                        f"Per-DUT CLI overrides provided ({list(per_dut_overrides.keys())}) but multiple DUTs detected. "
                        f"These overrides will be ignored to avoid applying the same values to all DUTs. "
                        f"Use DUT config file for per-DUT specific settings."
                    )

            # Clean up temporary file if it was created by auto-assignment
            if "temp_" in str(dut_config) and dut_config != original_dut_config:
                try:
                    dut_config.unlink()
                    sanitized_console.print_info("Cleaned up temporary DUT config file")
                except Exception as e:
                    sanitized_console.print_warning(
                        f"Could not clean up temporary file: {e}"
                    )

        except Exception as e:
            # Use pretty formatted error display for better user experience
            display_dut_config_error(str(e))
            sys.exit(1)

        # If CLI baseboard parameter is provided, override the baseboard in DUT configs
        if baseboard:
            if len(dut_configs) == 1:
                # Single DUT - allow CLI baseboard override
                sanitized_console.print_info(
                    f"\n\nCLI baseboard parameter '-b {baseboard}' provided - overriding baseboard in DUT config file"
                )
                for dut_config_obj in dut_configs:
                    dut_config_obj.baseboard = baseboard
                    sanitized_console.print_success(
                        f"Set baseboard '{baseboard}' for DUT '{dut_config_obj.name}' (overriding config file)"
                    )
            else:
                # Multi-DUT - CLI baseboard parameter cannot be used
                sanitized_console.print_warning(
                    f"\n\nCLI baseboard parameter '-b {baseboard}' provided but ignored for multi-DUT configuration"
                )
                sanitized_console.print_warning(
                    f"\nMulti-DUT operations require baseboards to be configured in the DUT config file for each DUT"
                )
                sanitized_console.print_warning(
                    f"\nPlease ensure all {len(dut_configs)} DUTs have baseboards configured in: {dut_config}"
                )
                # Don't override the baseboard - let the config file values stand

        # Set non_interactive flag on all DUT configs
        for dut_config in dut_configs:
            dut_config.non_interactive = non_interactive

    # Determine final collection level (config file default, CLI override)
    config_collection_level = getattr(config_file_data, "collection_level", "L1")
    # Use CLI level if it was determined earlier, otherwise use config file
    if final_collection_level is None:
        final_collection_level = config_collection_level

    # Convert enum to string if needed
    if hasattr(final_collection_level, "value"):
        final_collection_level = final_collection_level.value

    # Now create the ToolConfig after all config file loading and output directory logic
    tool_config = ToolConfig(
        # Execution Configuration
        max_concurrent_duts=max_concurrent_duts,
        max_concurrent_collectors_per_dut=max_concurrent_collectors_per_dut,
        timeout=timeout,
        retry_count=retry_count,
        # Output Configuration
        output_directory=final_output_dir,
        skip_zip=(
            skip_zip
            if should_use_cli_value(skip_zip, config_skip_zip, False)
            else config_skip_zip
        ),
        skip_zip_split=(
            skip_zip_split
            if should_use_cli_value(skip_zip_split, config_skip_zip_split, False)
            else config_skip_zip_split
        ),
        zip_split_threshold=(
            zip_split_threshold
            if should_use_cli_value(
                zip_split_threshold, config_zip_split_threshold, 200.0
            )
            else config_zip_split_threshold
        ),
        # Logging Configuration
        log_level=config_log_level,
        log_format=config_log_format,
        debug=debug,
        verbose=verbose,
        # Collection Configuration
        collection_level=final_collection_level,
        dry_run=dry_run,
        # Preflight and Sanitization
        skip_preflight=skip_preflight,
        skip_sanitization=(
            skip_sanitization
            if should_use_cli_value(
                skip_sanitization, not config_log_sanitization, False
            )
            else not config_log_sanitization
        ),
        skip_html_reports=(
            skip_html_reports
            if should_use_cli_value(
                skip_html_reports, not config_generate_html_reports, False
            )
            else not config_generate_html_reports
        ),
        # Collector Configuration
        collector_id=collector_id,
        collector_group=collector_group,
        # Collector Skip Configuration
        skip_collectors=skip_collectors.split(",") if skip_collectors else [],
        include_collectors=include_collectors.split(",") if include_collectors else [],
        # Configuration files
        spreadsheet=str(spreadsheet) if spreadsheet else None,
        # Parallelization Configuration
        parallel_dut_sequential_collectors=parallel_dut_sequential_collectors,
        service_grouped_sequential_collectors=service_grouped_sequential_collectors,
        # Skip Flags from config file
        SKIP_PORT_FW=getattr(config_file_data, "SKIP_PORT_FW", False),
        SKIP_BMC_SSH_LOGS=getattr(config_file_data, "SKIP_BMC_SSH_LOGS", True),
        SKIP_HOST_LOGS=getattr(config_file_data, "SKIP_HOST_LOGS", False),
        SKIP_IPMI_LOGS=getattr(config_file_data, "SKIP_IPMI_LOGS", False),
        SKIP_REDFISH_OOB_LOGS=getattr(config_file_data, "SKIP_REDFISH_OOB_LOGS", False),
        COLLECTOR_TO_SKIP=getattr(config_file_data, "COLLECTOR_TO_SKIP", None),
        SYSTEM_ID_TO_SKIP=getattr(config_file_data, "SYSTEM_ID_TO_SKIP", None),
        CHASSIS_ID_TO_SKIP=getattr(config_file_data, "CHASSIS_ID_TO_SKIP", None),
        MANAGER_ID_TO_SKIP=getattr(config_file_data, "MANAGER_ID_TO_SKIP", None),
        EXPAND_QUERY_CHASSIS_LEVEL=getattr(
            config_file_data, "EXPAND_QUERY_CHASSIS_LEVEL", 1
        ),
        EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL=getattr(
            config_file_data, "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL", 1
        ),
        EXPAND_QUERY_MANAGER_LEVEL=getattr(
            config_file_data, "EXPAND_QUERY_MANAGER_LEVEL", 1
        ),
        EXPAND_QUERY_SYSTEM_LEVEL=getattr(
            config_file_data, "EXPAND_QUERY_SYSTEM_LEVEL", 1
        ),
        NVOS_TECH_DUMP_TIMEOUT=getattr(
            config_file_data, "NVOS_TECH_DUMP_TIMEOUT", None
        ),
        REDFISH_DUMP_TIMEOUT=getattr(config_file_data, "REDFISH_DUMP_TIMEOUT", None),
        REDFISH_DEVICE_DUMP_SLEEP_DURATION=getattr(
            config_file_data, "REDFISH_DEVICE_DUMP_SLEEP_DURATION", 60
        ),
        BMC_TEMP_DIR=getattr(config_file_data, "BMC_TEMP_DIR", "/tmp"),
        FW_INVENTORY_TABLE_PROPERTIES=getattr(
            config_file_data, "FW_INVENTORY_TABLE_PROPERTIES", []
        ),
        ADDITIONAL_OOB_URI_COLLECTION=getattr(
            config_file_data, "ADDITIONAL_OOB_URI_COLLECTION", []
        ),
        NVLINK_OOB_URI=getattr(config_file_data, "NVLINK_OOB_URI", []),
        CUSTOM_DUMP_SERVICES=getattr(config_file_data, "CUSTOM_DUMP_SERVICES", []),
        POST_CODES_URI=getattr(config_file_data, "POST_CODES_URI", []),
        task_id_prefix=getattr(config_file_data, "TASK_ID_PREFIX", ""),
        tool_temp_dir=getattr(config_file_data, "TOOL_TEMP_DIR", "/tmp"),
        # Global feature flags / passthroughs (read from tool config if present)
        EXTRA_LOG_COLLECTION=getattr(config_file_data, "EXTRA_LOG_COLLECTION", None),
    )

    # Now create the CLICollector with the updated tool config
    cli_collector = CLICollector(
        tool_config,
        dut_configs,
        enable_status_tracking=enable_status_tracking,
        disable_live_display=disable_live_display,
        skip_validation=skip_validation,
    )

    # Run comprehensive validation after CLI collector creation (we now have access to loaded DUT configs)
    if not skip_validation:
        # Validate credentials and configuration for both CLI mode and DUT config mode
        # Pass the loaded DUT configs for validation so it can see the actual connection details
        is_valid, validation_errors = run_comprehensive_validation(
            dut_config=dut_configs,  # Pass the loaded DUT configs, not the file path
            local=local,
            cli_credentials=cli_credentials,
            collector_ids=collector_id,
            collector_groups=collector_group,
            collection_level=final_collection_level,
            output_dir=output_dir,
            config_manager=None,  # Will be validated later when config manager is available
            ansible_inventory=ansible_inventory,
        )

        if not is_valid:
            display_validation_errors(validation_errors)
            sys.exit(1)

    # Run collector-specific validation after CLI collector is created
    # This validates collector IDs, groups, and collection levels against the actual configuration
    if (
        collector_id
        or collector_group
        or include_collectors
        or skip_collectors
        or final_collection_level != "L1"
    ) and not skip_validation:
        # Fast validation without creating full DUT objects
        try:
            # Use the existing sanitized console for the progress bar
            progress_console = sanitized_console.console

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=progress_console,
                transient=False,
            ) as progress:
                validation_task = progress.add_task(
                    "Running fast collector validation...", total=None
                )

                # Fast validation: just load the config manager without creating DUTs
                progress.update(
                    validation_task,
                    description="Loading collector definitions...",
                )

                # Create a minimal config manager for validation
                from src.tool.core.config_manager import ConfigurationManager
                from src.tool.utils.yaml_manager import YAMLManager

                # Load tool config
                tool_config_data = (
                    YAMLManager.load_yaml(config_file, "Tool configuration")
                    if config_file
                    else {}
                )

                # Create config manager with minimal initialization
                config_manager = ConfigurationManager.from_objects(
                    tool_config=tool_config,
                    dut_configs=dut_configs,
                    sanitized_console=sanitized_console,
                    quiet_mode=True,  # Skip DUT creation
                )

                # Initialize only the config manager (skip DUT creation)
                # Run in a new event loop for async operations
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(config_manager.initialize_minimal())
                finally:
                    loop.close()

                progress.update(
                    validation_task, description="Validating collector IDs..."
                )

                # Validate collector IDs
                validation_errors = []
                is_valid, errors = validate_collector_ids(collector_id, config_manager)
                validation_errors.extend(errors)

                # Validate include_collectors
                if include_collectors:
                    is_valid, errors = validate_collector_ids(
                        include_collectors, config_manager
                    )
                    validation_errors.extend(errors)

                # Validate skip_collectors
                if skip_collectors:
                    is_valid, errors = validate_collector_ids(
                        skip_collectors, config_manager
                    )
                    validation_errors.extend(errors)

                # Validate collector groups
                is_valid, errors = validate_collector_groups(
                    collector_group, config_manager
                )
                validation_errors.extend(errors)

                # Validate collection level
                is_valid, errors = validate_collection_level(final_collection_level)
                validation_errors.extend(errors)

                is_valid = len(validation_errors) == 0

                if not is_valid:
                    display_validation_errors(validation_errors)
                    sys.exit(1)

                progress.update(
                    validation_task,
                    description="Validation complete",
                    completed=True,
                )

        except Exception as e:
            # If we can't validate collectors, continue without collector validation
            # Track error to prevent duplicates
            error_key = f"collector_validation_{str(e)}"
            if error_key not in _reported_config_errors:
                _reported_config_errors.add(error_key)
                sanitized_console.print_warning(
                    f"Warning: Could not validate collector IDs/groups: {e}. "
                    "Continuing with basic validation only."
                )

    # Validate baseboard against spreadsheet
    if baseboard is not None:
        if not spreadsheet:
            sanitized_console.print_error(
                "[red]Error:[/red] Baseboard validation requires a spreadsheet. "
                "Please provide a spreadsheet using [cyan]--spreadsheet[/cyan] argument."
            )
            sys.exit(1)

        if not validate_baseboard(baseboard, spreadsheet):
            try:
                available = get_available_baseboards(spreadsheet)
                sanitized_console.print_error(
                    f"[red]Invalid baseboard '{baseboard}'[/red]"
                )
                sanitized_console.print_info(
                    f"Available baseboards: {', '.join(available)}"
                )
            except Exception as e:
                sanitized_console.print_error(
                    f"[red]Error validating baseboard: {e}[/red]"
                )
            sys.exit(1)

    # Run collection using CLI handler
    try:
        asyncio.run(cli_collector.run_collection())
    except KeyboardInterrupt:
        sanitized_console.print_warning("\nCollection interrupted by user")
        # Clean up SSH proxy tunnels before exiting
        try:
            if hasattr(cli_collector, "dut_manager") and cli_collector.dut_manager:
                cli_collector.dut_manager.cleanup_all_ssh_proxy_tunnels_sync()
                # sanitized_console.print_info("Cleaned up SSH proxy tunnels")
        except Exception as cleanup_e:
            sanitized_console.print_warning(
                f"Warning: Could not clean up SSH proxy tunnels: {cleanup_e}"
            )
        sys.exit(1)
    except Exception as e:
        sanitized_console.print_error(f"Collection failed: {e}")
        if debug:
            console.print_exception()
        # Clean up SSH proxy tunnels before exiting
        try:
            if hasattr(cli_collector, "dut_manager") and cli_collector.dut_manager:
                cli_collector.dut_manager.cleanup_all_ssh_proxy_tunnels_sync()
                # sanitized_console.print_info("Cleaned up SSH proxy tunnels")
        except Exception as cleanup_e:
            sanitized_console.print_warning(
                f"Warning: Could not clean up SSH proxy tunnels: {cleanup_e}"
            )
        sys.exit(1)
    finally:
        # Clean up SSH proxy tunnels
        try:
            if hasattr(cli_collector, "dut_manager") and cli_collector.dut_manager:
                cli_collector.dut_manager.cleanup_all_ssh_proxy_tunnels_sync()
                # sanitized_console.print_info("Cleaned up SSH proxy tunnels")
            elif (
                hasattr(cli_collector, "orchestrator")
                and hasattr(cli_collector.orchestrator, "dut_manager")
                and cli_collector.orchestrator.dut_manager
            ):
                cli_collector.orchestrator.dut_manager.cleanup_all_ssh_proxy_tunnels_sync()
                # sanitized_console.print_info("Cleaned up SSH proxy tunnels")
        except Exception as e:
            sanitized_console.print_warning(
                f"Warning: Could not clean up SSH proxy tunnels: {e}"
            )

        # Clean up temporary config files if they were generated from ansible inventory
        if temp_config_file and temp_dut_config_file:
            try:
                cleanup_temp_config_files(temp_config_file, temp_dut_config_file)
                sanitized_console.print_info(
                    "Cleaned up temporary config files generated from ansible inventory"
                )
            except Exception as e:
                sanitized_console.print_warning(
                    f"Warning: Could not clean up temporary config files: {e}"
                )


@app.command(
    help='Display the default log collectors for a baseboard.\n\nExamples:\n\n  nvdebug default-collectors --baseboard "GB200 NVL"'
)
def default_collectors(
    baseboard: Optional[str] = typer.Option(
        None, "--baseboard", "-b", help="Filter by baseboard"
    ),
    spreadsheet: Optional[Path] = typer.Option(
        None, "--spreadsheet", help="Collector spreadsheet path"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON to stdout"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output file path (for JSON or table format)",
    ),
) -> None:
    """
    Display the default log collectors for a baseboard.

    This command shows which collectors are configured as defaults for a specific
    baseboard platform, helping users understand what will be collected by default.

    Args:
        baseboard (Optional[str]): Filter by baseboard name.
        spreadsheet (Optional[Path]): Collector spreadsheet path.
        json_output (bool): Output results as JSON to stdout.
        output_file (Optional[str]): Output file path.

    Example:
        >>> nvdebug default-collectors --baseboard "GB200 NVL"
    """

    # Auto-detect spreadsheet if not provided
    spreadsheet = auto_detect_spreadsheet(spreadsheet, suppress_print=json_output)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet)

    cli_default = CLIDefaultCollectors()
    asyncio.run(cli_default.run(baseboard, spreadsheet, json_output, output_file))


@app.command(
    help="Run preflight checks only and display results in a table format.\n\nExamples:\n  nvdebug preflight --dut-config dut_config.yaml"
)
def preflight(
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file path (auto-detected if not provided)",
    ),
    dut_config: Optional[Path] = typer.Option(
        None,
        "--dut-config",
        "-d",
        help="DUT configuration file (optional if using CLI credentials)",
    ),
    spreadsheet: Optional[Path] = typer.Option(
        None, "--spreadsheet", help="Collector spreadsheet path"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON to stdout"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output file path (for JSON or table format)",
    ),
    # Local Configuration
    local: bool = typer.Option(False, "--local", help="Run in local mode"),
    # BMC Configuration
    bmc_ip: Optional[str] = typer.Option(None, "--bmc-ip", "-i", help="BMC IP address"),
    bmc_user: Optional[str] = typer.Option(
        None, "--bmc-user", "-u", help="BMC username"
    ),
    bmc_pass: Optional[str] = typer.Option(
        None, "--bmc-pass", "-p", help="BMC password"
    ),
    bmc_ssh_user: Optional[str] = typer.Option(
        None, "--bmc-ssh-user", "-r", help="BMC SSH username"
    ),
    bmc_ssh_pass: Optional[str] = typer.Option(
        None, "--bmc-ssh-pass", "-w", help="BMC SSH password"
    ),
    bmc_ssh_port: Optional[int] = typer.Option(
        None, "--bmc-ssh-port", help="BMC SSH port"
    ),
    bmc_ssh_key_path: Optional[str] = typer.Option(
        None, "--bmc-ssh-key-path", help="BMC SSH key path"
    ),
    bmc_ssh_passwordless: bool = typer.Option(
        False, "--bmc-ssh-passwordless", help="Use passwordless SSH for BMC"
    ),
    bmc_ssh_max_retries: Optional[int] = typer.Option(
        3, "--bmc-ssh-max-retries", help="BMC SSH max retry attempts"
    ),
    bmc_rf_user: Optional[str] = typer.Option(
        None, "--bmc-rf-user", "-R", help="Redfish username"
    ),
    bmc_rf_pass: Optional[str] = typer.Option(
        None, "--bmc-rf-pass", "-W", help="Redfish password"
    ),
    bmc_rf_port: Optional[int] = typer.Option(
        None, "--bmc-rf-port", help="Redfish port"
    ),
    # Host Configuration
    host_ip: Optional[str] = typer.Option(
        None, "--host-ip", "-I", help="Host IP address"
    ),
    host_user: Optional[str] = typer.Option(
        None, "--host-user", "-U", help="Host username"
    ),
    host_pass: Optional[str] = typer.Option(
        None, "--host-pass", "-H", help="Host password"
    ),
    host_ssh_port: Optional[str] = typer.Option(
        None, "--host-ssh-port", "-P", help="Tunnel TCP port"
    ),
    host_ssh_key_path: Optional[str] = typer.Option(
        None, "--host-ssh-key-path", help="Host SSH key path"
    ),
    host_ssh_passwordless: bool = typer.Option(
        False, "--host-ssh-passwordless", help="Use passwordless SSH for Host"
    ),
    host_ssh_max_retries: Optional[int] = typer.Option(
        3, "--host-ssh-max-retries", help="Host SSH max retry attempts"
    ),
) -> None:
    """
    Run preflight checks only and display results in a table format.

    This command performs connectivity and configuration checks without collecting
    any logs. Useful for validating DUT accessibility before running full collection.

    Args:
        dut_config (Optional[Path]): DUT configuration file.
        spreadsheet (Optional[Path]): Collector spreadsheet path.
        json_output (bool): Output results as JSON to stdout.
        output_file (Optional[str]): Output file path.
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

    Example:
        >>> nvdebug preflight --dut-config dut_config.yaml
    """

    # Auto-detect spreadsheet if not provided
    spreadsheet = auto_detect_spreadsheet(spreadsheet, suppress_print=json_output)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet)

    cli_preflight = CLIPreflight()
    asyncio.run(
        cli_preflight.run(
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
    )


@app.command(
    help='List available collectors using the new WorkflowOrchestrator.\n\nExamples:\n\n -  nvdebug list-collectors \n\n -  nvdebug list-collectors --baseboard "GB200 NVL"'
)
def list_collectors(
    baseboard: Optional[str] = typer.Option(
        None, "--baseboard", "-b", help="Filter by baseboard"
    ),
    group: Optional[str] = typer.Option(
        None, "--group", "-g", help="Filter by collector group"
    ),
    spreadsheet: Optional[Path] = typer.Option(
        None, "--spreadsheet", help="Collector spreadsheet path"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON to stdout"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output file path (for JSON or table format)",
    ),
) -> None:
    """
    List available collectors using the WorkflowOrchestrator.

    This command displays all available log collectors, optionally filtered by
    baseboard or collector group.

    Args:
        baseboard (Optional[str]): Filter by baseboard name.
        group (Optional[str]): Filter by collector group.
        spreadsheet (Optional[Path]): Collector spreadsheet path.
        json_output (bool): Output results as JSON to stdout.
        output_file (Optional[str]): Output file path.

    Example:
        >>> nvdebug list-collectors
        >>> nvdebug list-collectors --baseboard "GB200 NVL"
    """
    # Auto-detect spreadsheet if not provided
    spreadsheet = auto_detect_spreadsheet(spreadsheet, suppress_print=json_output)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet)

    cli_handler = CLIListCollectors()
    asyncio.run(
        cli_handler.run(
            baseboard,
            group,
            spreadsheet,
            json_output,
            output_file,
        )
    )


@app.command(
    help="List available baseboards from the spreadsheet.\n\nExamples:\n\n -  nvdebug list-baseboards"
)
def list_baseboards(
    spreadsheet: Optional[Path] = typer.Option(
        None, "--spreadsheet", help="Collector spreadsheet path"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON to stdout"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output file path (for JSON or table format)",
    ),
) -> None:
    """
    List available baseboards from the spreadsheet.

    This command displays all baseboard platforms defined in the collector
    definitions spreadsheet.

    Args:
        spreadsheet (Optional[Path]): Collector spreadsheet path.
        json_output (bool): Output results as JSON to stdout.
        output_file (Optional[str]): Output file path.

    Example:
        >>> nvdebug list-baseboards
    """

    # Auto-detect spreadsheet if not provided
    spreadsheet = auto_detect_spreadsheet(spreadsheet, suppress_print=json_output)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet)

    cli_baseboards = CLIListBaseboards()
    asyncio.run(cli_baseboards.run(spreadsheet, json_output, output_file))


if __name__ == "__main__":
    app()
