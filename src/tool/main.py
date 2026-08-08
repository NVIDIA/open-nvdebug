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
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import click
import typer
from click.core import ParameterSource
from rich.console import Console

from .cli_handler import (
    CLICollector,
    CLIDefaultCollectors,
    CLIListBaseboards,
    CLIListCollectors,
    CLIPreflight,
)
from .config import (
    DUTConfig,
    auto_assign_config_file_to_use,
    get_available_baseboards,
    load_config,
    load_dut_config,
    validate_baseboard,
)
from .main_helpers import (
    _build_cli_dut_config,
    _extract_tool_defaults,
    _get_config_value,
    _load_config_mode_duts,
    _load_dut_defaults_from_yaml,
    _load_tool_config,
    _resolve_config_paths,
    _resolve_source_config_paths,
    _run_collector_and_level_validation,
    build_tool_config,
    should_use_cli_value,
)
from .utils.ansible_inventory import (
    cleanup_temp_config_files,
    generate_config_files_from_ansible,
)
from .utils.console_output import create_sanitized_console
from .utils.frozen_path import get_base_path, is_frozen
from .utils.resources import (
    find_all_config_files,
)
from .utils.spreadsheet_utils import (
    auto_detect_spreadsheet,
    validate_spreadsheet_requirement,
)
from .utils.streaming import (
    format_stream_window_component,
    normalize_stream_window,
)
from .utils.validation import (
    display_dut_config_error,
    display_validation_errors,
    run_comprehensive_validation,
    validate_collection_level,
    validate_collector_groups,
    validate_collector_ids,
)
from .version import __build_hash__, __build_time__, __version__


def _frozen_self_check() -> None:
    """Validate critical bundled files exist at startup (frozen mode only).

    Runs in ~5ms. Exits with code 78 (EX_CONFIG) if critical components
    are missing, indicating a corrupted or incomplete binary.
    """
    if not is_frozen():
        return

    import logging

    base = get_base_path()
    critical = ["tool"]
    for component in critical:
        path = base / component
        if not path.exists():
            print(
                f"FATAL: Bundled component '{component}' not found at {path}. "
                "Binary may be corrupted or incomplete.",
                file=sys.stderr,
            )
            sys.exit(78)



def _cli_param_was_set(param_name: str) -> bool:
    """Return True when a CLI parameter was explicitly provided by the user."""
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return False
    return ctx.get_parameter_source(param_name) == ParameterSource.COMMANDLINE


def _find_env_file() -> Optional[Path]:
    """Return the configured .env file, or the repo-local .env when available."""
    env_path = os.environ.get("NVDEBUG_ENV_FILE") or os.environ.get(
        "NVDEBUG_LOGLAKE_ENV_FILE"
    )
    if env_path:
        candidate = Path(env_path).expanduser()
        return candidate if candidate.is_file() else None

    try:
        repo_root = Path(__file__).resolve().parents[2]
    except (OSError, RuntimeError, IndexError):
        return None

    candidate = repo_root / ".env"
    return candidate if candidate.is_file() else None


def _load_env_file(env_path: Path, *, override: bool = False) -> bool:
    """Load KEY=VALUE pairs from a .env file into ``os.environ``."""
    try:
        content = env_path.read_text(encoding="utf-8")
    except OSError:
        return False

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        if not key:
            continue

        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]

        if override or key not in os.environ:
            os.environ[key] = value

    return True


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
        level1 (str): First collection level (L0, L1, L2, or L3).
        level2 (str): Second collection level (L0, L1, L2, or L3).

    Returns:
        str: The higher collection level.
    """
    level_mapping = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
    level1_num = level_mapping.get(level1.upper(), 1)
    level2_num = level_mapping.get(level2.upper(), 1)
    max_level = max(level1_num, level2_num)
    return (
        "L3"
        if max_level == 3
        else "L2" if max_level == 2 else "L1" if max_level == 1 else "L0"
    )


@app.callback(
    help="NVIDIA Debug Collection Tool\n\nEach command has dedicated COMMAND OPTIONS/ARGS. Run 'nvdebug COMMAND --help' to see them.\n\nExamples:\n\n -  nvdebug collect --dut-config dut_config.yaml\n\n -  nvdebug preflight --dut-config dut_config.yaml\n\n -  nvdebug --version",
    invoke_without_command=True,
)
def main(
    ctx: typer.Context,
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
    _frozen_self_check()
    env_file = _find_env_file()
    if env_file is not None:
        _load_env_file(env_file)

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
    # Status Tracking Configuration
    # enable_status_tracking: bool = typer.Option(
    #     True,
    #     "--enable-status-tracking",
    #     help="Enable real-time collection status tracking",
    # ),
    # disable_live_display: bool = typer.Option(
    #     False,
    #     "--disable-live-display",
    #     help="Disable live status display (status files still created)",
    # ),
    # Collector Configuration
    collector_id: Optional[str] = typer.Option(
        None,
        "--collector-id",
        "-S",
        help="Specific collector IDs to run (space or comma separated)",
    ),
    collector_group: Optional[List[str]] = typer.Option(
        None,
        "--collector-group",
        "-g",
        help="Specific log groups to run (comma or space separated, e.g. -g redfish,ipmi or -g redfish -g ipmi)",
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
    execution_scheduler: Optional[str] = typer.Option(
        None,
        "--execution-scheduler",
        help="Collector scheduler mode: per_dut or legacy_global",
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
    host_ssh_port: Optional[int] = typer.Option(
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
    rf_hmc_prefix: Optional[str] = typer.Option(
        None,
        "--hmc-rf-prefix",
        help=(
            "Redfish URI prefix for HMC-targeted resources (e.g. /hgx/redfish/v1). "
            "Overrides RF_HMC_DEFAULT_PREFIX in DUT config. "
            "Leave unset when BMC exposes HMC resources under the same prefix as the BMC Redfish root."
        ),
    ),
    rf_bmc_prefix: Optional[str] = typer.Option(
        None,
        "--bmc-rf-prefix",
        help=(
            "Redfish URI prefix for BMC (Customer BMC) resources (e.g. /custom/redfish/v1). "
            "Overrides RF_DEFAULT_PREFIX in DUT config. "
            "Defaults to /redfish/v1 when not set."
        ),
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
    report_format: str = typer.Option(
        "spa",
        "--report-format",
        help="Report format: 'spa' (Vue SPA, default), 'legacy' (HTML only), or 'both'",
    ),
    ssl_verify: Optional[bool] = typer.Option(
        None,
        "--ssl-verify/--no-ssl-verify",
        help="Enable/disable SSL certificate verification for Redfish connections. "
        "Default: disabled (BMC self-signed certs).",
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
        help="List of collector IDs to add to the default collectors (comma-separated, additive to defaults)",
    ),
    # Streaming Configuration
    streaming_only: bool = typer.Option(
        False,
        "--streaming-only",
        help="Only run collectors marked as streaming candidates",
    ),
    stream_begin: str = typer.Option(
        "24",
        "--stream-begin",
        help="Start of streaming window as UTC timestamp (YYYYMMDDTHHMMZ) or hours ago. Defaults to 24.",
    ),
    stream_end: str = typer.Option(
        "0",
        "--stream-end",
        help="End of streaming window as UTC timestamp (YYYYMMDDTHHMMZ) or hours ago. Defaults to 0 (now).",
    ),
    stream_destination: Optional[Path] = typer.Option(
        None,
        "--stream-destination",
        help="Destination path for streamed logs (e.g. shared NFS mount), separate from --output",
    ),
    append: bool = typer.Option(
        False,
        "--append",
        help="Write streaming output into a stable destination tree instead of creating a new timestamped run root.",
    ),
    rack_id: Optional[str] = typer.Option(
        None,
        "--rack-id",
        help="Optional rack identifier used as an intermediate output directory for streaming collections.",
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
        host_ssh_port (Optional[int]): Host SSH port.
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
        use_port_forwarding (bool): Enable port forwarding.
        tunnel_tcp_port (Optional[int]): Port for SSH tunnel forwarding.
        setup_port_forwarding (bool): Auto-setup port forwarding tunnels.
        force_port_fw (bool): Force cleanup existing port forwarding.
        hmc_access_method (Optional[str]): HMC access method.
        rf_hmc_prefix (Optional[str]): Redfish URI prefix for HMC-targeted resources.
            Overrides RF_HMC_DEFAULT_PREFIX in DUT config (e.g. /hgx/redfish/v1).
            Leave unset when BMC exposes HMC resources at the standard /redfish/v1.
        rf_bmc_prefix (Optional[str]): Redfish URI prefix for BMC (Customer BMC) resources.
            Overrides RF_DEFAULT_PREFIX in DUT config (e.g. /custom/redfish/v1).
            Defaults to /redfish/v1 when not set.
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

    # Normalize collector groups: split comma-separated values and lowercase
    if collector_group:
        expanded = []
        for g in collector_group:
            expanded.extend(
                part.strip().lower() for part in g.split(",") if part.strip()
            )
        collector_group = expanded

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

    # Minimal init; config_file_data and config-derived vars are set after _load_tool_config
    config_file_data = {}
    final_output_dir = str(output_dir)

    # Prepare CLI credentials dictionary for validation
    cli_credentials = {
        "bmc_ip": bmc_ip,
        "bmc_user": bmc_user,
        "bmc_pass": bmc_pass,
        "bmc_ssh_user": bmc_ssh_user,
        "bmc_ssh_pass": bmc_ssh_pass,
        "bmc_ssh_key_path": bmc_ssh_key_path,
        "bmc_ssh_passwordless": bmc_ssh_passwordless,
        "host_ip": host_ip,
        "host_user": host_user,
        "host_pass": host_pass,
        "host_ssh_key_path": host_ssh_key_path,
        "host_ssh_passwordless": host_ssh_passwordless,
        "hmc_ip": hmc_ip,
        "hmc_user": hmc_user,
        "hmc_pass": hmc_pass,
        "hmc_ssh_user": hmc_ssh_user,
        "hmc_ssh_pass": hmc_ssh_pass,
        "hmc_ssh_key_path": hmc_ssh_key_path,
        "hmc_ssh_passwordless": hmc_ssh_passwordless,
    }

    has_cli_credentials = any([bmc_ip, host_ip, hmc_ip])

    # Mutual-exclusion: ansible, dut_config, and CLI creds cannot be combined
    if ansible_inventory and (dut_config or has_cli_credentials):
        sanitized_console.print_error(
            "Error: --ansible-inventory cannot be combined with --dut-config or CLI credentials.\n"
            "  Use --ansible-inventory alone, OR --dut-config / CLI credentials."
        )
        sys.exit(1)

    # Mutual-exclusion: --local runs on the local machine without remote access
    if local and (has_cli_credentials or dut_config or ansible_inventory):
        sanitized_console.print_error(
            "Error: --local cannot be combined with --dut-config, --ansible-inventory, or CLI credentials.\n"
            "  --local runs collection on the local machine without remote access."
        )
        sys.exit(1)

    # Streaming validation
    if streaming_only and not stream_destination:
        sanitized_console.print_error(
            "Error: --streaming-only requires --stream-destination.\n"
            "  Provide a destination path for streamed logs (e.g. --stream-destination /mnt/shared/logs)."
        )
        sys.exit(1)

    if stream_destination and not streaming_only:
        sanitized_console.print_warning(
            "Warning: --stream-destination is set but --streaming-only is not. "
            "Enabling --streaming-only automatically."
        )
        streaming_only = True

    if stream_destination and not stream_destination.is_absolute():
        sanitized_console.print_error(
            "Error: --stream-destination must be an absolute path.\n"
            f"  Got: {stream_destination}"
        )
        sys.exit(1)

    if streaming_only and stream_destination and not append:
        sanitized_console.print_warning(
            "Warning: --stream-destination is set for streaming mode. "
            "Enabling --append automatically to preserve a stable directory tree."
        )
        append = True

    if append and stream_destination is None and not streaming_only:
        sanitized_console.print_error(
            "Error: '--append' requires '--stream-destination' or '--streaming-only'."
        )
        sys.exit(1)

    if streaming_only or stream_destination or append:
        normalized_now = datetime.now(timezone.utc)
        try:
            stream_begin_dt, stream_end_dt = normalize_stream_window(
                stream_begin, stream_end, normalized_now
            )
        except ValueError as exc:
            sanitized_console.print_error(f"Error: {exc}")
            sys.exit(1)

        stream_begin = format_stream_window_component(stream_begin_dt)
        stream_end = format_stream_window_component(stream_end_dt)

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

    # Resolve config paths (auto-detect if not explicitly provided)
    config_file, dut_config = _resolve_config_paths(
        config_file, dut_config, sanitized_console, local_mode=local
    )

    if not dut_config and not has_cli_credentials and not local:
        sanitized_console.print_error(
            "No DUT configuration found. Please provide one of:\n"
            "  * --dut-config <file>\n"
            "  * --local\n"
            "  * CLI credentials (--bmc-ip, --host-ip, etc.)"
        )
        sys.exit(1)

    # Load tool config once (applies to all modes)
    config_file_data = _load_tool_config(config_file, sanitized_console)
    defaults = _extract_tool_defaults(config_file_data, output_dir)
    tool_config_baseboard = defaults["tool_config_baseboard"]
    final_output_dir = defaults["final_output_dir"]
    config_generate_html_reports = defaults["config_generate_html_reports"]
    config_log_sanitization = defaults["config_log_sanitization"]
    max_concurrent_duts = defaults["max_concurrent_duts"]
    max_concurrent_collectors_per_dut = defaults["max_concurrent_collectors_per_dut"]
    timeout = defaults["timeout"]
    retry_count = defaults["retry_count"]
    config_skip_zip = defaults["config_skip_zip"]
    config_skip_zip_split = defaults["config_skip_zip_split"]
    config_zip_split_threshold = defaults["config_zip_split_threshold"]
    config_log_level = defaults["config_log_level"]
    config_log_format = defaults["config_log_format"]
    config_execution_scheduler = defaults["execution_scheduler"]
    final_execution_scheduler = str(
        execution_scheduler or config_execution_scheduler or "per_dut"
    ).strip().lower()
    if final_execution_scheduler not in {"per_dut", "legacy_global"}:
        sanitized_console.print_error(
            "Invalid --execution-scheduler value "
            f"'{final_execution_scheduler}'. Expected 'per_dut' or 'legacy_global'."
        )
        sys.exit(1)

    report_format = str(report_format or "spa").strip().lower()
    if report_format not in {"legacy", "spa", "both"}:
        sanitized_console.print_error(
            "Invalid --report-format value "
            f"'{report_format}'. Expected 'legacy', 'spa', or 'both'."
        )
        sys.exit(1)
    parallel_dut_sequential_collectors = defaults["parallel_dut_sequential_collectors"]
    service_grouped_sequential_collectors = defaults[
        "service_grouped_sequential_collectors"
    ]
    if hasattr(config_file_data, "__dict__"):
        config_file_data.LogSanitization = config_log_sanitization

    # Apply CLI --ssl-verify/--no-ssl-verify override to redfish_session_config
    if ssl_verify is not None:
        if isinstance(config_file_data, dict):
            rsc = config_file_data.setdefault("redfish_session_config", {})
            rsc["ssl_verify"] = ssl_verify
        elif hasattr(config_file_data, "redfish_session_config"):
            rsc = config_file_data.redfish_session_config
            if rsc is None:
                rsc = {}
                config_file_data.redfish_session_config = rsc
            if isinstance(rsc, dict):
                rsc["ssl_verify"] = ssl_verify
            else:
                setattr(rsc, "ssl_verify", ssl_verify)

    # Determine if we're in single DUT CLI mode or multi-DUT config mode.
    # Precedence rule: CLI > dut_config > defaults. An explicit --dut-config
    # always routes through the YAML path; CLI flags then merge as per-DUT
    # overrides (see per_dut_overrides block below). CLI mode (building a
    # DUTConfig entirely from CLI args) is reserved for when the user did not
    # provide a dut_config at all.
    # Auto-detected dut_configs (picked up by _resolve_config_paths) do not
    # block CLI mode; only a user-supplied --dut-config does.
    cli_mode = (has_cli_credentials or local) and not original_dut_config

    # Run early validation only for collection level (other validation happens after auto-detection)
    if not skip_validation and collection_level is not None:
        is_valid, collection_errors = validate_collection_level(collection_level)
        if not is_valid:
            display_validation_errors(collection_errors)
            sys.exit(1)

    # Handle CLI vs config file precedence
    if cli_mode:
        # Honor DUT_Defaults from an auto-detected dut_config.yaml when the
        # user didn't pass --dut-config explicitly. Without this, fields like
        # `baseboard` set in that file's DUT_Defaults would be silently
        # ignored even though the same file is archived into the output dir.
        auto_dut_defaults = (
            _load_dut_defaults_from_yaml(dut_config)
            if dut_config and not original_dut_config
            else {}
        )
        dut_configs = _build_cli_dut_config(
            baseboard,
            tool_config_baseboard,
            local,
            non_interactive,
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
            host_ip,
            host_user,
            host_pass,
            host_ssh_port,
            host_ssh_key_path,
            host_ssh_passwordless,
            host_ssh_max_retries,
            hmc_ip,
            hmc_user,
            hmc_pass,
            hmc_ssh_user,
            hmc_ssh_pass,
            hmc_ssh_port,
            hmc_ssh_key_path,
            hmc_ssh_passwordless,
            hmc_ssh_max_retries,
            hmc_http_port,
            hmc_https_port,
            hmc_use_https,
            use_port_forwarding,
            tunnel_tcp_port,
            setup_port_forwarding,
            force_port_fw,
            hmc_access_method,
            rf_hmc_prefix,
            rf_bmc_prefix,
            ssh_proxy_host,
            ssh_proxy_port,
            ssh_proxy_user,
            ssh_proxy_pass,
            ssh_proxy_key_path,
            ssh_proxy_passwordless,
            ssh_proxy_max_retries,
            sanitized_console,
            dut_defaults=auto_dut_defaults,
        )
    else:
        # Multi-DUT config mode (dut_config already resolved by _resolve_config_paths)
        # Load DUT configs (auto-assign, load, baseboard override, non_interactive)
        original_dut_config = dut_config
        dut_configs, resolved_dut_config = _load_config_mode_duts(
            dut_config, config_file, baseboard, non_interactive, sanitized_console
        )

        # Apply CLI overrides only when dut_config has a single DUT; multi-DUT → no overrides
        try:
            global_overrides = {}
            if ssh_proxy_host:
                global_overrides["ssh_proxy_host"] = ssh_proxy_host
            if _cli_param_was_set("ssh_proxy_port"):
                global_overrides["ssh_proxy_port"] = ssh_proxy_port
            if ssh_proxy_user:
                global_overrides["ssh_proxy_user"] = ssh_proxy_user
            if ssh_proxy_pass:
                global_overrides["ssh_proxy_pass"] = ssh_proxy_pass
            if ssh_proxy_key_path:
                global_overrides["ssh_proxy_key_path"] = ssh_proxy_key_path
            if _cli_param_was_set("ssh_proxy_passwordless"):
                global_overrides["ssh_proxy_passwordless"] = ssh_proxy_passwordless
            if _cli_param_was_set("ssh_proxy_max_retries"):
                global_overrides["ssh_proxy_max_retries"] = ssh_proxy_max_retries

            # Per-DUT overrides (apply only to single DUT if only one DUT exists)
            per_dut_overrides = {}
            if bmc_ip:
                per_dut_overrides["bmc_ip"] = bmc_ip
                per_dut_overrides["BMC_IP"] = (
                    bmc_ip  # Ensure legacy field matches CLI override
                )
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
            if _cli_param_was_set("bmc_ssh_passwordless"):
                per_dut_overrides["bmc_ssh_passwordless"] = bmc_ssh_passwordless
            if bmc_ssh_max_retries is not None and bmc_ssh_max_retries != 3:
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
            if _cli_param_was_set("host_ssh_passwordless"):
                per_dut_overrides["host_ssh_passwordless"] = host_ssh_passwordless
            if host_ssh_max_retries is not None and host_ssh_max_retries != 3:
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
            if _cli_param_was_set("hmc_ssh_passwordless"):
                per_dut_overrides["hmc_ssh_passwordless"] = hmc_ssh_passwordless
            if hmc_ssh_max_retries is not None and hmc_ssh_max_retries != 3:
                per_dut_overrides["hmc_ssh_max_retries"] = hmc_ssh_max_retries
            if hmc_http_port is not None and hmc_http_port != 80:
                per_dut_overrides["hmc_http_port"] = hmc_http_port
            if hmc_https_port is not None and hmc_https_port != 443:
                per_dut_overrides["hmc_https_port"] = hmc_https_port
            if _cli_param_was_set("hmc_use_https"):
                per_dut_overrides["hmc_use_https"] = hmc_use_https
            if hmc_access_method:
                per_dut_overrides["hmc_access_method"] = hmc_access_method
            if _cli_param_was_set("use_port_forwarding"):
                per_dut_overrides["use_port_forwarding"] = use_port_forwarding
            if tunnel_tcp_port is not None:
                per_dut_overrides["tunnel_tcp_port"] = tunnel_tcp_port
            if _cli_param_was_set("setup_port_forwarding"):
                per_dut_overrides["setup_port_forwarding"] = (
                    setup_port_forwarding
                    if setup_port_forwarding is not None
                    else False
                )
            if _cli_param_was_set("force_port_fw"):
                per_dut_overrides["force_port_fw"] = (
                    force_port_fw if force_port_fw is not None else False
                )
            if rf_hmc_prefix is not None:
                per_dut_overrides["RF_HMC_DEFAULT_PREFIX"] = rf_hmc_prefix
            if rf_bmc_prefix is not None:
                per_dut_overrides["RF_DEFAULT_PREFIX"] = rf_bmc_prefix

            # Per-DUT credential overrides (bmc, host, hmc, Redfish) are ambiguous with
            # multiple DUTs — reject those only. Tool-level flags (-o, -z, -VV, etc.) are
            # applied later via ToolConfig and are always allowed.
            if len(dut_configs) > 1 and per_dut_overrides:
                sanitized_console.print_error(
                    "DUT config file defines more than one DUT; per-DUT CLI credentials are not allowed.\n"
                    "  Do not pass --bmc-ip, --host-ip, --hmc-ip, credentials, or Redfish prefix overrides.\n"
                    "  Tool-level options (e.g. -o, -z, -VV, --spreadsheet) are allowed."
                )
                sys.exit(1)

            # Apply global overrides (e.g. ssh_proxy) to all DUTs; apply per-DUT overrides only when single DUT
            if global_overrides:
                for dut_config_obj in dut_configs:
                    for key, value in global_overrides.items():
                        setattr(dut_config_obj, key, value)
            if len(dut_configs) == 1 and per_dut_overrides:
                for key, value in per_dut_overrides.items():
                    setattr(dut_configs[0], key, value)

            # Clean up temporary file if it was created by auto-assignment
            if (
                "temp_" in str(resolved_dut_config)
                and resolved_dut_config != original_dut_config
            ):
                try:
                    resolved_dut_config.unlink()
                    sanitized_console.print_info("Cleaned up temporary DUT config file")
                except Exception as e:
                    sanitized_console.print_warning(
                        f"Could not clean up temporary file: {e}"
                    )

        except Exception as e:
            # Use pretty formatted error display for better user experience
            display_dut_config_error(str(e))
            sys.exit(1)

    # Determine final collection level (config file default, CLI override)
    config_collection_level = getattr(config_file_data, "collection_level", "L1")
    # Use CLI level if it was determined earlier, otherwise use config file
    if final_collection_level is None:
        final_collection_level = config_collection_level

    # Convert enum to string if needed
    if hasattr(final_collection_level, "value"):
        final_collection_level = final_collection_level.value

    # Now create the ToolConfig after all config file loading and output directory logic
    tool_config = build_tool_config(
        config_file_data,
        final_output_dir=final_output_dir,
        final_collection_level=final_collection_level,
        max_concurrent_duts=max_concurrent_duts,
        max_concurrent_collectors_per_dut=max_concurrent_collectors_per_dut,
        timeout=timeout,
        retry_count=retry_count,
        config_skip_zip=config_skip_zip,
        config_skip_zip_split=config_skip_zip_split,
        config_zip_split_threshold=config_zip_split_threshold,
        config_log_level=config_log_level,
        config_log_format=config_log_format,
        config_log_sanitization=config_log_sanitization,
        config_generate_html_reports=config_generate_html_reports,
        execution_scheduler=final_execution_scheduler,
        parallel_dut_sequential_collectors=parallel_dut_sequential_collectors,
        service_grouped_sequential_collectors=service_grouped_sequential_collectors,
        skip_zip=skip_zip,
        skip_zip_split=skip_zip_split,
        zip_split_threshold=zip_split_threshold,
        skip_sanitization=skip_sanitization,
        skip_html_reports=skip_html_reports,
        report_format=report_format,
        collector_id=collector_id,
        collector_group=collector_group,
        skip_collectors=skip_collectors,
        include_collectors=include_collectors,
        spreadsheet=spreadsheet,
        debug=debug,
        verbose=verbose,
        dry_run=dry_run,
        skip_preflight=skip_preflight,
        streaming_only=streaming_only,
        stream_begin=stream_begin,
        stream_end=stream_end,
        stream_destination=str(stream_destination) if stream_destination else None,
        append=append,
        rack_id=rack_id,
    )

    # Resolve source config paths for archiving (best-effort)
    source_tool_config_path, source_dut_config_path = _resolve_source_config_paths(
        config_file, original_dut_config, dut_config
    )

    cli_collector = CLICollector(
        tool_config,
        dut_configs,
        source_tool_config=source_tool_config_path,
        source_dut_config=source_dut_config_path,
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
            cli_mode=cli_mode,  # In CLI mode require complete credentials and exit on error
        )

        if not is_valid:
            display_validation_errors(validation_errors)
            sys.exit(1)

    # Run collector-specific validation after CLI collector is created
    if (
        collector_id
        or collector_group
        or include_collectors
        or skip_collectors
        or final_collection_level != "L1"
    ) and not skip_validation:
        _run_collector_and_level_validation(
            tool_config=tool_config,
            dut_configs=dut_configs,
            collector_id=collector_id,
            collector_group=collector_group,
            include_collectors=include_collectors,
            skip_collectors=skip_collectors,
            final_collection_level=final_collection_level,
            sanitized_console=sanitized_console,
            reported_config_errors=_reported_config_errors,
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
    host_ssh_port: Optional[int] = typer.Option(
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
        host_ssh_port (Optional[int]): Host SSH port.
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
            # HMC Configuration
            hmc_ip,
            hmc_user,
            hmc_pass,
            hmc_ssh_user,
            hmc_ssh_pass,
            hmc_ssh_port,
            hmc_ssh_key_path,
            hmc_ssh_passwordless,
            hmc_ssh_max_retries,
            hmc_http_port,
            hmc_https_port,
            hmc_use_https,
        )
    )


@app.command(
    help='List available collectors using the new WorkflowOrchestrator.\n\nExamples:\n\n -  nvdebug list-collectors \n\n -  nvdebug list-collectors --baseboard "GB200 NVL"\n\n -  nvdebug list-collectors --group ssh,redfish'
)
def list_collectors(
    baseboard: Optional[str] = typer.Option(
        None, "--baseboard", "-b", help="Filter by baseboard"
    ),
    group: Optional[str] = typer.Option(
        None,
        "--group",
        "-g",
        help="Filter by collector group(s), comma-separated, case-insensitive",
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
        group (Optional[str]): Filter by collector group(s), comma-separated.
        spreadsheet (Optional[Path]): Collector spreadsheet path.
        json_output (bool): Output results as JSON to stdout.
        output_file (Optional[str]): Output file path.

    Example:
        >>> nvdebug list-collectors
        >>> nvdebug list-collectors --baseboard "GB200 NVL"
        >>> nvdebug list-collectors --group health_check,inventory
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
