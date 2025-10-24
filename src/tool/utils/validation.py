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
Validation module for NVDebug Tool.

This module contains validation functions for the collect command to ensure
proper configuration and prevent invalid operations.
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from ..core.config_manager import ConfigurationManager
from .console_output import create_sanitized_console
from .resources import find_config_files


class ValidationError(Exception):
    """
    Custom exception for validation errors.

    Raised when configuration or parameter validation fails.
    """

    pass


def validate_dut_config_requirements(
    dut_config: Optional[Union[Path, Any]],  # Can be Path or DUTConfig object
    local: bool,
    cli_credentials: Dict[str, Any],
    ansible_inventory: Optional[Path] = None,
) -> Tuple[bool, List[str]]:
    """
    Validate that proper DUT configuration is provided.

    Args:
        dut_config: Path to DUT config file (can be auto-detected) or DUTConfig object
        local: Whether running in local mode
        cli_credentials: Dictionary of CLI credential arguments
        ansible_inventory: Path to Ansible inventory file

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Check if we have any configuration method
    # dut_config can be either a Path object (from file) or a DUTConfig object (from CLI)
    has_dut_config = dut_config is not None
    if hasattr(dut_config, "exists"):  # It's a Path object
        has_dut_config = has_dut_config and dut_config.exists()
    # If it's a DUTConfig object, we consider it valid (it was created from CLI args)

    has_ansible_inventory = ansible_inventory is not None and ansible_inventory.exists()
    has_cli_credentials = any(cli_credentials.values())

    # If we don't have any configuration and we're not in local mode, we need to check if auto-detection should have worked
    if (
        not has_dut_config
        and not has_ansible_inventory
        and not has_cli_credentials
        and not local
    ):
        # Try auto-detection to see if we can find configuration files
        auto_dut_config, auto_config = find_config_files()

        if auto_dut_config and auto_dut_config.exists():
            # Auto-detection found a file - this is expected and good!
            # Don't add an error, just note that auto-detection will be used
            pass
        else:
            # No configuration found at all
            errors.append(
                "Missing DUT configuration. Please provide one of the following:\n"
                "  • --dut-config <file> - Use a DUT configuration file\n"
                "  • --ansible-inventory <file> - Use an Ansible inventory file\n"
                "  • --local - Run in local mode (no remote access needed)\n"
                "  • BMC credentials - Provide --bmc-ip, --bmc-user, --bmc-pass\n"
                "  • Host credentials - Provide --host-ip, --host-user, --host-pass\n"
                "  • Auto-detection - Place dut_config.yaml in the same directory as the executable"
            )
    elif local:
        # In local mode, we don't need any DUT configuration files
        # Skip all validation related to connection parameters
        pass

    # Validate DUT config file if provided (only for Path objects)
    if (
        dut_config is not None
        and hasattr(dut_config, "exists")
        and not dut_config.exists()
    ):
        # Check if this is a temporary file from auto-assignment (which gets cleaned up)
        if "temp_" in str(dut_config):
            # This is expected - temporary file gets cleaned up after loading
            pass
        else:
            errors.append(f"DUT config file '{dut_config}' does not exist")

    # Validate Ansible inventory file if provided
    if ansible_inventory is not None and not ansible_inventory.exists():
        errors.append(f"Ansible inventory file '{ansible_inventory}' does not exist")

    return len(errors) == 0, errors


def validate_connection_parameters(
    cli_credentials: Dict[str, Any],
    local: bool,
    dut_config: Optional[Union[Path, Any]] = None,
) -> Tuple[bool, List[str]]:
    """
    Validate that at least one set of connection parameters (BMC or Host IP) is provided when not in local mode.

    This can come from CLI arguments or from a DUT config file.

    Note: This only validates the presence of connection parameters, not their validity.
    Preflight checks will handle testing the actual connections.

    Args:
        cli_credentials (Dict[str, Any]): Dictionary of CLI credential arguments.
        local (bool): Whether running in local mode.
        dut_config (Optional[Union[Path, Any]]): DUT config file path or DUTConfig object.

        Returns:
            Tuple of (is_valid, list_of_errors)
    """
    errors = []

    if local:
        # Local mode doesn't need connection parameters
        return True, errors

    # Check CLI credentials - only need IP addresses for validation
    has_bmc_ip_cli = bool(cli_credentials.get("bmc_ip"))
    has_host_ip_cli = bool(cli_credentials.get("host_ip"))

    # Check DUT config file if provided
    has_bmc_ip_config = False
    has_host_ip_config = False

    if dut_config is not None:
        if hasattr(dut_config, "exists") and dut_config.exists():
            # It's a Path object - load and check the file
            try:
                with open(dut_config, "r") as f:
                    config_data = yaml.safe_load(f)

                # Check for IP addresses in DUT config
                # First check DUT_Defaults (global defaults)
                dut_defaults = config_data.get("DUT_Defaults", {})
                has_bmc_ip_config = bool(
                    dut_defaults.get("BMC_IP") or dut_defaults.get("bmc_ip")
                )
                has_host_ip_config = bool(
                    dut_defaults.get("HOST_IP") or dut_defaults.get("host_ip")
                )

                # Then check individual DUT entries (they override defaults)
                for key, value in config_data.items():
                    if key != "DUT_Defaults" and isinstance(value, dict):
                        # This is a DUT entry
                        dut_data = value
                        if dut_data.get("BMC_IP") or dut_data.get("bmc_ip"):
                            has_bmc_ip_config = True
                        if dut_data.get("HOST_IP") or dut_data.get("host_ip"):
                            has_host_ip_config = True

            except Exception as e:
                errors.append(f"Error reading DUT config file: {e}")
        elif hasattr(dut_config, "bmc_ip"):
            # It's a DUTConfig object - check its attributes
            has_bmc_ip_config = bool(dut_config.bmc_ip)
            has_host_ip_config = bool(dut_config.host_ip)
        elif isinstance(dut_config, list):
            # It's a list of DUTConfig objects - check each one
            for dut in dut_config:
                if hasattr(dut, "bmc_ip") and dut.bmc_ip:
                    has_bmc_ip_config = True
                if hasattr(dut, "host_ip") and dut.host_ip:
                    has_host_ip_config = True

    # We need at least one IP address from either CLI or config
    has_bmc_ip = has_bmc_ip_cli or has_bmc_ip_config
    has_host_ip = has_host_ip_cli or has_host_ip_config

    if not has_bmc_ip and not has_host_ip:
        if (
            dut_config is not None
            and hasattr(dut_config, "exists")
            and dut_config.exists()
        ):
            # Sanitize the path to show only the filename
            config_filename = os.path.basename(str(dut_config))
            errors.append(
                f"Auto-detected DUT config file '{config_filename}' but it contains no connection IP addresses. "
                "Please provide one of the following:\n"
                "  • BMC_IP in DUT config file\n"
                "  • HOST_IP in DUT config file\n"
                "  • --bmc-ip via CLI\n"
                "  • --host-ip via CLI\n"
                "  • --local - Run in local mode (no remote access needed)"
            )
        else:
            errors.append(
                "No connection IP addresses provided. Please provide one of the following:\n"
                "  • --bmc-ip for BMC connection\n"
                "  • --host-ip for Host connection\n"
                "  • --local - Run in local mode (no remote access needed)"
            )

    return len(errors) == 0, errors


def validate_credentials_completeness(
    cli_credentials: Dict[str, Any], local: bool
) -> Tuple[bool, List[str]]:
    """
    Validate that credentials are complete when provided via CLI.

    Note: This only validates CLI credentials completeness. DUT config file credentials
    are validated by the connection parameters validation.

    Args:
        cli_credentials: Dictionary of CLI credential arguments
        local: Whether running in local mode

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    if local:
        # Local mode doesn't need credentials
        return True, errors

    # Check BMC credentials completeness (only if any BMC credential is provided)
    bmc_ip = cli_credentials.get("bmc_ip")
    bmc_user = cli_credentials.get("bmc_user")
    bmc_pass = cli_credentials.get("bmc_pass")

    if any([bmc_ip, bmc_user, bmc_pass]):
        missing_bmc = []
        if not bmc_ip:
            missing_bmc.append("--bmc-ip")
        if not bmc_user:
            missing_bmc.append("--bmc-user")
        if not bmc_pass:
            missing_bmc.append("--bmc-pass")

        if missing_bmc:
            errors.append(
                f"Incomplete BMC credentials. Missing: {', '.join(missing_bmc)}.\n"
                "  • Please provide all three: --bmc-ip, --bmc-user, --bmc-pass"
            )

    # Check Host credentials completeness (only if any Host credential is provided)
    host_ip = cli_credentials.get("host_ip")
    host_user = cli_credentials.get("host_user")
    host_pass = cli_credentials.get("host_pass")

    if any([host_ip, host_user, host_pass]):
        missing_host = []
        if not host_ip:
            missing_host.append("--host-ip")
        if not host_user:
            missing_host.append("--host-user")
        if not host_pass:
            missing_host.append("--host-pass")

        if missing_host:
            errors.append(
                f"Incomplete Host credentials. Missing: {', '.join(missing_host)}.\n"
                "  • Please provide all three: --host-ip, --host-user, --host-pass"
            )

    return len(errors) == 0, errors


def validate_collector_ids(
    collector_ids: Optional[str], config_manager: ConfigurationManager
) -> Tuple[bool, List[str]]:
    """
    Validate that specified collector IDs exist and are valid.

    Args:
        collector_ids: Comma or space separated collector IDs
        config_manager: Configuration manager instance

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    if not collector_ids:
        return True, errors

    # Parse collector IDs
    cid_items = []
    for item in collector_ids.split():
        if "," in item:
            cid_items.extend([cid.strip() for cid in item.split(",")])
        else:
            cid_items.append(item.strip())

    # Validate each collector ID
    invalid_ids = []
    for cid in cid_items:
        if not cid:
            continue

        collector_info = config_manager.get_collector_info(cid)
        if not collector_info:
            invalid_ids.append(cid)

    if invalid_ids:
        errors.append(
            f"Invalid collector IDs: {', '.join(invalid_ids)}.\n"
            "  • These collector IDs do not exist in the collector definitions\n"
            "  • Use --help to see available collector options"
        )

    return len(errors) == 0, errors


def validate_collector_groups(
    collector_groups: Optional[List[str]], config_manager: ConfigurationManager
) -> Tuple[bool, List[str]]:
    """
    Validate that specified collector groups exist and are valid.

    Args:
        collector_groups: List of collector group names
        config_manager: Configuration manager instance

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    if not collector_groups:
        return True, errors

    # Get all valid collector groups
    valid_groups = config_manager.get_all_collector_groups()

    # Validate each group
    invalid_groups = []
    for group in collector_groups:
        if group.lower() not in [g.lower() for g in valid_groups]:
            invalid_groups.append(group)

    if invalid_groups:
        errors.append(
            f"Invalid collector groups: {', '.join(invalid_groups)}.\n"
            f"  • Valid groups are: {', '.join(valid_groups)}\n"
            f"  • Use --help to see available group options"
        )

    return len(errors) == 0, errors


def validate_collector_mutual_exclusion(
    collector_ids: Optional[str], collector_groups: Optional[List[str]]
) -> Tuple[bool, List[str]]:
    """
    Validate that collector IDs and groups are not used inappropriately together.

    Args:
        collector_ids: Comma or space separated collector IDs
        collector_groups: List of collector group names

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    if not collector_ids or not collector_groups:
        return True, errors

    # Parse collector IDs to check for group conflicts
    cid_items = []
    for item in collector_ids.split():
        if "," in item:
            cid_items.extend([cid.strip() for cid in item.split(",")])
        else:
            cid_items.append(item.strip())

    # Check if any collector ID belongs to a specified group
    group_letter_map = {
        "redfish": "R",
        "ipmi": "I",
        "ssh": "S",
        "host": "H",
        "health_check": "C",
    }

    conflicts = []
    for cid in cid_items:
        if not cid:
            continue

        # Extract group letter from collector ID
        if len(cid) > 0:
            group_letter = cid[0].upper()

            # Check if this collector belongs to any specified group
            for group in collector_groups:
                expected_letter = group_letter_map.get(group.lower())
                if expected_letter and group_letter == expected_letter:
                    conflicts.append(f"Collector {cid} conflicts with group '{group}'")

    if conflicts:
        errors.append(
            f"Collector ID and group conflicts detected:\n"
            f"  {'; '.join(conflicts)}\n"
            f"  • Use either specific collector IDs OR groups, not both\n"
            f"  • Example: Use -S 'R1 R2' OR -g redfish, not both"
        )

    return len(errors) == 0, errors


def validate_collection_level(collection_level: str) -> Tuple[bool, List[str]]:
    """
    Validate that the collection level is valid.

    Args:
        collection_level: Collection level string

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    valid_levels = ["L1", "L2", "L3"]

    if collection_level not in valid_levels:
        errors.append(
            f"Invalid collection level '{collection_level}'.\n"
            f"  • Valid levels are: {', '.join(valid_levels)}\n"
            f"  • Use --level L1, L2, or L3"
        )

    return len(errors) == 0, errors


def validate_output_directory(output_dir: Path) -> Tuple[bool, List[str]]:
    """
    Validate that the output directory is accessible and writable.

    Args:
        output_dir: Output directory path

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    try:
        # Check if directory exists or can be created
        output_dir.mkdir(parents=True, exist_ok=True)

        # Check if directory is writable
        test_file = output_dir / ".test_write"
        test_file.write_text("test")
        test_file.unlink()

    except PermissionError:
        errors.append(
            f"Permission denied: Cannot write to output directory '{output_dir}'.\n"
            f"  • Check directory permissions or use a different location\n"
            f"  • Try using --output /tmp/your_directory"
        )
    except Exception as e:
        errors.append(
            f"Error with output directory '{output_dir}': {str(e)}.\n"
            f"  • Please check the directory path and permissions\n"
            f"  • Try using --output /tmp/your_directory"
        )

    return len(errors) == 0, errors


def run_comprehensive_validation(
    dut_config: Optional[Path],
    local: bool,
    cli_credentials: Dict[str, Any],
    collector_ids: Optional[str],
    collector_groups: Optional[List[str]],
    collection_level: str,
    output_dir: Path,
    config_manager: Optional[ConfigurationManager] = None,
    ansible_inventory: Optional[Path] = None,
) -> Tuple[bool, List[str]]:
    """
    Run comprehensive validation for the collect command.

    Args:
        dut_config: Path to DUT config file
        local: Whether running in local mode
        cli_credentials: Dictionary of CLI credential arguments
        collector_ids: Comma or space separated collector IDs
        collector_groups: List of collector group names
        collection_level: Collection level string
        output_dir: Output directory path
        config_manager: Configuration manager instance (optional)

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    all_errors = []

    # Validate DUT configuration requirements
    is_valid, errors = validate_dut_config_requirements(
        dut_config, local, cli_credentials, ansible_inventory
    )
    all_errors.extend(errors)

    # Validate connection parameters (at least one set of BMC or Host parameters)
    is_valid, errors = validate_connection_parameters(
        cli_credentials, local, dut_config
    )
    all_errors.extend(errors)

    # Validate credentials completeness
    is_valid, errors = validate_credentials_completeness(cli_credentials, local)
    all_errors.extend(errors)

    # Validate collection level
    is_valid, errors = validate_collection_level(collection_level)
    all_errors.extend(errors)

    # Validate output directory
    is_valid, errors = validate_output_directory(output_dir)
    all_errors.extend(errors)

    # Validate collector IDs if config manager is available
    if config_manager:
        is_valid, errors = validate_collector_ids(collector_ids, config_manager)
        all_errors.extend(errors)

        # Validate collector groups
        is_valid, errors = validate_collector_groups(collector_groups, config_manager)
        all_errors.extend(errors)

        # Validate mutual exclusion
        is_valid, errors = validate_collector_mutual_exclusion(
            collector_ids, collector_groups
        )
        all_errors.extend(errors)

    return len(all_errors) == 0, all_errors


def display_validation_errors(errors: List[str]) -> None:
    """
    Display validation errors in a visually appealing format using Rich console.

    Args:
        errors: List of error messages
    """
    from rich.columns import Columns
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    console = create_sanitized_console()

    # Create a table for better error formatting
    error_table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        show_edge=False,
        border_style="red",
    )

    error_table.add_column("Number", style="bold red", width=4)
    error_table.add_column("Error", style="red")

    for i, error in enumerate(errors, 1):
        # Split error into lines for better formatting
        error_lines = error.split("\n")
        first_line = error_lines[0]
        remaining_lines = error_lines[1:] if len(error_lines) > 1 else []

        # Add first line with number
        error_table.add_row(f"{i}.", first_line)

        # Add remaining lines indented
        for line in remaining_lines:
            if line.strip():  # Only add non-empty lines
                error_table.add_row("", f"  {line}")

    # Create the main error panel with enhanced styling
    error_panel = Panel(
        error_table,
        title="[bold red]🚫 Configuration Validation Failed[/bold red]",
        subtitle="[dim]Please review and fix the issues below[/dim]",
        border_style="red",
        padding=(1, 2),
        highlight=True,
        title_align="center",
    )

    console.print(error_panel)

    # Add a separator
    console.print(Rule(style="red"))

    # Create enhanced help panel with actionable steps
    help_text = Text()
    help_text.append("🔧 ", style="bold yellow")
    help_text.append("Fix the configuration issues above\n", style="bold yellow")
    help_text.append("    • 📖 ", style="bold cyan")
    help_text.append("Use ", style="dim")
    help_text.append("--help", style="bold cyan")
    help_text.append(" for detailed command options\n", style="dim")
    help_text.append("    • 💡 ", style="bold green")
    help_text.append("Common solutions:\n", style="bold green")
    help_text.append("        • Add ", style="dim")
    help_text.append("--local", style="bold cyan")
    help_text.append(" for local mode\n", style="dim")
    help_text.append("        • Use ", style="dim")
    help_text.append("--dut-config", style="bold cyan")
    help_text.append(" for configuration file\n", style="dim")
    help_text.append(
        "        • Provide complete credentials (IP, user, password)\n",
        style="dim",
    )

    help_panel = Panel(
        help_text,
        title="[bold yellow]💡 How to Fix[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
        title_align="center",
    )

    console.print(help_panel)


def display_dut_config_error(error_message: str) -> None:
    """
    Display DUT configuration errors in a visually appealing format using Rich console.

    Args:
        error_message: The error message to display
    """

    console = create_sanitized_console()

    # Create the main error panel with enhanced styling
    error_panel = Panel(
        error_message,
        title="[bold red]🚫 DUT Configuration Error[/bold red]",
        subtitle="[dim]The DUT config file could not be loaded[/dim]",
        border_style="red",
        padding=(1, 2),
        highlight=True,
        title_align="center",
    )

    console.print(error_panel)

    # Add a separator
    console.print(Rule(style="red"))

    # Create enhanced help panel with actionable steps
    help_text = Text()
    help_text.append("🔧 ", style="bold yellow")
    help_text.append("Quick Solutions:\n", style="bold yellow")
    help_text.append("    • 📝 ", style="bold cyan")
    help_text.append(
        "Edit your DUT config file to define at least one DUT\n", style="dim"
    )
    help_text.append("    • 🏠 ", style="bold green")
    help_text.append("Use ", style="dim")
    help_text.append("--local", style="bold cyan")
    help_text.append(" flag to run in local mode\n", style="dim")
    help_text.append("    • 🔑 ", style="bold magenta")
    help_text.append("Provide CLI credentials instead of a config file\n", style="dim")
    help_text.append("    • 📖 ", style="bold blue")
    help_text.append("Use ", style="dim")
    help_text.append("--help", style="bold cyan")
    help_text.append(" for more options", style="dim")

    help_panel = Panel(
        help_text,
        title="[bold yellow]💡 Need Help?[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
        highlight=True,
        title_align="center",
    )

    console.print(help_panel)
