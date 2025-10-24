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

This module handles parsing of Ansible inventory files and converting them
to DUT configurations with support for INI and YAML formats.
"""

import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..config import DUTConfig


def _display_yaml_error(file_path: Path, error_message: str, error_type: str) -> None:
    """
    Display YAML parsing errors in a visually appealing format using Rich console.

    Args:
        file_path: Path to the problematic YAML file
        error_message: The error message from YAML parser
        error_type: Type of error (e.g., "YAML parsing failed", "Auto-fix failed")
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
    error_table.add_row("Technical Details:", error_message)

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


def _fix_common_yaml_issues(file_path: Path) -> bool:
    """
    Attempt to fix common YAML encoding issues in the file.

    Args:
        file_path: Path to the YAML file

    Returns:
        True if fixes were applied, False otherwise
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        original_content = content
        fixes_applied = False

        # Fix common header corruption issues
        if content.startswith("D---"):
            content = content.replace("D---", "---", 1)
            fixes_applied = True

        # Fix other common header issues
        if content.startswith("---\n") == False and content.startswith("---"):
            # Already has proper header
            pass
        elif not content.startswith("---"):
            # Add missing header
            content = "---\n" + content
            fixes_applied = True

        # Only write back if we made changes
        if fixes_applied:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True

    except Exception:
        # If we can't fix it, that's okay - let the original error handling take over
        pass

    return False


def parse_ansible_inventory_to_dut_configs(
    ansible_inventory_path: Path,
    baseboard: Optional[str] = None,
) -> Tuple[List[DUTConfig], Dict[str, Any]]:
    """
    Parse Ansible inventory file and convert to DUT configurations.

    This is a simplified implementation that doesn't rely on sps_tools_utils
    but provides similar functionality for the nvdebugtool.

    Args:
        ansible_inventory_path: Path to the Ansible inventory file
        baseboard: Optional baseboard type to use for all DUTs

    Returns:
        Tuple of (list of DUTConfig objects, node_type_configs dictionary)
    """
    if not ansible_inventory_path.exists():
        raise FileNotFoundError(
            f"Ansible inventory file not found: {ansible_inventory_path}"
        )

    # Load the ansible inventory file with comprehensive error handling
    try:
        with open(ansible_inventory_path, "r") as f:
            ansible_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        # Try to automatically fix common YAML issues
        if _fix_common_yaml_issues(ansible_inventory_path):
            try:
                # Retry parsing after fixes
                with open(ansible_inventory_path, "r") as f:
                    ansible_data = yaml.safe_load(f)
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
    except Exception as e:
        error_msg = f"Unexpected error reading Ansible inventory file: {ansible_inventory_path}\n"
        error_msg += f"Error: {str(e)}"
        raise ValueError(error_msg)

    if not ansible_data:
        raise ValueError("Ansible inventory file is empty or invalid")

    dut_configs = []
    node_type_configs = {}

    # Get cluster information from ansible data
    cluster_info = ansible_data.get("all", {}).get("vars", {})
    product_family = cluster_info.get("product_family", "")

    # Parse different node types
    node_mappings = [
        ("switch", "SwitchTray"),
        ("compute", "Compute"),
        ("powershelf", "PowerShelf"),
    ]

    for node_key, node_type in node_mappings:
        if node_key in ansible_data and "hosts" in ansible_data[node_key]:
            hosts = ansible_data[node_key]["hosts"]
            vars_section = ansible_data[node_key].get("vars", {})

            # Detect baseboard from ansible data if not provided
            detected_baseboard = _detect_baseboard_from_ansible_data(
                product_family, node_type, baseboard
            )

            # Create node type config
            node_type_config = {
                "platform": "unknown",  # Platform is no longer configurable
                "baseboard": detected_baseboard,
                "vars": vars_section,
            }
            node_type_configs[node_type] = node_type_config

            # Create DUT configs for each host
            for host_name, host_data in hosts.items():
                dut_config = _create_dut_config_from_ansible_host(
                    host_name, host_data, vars_section, node_type, detected_baseboard
                )
                dut_configs.append(dut_config)

    return dut_configs, node_type_configs


def _detect_baseboard_from_ansible_data(
    product_family: str, node_type: str, provided_baseboard: Optional[str] = None
) -> str:
    """
    Detect baseboard from ansible inventory data.

    Args:
        product_family: Product family from ansible inventory
        node_type: Node type (Compute, SwitchTray, PowerShelf)
        provided_baseboard: Baseboard provided via CLI parameter

    Returns:
        Detected baseboard name
    """
    # If baseboard is explicitly provided, use it
    if provided_baseboard:
        return provided_baseboard

    # Common baseboard mappings based on product family and node type
    baseboard_mappings = {
        # GB300 mappings
        ("gb300", "Compute"): "GB300 NVL",
        ("gb300", "SwitchTray"): "GB300 NVL",
        ("gb300", "PowerShelf"): "GB300 NVL",
        # GB200 mappings
        ("gb200", "Compute"): "GB200 NVL",
        ("gb200", "SwitchTray"): "GB200 NVL",
        ("gb200", "PowerShelf"): "GB200 NVL",
        # H100 mappings
        ("h100", "Compute"): "H100 HGX",
        ("h100", "SwitchTray"): "H100 HGX",
        ("h100", "PowerShelf"): "H100 HGX",
        # H200 mappings
        ("h200", "Compute"): "H200 HGX",
        ("h200", "SwitchTray"): "H200 HGX",
        ("h200", "PowerShelf"): "H200 HGX",
        # B200 mappings
        ("b200", "Compute"): "B200 HGX",
        ("b200", "SwitchTray"): "B200 HGX",
        ("b200", "PowerShelf"): "B200 HGX",
        # Generic mappings for common patterns
        ("nvl", "Compute"): "NVL",
        ("nvl", "SwitchTray"): "NVL",
        ("nvl", "PowerShelf"): "NVL",
        ("hgx", "Compute"): "HGX",
        ("hgx", "SwitchTray"): "HGX",
        ("hgx", "PowerShelf"): "HGX",
    }

    # Try to find a mapping based on product family and node type
    product_family_lower = product_family.lower()
    node_type_lower = node_type.lower()

    # Direct mapping
    if (product_family_lower, node_type_lower) in baseboard_mappings:
        return baseboard_mappings[(product_family_lower, node_type_lower)]

    # Try partial matches
    for (pf, nt), baseboard in baseboard_mappings.items():
        if pf in product_family_lower and nt in node_type_lower:
            return baseboard

    # Try to extract baseboard from product family
    if "gb300" in product_family_lower:
        return "GB300 NVL"
    elif "gb200" in product_family_lower:
        return "GB200 NVL"
    elif "h200" in product_family_lower:
        return "H200 HGX"
    elif "h100" in product_family_lower:
        return "H100 HGX"
    elif "b200" in product_family_lower:
        return "B200 HGX"
    elif "nvl" in product_family_lower:
        return "NVL"
    elif "hgx" in product_family_lower:
        return "HGX"

    # Default fallback - try to use product family as baseboard
    if product_family:
        return product_family.upper()

    # Final fallback
    return "Unknown"


def _create_dut_config_from_ansible_host(
    host_name: str,
    host_data: Dict[str, Any],
    vars_section: Dict[str, Any],
    node_type: str,
    baseboard: Optional[str] = None,
) -> DUTConfig:
    """
    Create a DUTConfig object from Ansible host data.

    Args:
        host_name: Name of the host
        host_data: Host-specific data from Ansible inventory
        vars_section: Variables section from Ansible inventory
        node_type: Type of node (Compute, SwitchTray, PowerShelf)
        baseboard: Optional baseboard type

    Returns:
        DUTConfig object
    """
    # Extract hostname from host data or use the key
    hostname = host_data.get("hostname", host_name)

    # Create DUTConfig with Ansible data
    dut_config = DUTConfig(
        name=hostname,
        baseboard=baseboard,
        # BMC Configuration
        bmc_ip=host_data.get("ansible_bmc_host", ""),
        bmc_user=vars_section.get("ansible_bmc_user", ""),
        bmc_pass=vars_section.get("ansible_bmc_pass", ""),
        bmc_ssh_user=vars_section.get("ansible_user", ""),
        bmc_ssh_pass=vars_section.get("ansible_ssh_pass", ""),
        # Host Configuration
        host_ip=host_data.get("ansible_host", ""),
        host_user=vars_section.get("ansible_user", ""),
        host_pass=vars_section.get("ansible_ssh_pass", ""),
        # Redfish Configuration (use BMC credentials as fallback)
        bmc_rf_user=vars_section.get("ansible_bmc_user", ""),
        bmc_rf_pass=vars_section.get("ansible_bmc_pass", ""),
        # Additional configuration
        local=False,  # Default to remote mode
        non_interactive=False,
    )

    return dut_config


def generate_config_files_from_ansible(
    ansible_inventory_path: Path,
    baseboard: Optional[str] = None,
) -> Tuple[Path, Path]:
    """
    Generate tool_config.yaml and dut_config.yaml files from Ansible inventory.

    Args:
        ansible_inventory_path: Path to the Ansible inventory file
        baseboard: Optional baseboard type

    Returns:
        Tuple of (config_file_path, dut_config_file_path)
    """
    # Parse ansible inventory
    dut_configs, node_type_configs = parse_ansible_inventory_to_dut_configs(
        ansible_inventory_path, baseboard
    )

    # Create temporary directory for generated files
    temp_dir = tempfile.mkdtemp(prefix="nvdebug_ansible_")

    # Get the detected baseboard from the first DUT config
    detected_baseboard = "Unknown"
    if dut_configs:
        detected_baseboard = dut_configs[0].baseboard or "Unknown"

    # Generate config.yaml
    config_data = {
        "PLATFORM": "unknown",  # Platform is no longer configurable
        "TargetBaseboard": detected_baseboard,
        "LogSanitization": True,
        "AUTO_PARSE": True,
        "GENERATE_HTML_REPORTS": True,
    }

    config_file_path = Path(temp_dir) / "config.yaml"
    with open(config_file_path, "w") as f:
        yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)

    # Generate dut_config.yaml
    dut_config_data = {}

    # Add DUT_Defaults if we have common variables
    if node_type_configs:
        # Use the first node type's vars as defaults
        first_node_type = list(node_type_configs.keys())[0]
        defaults = node_type_configs[first_node_type].get("vars", {})
        if defaults:
            dut_config_data["DUT_Defaults"] = defaults

    # Add each DUT
    for dut_config in dut_configs:
        dut_dict = {
            "NodeType": dut_config.name,
            "baseboard": dut_config.baseboard,
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
            "ConfigFileToUse": str(config_file_path),
            "ExecutionMode": "RemoteClient",
        }
        dut_config_data[dut_config.name] = dut_dict

    dut_config_file_path = Path(temp_dir) / "dut_config.yaml"
    with open(dut_config_file_path, "w") as f:
        yaml.dump(dut_config_data, f, default_flow_style=False, sort_keys=False)

    return config_file_path, dut_config_file_path


def cleanup_temp_config_files(
    config_file_path: Path, dut_config_file_path: Path
) -> None:
    """
    Clean up temporary configuration files generated from Ansible inventory.

    Args:
        config_file_path: Path to the temporary config file
        dut_config_file_path: Path to the temporary DUT config file
    """
    try:
        if config_file_path.exists():
            config_file_path.unlink()
        if dut_config_file_path.exists():
            dut_config_file_path.unlink()

        # Remove the parent directory if it's empty
        temp_dir = config_file_path.parent
        if temp_dir.exists() and not any(temp_dir.iterdir()):
            temp_dir.rmdir()
    except Exception as e:
        # Log warning but don't fail
        print(f"Warning: Could not clean up temporary config files: {e}")
