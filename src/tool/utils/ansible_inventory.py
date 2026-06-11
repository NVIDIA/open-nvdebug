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

import json
import os
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from rich.console import Console

from . import excel_reader
from rich.panel import Panel
from rich.table import Table

from ..config import DUTConfig
from .spreadsheet_utils import auto_detect_spreadsheet


@lru_cache(maxsize=1)
def _load_ansible_baseboard_mappings() -> List[Dict[str, Any]]:
    """
    Load ansible baseboard mappings from the Telemetry Catalog spreadsheet.

    Returns:
        List of mapping dictionaries containing product_family, node_type, baseboard.
    """

    spreadsheet = auto_detect_spreadsheet(None, suppress_print=True)
    if not spreadsheet:
        return []

    spreadsheet_path = Path(spreadsheet)
    if not spreadsheet_path.exists():
        return []

    try:
        df = excel_reader.read_excel(spreadsheet_path, sheet_name="Log Collection Configuration")
    except Exception:
        return []

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
            raw_entries = json.loads(value)
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
    except FileNotFoundError as e:
        _display_yaml_error(ansible_inventory_path, str(e), "YAML parsing failed")
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

    # Parse inventory groups into canonical node types while supporting
    # ansible aliases such as "singlenode" for compute inventories.
    group_order = {"SwitchTray": 0, "Compute": 1, "PowerShelf": 2}
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

        node_type = _resolve_ansible_node_type(group_name, vars_section)
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
            product_family, node_type, baseboard
        )

        existing_node_config = node_type_configs.get(node_type, {})
        merged_vars = {
            **existing_node_config.get("vars", {}),
            **vars_section,
        }
        node_type_configs[node_type] = {
            "platform": "unknown",  # Platform is no longer configurable
            "baseboard": detected_baseboard,
            "vars": merged_vars,
        }

        # Create DUT configs for each host
        for host_name, host_data in hosts.items():
            dut_config = _create_dut_config_from_ansible_host(
                host_name, host_data, vars_section, node_type, detected_baseboard
            )
            dut_configs.append(dut_config)

    return dut_configs, node_type_configs


def _resolve_ansible_node_type(
    group_name: str, vars_section: Dict[str, Any]
) -> Optional[str]:
    """
    Resolve ansible inventory groups to the tool's canonical node types.

    Group aliases such as "singlenode" are treated as Compute so they flow
    through the same parsing path as standard compute groups.
    """

    normalized_mapping = {
        "switch": "SwitchTray",
        "switchtray": "SwitchTray",
        "compute": "Compute",
        "singlenode": "Compute",
        "powershelf": "PowerShelf",
    }

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

    product_family_lower = product_family.lower() if product_family else ""
    node_type_lower = node_type.lower()

    mappings = _load_ansible_baseboard_mappings()
    best_match: Optional[str] = None
    best_score: Tuple[int, int] = (-1, -1)

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

        # Prioritize exact matches over substring matches
        # Score: (pf_score, node_score) where pf_score: 2=exact, 1=contains
        pf_score = 2 if pf_exact else 1
        score = (pf_score, node_score)
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

    # Prefer common bmc ip keys in order of specificity
    bmc_ip = (
        host_data.get("ansible_bmc_host")
        or host_data.get("bmc_host")
        or vars_section.get("ansible_bmc_host")
        or vars_section.get("bmc_host")
        or ""
    )

    # BMC credentials: prefer explicit BMC creds, fall back to generic ansible creds
    bmc_user = (
        host_data.get("bmc_user")
        or vars_section.get("ansible_bmc_user")
        or vars_section.get("bmc_user")
        or vars_section.get("bmc_username")
        or vars_section.get("ansible_user")
        or ""
    )
    bmc_pass = (
        host_data.get("bmc_pass")
        or vars_section.get("ansible_bmc_pass")
        or vars_section.get("bmc_pass")
        or vars_section.get("bmc_password")
        or vars_section.get("ansible_bmc_password")
        or vars_section.get("ansible_ssh_pass")
        or ""
    )

    # BMC SSH creds: prefer BMC creds, fall back to host creds
    bmc_ssh_user = (
        vars_section.get("ansible_bmc_user")
        or vars_section.get("bmc_user")
        or vars_section.get("bmc_username")
        or vars_section.get("ansible_user")
        or bmc_user
        or ""
    )
    bmc_ssh_pass = (
        vars_section.get("ansible_bmc_pass")
        or vars_section.get("bmc_pass")
        or vars_section.get("bmc_password")
        or vars_section.get("ansible_bmc_password")
        or vars_section.get("ansible_ssh_pass")
        or bmc_pass
        or ""
    )
    bmc_ssh_key_path = (
        vars_section.get("ansible_bmc_ssh_private_key_file")
        or vars_section.get("ansible_bmc_ssh_key_path")
        or vars_section.get("bmc_ssh_key_path")
        or vars_section.get("BMC_SSH_KEY_PATH")
        or ""
    )
    host_ssh_key_path = (
        vars_section.get("ansible_ssh_private_key_file")
        or vars_section.get("host_ssh_key_path")
        or vars_section.get("HOST_SSH_KEY_PATH")
        or ""
    )

    # Redfish creds: default to BMC creds if not explicitly provided
    rf_user = (
        vars_section.get("ansible_bmc_user")
        or vars_section.get("bmc_user")
        or vars_section.get("bmc_username")
        or vars_section.get("RF_User")
        or bmc_user
        or ""
    )
    rf_pass = (
        vars_section.get("ansible_bmc_pass")
        or vars_section.get("bmc_pass")
        or vars_section.get("bmc_password")
        or vars_section.get("RF_Pass")
        or bmc_pass
        or ""
    )

    # Create DUTConfig with Ansible data
    dut_config = DUTConfig(
        name=hostname,
        baseboard=baseboard,
        # BMC Configuration
        bmc_ip=bmc_ip,
        bmc_user=bmc_user,
        bmc_pass=bmc_pass,
        bmc_ssh_user=bmc_ssh_user,
        bmc_ssh_pass=bmc_ssh_pass,
        bmc_ssh_key_path=bmc_ssh_key_path,
        # Host Configuration
        host_ip=host_data.get("ansible_host", ""),
        host_user=vars_section.get("ansible_user", ""),
        host_pass=vars_section.get("ansible_ssh_pass", ""),
        host_ssh_key_path=host_ssh_key_path,
        # Redfish Configuration (use BMC credentials as fallback)
        bmc_rf_user=rf_user,
        bmc_rf_pass=rf_pass,
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
        # Ensure SSH collectors are not skipped by default for ansible-generated configs
        "SKIP_BMC_SSH_LOGS": False,
    }

    config_file_path = Path(temp_dir) / "config.yaml"
    fd = os.open(str(config_file_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
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
    fd = os.open(
        str(dut_config_file_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
    )
    with os.fdopen(fd, "w") as f:
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
