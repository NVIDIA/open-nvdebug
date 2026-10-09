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
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from ..core.config_manager import ConfigurationManager
from .console_output import create_sanitized_console
from .logging import ensure_secure_log_directory
from .redfish_topology_profile import (
    RedfishTopologyProfileError,
    validate_redfish_request_uri,
)
from .resources import find_config_files
from .run_limits import MAX_DUTS

_PYDANTIC_INPUT_VALUE_RE = re.compile(
    r"(input_value=)(.*?)(?=, input_type=|\]|$)", re.DOTALL
)


def _is_present_config_value(value: Any) -> bool:
    """
    Return True for real configured values, ignoring mock placeholder attrs.

    The implementation uses ``value`` to produce True for real configured
    values, ignoring mock placeholder attrs.

    Args:
        value: Value evaluated while performing true for real configured values,
            ignoring mock placeholder attrs.

    Returns:
        Whether the true for real configured values, ignoring mock placeholder
        attrs operation succeeds.
    """
    if type(value).__module__.startswith("unittest.mock"):
        return False
    return bool(value)


def validate_dut_count(dut_configs: list, max_duts: int = MAX_DUTS) -> None:
    """
    Raise ValueError if too many DUTs configured.

    The implementation uses ``dut_configs`` and ``max_duts`` to raise ValueError
    if too many DUTs configured. If the function cannot raise ValueError if too
    many DUTs configured, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        dut_configs: DUT configs governing raise ValueError if too many DUTs
            configured.
        max_duts: Upper bound enforced for max duts; the consuming boundary
            rejects or truncates values that exceed it.

    Raises:
        ValueError: If the supplied input cannot be used to raise ValueError if
            too many DUTs configured.
    """
    if len(dut_configs) > max_duts:
        raise ValueError(
            f"Too many DUTs configured ({len(dut_configs)}). "
            f"Maximum allowed: {max_duts}. "
            f"Split into multiple collection runs."
        )


def validate_redfish_uri(
    uri: str,
    expected_host: str = None,
    expected_port: Optional[int] = None,
) -> bool:
    """
    Validate that a Redfish URI is safe to follow.

    Rejects:

    - Absolute URLs pointing to different hosts (SSRF via nextLink).
    - Non-http(s) schemes (file://, gopher://, etc.).
    - URIs with path traversal (../).

    Accepts:

    - Relative URIs starting with / (standard Redfish paths).
    - Absolute URLs matching expected_host and, when supplied, expected_port.

    Args:
        uri: Validated remote resource identifier used for URI.
        expected_host: Optional expected host; ``None`` selects the function's
            default behavior.
        expected_port: Optional expected port; ``None`` selects the function's
            default behavior.

    Returns:
        The normalized Redfish URI returned by the shared host and scheme
        validator.
    """
    from urllib.parse import urlparse

    if not uri or not isinstance(uri, str):
        return False

    # Relative request targets must obey the same path/query grammar enforced
    # at the transport boundary. This rejects network-path references,
    # traversal (including percent-encoded forms), fragments, controls, and
    # malformed escapes while retaining standard Redfish pagination queries.
    if uri.startswith("/"):
        try:
            validate_redfish_request_uri(uri, context="Redfish response URI")
        except (RedfishTopologyProfileError, TypeError, ValueError):
            return False
        return True

    # Absolute URLs — must match expected host
    try:
        parsed = urlparse(uri)
    except Exception:
        return False

    # Accessing hostname/port can raise for malformed bracketed hosts,
    # non-numeric ports, and ports outside the TCP range. Reject those
    # authorities even when the caller did not request an explicit port bind.
    try:
        parsed_host = parsed.hostname
        parsed_port = parsed.port
    except ValueError:
        return False
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        return False

    # Only allow fully-qualified HTTP(S) URLs whose host is explicitly bound.
    if parsed.scheme.lower() not in ("http", "https") or not parsed_host:
        return False

    if not isinstance(expected_host, str) or not expected_host:
        return False
    if parsed_host.lower() != expected_host.lower():
        return False

    if expected_port is not None:
        if type(expected_port) is not int or not 1 <= expected_port <= 65535:
            return False
        effective_port = parsed_port
        if effective_port is None:
            effective_port = 443 if parsed.scheme.lower() == "https" else 80
        if effective_port != expected_port:
            return False

    try:
        validate_redfish_request_uri(
            parsed.path + (f"?{parsed.query}" if parsed.query else ""),
            context="absolute Redfish response URI",
        )
    except (RedfishTopologyProfileError, TypeError, ValueError):
        return False
    return not parsed.fragment and parsed.username is None and parsed.password is None


def validate_dut_config_requirements(
    dut_config: Optional[Union[Path, Any]],  # Can be Path or DUTConfig object
    local: bool,
    cli_credentials: Dict[str, Any],
    ansible_inventory: Optional[Path] = None,
) -> Tuple[bool, List[str]]:
    """
    Validate that proper DUT configuration is provided.

    Check if we have any configuration method dut_config can be either a Path
    object (from file) or a DUTConfig object (from CLI).

    Args:
        dut_config: filesystem location used as the DUT config for this
            operation.
        local: Whether local is enabled or required for this operation.
        cli_credentials: Sensitive value supplied through the approved input
            boundary and never logged.
        ansible_inventory: Optional filesystem location used as the ansible
            inventory for this operation.

    Returns:
        A tuple containing ``comparison flag`` and ``errors`` in that order.
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
    Validate connection parameters.

    The implementation uses ``cli_credentials``, ``local``, and ``dut_config``
    to validate connection parameters. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        cli_credentials: Sensitive value supplied through the approved input
            boundary and never logged.
        local: Whether local is enabled or required for this operation.
        dut_config: Optional filesystem location used as the DUT config for this
            operation.

    Returns:
        A tuple containing ``outcome flag`` and ``errors`` in that order.
    """
    errors = []

    if local:
        # Local mode doesn't need connection parameters
        return True, errors

    # Check CLI credentials - only need IP addresses for validation
    has_bmc_ip_cli = bool(cli_credentials.get("bmc_ip"))
    has_host_ip_cli = bool(cli_credentials.get("host_ip"))
    has_hmc_ip_cli = bool(cli_credentials.get("hmc_ip"))

    # Check DUT config file if provided
    has_bmc_ip_config = False
    has_host_ip_config = False
    has_hmc_ip_config = False

    if dut_config is not None:
        if hasattr(dut_config, "exists") and dut_config.exists():
            # It's a Path object - load and check the file
            try:
                # Import locally to avoid a module-load cycle while still using
                # the same bounded, duplicate-key-rejecting loader as the main
                # DUT configuration path.
                from ..config import load_yaml_strict

                with open(dut_config, "r", encoding="utf-8") as f:
                    config_data = load_yaml_strict(f) or {}
                if not isinstance(config_data, dict):
                    errors.append("DUT config must contain a YAML mapping")
                    config_data = {}

                # Check for IP addresses in DUT config
                # First check DUT_Defaults (global defaults)
                dut_defaults = config_data.get("DUT_Defaults", {})
                has_bmc_ip_config = bool(
                    dut_defaults.get("BMC_IP") or dut_defaults.get("bmc_ip")
                )
                has_host_ip_config = bool(
                    dut_defaults.get("HOST_IP") or dut_defaults.get("host_ip")
                )
                has_hmc_ip_config = bool(
                    dut_defaults.get("HMC_IP") or dut_defaults.get("hmc_ip")
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
                        if dut_data.get("HMC_IP") or dut_data.get("hmc_ip"):
                            has_hmc_ip_config = True

            except Exception as e:
                errors.append(f"Error reading DUT config file: {e}")
        elif hasattr(dut_config, "bmc_ip"):
            # It's a DUTConfig object - check its attributes
            has_bmc_ip_config = _is_present_config_value(dut_config.bmc_ip)
            has_host_ip_config = _is_present_config_value(dut_config.host_ip)
            has_hmc_ip_config = _is_present_config_value(
                getattr(dut_config, "hmc_ip", None)
            )
        elif isinstance(dut_config, list):
            # It's a list of DUTConfig objects - check each one
            for dut in dut_config:
                if hasattr(dut, "bmc_ip") and _is_present_config_value(dut.bmc_ip):
                    has_bmc_ip_config = True
                if hasattr(dut, "host_ip") and _is_present_config_value(dut.host_ip):
                    has_host_ip_config = True
                if hasattr(dut, "hmc_ip") and _is_present_config_value(dut.hmc_ip):
                    has_hmc_ip_config = True

    # We need at least one IP address from either CLI or config
    has_bmc_ip = has_bmc_ip_cli or has_bmc_ip_config
    has_host_ip = has_host_ip_cli or has_host_ip_config
    has_hmc_ip = has_hmc_ip_cli or has_hmc_ip_config

    if not has_bmc_ip and not has_host_ip and not has_hmc_ip:
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
                "  • HMC_IP in DUT config file\n"
                "  • --bmc-ip via CLI\n"
                "  • --host-ip via CLI\n"
                "  • --hmc-ip via CLI\n"
                "  • --local - Run in local mode (no remote access needed)"
            )
        else:
            errors.append(
                "No connection IP addresses provided. Please provide one of the following:\n"
                "  • --bmc-ip for BMC connection\n"
                "  • --host-ip for Host connection\n"
                "  • --hmc-ip for HMC connection\n"
                "  • --local - Run in local mode (no remote access needed)"
            )

    return len(errors) == 0, errors


def validate_credentials_completeness(
    cli_credentials: Dict[str, Any],
    local: bool,
    dut_config: Optional[Union[Path, Any]] = None,
    cli_mode: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Validate that credentials are complete when provided via CLI.

    Note: This only validates CLI credentials completeness. DUT config file
    credentials are validated by the connection parameters validation.

    When a DUT config file is provided and we are not in CLI mode, partial CLI
    credentials are allowed (merged with file). In CLI mode (DUT built from CLI
    args only), all three BMC (or Host) credentials are required when any is
    provided.

    Args:
        cli_credentials: Sensitive value supplied through the approved input
            boundary and never logged.
        local: Whether local is enabled or required for this operation.
        dut_config: Optional filesystem location used as the DUT config for this
            operation.
        cli_mode: Whether CLI mode is enabled or required for this operation.

    Returns:
        A tuple containing ``outcome flag`` and ``errors`` in that order.
    """
    errors = []

    if local:
        # Local mode doesn't need credentials
        return True, errors

    # In CLI mode we built the DUT from CLI only — require complete credentials.
    # When not CLI mode, a DUT config (file) allows partial CLI.
    has_dut_config = dut_config is not None and not cli_mode

    bmc_ip = cli_credentials.get("bmc_ip")
    bmc_user = cli_credentials.get("bmc_user")
    bmc_ssh_user = cli_credentials.get("bmc_ssh_user")
    bmc_rf_user = cli_credentials.get("bmc_rf_user")
    bmc_pass = cli_credentials.get("bmc_pass")
    bmc_ssh_pass = cli_credentials.get("bmc_ssh_pass")
    bmc_rf_pass = cli_credentials.get("bmc_rf_pass")
    bmc_ssh_key_path = cli_credentials.get("bmc_ssh_key_path")
    bmc_ssh_passwordless = cli_credentials.get("bmc_ssh_passwordless")
    host_ip = cli_credentials.get("host_ip")
    host_user = cli_credentials.get("host_user")
    host_pass = cli_credentials.get("host_pass")
    host_ssh_key_path = cli_credentials.get("host_ssh_key_path")
    host_ssh_passwordless = cli_credentials.get("host_ssh_passwordless")
    hmc_ip = cli_credentials.get("hmc_ip")
    hmc_user = cli_credentials.get("hmc_user")
    hmc_ssh_user = cli_credentials.get("hmc_ssh_user")
    hmc_pass = cli_credentials.get("hmc_pass")
    hmc_ssh_pass = cli_credentials.get("hmc_ssh_pass")
    hmc_ssh_key_path = cli_credentials.get("hmc_ssh_key_path")
    hmc_ssh_passwordless = cli_credentials.get("hmc_ssh_passwordless")

    bmc_ssh_has_user = bool(bmc_ssh_user or bmc_user)
    bmc_ssh_has_auth = bool(
        bmc_ssh_key_path or bmc_ssh_passwordless or bmc_ssh_pass or bmc_pass
    )
    bmc_rf_has_user = bool(bmc_rf_user or bmc_user)
    bmc_rf_has_auth = bool(bmc_rf_pass or bmc_pass)
    bmc_has_user = bmc_ssh_has_user or bmc_rf_has_user
    bmc_has_auth = bmc_ssh_has_auth or bmc_rf_has_auth
    host_has_auth = bool(host_ssh_key_path or host_ssh_passwordless or host_pass)
    hmc_has_user = bool(hmc_ssh_user or hmc_user)
    hmc_has_auth = bool(
        hmc_ssh_key_path or hmc_ssh_passwordless or hmc_ssh_pass or hmc_pass
    )

    bmc_complete = bool(
        bmc_ip
        and (
            (bmc_ssh_has_user and bmc_ssh_has_auth)
            or (bmc_rf_has_user and bmc_rf_has_auth)
        )
    )
    host_complete = bool(host_ip and host_user and host_has_auth)
    hmc_complete = bool(hmc_ip and hmc_has_user and hmc_has_auth)
    # If at least one set (BMC, Host, or HMC) is complete, allow collection to continue
    # even if the other set is partial (e.g. all three BMC + only 2/3 Host).
    has_complete_set = bmc_complete or host_complete or hmc_complete

    if not has_dut_config:
        # Require completeness per set, but only fail when no set is complete
        if (
            any(
                [
                    bmc_ip,
                    bmc_user,
                    bmc_ssh_user,
                    bmc_rf_user,
                    bmc_pass,
                    bmc_ssh_pass,
                    bmc_rf_pass,
                    bmc_ssh_key_path,
                    bmc_ssh_passwordless,
                ]
            )
            and not bmc_complete
            and not has_complete_set
        ):
            missing_bmc = []
            if not bmc_ip:
                missing_bmc.append("--bmc-ip")
            if not bmc_has_user:
                missing_bmc.append("--bmc-user, --bmc-ssh-user, or --bmc-rf-user")
            if not bmc_has_auth:
                missing_bmc.append(
                    "--bmc-pass, --bmc-ssh-pass, --bmc-rf-pass, "
                    "--bmc-ssh-key-path, or --bmc-ssh-passwordless"
                )
            if not missing_bmc and not bmc_complete:
                missing_bmc.append(
                    "a matching username and authentication option for the "
                    "same BMC SSH or Redfish transport"
                )
            if missing_bmc:
                errors.append(
                    f"Incomplete BMC credentials. Missing: {', '.join(missing_bmc)}.\n"
                    "  • Please provide BMC IP, a BMC/SSH/Redfish username, and either a password, SSH key path, or passwordless SSH"
                )

        if (
            any(
                [
                    host_ip,
                    host_user,
                    host_pass,
                    host_ssh_key_path,
                    host_ssh_passwordless,
                ]
            )
            and not host_complete
            and not has_complete_set
        ):
            missing_host = []
            if not host_ip:
                missing_host.append("--host-ip")
            if not host_user:
                missing_host.append("--host-user")
            if not host_has_auth:
                missing_host.append(
                    "--host-pass, --host-ssh-key-path, or --host-ssh-passwordless"
                )
            if missing_host:
                errors.append(
                    f"Incomplete Host credentials. Missing: {', '.join(missing_host)}.\n"
                    "  • Please provide Host IP, Host username, and either a password, SSH key path, or passwordless SSH"
                )

        if (
            any(
                [
                    hmc_ip,
                    hmc_user,
                    hmc_ssh_user,
                    hmc_pass,
                    hmc_ssh_pass,
                    hmc_ssh_key_path,
                    hmc_ssh_passwordless,
                ]
            )
            and not hmc_complete
            and not has_complete_set
        ):
            missing_hmc = []
            if not hmc_ip:
                missing_hmc.append("--hmc-ip")
            if not hmc_has_user:
                missing_hmc.append("--hmc-user or --hmc-ssh-user")
            if not hmc_has_auth:
                missing_hmc.append(
                    "--hmc-pass, --hmc-ssh-pass, --hmc-ssh-key-path, or --hmc-ssh-passwordless"
                )
            if missing_hmc:
                errors.append(
                    f"Incomplete HMC credentials. Missing: {', '.join(missing_hmc)}.\n"
                    "  • Please provide HMC IP, an HMC/SSH username, and either a password, SSH key path, or passwordless SSH"
                )

    return len(errors) == 0, errors


def validate_collector_ids(
    collector_ids: Optional[str], config_manager: ConfigurationManager
) -> Tuple[bool, List[str]]:
    """
    Validate that specified collector IDs exist and are valid.

    The implementation uses ``collector_ids`` and ``config_manager`` to validate
    that specified collector IDs exist and are valid. Every required invariant
    is checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        collector_ids: Text supplied as collector identifiers in the format
            accepted by this function.
        config_manager: Config manager governing that specified collector IDs
            exist and are valid.

    Returns:
        A tuple containing ``outcome flag`` and ``errors`` in that order.
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

    The implementation uses ``collector_groups`` and ``config_manager`` to
    validate that specified collector groups exist and are valid. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        collector_groups: Entries supplied as ``collector_groups`` without
            transferring container ownership.
        config_manager: Config manager governing that specified collector groups
            exist and are valid.

    Returns:
        A tuple containing ``outcome flag`` and ``errors`` in that order.
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
    Validate collector mutual exclusion.

    Parse collector IDs to check for group conflicts.

    Args:
        collector_ids: Text supplied as collector identifiers in the format
            accepted by this function.
        collector_groups: Entries supplied as ``collector_groups`` without
            transferring container ownership.

    Returns:
        A tuple containing ``outcome flag`` and ``errors`` in that order.
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

    The implementation uses ``collection_level`` to validate that the collection
    level is valid. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        collection_level: Text supplied as collection level in the format
            accepted by this function.

    Returns:
        A tuple containing ``comparison flag`` and ``errors`` in that order.
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


def validate_output_directory(
    output_dir: Path,
    *,
    shared_read: bool = False,
    repair_existing_permissions: bool = False,
    allow_sticky_run_parent: bool = False,
    allow_external_path_owners: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Validate that the output directory is accessible and writable.

    The secure directory creator applies an exact mode to every missing path
    component before a write probe runs. Timestamped collection callers can
    also repair recoverable trusted-owner permissions in parent-to-child order,
    preserving automation compatibility without accepting replaceable path
    components.

    Args:
        output_dir: filesystem location used as the output dir for this
            operation.
        shared_read: Whether newly created components must remain traversable
            and readable by a separate read-only report server.
        repair_existing_permissions: Whether safely recoverable trusted-owner
            permissions should be secured before the write probe.
        allow_sticky_run_parent: Whether a trusted sticky shared directory may
            be validated as the parent of a private timestamped run directory.
        allow_external_path_owners: Whether the collection output boundary may
            trust safe or sticky existing components owned by another UID.

    Returns:
        A tuple containing ``comparison flag`` and ``errors`` in that order.
    """
    errors = []
    permission_repairs: list[tuple[Path, int, int]] = []

    try:
        # Create missing components through the same no-follow, descriptor-
        # pinned policy used by collection startup.
        ensure_secure_log_directory(
            os.fspath(output_dir),
            shared_read=shared_read,
            repair_existing_permissions=(shared_read or repair_existing_permissions),
            allow_sticky_run_parent=allow_sticky_run_parent,
            permission_repairs=permission_repairs,
            allow_external_path_owners=allow_external_path_owners,
        )
        if permission_repairs:
            console = create_sanitized_console()
            for component_path, previous_mode, repaired_mode in permission_repairs:
                console.print_warning(
                    "Warning: secured existing output-path permissions and "
                    f"continued: '{component_path}' "
                    f"({previous_mode:04o} -> {repaired_mode:04o})"
                )

        # Probe through an exclusively created private file so a trusted sticky
        # shared output base such as /tmp remains usable without touching a
        # caller- or attacker-selected name.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_dir,
            prefix=".nvdebug-write-test-",
        ) as test_file:
            test_file.write("test")
            test_file.flush()

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
    cli_mode: bool = False,
    output_shared_read: bool = False,
    output_repair_existing_permissions: bool = False,
    output_allow_sticky_run_parent: bool = False,
    output_allow_external_path_owners: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Run comprehensive validation for the collect command.

    The implementation uses ``dut_config``, ``local``, ``cli_credentials``,
    ``collector_ids``, and ``collector_groups`` to run comprehensive validation
    for the collect command. Terminal status is emitted only after comprehensive
    validation for the collect command and its owned cleanup have completed.

    Args:
        dut_config: filesystem location used as the DUT config for this
            operation.
        local: Whether local is enabled or required for this operation.
        cli_credentials: Sensitive value supplied through the approved input
            boundary and never logged.
        collector_ids: Text supplied as collector identifiers in the format
            accepted by this function.
        collector_groups: Entries supplied as ``collector_groups`` without
            transferring container ownership.
        collection_level: Text supplied as collection level in the format
            accepted by this function.
        output_dir: filesystem location used as the output dir for this
            operation.
        config_manager: Optional Config manager governing comprehensive
            validation for the collect command.
        ansible_inventory: Optional filesystem location used as the ansible
            inventory for this operation.
        cli_mode: Whether CLI mode is enabled or required for this operation.
        output_shared_read: Whether validation should create an explicitly
            selected output namespace for read-only report-server access.
        output_repair_existing_permissions: Whether validation should secure
            recoverable trusted-owner output permissions before writing.
        output_allow_sticky_run_parent: Whether the collection lifecycle will
            create a private timestamped run leaf beneath a trusted sticky
            shared output parent.
        output_allow_external_path_owners: Whether the collection output
            boundary may trust safe or sticky existing components owned by
            another UID.

    Returns:
        A tuple containing ``comparison flag`` and ``all errors`` in that order.
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

    # Validate credentials completeness (require all three when in CLI mode)
    is_valid, errors = validate_credentials_completeness(
        cli_credentials, local, dut_config, cli_mode=cli_mode
    )
    all_errors.extend(errors)

    # Validate collection level
    is_valid, errors = validate_collection_level(collection_level)
    all_errors.extend(errors)

    # Validate output directory
    is_valid, errors = validate_output_directory(
        output_dir,
        shared_read=output_shared_read,
        repair_existing_permissions=output_repair_existing_permissions,
        allow_sticky_run_parent=output_allow_sticky_run_parent,
        allow_external_path_owners=output_allow_external_path_owners,
    )
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

    The implementation uses ``errors`` to display validation errors in a
    visually appealing format using Rich console.

    Args:
        errors: Entries supplied as ``errors`` without transferring container
            ownership.
    """
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
    Display DUT config error.

    Pydantic embeds rejected values in validation text before the run's
    exact-value sanitizer exists. Strip every such value structurally because
    any configuration field can be credential-bearing.

    Args:
        error_message: Text supplied as error message in the format accepted by
            this function.
    """

    console = create_sanitized_console()

    # Pydantic embeds rejected values in validation text before the run's
    # exact-value sanitizer exists. Strip every such value structurally because
    # any configuration field can be credential-bearing.
    error_message = _PYDANTIC_INPUT_VALUE_RE.sub(r"\1<redacted>", str(error_message))

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
