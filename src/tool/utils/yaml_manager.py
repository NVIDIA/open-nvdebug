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
YAML Manager for NVDebug Tool.

Provides comprehensive YAML loading, validation, and error handling with
support for schema validation and detailed error reporting.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

logger = logging.getLogger(__name__)


class YAMLManager:
    """
    Comprehensive YAML manager for loading, validating, and handling YAML files.

    Provides static methods for loading, validating, saving, and managing YAML
    configuration files with detailed error handling and reporting.
    """

    @staticmethod
    def load_yaml(
        file_path: Union[str, Path], context: str = "YAML file"
    ) -> Dict[str, Any]:
        """
        Load YAML file with comprehensive error handling

        Args:
            file_path: Path to YAML file
            context: Context for error messages (e.g., "DUT config", "Tool config")

        Returns:
            Loaded YAML data as dictionary

        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file can't be read
            ValueError: If YAML is invalid
        """
        file_path = Path(file_path)

        # Check if file exists
        if not file_path.exists():
            raise FileNotFoundError(f"{context} not found: {file_path}")

        # Check file permissions
        if not file_path.is_file():
            raise ValueError(f"{context} is not a file: {file_path}")

        if not file_path.stat().st_size > 0:
            raise ValueError(f"{context} is empty: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if data is None:
                raise ValueError(
                    f"{context} is empty or contains only comments: {file_path}"
                )

            return data

        except yaml.YAMLError as e:
            error_msg = YAMLManager._format_yaml_error(e)
            raise ValueError(f"Invalid YAML in {context}: {error_msg}")
        except PermissionError:
            raise PermissionError(f"Permission denied reading {context}: {file_path}")
        except UnicodeDecodeError as e:
            raise ValueError(f"Encoding error in {context}: {e}")
        except Exception as e:
            raise ValueError(f"Error reading {context}: {e}")

    @staticmethod
    def save_yaml(
        data: Dict[str, Any],
        file_path: Union[str, Path],
        context: str = "YAML file",
    ) -> None:
        """
        Save data to YAML file with error handling

        Args:
            data: Data to save
            file_path: Path to save to
            context: Context for error messages

        Raises:
            ValueError: If save fails
        """
        file_path = Path(file_path)

        try:
            # Ensure directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, "w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        except Exception as e:
            raise ValueError(f"Error saving {context}: {e}")

    @staticmethod
    def validate_dut_config(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate DUT configuration structure

        Args:
            data: Loaded YAML data

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []

        if not isinstance(data, dict):
            issues.append("Root element must be a YAML mapping (dictionary)")
            return False, issues

        if not data:
            issues.append("DUT configuration file is empty")
            return False, issues

        # Check for DUT_Defaults (optional but recommended)
        if "DUT_Defaults" not in data:
            issues.append("No DUT_Defaults section found (optional but recommended)")

        # Check for actual DUTs (handle both CLI format and regular format)
        duts = []
        if "duts" in data:
            # CLI format: {"duts": {"cli-dut": {...}}}
            duts = [k for k in data["duts"].keys() if k != "DUT_Defaults"]
        else:
            # Regular format: {"dut-1": {...}, "dut-2": {...}}
            duts = [k for k in data.keys() if k != "DUT_Defaults"]

        if not duts:
            issues.append("No DUT configurations found. Add at least one DUT entry.")
            return False, issues

        # Validate each DUT configuration
        dut_configs = data.get(
            "duts", data
        )  # Handle both CLI format and regular format

        for dut_id, dut_config in dut_configs.items():
            if dut_id == "DUT_Defaults":
                continue

            if not isinstance(dut_config, dict):
                issues.append(
                    f"DUT '{dut_id}' configuration must be a mapping, not {type(dut_config).__name__}"
                )
                continue

            # Check that at least one access method is provided (BMC_IP, HOST_IP, or local mode)
            bmc_ip = dut_config.get("BMC_IP")
            host_ip = dut_config.get("HOST_IP")
            execution_mode = dut_config.get("ExecutionMode", "remote").lower()

            if not bmc_ip and not host_ip and execution_mode != "local":
                issues.append(
                    f"DUT '{dut_id}' must have at least one access method: BMC_IP, HOST_IP, or ExecutionMode: local"
                )

            # Check for recommended fields (optional but recommended)
            recommended_fields = []
            if bmc_ip and not host_ip:
                recommended_fields.append(
                    "HOST_IP"
                )  # Recommend host access if only BMC is provided
            elif host_ip and not bmc_ip:
                recommended_fields.append(
                    "BMC_IP"
                )  # Recommend BMC access if only host is provided

            missing_recommended = [
                field for field in recommended_fields if not dut_config.get(field)
            ]

            if missing_recommended:
                issues.append(
                    f"DUT '{dut_id}' is missing recommended fields: {missing_recommended}"
                )

        return len(issues) == 0, issues

    @staticmethod
    def validate_tool_config(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate tool configuration structure

        Args:
            data: Loaded YAML data

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []

        if not isinstance(data, dict):
            issues.append("Root element must be a YAML mapping (dictionary)")
            return False, issues

        if not data:
            issues.append("Tool configuration file is empty")
            return False, issues

        # Check for required sections
        required_sections = ["execution_config", "collector_definitions"]
        for section in required_sections:
            if section not in data:
                issues.append(f"Missing required section: {section}")

        return len(issues) == 0, issues

    @staticmethod
    def convert_legacy_dut_format(
        dut_config_data: Dict[str, Any],
        default_baseboard: str = "Blackwell-HGX-8-GPU",
    ) -> Dict[str, Any]:
        """
        Convert older format to current format

        Older format:
        - Baseboard is stored in config.yaml as 'TargetBaseboard'
        - DUT config only contains connection details

        New format:
        - Baseboard is stored in DUT config as 'baseboard'
        - All DUT-specific settings are in the DUT config
        """
        # Check if this is legacy format (no baseboard in DUT config)
        is_legacy_format = True
        for dut_id, dut_config in dut_config_data.items():
            if dut_id == "DUT_Defaults":
                continue
            if (
                "baseboard" in dut_config
                or "Baseboard" in dut_config
                or "TargetBaseboard" in dut_config
            ):
                is_legacy_format = False
                break

        if not is_legacy_format:
            # Already in new format, return as-is
            return dut_config_data

        # Convert each DUT to new format
        converted_config = {}
        for dut_id, dut_config in dut_config_data.items():
            if dut_id == "DUT_Defaults":
                converted_config[dut_id] = dut_config
                continue

            # Create new format DUT config
            new_dut_config = {
                "baseboard": default_baseboard,  # Will be overridden by config file
                # BMC Configuration
                "BMC_IP": dut_config.get("BMC_IP"),
                "BMC_USERNAME": dut_config.get("BMC_USERNAME"),
                "BMC_PASSWORD": dut_config.get("BMC_PASSWORD"),
                "BMC_SSH_USERNAME": dut_config.get("BMC_SSH_USERNAME"),
                "BMC_SSH_PASSWORD": dut_config.get("BMC_SSH_PASSWORD"),
                "BMC_SSH_PORT": dut_config.get("BMC_SSH_PORT", 22),
                "BMC_SSH_KEY_PATH": dut_config.get("BMC_SSH_KEY_PATH"),
                "BMC_RF_PORT": dut_config.get("BMC_RF_PORT", 443),
                "BMC_SSH_PASSWORDLESS": dut_config.get("BMC_SSH_PASSWORDLESS", False),
                # Redfish Configuration
                "RF_User": dut_config.get("RF_User"),
                "RF_Pass": dut_config.get("RF_Pass"),
                "RF_DEFAULT_PREFIX": dut_config.get("RF_DEFAULT_PREFIX", "/redfish/v1"),
                "RF_AUTH": dut_config.get("RF_AUTH", True),
                # Host Configuration
                "HOST_IP": dut_config.get("HOST_IP"),
                "HOST_USERNAME": dut_config.get("HOST_USERNAME"),
                "HOST_PASSWORD": dut_config.get("HOST_PASSWORD"),
                "HOST_SSH_PORT": dut_config.get("HOST_SSH_PORT", 22),
                "HOST_SSH_PASSWORDLESS": dut_config.get("HOST_SSH_PASSWORDLESS", False),
                # Network Configuration
                "IP_NETWORK": dut_config.get("IP_NETWORK", "ipv4"),
                # Execution Configuration
                "ExecutionMode": dut_config.get("ExecutionMode", "REMOTE"),
                "SETUP_PORT_FORWARDING": dut_config.get("SETUP_PORT_FORWARDING", False),
                "FORCE_PORT_FW": dut_config.get("FORCE_PORT_FW", False),
                "TUNNEL_TCP_PORT": dut_config.get("TUNNEL_TCP_PORT"),
                # SSH tunnel configuration
                "TUNNEL_LOCAL_HOST": dut_config.get("TUNNEL_LOCAL_HOST", "localhost"),
                "SSH_TUNNEL_OPTIONS": dut_config.get(
                    "SSH_TUNNEL_OPTIONS",
                    "-4 -o StrictHostKeyChecking=no -o LogLevel=ERROR -fNT",
                ),
                "SSH_TUNNEL_PREFIX": dut_config.get("SSH_TUNNEL_PREFIX", "sshpass -p"),
                # Other Configuration
                "NodeType": dut_config.get("NodeType", "Compute"),
                "auto_parse": dut_config.get("auto_parse", True),
                "collection_level": dut_config.get("collection_level", "L1"),
                "ipmi_cipher": dut_config.get("ipmi_cipher", "-C17"),
                "log_sanitization": dut_config.get("log_sanitization", True),
            }

            converted_config[dut_id] = new_dut_config

        return converted_config

    @staticmethod
    def _format_yaml_error(yaml_error: yaml.YAMLError) -> str:
        """
        Format YAML error messages to be more user-friendly.

        Args:
            yaml_error: YAML error to format.

        Returns:
            User-friendly error message with helpful guidance.
        """
        error_str = str(yaml_error)

        # Common YAML error patterns and their user-friendly explanations
        error_patterns = {
            "found duplicate anchor": "Duplicate anchor definition found. Each anchor (&name) must be unique.",
            "found unconstructable recursive node": "Circular reference detected. An anchor is referencing itself.",
            "found undefined alias": "Undefined alias reference. Make sure all aliases (*name) have corresponding anchors (&name).",
            "found multiple documents": "Multiple YAML documents detected. Please use a single document.",
            "found unknown tag": "Unknown YAML tag found. Please use standard YAML syntax.",
            "found duplicate key": "Duplicate key found in YAML mapping.",
            "found tab character": "Tab characters are not allowed in YAML. Use spaces for indentation.",
            "found invalid escape sequence": "Invalid escape sequence in string value.",
            "found invalid line break": "Invalid line break in string value.",
            "found invalid character": "Invalid character in YAML content.",
            "found unexpected end of stream": "Unexpected end of file. This usually means a quote, bracket, or brace is not properly closed.",
            "while scanning a quoted scalar": "Quote mismatch detected. Check that all quoted strings are properly closed.",
            "mapping values are not allowed here": "YAML structure error. This usually indicates indentation problems or missing colons after keys.",
            "expected '<document start>'": "Missing YAML document start marker. Add '---' as the first line of the file.",
            "while parsing a block mapping": "YAML structure/indentation problem. Check for correct indentation and proper key-value syntax.",
        }

        # Check for specific error patterns and provide helpful messages
        for pattern, explanation in error_patterns.items():
            if pattern in error_str.lower():
                return f"{explanation}\n\nTechnical details: {error_str}"

        # For anchor/alias specific errors, provide additional guidance
        if "anchor" in error_str.lower() or "alias" in error_str.lower():
            return (
                f"YAML anchor/alias error: {error_str}\n\nCommon fixes:\n"
                f"- Ensure each anchor (&name) is defined only once\n"
                f"- Check that aliases (*name) reference existing anchors\n"
                f"- Avoid circular references (anchor referencing itself)\n"
                f"- Use proper merge syntax: <<: *anchor_name"
            )

        # For quote mismatch errors, provide specific guidance
        if (
            "while scanning a quoted scalar" in error_str.lower()
            and "found unexpected end of stream" in error_str.lower()
        ):
            return (
                f"Quote mismatch error: {error_str}\n\nThis error occurs when a quoted string is not properly closed.\n"
                f"Common fixes:\n"
                f"- Check that all single quotes (') and double quotes (\") are properly paired\n"
                f"- Ensure quoted strings don't span multiple lines without proper escaping\n"
                f"- Look for missing closing quotes at the end of string values\n"
                f"- Example: 'HGX_I2CTRANSFER_WRITE_TO_ADDRESS: \"0x11\"' (note the closing quote)"
            )

        return f"YAML parsing error: {error_str}"

    @staticmethod
    def get_dut_count(data: Dict[str, Any]) -> int:
        """
        Get the number of DUTs in the configuration.

        Args:
            data: Configuration data.

        Returns:
            Number of DUTs (excluding DUT_Defaults).
        """
        if not isinstance(data, dict):
            return 0
        return len([k for k in data.keys() if k != "DUT_Defaults"])

    @staticmethod
    def get_dut_names(data: Dict[str, Any]) -> List[str]:
        """
        Get the names of all DUTs in the configuration.

        Args:
            data: Configuration data.

        Returns:
            List of DUT names (excluding DUT_Defaults).
        """
        if not isinstance(data, dict):
            return []
        return [k for k in data.keys() if k != "DUT_Defaults"]

    @staticmethod
    def has_dut_defaults(data: Dict[str, Any]) -> bool:
        """
        Check if the configuration has DUT_Defaults section.

        Args:
            data: Configuration data.

        Returns:
            True if DUT_Defaults section exists, False otherwise.
        """
        return isinstance(data, dict) and "DUT_Defaults" in data
