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

Provides comprehensive YAML loading, validation, and error handling with support
for schema validation and detailed error reporting.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

from .ssh_security import (
    DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS,
    DEFAULT_SSH_TUNNEL_PREFIX,
    infer_legacy_ssh_host_key_policy,
    infer_legacy_ssh_known_hosts_file,
    normalize_ssh_tunnel_prefix,
)

logger = logging.getLogger(__name__)

MAX_CONFIG_FILE_SIZE_MB = 8  # Keep every config path within the strict-loader cap.


class YAMLManager:
    """
    Comprehensive YAML manager for loading, validating, and handling YAML files.

    Provides static methods for loading, validating, saving, and managing YAML
    configuration files with detailed error handling and reporting.
    """

    @staticmethod
    def _validate_file_size(
        file_path: Path, max_size_mb: int = MAX_CONFIG_FILE_SIZE_MB
    ) -> None:
        """
        Raise ValueError if file exceeds max size.

        The implementation uses ``file_path`` and ``max_size_mb`` to raise
        ValueError if file exceeds max size. If the function cannot raise
        ValueError if file exceeds max size, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            max_size_mb: Upper bound enforced for max size mb; the consuming
                boundary rejects or truncates values that exceed it.

        Raises:
            ValueError: If the supplied input cannot be used to raise ValueError
                if file exceeds max size.
        """
        file_size = os.path.getsize(file_path)
        max_bytes = max_size_mb * 1024 * 1024
        if file_size > max_bytes:
            raise ValueError(
                f"Config file {file_path} ({file_size / (1024 * 1024):.1f} MB) "
                f"exceeds maximum allowed size ({max_size_mb} MB)"
            )

    @staticmethod
    def load_yaml(
        file_path: Union[str, Path], context: str = "YAML file"
    ) -> Dict[str, Any]:
        """
        Load YAML file with comprehensive error handling.

        The implementation uses ``file_path`` and ``context`` to load YAML file
        with comprehensive error handling. Parsing or I/O must finish before the
        validated representation is made available to the caller. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle. If the function cannot load YAML file with
        comprehensive error handling, its exception reaches the caller instead
        of being converted into a successful result.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The validated ``data``.

        Raises:
            FileNotFoundError: If ``context`` not found: ``file_path``.
            ValueError: If ``context`` is not a file: ``file_path``; ``context``
                is empty: ``file_path``; ``context`` is empty or contains only
                comments: ``file_path``; or invalid YAML in ``context``:
                ``error_msg``; or another input invariant is violated.
            PermissionError: If permission denied reading ``context``:
                ``file_path``.
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

        # Validate file size before loading
        YAMLManager._validate_file_size(file_path)

        try:
            # ``tool.config`` imports the utils package while it is defining
            # this loader, so defer the import to avoid an initialization
            # cycle while still using the canonical strict YAML boundary.
            from ..config import load_yaml_strict

            with open(file_path, "r", encoding="utf-8") as f:
                data = load_yaml_strict(f)

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
    def validate_dut_config(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate DUT configuration structure.

        Separates hard errors (config will not work) from soft warnings (config
        works but could be improved). Only hard errors cause is_valid to be
        False.

        Args:
            data: Mapping supplying fields for DUT configuration structure.

        Returns:
            A tuple containing ``outcome flag`` and ``selected entries`` in that
            order.
        """
        errors = []
        warnings = []

        if not isinstance(data, dict):
            errors.append("Root element must be a YAML mapping (dictionary)")
            return False, errors

        if not data:
            errors.append("DUT configuration file is empty")
            return False, errors

        if "DUT_Defaults" not in data:
            warnings.append("No DUT_Defaults section found (optional but recommended)")

        duts = []
        if "duts" in data:
            duts = [k for k in data["duts"].keys() if k != "DUT_Defaults"]
        else:
            duts = [k for k in data.keys() if k != "DUT_Defaults"]

        if not duts:
            errors.append("No DUT configurations found. Add at least one DUT entry.")
            return False, errors

        dut_configs = data.get("duts", data)

        for dut_id, dut_config in dut_configs.items():
            if dut_id == "DUT_Defaults":
                continue

            if not isinstance(dut_config, dict):
                errors.append(
                    f"DUT '{dut_id}' configuration must be a mapping, not {type(dut_config).__name__}"
                )
                continue

            bmc_ip = dut_config.get("BMC_IP")
            host_ip = dut_config.get("HOST_IP")
            execution_mode = dut_config.get("ExecutionMode", "remote").lower()

            if not bmc_ip and not host_ip and execution_mode != "local":
                errors.append(
                    f"DUT '{dut_id}' must have at least one access method: BMC_IP, HOST_IP, or ExecutionMode: local"
                )

            recommended_fields = []
            if bmc_ip and not host_ip:
                recommended_fields.append("HOST_IP")
            elif host_ip and not bmc_ip:
                recommended_fields.append("BMC_IP")

            missing_recommended = [
                field for field in recommended_fields if not dut_config.get(field)
            ]

            if missing_recommended:
                warnings.append(
                    f"DUT '{dut_id}' is missing recommended fields: {missing_recommended}"
                )

        return len(errors) == 0, errors + warnings

    @staticmethod
    def convert_legacy_dut_format(
        dut_config_data: Dict[str, Any],
        default_baseboard: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Convert legacy nvdebug format to new nvdebug format.

        Legacy format:

        - Baseboard is stored in config.yaml as 'TargetBaseboard'.
        - DUT config only contains connection details.

        New format:

        - Baseboard is stored in DUT config as 'baseboard'.
        - All DUT-specific settings are in the DUT config.

        Args:
            dut_config_data: DUT config data governing legacy nvdebug format to
                new nvdebug format.
            default_baseboard: Optional default baseboard; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing legacy DUT format.

        Raises:
            ValueError: If the dut configuration duts are not a mapping; DUT
                configuration has conflicting top-level and wrapped
                DUT_Defaults; the dut ``dut_id`` configuration is not a mapping;
                or the legacy dut baseboard from ``source`` is not a non-empty
                string; or another input invariant is violated.
        """
        is_wrapped = "duts" in dut_config_data
        raw_duts = dut_config_data.get("duts", dut_config_data)
        if not isinstance(raw_duts, dict):
            raise ValueError("DUT configuration duts must be a mapping")
        normalized_dut_config = dict(raw_duts) if is_wrapped else raw_duts
        outer_defaults = dut_config_data.get("DUT_Defaults") if is_wrapped else None
        if outer_defaults is not None:
            nested_defaults = normalized_dut_config.get("DUT_Defaults")
            if nested_defaults is not None and nested_defaults != outer_defaults:
                raise ValueError(
                    "DUT configuration has conflicting top-level and wrapped DUT_Defaults"
                )
            normalized_dut_config.setdefault("DUT_Defaults", outer_defaults)

        # Check if this is legacy format (no baseboard in DUT config)
        is_legacy_format = True
        for dut_id, dut_config in normalized_dut_config.items():
            if dut_id == "DUT_Defaults":
                continue
            if not isinstance(dut_config, dict):
                raise ValueError(f"DUT {dut_id!r} configuration must be a mapping")
            if (
                "baseboard" in dut_config
                or "Baseboard" in dut_config
                or "TargetBaseboard" in dut_config
            ):
                is_legacy_format = False
                break

        if not is_legacy_format:
            # Already in new format; return the normalized, unwrapped mapping.
            return normalized_dut_config

        configured_identities = []
        if default_baseboard is not None:
            configured_identities.append(("tool configuration", default_baseboard))

        raw_defaults = normalized_dut_config.get("DUT_Defaults")
        if isinstance(raw_defaults, dict):
            for field_name in ("baseboard", "Baseboard", "TargetBaseboard"):
                if field_name in raw_defaults:
                    configured_identities.append(
                        (f"DUT_Defaults.{field_name}", raw_defaults[field_name])
                    )

        normalized_identities = []
        for source, value in configured_identities:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Legacy DUT baseboard from {source} must be a non-empty string"
                )
            normalized_identities.append((source, value.strip()))

        distinct_identities = {value.casefold() for _, value in normalized_identities}
        if len(distinct_identities) > 1:
            details = ", ".join(
                f"{source}={value!r}" for source, value in normalized_identities
            )
            raise ValueError(
                "Legacy DUT configuration has conflicting authoritative "
                f"baseboards: {details}"
            )
        if not normalized_identities:
            raise ValueError(
                "Legacy DUT configuration has no authoritative baseboard. "
                "Set baseboard or TargetBaseboard in the tool configuration, "
                "or set baseboard in DUT_Defaults. Automatic platform "
                "replacement is disabled."
            )
        resolved_baseboard = normalized_identities[0][1]

        trust_field_aliases = {
            "ssh_host_key_policy": (
                "ssh_host_key_policy",
                "SSH_HOST_KEY_POLICY",
            ),
            "ssh_known_hosts_file": (
                "ssh_known_hosts_file",
                "SSH_KNOWN_HOSTS_FILE",
            ),
            "bmc_rf_tls_mode": (
                "bmc_rf_tls_mode",
                "BMC_RF_TLS_MODE",
            ),
            "bmc_rf_ca_file": (
                "bmc_rf_ca_file",
                "BMC_RF_CA_FILE",
            ),
            "bmc_rf_fingerprint_sha256": (
                "bmc_rf_fingerprint_sha256",
                "BMC_RF_FINGERPRINT_SHA256",
            ),
            "bmc_rf_tls_server_name": (
                "bmc_rf_tls_server_name",
                "BMC_RF_TLS_SERVER_NAME",
            ),
            "bmc_rf_verify_ssl": (
                "bmc_rf_verify_ssl",
                "BMC_RF_VERIFY_SSL",
            ),
        }

        def carry_trust_fields(
            source: Dict[str, Any],
            destination: Dict[str, Any],
        ) -> None:
            """
            Carry trust fields.

            The implementation uses ``source`` and ``destination`` to carry
            trust fields.

            Args:
                source: Mapping supplying fields for carry trust fields.
                destination: Mapping supplying fields for carry trust fields.
            """
            for canonical, aliases in trust_field_aliases.items():
                for alias in aliases:
                    if alias in source:
                        destination[canonical] = source[alias]
                        break

        default_ssh_policy = None
        if isinstance(raw_defaults, dict):
            normalized_default_trust: Dict[str, Any] = {}
            carry_trust_fields(raw_defaults, normalized_default_trust)
            default_ssh_policy = normalized_default_trust.get("ssh_host_key_policy")
            if default_ssh_policy is None:
                default_ssh_policy = infer_legacy_ssh_host_key_policy(
                    raw_defaults.get("SSH_TUNNEL_OPTIONS")
                )

        # Convert each DUT to new format
        converted_config = {}
        for dut_id, dut_config in normalized_dut_config.items():
            if dut_id == "DUT_Defaults":
                converted_defaults = dict(dut_config)
                carry_trust_fields(dut_config, converted_defaults)
                if "ssh_host_key_policy" not in converted_defaults:
                    inferred_policy = infer_legacy_ssh_host_key_policy(
                        converted_defaults.get("SSH_TUNNEL_OPTIONS")
                    )
                    if inferred_policy is not None:
                        converted_defaults["ssh_host_key_policy"] = inferred_policy
                if (
                    converted_defaults.get("ssh_host_key_policy") == "strict"
                    and "ssh_known_hosts_file" not in converted_defaults
                ):
                    inferred_known_hosts = infer_legacy_ssh_known_hosts_file(
                        converted_defaults.get("SSH_TUNNEL_OPTIONS")
                    )
                    if inferred_known_hosts is not None:
                        converted_defaults["ssh_known_hosts_file"] = (
                            inferred_known_hosts
                        )
                converted_config[dut_id] = converted_defaults
                continue

            # Create new format DUT config
            new_dut_config = {
                "baseboard": resolved_baseboard,
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
                **(
                    {"RF_DEFAULT_PREFIX": dut_config["RF_DEFAULT_PREFIX"]}
                    if "RF_DEFAULT_PREFIX" in dut_config
                    else {}
                ),
                "RF_AUTH": dut_config.get("RF_AUTH", True),
                # Host Configuration
                "HOST_IP": dut_config.get("HOST_IP"),
                "HOST_USERNAME": dut_config.get("HOST_USERNAME"),
                "HOST_PASSWORD": dut_config.get("HOST_PASSWORD"),
                "HOST_SSH_PORT": dut_config.get("HOST_SSH_PORT", 22),
                "HOST_SSH_KEY_PATH": dut_config.get("HOST_SSH_KEY_PATH"),
                "HOST_SSH_PASSWORDLESS": dut_config.get("HOST_SSH_PASSWORDLESS", False),
                # HMC Configuration
                "HMC_IP": dut_config.get("HMC_IP"),
                "HMC_USERNAME": dut_config.get("HMC_USERNAME"),
                "HMC_PASSWORD": dut_config.get("HMC_PASSWORD"),
                "HMC_SSH_USERNAME": dut_config.get("HMC_SSH_USERNAME"),
                "HMC_SSH_PASSWORD": dut_config.get("HMC_SSH_PASSWORD"),
                "HMC_SSH_PORT": dut_config.get("HMC_SSH_PORT", 22),
                "HMC_SSH_KEY_PATH": dut_config.get("HMC_SSH_KEY_PATH"),
                "HMC_SSH_PASSWORDLESS": dut_config.get("HMC_SSH_PASSWORDLESS", False),
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
                    DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS,
                ),
                "SSH_TUNNEL_PREFIX": normalize_ssh_tunnel_prefix(
                    dut_config.get("SSH_TUNNEL_PREFIX", DEFAULT_SSH_TUNNEL_PREFIX)
                ),
                # Other Configuration
                "NodeType": dut_config.get("NodeType", "Compute"),
                "collection_level": dut_config.get("collection_level", "L1"),
                "ipmi_cipher": dut_config.get("ipmi_cipher", "-C17"),
                "log_sanitization": dut_config.get("log_sanitization", True),
            }

            carry_trust_fields(dut_config, new_dut_config)

            if "ssh_host_key_policy" not in new_dut_config:
                inferred_policy = infer_legacy_ssh_host_key_policy(
                    new_dut_config.get("SSH_TUNNEL_OPTIONS")
                )
                if inferred_policy is not None:
                    new_dut_config["ssh_host_key_policy"] = inferred_policy
            if (
                new_dut_config.get("ssh_host_key_policy") == "strict"
                and "ssh_known_hosts_file" not in new_dut_config
            ):
                inferred_known_hosts = infer_legacy_ssh_known_hosts_file(
                    new_dut_config.get("SSH_TUNNEL_OPTIONS")
                )
                if inferred_known_hosts is not None:
                    new_dut_config["ssh_known_hosts_file"] = inferred_known_hosts
            if (
                new_dut_config.get("ssh_host_key_policy") or default_ssh_policy
            ) == "strict" and "SSH_TUNNEL_OPTIONS" not in dut_config:
                new_dut_config["SSH_TUNNEL_OPTIONS"] = (
                    DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS
                )

            converted_config[dut_id] = new_dut_config

        return converted_config

    @staticmethod
    def _format_yaml_error(yaml_error: yaml.YAMLError) -> str:
        """
        Format YAML error messages to be more user-friendly.

        For anchor/alias specific errors, provide additional guidance.

        Args:
            yaml_error: YAML error consumed while the function attempts to
                format YAML error messages to be more user-friendly.

        Returns:
            The canonical YAML error text.
        """
        error_str = str(yaml_error)

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

        return f"YAML parsing error: {error_str}"
