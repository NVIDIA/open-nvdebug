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
Configuration management for NVDebug Tool.

This module handles loading and validation of configuration files.
"""

import getpass
import os
import tempfile
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd
import yaml
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .utils.enums import CollectionLevel
from .utils.enums import DutExecutionMode as ExecutionMode
from .utils.enums import DutNodeType, NetworkType, RedfishHmcAccess
from .utils.sanitizer import create_sanitizer_from_config

# Global variable to track sanitization setting for early print statements
_global_sanitization_enabled = True


def set_global_sanitization_enabled(enabled: bool) -> None:
    """
    Set the global sanitization setting for early print statements.

    Args:
        enabled (bool): Enable or disable sanitization.
    """
    global _global_sanitization_enabled
    _global_sanitization_enabled = enabled


def _sanitize_print_message(message: str) -> str:
    """
    Sanitize print messages to avoid exposing usernames in paths.

    Args:
        message (str): Message to sanitize.

    Returns:
        str: Sanitized message with sensitive information masked.
    """
    try:
        current_username = getpass.getuser()
        sanitizer = create_sanitizer_from_config(
            {},
            enabled=_global_sanitization_enabled,
            extra_strings=[current_username] if current_username else [],
        )
        return sanitizer.sanitize(message)
    except Exception:
        # If sanitization fails, return original message
        return message


class Credentials(BaseModel):
    """
    Credentials for authentication.

    Attributes:
        username (str): Username for authentication.
        password (Optional[str]): Password for authentication.
        key_file (Optional[Path]): Path to SSH key file.
    """

    username: str
    password: Optional[str] = None
    key_file: Optional[Path] = None


class ConnectionConfig(BaseModel):
    """
    Connection configuration.

    Attributes:
        host (str): Hostname or IP address.
        port (int): Port number (default: 22).
        credentials (Credentials): Authentication credentials.
        network_type (NetworkType): Network type (IPv4/IPv6).
        timeout (int): Connection timeout in seconds.
    """

    host: str
    port: int = 22
    credentials: Credentials
    network_type: NetworkType = NetworkType.IPV4
    timeout: int = 30


class DUTConfig(BaseModel):
    """
    DUT (Device Under Test) configuration with consistent field naming.

    This class represents the configuration for a single device under test,
    including connection parameters, credentials, and execution settings.

    Attributes:
        name (str): DUT name/identifier.
        baseboard (Optional[str]): Baseboard platform name.
        description (Optional[str]): DUT description.
        local (bool): Run in local mode.
        non_interactive (bool): Non-interactive mode flag.
    """

    # Basic Configuration
    name: str
    baseboard: Optional[str] = (
        None  # Dynamic baseboard name from spreadsheet (auto-detected if not provided)
    )
    description: Optional[str] = None

    # Local Configuration
    local: bool = False
    non_interactive: bool = False

    # BMC Configuration
    bmc_ip: Optional[str] = None
    bmc_user: Optional[str] = None
    bmc_pass: Optional[str] = None
    bmc_ssh_user: Optional[str] = None
    bmc_ssh_pass: Optional[str] = None
    bmc_ssh_port: Optional[int] = 22
    bmc_ssh_key_path: Optional[str] = None
    bmc_ssh_passwordless: bool = False
    bmc_ssh_max_retries: int = 3
    bmc_rf_user: Optional[str] = ""  # Empty string for fallback to BMC credentials
    bmc_rf_pass: Optional[str] = ""  # Empty string for fallback to BMC credentials
    bmc_rf_port: Optional[int] = 443  # Default HTTPS port for Redfish
    bmc_use_https: bool = True  # Use HTTPS for BMC Redfish connections
    bmc_rf_verify_ssl: bool = False  # SSL certificate verification for Redfish

    # Host Configuration
    host_ip: Optional[str] = None
    host_user: Optional[str] = None
    host_pass: Optional[str] = None
    host_ssh_port: Optional[str] = None
    host_ssh_key_path: Optional[str] = None
    host_ssh_passwordless: bool = False
    host_ssh_max_retries: int = 3

    # HMC Configuration
    hmc_ip: Optional[str] = None
    hmc_user: Optional[str] = None
    hmc_pass: Optional[str] = None
    hmc_ssh_user: Optional[str] = None
    hmc_ssh_pass: Optional[str] = None
    hmc_ssh_port: Optional[int] = 22
    hmc_ssh_key_path: Optional[str] = None
    hmc_ssh_passwordless: bool = False
    hmc_ssh_max_retries: int = 3
    hmc_http_port: Optional[int] = 80
    hmc_https_port: Optional[int] = 443
    hmc_use_https: bool = True
    hmc_use_port_forwarding: bool = False
    hmc_access_method: Optional[str] = None

    # SSH Proxy Configuration
    ssh_proxy_host: Optional[str] = None
    ssh_proxy_port: int = 22
    ssh_proxy_user: Optional[str] = None
    ssh_proxy_pass: Optional[str] = None
    ssh_proxy_key_path: Optional[str] = None
    ssh_proxy_passwordless: bool = False
    ssh_proxy_max_retries: int = 3

    # Per-DUT Collector Configuration
    skip_collectors: List[str] = Field(default_factory=list)
    include_collectors: List[str] = Field(default_factory=list)

    # Skip Flags
    SKIP_PORT_FW: bool = False
    SKIP_BMC_SSH_LOGS: bool = True
    SKIP_HOST_LOGS: bool = False
    SKIP_IPMI_LOGS: bool = False
    SKIP_REDFISH_OOB_LOGS: bool = False

    # New Skip Fields
    COLLECTOR_TO_SKIP: List[str] = Field(default_factory=list)
    SYSTEM_ID_TO_SKIP: List[str] = Field(default_factory=list)
    CHASSIS_ID_TO_SKIP: List[str] = Field(default_factory=list)
    MANAGER_ID_TO_SKIP: List[str] = Field(default_factory=list)

    # Expand Query Fields
    EXPAND_QUERY_CHASSIS_LEVEL: int = 1
    EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL: int = 1
    EXPAND_QUERY_MANAGER_LEVEL: int = 1
    EXPAND_QUERY_SYSTEM_LEVEL: int = 1

    # Timeout Fields
    NVOS_TECH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DEVICE_DUMP_SLEEP_DURATION: Optional[int] = None

    # Feature Flags
    EXTRA_LOG_COLLECTION: Optional[bool] = None

    # Directory Fields
    BMC_TEMP_DIR: str = "/tmp"

    # Firmware Inventory Configuration
    FW_INVENTORY_TABLE_PROPERTIES: List[str] = Field(default_factory=list)

    # Additional OOB URI Collection Configuration
    ADDITIONAL_OOB_URI_COLLECTION: List[str] = Field(default_factory=list)

    # NVLink OOB URI Collection Configuration
    NVLINK_OOB_URI: List[str] = Field(default_factory=list)

    # Custom Dump Services Configuration
    CUSTOM_DUMP_SERVICES: List[str] = Field(default_factory=list)

    # Post Codes URI Configuration
    POST_CODES_URI: List[str] = Field(default_factory=list)

    # Legacy field mappings for backward compatibility
    BMC_IP: Optional[str] = None
    BMC_USERNAME: Optional[str] = None
    BMC_PASSWORD: Optional[str] = None
    BMC_SSH_USERNAME: Optional[str] = None
    BMC_SSH_PASSWORD: Optional[str] = None
    BMC_SSH_PORT: Optional[int] = None  # Will be set to 22 in validator
    BMC_SSH_KEY_PATH: Optional[str] = None
    BMC_SSH_PASSWORDLESS: Optional[bool] = False
    BMC_SSH_MAX_RETRIES: Optional[int] = 3
    BMC_RF_PORT: Optional[int] = None  # Will be set to 443 in validator
    RF_User: Optional[str] = None  # Will fall back to BMC_USERNAME in validator
    RF_Pass: Optional[str] = None  # Will fall back to BMC_PASSWORD in validator
    RF_DEFAULT_PREFIX: str = "/redfish/v1"
    RF_AUTH: bool = True
    RF_HMC_ACCESS_METHOD: Optional[str] = (
        None  # Will be set to NOTAPPLICABLE in validator
    )
    HMC_RF_PROTOCOL: Optional[str] = "http"
    TUNNEL_TCP_PORT: Optional[Union[int, str]] = None  # Can be int, string, or None
    SETUP_PORT_FORWARDING: bool = False
    FORCE_PORT_FW: bool = False
    IP_NETWORK: str = "ipv4"
    HOST_IP: Optional[str] = None
    HOST_USERNAME: Optional[str] = None  # Will be set to current user in validator
    HOST_PASSWORD: Optional[str] = None
    HOST_SSH_PORT: Optional[int] = None  # Will be set to 22 in validator
    HOST_SSH_KEY_PATH: Optional[str] = None
    HOST_SSH_PASSWORDLESS: Optional[bool] = False
    HOST_SSH_MAX_RETRIES: Optional[int] = 3
    SSH_PROXY_HOST: Optional[str] = None
    SSH_PROXY_PORT: Optional[int] = 22
    SSH_PROXY_USERNAME: Optional[str] = None
    SSH_PROXY_PASSWORD: Optional[str] = None
    SSH_PROXY_KEY_PATH: Optional[str] = None
    SSH_PROXY_PASSWORDLESS: Optional[bool] = False
    SSH_PROXY_MAX_RETRIES: Optional[int] = 3
    HMC_IP: Optional[str] = None
    HMC_USERNAME: Optional[str] = None
    HMC_PASSWORD: Optional[str] = None
    HMC_SSH_USERNAME: Optional[str] = None
    HMC_SSH_PASSWORD: Optional[str] = None
    HMC_SSH_PORT: Optional[int] = None  # Will be set to 22 in validator
    HMC_SSH_KEY_PATH: Optional[str] = None
    HMC_SSH_PASSWORDLESS: Optional[bool] = False
    HMC_SSH_MAX_RETRIES: Optional[int] = 3
    HMC_HTTP_PORT: Optional[int] = 80
    HMC_HTTPS_PORT: Optional[int] = 443
    HMC_USE_HTTPS: bool = False
    HMC_TCP_PORT: Optional[int] = (
        None  # Will be set based on HMC_RF_PROTOCOL in validator
    )
    USE_PORT_FORWARDING: bool = False
    # SSH tunnel configuration
    TUNNEL_LOCAL_HOST: str = "localhost"
    SSH_TUNNEL_OPTIONS: str = "-4 -o StrictHostKeyChecking=no -o LogLevel=ERROR -fNT"
    SSH_TUNNEL_PREFIX: str = "sshpass -p"
    ipmi_cipher: str = "-C17"
    NodeType: str = "Compute"
    ConfigFileToUse: Optional[str] = None
    ExecutionMode: Optional[str] = "REMOTE"

    @model_validator(mode="before")
    @classmethod
    def validate_legacy_fields(cls, values: Any) -> Any:
        """
        Convert between new and legacy field formats and handle credential fallbacks.

        Args:
            values (Any): Dictionary of configuration values.

        Returns:
            Any: Validated and converted configuration values.
        """
        if isinstance(values, dict):
            # Map new fields to legacy fields for backward compatibility
            field_mappings = {
                # BMC fields
                "bmc_ip": "BMC_IP",
                "bmc_user": "BMC_USERNAME",
                "bmc_pass": "BMC_PASSWORD",
                "bmc_ssh_user": "BMC_SSH_USERNAME",
                "bmc_ssh_pass": "BMC_SSH_PASSWORD",
                "bmc_ssh_port": "BMC_SSH_PORT",
                "bmc_ssh_key_path": "BMC_SSH_KEY_PATH",
                "bmc_ssh_passwordless": "BMC_SSH_PASSWORDLESS",
                "bmc_ssh_max_retries": "BMC_SSH_MAX_RETRIES",
                "bmc_rf_user": "RF_User",
                "bmc_rf_pass": "RF_Pass",
                "bmc_rf_port": "BMC_RF_PORT",
                # Host fields
                "host_ip": "HOST_IP",
                "host_user": "HOST_USERNAME",
                "host_pass": "HOST_PASSWORD",
                "host_ssh_port": "HOST_SSH_PORT",
                "host_ssh_key_path": "HOST_SSH_KEY_PATH",
                "host_ssh_passwordless": "HOST_SSH_PASSWORDLESS",
                "host_ssh_max_retries": "HOST_SSH_MAX_RETRIES",
                # HMC fields
                "hmc_ip": "HMC_IP",
                "hmc_user": "HMC_USERNAME",
                "hmc_pass": "HMC_PASSWORD",
                "hmc_ssh_user": "HMC_SSH_USERNAME",
                "hmc_ssh_pass": "HMC_SSH_PASSWORD",
                "hmc_ssh_port": "HMC_SSH_PORT",
                "hmc_ssh_key_path": "HMC_SSH_KEY_PATH",
                "hmc_ssh_passwordless": "HMC_SSH_PASSWORDLESS",
                "hmc_ssh_max_retries": "HMC_SSH_MAX_RETRIES",
                "hmc_http_port": "HMC_HTTP_PORT",
                "hmc_https_port": "HMC_HTTPS_PORT",
                "hmc_use_https": "HMC_USE_HTTPS",
                "hmc_use_port_forwarding": "USE_PORT_FORWARDING",
                "use_port_forwarding": "USE_PORT_FORWARDING",
                "hmc_access_method": "RF_HMC_ACCESS_METHOD",
                # SSH Proxy fields
                "ssh_proxy_host": "SSH_PROXY_HOST",
                "ssh_proxy_port": "SSH_PROXY_PORT",
                "ssh_proxy_user": "SSH_PROXY_USERNAME",
                "ssh_proxy_pass": "SSH_PROXY_PASSWORD",
                "ssh_proxy_key_path": "SSH_PROXY_KEY_PATH",
                "ssh_proxy_passwordless": "SSH_PROXY_PASSWORDLESS",
                "ssh_proxy_max_retries": "SSH_PROXY_MAX_RETRIES",
            }

            # Copy new fields to legacy fields if legacy fields don't exist
            for new_field, legacy_field in field_mappings.items():
                if new_field in values and legacy_field not in values:
                    values[legacy_field] = values[new_field]

            # Copy legacy fields to new fields if new fields don't exist
            for new_field, legacy_field in field_mappings.items():
                if legacy_field in values and new_field not in values:
                    values[new_field] = values[legacy_field]

            # Handle credential fallbacks (matching legacy dut.py behavior)
            # Replace RF credentials with BMC credentials if not provided
            if not values.get("RF_User") and values.get("BMC_USERNAME"):
                values["RF_User"] = values["BMC_USERNAME"]
            if not values.get("RF_Pass") and values.get("BMC_PASSWORD"):
                values["RF_Pass"] = values["BMC_PASSWORD"]

            # Replace BMC SSH credentials with BMC credentials if not provided
            if not values.get("BMC_SSH_USERNAME") and values.get("BMC_USERNAME"):
                values["BMC_SSH_USERNAME"] = values["BMC_USERNAME"]
            if not values.get("BMC_SSH_PASSWORD") and values.get("BMC_PASSWORD"):
                values["BMC_SSH_PASSWORD"] = values["BMC_PASSWORD"]

            # Set default ports if not provided
            if values.get("BMC_SSH_PORT") is None:
                values["BMC_SSH_PORT"] = 22
            if values.get("HMC_SSH_PORT") is None:
                values["HMC_SSH_PORT"] = 22
            if values.get("HOST_SSH_PORT") is None:
                values["HOST_SSH_PORT"] = 22
            if values.get("BMC_RF_PORT") is None:
                values["BMC_RF_PORT"] = 443

            # Set HMC TCP port based on protocol
            if values.get("HMC_TCP_PORT") is None:
                if values.get("HMC_RF_PROTOCOL") == "http":
                    values["HMC_TCP_PORT"] = 80
                else:
                    values["HMC_TCP_PORT"] = 443

            # Set RF_HMC_ACCESS_METHOD to NOTAPPLICABLE if not provided
            if not values.get("RF_HMC_ACCESS_METHOD"):
                values["RF_HMC_ACCESS_METHOD"] = "NOTAPPLICABLE"

            # Set HOST_USERNAME to current user if not provided
            if not values.get("HOST_USERNAME"):
                values["HOST_USERNAME"] = getpass.getuser()

            # Ensure passwordless flags are booleans
            if values.get("HOST_SSH_PASSWORDLESS") is None:
                values["HOST_SSH_PASSWORDLESS"] = False
            if values.get("BMC_SSH_PASSWORDLESS") is None:
                values["BMC_SSH_PASSWORDLESS"] = False
            if values.get("HMC_SSH_PASSWORDLESS") is None:
                values["HMC_SSH_PASSWORDLESS"] = False

            # Set SSH key paths to None if not provided
            if not values.get("BMC_SSH_KEY_PATH"):
                values["BMC_SSH_KEY_PATH"] = None
            if not values.get("HOST_SSH_KEY_PATH"):
                values["HOST_SSH_KEY_PATH"] = None

            # Handle TUNNEL_TCP_PORT - convert empty string to None, set default to 18888 if None
            if values.get("TUNNEL_TCP_PORT") == "":
                values["TUNNEL_TCP_PORT"] = None
            if values.get("TUNNEL_TCP_PORT") is None:
                values["TUNNEL_TCP_PORT"] = 18888

            # Also handle new field names for consistency
            if not values.get("bmc_ssh_user") and values.get("bmc_user"):
                values["bmc_ssh_user"] = values["bmc_user"]
            if not values.get("bmc_ssh_pass") and values.get("bmc_pass"):
                values["bmc_ssh_pass"] = values["bmc_pass"]
            if not values.get("bmc_rf_user") and values.get("bmc_user"):
                values["bmc_rf_user"] = values["bmc_user"]
            if not values.get("bmc_rf_pass") and values.get("bmc_pass"):
                values["bmc_rf_pass"] = values["bmc_pass"]

        return values


class CollectorConfig(BaseModel):
    """
    Collector configuration.

    Attributes:
        id (str): Collector unique identifier.
        name (str): Collector display name.
        group (str): Collector group name.
        enabled (bool): Whether collector is enabled.
        priority (int): Collection priority.
        workflow_type (str): Workflow type.
        action_type (str): Action type for collection.
        parser_type (str): Parser type for output.
        output_format (str): Output format.
        collection_level (CollectionLevel): Collection level (L1/L2/L3).
        timeout (int): Timeout in seconds.
        retry_count (int): Number of retry attempts.
    """

    id: str
    name: str
    group: str
    enabled: bool = True
    priority: int = 1
    workflow_type: str = "simple"
    action_type: str
    parser_type: str
    output_format: str = "json"
    collection_level: CollectionLevel = CollectionLevel.L1
    timeout: int = 300
    retry_count: int = 3
    tags: Dict[str, Any] = Field(default_factory=dict)
    dependencies: Dict[str, Any] = Field(default_factory=dict)
    description: str = ""
    action_uri: str = ""
    action_payload: Dict[str, Any] = Field(default_factory=dict)
    parser_config: Dict[str, Any] = Field(default_factory=dict)
    platform_config: Dict[str, Any] = Field(default_factory=dict)

    # Dynamic baseboard applicability - will be populated from spreadsheet
    applicable_baseboards: Dict[str, bool] = Field(default_factory=dict)


class OutputConfig(BaseModel):
    """
    Output configuration.

    Attributes:
        directory (Path): Output directory path.
        create_zip (bool): Create zip archive of logs.
        create_split_zip (bool): Split large zip archives.
        zip_split_threshold (float): Size threshold for splitting (MB).
        generate_html (bool): Generate HTML reports.
        generate_json (bool): Generate JSON reports.
        preserve_metadata (bool): Preserve file metadata.
    """

    directory: Path = Path("/tmp/nvdebug")
    create_zip: bool = True
    create_split_zip: bool = False
    zip_split_threshold: float = 200.0  # MB
    generate_html: bool = True
    generate_json: bool = True
    preserve_metadata: bool = True

    @property
    def output_dir(self) -> str:
        """
        Get output directory as string (backward compatibility alias).

        Returns:
            str: Output directory path.
        """
        return str(self.directory)

    @output_dir.setter
    def output_dir(self, value: str) -> None:
        """
        Set output directory from string (backward compatibility setter).

        Args:
            value (str): Output directory path.
        """
        self.directory = Path(value)


class LoggingConfig(BaseModel):
    """
    Logging configuration.

    Attributes:
        level (str): Logging level.
        file (Optional[Path]): Logging file path.
        format (str): Logging format.
        max_size (int): Maximum size of logging file in bytes.
        backup_count (int): Number of backup files to keep.
    """

    level: str = "INFO"
    file: Optional[Path] = None
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5


class RedfishSessionConfig(BaseModel):
    """
    Redfish session configuration for connection pooling and timeouts.

    Attributes:
        connection_pool_limit (int): Connection pool limit.
        connection_pool_limit_per_host (int): Connection pool limit per host.
        session_timeout (int): Session timeout in seconds.
        keepalive_timeout (int): Keepalive timeout in seconds.
        ssl (bool): SSL verification.
        ttl_dns_cache (int): TTL DNS cache in seconds.
        use_dns_cache (bool): Use DNS cache.
        force_close (bool): Force close.
        enable_cleanup_closed (bool): Enable cleanup closed.
    """

    # Connection pool settings
    connection_pool_limit: int = 20
    connection_pool_limit_per_host: int = 8

    # Timeout settings
    session_timeout: int = 300  # 5 minutes
    keepalive_timeout: int = 300  # 5 minutes

    # TCP Connector settings
    ssl: bool = False  # Disable SSL verification for BMC self-signed certs
    ttl_dns_cache: int = 300  # DNS cache TTL in seconds
    use_dns_cache: bool = True  # Enable DNS caching
    force_close: bool = False  # Keep connections alive
    enable_cleanup_closed: bool = True  # Clean up closed connections

    # Fallback session settings (more conservative)
    fallback_connection_pool_limit: int = 15
    fallback_connection_pool_limit_per_host: int = 6


class PreflightConfig(BaseModel):
    """
    Preflight credential validation configuration.

    Attributes:
        validate_credentials_in_preflight (bool): Enable/disable credential validation during preflight checks.
                                                  Default is True. When enabled, preflight will test an authenticated
                                                  endpoint to verify credentials work, not just that the service is up.
        credential_validation_uri (str): The Redfish URI to test for credential validation.
                                        Default is "/redfish/v1/Systems" which requires authentication on most BMCs.
                                        This URI will be normalized with any prefix_override settings.
                                        Alternative options: "/redfish/v1/Managers", "/redfish/v1/Chassis"
    """

    validate_credentials_in_preflight: bool = True
    credential_validation_uri: str = "/redfish/v1/Systems"


class Config(BaseSettings):
    """
    Main configuration class.

    Attributes:
        baseboard (str): Baseboard name.
        collection_level (CollectionLevel): Collection level.
        execution_mode (ExecutionMode): Execution mode.
        auto_parse (bool): Auto parse.
        duts (List[DUTConfig]): DUT configurations.
        collectors (List[CollectorConfig]): Collector configurations.
        output (OutputConfig): Output configuration.
        logging (LoggingConfig): Logging configuration.
        redfish_session_config (RedfishSessionConfig): Redfish session configuration.
        preflight_config (PreflightConfig): Preflight credential validation configuration.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="allow",
        validate_assignment=True,
    )

    # Basic configuration
    baseboard: str = "compute"
    collection_level: CollectionLevel = CollectionLevel.L1
    execution_mode: ExecutionMode = ExecutionMode.LOCAL
    auto_parse: bool = True

    # DUT configurations
    duts: List[DUTConfig] = Field(default_factory=list)

    # Collector configurations
    collectors: List[CollectorConfig] = Field(default_factory=list)

    # Output configuration
    output: OutputConfig = Field(default_factory=OutputConfig)

    # Logging configuration
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    # Redfish session configuration
    redfish_session_config: RedfishSessionConfig = Field(
        default_factory=RedfishSessionConfig
    )

    # Preflight configuration
    preflight_config: PreflightConfig = Field(default_factory=PreflightConfig)

    # Legacy fields for backward compatibility
    TargetBaseboard: Optional[str] = None
    LogSanitization: bool = True
    AUTO_PARSE: bool = True
    GENERATE_HTML_REPORTS: bool = True
    FPGA_REG_MAPPING_FILE: Optional[str] = None

    # Firmware Inventory Configuration
    FW_INVENTORY_TABLE_PROPERTIES: List[str] = Field(default_factory=list)

    # Additional OOB URI Collection Configuration
    ADDITIONAL_OOB_URI_COLLECTION: List[str] = Field(default_factory=list)

    # NVLink OOB URI Collection Configuration
    NVLINK_OOB_URI: List[str] = Field(default_factory=list)

    # Custom Dump Services Configuration
    CUSTOM_DUMP_SERVICES: List[str] = Field(default_factory=list)

    # Post Codes URI Configuration
    POST_CODES_URI: List[str] = Field(default_factory=list)

    # Skip flags for orchestrator
    skip_html_reports: bool = False
    skip_zip: bool = False
    skip_auto_parse: bool = False
    zip_split_threshold: float = 200.0

    # Per-DUT Collector Configuration
    skip_collectors: List[str] = Field(default_factory=list)
    include_collectors: List[str] = Field(default_factory=list)

    # Skip Flags
    SKIP_PORT_FW: bool = False
    SKIP_BMC_SSH_LOGS: bool = True
    SKIP_HOST_LOGS: bool = False
    SKIP_IPMI_LOGS: bool = False
    SKIP_REDFISH_OOB_LOGS: bool = False

    # New Skip Fields
    COLLECTOR_TO_SKIP: List[str] = Field(default_factory=list)
    SYSTEM_ID_TO_SKIP: List[str] = Field(default_factory=list)
    CHASSIS_ID_TO_SKIP: List[str] = Field(default_factory=list)
    MANAGER_ID_TO_SKIP: List[str] = Field(default_factory=list)

    # Expand Query Fields
    EXPAND_QUERY_CHASSIS_LEVEL: int = 1
    EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL: int = 1
    EXPAND_QUERY_MANAGER_LEVEL: int = 1
    EXPAND_QUERY_SYSTEM_LEVEL: int = 1

    # Timeout Fields
    NVOS_TECH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DEVICE_DUMP_SLEEP_DURATION: Optional[int] = None

    # Feature Flags
    EXTRA_LOG_COLLECTION: Optional[bool] = None

    # Sanitization configuration
    sanitization: Optional[Dict[str, Any]] = None

    # Execution configuration
    execution_config: Optional[Dict[str, Any]] = None

    # Collector definitions
    collector_definitions: Optional[Dict[str, Any]] = None

    # Preflight configuration
    preflight: Optional[Dict[str, Any]] = None

    # New configuration fields for enhanced functionality
    # URI configuration
    uri_overrides: Optional[Dict[str, Any]] = None

    # Enhanced logging configuration
    logging_config: Optional[Dict[str, Any]] = None

    # Baseboard configuration
    baseboard_config: Optional[Dict[str, Any]] = None

    # Enhanced output configuration
    output_config: Optional[Dict[str, Any]] = None

    # Network configuration
    network_config: Optional[Dict[str, Any]] = None

    # Debug configuration
    debug_config: Optional[Dict[str, Any]] = None

    # Execution configuration with defaults
    max_concurrent_duts: int = 5
    max_concurrent_collectors_per_dut: int = 3
    timeout: int = 300
    retry_count: int = 3

    # Parallelization configuration
    PARALLEL_DUT_SEQUENTIAL_COLLECTORS: bool = True
    SERVICE_GROUPED_SEQUENTIAL_COLLECTORS: bool = True

    # Global Directory and Prefix Fields
    TASK_ID_PREFIX: str = ""  # Empty by default, only used if user specifies
    TOOL_TEMP_DIR: str = "/tmp"

    # Pagination configuration
    max_pagination_pages: int = (
        100  # Maximum pages for Redfish pagination to prevent infinite loops
    )
    max_duplicate_url_retries: int = (
        3  # Maximum consecutive duplicate URLs before stopping pagination
    )

    # Logging configuration with defaults
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Output configuration with defaults
    output_directory: str = "/tmp/nvdebug"
    skip_zip: bool = False
    skip_zip_split: bool = False

    # Tool-level Collector Configuration
    skip_collectors: List[str] = Field(default_factory=list)
    include_collectors: List[str] = Field(default_factory=list)
    # Spreadsheet Configuration - Always True (spreadsheet-only mode)

    # Additional configuration fields for tests
    validation: Optional[Dict[str, Any]] = None
    transformation: Optional[Dict[str, Any]] = None
    reporting: Optional[Dict[str, Any]] = None

    @model_validator(mode="before")
    @classmethod
    def validate_legacy_fields(cls, values: Any) -> Any:
        """
        Convert legacy fields to new format.

        Args:
            values (Any): Dictionary of values to validate.

        Returns:
            Any: Validated values.
        """
        if isinstance(values, dict):
            # Baseboard mapping - handle precedence: baseboard > TargetBaseboard
            # If baseboard is not set but TargetBaseboard is, use TargetBaseboard
            if values.get("TargetBaseboard") and not values.get("baseboard"):
                values["baseboard"] = values["TargetBaseboard"].lower()
            # If both are present, baseboard takes precedence (no change needed)
            # If neither is present, that's fine - auto-detection will be used

            # Output settings
            if values.get("GENERATE_HTML_REPORTS") is not None:
                if "output" not in values:
                    values["output"] = {}
                values["output"]["generate_html"] = values["GENERATE_HTML_REPORTS"]

        return values

    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> "Config":
        """
        Load configuration from file.

        Args:
            file_path (Union[str, Path]): Path to configuration file.

        Returns:
            Config: Loaded configuration object.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            # Handle case where YAML file is mostly commented out and returns None
            if data is None:
                data = {}

            return cls(**data)
        except yaml.YAMLError as e:
            from .utils.yaml_manager import YAMLManager

            error_msg = YAMLManager._format_yaml_error(e)
            raise ValueError(f"Invalid YAML in configuration file: {error_msg}")
        except Exception as e:
            raise ValueError(f"Error loading configuration: {e}")

    def to_file(self, file_path: Union[str, Path]) -> None:
        """
        Save configuration to file.

        Args:
            file_path (Union[str, Path]): Output file path.

        Raises:
            ValueError: If file cannot be saved.
        """
        file_path = Path(file_path)

        try:
            # Ensure directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, "w", encoding="utf-8") as f:
                yaml.dump(
                    self.model_dump(),
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                )
        except Exception as e:
            raise ValueError(f"Error saving configuration: {e}")

    @classmethod
    def create_template(cls) -> "Config":
        """
        Create a template configuration.

        Returns:
            Config: Template configuration object.
        """
        return cls(
            baseboard="compute",  # Will be validated against spreadsheet
            duts=[
                DUTConfig(
                    name="example-dut",
                    baseboard="compute",
                    bmc_connection=ConnectionConfig(
                        host="192.168.1.100",
                        credentials=Credentials(username="admin"),
                    ),
                    host_connection=ConnectionConfig(
                        host="192.168.1.101",
                        credentials=Credentials(username="root"),
                    ),
                )
            ],
        )


def load_config(
    config_file: Optional[Path] = None,
    baseboard: Optional[str] = None,
    collection_level: Optional[str] = None,
) -> Config:
    """
    Load configuration with optional overrides.

    Args:
        config_file (Optional[Path]): Path to configuration file.
        baseboard (Optional[str]): Baseboard override.
        collection_level (Optional[str]): Collection level override.

    Returns:
        Config: Loaded configuration object.
    """
    # Load configuration
    if config_file and config_file.exists():
        config = Config.from_file(config_file)
    else:
        config = Config()

    # Apply overrides
    if baseboard:
        config.baseboard = baseboard
    if collection_level:
        config.collection_level = CollectionLevel(collection_level)

    return config


def load_dut_config(
    file_path: Union[str, Path], quiet_mode: bool = False
) -> List[DUTConfig]:
    """
    Load DUT configuration from file with proper DUT_Defaults handling.

    Args:
        file_path (Union[str, Path]): Path to DUT configuration file.
        quiet_mode (bool): Suppress output messages.

    Returns:
        List[DUTConfig]: List of DUT configuration objects.

    Raises:
        FileNotFoundError: If configuration file not found.
        ValueError: If configuration file is invalid.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"DUT configuration file not found: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # Handle fully commented out YAML files (yaml.safe_load returns None)
        if data is None:
            data = {}

        if not isinstance(data, dict):
            # Provide more specific error message based on the actual data type
            if isinstance(data, str):
                raise ValueError(
                    f"Invalid DUT configuration content: The file contains only text '{data}' "
                    f"but DUT configuration files must contain YAML mappings (key-value pairs).\n"
                    f"Please ensure your DUT config file contains proper YAML structure with DUT definitions."
                )
            elif isinstance(data, list):
                raise ValueError(
                    f"Invalid DUT configuration format: The file contains a list but DUT configuration files "
                    f"must contain YAML mappings (key-value pairs).\n"
                    f"Please restructure your config file to use dictionary format with DUT definitions."
                )
            else:
                raise ValueError(
                    f"Invalid DUT configuration format: Expected YAML mapping (dictionary) but found {type(data).__name__}.\n"
                    f"DUT configuration files must contain key-value pairs defining DUTs and their settings."
                )

        # Extract defaults if they exist
        defaults = data.get("DUT_Defaults", {})

        # Handle different formats
        if "DUT" in data and len([k for k in data.keys() if k != "DUT_Defaults"]) == 1:
            # Legacy single DUT format
            dut_data = {
                **defaults,
                **data["DUT"],
            }  # Merge defaults with DUT data
            dut_data["name"] = "DUT"
            return [DUTConfig(**dut_data)]
        else:
            # Multi-DUT format
            duts = []
            for name, dut_data in data.items():
                if name != "DUT_Defaults":
                    # Merge defaults with individual DUT data (DUT data takes precedence)
                    merged_data = {**defaults, **dut_data}
                    merged_data["name"] = name

                    # Use baseboard from defaults if not specified in individual DUT
                    if "baseboard" not in merged_data and "baseboard" in defaults:
                        merged_data["baseboard"] = defaults["baseboard"]

                    # If DUT has ConfigFileToUse but no baseboard, try to load baseboard from the config file
                    if merged_data.get("ConfigFileToUse") and not merged_data.get(
                        "baseboard"
                    ):
                        config_file_path = merged_data["ConfigFileToUse"]
                        try:
                            if os.path.exists(config_file_path):
                                with open(config_file_path, "r") as f:
                                    config_data = yaml.safe_load(f)

                                # Check for both baseboard (new format) and TargetBaseboard (legacy format)
                                baseboard_value = config_data.get(
                                    "baseboard"
                                ) or config_data.get("TargetBaseboard")
                                if baseboard_value:
                                    merged_data["baseboard"] = baseboard_value
                                    if not quiet_mode:
                                        print(
                                            _sanitize_print_message(
                                                f"Loaded baseboard '{baseboard_value}' from config file '{config_file_path}' for DUT '{name}'"
                                            )
                                        )
                                else:
                                    if not quiet_mode:
                                        print(
                                            _sanitize_print_message(
                                                f"Warning: No baseboard found in config file '{config_file_path}' for DUT '{name}'"
                                            )
                                        )
                        except Exception as e:
                            if not quiet_mode:
                                print(
                                    _sanitize_print_message(
                                        f"Warning: Could not load baseboard from config file '{config_file_path}' for DUT '{name}': {e}"
                                    )
                                )

                    # Note: If no baseboard is specified after all attempts, auto-detection will handle it

                    duts.append(DUTConfig(**merged_data))

            if not duts:
                # If quiet_mode is enabled, return empty list for fallback to CLI mode
                # Otherwise, raise an error to inform the user
                if quiet_mode:
                    return []
                else:
                    raise ValueError(
                        "No DUT configurations found in the file. "
                        "The DUT config file appears to be empty or fully commented out. "
                        "Please either:\n"
                        "  • Define at least one DUT in the config file, or\n"
                        "  • Use CLI credentials instead of a config file, or\n"
                        "  • Use --local flag if running locally"
                    )

            return duts

    except yaml.YAMLError as e:
        from .utils.yaml_manager import YAMLManager

        error_msg = YAMLManager._format_yaml_error(e)
        raise ValueError(f"Invalid YAML in DUT configuration file: {error_msg}")
    except Exception as e:
        raise ValueError(f"Error loading DUT configuration: {e}")


def load_dut_config_legacy(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Load DUT configuration in raw format for backward compatibility.

    This function returns the raw dictionary format.

    In the legacy format:
    - Baseboard is stored in config.yaml as 'TargetBaseboard', not in DUT config
    - DUT config only contains connection details (IPs, credentials, etc.)
    - DUT_Defaults can contain default values for all DUTs

    Args:
        file_path (Union[str, Path]): Path to DUT configuration file.

    Returns:
        Dict[str, Any]: Raw dictionary format.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"DUT configuration file not found: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            dut_config_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        from .utils.yaml_manager import YAMLManager

        error_msg = YAMLManager._format_yaml_error(e)
        raise ValueError(f"Invalid YAML in DUT configuration file: {error_msg}")
    except Exception as e:
        raise ValueError(f"Error loading DUT configuration: {e}")

    # If there's no data in the dut config file or it couldn't be loaded, initialize with an empty dict
    if not dut_config_data:
        dut_config_data = {"DUT": {}}

    # Remove Default DUT if multiple are specified (legacy behavior)
    if len(dut_config_data) >= 2:
        dut_config_data.pop("DUT_Defaults", None)
        if len(dut_config_data) >= 2:
            print(
                _sanitize_print_message("Multiple DUTs found. Ignoring CLI DUT details")
            )
    elif len(dut_config_data) == 0:
        dut_config_data["DUT"] = {}

    return dut_config_data


def get_available_baseboards(spreadsheet_path: Union[str, Path]) -> List[str]:
    """
    Get available baseboards from the collector spreadsheet (Excel only).

    Args:
        spreadsheet_path (Union[str, Path]): Path to spreadsheet file.

    Returns:
        List[str]: List of available baseboard names.

    Raises:
        ValueError: If file format is not supported.
    """
    try:
        spreadsheet_path = Path(spreadsheet_path)

        if spreadsheet_path.suffix.lower() not in [".xlsx", ".xls"]:
            raise ValueError(
                f"Only Excel files (.xlsx, .xls) are supported, got: {spreadsheet_path.suffix}"
            )

        # Read from the Log Collection Catalog sheet
        df = pd.read_excel(spreadsheet_path, sheet_name="Log Collection Catalog")

        # Find columns that start with various applicable prefixes
        baseboard_columns = []
        for col in df.columns:
            if any(
                col.startswith(prefix)
                for prefix in [
                    "applicable_for_",
                    "available_for_",
                    "Applicable for",
                    "Available for",
                ]
            ):
                baseboard_columns.append(col)

        # Extract baseboard names from column names
        baseboards = []
        for col in baseboard_columns:
            # Remove various prefixes
            baseboard_name = col
            for prefix in [
                "applicable_for_",
                "available_for_",
                "Applicable for",
                "Available for",
            ]:
                if col.startswith(prefix):
                    baseboard_name = col.replace(prefix, "").strip().strip("\n")
                    break

            if baseboard_name:  # Only add if we found a valid name
                baseboards.append(baseboard_name)

        return baseboards
    except Exception as e:
        raise ValueError(f"Error reading baseboards from spreadsheet: {e}")


def validate_baseboard(baseboard: str, spreadsheet_path: Union[str, Path]) -> bool:
    """
    Validate that a baseboard exists in the spreadsheet.

    Args:
        baseboard (str): Baseboard name to validate.
        spreadsheet_path (Union[str, Path]): Path to spreadsheet file.

    Returns:
        bool: True if baseboard exists, False otherwise.
    """
    if not spreadsheet_path:
        return False

    try:
        available_baseboards = get_available_baseboards(spreadsheet_path)
        return baseboard.lower() in [b.lower() for b in available_baseboards]
    except Exception:
        return False


def load_collectors_from_spreadsheet(
    spreadsheet_path: Union[str, Path],
) -> List[CollectorConfig]:
    """
    Load collector configurations from spreadsheet (Excel only).

    Args:
        spreadsheet_path (Union[str, Path]): Path to spreadsheet file.

    Returns:
        List[CollectorConfig]: List of collector configuration objects.

    Raises:
        ValueError: If file format is not supported or cannot be read.
    """
    try:
        spreadsheet_path = Path(spreadsheet_path)

        if spreadsheet_path.suffix.lower() not in [".xlsx", ".xls"]:
            raise ValueError(
                f"Only Excel files (.xlsx, .xls) are supported, got: {spreadsheet_path.suffix}"
            )

        # Read from the Log Collection Catalog sheet
        df = pd.read_excel(spreadsheet_path, sheet_name="Log Collection Catalog")

        collectors = []
        for _, row in df.iterrows():
            try:
                collector = CollectorConfig(
                    id=row.get("ID", ""),
                    name=row.get("Collector Name", ""),
                    group=row.get("Collection Group", ""),
                    action_type=row.get("Action Type", ""),
                    parser_type=row.get("Parser Type", ""),
                    description=row.get("Description", ""),
                    action_uri=row.get("action_uri", ""),
                    enabled=row.get("Enabled", True),
                    priority=row.get("priority", 1),
                    timeout=row.get("Timeout", 300),
                    retry_count=row.get("Retry Count", 3),
                    collection_level=CollectionLevel(row.get("Collection Level", "L1")),
                )
                collectors.append(collector)
            except Exception as e:
                # Skip invalid collector configurations
                continue

        return collectors
    except Exception as e:
        raise ValueError(f"Error reading collectors from spreadsheet: {e}")


def get_collector_applicability_from_spreadsheet(
    spreadsheet_path: Union[str, Path], collector_id: str, baseboard: str
) -> bool:
    """
    Get collector applicability for a specific baseboard from spreadsheet.

    Args:
        spreadsheet_path (Union[str, Path]): Path to spreadsheet file.
        collector_id (str): Collector ID to check.
        baseboard (str): Baseboard name.

    Returns:
        bool: True if collector is applicable for baseboard.

    Raises:
        ValueError: If spreadsheet cannot be read.
    """
    try:
        spreadsheet_path = Path(spreadsheet_path)

        if spreadsheet_path.suffix.lower() not in [".xlsx", ".xls"]:
            raise ValueError(
                f"Only Excel files (.xlsx, .xls) are supported, got: {spreadsheet_path.suffix}"
            )

        # Read from the Log Collection Catalog sheet
        df = pd.read_excel(spreadsheet_path, sheet_name="Log Collection Catalog")

        # Find the collector row
        collector_row = df[df["ID"] == collector_id]
        if collector_row.empty:
            return False

        # Try different column name formats
        possible_columns = [
            f"Applicable for {baseboard}",
            f"Available for {baseboard}",
            f"applicable_for_{baseboard}",
            f"available_for_{baseboard}",
        ]

        # Find the first column that exists
        column_name = None
        for col in possible_columns:
            if col in collector_row.columns:
                column_name = col
                break

        if column_name is None:
            return False

        # Get the value and check applicability
        cell_value = collector_row.iloc[0][column_name]
        return _is_applicable_value(cell_value)

    except Exception as e:
        raise ValueError(f"Error reading collector applicability from spreadsheet: {e}")


def get_all_collector_applicability_from_spreadsheet(
    spreadsheet_path: Union[str, Path],
) -> Dict[str, Dict[str, bool]]:
    """
    Get all collector applicability from spreadsheet.

    Args:
        spreadsheet_path (Union[str, Path]): Path to spreadsheet file.

    Returns:
        Dict[str, Dict[str, bool]]: Nested dict mapping collector_id -> baseboard -> applicable.

    Raises:
        ValueError: If spreadsheet cannot be read.
    """
    try:
        spreadsheet_path = Path(spreadsheet_path)

        if spreadsheet_path.suffix.lower() not in [".xlsx", ".xls"]:
            raise ValueError(
                f"Only Excel files (.xlsx, .xls) are supported, got: {spreadsheet_path.suffix}"
            )

        # Read from the Log Collection Catalog sheet
        df = pd.read_excel(spreadsheet_path, sheet_name="Log Collection Catalog")

        # Find all applicable columns with various formats
        applicable_columns = []
        for col in df.columns:
            if any(
                col.startswith(prefix)
                for prefix in [
                    "Applicable for",
                    "Available for",
                    "applicable_for_",
                    "available_for_",
                ]
            ):
                applicable_columns.append(col)

        # Extract baseboard names from column names
        baseboards = []
        for col in applicable_columns:
            # Remove various prefixes
            baseboard_name = col
            for prefix in [
                "Applicable for",
                "Available for",
                "applicable_for_",
                "available_for_",
            ]:
                if col.startswith(prefix):
                    baseboard_name = col.replace(prefix, "").strip().strip("\n")
                    break
            baseboards.append(baseboard_name)

        # Build applicability dictionary
        applicability = {}
        for _, row in df.iterrows():
            collector_id = row.get("ID", "")
            if not collector_id:
                continue

            applicability[collector_id] = {}
            for col in applicable_columns:
                # Extract baseboard name
                baseboard_name = col
                for prefix in [
                    "Applicable for",
                    "Available for",
                    "applicable_for_",
                    "available_for_",
                ]:
                    if col.startswith(prefix):
                        baseboard_name = col.replace(prefix, "").strip().strip("\n")
                        break

                # Get value and check applicability
                cell_value = row.get(col, "N/A")
                applicability[collector_id][baseboard_name] = _is_applicable_value(
                    cell_value
                )

        return applicability

    except Exception as e:
        raise ValueError(
            f"Error reading all collector applicability from spreadsheet: {e}"
        )


def _normalize_column_name(column_name: str) -> str:
    """
    Normalize column name to standard format.

    Args:
        column_name (str): Column name to normalize.

    Returns:
        str: Normalized column name in format "Applicable for {baseboard}".
    """
    # Remove common variations and normalize to "Applicable for {baseboard}"
    for prefix in ["applicable_for_", "available_for_", "Available for"]:
        if column_name.startswith(prefix):
            baseboard = column_name.replace(prefix, "").strip().strip("\n")
            return f"Applicable for {baseboard}"

    # If it already starts with "Applicable for", return as is
    if column_name.startswith("Applicable for"):
        return column_name

    return column_name


def _normalize_applicability_value(value) -> str:
    """
    Normalize applicability value to 'Yes' or 'N/A'.

    Args:
        value: Value to normalize (bool, str, or None).

    Returns:
        str: Normalized value ('Yes' or 'N/A').
    """
    if isinstance(value, bool):
        return "Yes" if value else "N/A"
    elif isinstance(value, str):
        value = value.strip().lower()
        if value in ["yes", "true", "1", "y", "applicable", "available"]:
            return "Yes"
        else:
            return "N/A"
    elif value is None:
        return "N/A"
    else:
        # Handle pandas NaN values
        try:
            if pd.isna(value):
                return "N/A"
        except (ImportError, NameError):
            # If pandas is not available, just check for None
            pass

        # Try to convert to string and check
        value = str(value).strip().lower()
        if value in ["yes", "true", "1", "y", "applicable", "available"]:
            return "Yes"
        else:
            return "N/A"


def _is_applicable_value(value) -> bool:
    """
    Check if a value indicates applicability.

    Args:
        value: Value to check (bool, str, or None).

    Returns:
        bool: True if value indicates applicability.
    """
    if isinstance(value, bool):
        return value
    elif isinstance(value, str):
        value = value.strip().lower()
        return value in ["yes", "true", "1", "y", "applicable", "available"]
    elif value is None:
        return False
    else:
        # Handle pandas NaN values
        try:
            if pd.isna(value):
                return False
        except (ImportError, NameError):
            # If pandas is not available, just check for None
            pass

        # Try to convert to string and check
        value = str(value).strip().lower()
        return value in ["yes", "true", "1", "y", "applicable", "available"]


def auto_assign_config_file_to_use(
    dut_config_file: Path, config_files: List[Optional[Path]]
) -> Path:
    """
    Automatically assign ConfigFileToUse to DUTs that don't have baseboard defined.
    ONLY if they don't already have ConfigFileToUse specified.

    This function implements the automation logic:
    1. If a user defines baseboard or TargetBaseboard in config.yaml/tool_config.yaml
    2. It will auto-assign ConfigFileToUse for any DUTs that don't have baseboard defined
    3. No ConfigFileToUse is required for this automation
    4. User-defined baseboard or ConfigFileToUse takes priority

    Args:
        dut_config_file: Path to the DUT configuration file
        config_files: List of config file paths (config.yaml, tool_config.yaml)

    Returns:
        Path to the DUT config file (original or temporary modified version)
    """
    # Read existing DUT config
    try:
        with open(dut_config_file, "r", encoding="utf-8") as f:
            dut_data = yaml.safe_load(f)
    except Exception as e:
        print(
            _sanitize_print_message(
                f"Warning: Could not read DUT config file '{dut_config_file}': {e}"
            )
        )
        return dut_config_file

    if not dut_data or not isinstance(dut_data, dict):
        return dut_config_file

    # Find the first config file that has baseboard information
    config_file_to_use = None
    for config_file in config_files:
        if config_file and config_file.exists():
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    config_data = yaml.safe_load(f)

                # Check for baseboard (new format) or TargetBaseboard (legacy)
                baseboard = config_data.get("baseboard") or config_data.get(
                    "TargetBaseboard"
                )
                if baseboard:
                    config_file_to_use = str(config_file)
                    print(
                        _sanitize_print_message(
                            f"Auto-detected baseboard '{baseboard}' from config file: {config_file}"
                        )
                    )
                    break
            except Exception as e:
                print(
                    _sanitize_print_message(
                        f"Warning: Could not read config file '{config_file}': {e}"
                    )
                )
                continue

    # If we found a config file, assign it to DUTs that need it
    if config_file_to_use:
        modified = False

        # Check each DUT
        for dut_name, dut_config in dut_data.items():
            if dut_name != "DUT_Defaults" and isinstance(dut_config, dict):
                # ONLY assign if:
                # 1. DUT has no baseboard defined (user hasn't specified one)
                # 2. DUT has no ConfigFileToUse defined (user hasn't specified one)
                if not dut_config.get("baseboard") and not dut_config.get(
                    "ConfigFileToUse"
                ):

                    dut_config["ConfigFileToUse"] = config_file_to_use
                    modified = True
                    print(
                        _sanitize_print_message(
                            f"Auto-assigned ConfigFileToUse '{config_file_to_use}' to DUT '{dut_name}' (no baseboard or ConfigFileToUse defined)"
                        )
                    )

        # If we made changes, write to temporary file
        if modified:
            try:
                # Create temporary file in proper temp directory with unique name
                temp_fd, temp_path = tempfile.mkstemp(
                    prefix="dut_config_", suffix=".yaml", text=True
                )
                temp_file = Path(temp_path)

                # Write the modified config to the temp file
                with open(temp_file, "w", encoding="utf-8") as f:
                    yaml.dump(dut_data, f, default_flow_style=False, sort_keys=False)

                # Close the file descriptor (tempfile.mkstemp keeps it open)
                os.close(temp_fd)

                print(
                    _sanitize_print_message(
                        f"Created temporary DUT config file: {temp_file}"
                    )
                )
                return temp_file
            except Exception as e:
                print(
                    _sanitize_print_message(
                        f"Warning: Could not create temporary DUT config file: {e}"
                    )
                )
                return dut_config_file

    return dut_config_file
