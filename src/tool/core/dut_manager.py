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
DUT Manager - Handles DUT connections and operations.

Manages Device Under Test (DUT) instances including connection pooling, service
initialization, platform detection, and execution orchestration across multiple
DUTs with support for various access methods (Redfish, IPMI, SSH, HMC).
"""

import asyncio
import json
import logging
import os
import platform
import random
import re
import shlex
import ssl
import string
import subprocess
import tarfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import aiohttp
import asyncssh
import paramiko
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

from ..services.auto_detection_service import AutoDetectionService
from ..services.dynamic_discovery_service import DynamicDiscoveryService
from ..services.hmc_service import HMCService
from ..services.platform_detection_service import PlatformDetectionService
from ..services.ssh_proxy_service import SSHProxyService
from ..utils.yaml_manager import YAMLManager
from .async_logger import AsyncSafeLogger
from .baseboard_manager import BaseboardManager

logger = logging.getLogger(__name__)


class RedfishSessionPool:
    """
    Manages a single high-performance Redfish session with connection pooling.

    Provides efficient HTTP session management with connection pooling, keep-alive,
    and automatic retry for Redfish API requests.

    Attributes:
        dut_id (str): DUT identifier.
        connection_info (Dict[str, Any]): Connection configuration.
        logger: Logger instance.
        session: aiohttp ClientSession.
        auth: Authentication tuple.
        connector: aiohttp TCPConnector.
    """

    def __init__(
        self,
        dut_id: str,
        connection_info: Dict[str, Any],
        logger=None,
        session_config: Dict[str, Any] = None,
    ):
        """
        Initialize Redfish session pool.

        Args:
            dut_id (str): DUT identifier.
            connection_info (Dict[str, Any]): Connection info with host/credentials.
            logger: Logger instance.
            session_config (Dict[str, Any]): Session configuration options.
        """
        self.dut_id = dut_id
        self.connection_info = connection_info
        self.logger = logger
        self.session = None
        self.auth = None
        self.connector = None
        self._lock = asyncio.Lock()
        self._initialized = False

        # Add unique instance identifier to prevent session conflicts
        self.instance_id = f"{os.getpid()}_{int(time.time() * 1000) % 10000}"

        # Session configuration with defaults
        self.session_config = session_config or {}
        self.connection_pool_limit = self.session_config.get(
            "connection_pool_limit", 20
        )
        self.connection_pool_limit_per_host = self.session_config.get(
            "connection_pool_limit_per_host", 8
        )
        self.session_timeout = self.session_config.get("session_timeout", 300)
        self.keepalive_timeout = self.session_config.get("keepalive_timeout", 300)
        self.ssl = self.session_config.get("ssl", False)
        self.ttl_dns_cache = self.session_config.get("ttl_dns_cache", 300)
        self.use_dns_cache = self.session_config.get("use_dns_cache", True)
        self.force_close = self.session_config.get("force_close", False)
        self.enable_cleanup_closed = self.session_config.get(
            "enable_cleanup_closed", True
        )

    async def _log_runtime(self, level: str, message: str) -> None:
        """
        Log message using async logger if available.

        Args:
            level: Log level (ERROR, WARNING, INFO, DEBUG).
            message: Message to log.
        """
        if self.logger and hasattr(self.logger, "write_to_dut_runtime_log"):
            await self.logger.write_to_dut_runtime_log(
                self.dut_id, level, "RedfishSessionPool", message
            )
        else:
            if level == "ERROR":
                logger.error(f"[{self.dut_id}] {message}")
            elif level == "WARNING":
                logger.warning(f"[{self.dut_id}] {message}")
            else:
                logger.info(f"[{self.dut_id}] {message}")

    async def initialize(self) -> bool:
        """
        Initialize the high-performance session with connection pooling.

        Returns:
            True if initialization successful, False otherwise.
        """
        try:
            if self._initialized:
                return True

            await self._log_runtime(
                "INFO",
                "Initializing high-performance Redfish session with connection pooling",
            )

            # Create connector with fully configurable settings
            self.connector = aiohttp.TCPConnector(
                ssl=self.ssl,  # Configurable SSL verification
                limit=self.connection_pool_limit,  # Configurable total connection pool size
                limit_per_host=self.connection_pool_limit_per_host,  # Configurable connections per host
                ttl_dns_cache=self.ttl_dns_cache,  # Configurable DNS cache TTL
                use_dns_cache=self.use_dns_cache,  # Configurable DNS caching
                force_close=self.force_close,  # Configurable connection reuse
                enable_cleanup_closed=self.enable_cleanup_closed,  # Configurable cleanup
                keepalive_timeout=self.keepalive_timeout,  # Configurable keepalive timeout
            )

            # Create session with persistent settings
            self.session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=aiohttp.ClientTimeout(
                    total=self.session_timeout
                ),  # Configurable session timeout
                headers={"User-Agent": f"nvdebug/1.0-instance-{self.instance_id}"},
            )

            # Setup authentication
            username = self.connection_info["username"]
            password = self.connection_info["password"]
            self.auth = aiohttp.BasicAuth(username, password)

            # Test the session with a simple request
            protocol = "https" if self.connection_info["use_https"] else "http"
            test_url = f"{protocol}://{self.connection_info['host']}:{self.connection_info['port']}/redfish/v1"

            async with self.session.get(
                test_url, auth=self.auth, ssl=False
            ) as response:
                if response.status == 200:
                    self._initialized = True
                    await self._log_runtime(
                        "INFO",
                        "High-performance Redfish session initialized successfully",
                    )
                    return True
                else:
                    await self._log_runtime(
                        "ERROR",
                        f"Redfish session test failed: HTTP {response.status}",
                    )
                    await self.cleanup()
                    return False

        except Exception as e:
            await self._log_runtime(
                "ERROR", f"Failed to initialize Redfish session: {str(e)}"
            )
            await self.cleanup()
            return False

    async def get_session(self) -> Optional[Dict[str, Any]]:
        """
        Get the high-performance session (no locking needed - shared session).

        Returns:
            Dictionary containing session and auth, or None if not initialized.
        """
        if not self._initialized or (self.session and self.session.closed):
            # Session is not initialized or has been closed, reinitialize
            await self._log_runtime(
                "DEBUG",
                f"Session not initialized or closed, reinitializing (instance: {self.instance_id})",
            )
            success = await self.initialize()
            if not success:
                return None

        # Return the shared session - aiohttp handles connection pooling internally
        return {
            "session": self.session,
            "auth": self.auth,
            "connector": self.connector,
        }

    async def release_session(self, session_obj: Dict[str, Any]) -> None:
        """
        Release session back to pool (no-op for shared session).

        Args:
            session_obj: Session object to release.
        """
        # No-op - shared session doesn't need release
        pass

    async def handle_session_conflict(self, error: Exception) -> bool:
        """
        Handle session conflicts by reinitializing the session.

        Args:
            error: Exception that triggered the conflict.

        Returns:
            True if session was reinitialized successfully.
        """
        # Check if session conflict handling is enabled
        if not self.session_config.get("handle_session_conflicts", True):
            return False

        error_str = str(error).lower()
        if any(
            keyword in error_str
            for keyword in ["session", "closed", "unauthorized", "forbidden"]
        ):
            await self._log_runtime(
                "WARNING",
                f"Detected potential session conflict, reinitializing session (instance: {self.instance_id})",
            )
            # Force reinitialize the session
            self._initialized = False
            if self.session and not self.session.closed:
                await self.session.close()
            self.session = None
            return True
        return False

    async def cleanup(self) -> None:
        """
        Clean up the session and close connections.
        """
        try:
            if self.session and not self.session.closed:
                await self.session.close()
            self.session = None
            if self.connector and not self.connector.closed:
                await self.connector.close()
            self.connector = None
            self._initialized = False
            await self._log_runtime("INFO", "Redfish session cleaned up")
        except Exception as e:
            await self._log_runtime("ERROR", f"Error cleaning up session: {str(e)}")
            # Ensure state is reset even if cleanup fails
            self._initialized = False
            self.session = None
            self.connector = None

    async def get_session_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the session.

        Returns:
            Dictionary of session statistics.
        """
        if self.session and self.connector:
            return {
                "initialized": self._initialized,
                "connection_limit": self.connector.limit,
                "connection_limit_per_host": self.connector.limit_per_host,
                "total_connections": (
                    len(self.connector._resolver_cache)
                    if hasattr(self.connector, "_resolver_cache")
                    else 0
                ),
                "active_connections": (
                    len(self.connector._acquired)
                    if hasattr(self.connector, "_acquired")
                    else 0
                ),
            }
        else:
            return {
                "initialized": False,
                "connection_limit": 0,
                "connection_limit_per_host": 0,
                "total_connections": 0,
                "active_connections": 0,
            }


class DUTCredentials:
    """
    DUT credentials and connection information.

    Attributes:
        bmc_ip: BMC IP address.
        bmc_username: BMC username.
        bmc_password: BMC password.
    """

    def __init__(
        self,
        bmc_ip: str,
        bmc_username: str,
        bmc_password: str,
        bmc_ssh_username: Optional[str] = None,
        bmc_ssh_password: Optional[str] = None,
        bmc_ssh_port: int = 22,
        bmc_ssh_key_path: Optional[str] = None,
        bmc_ssh_passwordless: bool = False,
        bmc_ssh_max_retries: int = 3,
        bmc_rf_port: int = 443,
        bmc_use_https: bool = True,
        bmc_rf_verify_ssl: bool = False,
        host_ip: Optional[str] = None,
        host_username: Optional[str] = None,
        host_password: Optional[str] = None,
        host_ssh_port: int = 22,
        host_ssh_key_path: Optional[str] = None,
        host_ssh_passwordless: bool = False,
        host_ssh_max_retries: int = 3,
        rf_username: Optional[str] = None,
        rf_password: Optional[str] = None,
        tunnel_tcp_port: Optional[int] = None,
        ipmi_cipher: str = "-C17",
        # HMC Configuration
        hmc_ip: Optional[str] = None,
        hmc_username: Optional[str] = None,
        hmc_password: Optional[str] = None,
        hmc_ssh_username: Optional[str] = None,
        hmc_ssh_password: Optional[str] = None,
        hmc_ssh_port: int = 22,
        hmc_ssh_key_path: Optional[str] = None,
        hmc_ssh_passwordless: bool = False,
        hmc_ssh_max_retries: int = 3,
        hmc_http_port: int = 80,
        hmc_https_port: int = 443,
        hmc_use_https: bool = False,
        use_port_forwarding: bool = False,
        rf_hmc_access_method: Optional[str] = None,
        execution_mode: str = "remote",
        # SSH Proxy Configuration
        ssh_proxy_host: Optional[str] = None,
        ssh_proxy_port: int = 22,
        ssh_proxy_username: Optional[str] = None,
        ssh_proxy_password: Optional[str] = None,
        ssh_proxy_key_path: Optional[str] = None,
        ssh_proxy_passwordless: bool = False,
        ssh_proxy_max_retries: int = 3,
    ) -> None:
        """
        Initialize DUT credentials and connection information.

        Args:
            bmc_ip: BMC IP address.
            bmc_username: BMC username.
            bmc_password: BMC password.
            bmc_ssh_username: BMC SSH username.
            bmc_ssh_password: BMC SSH password.
            bmc_ssh_port: BMC SSH port.
            bmc_ssh_key_path: BMC SSH key path.
            bmc_ssh_passwordless: BMC SSH passwordless.
            bmc_ssh_max_retries: BMC SSH max retries.
            bmc_rf_port: BMC Redfish port.
            bmc_use_https: BMC use HTTPS.
            bmc_rf_verify_ssl: BMC Redfish verify SSL.
            host_ip: Host IP address.
            host_username: Host username.
            host_password: Host password.
            host_ssh_port: Host SSH port.
            host_ssh_key_path: Host SSH key path.
            host_ssh_passwordless: Host SSH passwordless.
            host_ssh_max_retries: Host SSH max retries.
            rf_username: Redfish username.
            rf_password: Redfish password.
            tunnel_tcp_port: Tunnel TCP port.
            ipmi_cipher: IPMI cipher.
            hmc_ip: HMC IP address.
            hmc_username: HMC username.
            hmc_password: HMC password.
            hmc_ssh_username: HMC SSH username.
            hmc_ssh_password: HMC SSH password.
            hmc_ssh_port: HMC SSH port.
            hmc_ssh_key_path: HMC SSH key path.
            hmc_ssh_passwordless: HMC SSH passwordless.
            hmc_ssh_max_retries: HMC SSH max retries.
            hmc_http_port: HMC HTTP port.
            hmc_https_port: HMC HTTPS port.
            hmc_use_https: HMC use HTTPS.
            use_port_forwarding: Use port forwarding.
            rf_hmc_access_method: Redfish HMC access method.
            execution_mode: Execution mode.
            ssh_proxy_host: SSH proxy host.
            ssh_proxy_port: SSH proxy port.
            ssh_proxy_username: SSH proxy username.
            ssh_proxy_password: SSH proxy password.
            ssh_proxy_key_path: SSH proxy key path.
            ssh_proxy_passwordless: SSH proxy passwordless.
            ssh_proxy_max_retries: SSH proxy max retries.
        """
        self.bmc_ip = bmc_ip
        self.bmc_username = bmc_username
        self.bmc_password = bmc_password
        self.bmc_ssh_username = bmc_ssh_username
        self.bmc_ssh_password = bmc_ssh_password
        self.bmc_ssh_port = bmc_ssh_port
        self.bmc_ssh_key_path = bmc_ssh_key_path
        self.bmc_ssh_passwordless = bmc_ssh_passwordless
        self.bmc_ssh_max_retries = bmc_ssh_max_retries
        self.bmc_rf_port = bmc_rf_port
        self.bmc_use_https = bmc_use_https
        self.bmc_rf_verify_ssl = bmc_rf_verify_ssl
        self.host_ip = host_ip
        self.host_username = host_username
        self.host_password = host_password
        self.host_ssh_port = host_ssh_port
        self.host_ssh_key_path = host_ssh_key_path
        self.host_ssh_passwordless = host_ssh_passwordless
        self.host_ssh_max_retries = host_ssh_max_retries
        self.rf_username = rf_username
        self.rf_password = rf_password
        self.tunnel_tcp_port = tunnel_tcp_port
        self.ipmi_cipher = ipmi_cipher
        # HMC Configuration
        self.hmc_ip = hmc_ip
        self.hmc_username = hmc_username or bmc_username
        self.hmc_password = hmc_password or bmc_password
        self.hmc_ssh_username = hmc_ssh_username or bmc_ssh_username or bmc_username
        self.hmc_ssh_password = hmc_ssh_password or bmc_ssh_password or bmc_password
        self.hmc_ssh_port = hmc_ssh_port
        self.hmc_ssh_key_path = hmc_ssh_key_path
        self.hmc_ssh_passwordless = hmc_ssh_passwordless
        self.hmc_ssh_max_retries = hmc_ssh_max_retries
        self.hmc_http_port = hmc_http_port
        self.hmc_https_port = hmc_https_port
        self.hmc_use_https = hmc_use_https
        self.use_port_forwarding = use_port_forwarding
        self.rf_hmc_access_method = rf_hmc_access_method
        self.execution_mode = execution_mode
        # SSH Proxy Configuration
        self.ssh_proxy_host = ssh_proxy_host
        self.ssh_proxy_port = ssh_proxy_port
        self.ssh_proxy_username = ssh_proxy_username
        self.ssh_proxy_password = ssh_proxy_password
        self.ssh_proxy_key_path = ssh_proxy_key_path
        self.ssh_proxy_passwordless = ssh_proxy_passwordless
        self.ssh_proxy_max_retries = ssh_proxy_max_retries


class DUTConnectionState:
    """
    DUT connection state tracking.

    Attributes:
        redfish_connected: Redfish connection state.
        ipmi_connected: IPMI connection state.
        ssh_connected: SSH connection state.
        host_connected: Host connection state.
        hmc_connected: HMC connection state.
        port_forwarding_active: Port forwarding active state.
        last_redfish_check: Last Redfish check time.
        last_ipmi_check: Last IPMI check time.
        last_ssh_check: Last SSH check time.
        last_host_check: Last host check time.
        last_hmc_check: Last HMC check time.
    """

    def __init__(self) -> None:
        """
        Initialize DUT connection state.

        Attributes:
            redfish_connected: Redfish connection state.
            ipmi_connected: IPMI connection state.
            ssh_connected: SSH connection state.
            host_connected: Host connection state.
            hmc_connected: HMC connection state.
            port_forwarding_active: Port forwarding active state.
            last_redfish_check: Last Redfish check time.
            last_ipmi_check: Last IPMI check time.
            last_ssh_check: Last SSH check time.
            last_host_check: Last host check time.
            last_hmc_check: Last HMC check time.
        """
        self.redfish_connected = False
        self.ipmi_connected = False
        self.ssh_connected = False
        self.host_connected = False
        self.hmc_connected = False
        self.port_forwarding_active = False
        self.last_redfish_check: Optional[datetime] = None
        self.last_ipmi_check: Optional[datetime] = None
        self.last_ssh_check: Optional[datetime] = None
        self.last_host_check: Optional[datetime] = None
        self.last_hmc_check: Optional[datetime] = None

    def set_host_connected(self, connected: bool, dut_id: str = None) -> None:
        """
        Set host connection state with logging.

        Args:
            connected: Host connection state.
            dut_id: DUT ID.
        """
        if self.host_connected != connected:
            if dut_id:
                pass
                # print(
                #     f"[DEBUG] DUT {dut_id}: Host connection state changing from {self.host_connected} to {connected}"
                # )
        self.host_connected = connected

    def set_ssh_connected(self, connected: bool, dut_id: str = None) -> None:
        """
        Set SSH connection state with logging.

        Args:
            connected: SSH connection state.
            dut_id: DUT ID.
        """
        if self.ssh_connected != connected:
            if dut_id:
                pass
                # print(
                #     f"[DEBUG] DUT {dut_id}: SSH connection state changing from {self.ssh_connected} to {connected}"
                # )
        self.ssh_connected = connected

    def set_redfish_connected(self, connected: bool, dut_id: str = None) -> None:
        """
        Set Redfish connection state with logging.

        Args:
            connected: Redfish connection state.
            dut_id: DUT ID.
        """
        if self.redfish_connected != connected:
            if dut_id:
                pass
                # print(
                #     f"[DEBUG] DUT {dut_id}: Redfish connection state changing from {self.redfish_connected} to {connected}"
                # )
        self.redfish_connected = connected

    def set_ipmi_connected(self, connected: bool, dut_id: str = None) -> None:
        """
        Set IPMI connection state with logging.

        Args:
            connected: IPMI connection state.
            dut_id: DUT ID.
        """
        if self.ipmi_connected != connected:
            if dut_id:
                pass
                # print(
                #     f"[DEBUG] DUT {dut_id}: IPMI connection state changing from {self.ipmi_connected} to {connected}"
                # )
        self.ipmi_connected = connected

    def set_hmc_connected(self, connected: bool, dut_id: str = None) -> None:
        """
        Set HMC connection state with logging.

        Args:
            connected: HMC connection state.
            dut_id: DUT ID.
        """
        if self.hmc_connected != connected:
            if dut_id:
                pass
                # print(
                #     f"[DEBUG] DUT {dut_id}: HMC connection state changing from {self.hmc_connected} to {connected}"
                # )
        self.hmc_connected = connected


class DUT:
    """
    Device Under Test (DUT) class.

    Attributes:
        dut_id: DUT ID.
        credentials: DUT credentials.
        config: DUT configuration.
        dut_manager: DUT manager.
    """

    def __init__(
        self,
        dut_id: str,
        credentials: DUTCredentials,
        config: Dict[str, Any],
        dut_manager: Optional["DUTManager"] = None,
    ) -> None:
        """
        Initialize DUT.

        Args:
            dut_id: DUT ID.
            credentials: DUT credentials.
            config: DUT configuration.
            dut_manager: DUT manager.
        """
        self.dut_id = dut_id
        self.credentials = credentials
        self.config = config
        self.connection_state = DUTConnectionState()
        self.log_dir: Optional[Path] = None
        self.hmc_service = None  # Will be set if HMC mode is active
        self.platform_info: Optional[Dict[str, str]] = None
        self.dut_manager = dut_manager  # Reference to DUT manager for SSH operations

        # Check if this is HGX-HMC platform (will be set in async_init)
        self.is_hmc_platform = False

        # Auto-configure HMC settings (will be done in async_init)

        # Redfish session management
        self.redfish_session = None
        self.redfish_auth = None
        self.redfish_connector = None
        self.redfish_session_pool = None  # Will be initialized when needed

        # Redfish caching
        self.__redfish_cache = {}

        # Redfish prefix configuration
        self.redfish_default_prefix = self.config.get(
            "RF_DEFAULT_PREFIX", "/redfish/v1"
        )

        # Track which config keys were explicitly set in the DUT YAML (not from defaults)
        # Dictionary format: {key_name: True/False} where True means it was in the DUT YAML
        self.explicit_config_keys: Dict[str, bool] = {}

    def has_explicit_config_key(self, key: str) -> bool:
        """
        Check if a config key was explicitly set in the DUT YAML (not from defaults)

        Args:
            key: Config key.
        """
        return self.explicit_config_keys.get(key, False)

    async def async_init(self) -> None:
        """
        Async initialization - detect HMC platform and configure settings.

        Args:
            dut_id: DUT ID.
            credentials: DUT credentials.
            config: DUT configuration.
            dut_manager: DUT manager.
        """
        # Check if this is HGX-HMC platform
        self.is_hmc_platform = await self._detect_hmc_platform()

        # Auto-configure HMC settings
        if self.is_hmc_platform:
            self._configure_hmc_settings()

        # Initialize Redfish session pool for better concurrency
        await self.initialize_redfish_session_pool()

        # Log initial session pool status
        if self.redfish_session_pool:
            stats = await self.redfish_session_pool.get_session_stats()
            await self._log_runtime("INFO", f"Session pool initialized: {stats}")

    async def _log_runtime(self, level: str, message: str) -> None:
        """
        Log message to DUT runtime file using async logger if available

        Args:
            level: Log level.
            message: Log message.
        """
        if hasattr(self, "logger") and hasattr(self.logger, "write_to_dut_runtime_log"):
            await self.logger.write_to_dut_runtime_log(
                self.dut_id, level, "DUT", message
            )
        else:
            # Fallback to regular logger if async logger not available
            if level == "ERROR":
                logger.error(message)
            elif level == "WARNING":
                logger.warning(message)
            else:
                logger.info(message)

    async def create_redfish_session(self) -> bool:
        """
        Create persistent Redfish session - uses session pool.

        Args:
            level: Log level.
            message: Log message.
        """
        try:
            if self.redfish_session is not None:
                return True  # Session already exists

            await self._log_runtime("INFO", "Testing Redfish session pool")

            # Get connection info (handles HMC transparency)
            connection_info = self.get_redfish_connection_info()

            # Setup authentication for session pool
            username = connection_info["username"]
            password = connection_info["password"]
            self.redfish_auth = aiohttp.BasicAuth(username, password)

            # Test the session pool with a simple request
            protocol = "https" if connection_info["use_https"] else "http"
            test_url = f"{protocol}://{connection_info['host']}:{connection_info['port']}/redfish/v1"

            # Use the session pool instead of creating a separate session
            if self.redfish_session_pool:
                # Test using session pool
                session_obj = await self.redfish_session_pool.get_session()
                if session_obj:
                    try:
                        async with session_obj["session"].get(
                            test_url, auth=session_obj["auth"], ssl=False
                        ) as response:
                            if response.status == 200:
                                await self._log_runtime(
                                    "INFO",
                                    "Redfish session pool test successful",
                                )
                                return True
                            else:
                                await self._log_runtime(
                                    "ERROR",
                                    f"Redfish session pool test failed: HTTP {response.status}",
                                )
                                return False
                    except Exception as e:
                        raise e
                else:
                    await self._log_runtime(
                        "ERROR", "Failed to get session from pool for testing"
                    )
                    return await self._create_fallback_session(connection_info)
            else:
                await self._log_runtime(
                    "WARNING", "Session pool not available, using fallback"
                )
                return await self._create_fallback_session(connection_info)

        except Exception as e:
            await self._log_runtime(
                "ERROR", f"Failed to create Redfish session: {str(e)}"
            )
            return await self._create_fallback_session(connection_info)

    async def _create_fallback_session(self, connection_info: Dict[str, Any]) -> bool:
        """
        Create fallback session when session pool is not available.

        Args:
            connection_info: Connection info.
        """
        try:
            await self._log_runtime("INFO", "Creating fallback Redfish session")

            # Create connector with optimized settings
            self.redfish_connector = aiohttp.TCPConnector(
                ssl=self.redfish_ssl,  # Configurable SSL verification
                limit=self.redfish_fallback_connection_pool_limit,  # Configurable fallback connection pool size
                limit_per_host=self.redfish_fallback_connection_pool_limit_per_host,  # Configurable fallback connections per host
                ttl_dns_cache=self.redfish_ttl_dns_cache,  # Configurable DNS cache TTL
                use_dns_cache=self.redfish_use_dns_cache,  # Configurable DNS caching
                force_close=self.redfish_force_close,  # Configurable connection reuse
                enable_cleanup_closed=self.redfish_enable_cleanup_closed,  # Configurable cleanup
                keepalive_timeout=self.redfish_keepalive_timeout,  # Configurable keepalive timeout
            )

            # Create session with persistent settings
            self.redfish_session = aiohttp.ClientSession(
                connector=self.redfish_connector,
                timeout=aiohttp.ClientTimeout(
                    total=self.redfish_session_timeout
                ),  # Configurable session timeout
                headers={"User-Agent": "nvdebug/1.0"},
            )

            # Test the session with a simple request
            protocol = "https" if connection_info["use_https"] else "http"
            test_url = f"{protocol}://{connection_info['host']}:{connection_info['port']}/redfish/v1"

            async with self.redfish_session.get(
                test_url, auth=self.redfish_auth, ssl=False
            ) as response:
                if response.status == 200:
                    await self._log_runtime(
                        "INFO", "Fallback Redfish session created successfully"
                    )
                    return True
                else:
                    await self._log_runtime(
                        "ERROR",
                        f"Fallback Redfish session test failed: HTTP {response.status}",
                    )
                    await self.close_redfish_session()
                    return False

        except Exception as e:
            await self._log_runtime(
                "ERROR", f"Failed to create fallback Redfish session: {str(e)}"
            )
            await self.close_redfish_session()
            return False

    async def initialize_redfish_session_pool(self) -> bool:
        """
        Initialize the high-performance Redfish session pool.

        Args:
            level: Log level.
            message: Log message.
        """
        try:
            if self.redfish_session_pool is not None:
                return True  # Pool already exists

            await self._log_runtime(
                "INFO", "Initializing high-performance Redfish session pool"
            )

            # Get connection info (handles HMC transparency)
            connection_info = self.get_redfish_connection_info()

            # Create session pool with configuration
            self.redfish_session_pool = RedfishSessionPool(
                self.dut_id, connection_info, self.logger, self.redfish_session_config
            )

            # Initialize the high-performance session
            success = await self.redfish_session_pool.initialize()
            if success:
                await self._log_runtime(
                    "INFO",
                    "High-performance Redfish session pool initialized successfully",
                )
                return True
            else:
                await self._log_runtime(
                    "ERROR",
                    "Failed to initialize high-performance session pool",
                )
                return False

        except Exception as e:
            await self._log_runtime(
                "ERROR", f"Failed to initialize Redfish session pool: {str(e)}"
            )
            return False

    async def close_redfish_session(self) -> None:
        """
        Close Redfish session.

        Args:
            level: Log level.
            message: Log message.
        """
        try:
            # Close session pool first
            if self.redfish_session_pool:
                await self.redfish_session_pool.cleanup()
                self.redfish_session_pool = None
                await self._log_runtime("INFO", "Redfish session pool closed")

            # Close legacy single session
            if self.redfish_session:
                await self.redfish_session.close()
                self.redfish_session = None
                await self._log_runtime("INFO", "Redfish session closed")

            if self.redfish_connector:
                await self.redfish_connector.close()
                self.redfish_connector = None

        except Exception as e:
            await self._log_runtime("ERROR", f"Error closing Redfish session: {str(e)}")

    def normalize_redfish_uri(self, uri: str, ignore_prefix: bool = False) -> str:
        """
        Normalize Redfish URI with prefix handling.

        Args:
            uri: URI to normalize.
            ignore_prefix: Whether to ignore the prefix.
        """
        if ignore_prefix:
            return uri

        # Handle relative URIs - add prefix if URI doesn't start with a slash or http
        if not uri.startswith("/") and not uri.startswith("http"):
            # This is a relative URI like "Managers" - add the prefix
            uri = f"{self.redfish_default_prefix}/{uri}"
            asyncio.create_task(
                self._log_runtime("DEBUG", f"Added prefix to relative URI: {uri}")
            )
        elif (
            self.redfish_default_prefix != "/redfish/v1"
            and not uri.startswith(self.redfish_default_prefix)
            and "redfish/v1" in uri
        ):
            # Handle prefix substitution
            # Substitute prefix up to /redfish/v1 with the configured prefix
            uri = re.sub(r"(\S)*redfish/v1", self.redfish_default_prefix, uri, 1)
            asyncio.create_task(self._log_runtime("DEBUG", f"Normalized URI: {uri}"))

        return uri

    def reset_redfish_cache(self) -> None:
        """
        Reset Redfish cache.

        Args:
            level: Log level.
            message: Log message.
        """
        self.__redfish_cache.clear()
        asyncio.create_task(self._log_runtime("INFO", "Redfish cache cleared"))

    def get_redfish_cache(self) -> Dict[str, Any]:
        """
        Get Redfish cache.

        Args:
            level: Log level.
            message: Log message.
        """
        return self.__redfish_cache.copy()

    def _get_cached_response(self, uri: str) -> Optional[Any]:
        """
        Get cached response for URI.

        Args:
            uri: URI to get cached response for.
        """
        return self.__redfish_cache.get(uri)

    def _cache_response(self, uri: str, response: Any) -> None:
        """
        Cache response for URI.

        Args:
            uri: URI to cache response for.
            response: Response to cache.
        """
        self.__redfish_cache[uri] = response

    async def setup_logging(self, base_log_dir: Path) -> None:
        """
        Setup logging directory for this DUT.

        Args:
            base_log_dir: Base log directory.
        """
        # Debug logging
        await self._log_runtime(
            "INFO",
            f"setup_logging: self.dut_id = {self.dut_id} (type: {type(self.dut_id)})",
        )
        await self._log_runtime(
            "INFO",
            f"setup_logging: base_log_dir = {base_log_dir} (type: {type(base_log_dir)})",
        )

        self.log_dir = base_log_dir / self.dut_id
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories for different log types
        for subdir in ["redfish", "ipmi", "host", "ssh", "error-logs"]:
            (self.log_dir / subdir).mkdir(exist_ok=True)

    async def test_redfish_connection(self) -> Tuple[bool, str]:
        """
        Test Redfish connection using ping first, then HTTP if ping succeeds.

        Args:
            level: Log level.
            message: Log message.
        """
        connector = None
        try:
            # Debug logging
            await self._log_runtime(
                "DEBUG",
                f"test_redfish_connection called for DUT {self.dut_id}",
            )
            await self._log_runtime("DEBUG", f"is_hmc_platform: {self.is_hmc_platform}")
            await self._log_runtime("DEBUG", f"hmc_ip: {self.credentials.hmc_ip}")
            await self._log_runtime(
                "DEBUG", f"execution_mode: {self.credentials.execution_mode}"
            )

            # Handle local mode
            if self.credentials.execution_mode == "local":
                await self._log_runtime(
                    "INFO",
                    "DUT is in local mode, skipping Redfish connection test",
                )
                self.connection_state.set_redfish_connected(True, self.dut_id)
                self.connection_state.last_redfish_check = datetime.now()
                return (
                    True,
                    "Local mode - Redfish connection assumed successful",
                )

            # Handle HMC mode with port forwarding
            if self.is_hmc_platform and self.credentials.hmc_ip:
                await self._log_runtime("DEBUG", "Using HMC port forwarding path")
                return await self._test_redfish_hmc_connection()
            else:
                await self._log_runtime(
                    "DEBUG",
                    f"Using standard BMC path (is_hmc_platform={self.is_hmc_platform}, hmc_ip={self.credentials.hmc_ip})",
                )

            # Standard BMC connection
            # Check if SSH proxy is configured
            await self._log_runtime(
                "DEBUG",
                f"SSH proxy check: ssh_proxy_host={self.credentials.ssh_proxy_host}, ssh_proxy_username={self.credentials.ssh_proxy_username}",
            )
            if self.credentials.ssh_proxy_host:
                await self._log_runtime(
                    "INFO",
                    f"Using SSH proxy {self.credentials.ssh_proxy_host} for Redfish connections",
                )

                # Setup SSH proxy tunneling for Redfish (reuse existing setup if available)
                if not hasattr(self, "ssh_proxy_service") or not self.ssh_proxy_service:
                    ssh_proxy_service = SSHProxyService(
                        logger=self.logger, dut_manager=self.dut_manager
                    )

                    success, tunnel_ports, message = (
                        await ssh_proxy_service.setup_ssh_proxy_tunneling(
                            dut_id=self.dut_id,
                            bmc_ip=self.credentials.bmc_ip,
                            host_ip=self.credentials.host_ip,  # Include host_ip for complete setup
                            ssh_proxy_host=self.credentials.ssh_proxy_host,
                            ssh_proxy_username=self.credentials.ssh_proxy_username,
                            ssh_proxy_password=self.credentials.ssh_proxy_password,
                            ssh_proxy_port=self.credentials.ssh_proxy_port,
                            bmc_redfish_port=self.credentials.bmc_rf_port,
                            bmc_use_https=self.credentials.bmc_use_https,
                            bmc_ipmi_port=623,  # Standard IPMI port
                            host_ssh_port=self.credentials.host_ssh_port,  # Include host_ssh_port for complete setup
                            force_setup=True,
                        )
                    )

                    if not success:
                        return (
                            False,
                            f"Failed to setup SSH proxy tunneling for Redfish: {message}",
                        )

                    # Store the tunnel info for later use
                    self.ssh_proxy_service = ssh_proxy_service
                    self.ssh_proxy_tunnel_ports = tunnel_ports
                else:
                    # Reuse existing tunnel setup
                    success = True
                    tunnel_ports = self.ssh_proxy_tunnel_ports

                await self._log_runtime(
                    "INFO",
                    f"SSH proxy tunneling established for Redfish: localhost:{tunnel_ports['redfish_port']} -> {self.credentials.bmc_ip}:{self.credentials.bmc_rf_port}",
                )
            else:
                # First check if BMC is reachable via ping (only if no proxy)
                ping_success = await self._ping_host(self.credentials.bmc_ip)
                if not ping_success:
                    return (
                        False,
                        f"BMC {self.credentials.bmc_ip} is not reachable via ping",
                    )

            # If ping succeeds (or proxy is used), try HTTP connection with short timeout
            # Determine protocol based on bmc_use_https flag
            protocol = "https" if self.credentials.bmc_use_https else "http"

            if hasattr(self, "ssh_proxy_tunnel_ports") and self.ssh_proxy_tunnel_ports:
                # Use SSH proxy tunnel
                tunnel_port = self.ssh_proxy_tunnel_ports["redfish_port"]
                url = f"{protocol}://localhost:{tunnel_port}/redfish/v1"
                await self._log_runtime(
                    "DEBUG",
                    f"Using SSH proxy tunnel for Redfish: {url}",
                )
            else:
                # Use direct connection
                url = f"{protocol}://{self.credentials.bmc_ip}:{self.credentials.bmc_rf_port}/redfish/v1"
                await self._log_runtime(
                    "DEBUG",
                    f"Using direct connection for Redfish: {url}",
                )

            username = self.credentials.rf_username or self.credentials.bmc_username
            password = self.credentials.rf_password or self.credentials.bmc_password

            # Use aiohttp with retry logic for reliability
            timeout = aiohttp.ClientTimeout(
                total=6,  # Reduced timeout per attempt
                connect=2,  # Connection timeout
                sock_read=4,  # Read timeout
            )

            # Use connector with minimal connection pooling for preflight
            # Determine SSL usage based on bmc_use_https flag (consistent with HMC pattern)
            use_ssl = self.credentials.bmc_use_https

            if use_ssl:
                # HTTPS connection - use SSL context
                if self.credentials.bmc_rf_verify_ssl:
                    # Use default SSL context with certificate verification
                    ssl_context = ssl.create_default_context()
                    await self._log_runtime(
                        "DEBUG",
                        f"Using HTTPS with certificate verification for Redfish connection (port {self.credentials.bmc_rf_port})",
                    )
                else:
                    # Disable SSL certificate verification (default for BMCs)
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    await self._log_runtime(
                        "DEBUG",
                        f"Using HTTPS without certificate verification for Redfish connection (port {self.credentials.bmc_rf_port})",
                    )
            else:
                # HTTP connection - no SSL
                ssl_context = False
                await self._log_runtime(
                    "DEBUG",
                    f"Using HTTP (no SSL) for Redfish connection (port {self.credentials.bmc_rf_port})",
                )

            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=1,  # Single connection limit
                limit_per_host=1,  # Single connection per host
                ttl_dns_cache=300,  # DNS cache TTL
                use_dns_cache=True,
                force_close=True,  # Force close after use
                enable_cleanup_closed=True,  # Clean up closed connections
            )

            # Retry logic for transient failures
            max_retries = 2  # Try up to 3 times total (initial + 2 retries)
            retry_delay = 1  # 1 second between retries

            for attempt in range(max_retries + 1):
                try:
                    async with aiohttp.ClientSession(
                        timeout=timeout, connector=connector
                    ) as session:
                        async with session.get(
                            url,
                            auth=aiohttp.BasicAuth(username, password),
                            headers={"User-Agent": "nvdebug-preflight/1.0"},
                        ) as response:
                            if response.status == 200:
                                # Check if credential validation is enabled in tool_config
                                preflight_config = {}
                                if self.dut_manager and hasattr(
                                    self.dut_manager, "tool_config"
                                ):
                                    preflight_config = self.dut_manager.tool_config.get(
                                        "preflight_config", {}
                                    )

                                # Default to True if not specified
                                validate_creds = preflight_config.get(
                                    "validate_credentials_in_preflight", True
                                )

                                if validate_creds:
                                    # Get the auth URI to test (default to /redfish/v1/Systems)
                                    auth_uri = preflight_config.get(
                                        "credential_validation_uri",
                                        "/redfish/v1/Systems",
                                    )

                                    # Normalize the URI to respect prefix_override configuration
                                    normalized_auth_uri = self.normalize_redfish_uri(
                                        auth_uri
                                    )

                                    await self._log_runtime(
                                        "DEBUG",
                                        f"Validating credentials against authenticated endpoint: {auth_uri} (normalized: {normalized_auth_uri})",
                                    )

                                    # Build the full URL for credential validation
                                    if (
                                        hasattr(self, "ssh_proxy_tunnel_ports")
                                        and self.ssh_proxy_tunnel_ports
                                    ):
                                        tunnel_port = self.ssh_proxy_tunnel_ports[
                                            "redfish_port"
                                        ]
                                        auth_url = f"{protocol}://localhost:{tunnel_port}{normalized_auth_uri}"
                                    else:
                                        auth_url = f"{protocol}://{self.credentials.bmc_ip}:{self.credentials.bmc_rf_port}{normalized_auth_uri}"

                                    # Test the authenticated endpoint
                                    try:
                                        async with session.get(
                                            auth_url,
                                            auth=aiohttp.BasicAuth(username, password),
                                            headers={
                                                "User-Agent": "nvdebug-preflight/1.0"
                                            },
                                        ) as auth_response:
                                            if auth_response.status == 200:
                                                self.connection_state.set_redfish_connected(
                                                    True, self.dut_id
                                                )
                                                self.connection_state.last_redfish_check = (
                                                    datetime.now()
                                                )
                                                await self._log_runtime(
                                                    "INFO",
                                                    f"Redfish credentials validated successfully against {normalized_auth_uri}",
                                                )
                                                # Explicitly close connector before returning
                                                if connector:
                                                    await connector.close()
                                                return (
                                                    True,
                                                    "Redfish connection and credentials validated successfully",
                                                )
                                            elif auth_response.status == 401:
                                                # Authentication failed
                                                await self._log_runtime(
                                                    "ERROR",
                                                    f"Redfish credential validation failed: HTTP 401 Unauthorized at {normalized_auth_uri}",
                                                )
                                                # Explicitly close connector before returning
                                                if connector:
                                                    await connector.close()
                                                return (
                                                    False,
                                                    f"Redfish credentials invalid: HTTP 401 Unauthorized. Please verify BMC_USERNAME/BMC_PASSWORD or RF_User/RF_Pass are correct.",
                                                )
                                            elif auth_response.status == 403:
                                                # Forbidden - credentials might be valid but insufficient permissions
                                                await self._log_runtime(
                                                    "WARNING",
                                                    f"Redfish credential validation returned HTTP 403 Forbidden at {normalized_auth_uri}. Credentials may be valid but have insufficient permissions.",
                                                )
                                                # Explicitly close connector before returning
                                                if connector:
                                                    await connector.close()
                                                return (
                                                    False,
                                                    f"Redfish credentials may be valid but have insufficient permissions: HTTP 403 Forbidden at {normalized_auth_uri}",
                                                )
                                            else:
                                                # Other error - log and fail
                                                await self._log_runtime(
                                                    "WARNING",
                                                    f"Redfish credential validation returned unexpected status: HTTP {auth_response.status} at {normalized_auth_uri}",
                                                )
                                                # Explicitly close connector before returning
                                                if connector:
                                                    await connector.close()
                                                return (
                                                    False,
                                                    f"Redfish credential validation failed: HTTP {auth_response.status} at {normalized_auth_uri}",
                                                )
                                    except Exception as cred_error:
                                        await self._log_runtime(
                                            "ERROR",
                                            f"Redfish credential validation error: {str(cred_error)}",
                                        )
                                        # Explicitly close connector before returning
                                        if connector:
                                            await connector.close()
                                        return (
                                            False,
                                            f"Redfish credential validation failed: {str(cred_error)}",
                                        )
                                else:
                                    # Credential validation disabled, just check service availability
                                    await self._log_runtime(
                                        "INFO",
                                        "Credential validation disabled in preflight_config, only checking service availability",
                                    )
                                    self.connection_state.set_redfish_connected(
                                        True, self.dut_id
                                    )
                                    self.connection_state.last_redfish_check = (
                                        datetime.now()
                                    )
                                    # Explicitly close connector before returning
                                    if connector:
                                        await connector.close()
                                    return (
                                        True,
                                        "Redfish connection successful (credential validation disabled)",
                                    )
                            else:
                                # Explicitly close connector before returning
                                if connector:
                                    await connector.close()
                                return (
                                    False,
                                    f"Redfish connection failed: HTTP {response.status}",
                                )
                except asyncio.TimeoutError:
                    if attempt < max_retries:
                        await asyncio.sleep(retry_delay)
                        continue
                    # Explicitly close connector before returning
                    if connector:
                        await connector.close()
                    return (
                        False,
                        "Redfish connection timeout after retries (18s total)",
                    )
                except aiohttp.ClientConnectorError as e:
                    error_msg = str(e)
                    if "Connection refused" in error_msg:
                        detailed_error = f"Redfish connection refused - BMC may be unreachable or service not running: {error_msg}"
                    elif "Connection reset" in error_msg:
                        detailed_error = f"Redfish connection reset by peer - BMC may have closed the connection: {error_msg}"
                    elif "Timeout" in error_msg:
                        detailed_error = f"Redfish connection timeout - BMC may be slow to respond: {error_msg}"
                    else:
                        detailed_error = f"Redfish connection error: {error_msg}"

                    await self._log_runtime(
                        "WARNING",
                        f"Redfish connection attempt {attempt + 1} failed: {detailed_error}",
                    )

                    if attempt < max_retries:
                        await asyncio.sleep(retry_delay)
                        continue
                    # Explicitly close connector before returning
                    if connector:
                        await connector.close()
                    return (
                        False,
                        f"Redfish connection failed after {max_retries + 1} attempts: {detailed_error}",
                    )
                except Exception as e:
                    error_type = type(e).__name__
                    error_msg = str(e)

                    # Provide more context for common errors
                    if (
                        "Session is closed" in error_msg
                        or "session" in error_msg.lower()
                    ):
                        detailed_error = (
                            f"Redfish session error ({error_type}): {error_msg}. "
                            f"This may indicate: (1) BMC closed the connection prematurely, "
                            f"(2) Network instability, (3) BMC service restarted, or "
                            f"(4) Authentication/SSL issues. Check BMC logs and network connectivity."
                        )
                    else:
                        detailed_error = (
                            f"Redfish connection error ({error_type}): {error_msg}"
                        )

                    await self._log_runtime(
                        "WARNING",
                        f"Redfish connection attempt {attempt + 1} failed: {detailed_error}",
                    )

                    if attempt < max_retries:
                        await asyncio.sleep(retry_delay)
                        continue
                    # Explicitly close connector before returning
                    if connector:
                        await connector.close()
                    return (
                        False,
                        detailed_error,
                    )
        except asyncio.TimeoutError:
            # Explicitly close connector before returning
            if connector:
                await connector.close()
            return False, "Redfish connection timeout (10s)"
        except Exception as e:
            # Explicitly close connector before returning
            if connector:
                await connector.close()
            return False, f"Redfish connection error: {str(e)}"

    async def _test_redfish_hmc_connection(self) -> Tuple[bool, str]:
        """
        Test Redfish connection through HMC port forwarding.

        Args:
            level: Log level.
            message: Log message.
        """
        try:
            # Initialize HMC service with logger and DUT manager
            hmc_service = HMCService(logger=self.logger, dut_manager=self.dut_manager)

            # Setup transparent HMC port forwarding
            success, bound_port, message = await hmc_service.setup_hmc_port_forwarding(
                dut_id=self.dut_id,
                bmc_ip=self.credentials.bmc_ip,
                bmc_ssh_username=self.credentials.bmc_ssh_username,
                bmc_ssh_password=self.credentials.bmc_ssh_password,
                hmc_ip=self.credentials.hmc_ip,
                hmc_username=self.credentials.hmc_username,
                hmc_password=self.credentials.hmc_password,
                bmc_ssh_port=self.credentials.bmc_ssh_port,
                hmc_http_port=self.credentials.hmc_http_port,
                hmc_https_port=self.credentials.hmc_https_port,
                hmc_use_https=self.credentials.hmc_use_https,
                force_setup=self.config.get("FORCE_PORT_FW", False),
                local_port=self.config.get("TUNNEL_TCP_PORT"),
                tunnel_config={
                    "TUNNEL_LOCAL_HOST": self.config.get(
                        "TUNNEL_LOCAL_HOST", "localhost"
                    ),
                    "SSH_TUNNEL_OPTIONS": self.config.get(
                        "SSH_TUNNEL_OPTIONS",
                        "-4 -o StrictHostKeyChecking=no -o LogLevel=ERROR -fNT",
                    ),
                    "SSH_TUNNEL_PREFIX": self.config.get(
                        "SSH_TUNNEL_PREFIX", "sshpass -p"
                    ),
                },
            )

            if not success:
                return False, f"HMC port forwarding setup failed: {message}"

            # Store HMC service for transparent access
            self.hmc_service = hmc_service

            # Now test standard Redfish connection using forwarded connection
            # This uses the same logic as normal Redfish but through localhost:bound_port
            connection_info = hmc_service.get_redfish_connection_info()

            # Test the forwarded connection using standard HTTP client
            try:
                protocol = (
                    "https" if connection_info.get("use_https", False) else "http"
                )
                url = f"{protocol}://{connection_info['host']}:{connection_info['port']}/redfish/v1"

                # Debug logging
                await self._log_runtime(
                    "DEBUG",
                    f"HMC Redfish test - URL: {url}, protocol: {protocol}, host: {connection_info['host']}, port: {connection_info['port']}",
                )

                timeout_config = aiohttp.ClientTimeout(total=10)

                async with aiohttp.ClientSession(timeout=timeout_config) as session:
                    async with session.get(
                        url,
                        auth=aiohttp.BasicAuth(
                            self.credentials.hmc_username,
                            self.credentials.hmc_password,
                        ),
                        ssl=False,
                    ) as response:
                        if response.status == 200:
                            self.connection_state.set_redfish_connected(
                                True, self.dut_id
                            )
                            self.connection_state.last_redfish_check = datetime.now()
                            self.connection_state.port_forwarding_active = True
                            self.connection_state.set_hmc_connected(True, self.dut_id)
                            await self._log_runtime(
                                "INFO",
                                f"HMC Redfish connection successful via transparent forwarding",
                            )
                            return (
                                True,
                                f"HMC Redfish connection successful via port {bound_port}",
                            )
                        else:
                            return (
                                False,
                                f"HMC Redfish connection failed: HTTP {response.status}",
                            )

            except asyncio.TimeoutError:
                return False, "HMC Redfish connection timeout"
            except Exception as e:
                return False, f"HMC Redfish connection error: {str(e)}"

        except Exception as e:
            return False, f"HMC connection setup error: {str(e)}"

    async def test_ipmi_connection(self) -> Tuple[bool, str]:
        """
        Test IPMI connection using ping first, then ipmitool if ping succeeds.

        Args:
            level: Log level.
            message: Log message.
        """
        try:
            # Handle local mode
            if self.credentials.execution_mode == "local":
                await self._log_runtime(
                    "INFO",
                    "DUT is in local mode, skipping IPMI connection test",
                )
                self.connection_state.set_ipmi_connected(True, self.dut_id)
                self.connection_state.last_ipmi_check = datetime.now()
                return True, "Local mode - IPMI connection assumed successful"

            # Check if SSH proxy is configured
            if self.credentials.ssh_proxy_host:
                await self._log_runtime(
                    "INFO",
                    f"Using SSH proxy {self.credentials.ssh_proxy_host} for IPMI connections",
                )

                # Setup SSH proxy tunneling for IPMI (reuse existing setup if available)
                if not hasattr(self, "ssh_proxy_service") or not self.ssh_proxy_service:
                    ssh_proxy_service = SSHProxyService(
                        logger=self.logger, dut_manager=self.dut_manager
                    )

                    success, tunnel_ports, message = (
                        await ssh_proxy_service.setup_ssh_proxy_tunneling(
                            dut_id=self.dut_id,
                            bmc_ip=self.credentials.bmc_ip,
                            host_ip=self.credentials.host_ip,  # Include host_ip for complete setup
                            ssh_proxy_host=self.credentials.ssh_proxy_host,
                            ssh_proxy_username=self.credentials.ssh_proxy_username,
                            ssh_proxy_password=self.credentials.ssh_proxy_password,
                            ssh_proxy_port=self.credentials.ssh_proxy_port,
                            bmc_redfish_port=self.credentials.bmc_rf_port,
                            bmc_use_https=self.credentials.bmc_use_https,
                            bmc_ipmi_port=623,  # Standard IPMI port
                            host_ssh_port=self.credentials.host_ssh_port,  # Include host_ssh_port for complete setup
                            force_setup=True,
                        )
                    )

                    if not success:
                        return (
                            False,
                            f"Failed to setup SSH proxy tunneling for IPMI: {message}",
                        )

                    # Store the tunnel info for later use
                    self.ssh_proxy_service = ssh_proxy_service
                    self.ssh_proxy_tunnel_ports = tunnel_ports
                else:
                    # Reuse existing tunnel setup
                    success = True
                    tunnel_ports = self.ssh_proxy_tunnel_ports

                await self._log_runtime(
                    "INFO",
                    f"SSH proxy tunneling established for IPMI: localhost:{self.ssh_proxy_tunnel_ports['ipmi_port']} -> {self.credentials.bmc_ip}:623",
                )
            else:
                # First check if BMC is reachable via ping (only if no proxy)
                ping_success = await self._ping_host(self.credentials.bmc_ip)
                if not ping_success:
                    return (
                        False,
                        f"BMC {self.credentials.bmc_ip} is not reachable via ping",
                    )

            # If ping succeeds, try ipmitool with short timeout
            cmd = [
                "ipmitool",
                "-I",
                "lanplus",
                "-H",
                self.credentials.bmc_ip,
                "-U",
                self.credentials.bmc_username,
                "-P",
                self.credentials.bmc_password,
                self.credentials.ipmi_cipher,
                "mc",
                "info",
            ]

            # Use asyncio.create_subprocess_exec for true async execution
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for completion with timeout (increased for async environment)
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=30
                )
            except asyncio.TimeoutError:
                # Kill the process if it times out
                process.kill()
                await process.wait()  # Wait for the process to be cleaned up
                return False, "IPMI connection timeout (30s)"

            # Decode the output using robust method
            stdout_text = self._process_command_output(stdout)
            stderr_text = self._process_command_output(stderr)

            if process.returncode == 0:
                self.connection_state.set_ipmi_connected(True, self.dut_id)
                self.connection_state.last_ipmi_check = datetime.now()
                return True, "IPMI connection successful"
            else:
                return False, f"IPMI connection failed: {stderr_text}"
        except Exception as e:
            return False, f"IPMI connection error: {str(e)}"

    async def test_ssh_connection(self) -> Tuple[bool, str]:
        """
        Test SSH connection using ping first, then SSH if ping succeeds.

        Args:
            level: Log level.
            message: Log message.
        """
        try:
            # Handle local mode
            if self.credentials.execution_mode == "local":
                await self._log_runtime(
                    "INFO",
                    "DUT is in local mode, skipping SSH connection test",
                )
                self.connection_state.set_ssh_connected(True, self.dut_id)
                self.connection_state.last_ssh_check = datetime.now()
                return True, "Local mode - SSH connection assumed successful"

            # Check if SSH proxy is configured
            if self.credentials.ssh_proxy_host:
                await self._log_runtime(
                    "INFO",
                    f"Using SSH proxy {self.credentials.ssh_proxy_host} for BMC SSH connections",
                )

                # Setup SSH proxy tunneling for BMC SSH (reuse existing setup if available)
                if not hasattr(self, "ssh_proxy_service") or not self.ssh_proxy_service:
                    ssh_proxy_service = SSHProxyService(
                        logger=self.logger, dut_manager=self.dut_manager
                    )

                    success, tunnel_ports, message = (
                        await ssh_proxy_service.setup_ssh_proxy_tunneling(
                            dut_id=self.dut_id,
                            bmc_ip=self.credentials.bmc_ip,
                            host_ip=self.credentials.host_ip,  # Include host_ip for complete setup
                            ssh_proxy_host=self.credentials.ssh_proxy_host,
                            ssh_proxy_username=self.credentials.ssh_proxy_username,
                            ssh_proxy_password=self.credentials.ssh_proxy_password,
                            ssh_proxy_port=self.credentials.ssh_proxy_port,
                            bmc_redfish_port=self.credentials.bmc_rf_port,
                            bmc_use_https=self.credentials.bmc_use_https,
                            bmc_ipmi_port=623,  # Standard IPMI port
                            host_ssh_port=self.credentials.host_ssh_port,  # Include host_ssh_port for complete setup
                            force_setup=True,
                        )
                    )

                    if not success:
                        return (
                            False,
                            f"Failed to setup SSH proxy tunneling for BMC SSH: {message}",
                        )

                    # Store the tunnel info for later use
                    self.ssh_proxy_service = ssh_proxy_service
                    self.ssh_proxy_tunnel_ports = tunnel_ports
                else:
                    # Reuse existing tunnel setup
                    success = True
                    tunnel_ports = self.ssh_proxy_tunnel_ports

                await self._log_runtime(
                    "INFO",
                    f"SSH proxy tunneling established for BMC SSH: localhost:{self.ssh_proxy_tunnel_ports['bmc_ssh_port']} -> {self.credentials.bmc_ip}:{self.credentials.bmc_ssh_port}",
                )

                # Test SSH connection through tunnel
                username = (
                    self.credentials.bmc_ssh_username or self.credentials.bmc_username
                )
                password = (
                    self.credentials.bmc_ssh_password or self.credentials.bmc_password
                )

                # Use localhost and tunnel port for SSH connection
                exit_code, stdout, stderr = await self.dut_manager.execute_ssh_command(
                    host="localhost",  # Use localhost for tunnel
                    port=self.ssh_proxy_tunnel_ports[
                        "bmc_ssh_port"
                    ],  # Use BMC SSH tunnel port
                    username=username,
                    password=password,
                    command="",  # Empty command for connection test
                    timeout=10,  # Increased timeout for preflight
                    ssh_key_path=self.credentials.bmc_ssh_key_path,
                    passwordless=self.credentials.bmc_ssh_passwordless,
                    max_retries=self.credentials.bmc_ssh_max_retries,
                )
            else:
                # No proxy - use direct connection
                # First check if BMC is reachable via ping
                ping_success = await self._ping_host(self.credentials.bmc_ip)
                if not ping_success:
                    return (
                        False,
                        f"BMC {self.credentials.bmc_ip} is not reachable via ping",
                    )

                # If ping succeeds, try SSH with enhanced authentication
                username = (
                    self.credentials.bmc_ssh_username or self.credentials.bmc_username
                )
                password = (
                    self.credentials.bmc_ssh_password or self.credentials.bmc_password
                )

                # Use the enhanced SSH method for connection testing
                exit_code, stdout, stderr = await self.dut_manager.execute_ssh_command(
                    host=self.credentials.bmc_ip,
                    port=self.credentials.bmc_ssh_port,
                    username=username,
                    password=password,
                    command="",  # Empty command for connection test
                    timeout=10,  # Increased timeout for preflight
                    ssh_key_path=self.credentials.bmc_ssh_key_path,
                    passwordless=self.credentials.bmc_ssh_passwordless,
                    max_retries=self.credentials.bmc_ssh_max_retries,
                )

            if exit_code == 0:
                self.connection_state.set_ssh_connected(True, self.dut_id)
                self.connection_state.last_ssh_check = datetime.now()
                return True, "SSH connection successful"
            else:
                error_msg = (
                    stderr
                    if stderr
                    else f"SSH connection failed with exit code {exit_code}"
                )
                return False, f"SSH connection failed: {error_msg}"
        except Exception as e:
            return False, f"SSH connection error: {str(e)}"

    async def test_host_connection(self) -> Tuple[bool, str]:
        """
        Test host connection using ping first, then SSH if ping succeeds.

        Args:
            level: Log level.
            message: Log message.
        """
        try:
            # Handle local mode
            if self.credentials.execution_mode == "local":
                await self._log_runtime(
                    "INFO",
                    "DUT is in local mode, skipping host connection test",
                )
                self.connection_state.set_host_connected(True, self.dut_id)
                self.connection_state.last_host_check = datetime.now()
                return True, "Local mode - Host connection assumed successful"

            if not self.credentials.host_ip:
                # Assume local execution
                self.connection_state.set_host_connected(True, self.dut_id)
                self.connection_state.last_host_check = datetime.now()
                return True, "Local host execution"

            # Check if SSH proxy is configured
            if self.credentials.ssh_proxy_host:
                await self._log_runtime(
                    "INFO",
                    f"Using SSH proxy {self.credentials.ssh_proxy_host} for host connections",
                )

                # Setup SSH proxy tunneling for Host SSH (reuse existing setup if available)
                if not hasattr(self, "ssh_proxy_service") or not self.ssh_proxy_service:
                    ssh_proxy_service = SSHProxyService(
                        logger=self.logger, dut_manager=self.dut_manager
                    )

                    success, tunnel_ports, message = (
                        await ssh_proxy_service.setup_ssh_proxy_tunneling(
                            dut_id=self.dut_id,
                            bmc_ip=self.credentials.bmc_ip,
                            host_ip=self.credentials.host_ip,
                            ssh_proxy_host=self.credentials.ssh_proxy_host,
                            ssh_proxy_username=self.credentials.ssh_proxy_username,
                            ssh_proxy_password=self.credentials.ssh_proxy_password,
                            ssh_proxy_port=self.credentials.ssh_proxy_port,
                            bmc_redfish_port=self.credentials.bmc_rf_port,
                            bmc_use_https=self.credentials.bmc_use_https,
                            bmc_ipmi_port=623,  # Standard IPMI port
                            host_ssh_port=self.credentials.host_ssh_port,
                            force_setup=True,
                        )
                    )

                    if not success:
                        return (
                            False,
                            f"Failed to setup SSH proxy tunneling for Host SSH: {message}",
                        )

                    # Store the tunnel info for later use
                    self.ssh_proxy_service = ssh_proxy_service
                    self.ssh_proxy_tunnel_ports = tunnel_ports
                else:
                    # Reuse existing tunnel setup
                    success = True
                    tunnel_ports = self.ssh_proxy_tunnel_ports

                await self._log_runtime(
                    "INFO",
                    f"SSH proxy tunneling established for Host SSH: localhost:{self.ssh_proxy_tunnel_ports['host_ssh_port']} -> {self.credentials.host_ip}:{self.credentials.host_ssh_port}",
                )

                # Test SSH connection through tunnel
                exit_code, stdout, stderr = await self.dut_manager.execute_ssh_command(
                    host="localhost",  # Use localhost for tunnel
                    port=self.ssh_proxy_tunnel_ports[
                        "host_ssh_port"
                    ],  # Use Host SSH tunnel port
                    username=self.credentials.host_username,
                    password=self.credentials.host_password,
                    command="",  # Empty command for connection test
                    timeout=10,  # Increased timeout for preflight
                    ssh_key_path=self.credentials.host_ssh_key_path,
                    passwordless=self.credentials.host_ssh_passwordless,
                    max_retries=self.credentials.host_ssh_max_retries,
                )
            else:
                # No proxy - use direct connection
                # First check if host is reachable via ping
                ping_success = await self._ping_host(self.credentials.host_ip)
                if not ping_success:
                    return (
                        False,
                        f"Host {self.credentials.host_ip} is not reachable via ping",
                    )

                # If ping succeeds, try SSH with enhanced authentication
                exit_code, stdout, stderr = await self.dut_manager.execute_ssh_command(
                    host=self.credentials.host_ip,
                    port=self.credentials.host_ssh_port,
                    username=self.credentials.host_username,
                    password=self.credentials.host_password,
                    command="",  # Empty command for connection test
                    timeout=10,  # Increased timeout for preflight
                    ssh_key_path=self.credentials.host_ssh_key_path,
                    passwordless=self.credentials.host_ssh_passwordless,
                    max_retries=self.credentials.host_ssh_max_retries,
                )

            if exit_code == 0:
                self.connection_state.set_host_connected(True, self.dut_id)
                self.connection_state.last_host_check = datetime.now()
                return True, "Host SSH connection successful"
            else:
                error_msg = (
                    stderr
                    if stderr
                    else f"SSH connection failed with exit code {exit_code}"
                )
                return False, f"Host SSH connection failed: {error_msg}"
        except Exception as e:
            return False, f"Host connection error: {str(e)}"

    async def _detect_hmc_platform(self) -> bool:
        """
        Detect if HMC port forwarding should be used based on explicit USE_PORT_FORWARDING flag

        Returns:
            True if HMC port forwarding should be enabled
        """
        # Debug logging - use regular logger since this is a sync method

        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] _detect_hmc_platform called for DUT {self.dut_id}",
        )
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] supports_hmc: {self.config.get('supports_hmc', False)}",
        )
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] use_port_forwarding: {self.credentials.use_port_forwarding}",
        )
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] rf_hmc_access_method: {self.credentials.rf_hmc_access_method}",
        )
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] baseboard: {self.config.get('baseboard', 'None')}",
        )
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] platform_detection: {self.config.get('platform_detection', 'None')}",
        )

        # Check explicit USE_PORT_FORWARDING flag FIRST - this is the primary gate
        if not self.credentials.use_port_forwarding:
            await self._log_runtime(
                "DEBUG",
                f"[HMC DEBUG] use_port_forwarding is False, returning False",
            )
            return False

        # Check if baseboard supports HMC
        if not self.config.get("supports_hmc", False):
            await self._log_runtime(
                "DEBUG",
                f"[HMC DEBUG] Baseboard does not support HMC, returning False",
            )
            return False

        # If we get here, USE_PORT_FORWARDING is True and baseboard supports HMC
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] use_port_forwarding is True and baseboard supports HMC, returning True",
        )
        return True

    def _configure_hmc_settings(self) -> None:
        """
        Auto-configure HMC settings when USE_PORT_FORWARDING is enabled
        """
        # Double-check that USE_PORT_FORWARDING is enabled
        if not self.credentials.use_port_forwarding:
            return

        # Get HMC IP from baseboard config if not provided (respect explicit CLI/DUT overrides)
        if not self.credentials.hmc_ip:
            # Try to get from baseboard platform_detection
            platform_detection = self.config.get("platform_detection", {})
            hmc_ip = platform_detection.get("hmc_ip")
            if hmc_ip:
                self.credentials.hmc_ip = hmc_ip
            else:
                # Fallback to default HMC IP
                self.credentials.hmc_ip = "192.168.31.1"

        # Handle port forwarding setup
        setup_port_forwarding = self.config.get("SETUP_PORT_FORWARDING", False)

        if setup_port_forwarding:
            # nvdebug will set up port forwarding - use default port if not specified
            if not self.config.get("TUNNEL_TCP_PORT"):
                self.config["TUNNEL_TCP_PORT"] = 18888
        else:
            # User sets up port forwarding manually - use their specified port
            # TUNNEL_TCP_PORT should already be set by user
            pass

        # Set HMC access method to port forwarding
        self.credentials.rf_hmc_access_method = "HostBmcTcpPortForwarding"

        # Disable RF auth for HMC
        self.config["RF_AUTH"] = False

        # Use async logger for DUT-specific logging
        if hasattr(self, "logger") and hasattr(self.logger, "write_to_dut_runtime_log"):
            asyncio.create_task(
                self.logger.write_to_dut_runtime_log(
                    self.dut_id,
                    "INFO",
                    "DUT",
                    f"Auto-configured HMC port forwarding: IP={self.credentials.hmc_ip}, Port={self.config.get('TUNNEL_TCP_PORT')}, Setup={setup_port_forwarding}",
                )
            )
        else:
            # Fallback to regular logger if async logger not available
            asyncio.create_task(
                self._log_runtime(
                    "INFO",
                    f"Auto-configured HMC port forwarding: IP={self.credentials.hmc_ip}, Port={self.config.get('TUNNEL_TCP_PORT')}, Setup={setup_port_forwarding}",
                )
            )

    def get_redfish_connection_info(self) -> dict:
        """
        Get appropriate Redfish connection info - either direct BMC or forwarded HMC

        This allows existing Redfish service calls to work transparently
        """
        # Check if HMC mode is active
        if (
            self.is_hmc_platform
            and self.hmc_service
            and self.hmc_service.is_hmc_active()
        ):

            # Return forwarded connection info
            connection_info = self.hmc_service.get_redfish_connection_info()
            return {
                "host": connection_info["host"],
                "port": connection_info["port"],
                "use_https": connection_info["use_https"],
                "username": connection_info.get("username")
                or self.credentials.hmc_username,
                "password": connection_info.get("password")
                or self.credentials.hmc_password,
                "is_hmc_forwarded": True,
            }
        else:
            # Check if SSH proxy tunneling is active
            if hasattr(self, "ssh_proxy_tunnel_ports") and self.ssh_proxy_tunnel_ports:
                # Return SSH proxy tunnel connection info
                return {
                    "host": "localhost",  # Use localhost for tunnel
                    "port": self.ssh_proxy_tunnel_ports[
                        "redfish_port"
                    ],  # Use tunnel port
                    "use_https": True,  # BMC typically uses HTTPS
                    "username": self.credentials.rf_username
                    or self.credentials.bmc_username,
                    "password": self.credentials.rf_password
                    or self.credentials.bmc_password,
                    "is_hmc_forwarded": False,
                    "is_ssh_proxy_tunneled": True,
                }
            else:
                # Return direct BMC connection info
                return {
                    "host": self.credentials.bmc_ip,
                    "port": self.credentials.bmc_rf_port,
                    "use_https": True,  # BMC typically uses HTTPS
                    "username": self.credentials.rf_username
                    or self.credentials.bmc_username,
                    "password": self.credentials.rf_password
                    or self.credentials.bmc_password,
                    "is_hmc_forwarded": False,
                    "is_ssh_proxy_tunneled": False,
                }

    async def _ping_host(self, ip_address: str) -> bool:
        """
        Ping a host with timeout.

        Args:
            ip_address: IP address to ping.
        """
        try:
            # Use ping with 2 packets and 5 second timeout
            ping_cmd = ["ping", "-c", "2", "-W", "5", ip_address]

            # Use asyncio.create_subprocess_exec for true async execution
            # Note: asyncio.create_subprocess_exec doesn't support text=True
            process = await asyncio.create_subprocess_exec(
                *ping_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=10
                )
            except asyncio.TimeoutError:
                # Kill the process if it times out
                process.kill()
                await process.wait()  # Wait for the process to be cleaned up
                return False

            return process.returncode == 0
        except Exception:
            return False

    def _process_command_output(
        self, output: Union[str, bytes, None], encoding: str = "utf-8"
    ) -> str:
        """
        Process command output to ensure it's in string format.
        Handles binary data gracefully with fallback strategies.
        Delegates to DUTManager if available, otherwise uses local implementation.

        Args:
            output: The command output to process (can be str, bytes, or None)
            encoding: The encoding to use for bytes decoding (default: utf-8)

        Returns:
            str: The processed output as a string
        """
        # If we have a DUTManager reference, use its method
        if self.dut_manager and hasattr(self.dut_manager, "_process_command_output"):
            return self.dut_manager._process_command_output(output, encoding)

        # Otherwise, use local implementation
        if output is None:
            return ""

        if isinstance(output, bytes):
            try:
                # First try UTF-8 with replace
                return output.decode(encoding, errors="replace")
            except Exception:
                try:
                    # Try latin1 as fallback - it can handle all byte values
                    return output.decode("latin1", errors="replace")
                except Exception as e:
                    # Last resort - hex representation
                    return f"hex:{output.hex()}"

        # Handle case where output is already a string
        if isinstance(output, str):
            return output

        # For any other type, try string conversion with error handling
        try:
            return str(output)
        except Exception:
            return f"<unconvertible output of type {type(output).__name__}>"

    async def cleanup_ssh_proxy_tunnels(self) -> None:
        """
        Clean up SSH proxy tunnels when DUT operations complete
        """
        await self._log_runtime(
            "DEBUG", f"cleanup_ssh_proxy_tunnels called for DUT {self.dut_id}"
        )

        if hasattr(self, "ssh_proxy_service") and self.ssh_proxy_service:
            try:
                await self._log_runtime(
                    "INFO", f"Cleaning up SSH proxy tunnels for DUT {self.dut_id}"
                )
                success = await self.ssh_proxy_service.cleanup_tunnels(self.dut_id)
                if success:
                    await self._log_runtime(
                        "INFO",
                        f"SSH proxy tunnels cleaned up successfully for DUT {self.dut_id}",
                    )
                else:
                    await self._log_runtime(
                        "WARNING",
                        f"SSH proxy tunnel cleanup returned False for DUT {self.dut_id}",
                    )
            except Exception as e:
                await self._log_runtime(
                    "ERROR",
                    f"Failed to cleanup SSH proxy tunnels for DUT {self.dut_id}: {e}",
                )
        else:
            await self._log_runtime(
                "DEBUG",
                f"No SSH proxy service found for DUT {self.dut_id} - nothing to cleanup",
            )


class DUTManager:
    """
    Manager for multiple DUTs.

    Args:
        dut_configs: DUT configurations.
        base_log_dir: Base log directory.
        uri_config_manager: URI configuration manager.
        ssh_config: SSH configuration.
        spreadsheet_path: Spreadsheet path.
        sanitized_console: Sanitized console.
        debug_mode: Debug mode.
        redfish_session_config: Redfish session configuration.
        tool_config: Tool configuration.
    """

    def __init__(
        self,
        dut_configs: Dict[str, Any],
        base_log_dir: str,
        uri_config_manager=None,
        ssh_config: Dict[str, Any] = None,
        spreadsheet_path: Optional[str] = None,
        sanitized_console=None,
        debug_mode: bool = False,
        redfish_session_config: Optional[Dict[str, Any]] = None,
        tool_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize DUT manager.

        Args:
            dut_configs: DUT configurations.
            base_log_dir: Base log directory.
            uri_config_manager: URI configuration manager.
            ssh_config: SSH configuration.
            spreadsheet_path: Spreadsheet path.
            sanitized_console: Sanitized console.
            debug_mode: Debug mode.
            redfish_session_config: Redfish session configuration.
            tool_config: Tool configuration.
        """
        self.dut_configs = dut_configs
        self.base_log_dir = Path(base_log_dir)
        self.duts: Dict[str, DUT] = {}
        self.logger = AsyncSafeLogger(str(self.base_log_dir), debug_mode=debug_mode)
        self.uri_config_manager = uri_config_manager
        self.tool_config = tool_config or {}

        # Spreadsheet configuration
        self.spreadsheet_path = spreadsheet_path

        # Console for consistent output styling
        self.sanitized_console = sanitized_console

        # SSH implementation configuration with defaults
        self.ssh_config = ssh_config or {}
        self.ssh_backend = self.ssh_config.get(
            "backend", "asyncssh"
        )  # Default to asyncssh

        # Redfish session configuration with defaults
        self.redfish_session_config = redfish_session_config or {}
        self.redfish_connection_pool_limit = self.redfish_session_config.get(
            "connection_pool_limit", 20
        )
        self.redfish_connection_pool_limit_per_host = self.redfish_session_config.get(
            "connection_pool_limit_per_host", 8
        )
        self.redfish_session_timeout = self.redfish_session_config.get(
            "session_timeout", 300
        )
        self.redfish_keepalive_timeout = self.redfish_session_config.get(
            "keepalive_timeout", 300
        )
        self.redfish_ssl = self.redfish_session_config.get("ssl", False)
        self.redfish_ttl_dns_cache = self.redfish_session_config.get(
            "ttl_dns_cache", 300
        )
        self.redfish_use_dns_cache = self.redfish_session_config.get(
            "use_dns_cache", True
        )
        self.redfish_force_close = self.redfish_session_config.get("force_close", False)
        self.redfish_enable_cleanup_closed = self.redfish_session_config.get(
            "enable_cleanup_closed", True
        )
        self.redfish_fallback_connection_pool_limit = self.redfish_session_config.get(
            "fallback_connection_pool_limit", 15
        )
        self.redfish_fallback_connection_pool_limit_per_host = (
            self.redfish_session_config.get(
                "fallback_connection_pool_limit_per_host", 6
            )
        )
        self.ssh_fallback_enabled = self.ssh_config.get("fallback", {}).get(
            "enabled", True
        )
        self.ssh_fallback_on_error_only = self.ssh_config.get("fallback", {}).get(
            "on_error_only", True
        )

        # Shared DynamicDiscoveryService instance
        self._discovery_service = None

        # BaseboardManager for baseboard lookups and filtering
        self._baseboard_manager = None

        # SSH connection pooling
        self.ssh_connections: Dict[str, asyncssh.SSHClientConnection] = {}
        self.ssh_connection_locks: Dict[str, asyncio.Lock] = {}

        # Note: Async initialization (logging, DUT creation) will be done in initialize() method

    def _get_discovery_service(self):
        """
        Get or create the shared DynamicDiscoveryService instance.

        Returns:
            DynamicDiscoveryService instance.
        """
        if self._discovery_service is None:
            self._discovery_service = DynamicDiscoveryService(
                self, self.logger, self.uri_config_manager
            )
        return self._discovery_service

    def _get_baseboard_manager(self):
        """
        Get or create the shared BaseboardManager instance.

        Returns:
            BaseboardManager instance.
        """
        if self._baseboard_manager is None:
            self._baseboard_manager = BaseboardManager(
                spreadsheet_path=self.spreadsheet_path,
                logger=self.logger,
            )
        return self._baseboard_manager

    def _safe_tar_filter(self, member, target_dir):
        """
        Prevent path traversal by ensuring the extracted file stays within the target directory.
        Returns the member if safe, else None (skipped).

        Args:
            member: TarInfo object representing a file in the archive.
            target_dir: Target directory for extraction.

        Returns:
            The member if safe, None otherwise (or modified member for absolute paths).
        """
        # Handle absolute paths by stripping leading slashes (convert to relative)
        # This maintains backward compatibility with tar files created with -P option
        if member.name.startswith("/"):
            member.name = member.name.lstrip("/")

        # Reject path traversal attempts with ..
        if member.name.startswith("..") or "/.." in member.name or member.name == "..":
            return None

        # Reject hard links - they can bypass path restrictions
        if member.islnk():
            return None

        # For symlinks, validate that the link target stays within the extraction directory
        if member.issym():
            # Get the symlink target
            link_target = member.linkname

            # Reject absolute symlink targets
            if os.path.isabs(link_target):
                return None

            # Resolve the symlink path relative to its location
            member_dir = os.path.dirname(member.name)
            resolved_target = os.path.normpath(os.path.join(member_dir, link_target))

            # Check if the resolved target would escape the extraction directory
            if resolved_target.startswith("..") or "/.." in resolved_target:
                return None

        # Verify the final path is within the target directory
        member_path = os.path.join(target_dir, member.name)
        abs_target = os.path.abspath(target_dir)
        abs_member = os.path.abspath(member_path)
        if not abs_member.startswith(abs_target + os.sep) and abs_member != abs_target:
            return None

        return member

    async def _initialize_baseboard_manager_only(self):
        """
        Initialize only the BaseboardManager for simple mode operations.

        Used in simple mode for collector filtering without creating DUTs.
        """
        # This method initializes only the BaseboardManager without creating DUTs or connections
        # It's used in simple mode for collector filtering operations
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            "Initializing BaseboardManager for simple mode operations",
        )

        # Initialize the BaseboardManager by calling _get_baseboard_manager
        # This will load the baseboard definitions from the spreadsheet
        baseboard_manager = self._get_baseboard_manager()

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"BaseboardManager initialized with {len(baseboard_manager.get_all_baseboards())} baseboards",
        )

    async def get_ssh_connection(
        self, dut_id: str, hmc: bool = False
    ) -> Optional[asyncssh.SSHClientConnection]:
        """
        Get or create a persistent SSH connection for a DUT.

        Args:
            dut_id: DUT ID.
            hmc: Whether this is an HMC connection.

        Returns:
            SSH connection or None if connection fails.
        """
        connection_key = f"{dut_id}_{'hmc' if hmc else 'bmc'}"

        # Create lock if it doesn't exist
        if connection_key not in self.ssh_connection_locks:
            self.ssh_connection_locks[connection_key] = asyncio.Lock()

        async with self.ssh_connection_locks[connection_key]:
            # Check if we have an existing connection
            if connection_key in self.ssh_connections:
                conn = self.ssh_connections[connection_key]
                # Check if connection is still alive
                try:
                    # Try a simple command to test connection
                    await asyncio.wait_for(conn.run("echo test"), timeout=5)
                    return conn
                except Exception:
                    # Connection is dead, remove it
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"SSH connection {connection_key} is dead, removing",
                    )
                    del self.ssh_connections[connection_key]

            # Create new connection
            try:
                dut = self.get_dut(dut_id)
                if hmc:
                    host = dut.credentials.hmc_ip
                    port = dut.credentials.hmc_ssh_port
                    username = (
                        dut.credentials.hmc_ssh_username or dut.credentials.hmc_username
                    )
                    password = (
                        dut.credentials.hmc_ssh_password or dut.credentials.hmc_password
                    )
                    ssh_key_path = dut.credentials.hmc_ssh_key_path
                    passwordless = dut.credentials.hmc_ssh_passwordless
                else:
                    host = dut.credentials.bmc_ip
                    port = dut.credentials.bmc_ssh_port
                    username = (
                        dut.credentials.bmc_ssh_username or dut.credentials.bmc_username
                    )
                    password = (
                        dut.credentials.bmc_ssh_password or dut.credentials.bmc_password
                    )
                    ssh_key_path = dut.credentials.bmc_ssh_key_path
                    passwordless = dut.credentials.bmc_ssh_passwordless

                # Create connection using existing logic
                connect_kwargs = {
                    "host": host,
                    "port": port,
                    "username": username,
                    "connect_timeout": 30,
                    "keepalive_interval": None,
                    "known_hosts": None,
                }

                if ssh_key_path:
                    connect_kwargs["client_keys"] = [ssh_key_path]
                    if password:
                        connect_kwargs["passphrase"] = password
                elif not passwordless:
                    connect_kwargs["password"] = password

                conn = await asyncssh.connect(**connect_kwargs)
                self.ssh_connections[connection_key] = conn

                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    f"Created new SSH connection for {connection_key}",
                )
                return conn

            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"Failed to create SSH connection for {connection_key}: {str(e)}",
                )
                return None

    async def close_ssh_connection(self, dut_id: str, hmc: bool = False) -> None:
        """
        Close a specific SSH connection.

        Args:
            dut_id: DUT ID.
            hmc: Whether this is an HMC connection.
        """
        connection_key = f"{dut_id}_{'hmc' if hmc else 'bmc'}"

        if connection_key in self.ssh_connections:
            try:
                conn = self.ssh_connections[connection_key]
                conn.close()
                await conn.wait_closed()
                del self.ssh_connections[connection_key]
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    f"Closed SSH connection for {connection_key}",
                )
            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"Error closing SSH connection for {connection_key}: {str(e)}",
                )

    async def close_all_ssh_connections(self) -> None:
        """
        Close all SSH connections for all DUTs.
        """
        for connection_key in list(self.ssh_connections.keys()):
            try:
                conn = self.ssh_connections[connection_key]
                conn.close()
                await conn.wait_closed()
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Closed SSH connection for {connection_key}",
                )
            except Exception as e:
                await self.logger.log_runtime(
                    "ERROR",
                    "DUTManager",
                    f"Error closing SSH connection for {connection_key}: {str(e)}",
                )

        self.ssh_connections.clear()

    async def execute_bmc_commands_batched(
        self,
        dut_id: str,
        commands: List[str],
        timeout: int = 180,
        hmc: bool = False,
    ) -> List[Tuple[int, str, str]]:
        """
        Execute multiple BMC commands sequentially in a single SSH session for better performance.

        Note: Commands are executed sequentially (not in parallel) to avoid conflicts
        on shared resources like I2C buses. The performance improvement comes from
        reusing the SSH connection instead of creating a new one for each command.
        """
        results = []

        # Get or create SSH connection
        conn = await self.get_ssh_connection(dut_id, hmc)
        if not conn:
            # If connection failed, return errors for all commands
            return [(-1, "", "SSH connection failed")] * len(commands)

        try:
            # Execute all commands in sequence using the same connection
            for i, command in enumerate(commands):
                try:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        f"Executing batched command {i+1}/{len(commands)}: {command}",
                    )

                    result = await asyncio.wait_for(conn.run(command), timeout=timeout)
                    results.append(
                        (
                            result.exit_status,
                            result.stdout or "",
                            result.stderr or "",
                        )
                    )

                except asyncio.TimeoutError:
                    results.append(
                        (-1, "", f"Command timed out after {timeout} seconds")
                    )
                except Exception as e:
                    results.append((-1, "", f"Command failed: {str(e)}"))

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                f"Error in batched command execution: {str(e)}",
            )
            # Return errors for remaining commands
            while len(results) < len(commands):
                results.append((-1, "", f"Batched execution failed: {str(e)}"))

        return results

    async def initialize(self) -> None:
        """
        Initialize DUT manager - create DUTs and setup logging.
        """
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"DUTManager: dut_configs type: {type(self.dut_configs)}",
        )
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"DUTManager: base_log_dir type: {type(self.base_log_dir)}",
        )
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"DUTManager: self.base_log_dir type: {type(self.base_log_dir)}",
        )
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"DUTManager: SSH backend: {self.ssh_backend}, fallback enabled: {self.ssh_fallback_enabled}",
        )
        if isinstance(self.dut_configs, dict):
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"DUTManager: dut_configs keys: {list(self.dut_configs.keys())}",
            )

        # Create DUT objects from configuration
        await self._create_duts()

    async def _create_duts(self) -> None:
        """
        Create DUT objects from configuration.
        """
        defaults = self.dut_configs.get("DUT_Defaults", {})

        # Pre-process: collect all unique config files to avoid repeated I/O
        config_files_to_load = set()
        duts_needing_config = []
        duts_without_config = []

        # First pass: collect all DUTs and their config file requirements
        for dut_id, dut_config in self.dut_configs.items():
            if dut_id == "DUT_Defaults":
                continue

            # Debug logging
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"DUTManager: Creating DUT with dut_id: {dut_id} (type: {type(dut_id)})",
            )
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"DUTManager: dut_config type: {type(dut_config)}",
            )

            # Check if DUT needs config file loading
            config_file_to_use = dut_config.get("ConfigFileToUse")
            if config_file_to_use:
                config_files_to_load.add(config_file_to_use)
                duts_needing_config.append((dut_id, dut_config))
            else:
                duts_without_config.append((dut_id, dut_config))

        # Batch load all config files
        config_cache = {}
        for config_file_path in config_files_to_load:
            try:
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Loading config file: {config_file_path}",
                )
                dut_specific_config = YAMLManager.load_yaml(
                    config_file_path, f"Config file: {config_file_path}"
                )
                config_cache[config_file_path] = dut_specific_config
            except Exception as e:
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Could not load config file '{config_file_path}': {e}",
                )
                config_cache[config_file_path] = {}

        # Process DUTs with Rich progress bar
        total_duts = len(duts_without_config) + len(duts_needing_config)
        processed_duts = 0

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Creating {total_duts} DUT objects...",
        )

        # Process DUTs that don't need config files
        for dut_id, dut_config in duts_without_config:
            # Track which keys were explicitly set in the original DUT config
            # Dictionary format: {key_name: True/False} where True means it was in the DUT YAML
            explicit_keys = {}

            # Get the original YAML data for this DUT to see what was actually specified
            # The issue is that dut_config already contains defaults from config.py
            # We need to identify which keys were actually in the original YAML
            original_yaml_data = self.dut_configs.get(dut_id, {})

            # Skip flags that are known to come from config.py defaults
            config_py_defaults = {
                "SKIP_BMC_SSH_LOGS",
                "SKIP_HOST_LOGS",
                "SKIP_REDFISH_OOB_LOGS",
                "SKIP_IPMI_LOGS",
                "SKIP_PORT_FW",
                "COLLECTOR_TO_SKIP",
                "SYSTEM_ID_TO_SKIP",
                "CHASSIS_ID_TO_SKIP",
                "MANAGER_ID_TO_SKIP",
                "EXPAND_QUERY_CHASSIS_LEVEL",
                "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL",
                "EXPAND_QUERY_MANAGER_LEVEL",
                "EXPAND_QUERY_SYSTEM_LEVEL",
                "NVOS_TECH_DUMP_TIMEOUT",
                "REDFISH_DUMP_TIMEOUT",
                "REDFISH_DEVICE_DUMP_SLEEP_DURATION",
                "BMC_TEMP_DIR",
                "FW_INVENTORY_TABLE_PROPERTIES",
                "TASK_ID_PREFIX",
                "TOOL_TEMP_DIR",
            }

            if isinstance(original_yaml_data, dict):
                # Only mark keys as explicit if they are NOT known config.py defaults
                # or if they have non-default values
                for key in original_yaml_data.keys():
                    # Skip known config.py defaults unless they have been explicitly overridden
                    if key in config_py_defaults:
                        # For skip flags, only mark as explicit if they were actually set in YAML
                        # Note: config.py defaults for SKIP_BMC_SSH_LOGS is True, others are False
                        if key.startswith("SKIP_"):
                            # Only mark as explicit if the key was actually present in the original YAML
                            # This means it was explicitly set, regardless of the value
                            if key in original_yaml_data:
                                explicit_keys[key] = True
                        # For other config.py defaults, don't mark as explicit
                        # unless we can determine they were actually set in YAML
                    else:
                        # Non-config.py keys are considered explicit
                        explicit_keys[key] = True

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Original YAML keys: {list(explicit_keys.keys())}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: dut_config keys: {set(dut_config.keys())}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: defaults keys: {set(defaults.keys())}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: explicit_keys: {explicit_keys}",
            )
            # Merge with tool config first, then defaults, then DUT config
            # This ensures tool config values (like REDFISH_DUMP_TIMEOUT) are not overridden by defaults
            config = {**self.tool_config, **defaults, **dut_config}

            # Special handling: Tool config should override DUT defaults for certain fields
            # This ensures tool_config.yaml values take precedence over config.py defaults
            tool_config_override_fields = {
                "FW_INVENTORY_TABLE_PROPERTIES",
                "ADDITIONAL_OOB_URI_COLLECTION",
                "NVLINK_OOB_URI",
                "CUSTOM_DUMP_SERVICES",
                "POST_CODES_URI",
                "BMC_TEMP_DIR",
                "REDFISH_DUMP_TIMEOUT",
                "NVOS_TECH_DUMP_TIMEOUT",
                "REDFISH_DEVICE_DUMP_SLEEP_DURATION",
                # Skip flags
                "SKIP_BMC_SSH_LOGS",
                "SKIP_HOST_LOGS",
                "SKIP_REDFISH_OOB_LOGS",
                "SKIP_IPMI_LOGS",
                "SKIP_PORT_FW",
                # Feature flags
                "EXTRA_LOG_COLLECTION",
            }

            for field in tool_config_override_fields:
                if field in self.tool_config and self.tool_config[field] is not None:
                    config[field] = self.tool_config[field]

            # Log skip flag values for debugging
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Skip flags after merge - SKIP_BMC_SSH_LOGS={config.get('SKIP_BMC_SSH_LOGS')}, SKIP_HOST_LOGS={config.get('SKIP_HOST_LOGS')}, SKIP_REDFISH_OOB_LOGS={config.get('SKIP_REDFISH_OOB_LOGS')}, SKIP_IPMI_LOGS={config.get('SKIP_IPMI_LOGS')}",
            )

            await self._create_single_dut_object(dut_id, config, explicit_keys)
            processed_duts += 1
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Created DUT {dut_id} ({processed_duts}/{total_duts})",
            )

        # Process DUTs that need config files
        for dut_id, dut_config in duts_needing_config:
            config_file_to_use = dut_config.get("ConfigFileToUse")
            dut_specific_config = config_cache.get(config_file_to_use, {})

            # Track which keys were explicitly set in the original DUT config
            # Dictionary format: {key_name: True/False} where True means it was in the DUT YAML
            explicit_keys = {}

            # Mark keys from the DUT config as explicit
            for key in dut_config.keys():
                explicit_keys[key] = True

            # Mark keys from the DUT-specific config file as explicit
            for key in dut_specific_config.keys():
                explicit_keys[key] = True

            # Merge configurations: DUT config overrides DUT-specific config
            dut_config_with_overrides = {**dut_specific_config, **dut_config}

            # Merge with tool config first, then defaults, then DUT config
            # This ensures tool config values (like REDFISH_DUMP_TIMEOUT) are not overridden by defaults
            config = {**self.tool_config, **defaults, **dut_config_with_overrides}

            # Special handling: Tool config should override DUT defaults for certain fields
            # This ensures tool_config.yaml values take precedence over config.py defaults
            tool_config_override_fields = {
                "FW_INVENTORY_TABLE_PROPERTIES",
                "ADDITIONAL_OOB_URI_COLLECTION",
                "NVLINK_OOB_URI",
                "CUSTOM_DUMP_SERVICES",
                "POST_CODES_URI",
                "BMC_TEMP_DIR",
                "REDFISH_DUMP_TIMEOUT",
                "NVOS_TECH_DUMP_TIMEOUT",
                "REDFISH_DEVICE_DUMP_SLEEP_DURATION",
            }

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Tool config override check - tool_config keys: {list(self.tool_config.keys())}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Tool config FW_INVENTORY_TABLE_PROPERTIES: {self.tool_config.get('FW_INVENTORY_TABLE_PROPERTIES', 'NOT_FOUND')}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Tool config BMC_TEMP_DIR: {self.tool_config.get('BMC_TEMP_DIR', 'NOT_FOUND')}",
            )

            for field in tool_config_override_fields:
                if field in self.tool_config and self.tool_config[field]:
                    old_value = config.get(field, "NOT_SET")
                    config[field] = self.tool_config[field]
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "DUTManager",
                        f"DUT {dut_id}: Overriding {field} from tool config: {old_value} -> {self.tool_config[field]}",
                    )
                else:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        f"DUT {dut_id}: No tool config override for {field} - tool_config has: {self.tool_config.get(field, 'NOT_FOUND')}",
                    )

            # Log final config values after override
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Final config BMC_TEMP_DIR: {config.get('BMC_TEMP_DIR', 'NOT_SET')}",
            )

            # Log skip flag values for debugging
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Skip flags after merge - SKIP_BMC_SSH_LOGS={config.get('SKIP_BMC_SSH_LOGS')}, SKIP_HOST_LOGS={config.get('SKIP_HOST_LOGS')}, SKIP_REDFISH_OOB_LOGS={config.get('SKIP_REDFISH_OOB_LOGS')}, SKIP_IPMI_LOGS={config.get('SKIP_IPMI_LOGS')}",
            )

            await self._create_single_dut_object(dut_id, config, explicit_keys)
            processed_duts += 1
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Created DUT {dut_id} ({processed_duts}/{total_duts})",
            )

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Successfully created {total_duts} DUT objects",
        )

        # Initialize all DUTs (call async_init on each DUT)
        await self.initialize_duts()

    async def _create_single_dut_object(
        self,
        dut_id: str,
        config: Dict[str, Any],
        explicit_keys: Optional[Set[str]] = None,
    ) -> None:
        """
        Create a single DUT object with the given configuration.

        Args:
            dut_id: DUT ID.
            config: DUT configuration.
            explicit_keys: Explicit keys.
        """
        # Load baseboard configuration if baseboard is specified
        baseboard_name = config.get("baseboard")
        if baseboard_name:
            baseboard_manager = self._get_baseboard_manager()
            baseboard_config = baseboard_manager.get_baseboard_config(baseboard_name)
            if baseboard_config:
                # Preserve explicit/CLI-provided HMC_IP before merge so baseboard defaults don't override it
                original_hmc_ip = config.get("HMC_IP") or config.get("hmc_ip")

                # Merge baseboard config into DUT config (defaults only)
                config = {**config, **baseboard_config}

                # Extract HMC_IP from platform_detection if not already at top level
                if not original_hmc_ip:
                    platform_detection = config.get("platform_detection", {})
                    if isinstance(platform_detection, dict) and platform_detection.get(
                        "hmc_ip"
                    ):
                        config["HMC_IP"] = platform_detection["hmc_ip"]
                        config["hmc_ip"] = platform_detection["hmc_ip"]
                        await self.logger.log_runtime(
                            "INFO",
                            "DUTManager",
                            f"Extracted HMC_IP from baseboard platform_detection: {platform_detection['hmc_ip']}",
                        )

                # Restore HMC_IP if it was explicitly provided
                if original_hmc_ip:
                    if config.get("HMC_IP") != original_hmc_ip:
                        await self.logger.log_runtime(
                            "INFO",
                            "DUTManager",
                            f"Preserving CLI/DUT override for HMC_IP: {original_hmc_ip} (replacing baseboard value {config.get('HMC_IP')})",
                        )
                    config["HMC_IP"] = original_hmc_ip
                    config["hmc_ip"] = original_hmc_ip

                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Loaded baseboard configuration for '{baseboard_name}' into DUT {dut_id}",
                )
                # Log key baseboard configuration values for debugging
                await self.logger.log_runtime(
                    "DEBUG",
                    "DUTManager",
                    f"Baseboard config - supports_hmc: {baseboard_config.get('supports_hmc', 'Not found')}, platform_detection: {baseboard_config.get('platform_detection', 'Not found')}",
                )
            else:
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Baseboard '{baseboard_name}' not found in baseboard configuration for DUT {dut_id}",
                )

        # Create credentials
        # Ensure credentials.hmc_ip respects explicit config before any auto-configuration later
        explicit_hmc_ip = config.get("HMC_IP") or config.get("hmc_ip")

        credentials = DUTCredentials(
            bmc_ip=config.get("BMC_IP", ""),
            bmc_username=config.get("BMC_USERNAME", ""),
            bmc_password=config.get("BMC_PASSWORD", ""),
            bmc_ssh_username=config.get("BMC_SSH_USERNAME"),
            bmc_ssh_password=config.get("BMC_SSH_PASSWORD"),
            bmc_ssh_port=config.get("BMC_SSH_PORT", 22),
            bmc_ssh_key_path=config.get("BMC_SSH_KEY_PATH"),
            bmc_ssh_passwordless=config.get("BMC_SSH_PASSWORDLESS", False),
            bmc_ssh_max_retries=config.get("BMC_SSH_MAX_RETRIES", 3),
            bmc_rf_port=config.get("BMC_RF_PORT", 443),
            bmc_use_https=config.get("bmc_use_https", True),
            bmc_rf_verify_ssl=config.get("bmc_rf_verify_ssl", False),
            host_ip=config.get("HOST_IP"),
            host_username=config.get("HOST_USERNAME"),
            host_password=config.get("HOST_PASSWORD"),
            host_ssh_port=config.get("HOST_SSH_PORT", 22),
            host_ssh_key_path=config.get("HOST_SSH_KEY_PATH"),
            host_ssh_passwordless=config.get("HOST_SSH_PASSWORDLESS", False),
            host_ssh_max_retries=config.get("HOST_SSH_MAX_RETRIES", 3),
            rf_username=config.get("RF_User"),
            rf_password=config.get("RF_Pass"),
            tunnel_tcp_port=config.get("TUNNEL_TCP_PORT"),
            ipmi_cipher=config.get("ipmi_cipher", "-C17"),
            # HMC Configuration
            hmc_ip=explicit_hmc_ip or config.get("HMC_IP"),
            hmc_username=config.get("HMC_USERNAME"),
            hmc_password=config.get("HMC_PASSWORD"),
            hmc_ssh_username=config.get("HMC_SSH_USERNAME"),
            hmc_ssh_password=config.get("HMC_SSH_PASSWORD"),
            hmc_ssh_port=config.get("HMC_SSH_PORT", 22),
            hmc_ssh_key_path=config.get("HMC_SSH_KEY_PATH"),
            hmc_ssh_passwordless=config.get("HMC_SSH_PASSWORDLESS", False),
            hmc_ssh_max_retries=config.get("HMC_SSH_MAX_RETRIES", 3),
            hmc_http_port=config.get("HMC_HTTP_PORT", 80),
            hmc_https_port=config.get("HMC_HTTPS_PORT", 443),
            hmc_use_https=config.get("HMC_USE_HTTPS", True),
            use_port_forwarding=config.get("USE_PORT_FORWARDING", False),
            rf_hmc_access_method=config.get("RF_HMC_ACCESS_METHOD"),
            execution_mode=config.get("ExecutionMode", "remote"),
            # SSH Proxy Configuration
            ssh_proxy_host=config.get("ssh_proxy_host"),
            ssh_proxy_port=config.get("ssh_proxy_port", 22),
            ssh_proxy_username=config.get(
                "ssh_proxy_user"
            ),  # Map ssh_proxy_user to ssh_proxy_username
            ssh_proxy_password=config.get(
                "ssh_proxy_pass"
            ),  # Map ssh_proxy_pass to ssh_proxy_password
            ssh_proxy_key_path=config.get("ssh_proxy_key_path"),
            ssh_proxy_passwordless=config.get("ssh_proxy_passwordless", False),
            ssh_proxy_max_retries=config.get("ssh_proxy_max_retries", 3),
        )

        dut = DUT(dut_id, credentials, config, self)
        dut.logger = self.logger  # Give DUT access to the logger
        # Store explicit keys for configuration precedence
        dut.explicit_config_keys = explicit_keys or {}
        self.duts[dut_id] = dut

    async def _load_dut_specific_config(
        self, dut_id: str, dut_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Load DUT-specific configuration file if ConfigFileToUse is specified.

        Args:
            dut_id: The DUT identifier
            dut_config: The DUT configuration

        Returns:
            dict: Merged configuration with DUT-specific overrides
        """
        try:
            config_file_to_use = dut_config.get("ConfigFileToUse")
            if not config_file_to_use:
                return dut_config

            # Load the DUT-specific config file
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Loading DUT-specific config for {dut_id}: {config_file_to_use}",
            )
            dut_specific_config = YAMLManager.load_yaml(
                config_file_to_use, f"DUT-specific config for {dut_id}"
            )

            # Merge configurations: DUT config overrides DUT-specific config
            merged_config = {**dut_specific_config, **dut_config}

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Successfully loaded DUT-specific config for {dut_id}",
            )
            return merged_config

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                f"Failed to load DUT-specific config for {dut_id}: {e}",
            )
            return dut_config

    async def initialize_duts(self) -> None:
        """
        Initialize all DUTs (setup logging, test connections).
        """
        tasks = []
        for dut_id, dut in self.duts.items():
            tasks.append(self._initialize_single_dut(dut_id, dut))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def cleanup_all_ssh_proxy_tunnels(self) -> None:
        """
        Clean up SSH proxy tunnels for all DUTs.
        """
        cleanup_tasks = []
        for dut_id, dut in self.duts.items():
            if hasattr(dut, "ssh_proxy_service") and dut.ssh_proxy_service:
                cleanup_tasks.append(dut.cleanup_ssh_proxy_tunnels())

        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Cleaned up SSH proxy tunnels for {len(cleanup_tasks)} DUT(s)",
            )
        else:
            # Fallback to direct cleanup if no tasks found
            self._kill_all_ssh_tunnels_direct()

    def cleanup_all_ssh_proxy_tunnels_sync(self) -> None:
        """
        Synchronous cleanup of SSH proxy tunnels for all DUTs.
        """
        try:
            # Try to get the current event loop
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If there's a running loop, we can't use asyncio.run()
                # Instead, we'll use a more direct approach to kill SSH processes
                self._kill_all_ssh_tunnels_direct()
            else:
                # No running loop, safe to use asyncio.run()
                asyncio.run(self.cleanup_all_ssh_proxy_tunnels())
        except RuntimeError as e:
            # No event loop, safe to use asyncio.run()
            try:
                asyncio.run(self.cleanup_all_ssh_proxy_tunnels())
            except Exception as e2:
                self._kill_all_ssh_tunnels_direct()
        except Exception as e:
            # Fallback to direct SSH process killing
            print(
                f"Warning: Async cleanup failed ({e}), using direct SSH process cleanup"
            )
            self._kill_all_ssh_tunnels_direct()

    def _kill_all_ssh_tunnels_direct(self) -> None:
        """
        Directly kill all SSH tunnel processes as a fallback.
        """
        try:
            import subprocess

            # Kill all SSH processes with port forwarding
            result = subprocess.run(
                ["pkill", "-f", "ssh.*-L.*localhost:180"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print("Cleaned up SSH proxy tunnels (direct method)")
            else:
                pass
                # print("No SSH proxy tunnels found to clean up")
        except Exception as e:
            print(f"Warning: Failed to clean up SSH tunnels directly: {e}")

    async def _initialize_single_dut(self, dut_id: str, dut: DUT) -> None:
        """
        Initialize a single DUT.

        Args:
            dut_id: DUT ID.
            dut: DUT instance.
        """
        try:
            await dut.setup_logging(self.base_log_dir)
            await dut.async_init()  # Initialize HMC platform detection

            # Log SSH proxy configuration if present
            if dut.credentials.ssh_proxy_host:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    f"SSH proxy configured: {dut.credentials.ssh_proxy_host}:{dut.credentials.ssh_proxy_port} (user: {dut.credentials.ssh_proxy_username})",
                )
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"DUT {dut_id}: SSH proxy configured - {dut.credentials.ssh_proxy_host}:{dut.credentials.ssh_proxy_port}",
                )

            await self.logger.write_to_dut_runtime_log(
                dut_id, "INFO", "DUTManager", f"Initialized DUT {dut_id}"
            )
        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                f"Failed to initialize DUT {dut_id}: {e}",
            )

    def get_dut(self, dut_id: str) -> DUT:
        """
        Get a DUT by ID.

        Args:
            dut_id: DUT ID.

        Returns:
            DUT instance.

        Raises:
            KeyError: If DUT ID not found.
        """
        if dut_id not in self.duts:
            raise ValueError(f"DUT {dut_id} not found")
        return self.duts[dut_id]

    def get_all_dut_ids(self) -> List[str]:
        """
        Get all DUT IDs.

        Returns:
            List of DUT IDs.
        """
        return list(self.duts.keys())

    def get_dut_config(self, dut_id: str) -> Dict[str, Any]:
        """
        Get DUT configuration by ID.

        Args:
            dut_id: DUT ID.

        Returns:
            DUT configuration dictionary.

        Raises:
            ValueError: If DUT ID not found.
        """
        if dut_id not in self.duts:
            raise ValueError(f"DUT {dut_id} not found")
        return self.duts[dut_id].config

    async def run_preflight_checks(
        self,
        required_collector_groups: Optional[List[str]] = None,
        show_progress: bool = True,
    ) -> Dict[str, Any]:
        """
        Run preflight checks on all DUTs in parallel with comprehensive logging and progress bar

        Args:
            required_collector_groups: List of collector groups that will be executed.
                                     If None, runs all preflight checks.
                                     Valid groups: ["redfish", "ipmi", "ssh", "host"]
        """
        if not self.duts:
            await self.logger.log_runtime("ERROR", "DUTManager", "No DUTs configured")
            return {}

        # Determine which services to check based on collector groups
        services_to_check = self._get_services_for_collector_groups(
            required_collector_groups
        )

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Running preflight checks on {len(self.duts)} DUT(s) for services: {', '.join(services_to_check)}",
        )

        # Use the same console setup as workflow orchestrator
        if hasattr(self.logger, "original_stdout") and self.logger.original_stdout:
            console = Console(file=self.logger.original_stdout, force_terminal=True)
        else:
            console = Console(force_terminal=True)

        results = {}

        # Calculate total tasks: DUTs × services
        total_tasks = len(self.duts) * len(services_to_check)

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                refresh_per_second=10,
            ) as progress:

                main_task = progress.add_task(
                    f"[cyan]Preflight Checks ({len(self.duts)} DUTs × {len(services_to_check)} services) - DUTs Parallel, Services Sequential",
                    total=total_tasks,
                )

                # Run DUTs in parallel, but services sequentially within each DUT
                dut_tasks = []
                for dut_id, dut in self.duts.items():
                    task = self._run_dut_preflight_parallel(
                        dut_id, dut, progress, main_task, services_to_check
                    )
                    dut_tasks.append(task)

                # Wait for all DUTs to complete in parallel
                dut_results = await asyncio.gather(*dut_tasks, return_exceptions=True)

                # Process results
                for i, result in enumerate(dut_results):
                    dut_id = list(self.duts.keys())[i]
                    if isinstance(result, Exception):
                        # Handle exception
                        results[dut_id] = {
                            "dut_id": dut_id,
                            "services": {},
                            "overall_status": "fail",
                            "timestamp": datetime.now().isoformat(),
                            "error": str(result),
                        }
                        await self.logger.log_runtime(
                            "ERROR",
                            f"DUT:{dut_id}",
                            f"Preflight failed with exception: {result}",
                        )
                    else:
                        results[dut_id] = result
        else:
            # Run without progress bar
            dut_tasks = []
            for dut_id, dut in self.duts.items():
                task = self._run_dut_preflight_no_progress(
                    dut_id, dut, services_to_check
                )
                dut_tasks.append(task)

            # Wait for all DUTs to complete in parallel
            dut_results = await asyncio.gather(*dut_tasks, return_exceptions=True)

            # Process results
            for i, result in enumerate(dut_results):
                dut_id = list(self.duts.keys())[i]
                if isinstance(result, Exception):
                    # Handle exception
                    results[dut_id] = {
                        "dut_id": dut_id,
                        "services": {},
                        "overall_status": "fail",
                        "timestamp": datetime.now().isoformat(),
                        "error": str(result),
                    }
                    await self.logger.log_runtime(
                        "ERROR",
                        f"DUT:{dut_id}",
                        f"Preflight failed with exception: {result}",
                    )
                else:
                    results[dut_id] = result

        # Store preflight results in DUT objects for easy access by validation methods
        for dut_id, dut_result in results.items():
            if dut_id in self.duts:
                self.duts[dut_id].preflight_results = dut_result

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Preflight checks completed for all DUTs in parallel",
        )
        return results

    def _get_services_for_collector_groups(
        self, collector_groups: Optional[List[str]] = None
    ) -> List[str]:
        """
        Determine which services to check based on collector groups

        Args:
            collector_groups: List of collector groups that will be executed

        Returns:
            List of services to check in preflight
        """
        if collector_groups is None:
            # Run all services if no specific groups provided
            return ["redfish", "ipmi", "ssh", "host"]

        services_to_check = []

        # Always include redfish for platform discovery (needed for baseboard detection)
        if "redfish" not in services_to_check:
            services_to_check.append("redfish")

        # Map collector groups to services
        for group in collector_groups:
            if group == "redfish" and "redfish" not in services_to_check:
                services_to_check.append("redfish")
            elif group == "ipmi" and "ipmi" not in services_to_check:
                services_to_check.append("ipmi")
            elif (group == "ssh") and "ssh" not in services_to_check:
                services_to_check.append("ssh")
            elif group == "host" and "host" not in services_to_check:
                services_to_check.append("host")

        return services_to_check

    async def _run_dut_preflight_parallel(
        self,
        dut_id: str,
        dut: "DUT",
        progress,
        main_task,
        services_to_check: List[str],
    ) -> Dict[str, Any]:
        """
        Run preflight checks for a single DUT with all services in parallel.

        Args:
            dut_id: DUT ID.
            dut: DUT instance.
            progress: Progress bar instance.
            main_task: Main task ID for progress tracking.
            services_to_check: List of services to check.

        Returns:
            Dictionary with preflight results for the DUT.
        """
        await self.logger.log_runtime(
            "INFO",
            f"DUT:{dut_id}",
            f"Starting parallel preflight checks for DUT {dut_id}",
        )

        dut_result = {
            "dut_id": dut_id,
            "services": {},
            "overall_status": "pass",
            "timestamp": datetime.now().isoformat(),
        }

        # Define all services to test
        all_services = [
            ("redfish", self._fast_redfish_check, dut),
            ("ipmi", self._fast_ipmi_check, dut),
            ("ssh", self._fast_ssh_check, dut),
            ("host", self._fast_host_check, dut),
        ]

        # Filter services based on what's needed
        services = [
            service for service in all_services if service[0] in services_to_check
        ]

        # Run services sequentially to avoid resource contention
        service_results = []
        for service_name, test_func, dut_obj in services:
            # Check for shutdown request before each service
            if (
                hasattr(self.logger, "orchestrator")
                and self.logger.orchestrator
                and hasattr(self.logger.orchestrator, "is_shutdown_requested")
                and self.logger.orchestrator.is_shutdown_requested()
            ):
                await self.logger.log_runtime(
                    "WARN",
                    f"DUT:{dut_id}",
                    f"Shutdown requested, skipping {service_name} preflight check",
                )
                dut_result["services"][service_name] = {
                    "status": "interrupted",
                    "message": "Shutdown requested",
                }
                dut_result["overall_status"] = "interrupted"
                break

            result = await self._run_service_preflight_parallel(
                service_name, test_func, dut_obj, dut_id, progress, main_task
            )
            service_results.append(result)

        # Process service results
        for i, result in enumerate(service_results):
            service_name = services[i][0]
            if isinstance(result, Exception):
                # Handle exception
                dut_result["services"][service_name] = {
                    "status": "fail",
                    "message": f"Exception during {service_name} test: {str(result)}",
                }
                dut_result["overall_status"] = "fail"
                await self.logger.log_runtime(
                    "ERROR",
                    f"DUT:{dut_id}",
                    f"{service_name} service exception: {str(result)}",
                )
            else:
                success, message = result
                dut_result["services"][service_name] = {
                    "status": "pass" if success else "fail",
                    "message": message,
                }

                if not success:
                    dut_result["overall_status"] = "fail"
                    await self.logger.log_runtime(
                        "WARN",
                        f"DUT:{dut_id}",
                        f"{service_name} service failed: {message}",
                    )
                else:
                    await self.logger.log_runtime(
                        "INFO",
                        f"DUT:{dut_id}",
                        f"{service_name} service passed: {message}",
                    )

        status_msg = "PASSED" if dut_result["overall_status"] == "pass" else "FAILED"
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "PreflightChecks",
            f"Preflight checks {status_msg} for DUT {dut_id}",
        )

        return dut_result

    async def _run_dut_preflight_no_progress(
        self, dut_id: str, dut: "DUT", services_to_check: List[str]
    ) -> Dict[str, Any]:
        """
        Run preflight checks for a single DUT without progress bar.

        Args:
            dut_id: DUT ID.
            dut: DUT instance.
            services_to_check: List of services to check.
        """
        await self.logger.log_runtime(
            "INFO",
            f"DUT:{dut_id}",
            f"Starting preflight checks for DUT {dut_id}",
        )

        dut_result = {
            "dut_id": dut_id,
            "services": {},
            "overall_status": "pass",
            "timestamp": datetime.now().isoformat(),
        }

        # Define all services to test
        all_services = [
            ("redfish", self._fast_redfish_check, dut),
            ("ipmi", self._fast_ipmi_check, dut),
            ("ssh", self._fast_ssh_check, dut),
            ("host", self._fast_host_check, dut),
        ]

        # Filter services based on what's needed
        services = [
            service for service in all_services if service[0] in services_to_check
        ]

        # Run services sequentially to avoid resource contention
        service_results = []
        for service_name, test_func, dut_obj in services:
            result = await self._run_service_preflight_no_progress(
                service_name, test_func, dut_obj, dut_id
            )
            service_results.append(result)

        # Process service results
        for i, result in enumerate(service_results):
            service_name = services[i][0]
            if isinstance(result, Exception):
                # Handle exception
                dut_result["services"][service_name] = {
                    "status": "fail",
                    "message": f"Exception during {service_name} test: {str(result)}",
                }
                dut_result["overall_status"] = "fail"
                await self.logger.log_runtime(
                    "ERROR",
                    f"DUT:{dut_id}",
                    f"{service_name} service exception: {str(result)}",
                )
            else:
                success, message = result
                dut_result["services"][service_name] = {
                    "status": "pass" if success else "fail",
                    "message": message,
                }

                if not success:
                    dut_result["overall_status"] = "fail"
                    await self.logger.log_runtime(
                        "WARN",
                        f"DUT:{dut_id}",
                        f"{service_name} service failed: {message}",
                    )
                else:
                    await self.logger.log_runtime(
                        "INFO",
                        f"DUT:{dut_id}",
                        f"{service_name} service passed: {message}",
                    )

        status_msg = "PASSED" if dut_result["overall_status"] == "pass" else "FAILED"
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "PreflightChecks",
            f"Preflight checks {status_msg} for DUT {dut_id}",
        )

        return dut_result

    async def _run_service_preflight_parallel(
        self,
        service_name: str,
        test_func,
        dut_obj,
        dut_id: str,
        progress,
        main_task,
    ) -> Tuple[bool, str]:
        """
        Run a single service preflight check with progress updates.

        Args:
            service_name: Name of service being checked.
            test_func: Test function to execute.
            dut_obj: DUT instance.
            dut_id: DUT ID.
            progress: Progress bar instance.
            main_task: Main task ID for progress tracking.

        Returns:
            Tuple of (success, message).
        """
        # Update progress description
        progress.update(
            main_task,
            description=f"[cyan]Preflight: {service_name}[/cyan] on [yellow]{dut_id}[/yellow]",
        )
        progress.refresh()

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "PreflightChecks",
            f"Testing {service_name} service in parallel...",
        )

        try:
            success, message = await test_func(dut_obj)

            # Update progress with status
            status_text = "pass" if success else "fail"
            progress.update(
                main_task,
                description=f"[cyan]Preflight: {service_name}[/cyan] on [yellow]{dut_id}[/yellow] - {status_text}",
            )
            progress.advance(main_task)

            return success, message

        except Exception as e:
            # Update progress with error status
            progress.update(
                main_task,
                description=f"[cyan]Preflight: {service_name}[/cyan] on [yellow]{dut_id}[/yellow] - error",
            )
            progress.advance(main_task)

            raise e

    async def _run_service_preflight_no_progress(
        self, service_name: str, test_func, dut_obj, dut_id: str
    ) -> Tuple[bool, str]:
        """
        Run a single service preflight check without progress updates.

        Args:
            service_name: Name of service being checked.
            test_func: Test function to execute.
            dut_obj: DUT instance.
            dut_id: DUT ID.

        Returns:
            Tuple of (success, message).
        """
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "PreflightChecks",
            f"Testing {service_name} service...",
        )

        try:
            success, message = await test_func(dut_obj)
            return success, message

        except Exception as e:
            raise e

    async def _fast_redfish_check(self, dut: "DUT") -> Tuple[bool, str]:
        """
        Fast Redfish check using ping first, then actual interface test.

        Args:
            dut: DUT instance.

        Returns:
            Tuple of (success, message).
        """
        if not dut.credentials.bmc_ip:
            return False, "No BMC IP configured"

        # Check if SSH proxy is configured
        if dut.credentials.ssh_proxy_host:
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Using SSH proxy {dut.credentials.ssh_proxy_host} for Redfish preflight check",
            )
            # Skip direct ping when using proxy - go straight to Redfish test
        else:
            # No proxy - use direct ping first
            ping_success = await dut._ping_host(dut.credentials.bmc_ip)
            if not ping_success:
                return (
                    False,
                    f"BMC {dut.credentials.bmc_ip} not reachable via ping",
                )

        # Then test actual Redfish interface using DUT method
        try:
            # Use the DUT's redfish method with timeout
            # Increase timeout for SSH proxy scenarios (tunnel setup takes time)
            timeout = 30.0 if dut.credentials.ssh_proxy_host else 10.0
            success, response = await asyncio.wait_for(
                dut.test_redfish_connection(), timeout=timeout
            )
            if success:
                return True, "Redfish interface accessible"
            else:
                return False, f"Redfish interface failed: {response}"
        except asyncio.TimeoutError:
            timeout_msg = f"Redfish interface timeout ({timeout}s)"
            return False, timeout_msg
        except Exception as e:
            return False, f"Redfish interface error: {str(e)}"

    async def _fast_ipmi_check(self, dut: "DUT") -> Tuple[bool, str]:
        """
        Fast IPMI check using ping first, then actual interface test.

        Args:
            dut: DUT instance.

        Returns:
            Tuple of (success, message).
        """
        # In local mode, IPMI can work via sudo commands even without BMC IP
        if dut.config and dut.config.get("local", False):
            return True, "Local IPMI execution via sudo"

        if not dut.credentials.bmc_ip:
            return False, "No BMC IP configured"

        # Check if SSH proxy is configured
        if dut.credentials.ssh_proxy_host:
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Using SSH proxy {dut.credentials.ssh_proxy_host} for IPMI preflight check",
            )
            # Skip direct ping when using proxy - go straight to IPMI test
        else:
            # No proxy - use direct ping first
            ping_success = await dut._ping_host(dut.credentials.bmc_ip)
            if not ping_success:
                return (
                    False,
                    f"BMC {dut.credentials.bmc_ip} not reachable via ping",
                )

        # Then test actual IPMI interface using DUT method
        try:
            # Use the DUT's ipmi method with timeout
            success, response = await asyncio.wait_for(
                dut.test_ipmi_connection(), timeout=5.0
            )
            if success:
                return True, "IPMI interface accessible"
            else:
                return False, f"IPMI interface failed: {response}"
        except asyncio.TimeoutError:
            return False, "IPMI interface timeout (5s)"
        except Exception as e:
            return False, f"IPMI interface error: {str(e)}"

    async def _fast_ssh_check(self, dut: "DUT") -> Tuple[bool, str]:
        """
        Fast SSH check using ping first, then actual interface test.

        Args:
            dut: DUT instance.

        Returns:
            Tuple of (success, message).
        """
        if not dut.credentials.bmc_ip:
            return False, "No BMC IP configured"

        # Check if SSH proxy is configured
        if dut.credentials.ssh_proxy_host:
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Using SSH proxy {dut.credentials.ssh_proxy_host} for SSH preflight check",
            )
            # Skip direct ping when using proxy - go straight to SSH test
            try:
                # Use the DUT's ssh method with timeout
                success, response = await asyncio.wait_for(
                    dut.test_ssh_connection(), timeout=30.0
                )
                if success:
                    return (
                        True,
                        f"SSH interface accessible via SSH proxy {dut.credentials.ssh_proxy_host}",
                    )
                else:
                    return False, f"SSH interface failed via proxy: {response}"
            except asyncio.TimeoutError:
                return False, "SSH interface timeout (30s)"
            except Exception as e:
                return False, f"SSH interface error: {str(e)}"
        else:
            # No proxy - use direct ping first
            ping_success = await dut._ping_host(dut.credentials.bmc_ip)
            if not ping_success:
                return (
                    False,
                    f"BMC {dut.credentials.bmc_ip} not reachable via ping",
                )

            # Then test actual SSH interface using DUT method
            try:
                # Use the DUT's ssh method with timeout
                success, response = await asyncio.wait_for(
                    dut.test_ssh_connection(), timeout=30.0
                )
                if success:
                    return True, "SSH interface accessible"
                else:
                    return False, f"SSH interface failed: {response}"
            except asyncio.TimeoutError:
                return False, "SSH interface timeout (30s)"
            except Exception as e:
                return False, f"SSH interface error: {str(e)}"

    async def _fast_host_check(self, dut: "DUT") -> Tuple[bool, str]:
        """
        Fast host check using ping first, then actual interface test.

        Args:
            dut: DUT instance.

        Returns:
            Tuple of (success, message).
        """
        if not dut.credentials.host_ip:
            return True, "Local host execution"

        # Check if SSH proxy is configured
        if dut.credentials.ssh_proxy_host:
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Using SSH proxy {dut.credentials.ssh_proxy_host} for host preflight check",
            )
            # Skip direct ping when using proxy - go straight to SSH test
            try:
                # Use the DUT's host method with timeout
                success, response = await asyncio.wait_for(
                    dut.test_host_connection(), timeout=30.0
                )
                if success:
                    return (
                        True,
                        f"Host interface accessible via SSH proxy {dut.credentials.ssh_proxy_host}",
                    )
                else:
                    return False, f"Host interface failed via proxy: {response}"
            except asyncio.TimeoutError:
                return False, "Host interface timeout (30s)"
            except Exception as e:
                return False, f"Host interface error: {str(e)}"
        else:
            # No proxy - use direct ping first
            ping_success = await dut._ping_host(dut.credentials.host_ip)
            if not ping_success:
                return (
                    False,
                    f"Host {dut.credentials.host_ip} not reachable via ping",
                )

            # Then test actual host interface using DUT method
            try:
                # Use the DUT's host method with timeout
                success, response = await asyncio.wait_for(
                    dut.test_host_connection(), timeout=30.0
                )
                if success:
                    return True, "Host interface accessible"
                else:
                    return False, f"Host interface failed: {response}"
            except asyncio.TimeoutError:
                return False, "Host interface timeout (30s)"
            except Exception as e:
                return False, f"Host interface error: {str(e)}"

    async def execute_redfish_request(
        self,
        dut_id: str,
        method: str,
        url: str,
        body: Any = None,
        timeout: int = 300,
        get_raw_content: bool = False,
        bypass_cache: bool = False,
        retry_count: int = 3,  # Default retry count, can be overridden by collector definition
    ) -> Tuple[bool, Union[str, dict, bytes], dict, dict]:
        """
        Execute Redfish request with session management, prefix handling, and caching.

        Args:
            dut_id: DUT ID.
            method: HTTP method (GET, POST, etc).
            url: Redfish URI.
            body: Optional request body.
            timeout: Request timeout in seconds.
            get_raw_content: Whether to return raw binary content.
            bypass_cache: Whether to bypass response cache.
            retry_count: Number of retry attempts.

        Returns:
            Tuple of (success, response, metadata, headers).
        """
        dut = self.get_dut(dut_id)

        # Ensure Redfish connection is established
        success, message = await self._ensure_connection(
            dut_id, "redfish", "test_redfish_connection"
        )
        if not success:
            return (
                False,
                message,
                {"error": "connection_failed", "message": message},
                {},
            )

        # Normalize URI with prefix handling
        normalized_url = dut.normalize_redfish_uri(url)

        # Check cache for GET requests (unless bypass_cache is True)
        if (
            method.upper() == "GET"
            and not bypass_cache
            and dut._get_cached_response(normalized_url)
        ):
            await dut._log_runtime(
                "DEBUG", f"Using cached response for {normalized_url}"
            )
            return True, dut._get_cached_response(normalized_url), {}, {}
        elif method.upper() == "GET" and bypass_cache:
            await dut._log_runtime("DEBUG", f"Bypassing cache for {normalized_url}")

        # Get connection info (handles HMC transparency)
        # If HMC mode is active, this returns localhost:port
        # If not, this returns the direct BMC connection
        connection_info = dut.get_redfish_connection_info()

        # Build the full URL using the connection info
        protocol = "https" if connection_info["use_https"] else "http"
        full_url = f"{protocol}://{connection_info['host']}:{connection_info['port']}{normalized_url}"

        # Use credentials from connection info (HMC or BMC)
        username = connection_info["username"]
        password = connection_info["password"]

        # Retry configuration with exponential backoff
        max_retries = retry_count
        base_delay = 1  # Start with 1 second
        max_delay = 30  # Cap at 30 seconds
        retryable_status_codes = {500, 502, 503, 504, 520, 521, 522, 523, 524}

        # Log request start
        await dut._log_runtime(
            "DEBUG",
            f"Starting {method} request to {normalized_url} (timeout={timeout}s, max_retries={max_retries})",
        )

        for attempt in range(max_retries + 1):
            current_delay = min(
                base_delay * (2**attempt), max_delay
            )  # Exponential backoff

            try:
                # Log attempt
                if attempt > 0:
                    await dut._log_runtime(
                        "INFO",
                        f"Retry attempt {attempt}/{max_retries} for {method} {normalized_url} (delay={current_delay}s)",
                    )

                # Use high-performance session pool if available
                if dut.redfish_session_pool:
                    await dut._log_runtime(
                        "DEBUG",
                        f"Using high-performance session pool for request (timeout={timeout}s)",
                    )
                    session_obj = await dut.redfish_session_pool.get_session()
                    if (
                        session_obj
                        and session_obj["session"]
                        and not session_obj["session"].closed
                    ):
                        try:
                            async with session_obj["session"].request(
                                method,
                                full_url,
                                auth=session_obj["auth"],
                                json=body if body else None,
                                ssl=False,
                                timeout=aiohttp.ClientTimeout(total=timeout),
                            ) as response:
                                result = await self._handle_redfish_response(
                                    dut,
                                    response,
                                    normalized_url,
                                    method,
                                    attempt,
                                    max_retries,
                                    current_delay,
                                    retryable_status_codes,
                                    get_raw_content,
                                )
                                # No need to release - shared session
                                return result
                        except Exception as e:
                            # Check for session conflicts and handle them
                            if (
                                dut.redfish_session_pool
                                and await dut.redfish_session_pool.handle_session_conflict(
                                    e
                                )
                            ):
                                # Session was reinitialized, retry the request
                                if attempt < max_retries:
                                    await dut._log_runtime(
                                        "INFO",
                                        f"Session conflict detected, retrying request after session reinitialization (attempt {attempt + 1}/{max_retries + 1})",
                                    )
                                    await asyncio.sleep(current_delay)
                                    continue
                            # No need to release - shared session
                            raise e
                    else:
                        await dut._log_runtime(
                            "WARNING",
                            "Session pool not available, falling back to single session",
                        )

                # Use persistent session if available, otherwise create temporary session
                if dut.redfish_session and dut.redfish_auth:
                    await dut._log_runtime(
                        "DEBUG",
                        f"Using single session for request (timeout={timeout}s)",
                    )
                else:
                    await dut._log_runtime(
                        "DEBUG",
                        f"Creating temporary session for request (timeout={timeout}s)",
                    )
                if dut.redfish_session and dut.redfish_auth:
                    # Use existing session
                    async with dut.redfish_session.request(
                        method,
                        full_url,
                        auth=dut.redfish_auth,
                        json=body if body else None,
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                    ) as response:
                        return await self._handle_redfish_response(
                            dut,
                            response,
                            normalized_url,
                            method,
                            attempt,
                            max_retries,
                            current_delay,
                            retryable_status_codes,
                            get_raw_content,
                        )
                else:
                    # Create temporary session
                    async with aiohttp.ClientSession() as session:
                        async with session.request(
                            method,
                            full_url,
                            auth=aiohttp.BasicAuth(username, password),
                            json=body if body else None,
                            ssl=False,
                            timeout=aiohttp.ClientTimeout(total=timeout),
                        ) as response:
                            return await self._handle_redfish_response(
                                dut,
                                response,
                                normalized_url,
                                method,
                                attempt,
                                max_retries,
                                current_delay,
                                retryable_status_codes,
                                get_raw_content,
                            )

            except (
                asyncio.TimeoutError,
                aiohttp.ClientConnectorError,
                aiohttp.ServerDisconnectedError,
            ) as e:
                # Connection failures - retry if we have attempts left
                await dut._log_runtime(
                    "WARNING",
                    f"Connection error on attempt {attempt + 1}/{max_retries + 1} for {method} {normalized_url}: {str(e)}",
                )

                if attempt < max_retries:
                    await dut._log_runtime(
                        "INFO",
                        f"Waiting {current_delay}s before retry {attempt + 2}/{max_retries + 1}",
                    )
                    await asyncio.sleep(current_delay)
                    continue
                else:
                    await dut._log_runtime(
                        "ERROR",
                        f"All {max_retries + 1} attempts failed for {method} {normalized_url}: {str(e)}",
                    )
                    return (
                        False,
                        f"Redfish connection error after {max_retries + 1} attempts: {str(e)}",
                        {
                            "error": "connection_failed",
                            "message": str(e),
                            "attempts": max_retries + 1,
                        },
                        {},
                    )
            except Exception as e:
                # Other errors - don't retry
                await dut._log_runtime(
                    "ERROR",
                    f"Non-retryable error on attempt {attempt + 1}/{max_retries + 1} for {method} {normalized_url}: {str(e)}",
                )
                return (
                    False,
                    f"Redfish request error: {str(e)}",
                    {"error": "exception", "message": str(e)},
                    {},
                )

    async def _handle_redfish_response(
        self,
        dut: "DUT",
        response: aiohttp.ClientResponse,
        uri: str,
        method: str,
        attempt: int,
        max_retries: int,
        current_delay: float,
        retryable_status_codes: set,
        get_raw_content: bool = False,
    ) -> Tuple[bool, Union[str, dict, bytes], dict, dict]:
        """
        Handle Redfish response with caching and retry logic.

        Args:
            dut: DUT instance.
            response: HTTP response object.
            uri: Redfish URI.
            method: HTTP method.
            attempt: Current attempt number.
            max_retries: Maximum retry attempts.
            current_delay: Current retry delay.
            retryable_status_codes: Set of status codes that trigger retries.
            get_raw_content: Whether to return raw binary content.

        Returns:
            Tuple of (success, response, metadata, headers).
        """
        # Log response status
        await dut._log_runtime(
            "DEBUG",
            f"Response for {method} {uri}: HTTP {response.status} (attempt {attempt + 1}/{max_retries + 1})",
        )

        if response.status < 400:
            # Success - parse response
            if get_raw_content:
                # For binary data, return raw bytes
                content = await response.read()
                await dut._log_runtime(
                    "DEBUG",
                    f"Successfully downloaded {len(content)} bytes for {method} {uri}",
                )
                # Don't cache binary responses
                return True, content, {}, {}
            else:
                # For JSON/text data, parse as usual
                content = await response.text()
                try:
                    result = json.loads(content)
                    await dut._log_runtime(
                        "DEBUG",
                        f"Successfully parsed JSON response for {method} {uri} ({len(content)} chars)",
                    )
                except json.JSONDecodeError:
                    result = content
                    await dut._log_runtime(
                        "DEBUG",
                        f"Response is not JSON for {method} {uri} ({len(content)} chars)",
                    )

                # Cache successful GET responses
                if method.upper() == "GET":
                    dut._cache_response(uri, result)
                    await dut._log_runtime("DEBUG", f"Cached response for {uri}")

                return True, result, {}, {}
        elif response.status in retryable_status_codes:
            # Server error - retry if we have attempts left
            response_text = await response.text()
            await dut._log_runtime(
                "WARNING",
                f"Server error HTTP {response.status} for {method} {uri}: {response_text[:200]}...",
            )

            if attempt < max_retries:
                await dut._log_runtime(
                    "INFO",
                    f"Retrying due to server error HTTP {response.status} (attempt {attempt + 1}/{max_retries})",
                )
                await asyncio.sleep(current_delay)
                return (
                    False,
                    "retry",
                    {
                        "http_status": response.status,
                        "error_message": response_text,
                        "uri": uri,
                        "method": method,
                    },
                    {
                        "attempt": attempt + 1,
                        "max_retries": max_retries,
                        "current_delay": current_delay,
                    },
                )  # Signal to retry with detailed error info
            else:
                await dut._log_runtime(
                    "ERROR",
                    f"Max retries exceeded for server error HTTP {response.status} on {method} {uri}",
                )
                return (
                    False,
                    f"HTTP {response.status}: {response_text}",
                    {
                        "http_status": response.status,
                        "error_message": response_text,
                        "uri": uri,
                        "method": method,
                        "max_retries_exceeded": True,
                    },
                    {"attempt": attempt + 1, "max_retries": max_retries},
                )
        else:
            # Client error (4xx) - don't retry
            response_text = await response.text()
            await dut._log_runtime(
                "ERROR",
                f"Client error HTTP {response.status} for {method} {uri}: {response_text[:200]}...",
            )
            return (
                False,
                f"HTTP {response.status}: {response_text}",
                {
                    "http_status": response.status,
                    "error_message": response_text,
                    "uri": uri,
                    "method": method,
                    "client_error": True,
                },
                {},
            )

    async def create_redfish_sessions(self) -> None:
        """
        Create Redfish sessions for all DUTs.
        """
        for dut_id, dut in self.duts.items():
            if dut.connection_state.redfish_connected:
                await dut.create_redfish_session()

    async def close_redfish_sessions(self) -> None:
        """
        Close Redfish sessions for all DUTs.
        """
        for dut_id, dut in self.duts.items():
            await dut.close_redfish_session()

    async def reset_redfish_caches(self) -> None:
        """
        Reset Redfish caches for all DUTs.
        """
        for dut_id, dut in self.duts.items():
            dut.reset_redfish_cache()

    async def execute_ipmi_command(
        self, dut_id: str, command: str, timeout: int = 180
    ) -> Tuple[int, str, str]:
        """
        Execute IPMI command on a DUT with retry logic

        Args:
            dut_id: DUT identifier
            command: IPMI command to execute
            timeout: Command timeout in seconds

        Returns:
            Tuple of (exit_code, stdout, stderr)

        Notes:
            - Automatically removes 'ipmitool' prefix if present
            - If command fails, retries with -v flag to collect verbose debug data
            - Handles sanitization of output when writing to file
            - Provides comprehensive error logging
        """
        dut = self.get_dut(dut_id)

        # Ensure IPMI connection is established
        success, message = await self._ensure_connection(
            dut_id, "ipmi", "test_ipmi_connection"
        )
        if not success:
            return -1, "", message

        try:
            # Remove 'ipmitool' prefix if present since we handle that
            original_command = command
            if command.strip().startswith("ipmitool"):
                command = command.strip()[len("ipmitool") :].strip()
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Warning IPMI.1: Removed redundant 'ipmitool' prefix from command: {original_command}",
                )

            # Run the original command
            exit_code, stdout, stderr = await self._run_single_ipmi_command(
                dut, command, timeout
            )

            # If command succeeded, return the result
            if exit_code == 0:
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"IPMI command ran successfully: {command}",
                )
                return exit_code, stdout, stderr

            # If command failed and doesn't already have -v flag, try verbose version
            if exit_code != 0 and "-v" not in command:
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Warning IPMI.4: Command failed with code {exit_code}, retrying with -v flag",
                )

                # Run verbose command
                verbose_command = f"{command} -v"
                verbose_exit_code, verbose_stdout, verbose_stderr = (
                    await self._run_single_ipmi_command(dut, verbose_command, timeout)
                )

                # If verbose succeeded where original failed, return verbose result
                if verbose_exit_code == 0:
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"Warning IPMI.7: Verbose command succeeded where original failed",
                    )
                    return verbose_exit_code, verbose_stdout, verbose_stderr

                # If verbose also failed, log the verbose errors
                if verbose_exit_code != 0:
                    await self.logger.log_runtime(
                        "ERROR",
                        "DUTManager",
                        f"Error IPMI.8: Verbose command also failed (code: {verbose_exit_code})",
                    )

                    # Log verbose error details
                    verbose_error_msg = self._format_ipmi_command_error(
                        verbose_command,
                        verbose_exit_code,
                        verbose_stdout,
                        verbose_stderr,
                        "IPMI (verbose)",
                    )
                    await self.logger.log_runtime(
                        "ERROR",
                        "DUTManager",
                        f"Verbose Error Output (-v):\n{verbose_error_msg}",
                    )

            # Log result of original command
            if exit_code != 0:
                error_msg = self._format_ipmi_command_error(
                    command, exit_code, stdout, stderr, "IPMI"
                )
                await self.logger.log_runtime(
                    "ERROR", "DUTManager", f"IPMI command failed:\n{error_msg}"
                )

            return exit_code, stdout, stderr

        except Exception as e:
            await self.logger.log_runtime(
                "ERROR",
                "DUTManager",
                f"Error IPMI.9: Unexpected error in execute_ipmi_command: {e}",
            )
            return -1, "", f"IPMI command error: {str(e)}"

    async def _run_single_ipmi_command(
        self, dut, command: str, timeout: int
    ) -> Tuple[int, str, str]:
        """
        Execute a single IPMI command without retry logic

        Args:
            dut: DUT object
            command: IPMI command to execute
            timeout: Command timeout in seconds

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            # Check if we're in local mode without BMC IP - if so, run locally via sudo
            if dut.config and dut.config.get("local", False):
                has_bmc_ip = dut.credentials and dut.credentials.bmc_ip
                if not has_bmc_ip:
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running IPMI command locally via sudo (local mode without BMC IP): {command}",
                    )
                    # Run IPMI command locally via sudo without BMC connection parameters
                    cmd = ["sudo", "ipmitool"] + command.split()
                else:
                    # Local mode but with BMC IP - use BMC connection
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running IPMI command via BMC connection (local mode with BMC IP): {command}",
                    )
                    cmd = [
                        "ipmitool",
                        "-I",
                        "lanplus",
                        "-H",
                        dut.credentials.bmc_ip,
                        "-U",
                        dut.credentials.bmc_username,
                        "-P",
                        dut.credentials.bmc_password,
                        dut.credentials.ipmi_cipher,
                    ] + command.split()
            else:
                # Normal mode - use BMC connection (direct or via SSH proxy)
                if dut.credentials.ssh_proxy_host:
                    # Use SSH proxy - run ipmitool on the proxy machine
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running IPMI command via SSH proxy: {dut.credentials.ssh_proxy_host} -> {dut.credentials.bmc_ip}:623",
                    )

                    # Build the ipmitool command to run on the proxy
                    ipmitool_cmd = [
                        "ipmitool",
                        "-I",
                        "lanplus",
                        "-H",
                        dut.credentials.bmc_ip,
                        "-U",
                        dut.credentials.bmc_username,
                        "-P",
                        dut.credentials.bmc_password,
                        dut.credentials.ipmi_cipher,
                    ] + command.split()

                    # Execute the command over SSH on the proxy
                    exit_code, stdout, stderr = await self.execute_ssh_command(
                        host=dut.credentials.ssh_proxy_host,
                        port=dut.credentials.ssh_proxy_port,
                        username=dut.credentials.ssh_proxy_username,
                        password=dut.credentials.ssh_proxy_password,
                        command=" ".join(ipmitool_cmd),
                        timeout=timeout,
                        ssh_key_path=dut.credentials.ssh_proxy_key_path,
                        passwordless=dut.credentials.ssh_proxy_passwordless,
                        max_retries=dut.credentials.ssh_proxy_max_retries,
                    )

                    # Return the result directly since we already executed the command
                    return exit_code, stdout, stderr
                else:
                    # Use direct BMC connection
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running IPMI command via direct BMC connection: {dut.credentials.bmc_ip}",
                    )
                    cmd = [
                        "ipmitool",
                        "-I",
                        "lanplus",
                        "-H",
                        dut.credentials.bmc_ip,
                        "-U",
                        dut.credentials.bmc_username,
                        "-P",
                        dut.credentials.bmc_password,
                        dut.credentials.ipmi_cipher,
                    ] + command.split()

            # Use asyncio.create_subprocess_exec for async execution
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                # Kill the process if it times out
                process.kill()
                await process.wait()  # Wait for the process to be cleaned up
                await self.logger.log_runtime(
                    "ERROR",
                    "DUTManager",
                    f"Error IPMI.2: Command timed out after {timeout} seconds",
                )
                return (
                    -1,
                    "",
                    f"IPMI command timed out after {timeout} seconds",
                )

            # Decode the output using robust method
            stdout_text = self._process_command_output(stdout)
            stderr_text = self._process_command_output(stderr)

            # Always capture both stdout and stderr
            return process.returncode, stdout_text, stderr_text

        except Exception as e:
            await self.logger.log_runtime(
                "ERROR", "DUTManager", f"Error IPMI.3: Command failed: {e}"
            )
            return -1, "", f"IPMI command error: {str(e)}"

    def _process_command_output(
        self, output: Union[str, bytes, None], encoding: str = "utf-8"
    ) -> str:
        """
        Process command output to ensure it's in string format.
        Handles binary data gracefully with fallback strategies.

        Args:
            output: The command output to process (can be str, bytes, or None)
            encoding: The encoding to use for bytes decoding (default: utf-8)

        Returns:
            str: The processed output as a string
        """
        if output is None:
            return ""

        if isinstance(output, bytes):
            try:
                # First try UTF-8 with replace
                return output.decode(encoding, errors="replace")
            except Exception:
                try:
                    # Try latin1 as fallback - it can handle all byte values
                    return output.decode("latin1", errors="replace")
                except Exception as e:
                    # Last resort - hex representation
                    return f"hex:{output.hex()}"

        # Handle case where output is already a string
        if isinstance(output, str):
            return output

        # For any other type, try string conversion with error handling
        try:
            return str(output)
        except Exception:
            return f"<unconvertible output of type {type(output).__name__}>"

    def _format_ipmi_command_error(
        self,
        command: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        command_type: str = "",
    ) -> str:
        """
        Format error messages for IPMI command execution failures consistently.
        Standard implementation.

        Args:
            command: The command that was executed
            exit_code: The exit/return code from the command
            stdout: The stdout from the command
            stderr: The stderr from the command
            command_type: Optional type of command (IPMI, IPMI (verbose), etc.)

        Returns:
            str: Formatted error message
        """
        try:
            # Process stdout and stderr
            stdout_msg = stdout if stdout else "<empty>"
            stderr_msg = stderr if stderr else "<empty>"
            cmd_type = f"{command_type}" if command_type else ""

            # Format the error message
            error_msg = f"Command failed: {command}\n"
            error_msg += f"Exit code: {exit_code}\n"
            if cmd_type:
                error_msg += f"Command type: {cmd_type}\n"

            if stdout_msg:
                error_msg += f"STDOUT:\n{stdout_msg}\n"

            if stderr_msg:
                error_msg += f"STDERR:\n{stderr_msg}\n"

            return error_msg

        except Exception as e:
            return f"Error formatting command error: {str(e)}"

    async def _execute_ssh_command_paramiko(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str] = None,
        command: str = "",
        timeout: int = 180,
        ssh_key_path: Optional[str] = None,
        passwordless: bool = False,
        max_retries: int = 3,
        proxy_client: Optional[paramiko.SSHClient] = None,
        use_sudo: bool = False,
        use_shell: bool = True,
    ) -> Tuple[int, str, str]:
        """
        Execute SSH command with advanced authentication support

        Args:
            host: Target host IP/hostname
            port: SSH port
            username: SSH username
            password: SSH password (optional if using key auth)
            command: Command to execute (empty for connection test)
            timeout: Connection/command timeout
            ssh_key_path: Path to SSH private key file
            passwordless: Enable passwordless SSH
            max_retries: Maximum retry attempts
            proxy_client: SSH proxy client for jumpbox connections
            use_sudo: Enable automatic sudo password injection
            use_shell: Use shell when running commands

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        last_error = ""

        for attempt in range(max_retries):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # Prepare connection parameters
                connect_kwargs = {
                    "hostname": host,
                    "port": port,
                    "username": username,
                    "timeout": timeout,
                }

                # Add proxy if provided (for SSH jumpbox)
                if proxy_client:
                    connect_kwargs["sock"] = proxy_client.get_transport().open_channel(
                        "direct-tcpip", (host, port), ("", 0)
                    )

                # Handle different authentication methods
                if ssh_key_path:
                    # SSH key authentication (with optional password for encrypted keys)
                    try:
                        key = paramiko.RSAKey.from_private_key_file(
                            ssh_key_path, password=password
                        )
                        connect_kwargs["pkey"] = key
                    except paramiko.PasswordRequiredException:
                        if password:
                            key = paramiko.RSAKey.from_private_key_file(
                                ssh_key_path, password=password
                            )
                            connect_kwargs["pkey"] = key
                        else:
                            return (
                                -1,
                                "",
                                f"SSH key {ssh_key_path} requires password but none provided",
                            )
                    except Exception as e:
                        # Try other key types
                        try:
                            key = paramiko.Ed25519Key.from_private_key_file(
                                ssh_key_path, password=password
                            )
                            connect_kwargs["pkey"] = key
                        except:
                            try:
                                key = paramiko.ECDSAKey.from_private_key_file(
                                    ssh_key_path, password=password
                                )
                                connect_kwargs["pkey"] = key
                            except:
                                return (
                                    -1,
                                    "",
                                    f"Failed to load SSH key {ssh_key_path}: {str(e)}",
                                )

                elif passwordless:
                    # Passwordless SSH (no password, no key - relies on SSH agent or host-based auth)
                    connect_kwargs["password"] = None
                    connect_kwargs["allow_agent"] = True
                    connect_kwargs["look_for_keys"] = True
                else:
                    # Password authentication
                    if not password:
                        return (
                            -1,
                            "",
                            "Password required for SSH authentication",
                        )
                    connect_kwargs["password"] = password

                # Attempt connection
                client.connect(**connect_kwargs)

                # If no command specified, this is just a connection test
                if not command:
                    client.close()
                    return 0, "SSH connection successful", ""

                # Execute command
                stdin, stdout, stderr = client.exec_command(command, timeout=timeout)

                # Handle sudo commands if requested
                if use_sudo and "sudo" in command and not passwordless and password:
                    # Provide the sudo password
                    stdin.write(password + "\n")
                    stdin.flush()

                exit_code = stdout.channel.recv_exit_status()

                output = self._process_command_output(stdout.read())
                error = self._process_command_output(stderr.read())

                client.close()

                # Always capture both stdout and stderr
                return exit_code, output, error

            except Exception as e:
                last_error = f"SSH attempt {attempt + 1}/{max_retries} failed: {str(e)}"
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Paramiko connection attempt {attempt + 1}/{max_retries} to {host}:{port} failed: {str(e)}",
                )
                if attempt < max_retries - 1:
                    # Wait before retry (exponential backoff)
                    wait_time = 2**attempt
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Waiting {wait_time}s before retry {attempt + 2}/{max_retries}",
                    )
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    return -1, "", last_error

        return -1, "", f"SSH failed after {max_retries} attempts: {last_error}"

    async def _execute_ssh_command_async(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str] = None,
        command: str = "",
        timeout: int = 180,
        ssh_key_path: Optional[str] = None,
        passwordless: bool = False,
        max_retries: int = 3,
        proxy_client: Optional[asyncssh.SSHClientConnection] = None,
        use_sudo: bool = False,
        use_shell: bool = True,
    ) -> Tuple[int, str, str]:
        """
        Execute SSH command using asyncssh (async version)

        Args:
            host: Target host IP/hostname
            port: SSH port
            username: SSH username
            password: SSH password (optional if using key auth)
            command: Command to execute (empty for connection test)
            timeout: Connection/command timeout
            ssh_key_path: Path to SSH private key file
            passwordless: Enable passwordless SSH
            max_retries: Maximum retry attempts
            proxy_client: SSH proxy client for jumpbox connections
            use_sudo: Enable automatic sudo password injection
            use_shell: Use shell when running commands

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        last_error = ""

        for attempt in range(max_retries):
            try:
                # Prepare connection parameters
                connect_kwargs = {
                    "host": host,
                    "port": port,
                    "username": username,
                    "connect_timeout": timeout,
                    "keepalive_interval": None,  # Disable keepalive for faster connections
                }

                # Add proxy if provided (for SSH jumpbox)
                if proxy_client:
                    connect_kwargs["sock"] = proxy_client.get_extra_info("socket")

                # Handle different authentication methods
                if ssh_key_path:
                    # SSH key authentication
                    try:
                        # asyncssh supports multiple key types automatically
                        connect_kwargs["client_keys"] = [ssh_key_path]
                        if password:
                            connect_kwargs["passphrase"] = password
                    except Exception as e:
                        return (
                            -1,
                            "",
                            f"Failed to load SSH key {ssh_key_path}: {str(e)}",
                        )

                elif passwordless:
                    # Passwordless SSH (relies on SSH agent or host-based auth)
                    connect_kwargs["known_hosts"] = None  # Accept any host key
                else:
                    # Password authentication
                    if not password:
                        return (
                            False,
                            "Password required for SSH authentication",
                        )
                    connect_kwargs["password"] = password

                # Always accept unknown host keys (similar to paramiko.AutoAddPolicy())
                connect_kwargs["known_hosts"] = None

                # Attempt connection with explicit cleanup
                conn = None
                try:
                    conn = await asyncssh.connect(**connect_kwargs)

                    # If no command specified, this is just a connection test
                    if not command:
                        return 0, "SSH connection successful", ""

                    # Execute command with timeout
                    try:
                        # Handle sudo commands if requested
                        if (
                            use_sudo
                            and "sudo" in command
                            and not passwordless
                            and password
                        ):
                            # For sudo commands, we need to provide the password
                            # asyncssh doesn't have direct stdin support like paramiko
                            # So we'll use a different approach - modify the command to use sudo -S
                            if "sudo -S" not in command:
                                command = command.replace("sudo ", "sudo -S ")

                            # Create a process that can handle stdin
                            result = await asyncio.wait_for(
                                conn.run(command, input=password + "\n"),
                                timeout=timeout,
                            )
                        else:
                            result = await asyncio.wait_for(
                                conn.run(command), timeout=timeout
                            )

                        # Always capture both stdout and stderr
                        stdout = result.stdout or ""
                        stderr = result.stderr or ""

                        return result.exit_status, stdout, stderr

                    except asyncio.TimeoutError:
                        return (
                            -1,
                            "",
                            f"SSH command timed out after {timeout} seconds",
                        )

                finally:
                    # Ensure connection is properly closed
                    if conn:
                        conn.close()
                        await conn.wait_closed()

            except Exception as e:
                last_error = f"SSH attempt {attempt + 1}/{max_retries} failed: {str(e)}"
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"AsyncSSH connection attempt {attempt + 1}/{max_retries} to {host}:{port} failed: {str(e)}",
                )
                if attempt < max_retries - 1:
                    # Wait before retry (exponential backoff)
                    wait_time = 2**attempt
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Waiting {wait_time}s before retry {attempt + 2}/{max_retries}",
                    )
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    return -1, "", last_error

        return -1, "", f"SSH failed after {max_retries} attempts: {last_error}"

    async def execute_ssh_command(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str] = None,
        command: str = "",
        timeout: int = 180,
        ssh_key_path: Optional[str] = None,
        passwordless: bool = False,
        max_retries: int = 3,
        proxy_client=None,
        use_sudo: bool = False,
        use_shell: bool = True,
    ) -> Tuple[int, str, str]:
        """
        Execute SSH command using the configured backend (asyncssh or paramiko)

        Args:
            host: Target host IP/hostname
            port: SSH port
            username: SSH username
            password: SSH password (optional if using key auth)
            command: Command to execute (empty for connection test)
            timeout: Connection/command timeout
            ssh_key_path: Path to SSH private key file
            passwordless: Enable passwordless SSH
            max_retries: Maximum retry attempts
            proxy_client: SSH proxy client for jumpbox connections
            use_sudo: Enable automatic sudo password injection
            use_shell: Use shell when running commands

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        # Use asyncssh by default, fallback to paramiko if configured
        if self.ssh_backend == "asyncssh":
            try:
                return await self._execute_ssh_command_async(
                    host,
                    port,
                    username,
                    password,
                    command,
                    timeout,
                    ssh_key_path,
                    passwordless,
                    max_retries,
                    proxy_client,
                    use_sudo,
                    use_shell,
                )
            except Exception as e:
                # If fallback is enabled and this is a connection error, try paramiko
                if self.ssh_fallback_enabled:
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"AsyncSSH failed: {e}, falling back to paramiko",
                    )
                    return await self._execute_ssh_command_paramiko(
                        host,
                        port,
                        username,
                        password,
                        command,
                        timeout,
                        ssh_key_path,
                        passwordless,
                        max_retries,
                        proxy_client,
                        use_sudo,
                        use_shell,
                    )
                else:
                    raise
        else:
            # Use paramiko directly
            return await self._execute_ssh_command_paramiko(
                host,
                port,
                username,
                password,
                command,
                timeout,
                ssh_key_path,
                passwordless,
                max_retries,
                proxy_client,
                use_sudo,
                use_shell,
            )

    async def create_proxy_connection(self, dut_id: str):
        """
        Create SSH proxy connection using the configured backend

        Args:
            dut_id: DUT identifier

        Returns:
            SSH proxy connection object (type depends on backend)
        """
        if self.ssh_backend == "asyncssh":
            try:
                return await self._create_proxy_connection_async(dut_id)
            except Exception as e:
                # If fallback is enabled, try paramiko
                if self.ssh_fallback_enabled:
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"AsyncSSH proxy failed: {e}, falling back to paramiko",
                    )
                    return await self._create_proxy_connection(dut_id)
                else:
                    raise
        else:
            # Use paramiko directly
            return await self._create_proxy_connection(dut_id)

    async def _create_proxy_connection_async(
        self, dut_id: str
    ) -> Optional[asyncssh.SSHClientConnection]:
        """
        Create async SSH connection to proxy for multi-hop access

        Args:
            dut_id: DUT identifier

        Returns:
            SSH client connection to proxy, or None if no proxy configured
        """
        dut = self.get_dut(dut_id)

        # Check if proxy is configured
        if not dut.credentials.ssh_proxy_host:
            return None

        try:
            # Prepare connection parameters
            connect_kwargs = {
                "host": dut.credentials.ssh_proxy_host,
                "port": dut.credentials.ssh_proxy_port,
                "username": dut.credentials.ssh_proxy_username,
                "connect_timeout": 30,
                "keepalive_interval": None,  # Disable keepalive for faster connections
            }

            # Handle authentication
            if dut.credentials.ssh_proxy_key_path:
                try:
                    connect_kwargs["client_keys"] = [dut.credentials.ssh_proxy_key_path]
                    if dut.credentials.ssh_proxy_password:
                        connect_kwargs["passphrase"] = (
                            dut.credentials.ssh_proxy_password
                        )
                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DUTManager",
                        f"Failed to load proxy SSH key: {e}",
                    )
                    return None
            elif dut.credentials.ssh_proxy_passwordless:
                connect_kwargs["known_hosts"] = None  # Accept any host key
            else:
                connect_kwargs["password"] = dut.credentials.ssh_proxy_password

            # Always accept unknown host keys (similar to paramiko.AutoAddPolicy())
            connect_kwargs["known_hosts"] = None

            # Connect to proxy
            conn = await asyncssh.connect(**connect_kwargs)
            return conn

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                f"Failed to create async proxy connection: {e}",
            )
            return None

    async def _create_proxy_connection(
        self, dut_id: str
    ) -> Optional[paramiko.SSHClient]:
        """
        Create SSH connection to proxy for multi-hop access

        Args:
            dut_id: DUT identifier

        Returns:
            SSH client connected to proxy, or None if no proxy configured
        """
        dut = self.get_dut(dut_id)

        # Check if proxy is configured
        if not dut.credentials.ssh_proxy_host:
            return None

        try:
            # Create proxy connection using the enhanced SSH method
            success, _ = await self._execute_ssh_command(
                host=dut.credentials.ssh_proxy_host,
                port=dut.credentials.ssh_proxy_port,
                username=dut.credentials.ssh_proxy_username,
                password=dut.credentials.ssh_proxy_password,
                command="",  # Just test connection
                timeout=30,
                ssh_key_path=dut.credentials.ssh_proxy_key_path,
                passwordless=dut.credentials.ssh_proxy_passwordless,
                max_retries=dut.credentials.ssh_proxy_max_retries,
            )

            if success:
                # Create actual SSH client for jumpbox
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # Prepare connection parameters
                connect_kwargs = {
                    "hostname": dut.credentials.ssh_proxy_host,
                    "port": dut.credentials.ssh_proxy_port,
                    "username": dut.credentials.ssh_proxy_username,
                    "timeout": 30,
                }

                # Handle authentication
                if dut.credentials.ssh_proxy_key_path:
                    try:
                        key = paramiko.RSAKey.from_private_key_file(
                            dut.credentials.ssh_proxy_key_path,
                            password=dut.credentials.ssh_proxy_password,
                        )
                        connect_kwargs["pkey"] = key
                    except Exception as e:
                        # Try other key types
                        try:
                            key = paramiko.Ed25519Key.from_private_key_file(
                                dut.credentials.ssh_proxy_key_path,
                                password=dut.credentials.ssh_proxy_password,
                            )
                            connect_kwargs["pkey"] = key
                        except:
                            try:
                                key = paramiko.ECDSAKey.from_private_key_file(
                                    dut.credentials.ssh_proxy_key_path,
                                    password=dut.credentials.ssh_proxy_password,
                                )
                                connect_kwargs["pkey"] = key
                            except:
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "ERROR",
                                    "DUTManager",
                                    f"Failed to load proxy SSH key: {e}",
                                )
                                return None
                elif dut.credentials.ssh_proxy_passwordless:
                    connect_kwargs["password"] = None
                    connect_kwargs["allow_agent"] = True
                    connect_kwargs["look_for_keys"] = True
                else:
                    connect_kwargs["password"] = dut.credentials.ssh_proxy_password

                # Connect to proxy
                client.connect(**connect_kwargs)
                return client

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                f"Failed to create proxy connection: {e}",
            )
            return None

        return None

    async def execute_bmc_command(
        self, dut_id: str, command: str, timeout: int = 180, hmc: bool = False
    ) -> Tuple[int, str, str]:
        """
        Execute BMC SSH command on a DUT.

        Args:
            dut_id: DUT ID.
            command: Command to execute.
            timeout: Command timeout in seconds.
            hmc: Whether this is an HMC connection.

        Returns:
            Tuple of (return_code, stdout, stderr).
        """
        dut = self.get_dut(dut_id)

        # Ensure BMC SSH connection is established
        success, message = await self._ensure_connection(
            dut_id, "ssh", "test_ssh_connection"
        )
        if not success:
            return -1, "", message

        if hmc:
            # HMC execution
            if not dut.credentials.hmc_ip:
                return -1, "", "HMC IP not configured"

            username = dut.credentials.hmc_ssh_username or dut.credentials.hmc_username
            password = dut.credentials.hmc_ssh_password or dut.credentials.hmc_password

            return await self.execute_ssh_command(
                host=dut.credentials.hmc_ip,
                port=dut.credentials.hmc_ssh_port,
                username=username,
                password=password,
                command=command,
                timeout=timeout,
                ssh_key_path=dut.credentials.hmc_ssh_key_path,
                passwordless=dut.credentials.hmc_ssh_passwordless,
                max_retries=dut.credentials.hmc_ssh_max_retries,
                proxy_client=None,  # HMC doesn't use proxy
            )
        else:
            # BMC execution
            username = dut.credentials.bmc_ssh_username or dut.credentials.bmc_username
            password = dut.credentials.bmc_ssh_password or dut.credentials.bmc_password

            # Check if SSH proxy tunneling is active
            if hasattr(dut, "ssh_proxy_tunnel_ports") and dut.ssh_proxy_tunnel_ports:
                # Use SSH proxy tunnel
                tunnel_port = dut.ssh_proxy_tunnel_ports["bmc_ssh_port"]
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Running BMC SSH command via SSH proxy tunnel: localhost:{tunnel_port} -> {dut.credentials.bmc_ip}:{dut.credentials.bmc_ssh_port}",
                )
                return await self.execute_ssh_command(
                    host="localhost",  # Use localhost for tunnel
                    port=tunnel_port,  # Use BMC SSH tunnel port
                    username=username,
                    password=password,
                    command=command,
                    timeout=timeout,
                    ssh_key_path=dut.credentials.bmc_ssh_key_path,
                    passwordless=dut.credentials.bmc_ssh_passwordless,
                    max_retries=dut.credentials.bmc_ssh_max_retries,
                )
            else:
                # Use direct BMC connection
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Running BMC SSH command via direct BMC connection: {dut.credentials.bmc_ip}",
                )
                return await self.execute_ssh_command(
                    host=dut.credentials.bmc_ip,
                    port=dut.credentials.bmc_ssh_port,
                    username=username,
                    password=password,
                    command=command,
                    timeout=timeout,
                    ssh_key_path=dut.credentials.bmc_ssh_key_path,
                    passwordless=dut.credentials.bmc_ssh_passwordless,
                    max_retries=dut.credentials.bmc_ssh_max_retries,
                )

    async def execute_host_command(
        self,
        dut_id: str,
        command: str,
        timeout: int = 180,
        max_retries: int = 3,
        override_shell: Optional[bool] = None,
        input_val: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        use_sudo: bool = False,
        use_shell: bool = True,
    ) -> Tuple[int, str, str]:
        """
        Execute host command on a DUT.

        Args:
            dut_id: DUT ID.
            command: Command to execute.
            timeout: Command timeout in seconds.
            max_retries: Maximum retry attempts.
            override_shell: Override shell execution setting.
            input_val: Input value for command.
            environment: Environment variables.
            use_sudo: Whether to use sudo.
            use_shell: Whether to use shell execution.

        Returns:
            Tuple of (return_code, stdout, stderr).
        """
        dut = self.get_dut(dut_id)

        # Debug logging
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"execute_host_command called with use_sudo={use_sudo}, use_shell={use_shell}",
        )
        await self.logger.log_runtime(
            "DEBUG", "DUTManager", f"Original command: {command}"
        )
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"Host connected: {dut.connection_state.host_connected}",
        )
        await self.logger.log_runtime(
            "DEBUG", "DUTManager", f"Host IP: {dut.credentials.host_ip}"
        )

        # Ensure host connection is established
        success, message = await self._ensure_connection(
            dut_id, "host", "test_host_connection"
        )
        if not success:
            return -1, "", message

        # Follow legacy pattern: prepend sudo -S if use_sudo is True
        command_to_run = command
        if use_sudo and not command.strip().startswith("sudo"):
            command_to_run = f"sudo -S {command}"
            await self.logger.log_runtime(
                "DEBUG",
                "DUTManager",
                f"Command after sudo prepend: {command_to_run}",
            )

        try:
            if not dut.credentials.host_ip:
                # Local execution - use unified execute_bash_command
                await self.logger.log_runtime(
                    "DEBUG", "DUTManager", "Using local execution path"
                )

                # Determine shell usage
                use_shell = True if override_shell is None else override_shell

                # For local execution, we can use the same password as SSH if available
                # or a local sudo password if configured
                sudo_password = None
                if use_sudo:
                    # In local mode, assume passwordless sudo access
                    if dut.config and dut.config.get("local", False):
                        await self.logger.log_runtime(
                            "DEBUG",
                            "DUTManager",
                            "Local mode detected - assuming passwordless sudo access",
                        )
                        # Don't require sudo password in local mode
                        sudo_password = None
                    else:
                        # Try to get sudo password from credentials
                        sudo_password = getattr(
                            dut.credentials, "host_sudo_password", None
                        )
                        if not sudo_password:
                            # Fallback to SSH password if available
                            sudo_password = dut.credentials.host_password

                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        f"Sudo password available: {sudo_password is not None}",
                    )

                result = await self.execute_bash_command(
                    command=command_to_run,
                    timeout=timeout,
                    use_shell=use_shell,
                    input_val=input_val,
                    environment=environment,
                    use_sudo=use_sudo,
                    sudo_password=sudo_password,
                )

                await self.logger.log_runtime(
                    "DEBUG", "DUTManager", f"Local execution result: {result}"
                )
                return result
            else:
                # Remote execution via SSH
                if (
                    not dut.credentials.host_username
                    or not dut.credentials.host_password
                ):
                    return -1, "", "Host SSH credentials not configured"

                # Check if SSH proxy tunneling is active
                if (
                    hasattr(dut, "ssh_proxy_tunnel_ports")
                    and dut.ssh_proxy_tunnel_ports
                ):
                    # Use SSH proxy tunnel
                    tunnel_port = dut.ssh_proxy_tunnel_ports["host_ssh_port"]
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running Host SSH command via SSH proxy tunnel: localhost:{tunnel_port} -> {dut.credentials.host_ip}:{dut.credentials.host_ssh_port}",
                    )
                    return await self.execute_ssh_command(
                        host="localhost",  # Use localhost for tunnel
                        port=tunnel_port,  # Use Host SSH tunnel port
                        username=dut.credentials.host_username,
                        password=dut.credentials.host_password,
                        command=command_to_run,
                        timeout=timeout,
                        ssh_key_path=dut.credentials.host_ssh_key_path,
                        passwordless=dut.credentials.host_ssh_passwordless,
                        max_retries=dut.credentials.host_ssh_max_retries,
                        use_sudo=use_sudo,
                        use_shell=use_shell,
                    )
                else:
                    # Use direct host connection
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running Host SSH command via direct host connection: {dut.credentials.host_ip}",
                    )
                    return await self.execute_ssh_command(
                        host=dut.credentials.host_ip,
                        port=dut.credentials.host_ssh_port,
                        username=dut.credentials.host_username,
                        password=dut.credentials.host_password,
                        command=command_to_run,
                        timeout=timeout,
                        ssh_key_path=dut.credentials.host_ssh_key_path,
                        passwordless=dut.credentials.host_ssh_passwordless,
                        max_retries=dut.credentials.host_ssh_max_retries,
                        use_sudo=use_sudo,
                        use_shell=use_shell,
                    )
        except Exception as e:
            return -1, "", f"Host command error: {str(e)}"

    async def execute_nvos_command(
        self,
        dut_id: str,
        command: str,
        timeout: int = 180,
        use_sudo: bool = False,
    ) -> Tuple[bool, Any]:
        """
        Execute NVOS command and return JSON output.

        Args:
            dut_id: DUT identifier
            command: NVOS command to execute (e.g., 'nv show platform inventory')
            timeout: Command timeout in seconds
            use_sudo: Whether to use sudo for the command

        Returns:
            Tuple of (success, output) where output is parsed JSON or None on failure
        """
        # Add --output json to ensure JSON output (like the original run_nvos_command)
        nv_command = f"{command} --output json"

        await self.logger.log_runtime(
            "DEBUG", "DUTManager", f"Executing NVOS command: {nv_command}"
        )

        exit_code, stdout, stderr = await self.execute_host_command(
            dut_id, nv_command, timeout=timeout, use_sudo=use_sudo
        )

        if exit_code == 0:
            try:
                output = json.loads(stdout)
                await self.logger.log_runtime(
                    "DEBUG",
                    "DUTManager",
                    f"NVOS command successful: {command}",
                )
                return True, output
            except (json.JSONDecodeError, TypeError):
                # If not JSON, return raw output (matching original run_nvos_command behavior)
                await self.logger.log_runtime(
                    "WARN",
                    "DUTManager",
                    f"NVOS command output not JSON: {command}",
                )
                return True, stdout
        else:
            await self.logger.log_runtime(
                "ERROR",
                "DUTManager",
                f"NVOS command failed: {command}, exit_code: {exit_code}, stderr: {stderr}",
            )
            return False, None

    def is_hmc_present(self, dut_id: str) -> bool:
        """
        Check if HMC is present for a DUT.

        Args:
            dut_id: DUT ID.

        Returns:
            True if HMC is configured for the DUT.
        """
        dut = self.get_dut(dut_id)
        return dut.credentials.hmc_ip is not None

    async def execute_bmc_command_with_hmc_detection(
        self,
        dut_id: str,
        command: str,
        timeout: int = 180,
        max_retries: int = 3,
    ) -> Tuple[int, str, str]:
        """
        Execute BMC command with automatic HMC detection.
        Wrapper around execute_bmc_command to let DUT decide if the command should be run on BMC or HMC.
        """
        return await self.execute_bmc_command(
            dut_id, command, timeout, hmc=self.is_hmc_present(dut_id)
        )

    async def transfer_files(
        self,
        dut_id: str,
        sources: Union[str, List[str]],
        destination_directory: str,
        copy_to_destination: bool = True,
        max_retries: int = 3,
    ) -> Tuple[bool, str]:
        """
        Copy files from/to BMC via SSH (legacy method for BMC transfers)

        Args:
            dut_id: DUT identifier
            sources: Single source path or list of paths
            destination_directory: Target path
            copy_to_destination: Flag to set if copying files to/from destination.
                               True = copy to destination, False = copy from destination
            max_retries: Maximum number of retries. 3 by default

        Returns:
            Tuple of (success, error_message)
        """
        dut = self.get_dut(dut_id)

        # Ensure BMC SSH connection is established
        success, message = await self._ensure_connection(
            dut_id, "ssh", "test_ssh_connection"
        )
        if not success:
            return False, message

        # Validate inputs
        if not isinstance(sources, (list, tuple, str)) or not isinstance(
            destination_directory, str
        ):
            return (
                False,
                "Invalid argument combination. Please provide either a single source or list of sources, and a single destination directory.",
            )

        if isinstance(sources, str):
            sources = [sources]

        username = dut.credentials.bmc_ssh_username or dut.credentials.bmc_username
        password = dut.credentials.bmc_ssh_password or dut.credentials.bmc_password

        # Check if proxy is configured
        proxy_client = await self.create_proxy_connection(dut_id)

        for source in sources:
            retry_count = 0
            sftp_error = None
            transfer_method = None

            while retry_count < max_retries:
                try:
                    if self.ssh_backend == "asyncssh":
                        # Use asyncssh for file transfer
                        connect_kwargs = {
                            "host": dut.credentials.bmc_ip,
                            "port": dut.credentials.bmc_ssh_port,
                            "username": username,
                            "connect_timeout": 30,
                            "known_hosts": None,
                        }

                        if password:
                            connect_kwargs["password"] = password
                        elif dut.credentials.bmc_ssh_key_path:
                            connect_kwargs["client_keys"] = [
                                dut.credentials.bmc_ssh_key_path
                            ]

                        conn = await asyncssh.connect(**connect_kwargs)

                        # Try SFTP first
                        try:
                            async with conn.start_sftp_client() as sftp:
                                file_name = os.path.basename(source)
                                remote_path = f"{destination_directory}/{file_name}"

                                if copy_to_destination:
                                    # Copy local file to remote
                                    await sftp.put(source, remote_path)
                                    transfer_method = "SFTP"
                                    await self.logger.log_runtime(
                                        "INFO",
                                        "DUTManager",
                                        f"Transferred {source} to {remote_path} via SFTP",
                                    )
                                else:
                                    # Copy remote file to local
                                    await sftp.get(remote_path, source)
                                    transfer_method = "SFTP"
                                    await self.logger.log_runtime(
                                        "INFO",
                                        "DUTManager",
                                        f"Transferred {remote_path} to {source} via SFTP",
                                    )
                            conn.close()
                            await conn.wait_closed()
                        except Exception as sftp_ex:
                            # SFTP failed - try SCP as fallback
                            await self.logger.log_runtime(
                                "DEBUG",
                                "DUTManager",
                                f"SFTP failed ({sftp_ex}), trying SCP fallback",
                            )

                            file_name = os.path.basename(source)
                            remote_path = f"{destination_directory}/{file_name}"

                            if copy_to_destination:
                                # Upload using SCP
                                await asyncssh.scp(source, (conn, remote_path))
                                transfer_method = "SCP"
                                await self.logger.log_runtime(
                                    "INFO",
                                    "DUTManager",
                                    f"Transferred {source} to {remote_path} via SCP",
                                )
                            else:
                                # Download using SCP
                                await asyncssh.scp((conn, remote_path), source)
                                transfer_method = "SCP"
                                await self.logger.log_runtime(
                                    "INFO",
                                    "DUTManager",
                                    f"Transferred {remote_path} to {source} via SCP",
                                )

                            conn.close()
                            await conn.wait_closed()
                    else:
                        # Use paramiko for file transfer
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                        connect_kwargs = {
                            "hostname": dut.credentials.bmc_ip,
                            "port": dut.credentials.bmc_ssh_port,
                            "username": username,
                            "timeout": 30,
                        }

                        if password:
                            connect_kwargs["password"] = password
                        elif dut.credentials.bmc_ssh_key_path:
                            key = paramiko.RSAKey.from_private_key_file(
                                dut.credentials.bmc_ssh_key_path
                            )
                            connect_kwargs["pkey"] = key

                        client.connect(**connect_kwargs)

                        # Try SFTP first
                        try:
                            with client.open_sftp() as sftp:
                                file_name = os.path.basename(source)
                                remote_path = f"{destination_directory}/{file_name}"

                                if copy_to_destination:
                                    # Copy local file to remote
                                    sftp.put(source, remote_path)
                                    transfer_method = "SFTP"
                                    await self.logger.log_runtime(
                                        "INFO",
                                        "DUTManager",
                                        f"Transferred {source} to {remote_path} via SFTP",
                                    )
                                else:
                                    # Copy remote file to local
                                    sftp.get(remote_path, source)
                                    transfer_method = "SFTP"
                                    await self.logger.log_runtime(
                                        "INFO",
                                        "DUTManager",
                                        f"Transferred {remote_path} to {source} via SFTP",
                                    )
                            client.close()
                        except Exception as sftp_ex:
                            # SFTP failed - try SCP as fallback using paramiko
                            await self.logger.log_runtime(
                                "DEBUG",
                                "DUTManager",
                                f"SFTP failed ({sftp_ex}), trying SCP fallback",
                            )

                            scp_attempted = False
                            try:
                                try:
                                    from scp import SCPClient

                                    scp_available = True
                                except ImportError:
                                    scp_available = False
                                    await self.logger.log_runtime(
                                        "DEBUG",
                                        "DUTManager",
                                        "SCP module not installed, skipping SCP fallback (install with: pip install scp)",
                                    )

                                if scp_available:
                                    scp_attempted = True
                                    file_name = os.path.basename(source)
                                    remote_path = f"{destination_directory}/{file_name}"

                                    with SCPClient(client.get_transport()) as scp:
                                        if copy_to_destination:
                                            # Upload using SCP
                                            scp.put(source, remote_path)
                                            transfer_method = "SCP"
                                            await self.logger.log_runtime(
                                                "INFO",
                                                "DUTManager",
                                                f"Transferred {source} to {remote_path} via SCP",
                                            )
                                        else:
                                            # Download using SCP
                                            scp.get(remote_path, source)
                                            transfer_method = "SCP"
                                            await self.logger.log_runtime(
                                                "INFO",
                                                "DUTManager",
                                                f"Transferred {remote_path} to {source} via SCP",
                                            )
                            except Exception as scp_ex:
                                if scp_attempted:
                                    await self.logger.log_runtime(
                                        "DEBUG",
                                        "DUTManager",
                                        f"SCP fallback also failed: {scp_ex}",
                                    )
                                # Re-raise the original SFTP error since SCP also failed
                                raise sftp_ex
                            finally:
                                client.close()

                    break  # Transfer successful
                except Exception as e:
                    retry_count += 1
                    if retry_count < max_retries:
                        await self.logger.log_runtime(
                            "WARNING",
                            "DUTManager",
                            f"File transfer attempt {retry_count}/{max_retries} failed: {e}",
                        )
                        await asyncio.sleep(2**retry_count)  # Exponential backoff
                    else:
                        return (
                            False,
                            f"File transfer failed after {max_retries} attempts: {e}",
                        )

        return True, ""

    async def transfer_host_files(
        self,
        dut_id: str,
        sources: Union[str, List[str]],
        destination_directory: str,
        copy_to_destination: bool = True,
        max_retries: int = 3,
    ) -> Tuple[bool, str]:
        """
        Copy files from/to host via SSH (for host file transfers)

        Args:
            dut_id: DUT identifier
            sources: Single source path or list of paths
            destination_directory: Target path
            copy_to_destination: Flag to set if copying files to/from destination.
                               True = copy to destination, False = copy from destination
            max_retries: Maximum number of retries. 3 by default

        Returns:
            Tuple of (success, error_message)
        """
        dut = self.get_dut(dut_id)

        # Debug logging
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"transfer_host_files called with sources={sources}, destination={destination_directory}, copy_to_destination={copy_to_destination}",
        )
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"transfer_host_files: sources type={type(sources)}, destination type={type(destination_directory)}",
        )
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"Host connected: {dut.connection_state.host_connected}",
        )
        await self.logger.log_runtime(
            "DEBUG", "DUTManager", f"Host IP: {dut.credentials.host_ip}"
        )

        # Ensure host connection is established
        success, message = await self._ensure_connection(
            dut_id, "host", "test_host_connection"
        )
        if not success:
            return False, message

        # Validate inputs
        if not isinstance(sources, (list, tuple, str)) or not isinstance(
            destination_directory, str
        ):
            return (
                False,
                "Invalid argument combination. Please provide either a single source or list of sources, and a single destination directory.",
            )

        if isinstance(sources, str):
            sources = [sources]

        # For downloading files (copy_to_destination=False), use enhanced fallback logic
        if not copy_to_destination:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Using enhanced fallback logic for host file transfer",
            )
            return await self._transfer_host_files_with_fallback(
                dut_id, sources, destination_directory, max_retries
            )

        # For uploading files (copy_to_destination=True), use original logic
        username = dut.credentials.host_username
        password = dut.credentials.host_password

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "DUTManager",
            f"Host credentials - username: {username}, password available: {'Yes' if password else 'No'}",
        )

        # Check if proxy is configured
        proxy_client = await self.create_proxy_connection(dut_id)

        for source in sources:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"Attempting to transfer source: {source}",
            )
            retry_count = 0
            while retry_count < max_retries:
                try:
                    if self.ssh_backend == "asyncssh":
                        # Use asyncssh for file transfer
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Using asyncssh for host file transfer",
                        )
                        connect_kwargs = {
                            "host": dut.credentials.host_ip,
                            "port": dut.credentials.host_ssh_port,
                            "username": username,
                            "connect_timeout": 30,
                            "known_hosts": None,
                        }
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"asyncssh connect_kwargs: host={dut.credentials.host_ip}, port={dut.credentials.host_ssh_port}, username={username}",
                        )

                        if password:
                            connect_kwargs["password"] = password
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "DUTManager",
                                "Using password authentication for host file transfer",
                            )
                        elif dut.credentials.host_ssh_key_path:
                            connect_kwargs["client_keys"] = [
                                dut.credentials.host_ssh_key_path
                            ]
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "DUTManager",
                                f"Using SSH key authentication for host file transfer: {dut.credentials.host_ssh_key_path}",
                            )

                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Attempting asyncssh connection to {dut.credentials.host_ip}",
                        )
                        conn = await asyncssh.connect(**connect_kwargs)
                        try:
                            async with conn.start_sftp_client() as sftp:
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "DEBUG",
                                    "DUTManager",
                                    f"SFTP client started successfully",
                                )
                                file_name = os.path.basename(source)
                                remote_path = f"{destination_directory}/{file_name}"

                                if copy_to_destination:
                                    # Copy local file to remote
                                    await self.logger.write_to_dut_runtime_log(
                                        dut_id,
                                        "DEBUG",
                                        "DUTManager",
                                        f"Copying local file {source} to remote {remote_path}",
                                    )
                                    await sftp.put(source, remote_path)
                                    await self.logger.log_runtime(
                                        "INFO",
                                        "DUTManager",
                                        f"Transferred {source} to {remote_path}",
                                    )
                                else:
                                    # Copy remote file to local
                                    local_path = f"{destination_directory}/{file_name}"
                                    await self.logger.log_runtime(
                                        "DEBUG",
                                        "DUTManager",
                                        f"Copying remote file {source} to local {local_path}",
                                    )
                                    await self.logger.log_runtime(
                                        "DEBUG",
                                        "DUTManager",
                                        f"About to call sftp.get({source}, {local_path})",
                                    )
                                    await sftp.get(source, local_path)
                                    await self.logger.write_to_dut_runtime_log(
                                        dut_id,
                                        "DEBUG",
                                        "DUTManager",
                                        f"SFTP get operation completed successfully",
                                    )
                                    await self.logger.write_to_dut_runtime_log(
                                        dut_id,
                                        "INFO",
                                        "DUTManager",
                                        f"Transferred {source} to {local_path}",
                                    )
                        finally:
                            conn.close()
                            await conn.wait_closed()
                    else:
                        # Use paramiko for file transfer
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                        connect_kwargs = {
                            "hostname": dut.credentials.host_ip,
                            "port": dut.credentials.host_ssh_port,
                            "username": username,
                            "timeout": 30,
                        }
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"paramiko connect_kwargs: hostname={dut.credentials.host_ip}, port={dut.credentials.host_ssh_port}, username={username}",
                        )

                        if password:
                            connect_kwargs["password"] = password
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "DUTManager",
                                "Using password authentication for paramiko host file transfer",
                            )
                        elif dut.credentials.host_ssh_key_path:
                            connect_kwargs["key_filename"] = (
                                dut.credentials.host_ssh_key_path
                            )
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "DUTManager",
                                f"Using SSH key authentication for paramiko host file transfer: {dut.credentials.host_ssh_key_path}",
                            )

                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Attempting paramiko connection to {dut.credentials.host_ip}",
                        )
                        client.connect(**connect_kwargs)
                        try:
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "DUTManager",
                                f"paramiko connection successful",
                            )
                            sftp = client.open_sftp()
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "DUTManager",
                                f"paramiko SFTP client opened successfully",
                            )
                            file_name = os.path.basename(source)
                            remote_path = f"{destination_directory}/{file_name}"

                            if copy_to_destination:
                                # Copy local file to remote
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "DEBUG",
                                    "DUTManager",
                                    f"paramiko: Copying local file {source} to remote {remote_path}",
                                )
                                sftp.put(source, remote_path)
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "INFO",
                                    "DUTManager",
                                    f"Transferred {source} to {remote_path}",
                                )
                            else:
                                # Copy remote file to local
                                local_path = f"{destination_directory}/{file_name}"
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "DEBUG",
                                    "DUTManager",
                                    f"paramiko: Copying remote file {source} to local {local_path}",
                                )
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "DEBUG",
                                    "DUTManager",
                                    f"paramiko: About to call sftp.get({source}, {local_path})",
                                )
                                sftp.get(source, local_path)
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "DEBUG",
                                    "DUTManager",
                                    f"paramiko SFTP get operation completed successfully",
                                )
                                await self.logger.log_runtime(
                                    "INFO",
                                    "DUTManager",
                                    f"Transferred {source} to {local_path}",
                                )
                        finally:
                            client.close()

                    # If we get here, transfer was successful
                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        f"File transfer successful for {source}",
                    )
                    break

                except Exception as e:
                    retry_count += 1
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"File transfer attempt {retry_count} failed for {source}: {e}",
                    )
                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        f"Exception details: {type(e).__name__}: {str(e)}",
                    )
                    if retry_count >= max_retries:
                        await self.logger.log_runtime(
                            "ERROR",
                            "DUTManager",
                            f"File transfer failed after {max_retries} attempts for {source}",
                        )
                        return (
                            False,
                            f"File transfer failed after {max_retries} attempts: {e}",
                        )

        return True, ""

    async def _transfer_host_files_with_fallback(
        self,
        dut_id: str,
        sources: List[str],
        destination_directory: str,
        max_retries: int = 3,
    ) -> Tuple[bool, str]:
        """
        Enhanced file transfer with multiple fallback approaches.

        Uses multiple approaches to download files:
        1. Direct SFTP download
        2. Copy to temp location with readable permissions using sudo
        3. Create tar archive if multiple files fail

        Args:
            dut_id: DUT identifier
            sources: List of source file paths to download
            destination_directory: Local directory to store downloaded files
            max_retries: Maximum number of retries for each method

        Returns:
            Tuple of (success, error_message)
        """
        dut = self.get_dut(dut_id)
        username = dut.credentials.host_username
        password = dut.credentials.host_password

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "DUTManager",
            f"Starting enhanced file transfer with fallback for {len(sources)} files",
        )

        # Create a unique temp directory using timestamp and random string
        timestamp = int(time.time())
        random_str = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=8)
        )
        temp_dir = f"/tmp/nvdebug_transfer_{timestamp}_{random_str}"

        try:
            # Ensure destination directory exists
            os.makedirs(destination_directory, exist_ok=True)

            successful_downloads = []
            failed_paths = []

            # Step 1: Try direct SFTP download first
            await self.logger.write_to_dut_runtime_log(
                dut_id, "INFO", "DUTManager", "Attempting direct SFTP download..."
            )

            # Pre-transfer diagnostics
            await self.logger.write_to_dut_runtime_log(
                dut_id, "DEBUG", "DUTManager", "Running pre-transfer diagnostics"
            )

            # Check SSH user context
            user_check_cmd = "whoami && id && groups"
            user_exit_code, user_stdout, _ = await self.execute_host_command(
                dut_id, user_check_cmd, timeout=30, use_sudo=False
            )
            if user_exit_code == 0:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DUTManager",
                    f"SSH user context: {user_stdout.strip()}",
                )

            # Check /tmp directory permissions
            tmp_check_cmd = "ls -ld /tmp && df -h /tmp"
            tmp_exit_code, tmp_stdout, _ = await self.execute_host_command(
                dut_id, tmp_check_cmd, timeout=30, use_sudo=False
            )
            if tmp_exit_code == 0:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DUTManager",
                    f"/tmp directory status: {tmp_stdout.strip()}",
                )

            for source in sources:
                try:
                    # Pre-download diagnostics for each file
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        f"Pre-download diagnostics for: {source}",
                    )

                    # Check file existence and permissions
                    file_check_cmd = f"test -f '{source}' && ls -la '{source}' || echo 'File does not exist: {source}'"
                    file_exit_code, file_stdout, _ = await self.execute_host_command(
                        dut_id, file_check_cmd, timeout=30, use_sudo=False
                    )
                    if file_exit_code == 0:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"File check result: {file_stdout.strip()}",
                        )

                    # Check if we can read the file
                    read_test_cmd = f"head -c 100 '{source}' > /dev/null 2>&1 && echo 'File readable' || echo 'File not readable'"
                    read_exit_code, read_stdout, _ = await self.execute_host_command(
                        dut_id, read_test_cmd, timeout=30, use_sudo=False
                    )
                    if read_exit_code == 0:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"File readability test: {read_stdout.strip()}",
                        )

                    # Try direct SFTP download
                    success, error_msg = await self._simple_sftp_download(
                        dut_id, source, destination_directory
                    )

                    if success:
                        successful_downloads.append(source)
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "DUTManager",
                            f"Direct download successful for {source}",
                        )
                    else:
                        failed_paths.append(source)
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "DUTManager",
                            f"Direct download failed for {source}: {error_msg}",
                        )
                except Exception as e:
                    failed_paths.append(source)
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Direct download exception for {source}: {str(e)}",
                    )

            if not failed_paths:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    "All files downloaded successfully via direct SFTP",
                )
                return True, ""

            # Step 2: For failed files, try copying to temp location with readable permissions
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Attempting permission-based fallback for {len(failed_paths)} failed files",
            )

            # Create the temporary directory with sudo
            mkdir_cmd = f"mkdir -p {temp_dir}"
            exit_code, _, stderr_mkdir = await self.execute_host_command(
                dut_id, mkdir_cmd, timeout=60, use_sudo=True
            )

            if exit_code != 0:
                error_msg = f"Failed to create temp directory: {stderr_mkdir}"
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "ERROR", "DUTManager", error_msg
                )
                return False, error_msg

            # Set directory permissions to 777
            chmod_dir_cmd = f"chmod 777 {temp_dir}"
            exit_code, _, stderr_chmod = await self.execute_host_command(
                dut_id, chmod_dir_cmd, timeout=60, use_sudo=True
            )

            if exit_code != 0:
                error_msg = f"Failed to set temp directory permissions: {stderr_chmod}"
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "ERROR", "DUTManager", error_msg
                )
                return False, error_msg

            # Try to copy failed files to temp location with readable permissions
            for remote_path in failed_paths[:]:  # Copy list to allow modification
                unique_filename = os.path.basename(remote_path)
                temp_file = f"{temp_dir}/{unique_filename}"

                # Copy file to temporary location using sudo with better error handling
                cp_cmd = f"cp {shlex.quote(remote_path)} {shlex.quote(temp_file)}"
                exit_code, _, stderr_cp = await self.execute_host_command(
                    dut_id, cp_cmd, timeout=60, use_sudo=True
                )

                # If copy failed, try multiple permission-related fixes
                if exit_code != 0 and any(
                    perm_error in stderr_cp.lower()
                    for perm_error in [
                        "permission denied",
                        "operation not permitted",
                        "access denied",
                    ]
                ):
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "DUTManager",
                        f"Copy failed due to permissions, attempting to fix permissions on {remote_path}",
                    )

                    # First, try to get file info to understand the issue
                    info_cmd = f"ls -la {shlex.quote(remote_path)} 2>/dev/null || echo 'File not accessible'"
                    info_exit_code, info_stdout, _ = await self.execute_host_command(
                        dut_id, info_cmd, timeout=30, use_sudo=True
                    )

                    if info_exit_code == 0:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"File info before permission fix: {info_stdout.strip()}",
                        )

                    # Try multiple permission fixes in order of preference
                    permission_fixes = [
                        ("chmod 644", f"chmod 644 {shlex.quote(remote_path)}"),
                        ("chmod 755", f"chmod 755 {shlex.quote(remote_path)}"),
                        (
                            "chmod o+r",
                            f"chmod o+r {shlex.quote(remote_path)}",
                        ),  # Add read for others
                    ]

                    for fix_name, chmod_cmd in permission_fixes:
                        chmod_exit_code, _, chmod_stderr = (
                            await self.execute_host_command(
                                dut_id, chmod_cmd, timeout=60, use_sudo=True
                            )
                        )

                        if chmod_exit_code == 0:
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "DUTManager",
                                f"Successfully applied {fix_name} to {remote_path}",
                            )

                            # Retry the copy after fixing permissions
                            exit_code, _, stderr_cp = await self.execute_host_command(
                                dut_id, cp_cmd, timeout=60, use_sudo=True
                            )

                            if exit_code == 0:
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "INFO",
                                    "DUTManager",
                                    f"Copy succeeded after applying {fix_name}",
                                )
                                break
                        else:
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "DUTManager",
                                f"Failed to apply {fix_name}: {chmod_stderr}",
                            )

                if exit_code != 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Failed to copy {remote_path} to temp location: {stderr_cp}",
                    )
                    continue

                # Set file permissions to 644 on the copied file
                chmod_file_cmd = f"chmod 644 {shlex.quote(temp_file)}"
                exit_code, _, stderr_file_chmod = await self.execute_host_command(
                    dut_id, chmod_file_cmd, timeout=60, use_sudo=True
                )

                if exit_code != 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Failed to set file permissions: {stderr_file_chmod}",
                    )
                    continue

                # Verify the temporary file has content before attempting download
                verify_cmd = f"test -s {shlex.quote(temp_file)}"
                exit_code, _, _ = await self.execute_host_command(
                    dut_id, verify_cmd, timeout=60, use_sudo=True
                )

                if exit_code != 0:
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"Empty temp file: {temp_file}",
                        dut_id,
                    )
                    # Clean up empty temp file
                    await self.execute_host_command(
                        dut_id,
                        f"rm -f {shlex.quote(temp_file)}",
                        timeout=60,
                        use_sudo=True,
                    )
                    continue

                # Attempt download of the file from the temporary location
                try:
                    success, error_msg = await self._simple_sftp_download(
                        dut_id, temp_file, destination_directory
                    )

                    if success:
                        failed_paths.remove(remote_path)
                        successful_downloads.append(remote_path)
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "DUTManager",
                            f"Fallback download successful for {remote_path}",
                        )
                    else:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "DUTManager",
                            f"Fallback download failed for {remote_path}: {error_msg}",
                        )
                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Fallback download exception for {remote_path}: {str(e)}",
                    )

                # Clean up temp file
                await self.execute_host_command(
                    dut_id, f"rm -f {shlex.quote(temp_file)}", timeout=60, use_sudo=True
                )

            if not failed_paths:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    "All files downloaded successfully via permission-based fallback",
                )
                return True, ""

            # Step 3: If we still have failed files, try tar archive approach
            if len(failed_paths) > 1:  # Only create tar if multiple files
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    f"Attempting tar archive fallback for {len(failed_paths)} remaining failed files",
                )

                temp_tar = f"{temp_dir}/files_transfer.tar.gz"

                # Create tar in the temp directory to avoid permission issues
                # Use -h flag to follow symlinks (dereference) to ensure actual data is archived
                # Important: -h must come before -f, not after it
                files_str = " ".join(shlex.quote(f) for f in failed_paths)
                tar_cmd = f"cd {temp_dir} && sudo tar -h -czf {os.path.basename(temp_tar)} {files_str}"

                await self.logger.write_to_dut_runtime_log(
                    dut_id, "DEBUG", "DUTManager", f"Tar command: {tar_cmd}"
                )

                exit_code, stdout, stderr = await self.execute_host_command(
                    dut_id, tar_cmd, timeout=300, use_sudo=True
                )

                if exit_code == 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id, "INFO", "DUTManager", "Remote tar creation successful"
                    )

                    # Set permissions on the tar file
                    chmod_cmd = f"sudo chmod 644 {temp_tar}"
                    chmod_exit_code, _, chmod_stderr = await self.execute_host_command(
                        dut_id, chmod_cmd, timeout=60, use_sudo=True
                    )

                    if chmod_exit_code != 0:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "DUTManager",
                            f"Failed to set permissions on tar file: {chmod_stderr}",
                        )

                    # Try to download the tar file
                    success, error_msg = await self._simple_sftp_download(
                        dut_id, temp_tar, destination_directory
                    )

                    if success:
                        local_tar = os.path.join(
                            destination_directory, os.path.basename(temp_tar)
                        )

                        try:
                            # Extract the tar file locally
                            with tarfile.open(local_tar, "r:gz") as tar:
                                tar.extractall(
                                    path=destination_directory,
                                    filter=lambda m: self._safe_tar_filter(
                                        m, destination_directory
                                    ),
                                )

                            # Remove the tar file
                            os.remove(local_tar)

                            # Verify extracted files
                            newly_extracted = []
                            for remote_path in failed_paths[:]:
                                local_path = os.path.join(
                                    destination_directory,
                                    os.path.basename(remote_path),
                                )

                                if self._verify_file_content(local_path):
                                    failed_paths.remove(remote_path)
                                    newly_extracted.append(remote_path)
                                    await self.logger.write_to_dut_runtime_log(
                                        dut_id,
                                        "INFO",
                                        "DUTManager",
                                        f"Successfully extracted: {os.path.basename(remote_path)}",
                                    )
                                else:
                                    await self.logger.write_to_dut_runtime_log(
                                        dut_id,
                                        "WARNING",
                                        "DUTManager",
                                        f"Extracted file verification failed: {os.path.basename(remote_path)}",
                                    )

                            successful_downloads.extend(newly_extracted)

                        except Exception as e:
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "ERROR",
                                "DUTManager",
                                f"Failed to extract tar: {str(e)}",
                            )
                    else:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "DUTManager",
                            f"Failed to download tar: {error_msg}",
                        )

                    # Clean up remote tar
                    await self.execute_host_command(
                        dut_id, f"sudo rm -f {temp_tar}", timeout=60, use_sudo=True
                    )
                else:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DUTManager",
                        f"Remote tar creation failed: {stderr}",
                    )
                    if stdout:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Tar command output: {stdout}",
                        )

            # Final status
            if failed_paths:
                error_msg = f"Failed to download files: {', '.join(failed_paths)}"
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "ERROR", "DUTManager", error_msg
                )
                return False, error_msg

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Enhanced file transfer completed successfully. Downloaded {len(successful_downloads)} files.",
            )
            return True, ""

        except Exception as error:
            error_msg = f"Unexpected error in enhanced file transfer: {str(error)}"
            await self.logger.write_to_dut_runtime_log(
                dut_id, "ERROR", "DUTManager", error_msg
            )
            return False, error_msg
        finally:
            # Clean up temp directory if it exists
            try:
                await self.execute_host_command(
                    dut_id, f"sudo rm -rf {temp_dir}", timeout=60, use_sudo=True
                )
            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "DUTManager",
                    f"Failed to clean up temp directory {temp_dir}: {str(e)}",
                )

    async def _create_connection_with_proxy(
        self,
        dut_id: str,
        use_proxy: bool = True,
    ) -> Tuple[Union[asyncssh.SSHClientConnection, paramiko.SSHClient], str]:
        """
        Create SSH connection with optional proxy support.

        Args:
            dut_id: DUT identifier
            use_proxy: Whether to use proxy connection if available

        Returns:
            Tuple of (connection_object, connection_type)
        """
        dut = self.get_dut(dut_id)
        username = dut.credentials.host_username
        password = dut.credentials.host_password

        # Check if proxy is configured and should be used
        proxy_client = None
        if use_proxy and dut.credentials.ssh_proxy_host:
            proxy_client = await self.create_proxy_connection(dut_id)
            if proxy_client:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DUTManager",
                    "Using proxy connection for file transfer",
                )

        try:
            if self.ssh_backend == "asyncssh":
                # Use asyncssh for file transfer
                connect_kwargs = {
                    "host": dut.credentials.host_ip,
                    "port": dut.credentials.host_ssh_port,
                    "username": username,
                    "connect_timeout": 30,
                    "known_hosts": None,
                }

                if password:
                    connect_kwargs["password"] = password
                elif dut.credentials.host_ssh_key_path:
                    connect_kwargs["client_keys"] = [dut.credentials.host_ssh_key_path]

                # If proxy is available, use it
                if proxy_client and hasattr(proxy_client, "get_extra_info"):
                    # asyncssh proxy connection
                    conn = await asyncssh.connect(**connect_kwargs, proxy=proxy_client)
                else:
                    # Direct connection
                    conn = await asyncssh.connect(**connect_kwargs)

                return conn, "asyncssh"
            else:
                # Use paramiko for file transfer
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                connect_kwargs = {
                    "hostname": dut.credentials.host_ip,
                    "port": dut.credentials.host_ssh_port,
                    "username": username,
                    "timeout": 30,
                }

                if password:
                    connect_kwargs["password"] = password
                elif dut.credentials.host_ssh_key_path:
                    connect_kwargs["key_filename"] = dut.credentials.host_ssh_key_path

                # If proxy is available, use it
                if proxy_client and hasattr(proxy_client, "get_transport"):
                    # paramiko proxy connection
                    proxy_transport = proxy_client.get_transport()
                    proxy_channel = proxy_transport.open_channel(
                        "direct-tcpip",
                        (dut.credentials.host_ip, dut.credentials.host_ssh_port),
                        ("", 0),
                    )
                    client.connect(**connect_kwargs, sock=proxy_channel)
                else:
                    # Direct connection
                    client.connect(**connect_kwargs)

                return client, "paramiko"

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id, "ERROR", "DUTManager", f"Failed to create connection: {str(e)}"
            )
            raise

    async def _simple_sftp_download(
        self,
        dut_id: str,
        source: str,
        destination_directory: str,
        use_proxy: bool = True,
    ) -> Tuple[bool, str]:
        """
        Simple SFTP download without retries (used by fallback methods).

        Args:
            dut_id: DUT identifier
            source: Source file path on remote host
            destination_directory: Local directory to store downloaded file
            use_proxy: Whether to use proxy connection if available

        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Create connection with proxy support
            conn, conn_type = await self._create_connection_with_proxy(
                dut_id, use_proxy
            )

            if conn_type == "asyncssh":
                # Use asyncssh for file transfer
                try:
                    async with conn.start_sftp_client() as sftp:
                        file_name = os.path.basename(source)
                        local_path = f"{destination_directory}/{file_name}"

                        # Check if source file exists on remote system
                        try:
                            stat_result = await sftp.stat(source)
                            # asyncssh uses 'size' attribute, paramiko uses 'st_size'
                            file_size = getattr(
                                stat_result,
                                "size",
                                getattr(stat_result, "st_size", "unknown"),
                            )
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "DUTManager",
                                f"Remote file {source} exists, size: {file_size} bytes",
                            )
                        except FileNotFoundError:
                            error_msg = (
                                f"Source file {source} does not exist on remote system"
                            )
                            await self.logger.write_to_dut_runtime_log(
                                dut_id, "ERROR", "DUTManager", error_msg
                            )
                            return False, error_msg
                        except Exception as e:
                            error_msg = (
                                f"Failed to check remote file {source}: {str(e)}"
                            )
                            await self.logger.write_to_dut_runtime_log(
                                dut_id, "ERROR", "DUTManager", error_msg
                            )
                            return False, error_msg

                        # Download remote file to local
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Downloading {source} to {local_path}",
                        )
                        await sftp.get(source, local_path)

                        # Verify file was downloaded and has content
                        if self._verify_file_content(local_path):
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "DUTManager",
                                f"Successfully downloaded and verified {local_path}",
                            )
                            return True, ""
                        else:
                            error_msg = (
                                f"Downloaded file {local_path} is empty or missing"
                            )
                            await self.logger.write_to_dut_runtime_log(
                                dut_id, "ERROR", "DUTManager", error_msg
                            )
                            return False, error_msg

                finally:
                    conn.close()
                    await conn.wait_closed()
            else:
                # Use paramiko for file transfer
                try:
                    sftp = conn.open_sftp()
                    file_name = os.path.basename(source)
                    local_path = f"{destination_directory}/{file_name}"

                    # Check if source file exists on remote system
                    try:
                        stat_result = sftp.stat(source)
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Remote file {source} exists, size: {stat_result.st_size} bytes",
                        )
                    except FileNotFoundError:
                        error_msg = (
                            f"Source file {source} does not exist on remote system"
                        )
                        await self.logger.write_to_dut_runtime_log(
                            dut_id, "ERROR", "DUTManager", error_msg
                        )
                        return False, error_msg
                    except Exception as e:
                        error_msg = f"Failed to check remote file {source}: {str(e)}"
                        await self.logger.write_to_dut_runtime_log(
                            dut_id, "ERROR", "DUTManager", error_msg
                        )
                        return False, error_msg

                    # Download remote file to local
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        f"Downloading {source} to {local_path}",
                    )
                    sftp.get(source, local_path)

                    # Verify file was downloaded and has content
                    if self._verify_file_content(local_path):
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Successfully downloaded and verified {local_path}",
                        )
                        return True, ""
                    else:
                        error_msg = f"Downloaded file {local_path} is empty or missing"
                        await self.logger.write_to_dut_runtime_log(
                            dut_id, "ERROR", "DUTManager", error_msg
                        )
                        return False, error_msg

                finally:
                    conn.close()

        except Exception as e:
            error_msg = f"SFTP download failed: {str(e)}"
            await self.logger.write_to_dut_runtime_log(
                dut_id, "ERROR", "DUTManager", error_msg
            )
            return False, error_msg

    def _verify_file_content(self, file_path: str) -> bool:
        """
        Verify that a file exists and has content.

        Args:
            file_path: Path to the file to verify

        Returns:
            True if file exists and has content, False otherwise
        """
        try:
            return os.path.exists(file_path) and os.path.getsize(file_path) > 0
        except (OSError, IOError):
            return False

    def ssh_client_is_active(self, ssh_client) -> bool:
        """
        Check if SSH client connection is still active

        Args:
            ssh_client: SSH client to check (paramiko.SSHClient or asyncssh.SSHClientConnection)

        Returns:
            True if connection is active, False otherwise
        """
        if not ssh_client:
            return False

        try:
            if hasattr(ssh_client, "get_transport"):  # paramiko
                transport = ssh_client.get_transport()
                if transport:
                    transport.send_ignore()
                    return True
                return False
            elif hasattr(ssh_client, "get_extra_info"):  # asyncssh
                # For asyncssh, we can check if the connection is still open
                return not ssh_client.is_closing()
            else:
                return False
        except (EOFError, Exception):
            return False

    async def check_ping_status(
        self,
        ip_address: str,
        ssh_pass: bool = False,
        ssh_server_ip: Optional[str] = None,
        ssh_username: Optional[str] = None,
        ssh_password: Optional[str] = None,
        ssh_port: int = 22,
    ) -> bool:
        """
        Try pinging the IP address

        Args:
            ip_address: IP address to ping
            ssh_pass: Whether to ping through SSH
            ssh_server_ip: Machine IP address to SSH through
            ssh_username: SSH username
            ssh_password: SSH password
            ssh_port: SSH port

        Returns:
            True if ping successful, False otherwise
        """

        ping_option = "-n" if platform.system().lower() == "windows" else "-c"
        ping_cmd = f"ping {ping_option} 2 {ip_address}"

        if ssh_pass:
            if not ssh_server_ip or not ssh_username or not ssh_password:
                await self.logger.log_runtime(
                    "ERROR",
                    "DUTManager",
                    "SSH ping requires server IP, username, and password",
                )
                return False
            sshpass_ping_cmd = f"sshpass -p {ssh_password} ssh -o StrictHostKeyChecking=no {ssh_username}@{ssh_server_ip} -p {ssh_port} "
        else:
            sshpass_ping_cmd = ""

        try:
            process = await asyncio.create_subprocess_shell(
                f"{sshpass_ping_cmd}{ping_cmd}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                return True
            else:
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Ping failed for {ip_address}: {self._process_command_output(stderr)}",
                )
                return False
        except Exception as e:
            await self.logger.log_runtime(
                "ERROR", "DUTManager", f"Ping error for {ip_address}: {e}"
            )
            return False

    async def create_standalone_ssh_client(
        self,
        host_ip: str,
        host_user: str,
        host_password: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
        proxy: Optional[paramiko.SSHClient] = None,
        max_retries: int = 2,
        timeout: int = 20,
        passwordless: bool = False,
        shell: bool = True,
        ssh_port: int = 22,
    ) -> Optional[paramiko.SSHClient]:
        """
        Create a standalone SSH client to connect to host IP

        Args:
            host_ip: Target machine IP address
            host_user: Target machine SSH Username
            host_password: Target machine SSH Password
            ssh_key_path: Target machine SSH Key filepath
            proxy: Proxy SSH client to be used as jumpbox
            max_retries: Maximum number of retries
            timeout: Timeout for SSH client creation
            passwordless: Enable passwordless SSH
            shell: Use shell when running commands
            ssh_port: SSH port to connect to

        Returns:
            SSH client if successful, None if failed
        """
        if not passwordless:
            if not host_ip or not host_user or (not host_password and not ssh_key_path):
                await self.logger.log_runtime(
                    "ERROR",
                    "DUTManager",
                    "Host IP and/or credentials are missing",
                )
                return None

        retry_count = 0
        while retry_count < max_retries:
            try:
                # Check ping if no proxy
                if not proxy and not await self.check_ping_status(
                    host_ip, ssh_port=ssh_port
                ):
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"Host {host_ip} is not reachable",
                    )
                    retry_count += 1
                    continue

                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                connect_kwargs = {
                    "hostname": host_ip,
                    "port": ssh_port,
                    "username": host_user,
                    "timeout": timeout,
                }

                # Handle proxy
                if proxy:
                    proxy_socket = proxy.get_transport().open_channel(
                        kind="direct-tcpip",
                        dest_addr=(host_ip, ssh_port),
                        src_addr=("", 0),
                    )
                    connect_kwargs["sock"] = proxy_socket
                else:
                    # Clear SSH key for this host
                    try:
                        process = await asyncio.create_subprocess_shell(
                            f"ssh-keygen -R {host_ip}",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        await process.communicate()
                    except Exception:
                        pass  # Ignore errors in key clearing

                # Handle authentication
                if ssh_key_path:
                    try:
                        key = paramiko.RSAKey.from_private_key_file(
                            ssh_key_path, password=host_password
                        )
                        connect_kwargs["pkey"] = key
                    except Exception as e:
                        await self.logger.log_runtime(
                            "ERROR",
                            "DUTManager",
                            f"Failed to load SSH key: {e}",
                        )
                        retry_count += 1
                        continue
                elif host_password:
                    connect_kwargs["password"] = host_password

                ssh_client.connect(**connect_kwargs)
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Successfully connected to {host_ip}:{ssh_port}",
                )
                return ssh_client

            except Exception as e:
                if "ssh_client" in locals():
                    ssh_client.close()
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"SSH connection attempt {retry_count + 1}/{max_retries} failed: {e}",
                )
                retry_count += 1
                if retry_count < max_retries:
                    await asyncio.sleep(2**retry_count)  # Exponential backoff

        await self.logger.log_runtime(
            "ERROR",
            "DUTManager",
            f"Failed to connect to {host_ip}:{ssh_port} after {max_retries} attempts",
        )
        return None

    def get_info_from_ipmi_output(
        self, ipmi_response: str = None, keyword_phrase: str = None
    ) -> str:
        """
        Returns a response if keyword_phrase is present in the IPMI output

        Args:
            ipmi_response: IPMI response from ipmitool command
            keyword_phrase: Key to look for in IPMI response

        Returns:
            "" if keyword_phrase does not exist in response else value
        """
        if not ipmi_response or not keyword_phrase:
            return ""

        pattern = re.compile(
            rf"\b{re.escape(keyword_phrase)}\s*:\s*([^<>\n]+)", re.IGNORECASE
        )
        match = pattern.search(ipmi_response)
        if match:
            return match.group(1).strip()
        else:
            return ""

    async def check_passwordless_ssh(
        self, ip: str, username: str, timeout: int = 5
    ) -> bool:
        """
        Check if passwordless SSH is set up correctly

        Args:
            ip: IP address to check
            username: Username to use for SSH
            timeout: Timeout in seconds

        Returns:
            True if passwordless SSH is set up, False otherwise
        """
        try:
            if self.ssh_backend == "asyncssh":
                # Use asyncssh for passwordless check
                try:
                    conn = await asyncio.wait_for(
                        asyncssh.connect(
                            host=ip,
                            username=username,
                            known_hosts=None,
                            connect_timeout=timeout,
                        ),
                        timeout=timeout,
                    )
                    conn.close()
                    await conn.wait_closed()
                    return True
                except Exception:
                    return False
            else:
                # Use paramiko for passwordless check
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(ip, username=username, timeout=timeout)
                    client.close()
                    return True
                except paramiko.AuthenticationException:
                    return False
                except Exception:
                    return False
        except Exception:
            return False

    async def execute_bash_command(
        self,
        command: str,
        timeout: Optional[float] = None,
        use_shell: bool = True,
        input_val: Optional[str] = None,
        environment: Optional[dict] = None,
        use_sudo: bool = False,
        sudo_password: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """
        Spawns a subprocess to run a command

        Args:
            command: Command to be run
            timeout: Set a timeout for the command. Default: None (no timeout)
            use_shell: Whether to run the command with shell. Default is True
            input_val: Input value to be passed. None by default
            environment: Environment variables to be passed. None by default
            use_sudo: Enable automatic sudo password injection. Default is False
            sudo_password: Password for sudo commands. Required if use_sudo is True

        Returns:
            Tuple of (exit_code, stdout, stderr) - matching execute_host_command format
        """
        try:
            # Handle sudo commands if requested
            if use_sudo and "sudo" in command:
                if sudo_password:
                    # Modify command to use sudo -S for password input
                    if "sudo -S" not in command:
                        command = command.replace("sudo ", "sudo -S ")

                    # Prepare input for sudo password (password + newline)
                    sudo_input = f"{sudo_password}\n"
                    if input_val:
                        sudo_input += input_val
                else:
                    # No sudo password provided - assume passwordless sudo (e.g., in local mode)
                    # Just run the command as-is with sudo
                    sudo_input = input_val
            else:
                sudo_input = input_val

            if not use_shell and not isinstance(command, list):
                cmd = shlex.split(command)
            else:
                cmd = command

            # Prepare environment
            env = None
            if environment:
                env = os.environ.copy()
                env.update(environment)

            # Create subprocess
            if use_shell:
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.PIPE if sudo_input else None,
                    env=env,
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.PIPE if sudo_input else None,
                    env=env,
                )

            # Wait for completion with timeout
            try:
                if sudo_input:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(input=sudo_input.encode()),
                        timeout=timeout,
                    )
                else:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), timeout=timeout
                    )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return -1, "", f"Command timed out after {timeout} seconds"

            # Decode the output using robust method
            stdout_text = self._process_command_output(stdout)
            stderr_text = self._process_command_output(stderr)

            return process.returncode, stdout_text, stderr_text

        except Exception as e:
            return -1, "", f"Error: {e}"

    def get_prop_from_response(
        self, response_dict: dict, property_string: str
    ) -> Tuple[bool, Any]:
        """
        Extracts a property from the response dict and returns it.
        Returns prop_present = False if the property was not found

        Args:
            response_dict: Property to fetch from the URI response
            property_string: Property to fetch from the URI response

        Returns:
            Tuple of (prop_present, property_value)
        """
        if not response_dict or not property_string:
            return False, None

        property_value = None
        prop_present = True
        property_list = list(filter(None, re.split(r"{|}", property_string)))
        curr_dict = response_dict

        for prop in property_list:
            # Check if the property is supposed to be a list
            prop_elements = list(filter(None, re.split(r"\[|\]", prop)))
            if prop_elements[0] in curr_dict:
                curr_dict = curr_dict.get(prop_elements[0])
            elif isinstance(curr_dict, list):
                property_value = []
                for item in curr_dict:  # item should be a dictionary
                    if isinstance(item, dict) and prop_elements[0] in item:
                        property_value.append(item.get(prop_elements[0]))
                    else:
                        property_value.append(None)
                return prop_present, property_value
            else:
                prop_present = False
                break

            # Handle array indexing if specified
            if len(prop_elements) > 1:
                try:
                    index = int(prop_elements[1])
                    if isinstance(curr_dict, list) and 0 <= index < len(curr_dict):
                        curr_dict = curr_dict[index]
                    else:
                        prop_present = False
                        break
                except (ValueError, IndexError):
                    prop_present = False
                    break

        property_value = curr_dict
        return prop_present, property_value

    async def get_preflight_results(self, dut_id: str) -> Dict[str, Any]:
        """
        Get preflight results for a specific DUT.

        Args:
            dut_id: DUT ID.

        Returns:
            Preflight results dictionary.
        """
        dut = self.get_dut(dut_id)
        return getattr(dut, "preflight_results", {})

    async def gather_platform_info(
        self, dut_id: str, preflight_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """
        Gather platform information for a DUT.

        Args:
            dut_id: DUT ID.
            preflight_results: Optional preflight results.

        Returns:
            Platform information dictionary.
        """
        dut = self.get_dut(dut_id)

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Starting platform detection for DUT: {dut_id}",
        )

        # Create platform detection service
        baseboard_manager = self._get_baseboard_manager()
        platform_service = PlatformDetectionService(
            self, self.logger, baseboard_manager
        )
        await platform_service.async_init()

        # Gather platform info
        platform_info = await platform_service.gather_platform_info(
            dut_id, preflight_results
        )

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Platform detection result for DUT {dut_id}: {platform_info}",
        )

        # Store in DUT object
        dut.platform_info = platform_info

        return platform_info

    async def get_platform_info(self, dut_id: str) -> Optional[Dict[str, str]]:
        """
        Get platform information for a DUT (returns cached if available).

        Args:
            dut_id: DUT ID.

        Returns:
            Platform information dictionary or None if not available.
        """
        dut = self.get_dut(dut_id)

        if dut.platform_info is None:
            # Gather platform info if not already cached
            dut.platform_info = await self.gather_platform_info(dut_id)

        return dut.platform_info

    async def detect_platform_and_baseboard(
        self,
        dut_id: str,
        preflight_results: Optional[Dict[str, Any]] = None,
        non_interactive: bool = False,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect platform and baseboard type from the DUT.

        Args:
            dut_id: The DUT identifier
            preflight_results: Optional preflight results for the DUT
            non_interactive: If True, use detected values or exit

        Returns:
            tuple: (success, info_dict) where:
                - success (bool): True if detection was successful
                - info_dict (dict): Dictionary containing platform, baseboard, and node_type
        """
        detection_service = AutoDetectionService(
            self, self.logger, self.sanitized_console
        )
        await detection_service.async_init()
        return await detection_service.detect_platform_and_baseboard(
            dut_id, preflight_results, non_interactive
        )

    async def run_dynamic_discovery(
        self, dut_id: str, preflight_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run dynamic discovery for Redfish resources on a DUT.

        Args:
            dut_id: The DUT identifier
            preflight_results: Optional preflight results to check Redfish status

        Returns:
            dict: Discovery results with resource members and metadata
        """
        discovery_service = self._get_discovery_service()
        return await discovery_service.discover_all_resources(dut_id, preflight_results)

    async def get_resource_members(self, dut_id: str, resource_type: str) -> List[str]:
        """
        Get cached resource members for a specific resource type.

        Args:
            dut_id: The DUT identifier
            resource_type: The resource type (e.g., "Systems", "Chassis", "Managers")

        Returns:
            list: List of resource member IDs
        """
        discovery_service = self._get_discovery_service()
        return await discovery_service.get_resource_members(dut_id, resource_type)

    async def get_resource_details(
        self, dut_id: str, resource_type: str
    ) -> Dict[str, Any]:
        """
        Get cached resource details for a specific resource type.

        Args:
            dut_id: The DUT identifier
            resource_type: The resource type

        Returns:
            dict: Resource details by member ID
        """
        discovery_service = self._get_discovery_service()
        return await discovery_service.get_resource_details(dut_id, resource_type)

    async def get_discovery_results(self, dut_id: str) -> Optional[Dict[str, Any]]:
        """
        Get cached discovery results for a DUT.

        Args:
            dut_id: The DUT identifier

        Returns:
            dict: Cached discovery results or None if not found
        """
        discovery_service = self._get_discovery_service()
        return await discovery_service.get_discovery_results(dut_id)

    async def get_firmware_inventory(self, dut_id: str) -> Optional[Dict[str, Any]]:
        """
        Get cached firmware inventory for a DUT.

        Args:
            dut_id: The DUT identifier

        Returns:
            dict: Firmware inventory data or None if not found
        """
        discovery_service = self._get_discovery_service()
        return await discovery_service.get_firmware_inventory(dut_id)

    async def cleanup(self) -> None:
        """
        Cleanup DUT manager resources.
        """
        await self.close_redfish_sessions()

        # Close any other sessions that might be open
        for dut_id, dut in self.duts.items():
            # Close any other sessions the DUT might have
            if hasattr(dut, "session") and dut.session:
                try:
                    await dut.session.close()
                    dut.session = None
                except Exception as e:
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"Error closing session for {dut_id}: {str(e)}",
                    )

            # Close any redfish sessions
            if hasattr(dut, "redfish_session") and dut.redfish_session:
                try:
                    await dut.redfish_session.close()
                    dut.redfish_session = None
                except Exception as e:
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"Error closing redfish session for {dut_id}: {str(e)}",
                    )

            # ✅ Clean up HMC port forwarding tunnels
            if hasattr(dut, "hmc_service") and dut.hmc_service:
                try:
                    await dut.hmc_service.cleanup_hmc_access(dut_id)
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Cleaned up HMC port forwarding for {dut_id}",
                    )
                except Exception as e:
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"Error cleaning up HMC port forwarding for {dut_id}: {str(e)}",
                    )

    async def _ensure_connection(
        self, dut_id: str, connection_type: str, test_method_name: str
    ) -> Tuple[bool, str]:
        """
        Common method to ensure a connection is established before executing commands.

        Args:
            dut_id: DUT identifier
            connection_type: Type of connection ('host', 'ssh', 'redfish', 'ipmi')
            test_method_name: Name of the test method to call (e.g., 'test_host_connection')

        Returns:
            Tuple of (success, message)
        """
        dut = self.get_dut(dut_id)

        # Special handling for IPMI in local mode without BMC IP
        if connection_type == "ipmi" and dut.config and dut.config.get("local", False):
            has_bmc_ip = dut.credentials and dut.credentials.bmc_ip
            if not has_bmc_ip:
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"IPMI connection check skipped for local mode without BMC IP - will execute locally via sudo",
                )
                return (
                    True,
                    "Local mode without BMC IP - IPMI will execute locally via sudo",
                )

        # Get the current connection state
        connection_state_attr = f"{connection_type}_connected"
        if not hasattr(dut.connection_state, connection_state_attr):
            return False, f"Invalid connection type: {connection_type}"

        is_connected = getattr(dut.connection_state, connection_state_attr)

        if is_connected:
            return (
                True,
                f"{connection_type.capitalize()} connection is already established",
            )

        # Try to re-establish the connection
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"{connection_type.capitalize()} connection state shows as disconnected, attempting to re-establish connection",
        )

        # Call the test method dynamically
        test_method = getattr(dut, test_method_name)
        success, message = await test_method()

        if not success:
            await self.logger.log_runtime(
                "ERROR",
                "DUTManager",
                f"Failed to re-establish {connection_type} connection: {message}",
            )
            return (
                False,
                f"{connection_type.capitalize()} not connected: {message}",
            )
        else:
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Successfully re-established {connection_type} connection: {message}",
            )
            return (
                True,
                f"{connection_type.capitalize()} connection re-established",
            )
