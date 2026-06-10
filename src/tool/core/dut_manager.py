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
import getpass
import grp
import json
import logging
import os
import platform
import re
import secrets
import shlex
import ssl
import tarfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import aiohttp
import asyncssh
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
from ..utils.tar_utils import get_tar_command
from ..utils.yaml_manager import YAMLManager
from .async_logger import AsyncSafeLogger
from .baseboard_manager import BaseboardManager

logger = logging.getLogger(__name__)

REDFISH_PREFLIGHT_REQUEST_TIMEOUT = 20
REDFISH_PREFLIGHT_CONNECT_TIMEOUT = 5
REDFISH_PREFLIGHT_SOCK_READ_TIMEOUT = 18
REDFISH_PREFLIGHT_MAX_RETRIES = 2
REDFISH_PREFLIGHT_RETRY_DELAY = 1
REDFISH_PREFLIGHT_RETRY_BUDGET = (
    (REDFISH_PREFLIGHT_MAX_RETRIES + 1) * REDFISH_PREFLIGHT_REQUEST_TIMEOUT
    + REDFISH_PREFLIGHT_MAX_RETRIES * REDFISH_PREFLIGHT_RETRY_DELAY
)
REDFISH_PREFLIGHT_WAIT_FOR_TIMEOUT = REDFISH_PREFLIGHT_RETRY_BUDGET + 5

INTERNAL_CONFIG_KEYS = {"__explicit_fields"}

DUT_TOOL_OVERRIDE_FIELDS = {
    "FW_INVENTORY_TABLE_PROPERTIES",
    "ADDITIONAL_OOB_URI_COLLECTION",
    "NVLINK_OOB_URI",
    "CUSTOM_DUMP_SERVICES",
    "POST_CODES_URI",
    "BMC_TEMP_DIR",
    "TASK_ID_PREFIX",
    "TOOL_TEMP_DIR",
    "REDFISH_DUMP_TIMEOUT",
    "REDFISH_DEVICE_DUMP_SLEEP_DURATION",
    "NVOS_TECH_DUMP_TIMEOUT",
    "SKIP_BMC_SSH_LOGS",
    "SKIP_HOST_LOGS",
    "SKIP_REDFISH_OOB_LOGS",
    "SKIP_IPMI_LOGS",
    "SKIP_PORT_FW",
    "COLLECTOR_TO_SKIP",
    "SYSTEM_ID_TO_SKIP",
    "CHASSIS_ID_TO_SKIP",
    "MANAGER_ID_TO_SKIP",
    "SYSTEM_ID_OVERRIDE",
    "MANAGER_ID_OVERRIDE",
    "CHASSIS_ID_OVERRIDE",
    "EXTRA_LOG_COLLECTION",
    "EXPAND_QUERY_CHASSIS_LEVEL",
    "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL",
    "EXPAND_QUERY_MANAGER_LEVEL",
    "EXPAND_QUERY_SYSTEM_LEVEL",
    "i2c_config",
}


def _strip_internal_config_keys(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy without internal merge bookkeeping fields."""
    return {
        key: value
        for key, value in dict(config).items()
        if key not in INTERNAL_CONFIG_KEYS
    }


def _explicit_key_map(config: Dict[str, Any]) -> Dict[str, bool]:
    """Return explicit-field metadata preserved from config loading."""
    if not isinstance(config, dict):
        return {}

    raw = config.get("__explicit_fields")
    if raw is None:
        return {key: True for key in config.keys() if key not in INTERNAL_CONFIG_KEYS}
    if isinstance(raw, dict):
        return {key: bool(value) for key, value in raw.items()}
    if isinstance(raw, (list, tuple, set)):
        return {key: True for key in raw}
    return {}


def _drop_implicit_tool_like_defaults(
    config: Dict[str, Any], explicit_keys: Dict[str, bool]
) -> Dict[str, Any]:
    """Remove DUTConfig defaults that should not override tool-level config."""
    cleaned = _strip_internal_config_keys(config)
    for field in DUT_TOOL_OVERRIDE_FIELDS:
        if not explicit_keys.get(field) or cleaned.get(field) is None:
            cleaned.pop(field, None)
    return cleaned


def _is_truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _normalize_execution_mode(value: Any, *, local: Any = False) -> str:
    if _is_truthy(local):
        return "local"

    if hasattr(value, "value"):
        value = value.value

    normalized = str(value or "remote").strip().lower()
    compact = normalized.replace("_", "").replace("-", "").replace(" ", "")
    if compact == "local":
        return "local"
    if compact in {"remote", "remoteclient"}:
        return "remote"
    return normalized


def _resolve_execution_mode(config: Dict[str, Any]) -> str:
    return _normalize_execution_mode(
        config.get("ExecutionMode") or config.get("execution_mode"),
        local=config.get("local", False),
    )


def _strip_leading_sudo(command: str) -> str:
    stripped = command.lstrip()
    leading = command[: len(command) - len(stripped)]

    for prefix in ("sudo -S ", "sudo -n ", "sudo "):
        if stripped.startswith(prefix):
            return f"{leading}{stripped[len(prefix):]}"

    return command


def _build_sudo_command(command: str, *, local_execution: bool) -> str:
    if not local_execution:
        if command.strip().startswith("sudo"):
            return command
        return f"sudo -S {command}"

    command_without_sudo = _strip_leading_sudo(command)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return command_without_sudo
    return f"sudo -n {command_without_sudo}"


async def _communicate_subprocess(
    process: asyncio.subprocess.Process,
    timeout: Optional[float] = None,
    input_data: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """Communicate with a subprocess and drain pipes before event-loop shutdown."""
    try:
        communicate = (
            process.communicate()
            if input_data is None
            else process.communicate(input=input_data)
        )
        if timeout is None:
            stdout, stderr = await communicate
        else:
            stdout, stderr = await asyncio.wait_for(communicate, timeout=timeout)
        return stdout, stderr
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass

        # Draining communicate() after kill closes stdout/stderr transports.
        # Waiting alone can leave BaseSubprocessTransport cleanup until __del__.
        try:
            await process.communicate()
        except Exception:
            if process.returncode is None:
                await process.wait()
        raise
    finally:
        if process.returncode is None:
            try:
                await process.wait()
            except Exception:
                pass
        await asyncio.sleep(0)


async def _wait_closed(conn: Any) -> None:
    """Drain asyncssh connection shutdown for deterministic fd cleanup."""
    await conn.wait_closed()


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
        self.ssl_verify = self.session_config.get(
            "ssl_verify", self.session_config.get("ssl", False)
        )
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
                ssl=self.ssl_verify,  # Configurable SSL verification
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
            if self.connection_info.get("auth_enabled", True) and username and password:
                self.auth = aiohttp.BasicAuth(username, password)
            else:
                self.auth = None

            # Test the session with a simple request
            protocol = "https" if self.connection_info["use_https"] else "http"
            test_url = f"{protocol}://{self.connection_info['host']}:{self.connection_info['port']}/redfish/v1"

            async with self.session.get(
                test_url, auth=self.auth, ssl=self.ssl_verify
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
        hmc_ip_candidates: Optional[List[str]] = None,
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
            hmc_ip_candidates: Ordered list of potential HMC IP/hostname values.
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
        self.execution_mode = _normalize_execution_mode(execution_mode)
        self.hmc_ip_candidates = list(hmc_ip_candidates) if hmc_ip_candidates else []
        self.hmc_ip_validated = False
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

    REDFISH_CACHE_MAX_ENTRIES = 500  # Max cached responses per DUT

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
        self.redfish_session_config: Dict[str, Any] = {}
        self.redfish_ssl = False
        self.redfish_session_timeout = 300
        self.redfish_keepalive_timeout = 300
        self.redfish_ttl_dns_cache = 300
        self.redfish_use_dns_cache = True
        self.redfish_force_close = False
        self.redfish_enable_cleanup_closed = True
        self.redfish_fallback_connection_pool_limit = 15
        self.redfish_fallback_connection_pool_limit_per_host = 6

        # Redfish caching
        self.__redfish_cache = {}

        # Redfish prefix configuration
        self.redfish_default_prefix = self.config.get(
            "RF_DEFAULT_PREFIX", "/redfish/v1"
        )
        # HMC-specific prefix for URIs containing HGX_* resource segments.
        # When set, response-body URIs (pagination, task links, etc.) that target
        # HMC resources are normalized with this prefix instead of redfish_default_prefix.
        self.redfish_hmc_default_prefix = (
            self.config.get("RF_HMC_DEFAULT_PREFIX") or None
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

        if self.config.get("dry_run"):
            await self._log_runtime(
                "INFO",
                "Dry-run mode - skipping Redfish session pool initialization",
            )
            return

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
        Create persistent Redfish session (like legacy nvdebug) - Now uses session pool.

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
            if connection_info.get("auth_enabled", True) and username and password:
                self.redfish_auth = aiohttp.BasicAuth(username, password)
            else:
                self.redfish_auth = None

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
                            test_url, auth=session_obj["auth"], ssl=self.redfish_ssl
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
                test_url, auth=self.redfish_auth, ssl=self.redfish_ssl
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
        Close Redfish session (like legacy nvdebug logout).

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
        Normalize Redfish URI with prefix handling (like legacy nvdebug).

        On arm64 / aggregation platforms where ``RF_HMC_DEFAULT_PREFIX`` differs
        from ``RF_DEFAULT_PREFIX``, URIs containing an ``/HGX_`` resource segment
        (returned in response bodies, pagination links, task status URIs, etc.) are
        rewritten with ``redfish_hmc_default_prefix`` instead of the BMC prefix.
        This ensures that follow-on requests derived from API responses are routed
        to the correct HMC Redfish root.

        Args:
            uri: URI to normalize.
            ignore_prefix: Whether to ignore the prefix.
        """
        if ignore_prefix:
            return uri

        # --- HMC URI: contains /HGX_ resource segment ---
        if self.redfish_hmc_default_prefix and "/HGX_" in uri:
            if not uri.startswith("/") and not uri.startswith("http"):
                # Raw relative URI (e.g. "Systems/HGX_Baseboard_0/...") — prepend HMC prefix
                uri = f"{self.redfish_hmc_default_prefix}/{uri}"
                asyncio.create_task(
                    self._log_runtime(
                        "DEBUG", f"Added HMC prefix to relative URI: {uri}"
                    )
                )
            elif (
                not uri.startswith(self.redfish_hmc_default_prefix)
                and "redfish/v1" in uri
            ):
                uri = re.sub(
                    r"(\S)*redfish/v1", self.redfish_hmc_default_prefix, uri, 1
                )
                asyncio.create_task(
                    self._log_runtime("DEBUG", f"Normalized HMC URI: {uri}")
                )
            return uri

        # --- BMC URI ---
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
            # Handle prefix substitution like legacy nvdebug
            # Substitute prefix up to /redfish/v1 with the configured prefix
            uri = re.sub(r"(\S)*redfish/v1", self.redfish_default_prefix, uri, 1)
            asyncio.create_task(self._log_runtime("DEBUG", f"Normalized URI: {uri}"))

        return uri

    def reset_redfish_cache(self) -> None:
        """
        Reset Redfish cache (like legacy nvdebug).

        Args:
            level: Log level.
            message: Log message.
        """
        self.__redfish_cache.clear()
        asyncio.create_task(self._log_runtime("INFO", "Redfish cache cleared"))

    def get_redfish_cache(self) -> Dict[str, Any]:
        """
        Get Redfish cache (like legacy nvdebug).

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
        # Evict oldest entry if cache is full
        if len(self.__redfish_cache) >= self.REDFISH_CACHE_MAX_ENTRIES:
            try:
                oldest_key = next(iter(self.__redfish_cache))
                del self.__redfish_cache[oldest_key]
            except (StopIteration, KeyError):
                pass
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

            use_hmc_path = self.is_hmc_platform
            if (
                not use_hmc_path
                and self.credentials.use_port_forwarding
                and self.credentials.hmc_ip
            ):
                use_hmc_path = await self._detect_hmc_platform()
                self.is_hmc_platform = use_hmc_path
                await self._log_runtime(
                    "DEBUG",
                    f"Early HMC preflight detection result: {use_hmc_path}",
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

            # Handle HMC mode with port forwarding (like legacy nvdebug)
            if use_hmc_path and self.credentials.hmc_ip:
                await self._log_runtime("DEBUG", "Using HMC port forwarding path")
                return await self._test_redfish_hmc_connection()
            else:
                await self._log_runtime(
                    "DEBUG",
                    f"Using standard BMC path (is_hmc_platform={use_hmc_path}, hmc_ip={self.credentials.hmc_ip})",
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
                            ssh_proxy_key_path=self.credentials.ssh_proxy_key_path,
                            ssh_proxy_passwordless=self.credentials.ssh_proxy_passwordless,
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
            use_auth = self.config.get("RF_AUTH", True) and bool(username and password)
            redfish_auth = aiohttp.BasicAuth(username, password) if use_auth else None

            # Use aiohttp with retry logic for reliability. BMC Redfish services
            # can pause for several seconds while collectors are active.
            timeout = aiohttp.ClientTimeout(
                total=REDFISH_PREFLIGHT_REQUEST_TIMEOUT,
                connect=REDFISH_PREFLIGHT_CONNECT_TIMEOUT,
                sock_read=REDFISH_PREFLIGHT_SOCK_READ_TIMEOUT,
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

            # Retry logic for transient failures
            max_retries = REDFISH_PREFLIGHT_MAX_RETRIES
            retry_delay = REDFISH_PREFLIGHT_RETRY_DELAY

            for attempt in range(max_retries + 1):
                connector = aiohttp.TCPConnector(
                    ssl=ssl_context,
                    limit=1,  # Single connection limit
                    limit_per_host=1,  # Single connection per host
                    ttl_dns_cache=300,  # DNS cache TTL
                    use_dns_cache=True,
                    force_close=True,  # Force close after use
                    enable_cleanup_closed=True,  # Clean up closed connections
                )
                try:
                    async with aiohttp.ClientSession(
                        timeout=timeout, connector=connector
                    ) as session:
                        async with session.get(
                            url,
                            auth=redfish_auth,
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

                                if validate_creds and use_auth:
                                    validation_uris = self._get_redfish_validation_uris(
                                        preflight_config
                                    )
                                    validation_failures = []

                                    for auth_uri in validation_uris:
                                        normalized_auth_uri = self.normalize_redfish_uri(
                                            auth_uri
                                        )

                                        await self._log_runtime(
                                            "DEBUG",
                                            f"Validating credentials against authenticated endpoint: {auth_uri} (normalized: {normalized_auth_uri})",
                                        )

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

                                        try:
                                            async with session.get(
                                                auth_url,
                                                auth=redfish_auth,
                                                headers={
                                                    "User-Agent": "nvdebug-preflight/1.0"
                                                },
                                            ) as auth_response:
                                                response_text = await auth_response.text()
                                                response_payload = None
                                                if response_text:
                                                    try:
                                                        response_payload = json.loads(
                                                            response_text
                                                        )
                                                    except json.JSONDecodeError:
                                                        response_payload = None

                                                if auth_response.status == 401:
                                                    await self._log_runtime(
                                                        "ERROR",
                                                        f"Redfish credential validation failed: HTTP 401 Unauthorized at {normalized_auth_uri}",
                                                    )
                                                    if connector:
                                                        await connector.close()
                                                    return (
                                                        False,
                                                        "Redfish credentials invalid: HTTP 401 Unauthorized. Please verify BMC_USERNAME/BMC_PASSWORD or RF_User/RF_Pass are correct.",
                                                    )

                                                if auth_response.status == 403:
                                                    validation_failures.append(
                                                        f"{normalized_auth_uri} -> HTTP 403 Forbidden"
                                                    )
                                                    await self._log_runtime(
                                                        "DEBUG",
                                                        f"Redfish credential validation probe returned HTTP 403 Forbidden at {normalized_auth_uri}",
                                                    )
                                                    continue

                                                if auth_response.status != 200:
                                                    validation_failures.append(
                                                        f"{normalized_auth_uri} -> HTTP {auth_response.status}"
                                                    )
                                                    await self._log_runtime(
                                                        "DEBUG",
                                                        f"Redfish credential validation probe failed at {normalized_auth_uri}: HTTP {auth_response.status}",
                                                    )
                                                    continue

                                                if not self._is_valid_redfish_validation_payload(
                                                    response_payload
                                                ):
                                                    validation_failures.append(
                                                        f"{normalized_auth_uri} -> HTTP 200 with non-resource/error payload"
                                                    )
                                                    await self._log_runtime(
                                                        "DEBUG",
                                                        f"Redfish credential validation probe at {normalized_auth_uri} returned HTTP 200 but not a valid Redfish resource payload",
                                                    )
                                                    continue

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
                                                # Detect DGX only from an explicit Redfish member ID.
                                                # Model-name heuristics are intentionally excluded here because
                                                # some HGX/GB200 platforms report DGX-like model strings without
                                                # exposing the DGX-specific Redfish endpoints.
                                                try:
                                                    systems_data = await auth_response.json(
                                                        content_type=None
                                                    )
                                                    members = systems_data.get("Members", [])
                                                    self.is_dgx = any(
                                                        m.get("@odata.id", "")
                                                        .rstrip("/")
                                                        .split("/")[-1]
                                                        == "DGX"
                                                        for m in members
                                                    )
                                                    if self.is_dgx:
                                                        await self._log_runtime(
                                                            "INFO",
                                                            "DGX platform detected via explicit /redfish/v1/Systems member 'DGX' — DGX-specific collectors will be activated",
                                                        )
                                                        self.is_dgx = any(
                                                            "DGX" in m.get("@odata.id", "")
                                                            for m in members
                                                            if isinstance(m, dict)
                                                        )
                                                        if self.is_dgx:
                                                            await self._log_runtime(
                                                                "INFO",
                                                                "DGX platform detected via /redfish/v1/Systems — DGX-specific collectors will be activated",
                                                            )
                                                        else:
                                                            await self._log_runtime(
                                                                "DEBUG",
                                                                "No DGX entry found in /redfish/v1/Systems — DGX status remains undetermined until additional heuristics run",
                                                            )
                                                except Exception as dgx_err:
                                                    await self._log_runtime(
                                                        "INFO",
                                                        "No explicit 'DGX' member found in /redfish/v1/Systems — DGX-specific collectors remain disabled",
                                                    )
                                                    self.is_dgx = False

                                                if connector:
                                                    await connector.close()
                                                return (
                                                    True,
                                                    "Redfish connection and credentials validated successfully",
                                                )
                                        except Exception as cred_error:
                                            validation_failures.append(
                                                f"{normalized_auth_uri} -> error: {str(cred_error)}"
                                            )
                                            await self._log_runtime(
                                                "DEBUG",
                                                f"Redfish credential validation probe error at {normalized_auth_uri}: {str(cred_error)}",
                                            )
                                            continue

                                    if connector:
                                        await connector.close()
                                    return (
                                        False,
                                        "Redfish credential validation failed for all candidate endpoints: "
                                        + "; ".join(validation_failures),
                                    )
                                else:
                                    # Credential validation disabled, just check service availability
                                    validation_reason = (
                                        "RF_AUTH disabled"
                                        if not use_auth
                                        else "credential validation disabled in preflight_config"
                                    )
                                    await self._log_runtime(
                                        "INFO",
                                        f"{validation_reason}; only checking Redfish service availability",
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
                        if connector:
                            await connector.close()
                        await asyncio.sleep(retry_delay)
                        continue
                    # Explicitly close connector before returning
                    if connector:
                        await connector.close()
                    return (
                        False,
                        f"Redfish connection timeout after retries ({REDFISH_PREFLIGHT_RETRY_BUDGET}s total)",
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
                        if connector:
                            await connector.close()
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
                        if connector:
                            await connector.close()
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
            return (
                False,
                f"Redfish connection timeout ({REDFISH_PREFLIGHT_WAIT_FOR_TIMEOUT}s)",
            )
        except Exception as e:
            # Explicitly close connector before returning
            if connector:
                await connector.close()
            return False, f"Redfish connection error: {str(e)}"

    def _get_redfish_validation_uris(
        self, preflight_config: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """Return unique Redfish credential-validation URIs in probe order."""
        preflight_config = preflight_config or {}

        candidates: List[str] = []

        configured_uri = preflight_config.get("credential_validation_uri")
        if configured_uri:
            configured_candidates = (
                configured_uri
                if isinstance(configured_uri, (list, tuple))
                else [configured_uri]
            )
            return [
                candidate
                for candidate in configured_candidates
                if candidate and str(candidate).strip()
            ]
        else:
            default_auth_uri = "/redfish/v1/Systems"
            if self.redfish_default_prefix != "/redfish/v1":
                default_auth_uri = "/redfish/v1"
            candidates.append(default_auth_uri)

        candidates.extend(
            ["/redfish/v1/Systems", "/redfish/v1/Chassis", "/redfish/v1/Managers"]
        )

        unique_candidates: List[str] = []
        for candidate in candidates:
            if candidate and candidate not in unique_candidates:
                unique_candidates.append(candidate)

        return unique_candidates

    @staticmethod
    def _is_valid_redfish_validation_payload(
        payload: Optional[Dict[str, Any]],
    ) -> bool:
        """Accept only real Redfish resources or collections for auth validation."""
        if not isinstance(payload, dict):
            return False
        if payload.get("error"):
            return False
        if payload.get("@odata.id"):
            return True
        if "Members" in payload:
            return True
        return False

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
            bmc_ssh_host = self.credentials.bmc_ip
            bmc_ssh_port = self.credentials.bmc_ssh_port

            if self.credentials.ssh_proxy_host:
                await self._log_runtime(
                    "INFO",
                    f"Using SSH proxy {self.credentials.ssh_proxy_host} for HMC Redfish port forwarding",
                )
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
                            ssh_proxy_key_path=self.credentials.ssh_proxy_key_path,
                            ssh_proxy_passwordless=self.credentials.ssh_proxy_passwordless,
                            ssh_proxy_port=self.credentials.ssh_proxy_port,
                            bmc_redfish_port=self.credentials.bmc_rf_port,
                            bmc_use_https=self.credentials.bmc_use_https,
                            bmc_ipmi_port=623,
                            host_ssh_port=self.credentials.host_ssh_port,
                            force_setup=True,
                        )
                    )

                    if not success:
                        return (
                            False,
                            f"Failed to setup SSH proxy tunneling for HMC Redfish: {message}",
                        )

                    self.ssh_proxy_service = ssh_proxy_service
                    self.ssh_proxy_tunnel_ports = tunnel_ports

                bmc_ssh_host = "localhost"
                bmc_ssh_port = self.ssh_proxy_tunnel_ports["bmc_ssh_port"]
                await self._log_runtime(
                    "INFO",
                    f"Using BMC SSH tunnel for HMC forwarding: {bmc_ssh_host}:{bmc_ssh_port}",
                )

            # Setup transparent HMC port forwarding
            success, bound_port, message = await hmc_service.setup_hmc_port_forwarding(
                dut_id=self.dut_id,
                bmc_ip=bmc_ssh_host,
                bmc_ssh_username=self.credentials.bmc_ssh_username,
                bmc_ssh_password=self.credentials.bmc_ssh_password,
                bmc_ssh_key_path=self.credentials.bmc_ssh_key_path,
                bmc_ssh_passwordless=self.credentials.bmc_ssh_passwordless,
                hmc_ip=self.credentials.hmc_ip,
                hmc_username=self.credentials.hmc_username,
                hmc_password=self.credentials.hmc_password,
                bmc_ssh_port=bmc_ssh_port,
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
                use_auth = self.config.get("RF_AUTH", True) and bool(
                    self.credentials.hmc_username and self.credentials.hmc_password
                )
                auth = (
                    aiohttp.BasicAuth(
                        self.credentials.hmc_username,
                        self.credentials.hmc_password,
                    )
                    if use_auth
                    else None
                )

                # Debug logging
                await self._log_runtime(
                    "DEBUG",
                    f"HMC Redfish test - URL: {url}, protocol: {protocol}, host: {connection_info['host']}, port: {connection_info['port']}",
                )

                timeout_config = aiohttp.ClientTimeout(total=10)

                async with aiohttp.ClientSession(timeout=timeout_config) as session:
                    async with session.get(
                        url,
                        auth=auth,
                        ssl=self.redfish_ssl,
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
                                "HMC Redfish connection successful via transparent forwarding",
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
            use_hmc_path = self.is_hmc_platform
            if (
                not use_hmc_path
                and self.credentials.use_port_forwarding
                and self.credentials.hmc_ip
            ):
                use_hmc_path = await self._detect_hmc_platform()
                self.is_hmc_platform = use_hmc_path
                await self._log_runtime(
                    "DEBUG",
                    f"Early HMC IPMI preflight detection result: {use_hmc_path}",
                )

            # Handle local mode
            if self.credentials.execution_mode == "local":
                await self._log_runtime(
                    "INFO",
                    "DUT is in local mode, skipping IPMI connection test",
                )
                self.connection_state.set_ipmi_connected(True, self.dut_id)
                self.connection_state.last_ipmi_check = datetime.now()
                return True, "Local mode - IPMI connection assumed successful"

            if use_hmc_path:
                await self._log_runtime(
                    "INFO",
                    "Using BMC-local IPMI preflight path for HMC platform",
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    self.dut_id,
                    "ipmitool mc info",
                    timeout=20,
                )
                if exit_code == 0:
                    self.connection_state.set_ipmi_connected(True, self.dut_id)
                    self.connection_state.last_ipmi_check = datetime.now()
                    return True, "IPMI connection successful via BMC-local ipmitool"

                error_msg = self._process_command_output(stderr) or self._process_command_output(stdout)
                return False, f"IPMI connection failed via BMC-local ipmitool: {error_msg}"

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
                            ssh_proxy_key_path=self.credentials.ssh_proxy_key_path,
                            ssh_proxy_passwordless=self.credentials.ssh_proxy_passwordless,
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
                "-U",
                self.credentials.bmc_username,
                "-P",
                self.credentials.bmc_password,
                self.credentials.ipmi_cipher,
                "mc",
                "info",
            ]

            if hasattr(self, "ssh_proxy_tunnel_ports") and self.ssh_proxy_tunnel_ports:
                cmd[3:3] = [
                    "-H",
                    "localhost",
                    "-p",
                    str(self.ssh_proxy_tunnel_ports["ipmi_port"]),
                ]
            else:
                cmd[3:3] = ["-H", self.credentials.bmc_ip]

            # Use asyncio.create_subprocess_exec for true async execution
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for completion with timeout (increased for async environment)
            try:
                stdout, stderr = await _communicate_subprocess(process, timeout=30)
            except asyncio.TimeoutError:
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
                            ssh_proxy_key_path=self.credentials.ssh_proxy_key_path,
                            ssh_proxy_passwordless=self.credentials.ssh_proxy_passwordless,
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

            # Check if local mode is set in config
            is_local_mode = self.config and self.config.get("local", False)

            if not self.credentials.host_ip:
                if is_local_mode:
                    # Local mode explicitly requested - allow execution without host IP
                    await self._log_runtime(
                        "INFO",
                        "Local mode enabled (--local flag), skipping host connection test",
                    )
                    self.connection_state.set_host_connected(True, self.dut_id)
                    self.connection_state.last_host_check = datetime.now()
                    return True, "Local host execution (--local flag)"
                else:
                    # No host IP and no local flag - this is a configuration error
                    return False, "No host IP configured and --local flag not set"

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
                            ssh_proxy_key_path=self.credentials.ssh_proxy_key_path,
                            ssh_proxy_passwordless=self.credentials.ssh_proxy_passwordless,
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
                "[HMC DEBUG] use_port_forwarding is False, returning False",
            )
            return False

        # Check if baseboard supports HMC
        if not self.config.get("supports_hmc", False):
            await self._log_runtime(
                "DEBUG",
                "[HMC DEBUG] Baseboard does not support HMC, returning False",
            )
            return False

        # If we get here, USE_PORT_FORWARDING is True and baseboard supports HMC
        await self._log_runtime(
            "DEBUG",
            "[HMC DEBUG] use_port_forwarding is True and baseboard supports HMC, returning True",
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
            hmc_ip_value = platform_detection.get("hmc_ip")
            if isinstance(hmc_ip_value, list):
                hmc_ip_candidates = [
                    str(value).strip()
                    for value in hmc_ip_value
                    if isinstance(value, str) and value.strip()
                ]
                if hmc_ip_candidates:
                    self.credentials.hmc_ip = hmc_ip_candidates[0]
                    if not self.credentials.hmc_ip_candidates:
                        self.credentials.hmc_ip_candidates = hmc_ip_candidates
            elif hmc_ip_value:
                self.credentials.hmc_ip = hmc_ip_value
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

        # Disable RF auth for HMC (like legacy nvdebug)
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
        # Check if HMC mode is active (like legacy nvdebug)
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
                "auth_enabled": self.config.get("RF_AUTH", True),
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
                    "use_https": self.credentials.bmc_use_https,
                    "username": self.credentials.rf_username
                    or self.credentials.bmc_username,
                    "password": self.credentials.rf_password
                    or self.credentials.bmc_password,
                    "auth_enabled": self.config.get("RF_AUTH", True),
                    "is_hmc_forwarded": False,
                    "is_ssh_proxy_tunneled": True,
                }
            else:
                # Return direct BMC connection info
                return {
                    "host": self.credentials.bmc_ip,
                    "port": self.credentials.bmc_rf_port,
                    "use_https": self.credentials.bmc_use_https,
                    "username": self.credentials.rf_username
                    or self.credentials.bmc_username,
                    "password": self.credentials.rf_password
                    or self.credentials.bmc_password,
                    "auth_enabled": self.config.get("RF_AUTH", True),
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
            # Use ping with 2 packets and 5 second timeout (like legacy tool)
            network_type = str(self.config.get("IP_NETWORK", "ipv4")).lower()
            network_arg = "-6" if network_type == "ipv6" else "-4"
            ping_cmd = ["ping", network_arg, "-c", "2", "-W", "5", ip_address]

            # Use asyncio.create_subprocess_exec for true async execution
            # Note: asyncio.create_subprocess_exec doesn't support text=True
            process = await asyncio.create_subprocess_exec(
                *ping_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = await _communicate_subprocess(process, timeout=10)
            except asyncio.TimeoutError:
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
                except Exception:
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
        logger: Optional[AsyncSafeLogger] = None,
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
            logger: Shared async logger. Reusing the orchestrator logger keeps
                per-DUT runtime log writes serialized through one file handle.
        """
        self.dut_configs = dut_configs
        self.base_log_dir = Path(base_log_dir)
        self.duts: Dict[str, DUT] = {}
        self.logger = logger or AsyncSafeLogger(
            str(self.base_log_dir), debug_mode=debug_mode
        )
        self.uri_config_manager = uri_config_manager
        self.tool_config = tool_config or {}

        # Spreadsheet configuration
        self.spreadsheet_path = spreadsheet_path

        # Console for consistent output styling
        self.sanitized_console = sanitized_console

        # SSH implementation configuration with defaults
        self.ssh_config = ssh_config or {}

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
        self.redfish_ssl = self.redfish_session_config.get(
            "ssl_verify", self.redfish_session_config.get("ssl", False)
        )
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
        # Warn about stale fallback config (paramiko removed)
        if self.ssh_config.get("fallback"):
            import warnings
            warnings.warn(
                "ssh_implementation.fallback config is deprecated — paramiko has been removed. "
                "asyncssh is the sole SSH backend. Remove the fallback section from your config.",
                DeprecationWarning,
                stacklevel=2,
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

                connect_kwargs = self._build_ssh_connect_kwargs(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    ssh_key_path=ssh_key_path,
                    passwordless=passwordless,
                    connect_timeout=30,
                    keepalive_interval=None,
                )

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

    @staticmethod
    def _has_ssh_auth_method(
        password: Optional[str],
        ssh_key_path: Optional[str],
        passwordless: bool,
    ) -> bool:
        """Return True when any supported SSH auth method is configured."""
        return bool(ssh_key_path or passwordless or password)

    @staticmethod
    def _build_ssh_connect_kwargs(
        host: str,
        port: int,
        username: Optional[str],
        password: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
        passwordless: bool = False,
        connect_timeout: int = 30,
        keepalive_interval: Optional[int] = None,
        proxy_client: Optional[asyncssh.SSHClientConnection] = None,
    ) -> Dict[str, Any]:
        """
        Build asyncssh connection kwargs using the tool's auth precedence.

        Explicit key-path authentication wins over password auth so users do not
        need to provide SSH passwords when a key is configured. If no key is
        configured, existing password and Redfish-to-SSH fallback behavior stays
        intact.
        """
        if not host:
            raise ValueError("SSH host not configured")
        if not username:
            raise ValueError("SSH username not configured")
        if not DUTManager._has_ssh_auth_method(password, ssh_key_path, passwordless):
            raise ValueError("SSH password, key path, or passwordless auth required")

        connect_kwargs: Dict[str, Any] = {
            "host": host,
            "port": port,
            "username": username,
            "connect_timeout": connect_timeout,
            "keepalive_interval": keepalive_interval,
            "known_hosts": None,
        }

        if proxy_client:
            connect_kwargs["tunnel"] = proxy_client

        if ssh_key_path:
            connect_kwargs["client_keys"] = [ssh_key_path]
            if password:
                connect_kwargs["passphrase"] = password
        elif not passwordless:
            connect_kwargs["password"] = password

        return connect_kwargs

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
            "DUTManager: SSH backend: asyncssh",
        )
        if isinstance(self.dut_configs, dict):
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"DUTManager: dut_configs keys: {list(self.dut_configs.keys())}",
            )

        # Create DUT objects from configuration
        await self._create_duts()

    async def _apply_and_log_prefix_override(
        self, dut_id: str, config: Dict[str, Any]
    ) -> None:
        """
        Apply prefix_override / hmc_prefix_override to RF_DEFAULT_PREFIX /
        RF_HMC_DEFAULT_PREFIX and keep URIConfigManager in sync.

        Priority rules:
        - BMC prefix: tool-level ``prefix_override`` applies when DUT still has
          the default ``/redfish/v1``; a custom DUT-level value takes precedence.
        - HMC prefix: tool-level ``hmc_prefix_override`` applies when DUT has no
          ``RF_HMC_DEFAULT_PREFIX``; a DUT-level value always takes precedence.

        Args:
            dut_id: The DUT identifier
            config: The DUT configuration dictionary (modified in place)
        """
        uri_overrides = self.tool_config.get("uri_overrides") or {}

        # ── BMC prefix ──────────────────────────────────────────────────────────
        prefix_override = uri_overrides.get("prefix_override")
        current_rf_prefix = config.get("RF_DEFAULT_PREFIX", "/redfish/v1")

        if prefix_override and current_rf_prefix == "/redfish/v1":
            config["RF_DEFAULT_PREFIX"] = prefix_override
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"DUT {dut_id}: Applied tool-level prefix_override '{prefix_override}' to RF_DEFAULT_PREFIX (was using default '/redfish/v1')",
            )
        elif prefix_override and current_rf_prefix != "/redfish/v1":
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"DUT {dut_id}: Using custom RF_DEFAULT_PREFIX '{current_rf_prefix}' (overrides tool-level prefix_override '{prefix_override}')",
            )

        # Always update URIConfigManager with the final RF_DEFAULT_PREFIX value
        final_rf_prefix = config.get("RF_DEFAULT_PREFIX", "/redfish/v1")
        if self.uri_config_manager:
            self.uri_config_manager.update_dut_rf_prefix(dut_id, final_rf_prefix)

        # ── HMC prefix ──────────────────────────────────────────────────────────
        hmc_prefix_override = uri_overrides.get("hmc_prefix_override")
        current_hmc_prefix = config.get("RF_HMC_DEFAULT_PREFIX")

        if hmc_prefix_override and not current_hmc_prefix:
            # Tool-level hmc_prefix_override applies when DUT has no explicit value
            config["RF_HMC_DEFAULT_PREFIX"] = hmc_prefix_override
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"DUT {dut_id}: Applied tool-level hmc_prefix_override '{hmc_prefix_override}' to RF_HMC_DEFAULT_PREFIX",
            )
        elif hmc_prefix_override and current_hmc_prefix:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"DUT {dut_id}: Using custom RF_HMC_DEFAULT_PREFIX '{current_hmc_prefix}' (overrides tool-level hmc_prefix_override '{hmc_prefix_override}')",
            )

        # Update URIConfigManager with the final RF_HMC_DEFAULT_PREFIX value
        final_hmc_prefix = config.get("RF_HMC_DEFAULT_PREFIX")
        if self.uri_config_manager and final_hmc_prefix:
            self.uri_config_manager.update_dut_hmc_prefix(dut_id, final_hmc_prefix)

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
            explicit_keys = _explicit_key_map(dut_config)
            defaults_config = _strip_internal_config_keys(defaults)
            effective_dut_config = _drop_implicit_tool_like_defaults(
                dut_config, explicit_keys
            )

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
                f"DUT {dut_id}: dut_config keys: {set(effective_dut_config.keys())}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: defaults keys: {set(defaults_config.keys())}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: explicit_keys: {explicit_keys}",
            )
            # tool_config < DUT_Defaults < explicit per-DUT values. Implicit
            # DUTConfig model defaults are removed above so they cannot clobber
            # tool_config.yaml values.
            config = {**self.tool_config, **defaults_config, **effective_dut_config}

            # Apply prefix_override to RF_DEFAULT_PREFIX and update URIConfigManager
            await self._apply_and_log_prefix_override(dut_id, config)

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

            explicit_keys = _explicit_key_map(dut_config)
            for key in dut_specific_config.keys():
                explicit_keys[key] = True

            defaults_config = _strip_internal_config_keys(defaults)
            dut_config_with_overrides = {
                **dut_specific_config,
                **_strip_internal_config_keys(dut_config),
            }
            effective_dut_config = _drop_implicit_tool_like_defaults(
                dut_config_with_overrides, explicit_keys
            )

            # tool_config < DUT_Defaults < ConfigFileToUse < DUT YAML. The
            # Pydantic default-only values are stripped before this merge.
            config = {**self.tool_config, **defaults_config, **effective_dut_config}

            # Apply prefix_override to RF_DEFAULT_PREFIX and update URIConfigManager
            await self._apply_and_log_prefix_override(dut_id, config)

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
        explicit_keys: Optional[Dict[str, bool]] = None,
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

                # Save i2c_config before baseboard merge overwrites it.
                # At this point config already has the correct precedence:
                # global tool_config < defaults < per-DUT ConfigFileToUse < DUT YAML
                pre_merge_i2c_config = config.get("i2c_config", {})

                # Merge baseboard config into DUT config (defaults only)
                config = {**config, **baseboard_config}

                # Special handling for i2c_config - deep merge with proper precedence:
                # baseboard (lowest) < tool_config / per-DUT config (higher)
                if pre_merge_i2c_config:
                    baseboard_i2c_config = baseboard_config.get("i2c_config", {})
                    merged_i2c_config = {**baseboard_i2c_config, **pre_merge_i2c_config}
                    config["i2c_config"] = merged_i2c_config
                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        f"Applied i2c_config overrides for DUT {dut_id}: {list(pre_merge_i2c_config.keys())}",
                    )

                platform_detection = config.get("platform_detection", {})

                hmc_ip_candidates: List[str] = []
                if isinstance(platform_detection, dict):
                    raw_hmc_ip = platform_detection.get("hmc_ip")
                    candidate_values: List[Any] = []

                    if isinstance(raw_hmc_ip, list):
                        candidate_values.extend(raw_hmc_ip)
                    else:
                        candidate_values.append(raw_hmc_ip)

                    existing_candidate_list = platform_detection.get(
                        "hmc_ip_candidates"
                    )
                    if isinstance(existing_candidate_list, list):
                        candidate_values.extend(existing_candidate_list)

                    for candidate in candidate_values:
                        if isinstance(candidate, str):
                            value = candidate.strip()
                            if value and value not in hmc_ip_candidates:
                                hmc_ip_candidates.append(value)

                    if hmc_ip_candidates:
                        platform_detection["hmc_ip_candidates"] = hmc_ip_candidates
                        platform_detection["hmc_ip"] = hmc_ip_candidates[0]
                        combined_candidates: List[str] = []
                        existing_config_candidates = config.get("HMC_IP_CANDIDATES", [])
                        if isinstance(existing_config_candidates, list):
                            for candidate in existing_config_candidates:
                                if (
                                    isinstance(candidate, str)
                                    and candidate
                                    and candidate not in combined_candidates
                                ):
                                    combined_candidates.append(candidate.strip())

                        for candidate in hmc_ip_candidates:
                            if candidate not in combined_candidates:
                                combined_candidates.append(candidate)

                        if combined_candidates:
                            config["HMC_IP_CANDIDATES"] = combined_candidates

                # Extract HMC_IP from platform_detection if not already at top level
                if not original_hmc_ip and hmc_ip_candidates:
                    config["HMC_IP"] = hmc_ip_candidates[0]
                    config["hmc_ip"] = hmc_ip_candidates[0]
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Extracted HMC_IP from baseboard platform_detection: {hmc_ip_candidates[0]}",
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

        bmc_username = config.get("BMC_USERNAME") or config.get("bmc_user") or ""
        bmc_password = config.get("BMC_PASSWORD") or config.get("bmc_pass") or ""
        # Redfish user/pass: if not provided, use BMC user/pass
        rf_username = config.get("RF_User") or config.get("bmc_rf_user")
        rf_password = config.get("RF_Pass") or config.get("bmc_rf_pass")
        if not rf_username and bmc_username:
            rf_username = bmc_username
        if not rf_password and bmc_password:
            rf_password = bmc_password
        # BMC SSH user/pass: if not provided, use BMC user/pass
        bmc_ssh_username = config.get("BMC_SSH_USERNAME") or config.get("bmc_ssh_user")
        bmc_ssh_password = config.get("BMC_SSH_PASSWORD") or config.get("bmc_ssh_pass")
        if not bmc_ssh_username and bmc_username:
            bmc_ssh_username = bmc_username
        if not bmc_ssh_password and bmc_password:
            bmc_ssh_password = bmc_password

        bmc_use_https = config.get("BMC_USE_HTTPS")
        if bmc_use_https is None:
            bmc_use_https = config.get("bmc_use_https", True)

        hmc_use_https = config.get("HMC_USE_HTTPS")
        if hmc_use_https is None:
            hmc_use_https = config.get("hmc_use_https", True)

        execution_mode = _resolve_execution_mode(config)
        config["ExecutionMode"] = execution_mode
        config["execution_mode"] = execution_mode
        if execution_mode == "local":
            config["local"] = True

        credentials = DUTCredentials(
            bmc_ip=config.get("BMC_IP") or config.get("bmc_ip") or "",
            bmc_username=bmc_username,
            bmc_password=bmc_password,
            bmc_ssh_username=bmc_ssh_username,
            bmc_ssh_password=bmc_ssh_password,
            bmc_ssh_port=config.get("BMC_SSH_PORT") or config.get("bmc_ssh_port") or 22,
            bmc_ssh_key_path=config.get("BMC_SSH_KEY_PATH")
            or config.get("bmc_ssh_key_path"),
            bmc_ssh_passwordless=config.get(
                "BMC_SSH_PASSWORDLESS", config.get("bmc_ssh_passwordless", False)
            ),
            bmc_ssh_max_retries=config.get(
                "BMC_SSH_MAX_RETRIES", config.get("bmc_ssh_max_retries", 3)
            ),
            bmc_rf_port=config.get("BMC_RF_PORT") or config.get("bmc_rf_port") or 443,
            bmc_use_https=bmc_use_https,
            bmc_rf_verify_ssl=config.get("bmc_rf_verify_ssl", False),
            host_ip=config.get("HOST_IP") or config.get("host_ip"),
            host_username=config.get("HOST_USERNAME") or config.get("host_user"),
            host_password=config.get("HOST_PASSWORD") or config.get("host_pass"),
            host_ssh_port=config.get("HOST_SSH_PORT")
            or config.get("host_ssh_port")
            or 22,
            host_ssh_key_path=config.get("HOST_SSH_KEY_PATH")
            or config.get("host_ssh_key_path"),
            host_ssh_passwordless=config.get(
                "HOST_SSH_PASSWORDLESS", config.get("host_ssh_passwordless", False)
            ),
            host_ssh_max_retries=config.get(
                "HOST_SSH_MAX_RETRIES", config.get("host_ssh_max_retries", 3)
            ),
            rf_username=rf_username,
            rf_password=rf_password,
            tunnel_tcp_port=config.get("TUNNEL_TCP_PORT")
            or config.get("tunnel_tcp_port"),
            ipmi_cipher=config.get("ipmi_cipher", "-C17"),
            # HMC Configuration
            hmc_ip=explicit_hmc_ip or config.get("HMC_IP"),
            hmc_username=config.get("HMC_USERNAME") or config.get("hmc_user"),
            hmc_password=config.get("HMC_PASSWORD") or config.get("hmc_pass"),
            hmc_ssh_username=config.get("HMC_SSH_USERNAME")
            or config.get("hmc_ssh_user"),
            hmc_ssh_password=config.get("HMC_SSH_PASSWORD")
            or config.get("hmc_ssh_pass"),
            hmc_ssh_port=config.get("HMC_SSH_PORT") or config.get("hmc_ssh_port") or 22,
            hmc_ssh_key_path=config.get("HMC_SSH_KEY_PATH")
            or config.get("hmc_ssh_key_path"),
            hmc_ssh_passwordless=config.get(
                "HMC_SSH_PASSWORDLESS", config.get("hmc_ssh_passwordless", False)
            ),
            hmc_ssh_max_retries=config.get(
                "HMC_SSH_MAX_RETRIES", config.get("hmc_ssh_max_retries", 3)
            ),
            hmc_http_port=config.get("HMC_HTTP_PORT", 80),
            hmc_https_port=config.get("HMC_HTTPS_PORT", 443),
            hmc_use_https=hmc_use_https,
            use_port_forwarding=config.get("USE_PORT_FORWARDING", False),
            rf_hmc_access_method=config.get("RF_HMC_ACCESS_METHOD"),
            execution_mode=execution_mode,
            hmc_ip_candidates=config.get("HMC_IP_CANDIDATES"),
            # SSH Proxy Configuration
            ssh_proxy_host=config.get("SSH_PROXY_HOST")
            or config.get("ssh_proxy_host"),
            ssh_proxy_port=config.get(
                "SSH_PROXY_PORT", config.get("ssh_proxy_port", 22)
            ),
            ssh_proxy_username=config.get(
                "SSH_PROXY_USERNAME", config.get("ssh_proxy_user")
            ),  # Map ssh_proxy_user to ssh_proxy_username
            ssh_proxy_password=config.get(
                "SSH_PROXY_PASSWORD", config.get("ssh_proxy_pass")
            ),  # Map ssh_proxy_pass to ssh_proxy_password
            ssh_proxy_key_path=config.get("SSH_PROXY_KEY_PATH")
            or config.get("ssh_proxy_key_path"),
            ssh_proxy_passwordless=config.get(
                "SSH_PROXY_PASSWORDLESS", config.get("ssh_proxy_passwordless", False)
            ),
            ssh_proxy_max_retries=config.get(
                "SSH_PROXY_MAX_RETRIES", config.get("ssh_proxy_max_retries", 3)
            ),
        )

        dut = DUT(dut_id, credentials, config, self)
        dut.redfish_ssl = self.redfish_ssl
        dut.redfish_session_config = self.redfish_session_config
        dut.redfish_session_timeout = self.redfish_session_timeout
        dut.redfish_keepalive_timeout = self.redfish_keepalive_timeout
        dut.redfish_ttl_dns_cache = self.redfish_ttl_dns_cache
        dut.redfish_use_dns_cache = self.redfish_use_dns_cache
        dut.redfish_force_close = self.redfish_force_close
        dut.redfish_enable_cleanup_closed = self.redfish_enable_cleanup_closed
        dut.redfish_fallback_connection_pool_limit = (
            self.redfish_fallback_connection_pool_limit
        )
        dut.redfish_fallback_connection_pool_limit_per_host = (
            self.redfish_fallback_connection_pool_limit_per_host
        )
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
        except RuntimeError:
            # No event loop, safe to use asyncio.run()
            try:
                asyncio.run(self.cleanup_all_ssh_proxy_tunnels())
            except Exception:
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
        collector_definitions: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run preflight checks on all DUTs in parallel with comprehensive logging and progress bar

        Args:
            required_collector_groups: List of collector groups that will be executed.
                                     If None, runs all preflight checks.
                                     Valid groups: ["redfish", "ipmi", "ssh", "host"]
            collector_definitions: Full collector catalog with applicable baseboards.
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

        # Build collector group mapping once for baseboard-aware preflight skipping
        collectors_by_group = self._build_collectors_by_group_map(collector_definitions)

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
                        dut_id,
                        dut,
                        progress,
                        main_task,
                        services_to_check,
                        collectors_by_group,
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
                    dut_id, dut, services_to_check, collectors_by_group
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
            "Preflight checks completed for all DUTs in parallel",
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

    def _build_collectors_by_group_map(
        self, collector_definitions: Optional[Dict[str, Any]]
    ) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
        """
        Build a mapping of collector group -> collector definitions for quick lookups.

        Args:
            collector_definitions: Collector catalog data structure.

        Returns:
            Dictionary keyed by lowercase group name with list of (collector_id, definition).
        """
        group_map: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
        if not collector_definitions:
            return group_map

        collectors = collector_definitions.get("collectors", {})
        if not isinstance(collectors, dict):
            return group_map

        for collector_id, collector in collectors.items():
            if not isinstance(collector, dict):
                continue
            group = collector.get("group")
            if not group:
                continue
            group_key = str(group).strip().lower()
            if not group_key:
                continue
            group_map.setdefault(group_key, []).append((str(collector_id), collector))

        return group_map

    def _normalize_applicable_baseboards(
        self, applicable: Optional[Union[str, List[Any], Dict[str, Any]]]
    ) -> List[str]:
        """
        Normalize applicable_baseboards values into a flat list of strings.
        """
        normalized: List[str] = []

        def _flatten(value):
            if value is None:
                return
            if isinstance(value, str):
                trimmed = value.strip()
                if trimmed:
                    normalized.append(trimmed)
                return
            if isinstance(value, list):
                for item in value:
                    _flatten(item)
                return
            if isinstance(value, dict):
                for key, flag in value.items():
                    include = True
                    if isinstance(flag, bool):
                        include = flag
                    elif isinstance(flag, str):
                        include = flag.strip().lower() not in (
                            "false",
                            "0",
                            "no",
                            "off",
                        )
                    elif isinstance(flag, (int, float)):
                        include = bool(flag)
                    if include:
                        normalized.append(str(key).strip())
                return
            normalized.append(str(value).strip())

        _flatten(applicable)
        return [spec for spec in normalized if spec]

    def _collector_matches_baseboard(
        self,
        collector_def: Dict[str, Any],
        baseboard_name: str,
        baseboard_type: Optional[str],
        baseboard_manager: Optional[BaseboardManager],
        node_type: Optional[str] = None,
    ) -> bool:
        """
        Determine if collector applies to given baseboard name/type.
        """
        applicable_specs = self._normalize_applicable_baseboards(
            collector_def.get("applicable_baseboards")
        )
        exclude_specs = self._normalize_applicable_baseboards(
            collector_def.get("exclude_baseboards")
        )

        # If no specification, assume collector applies broadly.
        if not applicable_specs:
            applicable_specs = ["all"]

        baseboard_type_lower = baseboard_type.lower() if baseboard_type else None
        node_type_lower = node_type.lower() if node_type else None
        effective_baseboard_names = [baseboard_name]
        effective_baseboard_names_lower = [
            member.lower() for member in effective_baseboard_names
        ]

        def spec_matches(spec: str) -> bool:
            spec_lower = spec.lower()
            if spec_lower in {"all", "*"}:
                return True
            if spec_lower in effective_baseboard_names_lower:
                return True
            if baseboard_type_lower and baseboard_type_lower == spec_lower:
                return True
            if node_type_lower and node_type_lower == spec_lower:
                return True
            if baseboard_manager:
                group_members = baseboard_manager.get_baseboards_in_group(spec)
                if group_members:
                    members_lower = [member.lower() for member in group_members]
                    if any(
                        effective_name in members_lower
                        for effective_name in effective_baseboard_names_lower
                    ):
                        return True
            return False

        if any(spec_matches(spec) for spec in exclude_specs):
            return False

        return any(spec_matches(spec) for spec in applicable_specs)

    def _should_run_service_for_dut(
        self,
        dut: "DUT",
        service_name: str,
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Tuple[bool, str]:
        """
        Check if a preflight service should run for a DUT based on applicable baseboards.

        Returns:
            Tuple of (should_run, reason_message).
        """
        if not collectors_by_group:
            return True, "Collector definitions unavailable"

        service_collectors = collectors_by_group.get(service_name.lower(), [])
        if not service_collectors:
            return True, f"No {service_name} collectors defined"

        baseboard_name = None
        node_type = None
        if dut and getattr(dut, "config", None):
            baseboard_name = dut.config.get("baseboard") or dut.config.get(
                "TargetBaseboard"
            )
            node_type = dut.config.get("NodeType") or dut.config.get("node_type")

        if not baseboard_name:
            return True, "Baseboard not specified; running preflight by default"

        baseboard_name = str(baseboard_name).strip()
        if not baseboard_name or baseboard_name.lower() == "unknown":
            return True, "Baseboard not specified; running preflight by default"

        baseboard_manager = self._get_baseboard_manager()
        baseboard_type = (
            baseboard_manager.get_baseboard_type(baseboard_name)
            if baseboard_manager
            else None
        )

        for collector_id, collector_def in service_collectors:
            if self._collector_matches_baseboard(
                collector_def,
                baseboard_name,
                baseboard_type,
                baseboard_manager,
                node_type=node_type,
            ):
                return (
                    True,
                    f"Collector {collector_id} targets baseboard {baseboard_name}",
                )

        if baseboard_type:
            return (
                False,
                f"No applicable {service_name} collectors for baseboard '{baseboard_name}' ({baseboard_type})",
            )
        else:
            return (
                False,
                f"No applicable {service_name} collectors for baseboard '{baseboard_name}'",
            )

    async def _run_dut_preflight_parallel(
        self,
        dut_id: str,
        dut: "DUT",
        progress,
        main_task,
        services_to_check: List[str],
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Dict[str, Any]:
        """
        Run preflight checks for a single DUT with all services in parallel.

        Args:
            dut_id: DUT ID.
            dut: DUT instance.
            progress: Progress bar instance.
            main_task: Main task ID for progress tracking.
            services_to_check: List of services to check.
            collectors_by_group: Mapping of collector group -> collectors with metadata.

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
            (
                "redfish",
                lambda d: self._fast_redfish_check(d, collectors_by_group),
                dut,
            ),
            ("ipmi", lambda d: self._fast_ipmi_check(d, collectors_by_group), dut),
            ("ssh", lambda d: self._fast_ssh_check(d, collectors_by_group), dut),
            ("host", lambda d: self._fast_host_check(d, collectors_by_group), dut),
        ]

        # Filter services based on what's needed
        services = [
            service for service in all_services if service[0] in services_to_check
        ]

        # Run services sequentially to avoid resource contention
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

            should_run, skip_reason = self._should_run_service_for_dut(
                dut, service_name, collectors_by_group
            )
            if not should_run:
                progress.update(
                    main_task,
                    description=f"[cyan]Preflight: {service_name}[/cyan] on [yellow]{dut_id}[/yellow] - skipped",
                )
                progress.advance(main_task)
                dut_result["services"][service_name] = {
                    "status": "skip",
                    "message": skip_reason,
                }
                await self.logger.log_runtime(
                    "INFO",
                    f"DUT:{dut_id}",
                    f"Skipping {service_name} preflight: {skip_reason}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "PreflightChecks",
                    f"Skipping {service_name} preflight: {skip_reason}",
                )
                continue

            try:
                success, message = await self._run_service_preflight_parallel(
                    service_name, test_func, dut_obj, dut_id, progress, main_task
                )
            except Exception as exc:
                dut_result["services"][service_name] = {
                    "status": "fail",
                    "message": f"Exception during {service_name} test: {str(exc)}",
                }
                dut_result["overall_status"] = "fail"
                await self.logger.log_runtime(
                    "ERROR",
                    f"DUT:{dut_id}",
                    f"{service_name} service exception: {str(exc)}",
                )
                continue

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
        self,
        dut_id: str,
        dut: "DUT",
        services_to_check: List[str],
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Dict[str, Any]:
        """
        Run preflight checks for a single DUT without progress bar.

        Args:
            dut_id: DUT ID.
            dut: DUT instance.
            services_to_check: List of services to check.
            collectors_by_group: Mapping of collector group -> collectors with metadata.
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
            (
                "redfish",
                lambda d: self._fast_redfish_check(d, collectors_by_group),
                dut,
            ),
            ("ipmi", lambda d: self._fast_ipmi_check(d, collectors_by_group), dut),
            ("ssh", lambda d: self._fast_ssh_check(d, collectors_by_group), dut),
            ("host", lambda d: self._fast_host_check(d, collectors_by_group), dut),
        ]

        # Filter services based on what's needed
        services = [
            service for service in all_services if service[0] in services_to_check
        ]

        # Run services sequentially to avoid resource contention
        for service_name, test_func, dut_obj in services:
            should_run, skip_reason = self._should_run_service_for_dut(
                dut, service_name, collectors_by_group
            )
            if not should_run:
                dut_result["services"][service_name] = {
                    "status": "skip",
                    "message": skip_reason,
                }
                await self.logger.log_runtime(
                    "INFO",
                    f"DUT:{dut_id}",
                    f"Skipping {service_name} preflight: {skip_reason}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "PreflightChecks",
                    f"Skipping {service_name} preflight: {skip_reason}",
                )
                continue

            try:
                success, message = await self._run_service_preflight_no_progress(
                    service_name, test_func, dut_obj, dut_id
                )
            except Exception as exc:
                dut_result["services"][service_name] = {
                    "status": "fail",
                    "message": f"Exception during {service_name} test: {str(exc)}",
                }
                dut_result["overall_status"] = "fail"
                await self.logger.log_runtime(
                    "ERROR",
                    f"DUT:{dut_id}",
                    f"{service_name} service exception: {str(exc)}",
                )
                continue

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

    def _check_service_collector_applicability(
        self,
        dut: "DUT",
        service_name: str,
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Tuple[bool, str]:
        """
        Check if any collectors for a given service are applicable to the DUT's baseboard.

        Args:
            dut: DUT instance.
            service_name: Service name (e.g., "ipmi", "redfish", "ssh", "host").
            collectors_by_group: Mapping of collector group -> collectors with metadata.

        Returns:
            Tuple of (should_skip, message). If should_skip is True, the preflight should be skipped.
        """
        if not collectors_by_group:
            return False, ""

        service_collectors = collectors_by_group.get(service_name.lower(), [])
        if not service_collectors:
            return False, ""

        # Get baseboard information
        baseboard_name = None
        node_type = None
        if dut and getattr(dut, "config", None):
            baseboard_name = dut.config.get("baseboard") or dut.config.get(
                "TargetBaseboard"
            )
            node_type = dut.config.get("NodeType") or dut.config.get("node_type")

        if not baseboard_name:
            return False, ""

        baseboard_name = str(baseboard_name).strip()
        if not baseboard_name or baseboard_name.lower() == "unknown":
            return False, ""

        # Check if any collector is applicable for this baseboard
        baseboard_manager = self._get_baseboard_manager()
        baseboard_type = (
            baseboard_manager.get_baseboard_type(baseboard_name)
            if baseboard_manager
            else None
        )

        # Count applicable collectors
        applicable_count = 0
        for collector_id, collector_def in service_collectors:
            if self._collector_matches_baseboard(
                collector_def,
                baseboard_name,
                baseboard_type,
                baseboard_manager,
                node_type=node_type,
            ):
                applicable_count += 1

        # If no collectors are applicable, return skip signal
        if applicable_count == 0:
            if baseboard_type:
                return (
                    True,
                    f"No applicable {service_name.upper()} collectors for baseboard '{baseboard_name}' ({baseboard_type})",
                )
            else:
                return (
                    True,
                    f"No applicable {service_name.upper()} collectors for baseboard '{baseboard_name}'",
                )

        return False, ""

    async def _fast_redfish_check(
        self,
        dut: "DUT",
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Tuple[bool, str]:
        """
        Fast Redfish check using ping first, then actual interface test.

        Args:
            dut: DUT instance.
            collectors_by_group: Mapping of collector group -> collectors with metadata.

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
            timeout = REDFISH_PREFLIGHT_WAIT_FOR_TIMEOUT
            if dut.credentials.ssh_proxy_host or dut.credentials.use_port_forwarding:
                timeout = max(timeout, 60.0)
            success, response = await asyncio.wait_for(
                dut.test_redfish_connection(), timeout=timeout
            )
            if success:
                return True, "Redfish interface accessible"
            else:
                return False, f"Redfish interface failed: {response}"
        except asyncio.TimeoutError:
            # Check if any Redfish collectors are applicable for this DUT's baseboard
            should_skip, skip_message = self._check_service_collector_applicability(
                dut, "redfish", collectors_by_group
            )
            if should_skip:
                return False, skip_message

            timeout_msg = f"Redfish interface timeout ({timeout}s)"
            return False, timeout_msg
        except Exception as e:
            return False, f"Redfish interface error: {str(e)}"

    async def _fast_ipmi_check(
        self,
        dut: "DUT",
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Tuple[bool, str]:
        """
        Fast IPMI check using ping first, then actual interface test.

        Args:
            dut: DUT instance.
            collectors_by_group: Mapping of collector group -> collectors with metadata.

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
            timeout = (
                30.0
                if dut.credentials.ssh_proxy_host or dut.credentials.use_port_forwarding
                else 5.0
            )
            # Use the DUT's ipmi method with timeout
            success, response = await asyncio.wait_for(
                dut.test_ipmi_connection(), timeout=timeout
            )
            if success:
                return True, "IPMI interface accessible"
            else:
                return False, f"IPMI interface failed: {response}"
        except asyncio.TimeoutError:
            # Check if any IPMI collectors are applicable for this DUT's baseboard
            should_skip, skip_message = self._check_service_collector_applicability(
                dut, "ipmi", collectors_by_group
            )
            if should_skip:
                return False, skip_message

            return False, f"IPMI interface timeout ({timeout}s)"
        except Exception as e:
            return False, f"IPMI interface error: {str(e)}"

    async def _fast_ssh_check(
        self,
        dut: "DUT",
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Tuple[bool, str]:
        """
        Fast SSH check using ping first, then actual interface test.

        Args:
            dut: DUT instance.
            collectors_by_group: Mapping of collector group -> collectors with metadata.

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
                # Check if any SSH collectors are applicable for this DUT's baseboard
                should_skip, skip_message = self._check_service_collector_applicability(
                    dut, "ssh", collectors_by_group
                )
                if should_skip:
                    return False, skip_message

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
                # Check if any SSH collectors are applicable for this DUT's baseboard
                should_skip, skip_message = self._check_service_collector_applicability(
                    dut, "ssh", collectors_by_group
                )
                if should_skip:
                    return False, skip_message

                return False, "SSH interface timeout (30s)"
            except Exception as e:
                return False, f"SSH interface error: {str(e)}"

    async def _fast_host_check(
        self,
        dut: "DUT",
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Tuple[bool, str]:
        """
        Fast host check using ping first, then actual interface test.

        Args:
            dut: DUT instance.
            collectors_by_group: Mapping of collector group -> collectors with metadata.

        Returns:
            Tuple of (success, message).
        """
        # Check if local mode is enabled
        is_local_mode = dut.config and dut.config.get("local", False)

        if not dut.credentials.host_ip:
            if is_local_mode:
                # Local mode explicitly requested - allow execution without host IP
                return True, "Local host execution (--local flag)"
            else:
                # No host IP and no local flag - this is a configuration error
                return False, "No host IP configured and --local flag not set"

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
                # Check if any Host collectors are applicable for this DUT's baseboard
                should_skip, skip_message = self._check_service_collector_applicability(
                    dut, "host", collectors_by_group
                )
                if should_skip:
                    return False, skip_message

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
                # Check if any Host collectors are applicable for this DUT's baseboard
                should_skip, skip_message = self._check_service_collector_applicability(
                    dut, "host", collectors_by_group
                )
                if should_skip:
                    return False, skip_message

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
        request_auth = (
            aiohttp.BasicAuth(username, password)
            if connection_info.get("auth_enabled", True) and username and password
            else None
        )

        # Retry configuration with exponential backoff
        max_retries = retry_count
        base_delay = 1  # Start with 1 second
        max_delay = 30  # Cap at 30 seconds

        # HTTP 500 (Internal Server Error) typically indicates a persistent server-side issue
        # that won't be resolved by retrying, so we use fewer retries for it.
        # Other 5xx errors (502, 503, 504) are more likely to be transient and benefit from retries.
        retryable_status_codes = {502, 503, 504, 520, 521, 522, 523, 524}
        limited_retry_status_codes = {500}  # Only 1 retry for HTTP 500
        max_retries_for_500 = 1  # Reduced retries for persistent server errors

        # Track consecutive 500 errors for this request
        consecutive_500_count = 0

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
                                ssl=dut.redfish_ssl,
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
                                    limited_retry_status_codes,
                                    max_retries_for_500,
                                )
                                # Check if we should retry
                                success, data, _, _ = result
                                if not success and data == "retry":
                                    # No need to release - shared session
                                    continue  # Retry in the loop
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
                        ssl=dut.redfish_ssl,
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
                            limited_retry_status_codes,
                            max_retries_for_500,
                        )
                        # Check if we should retry
                        success, data, _, _ = result
                        if not success and data == "retry":
                            continue  # Retry in the loop
                        return result
                else:
                    # Create temporary session
                    async with aiohttp.ClientSession() as session:
                        async with session.request(
                            method,
                            full_url,
                            auth=request_auth,
                            json=body if body else None,
                            ssl=dut.redfish_ssl,
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
                                limited_retry_status_codes,
                                max_retries_for_500,
                            )
                            # Check if we should retry
                            success, data, _, _ = result
                            if not success and data == "retry":
                                continue  # Retry in the loop
                            return result

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
        limited_retry_status_codes: set = None,
        max_retries_for_limited: int = 1,
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
            retryable_status_codes: Set of status codes that trigger full retries.
            get_raw_content: Whether to return raw binary content.
            limited_retry_status_codes: Set of status codes that trigger limited retries (e.g., HTTP 500).
            max_retries_for_limited: Maximum retries for limited retry status codes.

        Returns:
            Tuple of (success, response, metadata, headers).
        """
        if limited_retry_status_codes is None:
            limited_retry_status_codes = {500}
        # Log response status
        await dut._log_runtime(
            "DEBUG",
            f"Response for {method} {uri}: HTTP {response.status} (attempt {attempt + 1}/{max_retries + 1})",
        )

        if response.status < 400:
            # Success - parse response
            if get_raw_content:
                # For binary data, return raw bytes
                MAX_RESPONSE_SIZE = 500 * 1024 * 1024  # 500 MB
                content = await response.read()
                if len(content) > MAX_RESPONSE_SIZE:
                    raise ValueError(
                        f"Response exceeds {MAX_RESPONSE_SIZE // (1024 * 1024)}MB limit"
                    )
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
        elif (
            response.status in retryable_status_codes
            or response.status in limited_retry_status_codes
        ):
            # Server error - retry if we have attempts left
            response_text = await response.text()

            # Try to parse as JSON even for error responses
            # Many BMCs (including NVIDIA) return valid Redfish JSON with HTTP 500
            parsed_response = response_text
            try:
                parsed_response = json.loads(response_text)
                await dut._log_runtime(
                    "DEBUG",
                    f"Parsed JSON from HTTP {response.status} response for {method} {uri}",
                )
            except json.JSONDecodeError:
                await dut._log_runtime(
                    "DEBUG",
                    f"Could not parse HTTP {response.status} response as JSON for {method} {uri}",
                )

            compact_text = " ".join(response_text.split())[:200]
            await dut._log_runtime(
                "WARNING",
                f"Server error HTTP {response.status} for {method} {uri}: {compact_text}",
            )

            # Determine effective max retries based on status code
            # HTTP 500 (Internal Server Error) typically indicates a persistent issue,
            # so we use fewer retries to avoid wasting time on endpoints that won't recover
            effective_max_retries = max_retries
            if response.status in limited_retry_status_codes:
                effective_max_retries = min(max_retries, max_retries_for_limited)
                if attempt == 0:
                    await dut._log_runtime(
                        "INFO",
                        f"HTTP {response.status} uses limited retries ({effective_max_retries}) - persistent server errors typically don't resolve with more retries",
                    )

            if attempt < effective_max_retries:
                await dut._log_runtime(
                    "INFO",
                    f"Retrying due to server error HTTP {response.status} (attempt {attempt + 1}/{effective_max_retries + 1})",
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
                        "max_retries": effective_max_retries,
                        "current_delay": current_delay,
                    },
                )  # Signal to retry with detailed error info
            else:
                await dut._log_runtime(
                    "WARNING",
                    f"Max retries ({effective_max_retries}) exceeded for server error HTTP {response.status} on {method} {uri}, returning parsed response if available",
                )
                # Return the parsed response (JSON dict or string) even though retries exceeded
                # This allows valid Redfish data to be used even with HTTP 500 errors
                return (
                    False,
                    parsed_response,
                    {
                        "http_status": response.status,
                        "error_message": response_text,
                        "uri": uri,
                        "method": method,
                        "max_retries_exceeded": True,
                        "limited_retries_used": response.status
                        in limited_retry_status_codes,
                    },
                    {"attempt": attempt + 1, "max_retries": effective_max_retries},
                )
        else:
            # Client error (4xx) - don't retry
            response_text = await response.text()
            compact_text = " ".join(response_text.split())[:200]
            await dut._log_runtime(
                "ERROR",
                f"Client error HTTP {response.status} for {method} {uri}: {compact_text}",
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
        Execute IPMI command on a DUT with legacy nvdebug retry logic

        Args:
            dut_id: DUT identifier
            command: IPMI command to execute
            timeout: Command timeout in seconds

        Returns:
            Tuple of (exit_code, stdout, stderr) - matching legacy nvdebug pattern

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
                        "Warning IPMI.7: Verbose command succeeded where original failed",
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
                stdout, stderr = await _communicate_subprocess(
                    process, timeout=timeout
                )
            except asyncio.TimeoutError:
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

            # Always capture both stdout and stderr (matching legacy nvdebug pattern)
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
                except Exception:
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
        Matches legacy nvdebug implementation.

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

            # Format the error message similar to legacy nvdebug
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
            Tuple of (exit_code, stdout, stderr) - matching legacy nvdebug pattern
        """
        last_error = ""

        for attempt in range(max_retries):
            try:
                connect_kwargs = self._build_ssh_connect_kwargs(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    ssh_key_path=ssh_key_path,
                    passwordless=passwordless,
                    connect_timeout=timeout,
                    keepalive_interval=None,
                    proxy_client=proxy_client,
                )

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
                            # asyncssh doesn't have direct stdin support
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

                        # Always capture both stdout and stderr (matching legacy nvdebug pattern)
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
                        try:
                            await asyncio.wait_for(_wait_closed(conn), timeout=5)
                        except asyncio.TimeoutError:
                            await self.logger.log_runtime(
                                "WARNING",
                                "DUTManager",
                                (
                                    "Timed out waiting for SSH connection close "
                                    f"after command timeout on {host}:{port}"
                                ),
                            )
                            if hasattr(conn, "abort"):
                                conn.abort()
                        except Exception as close_error:
                            await self.logger.log_runtime(
                                "WARNING",
                                "DUTManager",
                                (
                                    "Error while closing SSH connection "
                                    f"to {host}:{port}: {close_error}"
                                ),
                            )

            except Exception as e:
                if isinstance(e, ValueError):
                    return -1, "", str(e)

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
        Execute SSH command using asyncssh

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
            Tuple of (exit_code, stdout, stderr) - matching legacy nvdebug pattern
        """
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

    async def create_proxy_connection(self, dut_id: str) -> Optional[asyncssh.SSHClientConnection]:
        """
        Create SSH proxy connection using asyncssh

        Args:
            dut_id: DUT identifier

        Returns:
            SSH proxy connection object
        """
        return await self._create_proxy_connection_async(dut_id)

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
            connect_kwargs = self._build_ssh_connect_kwargs(
                host=dut.credentials.ssh_proxy_host,
                port=dut.credentials.ssh_proxy_port,
                username=dut.credentials.ssh_proxy_username,
                password=dut.credentials.ssh_proxy_password,
                ssh_key_path=dut.credentials.ssh_proxy_key_path,
                passwordless=dut.credentials.ssh_proxy_passwordless,
                connect_timeout=30,
                keepalive_interval=None,
            )

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
            # Ensure BMC SSH connection is established
            success, message = await self._ensure_connection(
                dut_id, "ssh", "test_ssh_connection"
            )
            if not success:
                return -1, "", message

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

        local_execution = not dut.credentials.host_ip

        command_to_run = command
        if use_sudo:
            command_to_run = _build_sudo_command(
                command, local_execution=local_execution
            )
            await self.logger.log_runtime(
                "DEBUG",
                "DUTManager",
                f"Command after sudo handling: {command_to_run}",
            )

        try:
            if local_execution:
                # Local execution - use unified execute_bash_command
                await self.logger.log_runtime(
                    "DEBUG", "DUTManager", "Using local execution path"
                )

                # Determine shell usage
                use_shell = True if override_shell is None else override_shell

                sudo_password = None
                if use_sudo:
                    if dut.config and dut.config.get("local", False):
                        await self.logger.log_runtime(
                            "DEBUG",
                            "DUTManager",
                            "Local mode detected - using non-interactive local sudo behavior",
                        )
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
                has_host_auth = self._has_ssh_auth_method(
                    dut.credentials.host_password,
                    dut.credentials.host_ssh_key_path,
                    dut.credentials.host_ssh_passwordless,
                )
                if not dut.credentials.host_username or not has_host_auth:
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
            error_output = stderr or stdout or ""
            if exit_code == -1 and (
                "timeout" in error_output.lower()
                or "timed out" in error_output.lower()
            ):
                return False, error_output
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
                    connect_kwargs = self._build_ssh_connect_kwargs(
                        host=dut.credentials.bmc_ip,
                        port=dut.credentials.bmc_ssh_port,
                        username=username,
                        password=password,
                        ssh_key_path=dut.credentials.bmc_ssh_key_path,
                        passwordless=dut.credentials.bmc_ssh_passwordless,
                        connect_timeout=30,
                    )

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
                "DEBUG",
                "DUTManager",
                "Using enhanced fallback logic for host file transfer",
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
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        "Using asyncssh for host file transfer",
                    )
                    connect_kwargs = self._build_ssh_connect_kwargs(
                        host=dut.credentials.host_ip,
                        port=dut.credentials.host_ssh_port,
                        username=username,
                        password=password,
                        ssh_key_path=dut.credentials.host_ssh_key_path,
                        passwordless=dut.credentials.host_ssh_passwordless,
                        connect_timeout=30,
                    )
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        f"asyncssh connect_kwargs: host={dut.credentials.host_ip}, port={dut.credentials.host_ssh_port}, username={username}",
                    )

                    if dut.credentials.host_ssh_key_path:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Using SSH key authentication for host file transfer: {dut.credentials.host_ssh_key_path}",
                        )
                    elif dut.credentials.host_ssh_passwordless:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            "Using passwordless authentication for host file transfer",
                        )
                    else:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            "Using password authentication for host file transfer",
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
                                "SFTP client started successfully",
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
                                    "SFTP get operation completed successfully",
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
        Enhanced file transfer with multiple fallback approaches (ported from legacy nvdebug).

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

        if dut.config and dut.config.get("local", False):
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                "Local mode detected - using local file copy instead of SFTP",
            )
            return await self._copy_local_files_to_destination(
                dut_id, sources, destination_directory
            )

        username = dut.credentials.host_username
        password = dut.credentials.host_password

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "DUTManager",
            f"Starting enhanced file transfer with fallback for {len(sources)} files",
        )

        # Create a unique temp directory using timestamp and random string
        # Note: preamble logs above are DEBUG-level; per-file results below are also DEBUG
        timestamp = int(time.time())
        random_str = secrets.token_hex(8)
        temp_dir = f"/tmp/nvdebug_transfer_{timestamp}_{random_str}"

        try:
            # Ensure destination directory exists
            os.makedirs(destination_directory, exist_ok=True)

            successful_downloads = []
            failed_paths = []

            # Step 1: Try direct SFTP download first
            await self.logger.write_to_dut_runtime_log(
                dut_id, "DEBUG", "DUTManager", "Attempting direct SFTP download..."
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
                    file_check_cmd = f"test -f {shlex.quote(str(source))} && ls -la {shlex.quote(str(source))} || echo {shlex.quote('File does not exist: ' + str(source))}"
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
                    read_test_cmd = f"head -c 100 {shlex.quote(str(source))} > /dev/null 2>&1 && echo 'File readable' || echo 'File not readable'"
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
                            "DEBUG",
                            "DUTManager",
                            f"Downloaded {source}",
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
                    "DEBUG",
                    "DUTManager",
                    "All files downloaded via SFTP",
                )
                return True, ""

            # Step 2: For failed files, try copying to temp location with readable permissions
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Attempting permission-based fallback for {len(failed_paths)} failed files",
            )

            # Create a private temporary directory owned by the SSH/SFTP user.
            mkdir_cmd = f"mkdir -p {shlex.quote(str(temp_dir))}"
            exit_code, _, stderr_mkdir = await self.execute_host_command(
                dut_id, mkdir_cmd, timeout=60, use_sudo=True
            )

            if exit_code != 0:
                error_msg = f"Failed to create temp directory: {stderr_mkdir}"
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "ERROR", "DUTManager", error_msg
                )
                return False, error_msg

            chown_dir_cmd = (
                f"chown {shlex.quote(str(username))} {shlex.quote(str(temp_dir))}"
            )
            exit_code, _, stderr_chown = await self.execute_host_command(
                dut_id, chown_dir_cmd, timeout=60, use_sudo=True
            )

            if exit_code != 0:
                error_msg = f"Failed to set temp directory owner: {stderr_chown}"
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "ERROR", "DUTManager", error_msg
                )
                return False, error_msg

            chmod_dir_cmd = f"chmod 700 {shlex.quote(str(temp_dir))}"
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

                if exit_code != 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Failed to copy {remote_path} to temp location: {stderr_cp}",
                    )
                    continue

                chown_file_cmd = (
                    f"chown {shlex.quote(str(username))} {shlex.quote(temp_file)}"
                )
                exit_code, _, stderr_file_chown = await self.execute_host_command(
                    dut_id, chown_file_cmd, timeout=60, use_sudo=True
                )

                if exit_code != 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Failed to set file owner: {stderr_file_chown}",
                    )
                    continue

                chmod_file_cmd = f"chmod 600 {shlex.quote(temp_file)}"
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
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Empty temp file: {temp_file}",
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
                    "All files downloaded via permission-based fallback",
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

                # Get tar command with fallback to bundled busybox
                try:
                    tar_binary = get_tar_command()
                except RuntimeError as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DUTManager",
                        f"tar not available: {e}",
                    )
                    return False, ""

                files_str = " ".join(shlex.quote(f) for f in failed_paths)
                tar_cmd = f"cd {shlex.quote(str(temp_dir))} && sudo {tar_binary} -h -czf {shlex.quote(os.path.basename(temp_tar))} {files_str}"

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

                    chown_cmd = (
                        f"chown {shlex.quote(str(username))} {shlex.quote(str(temp_tar))}"
                    )
                    chown_exit_code, _, chown_stderr = await self.execute_host_command(
                        dut_id, chown_cmd, timeout=60, use_sudo=True
                    )

                    if chown_exit_code != 0:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "DUTManager",
                            f"Failed to set owner on tar file: {chown_stderr}",
                        )

                    chmod_cmd = f"chmod 600 {shlex.quote(str(temp_tar))}"
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
                                    filter=lambda m, p: self._safe_tar_filter(
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
                        dut_id,
                        f"sudo rm -f {shlex.quote(str(temp_tar))}",
                        timeout=60,
                        use_sudo=True,
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
                    dut_id,
                    f"sudo rm -rf {shlex.quote(str(temp_dir))}",
                    timeout=60,
                    use_sudo=True,
                )
            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "DUTManager",
                    f"Failed to clean up temp directory {temp_dir}: {str(e)}",
                )

    async def _copy_local_files_to_destination(
        self, dut_id: str, sources: List[str], destination_directory: str
    ) -> Tuple[bool, str]:
        """
        Copy files locally when running in local mode (no SFTP required).

        Args:
            dut_id: DUT identifier.
            sources: List of source file paths on the local system.
            destination_directory: Local directory to store copied files.

        Returns:
            Tuple of (success, error_message).
        """
        try:
            os.makedirs(destination_directory, exist_ok=True)
        except Exception as e:
            error_msg = (
                f"Failed to create destination directory {destination_directory}: {e}"
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id, "ERROR", "DUTManager", error_msg
            )
            return False, error_msg

        user = getpass.getuser()
        group = grp.getgrgid(os.getgid()).gr_name
        failed_paths = []

        for source in sources:
            if not os.path.exists(source):
                failed_paths.append(source)
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"Source file does not exist: {source}",
                )
                continue

            dest_path = os.path.join(destination_directory, os.path.basename(source))

            if os.path.isfile(source):
                cmd = f"install -m 0644 -o {shlex.quote(user)} -g {shlex.quote(group)} {shlex.quote(source)} {shlex.quote(dest_path)}"
            else:
                cmd = f"cp -a {shlex.quote(source)} {shlex.quote(dest_path)}"

            exit_code, _, stderr = await self.execute_host_command(
                dut_id, cmd, timeout=60, use_sudo=True
            )
            if exit_code != 0:
                failed_paths.append(source)
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"Local copy failed for {source}: {stderr}",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    f"Local copy successful: {source} -> {dest_path}",
                )

        if failed_paths:
            return (
                False,
                f"Failed to copy files locally: {', '.join(failed_paths)}",
            )

        return True, ""

    async def _create_connection_with_proxy(
        self,
        dut_id: str,
        use_proxy: bool = True,
    ) -> Tuple[asyncssh.SSHClientConnection, str]:
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
            connect_kwargs = self._build_ssh_connect_kwargs(
                host=dut.credentials.host_ip,
                port=dut.credentials.host_ssh_port,
                username=username,
                password=password,
                ssh_key_path=dut.credentials.host_ssh_key_path,
                passwordless=dut.credentials.host_ssh_passwordless,
                connect_timeout=30,
            )

            # If proxy is available, use it
            if proxy_client:
                conn = await asyncssh.connect(**connect_kwargs, tunnel=proxy_client)
            else:
                # Direct connection
                conn = await asyncssh.connect(**connect_kwargs)

            return conn, "asyncssh"

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

            try:
                async with conn.start_sftp_client() as sftp:
                    file_name = os.path.basename(source)
                    local_path = f"{destination_directory}/{file_name}"

                    # Check if source file exists on remote system
                    try:
                        stat_result = await sftp.stat(source)
                        file_size = getattr(stat_result, "size", "unknown")
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

                    # Capture the remote size before the transfer so we can
                    # distinguish "remote was already 0 bytes" from "transfer
                    # silently dropped bytes due to read-permission failure".
                    # The symptom in B6099139 (H16 archives appearing empty
                    # locally despite being valid remotely) collapsed into a
                    # single generic message here; the split below preserves
                    # the useful triage signal.
                    remote_size_before = getattr(stat_result, "size", None)

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
                        local_exists = os.path.exists(local_path)
                        local_size = (
                            os.path.getsize(local_path) if local_exists else None
                        )
                        if (
                            local_exists
                            and local_size == 0
                            and isinstance(remote_size_before, int)
                            and remote_size_before > 0
                        ):
                            error_msg = (
                                f"Downloaded file {local_path} is 0 bytes locally "
                                f"but remote {source} was {remote_size_before} bytes "
                                "— likely the SFTP user cannot read the remote file "
                                "(wrong ownership or permissions)"
                            )
                        elif not local_exists:
                            error_msg = (
                                f"Downloaded file {local_path} is missing "
                                "(sftp.get completed but the local file was not created)"
                            )
                        else:
                            error_msg = (
                                f"Downloaded file {local_path} is empty (remote size "
                                f"{remote_size_before} bytes)"
                            )
                        await self.logger.write_to_dut_runtime_log(
                            dut_id, "ERROR", "DUTManager", error_msg
                        )
                        return False, error_msg

            finally:
                conn.close()
                await conn.wait_closed()

        except Exception as e:
            error_msg = f"SFTP download failed: {str(e)}"
            await self.logger.write_to_dut_runtime_log(
                dut_id, "ERROR", "DUTManager", error_msg
            )
            return False, error_msg

    def _verify_file_content(self, file_path: str) -> bool:
        """
        Verify that a file exists and has content (ported from legacy nvdebug).

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
            ssh_client: SSH client to check (asyncssh.SSHClientConnection)

        Returns:
            True if connection is active, False otherwise
        """
        if not ssh_client:
            return False

        try:
            return not ssh_client.is_closing()
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
        network_type = str(self.tool_config.get("IP_NETWORK", "ipv4")).lower()
        network_arg = "-6" if network_type == "ipv6" else "-4"
        ping_cmd = (
            f"ping {network_arg} {ping_option} 2 {shlex.quote(str(ip_address))}"
        )

        if ssh_pass:
            if not ssh_server_ip or not ssh_username or not ssh_password:
                await self.logger.log_runtime(
                    "ERROR",
                    "DUTManager",
                    "SSH ping requires server IP, username, and password",
                )
                return False
            sshpass_ping_cmd = (
                f"sshpass -p {shlex.quote(str(ssh_password))} ssh -o StrictHostKeyChecking=no "
                f"{shlex.quote(str(ssh_username))}@{shlex.quote(str(ssh_server_ip))} -p {int(ssh_port)} "
            )
        else:
            sshpass_ping_cmd = ""

        try:
            process = await asyncio.create_subprocess_shell(
                f"{sshpass_ping_cmd}{ping_cmd}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await _communicate_subprocess(process)

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
                    # No sudo password provided: force non-interactive sudo so
                    # local commands fail instead of blocking on a password prompt.
                    if "sudo -S" in command:
                        command = command.replace("sudo -S", "sudo -n", 1)
                    elif "sudo -n" not in command:
                        command = command.replace("sudo ", "sudo -n ", 1)
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
                    stdout, stderr = await _communicate_subprocess(
                        process,
                        timeout=timeout,
                        input_data=sudo_input.encode(),
                    )
                else:
                    stdout, stderr = await _communicate_subprocess(
                        process, timeout=timeout
                    )
            except asyncio.TimeoutError:
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

        # Drain pending log tasks from the baseboard manager
        if self._baseboard_manager is not None:
            await self._baseboard_manager.drain_pending_logs()

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
                    "IPMI connection check skipped for local mode without BMC IP - will execute locally via sudo",
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
