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
HMC Service for NVDebug Tool.

This service provides transparent HMC (Host Management Controller) access
through port forwarding, SSH tunneling, and aggregation methods.
It sets up the infrastructure so existing Redfish calls work transparently.
"""

import logging
from typing import Any, Dict, Optional, Tuple

from .port_forwarding_service import PortForwardingService

logger = logging.getLogger(__name__)


class HMCService:
    """
    Transparent HMC service - sets up port forwarding infrastructure
    so existing Redfish calls work without modification
    """

    def __init__(self, logger=None, dut_manager=None):
        """
        Initialize the HMC service.

        Args:
            logger: Logger instance.
            dut_manager: DUT manager instance.
        """
        self.port_forwarding_service = PortForwardingService(
            logger=logger, dut_manager=dut_manager
        )
        self.active_forwarding_port: Optional[int] = None
        self.hmc_connection_info: Optional[dict] = None
        self.logger = logger

    async def setup_hmc_port_forwarding(
        self,
        dut_id: str,
        bmc_ip: str,
        bmc_ssh_username: str,
        bmc_ssh_password: str,
        hmc_ip: str,
        hmc_username: Optional[str] = None,
        hmc_password: Optional[str] = None,
        bmc_ssh_port: int = 22,
        hmc_http_port: int = 80,
        hmc_https_port: int = 443,
        hmc_use_https: bool = False,
        force_setup: bool = False,
        local_port: Optional[int] = None,
        tunnel_config: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[int], str]:
        """
        Setup transparent HMC port forwarding infrastructure

        Returns:
            Tuple of (success, bound_port, message)
        """
        # Log to console for user visibility (sanitized)
        message = f"Setting up port forwarding to HMC {hmc_ip}:{hmc_https_port if hmc_use_https else hmc_http_port}"
        await self.logger.write_to_dut_runtime_log(
            dut_id, "INFO", "HMCService", message
        )

        # Also log to sanitized console if available
        if (
            hasattr(self.logger, "orchestrator")
            and self.logger.orchestrator
            and hasattr(self.logger.orchestrator, "sanitized_console")
        ):
            self.logger.orchestrator.sanitized_console.print_info(f"[HMC] {message}")

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "HMCService",
            f"[HMC DEBUG] setup_hmc_port_forwarding called",
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id, "DEBUG", "HMCService", f"[HMC DEBUG] bmc_ip: {bmc_ip}"
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id, "DEBUG", "HMCService", f"[HMC DEBUG] hmc_ip: {hmc_ip}"
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "HMCService",
            f"[HMC DEBUG] hmc_use_https: {hmc_use_https}",
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "HMCService",
            f"[HMC DEBUG] force_setup: {force_setup}",
        )

        try:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HMCService",
                f"[HMC DEBUG] About to setup port forwarding to HMC",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HMCService",
                f"[HMC DEBUG] ssh_server_ip: {bmc_ip}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HMCService",
                f"[HMC DEBUG] ssh_username: {bmc_ssh_username}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HMCService",
                f"[HMC DEBUG] destination_server_ip: {hmc_ip}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HMCService",
                f"[HMC DEBUG] ssh_port: {bmc_ssh_port}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HMCService",
                f"[HMC DEBUG] remote_port: {hmc_https_port if hmc_use_https else hmc_http_port}",
            )

            # Setup port forwarding to HMC
            # Use the specified local port or default to None (which will use the default ports)
            local_ports = [local_port] if local_port else None

            success, bound_port, message = (
                await self.port_forwarding_service.setup_port_forwarding(
                    dut_id=dut_id,
                    ssh_server_ip=bmc_ip,
                    ssh_username=bmc_ssh_username,
                    ssh_password=bmc_ssh_password,
                    destination_server_ip=hmc_ip,
                    ssh_port=bmc_ssh_port,
                    remote_port=(hmc_https_port if hmc_use_https else hmc_http_port),
                    remote_tcp_protocol="https" if hmc_use_https else "http",
                    local_ports=local_ports,
                    force_setup=force_setup,
                    tunnel_config=tunnel_config,
                )
            )

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HMCService",
                f"[HMC DEBUG] Port forwarding setup result: success={success}, bound_port={bound_port}, message={message}",
            )

            if success and bound_port:
                self.active_forwarding_port = bound_port
                # Store connection info for transparent access
                self.hmc_connection_info = {
                    "forwarded_host": "localhost",
                    "forwarded_port": bound_port,
                    "use_https": hmc_use_https,
                    "original_hmc_ip": hmc_ip,
                    "original_hmc_port": (
                        hmc_https_port if hmc_use_https else hmc_http_port
                    ),
                    "hmc_username": hmc_username,
                    "hmc_password": hmc_password,
                }
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HMCService",
                    f"HMC port forwarding established: localhost:{bound_port} -> {hmc_ip}:{hmc_https_port if hmc_use_https else hmc_http_port}",
                )
                return (
                    True,
                    bound_port,
                    f"HMC port forwarding established via port {bound_port}",
                )
            else:
                # Log to console for user visibility (sanitized)
                error_message = f"Port forwarding failed: {message}"
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "ERROR", "HMCService", error_message
                )

                # Also log to sanitized console if available
                if (
                    hasattr(self.logger, "orchestrator")
                    and self.logger.orchestrator
                    and hasattr(self.logger.orchestrator, "sanitized_console")
                ):
                    self.logger.orchestrator.sanitized_console.print_error(
                        f"[HMC] {error_message}"
                    )

                return False, None, f"HMC port forwarding failed: {message}"

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "HMCService",
                f"HMC port forwarding setup error: {str(e)}",
            )
            return False, None, f"HMC port forwarding setup error: {str(e)}"

    def get_redfish_connection_info(self) -> dict:
        """
        Get connection info for Redfish calls to use transparently

        Returns connection details that existing Redfish service can use
        """
        if self.hmc_connection_info:
            return {
                "host": self.hmc_connection_info["forwarded_host"],
                "port": self.hmc_connection_info["forwarded_port"],
                "use_https": self.hmc_connection_info["use_https"],
                "username": self.hmc_connection_info.get("hmc_username"),
                "password": self.hmc_connection_info.get("hmc_password"),
                "is_forwarded": True,
            }
        return {
            "host": None,
            "port": None,
            "use_https": True,
            "username": None,
            "password": None,
            "is_forwarded": False,
        }

    def is_hmc_active(self) -> bool:
        """
        Check if HMC port forwarding is active.

        Returns:
            True if HMC port forwarding is active, False otherwise.
        """
        return (
            self.active_forwarding_port is not None
            and self.hmc_connection_info is not None
        )

    async def cleanup_hmc_access(self, dut_id: str) -> bool:
        """
        Cleanup HMC port forwarding.

        Args:
            dut_id: DUT ID.
        """
        try:
            if self.active_forwarding_port:
                # Cleanup all tunnels
                await self.port_forwarding_service.cleanup_all_tunnels(dut_id)
                self.active_forwarding_port = None
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HMCService",
                    "HMC access cleanup completed",
                )
                return True
            return True
        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "HMCService",
                f"HMC access cleanup error: {str(e)}",
            )
            return False

    def get_hmc_redfish_url(
        self, bound_port: int, endpoint: str = "/redfish/v1"
    ) -> str:
        """
        Get the Redfish URL for HMC access through port forwarding.

        Args:
            bound_port: Bound port.
            endpoint: Endpoint.
        """
        return f"https://localhost:{bound_port}{endpoint}"

    async def check_hmc_ready_gpio(
        self,
        dut_manager,
        dut_id: str,
    ) -> Tuple[bool, str]:
        """
        Check HMC ready GPIO status using existing BMC SSH service

        Args:
            dut_manager: DUT manager instance.
            dut_id: DUT ID.
            hmc_id: HMC ID.
            timeout: Timeout.

        Returns:
            Tuple of (success, message)
        """
        try:
            # Use existing BMC SSH service to execute GPIO command
            exit_code, stdout, stderr = await dut_manager.execute_bmc_command(
                dut_id, 'gpioget `gpiofind "HMC_READY-I"`'
            )

            if exit_code == 0:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HMCService",
                    f"HMC ready GPIO check successful: {stdout}",
                )
                return True, f"HMC ready GPIO: {stdout}"
            else:
                return (
                    False,
                    f"HMC ready GPIO check failed: {stderr or stdout}",
                )

        except Exception as e:
            return False, f"HMC ready GPIO check error: {str(e)}"

    async def reset_hmc_to_defaults(
        self,
        dut_manager,
        dut_id: str,
        hmc_id: str = "HGX_BMC_0",
        timeout: int = 60,
    ) -> Tuple[bool, str]:
        """
        Reset HMC to default factory settings using existing Redfish service

        The service automatically uses port forwarding if the DUT is configured for it.
        If port forwarding is not enabled, it uses direct BMC connection.

        Returns:
            Tuple of (success, message)
        """
        try:
            # Get the DUT to check its configuration
            dut = dut_manager.get_dut(dut_id)

            # Use existing Redfish service - it will automatically use port forwarding
            # if the DUT is configured for it via get_redfish_connection_info()
            endpoint = f"/redfish/v1/Managers/{hmc_id}/Actions/Manager.ResetToDefaults"
            payload = {}

            success, response_data, _, _ = await dut_manager.execute_redfish_request(
                dut_id, "POST", endpoint, payload, timeout=timeout
            )

            if success:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HMCService",
                    f"HMC reset to defaults successful",
                )
                return True, "HMC reset to defaults successful"
            else:
                return False, f"HMC reset to defaults failed: {response_data}"

        except Exception as e:
            return False, f"HMC reset to defaults error: {str(e)}"
