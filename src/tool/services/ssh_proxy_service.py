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
SSH Proxy Service for nvdebug.

This service provides SSH proxy tunneling functionality for HMC access,
allowing BMC connectivity through host systems via SSH tunnels.
but for general SSH proxy (jump box) scenarios. It sets up SSH tunnels for Redfish
and IPMI connections through the SSH proxy.
"""

import logging
import shlex
import socket
from typing import Any, Dict, List, Optional, Tuple

from .port_forwarding_service import PortForwardingService

logger = logging.getLogger(__name__)


class SSHProxyService:
    """
    SSH Proxy service - sets up SSH tunneling infrastructure
    so existing Redfish and IPMI calls work through the proxy without modification
    """

    def __init__(self, logger=None, dut_manager=None):
        self.port_forwarding_service = None
        if dut_manager:
            # Import here to avoid circular imports
            self.port_forwarding_service = PortForwardingService(
                logger=logger, dut_manager=dut_manager
            )

        self.active_tunnels: Dict[str, Dict[str, Any]] = {}  # dut_id -> tunnel_info
        self.logger = logger

    async def setup_ssh_proxy_tunneling(
        self,
        dut_id: str,
        bmc_ip: str,
        host_ip: Optional[str] = None,
        ssh_proxy_host: str = None,
        ssh_proxy_username: str = None,
        ssh_proxy_password: Optional[str] = None,
        ssh_proxy_key_path: Optional[str] = None,
        ssh_proxy_passwordless: bool = False,
        ssh_proxy_port: int = 22,
        bmc_redfish_port: int = 443,
        bmc_use_https: bool = True,
        bmc_ipmi_port: int = 623,
        host_ssh_port: int = 22,
        force_setup: bool = False,
        tunnel_config: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Dict[str, int], str]:
        """
        Setup SSH proxy tunneling for Redfish, IPMI, and SSH connections

        Args:
            dut_id: DUT identifier
            bmc_ip: BMC IP address (target)
            host_ip: Host IP address (target, optional)
            ssh_proxy_host: SSH proxy host (jump box)
            ssh_proxy_username: SSH proxy username
            ssh_proxy_password: SSH proxy password
            ssh_proxy_key_path: SSH proxy private key path
            ssh_proxy_passwordless: Use SSH agent/default-key auth without a password
            ssh_proxy_port: SSH proxy port
            bmc_redfish_port: BMC Redfish port
            bmc_ipmi_port: BMC IPMI port
            host_ssh_port: Host SSH port
            force_setup: Force tunnel setup even if tunnels exist
            tunnel_config: Additional tunnel configuration

        Returns:
            Tuple of (success, tunnel_ports, message)
            tunnel_ports: Dict with 'redfish_port', 'ipmi_port', 'ssh_port' keys
        """
        if not self.port_forwarding_service:
            return False, {}, "Port forwarding service not available"

        if not ssh_proxy_host:
            return False, {}, "SSH proxy host not configured"

        # Validate SSH proxy credentials before attempting tunnel setup
        if not ssh_proxy_username:
            return False, {}, "SSH proxy username not configured"

        if not (ssh_proxy_key_path or ssh_proxy_passwordless or ssh_proxy_password):
            return (
                False,
                {},
                "SSH proxy password, key path, or passwordless auth not configured",
            )

        # Test SSH proxy connection first to avoid hanging
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "SSHProxyService",
            f"Testing SSH proxy connection to {ssh_proxy_host}:{ssh_proxy_port}",
        )

        test_success = await self._test_ssh_proxy_connection(
            dut_id,
            ssh_proxy_host,
            ssh_proxy_port,
            ssh_proxy_username,
            ssh_proxy_password,
            ssh_proxy_key_path,
            ssh_proxy_passwordless,
        )

        if not test_success:
            return (
                False,
                {},
                f"SSH proxy connection test failed for {ssh_proxy_host}:{ssh_proxy_port}. Please verify credentials and connectivity.",
            )

        # Log to console for user visibility (sanitized)
        message = (
            f"Setting up SSH proxy tunneling through {ssh_proxy_host}:{ssh_proxy_port}"
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id, "INFO", "SSHProxyService", message
        )

        # Also log to sanitized console if available
        if (
            hasattr(self.logger, "orchestrator")
            and self.logger.orchestrator
            and hasattr(self.logger.orchestrator, "sanitized_console")
        ):
            self.logger.orchestrator.sanitized_console.print_info(
                f"[SSH Proxy] {message}"
            )

        # Find available local ports for tunneling
        # Need 4 ports: redfish, ipmi, bmc_ssh, host_ssh (if host_ip exists)
        num_ports_needed = 4 if host_ip else 3
        tunnel_ports = await self._find_available_ports(dut_id, num_ports_needed)
        if not tunnel_ports:
            return False, {}, "Could not find available local ports for tunneling"

        redfish_port, ipmi_port, bmc_ssh_port = (
            tunnel_ports[0],
            tunnel_ports[1],
            tunnel_ports[2],
        )
        host_ssh_port = tunnel_ports[3] if len(tunnel_ports) > 3 else None

        # Setup tunnel configuration
        tunnel_config = tunnel_config or {}
        local_host = tunnel_config.get("TUNNEL_LOCAL_HOST", "localhost")
        # Omit BatchMode=yes so keyboard-interactive auth works (same as proxy test)
        ssh_options = tunnel_config.get(
            "SSH_TUNNEL_OPTIONS",
            "-4 -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -o PreferredAuthentications=keyboard-interactive,password -fNT",
        )
        ssh_prefix = tunnel_config.get("SSH_TUNNEL_PREFIX", "sshpass -p")

        success_count = 0
        tunnel_info = {
            "redfish_port": redfish_port,
            "ipmi_port": ipmi_port,
            "bmc_ssh_port": bmc_ssh_port,
            "host_ssh_port": host_ssh_port,
            "proxy_host": ssh_proxy_host,
            "proxy_port": ssh_proxy_port,
            "tunnels": {},
        }

        # Setup Redfish tunnel (BMC HTTP/HTTPS based on bmc_use_https)
        if bmc_ip:
            redfish_protocol = "https" if bmc_use_https else "http"
            redfish_success, _, redfish_msg = (
                await self.port_forwarding_service.setup_port_forwarding(
                    dut_id=dut_id,
                    ssh_server_ip=ssh_proxy_host,
                    ssh_username=ssh_proxy_username,
                    ssh_password=ssh_proxy_password,
                    destination_server_ip=bmc_ip,
                    ssh_port=ssh_proxy_port,
                    ssh_key_path=ssh_proxy_key_path,
                    ssh_passwordless=ssh_proxy_passwordless,
                    remote_port=bmc_redfish_port,
                    local_ports=[redfish_port],
                    remote_tcp_protocol=redfish_protocol,
                    force_setup=force_setup,
                    tunnel_config={
                        "TUNNEL_LOCAL_HOST": local_host,
                        "SSH_TUNNEL_OPTIONS": ssh_options,
                        "SSH_TUNNEL_PREFIX": ssh_prefix,
                    },
                )
            )

            if redfish_success:
                tunnel_info["tunnels"]["redfish"] = {
                    "local_port": redfish_port,
                    "remote_host": bmc_ip,
                    "remote_port": bmc_redfish_port,
                    "protocol": redfish_protocol,
                }
                success_count += 1
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "SSHProxyService",
                    f"Redfish tunnel established: localhost:{redfish_port} -> {bmc_ip}:{bmc_redfish_port} ({redfish_protocol.upper()}) via {ssh_proxy_host}",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "SSHProxyService",
                    f"Failed to establish Redfish tunnel: {redfish_msg}",
                )

        # Setup IPMI tunnel (BMC IPMI)
        if bmc_ip:
            ipmi_success, _, ipmi_msg = (
                await self.port_forwarding_service.setup_port_forwarding(
                    dut_id=dut_id,
                    ssh_server_ip=ssh_proxy_host,
                    ssh_username=ssh_proxy_username,
                    ssh_password=ssh_proxy_password,
                    destination_server_ip=bmc_ip,
                    ssh_port=ssh_proxy_port,
                    ssh_key_path=ssh_proxy_key_path,
                    ssh_passwordless=ssh_proxy_passwordless,
                    remote_port=bmc_ipmi_port,
                    local_ports=[ipmi_port],
                    remote_tcp_protocol="tcp",
                    force_setup=force_setup,
                    tunnel_config={
                        "TUNNEL_LOCAL_HOST": local_host,
                        "SSH_TUNNEL_OPTIONS": ssh_options,
                        "SSH_TUNNEL_PREFIX": ssh_prefix,
                    },
                )
            )

            if ipmi_success:
                tunnel_info["tunnels"]["ipmi"] = {
                    "local_port": ipmi_port,
                    "remote_host": bmc_ip,
                    "remote_port": bmc_ipmi_port,
                    "protocol": "tcp",
                }
                success_count += 1
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "SSHProxyService",
                    f"IPMI tunnel established: localhost:{ipmi_port} -> {bmc_ip}:{bmc_ipmi_port} via {ssh_proxy_host}",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "SSHProxyService",
                    f"Failed to establish IPMI tunnel: {ipmi_msg}",
                )

        # Setup BMC SSH tunnel
        if bmc_ip:
            bmc_ssh_success, _, bmc_ssh_msg = (
                await self.port_forwarding_service.setup_port_forwarding(
                    dut_id=dut_id,
                    ssh_server_ip=ssh_proxy_host,
                    ssh_username=ssh_proxy_username,
                    ssh_password=ssh_proxy_password,
                    destination_server_ip=bmc_ip,
                    ssh_port=ssh_proxy_port,
                    ssh_key_path=ssh_proxy_key_path,
                    ssh_passwordless=ssh_proxy_passwordless,
                    remote_port=22,  # Standard SSH port for BMC
                    local_ports=[bmc_ssh_port],
                    remote_tcp_protocol="tcp",
                    force_setup=force_setup,
                    tunnel_config={
                        "TUNNEL_LOCAL_HOST": local_host,
                        "SSH_TUNNEL_OPTIONS": ssh_options,
                        "SSH_TUNNEL_PREFIX": ssh_prefix,
                    },
                )
            )

            if bmc_ssh_success:
                tunnel_info["tunnels"]["bmc_ssh"] = {
                    "local_port": bmc_ssh_port,
                    "remote_host": bmc_ip,
                    "remote_port": 22,
                    "protocol": "tcp",
                }
                success_count += 1
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "SSHProxyService",
                    f"BMC SSH tunnel established: localhost:{bmc_ssh_port} -> {bmc_ip}:22 via {ssh_proxy_host}",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "SSHProxyService",
                    f"Failed to establish BMC SSH tunnel: {bmc_ssh_msg}",
                )

        # Setup Host SSH tunnel (separate from BMC SSH)
        if host_ip and host_ssh_port:
            host_ssh_success, _, host_ssh_msg = (
                await self.port_forwarding_service.setup_port_forwarding(
                    dut_id=dut_id,
                    ssh_server_ip=ssh_proxy_host,
                    ssh_username=ssh_proxy_username,
                    ssh_password=ssh_proxy_password,
                    destination_server_ip=host_ip,
                    ssh_port=ssh_proxy_port,
                    ssh_key_path=ssh_proxy_key_path,
                    ssh_passwordless=ssh_proxy_passwordless,
                    remote_port=22,  # Standard SSH port for Host
                    local_ports=[host_ssh_port],
                    remote_tcp_protocol="tcp",
                    force_setup=force_setup,
                    tunnel_config={
                        "TUNNEL_LOCAL_HOST": local_host,
                        "SSH_TUNNEL_OPTIONS": ssh_options,
                        "SSH_TUNNEL_PREFIX": ssh_prefix,
                    },
                )
            )

            if host_ssh_success:
                tunnel_info["tunnels"]["host_ssh"] = {
                    "local_port": host_ssh_port,
                    "remote_host": host_ip,
                    "remote_port": 22,  # Standard SSH port for Host
                    "protocol": "tcp",
                }
                success_count += 1
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "SSHProxyService",
                    f"Host SSH tunnel established: localhost:{host_ssh_port} -> {host_ip}:22 via {ssh_proxy_host}",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "SSHProxyService",
                    f"Failed to establish Host SSH tunnel: {host_ssh_msg}",
                )

        # Store tunnel info
        self.active_tunnels[dut_id] = tunnel_info

        if success_count > 0:
            tunnel_ports_dict = {
                "redfish_port": redfish_port,
                "ipmi_port": ipmi_port,
                "bmc_ssh_port": bmc_ssh_port,
                "host_ssh_port": host_ssh_port,
            }
            success_msg = (
                f"SSH proxy tunneling established: {success_count} tunnel(s) active"
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id, "INFO", "SSHProxyService", success_msg
            )
            return True, tunnel_ports_dict, success_msg
        else:
            return False, {}, "Failed to establish any SSH proxy tunnels"

    async def get_tunnel_connection_info(self, dut_id: str) -> Dict[str, Any]:
        """
        Get connection info for tunnels (similar to HMC get_connection_info)

        Returns:
            Dict with connection info for Redfish, IPMI, and SSH
        """
        if dut_id not in self.active_tunnels:
            return {}

        tunnel_info = self.active_tunnels[dut_id]
        connection_info = {
            "redfish": {
                "host": "localhost",
                "port": tunnel_info["redfish_port"],
                "use_https": True,
                "protocol": "https",
            },
            "ipmi": {
                "host": "localhost",
                "port": tunnel_info["ipmi_port"],
                "protocol": "tcp",
            },
            "ssh": {
                "host": "localhost",
                "port": tunnel_info["ssh_port"],
                "protocol": "tcp",
            },
        }

        return connection_info

    async def cleanup_tunnels(self, dut_id: str) -> bool:
        """
        Clean up SSH proxy tunnels for a DUT.

        Args:
            dut_id: DUT ID.

        Returns:
            True if cleanup successful, False otherwise.
        """
        if dut_id not in self.active_tunnels:
            return True

        tunnel_info = self.active_tunnels[dut_id]
        success = True

        # Clean up each tunnel
        for tunnel_type, tunnel_details in tunnel_info["tunnels"].items():
            try:
                if self.port_forwarding_service:
                    await self.port_forwarding_service.kill_port_forwarding(
                        dut_id=dut_id,
                        ssh_server_ip=tunnel_info["proxy_host"],
                        destination_server_ip=tunnel_details["remote_host"],
                        port=tunnel_details["local_port"],
                    )
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "SSHProxyService",
                        f"Cleaned up {tunnel_type} tunnel on port {tunnel_details['local_port']}",
                    )
                else:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "SSHProxyService",
                        f"No port forwarding service available for {tunnel_type} tunnel cleanup",
                    )
                    success = False
            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "SSHProxyService",
                    f"Failed to clean up {tunnel_type} tunnel: {e}",
                )
                success = False

        # Remove from active tunnels
        del self.active_tunnels[dut_id]
        return success

    async def _find_available_ports(
        self, dut_id: str, count: int
    ) -> Optional[List[int]]:
        """
        Find available local ports for tunneling.

        Args:
            dut_id: DUT ID.
            count: Number of ports needed.

        Returns:
            List of available ports or None if not found.
        """
        ports = []
        start_port = 18000  # Start from a reasonable port range
        current_port = start_port

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "SSHProxyService",
            f"Searching for {count} available local ports for SSH tunneling...",
        )

        for i in range(count):
            port_found = False
            # Search from current_port onwards, ensuring no overlap with previously found ports
            for port in range(current_port, current_port + 100):
                # Skip if this port is already in our list
                if port in ports:
                    continue

                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.bind(("localhost", port))
                        ports.append(port)
                        port_found = True
                        current_port = port + 1  # Start next search from the next port
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "SSHProxyService",
                            f"Found available port {port} for tunnel {i+1}",
                        )
                        break
                except OSError as e:
                    # Port is in use, try next one
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "SSHProxyService",
                        f"Port {port} is in use ({e}), trying next port...",
                    )
                    continue

            if not port_found:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "SSHProxyService",
                    f"Could not find available port for tunnel {i+1} (searched from port {current_port})",
                )
                return None

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "SSHProxyService",
            f"Successfully found {len(ports)} available ports: {ports}",
        )
        return ports

    async def _test_ssh_proxy_connection(
        self,
        dut_id: str,
        ssh_proxy_host: str,
        ssh_proxy_port: int,
        ssh_proxy_username: str,
        ssh_proxy_password: Optional[str],
        ssh_proxy_key_path: Optional[str] = None,
        ssh_proxy_passwordless: bool = False,
    ) -> bool:
        """
        Test SSH proxy connection with credentials to avoid hanging

        Args:
            dut_id: DUT identifier
            ssh_proxy_host: SSH proxy host
            ssh_proxy_port: SSH proxy port
            ssh_proxy_username: SSH proxy username
            ssh_proxy_password: SSH proxy password
            ssh_proxy_key_path: SSH proxy private key path
            ssh_proxy_passwordless: Use SSH agent/default-key auth without a password

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            test_cmd = self._build_ssh_proxy_test_command(
                ssh_proxy_host=ssh_proxy_host,
                ssh_proxy_port=ssh_proxy_port,
                ssh_proxy_username=ssh_proxy_username,
                ssh_proxy_password=ssh_proxy_password,
                ssh_proxy_key_path=ssh_proxy_key_path,
                ssh_proxy_passwordless=ssh_proxy_passwordless,
            )

            await self.logger.write_to_dut_runtime_log(
                dut_id, "DEBUG", "SSHProxyService", "Testing SSH proxy connection..."
            )

            # Use port forwarding service's dut_manager to execute the test command
            if (
                not self.port_forwarding_service
                or not self.port_forwarding_service.dut_manager
            ):
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "SSHProxyService",
                    "DUT manager not available for SSH proxy test",
                )
                return False

            returncode, stdout_text, stderr_text = (
                await self.port_forwarding_service.dut_manager.execute_bash_command(
                    test_cmd, timeout=15, use_shell=True
                )
            )

            # Check if the test was successful
            if returncode == 0 and "SSH_PROXY_TEST_SUCCESS" in stdout_text:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "SSHProxyService",
                    "SSH proxy connection test successful",
                )
                return True
            else:
                # Log specific error details
                error_msg = stderr_text.lower()
                if (
                    "permission denied" in error_msg
                    or "authentication failed" in error_msg
                ):
                    detailed_msg = f"SSH proxy authentication failed for {ssh_proxy_username}@{ssh_proxy_host}. Please verify credentials."
                elif "connection refused" in error_msg:
                    detailed_msg = f"SSH proxy connection refused to {ssh_proxy_host}:{ssh_proxy_port}. Please verify host and port."
                elif "connection timed out" in error_msg or "timeout" in error_msg:
                    detailed_msg = f"SSH proxy connection timed out to {ssh_proxy_host}:{ssh_proxy_port}. Please verify network connectivity."
                elif "no route to host" in error_msg:
                    detailed_msg = f"No network route to SSH proxy host {ssh_proxy_host}. Please verify network connectivity."
                else:
                    detailed_msg = f"SSH proxy test failed with return code {returncode}: {stderr_text}"

                await self.logger.write_to_dut_runtime_log(
                    dut_id, "ERROR", "SSHProxyService", detailed_msg
                )

                # Also log to console for user visibility
                if (
                    hasattr(self.logger, "orchestrator")
                    and self.logger.orchestrator
                    and hasattr(self.logger.orchestrator, "sanitized_console")
                ):
                    self.logger.orchestrator.sanitized_console.print_error(
                        f"[SSH Proxy] {detailed_msg}"
                    )

                return False

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "SSHProxyService",
                f"SSH proxy connection test failed with exception: {e}",
            )
            return False

    @staticmethod
    def _build_ssh_proxy_test_command(
        ssh_proxy_host: str,
        ssh_proxy_port: int,
        ssh_proxy_username: str,
        ssh_proxy_password: Optional[str],
        ssh_proxy_key_path: Optional[str] = None,
        ssh_proxy_passwordless: bool = False,
    ) -> str:
        """
        Build the SSH proxy connection-test command for the selected auth mode.
        """
        base_options = (
            "-o ConnectTimeout=10 "
            "-o ServerAliveInterval=5 "
            "-o ServerAliveCountMax=2 "
            "-o StrictHostKeyChecking=no "
            "-o LogLevel=ERROR "
        )
        destination = (
            f"{shlex.quote(str(ssh_proxy_username))}@"
            f"{shlex.quote(str(ssh_proxy_host))}"
        )

        if ssh_proxy_key_path:
            ssh_invocation = (
                "ssh "
                f"{base_options}"
                "-o PreferredAuthentications=publickey "
                "-o BatchMode=yes "
                "-o IdentitiesOnly=yes "
                f"-i {shlex.quote(str(ssh_proxy_key_path))} "
            )
        elif ssh_proxy_passwordless:
            ssh_invocation = (
                "ssh "
                f"{base_options}"
                "-o PreferredAuthentications=publickey "
                "-o BatchMode=yes "
            )
        else:
            # Do NOT use BatchMode=yes for password mode: it can prevent
            # keyboard-interactive auth, which sshpass can otherwise satisfy.
            ssh_invocation = (
                f"sshpass -p {shlex.quote(str(ssh_proxy_password))} ssh "
                f"{base_options}"
                "-o PreferredAuthentications=keyboard-interactive,password "
            )

        return (
            f"{ssh_invocation}"
            f"-p {int(ssh_proxy_port)} "
            f"{destination} "
            "'echo SSH_PROXY_TEST_SUCCESS'"
        )
