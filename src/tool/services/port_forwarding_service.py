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
Port Forwarding Service for NVDebug Tool.

This service handles port forwarding for HMC access through SSH tunnels,
integrating with sps-tools-utils for BMC connectivity through host systems.
"""

import asyncio
import logging
import os
import subprocess
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class PortForwardingService:
    """
    Service for managing port forwarding connections.
    """

    def __init__(self, logger=None, dut_manager=None):
        """
        Initialize the Port Forwarding Service.

        Args:
            logger: Logger instance.
            dut_manager: DUT manager instance.
        """
        self.active_tunnels = {}  # Track active port forwarding sessions
        self.logger = logger
        self.dut_manager = dut_manager

    async def setup_port_forwarding(
        self,
        dut_id: str,
        ssh_server_ip: str,
        ssh_username: str,
        ssh_password: str,
        destination_server_ip: str,
        ssh_port: int = 22,
        remote_port: Optional[int] = None,
        local_ports: list = None,
        remote_tcp_protocol: str = "https",
        force_setup: bool = False,
        timeout: Optional[int] = None,
        tunnel_config: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[int], str]:
        """
        Setup port forwarding using SSH tunnel

        Args:
            dut_id: DUT ID.
            ssh_server_ip: SSH server IP.
            ssh_username: SSH username.
            ssh_password: SSH password.
            destination_server_ip: Destination server IP.
            ssh_port: SSH port.
            remote_port: Remote port.
            local_ports: Local ports.
            remote_tcp_protocol: Remote TCP protocol.
            force_setup: Force setup.
            timeout: Timeout.
            tunnel_config: Tunnel configuration.

        Returns:
            Tuple of (success, bound_port, message)
        """
        try:
            if local_ports is None:
                local_ports = [18888]

            if remote_port is None:
                remote_port = 443 if remote_tcp_protocol == "https" else 80

            # Enhanced logging for better debugging
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "PortForwardingService",
                f"Setting up port forwarding: {ssh_username}@{ssh_server_ip}:{ssh_port} -> {destination_server_ip}:{remote_port}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "PortForwardingService",
                f"Available local ports: {local_ports}, Force setup: {force_setup}",
            )

            # Also log to console for user visibility
            if (
                hasattr(self.logger, "orchestrator")
                and self.logger.orchestrator
                and hasattr(self.logger.orchestrator, "sanitized_console")
            ):
                self.logger.orchestrator.sanitized_console.print_info(
                    f"[Port Forwarding] Setting up tunnel: {ssh_username}@{ssh_server_ip}:{ssh_port} -> {destination_server_ip}:{remote_port}"
                )
                self.logger.orchestrator.sanitized_console.print_info(
                    f"[Port Forwarding] Available ports: {local_ports}, Force setup: {force_setup}"
                )

            # Try each port in the list (like sps-tools-utils approach)
            for port in local_ports:
                try:
                    # If force_setup is True, try to kill existing tunnels first (like sps-tools-utils)
                    if force_setup:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "PortForwardingService",
                            f"Force setup enabled - attempting to kill existing tunnels on port {port}",
                        )

                        # Kill tracked tunnels first
                        await self.kill_port_forwarding(
                            dut_id, ssh_server_ip, destination_server_ip, port
                        )

                        # Then try to kill any external SSH tunnels using the port (like sps-tools-utils)
                        await self._kill_ssh_tunnel_on_port(dut_id, port)

                        # Wait a moment for the port to be released
                        await asyncio.sleep(1)

                    # Get tunnel configuration with defaults
                    tunnel_config = tunnel_config or {}
                    local_host = tunnel_config.get("TUNNEL_LOCAL_HOST", "localhost")
                    ssh_options = tunnel_config.get(
                        "SSH_TUNNEL_OPTIONS",
                        "-4 -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -o BatchMode=yes -fNT",
                    )
                    ssh_prefix = tunnel_config.get("SSH_TUNNEL_PREFIX", "sshpass -p")

                    # Create SSH tunnel command with configurable parameters
                    ssh_cmd = f"{ssh_prefix} {ssh_password} nohup ssh {ssh_options} -L {local_host}:{port}:{destination_server_ip}:{remote_port} {ssh_username}@{ssh_server_ip} -p {ssh_port}"

                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "PortForwardingService",
                        f"Executing SSH tunnel command for port {port}",
                    )

                    # Also log to console for user visibility
                    if (
                        hasattr(self.logger, "orchestrator")
                        and self.logger.orchestrator
                        and hasattr(self.logger.orchestrator, "sanitized_console")
                    ):
                        self.logger.orchestrator.sanitized_console.print_info(
                            f"[Port Forwarding] Attempting to bind port {port}..."
                        )

                    # Execute the command using the unified execute_bash_command method
                    returncode, stdout_text, stderr_text = (
                        await self.dut_manager.execute_bash_command(
                            ssh_cmd, timeout=timeout or 30, use_shell=True
                        )
                    )

                    # Enhanced error handling for SSH connection issues
                    if returncode != 0:
                        # Check for specific SSH authentication and connection errors
                        error_msg = stderr_text.lower()
                        if (
                            "permission denied" in error_msg
                            or "authentication failed" in error_msg
                        ):
                            detailed_msg = f"SSH authentication failed for {ssh_username}@{ssh_server_ip}. Please verify credentials."
                        elif "connection refused" in error_msg:
                            detailed_msg = f"SSH connection refused to {ssh_server_ip}:{ssh_port}. Please verify host and port."
                        elif (
                            "connection timed out" in error_msg
                            or "timeout" in error_msg
                        ):
                            detailed_msg = f"SSH connection timed out to {ssh_server_ip}:{ssh_port}. Please verify network connectivity."
                        elif "host key verification failed" in error_msg:
                            detailed_msg = f"SSH host key verification failed for {ssh_server_ip}. This should not happen with StrictHostKeyChecking=no."
                        elif "no route to host" in error_msg:
                            detailed_msg = f"No network route to SSH proxy host {ssh_server_ip}. Please verify network connectivity."
                        else:
                            detailed_msg = f"SSH tunnel setup failed with return code {returncode}: {stderr_text}"

                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "PortForwardingService",
                            detailed_msg,
                        )

                        # Also log to console for user visibility
                        if (
                            hasattr(self.logger, "orchestrator")
                            and self.logger.orchestrator
                            and hasattr(self.logger.orchestrator, "sanitized_console")
                        ):
                            self.logger.orchestrator.sanitized_console.print_error(
                                f"[Port Forwarding] {detailed_msg}"
                            )

                        # Continue to try next port instead of hanging
                        continue

                    # Check return code (SSH with nohup always outputs "nohup: ignoring input" to stderr, so we ignore stderr)
                    if returncode == 0:
                        # Store tunnel info for cleanup
                        tunnel_key = f"{ssh_server_ip}:{destination_server_ip}:{port}"
                        self.active_tunnels[tunnel_key] = {
                            "port": port,
                            "cmd": ssh_cmd,
                            "pid": None,  # We don't track PID in this implementation
                            "destination_server_ip": destination_server_ip,
                            "remote_port": remote_port,
                        }

                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "PortForwardingService",
                            f"Port forwarding established: localhost:{port} -> {destination_server_ip}:{remote_port}",
                        )

                        # Also log to console for user visibility
                        if (
                            hasattr(self.logger, "orchestrator")
                            and self.logger.orchestrator
                            and hasattr(self.logger.orchestrator, "sanitized_console")
                        ):
                            self.logger.orchestrator.sanitized_console.print_success(
                                f"[Port Forwarding] Successfully established tunnel: localhost:{port} -> {destination_server_ip}:{remote_port}"
                            )

                        return (
                            True,
                            port,
                            f"Port forwarding setup successful via port {port}",
                        )
                    else:
                        msg = f"Failed to bind port {port}.\nReturnCode: {returncode}\nError: {stderr_text}\nTrying the next one..."
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "PortForwardingService",
                            msg,
                        )

                        # Also log to console for user visibility
                        if (
                            hasattr(self.logger, "orchestrator")
                            and self.logger.orchestrator
                            and hasattr(self.logger.orchestrator, "sanitized_console")
                        ):
                            self.logger.orchestrator.sanitized_console.print_warning(
                                f"[Port Forwarding] Failed to bind port {port}: {stderr_text}"
                            )

                except asyncio.TimeoutError as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PortForwardingService",
                        f"Timeout setting up port forwarding on port {port}: {e}",
                    )
                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PortForwardingService",
                        f"Error setting up port forwarding on port {port}: {str(e)}",
                    )

            # Provide helpful error message for SSH configuration
            error_msg = (
                "Failed to bind any port for forwarding. "
                "This may be due to SSH configuration on the BMC. "
                "Please ensure the following is configured on the BMC:\n\n"
                "Host BMC shell # vi /etc/ssh/sshd_config\n\n"
                "/* Please make sure AllowTcpForwarding is set to yes */\n"
                "AllowTcpForwarding yes\n\n"
                "Host BMC shell # /etc/init.d/ssh restart\n\n"
                "After making these changes, try the collection again."
            )
            return False, None, error_msg

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "PortForwardingService",
                f"Port forwarding setup failed: {str(e)}",
            )
            return False, None, f"Port forwarding setup failed: {str(e)}"

    async def kill_port_forwarding(
        self,
        dut_id: str,
        ssh_server_ip: str,
        destination_server_ip: str,
        port: Optional[int] = None,
    ) -> bool:
        """
        Kill port forwarding tunnel

        Args:
            ssh_server_ip: SSH server IP
            destination_server_ip: Destination server IP
            port: Specific port to kill (if None, kills all for this connection)

        Returns:
            True if successful, False otherwise
        """
        try:
            killed_count = 0

            # Find tunnels to kill
            tunnels_to_kill = []
            for tunnel_key, tunnel_info in self.active_tunnels.items():
                if tunnel_key.startswith(f"{ssh_server_ip}:{destination_server_ip}"):
                    if port is None or tunnel_key.endswith(f":{port}"):
                        tunnels_to_kill.append((tunnel_key, tunnel_info))

            for tunnel_key, tunnel_info in tunnels_to_kill:
                try:
                    # Kill by finding SSH processes
                    tunnel_port = tunnel_info.get("port")
                    if tunnel_port:
                        await self._kill_manual_tunnel(dut_id, tunnel_port)
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "PortForwardingService",
                            f"Killed tunnel: {tunnel_key}",
                        )

                    del self.active_tunnels[tunnel_key]
                    killed_count += 1

                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PortForwardingService",
                        f"Failed to kill tunnel {tunnel_key}: {str(e)}",
                    )

            return killed_count > 0

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "PortForwardingService",
                f"Error killing port forwarding: {str(e)}",
            )
            return False

    async def _kill_ssh_tunnel_on_port(self, dut_id: str, port: int) -> bool:
        """
        Kill SSH tunnel on specific port using sps-tools-utils approach.

        Args:
            dut_id: DUT ID.
            port: Port to kill.
        """
        try:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "PortForwardingService",
                f"Attempting to kill SSH tunnel on port {port} using sps-tools-utils method",
            )

            # Use sps-tools-utils approach: lsof -t -i :{port} -a -c ssh
            lsof_cmd = ["lsof", "-t", "-i", f":{port}", "-a", "-c", "ssh"]
            result = subprocess.run(lsof_cmd, capture_output=True, text=True)

            if result.returncode == 0 and result.stdout.strip():
                pids = result.stdout.strip().split("\n")
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "PortForwardingService",
                    f"Found SSH processes using port {port}: PIDs {pids}",
                )

                killed_any = False
                my_pid = os.getpid()

                for pid in pids:
                    if pid.strip():
                        pid_int = int(pid.strip())
                        # Make sure to not kill this running process (like sps-tools-utils)
                        if pid_int != my_pid:
                            kill_cmd = f"kill {pid_int}"
                            kill_result = subprocess.run(
                                kill_cmd, shell=True, capture_output=True, text=True
                            )

                            if kill_result.returncode == 0:
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "INFO",
                                    "PortForwardingService",
                                    f"Successfully killed SSH tunnel process {pid_int} on port {port}",
                                )
                                killed_any = True
                            else:
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "WARNING",
                                    "PortForwardingService",
                                    f"Failed to kill process {pid_int}: {kill_result.stderr}",
                                )
                        else:
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "PortForwardingService",
                                f"Skipping current process PID {pid_int}",
                            )

                if killed_any:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "PortForwardingService",
                        f"SSH tunnel on port {port} killed successfully",
                    )
                    return True
                else:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "PortForwardingService",
                        f"No SSH tunnels killed on port {port}",
                    )
                    return False
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "PortForwardingService",
                    f"No SSH processes found using port {port}",
                )
                return False

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "PortForwardingService",
                f"Error killing SSH tunnel on port {port}: {str(e)}",
            )
            return False

    async def _kill_targeted_tunnel(
        self, dut_id: str, port: int, destination_server_ip: str
    ) -> bool:
        """
        Kill SSH tunnel only if it's to our specific destination server.

        Args:
            dut_id: DUT ID.
            port: Port to kill.
            destination_server_ip: Destination server IP.
        """
        try:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "PortForwardingService",
                f"Checking if port {port} is used by tunnel to {destination_server_ip}",
            )

            # Method 1: Check if there's an SSH process with port forwarding to our destination
            # Look for SSH processes that forward to our specific destination
            # The pattern should match: ssh -L localhost:port:destination:remote_port
            target_pattern = f"ssh.*-L.*{port}:{destination_server_ip}"
            cmd = f"ps aux | grep '{target_pattern}' | grep -v grep"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0 and result.stdout.strip():
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "PortForwardingService",
                    f"Found SSH tunnel to {destination_server_ip} on port {port}: {result.stdout.strip()}",
                )

                # Kill the SSH process
                kill_cmd = f"pkill -f '{target_pattern}'"
                kill_result = subprocess.run(
                    kill_cmd, shell=True, capture_output=True, text=True
                )

                if kill_result.returncode == 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "PortForwardingService",
                        f"Successfully killed SSH tunnel to {destination_server_ip} on port {port}",
                    )
                    return True
                else:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PortForwardingService",
                        f"pkill failed for tunnel to {destination_server_ip} on port {port}: {kill_result.stderr}",
                    )

                    # Even if pkill fails, check if the port is now free
                    # Sometimes pkill returns non-zero even when it succeeds
                    await asyncio.sleep(1)  # Give it a moment
                    port_check = await self._check_port_in_use(port, dut_id)
                    if not port_check:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "PortForwardingService",
                            f"Port {port} is now free despite pkill failure - tunnel was killed",
                        )
                        return True

            # Method 2: Check if the process using the port is actually forwarding to our destination
            # This is more complex but safer - we need to verify the tunnel destination
            try:
                lsof_cmd = f"lsof -ti :{port}"
                lsof_result = subprocess.run(
                    lsof_cmd, shell=True, capture_output=True, text=True
                )

                if lsof_result.returncode == 0 and lsof_result.stdout.strip():
                    pids = lsof_result.stdout.strip().split("\n")
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "PortForwardingService",
                        f"Found processes using port {port}: PIDs {pids}",
                    )

                    for pid in pids:
                        if pid.strip():
                            # Check if this PID is an SSH process
                            ps_cmd = f"ps -p {pid.strip()} -o comm="
                            ps_result = subprocess.run(
                                ps_cmd, shell=True, capture_output=True, text=True
                            )

                            if (
                                ps_result.returncode == 0
                                and "ssh" in ps_result.stdout.strip()
                            ):
                                # Check if this SSH process is forwarding to our destination
                                ps_full_cmd = f"ps -p {pid.strip()} -o args="
                                ps_full_result = subprocess.run(
                                    ps_full_cmd,
                                    shell=True,
                                    capture_output=True,
                                    text=True,
                                )

                                if ps_full_result.returncode == 0:
                                    cmd_line = ps_full_result.stdout.strip()
                                    # Check if this SSH command forwards to our destination
                                    if (
                                        f":{destination_server_ip}:" in cmd_line
                                        or f":{destination_server_ip} " in cmd_line
                                    ):
                                        await self.logger.write_to_dut_runtime_log(
                                            dut_id,
                                            "DEBUG",
                                            "PortForwardingService",
                                            f"Confirmed SSH process {pid} forwards to {destination_server_ip}",
                                        )

                                        # Kill this specific process
                                        kill_cmd = f"kill {pid.strip()}"
                                        kill_result = subprocess.run(
                                            kill_cmd,
                                            shell=True,
                                            capture_output=True,
                                            text=True,
                                        )

                                        if kill_result.returncode == 0:
                                            await self.logger.write_to_dut_runtime_log(
                                                dut_id,
                                                "INFO",
                                                "PortForwardingService",
                                                f"Successfully killed SSH tunnel to {destination_server_ip} on port {port}",
                                            )
                                            return True
                                        else:
                                            await self.logger.write_to_dut_runtime_log(
                                                dut_id,
                                                "WARNING",
                                                "PortForwardingService",
                                                f"Failed to kill process {pid}: {kill_result.stderr}",
                                            )
                                    else:
                                        await self.logger.write_to_dut_runtime_log(
                                            dut_id,
                                            "DEBUG",
                                            "PortForwardingService",
                                            f"SSH process {pid} does not forward to {destination_server_ip}, leaving alone",
                                        )
                                else:
                                    await self.logger.write_to_dut_runtime_log(
                                        dut_id,
                                        "DEBUG",
                                        "PortForwardingService",
                                        f"Could not get full command for process {pid}",
                                    )
                            else:
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "DEBUG",
                                    "PortForwardingService",
                                    f"Process {pid} is not SSH, leaving alone",
                                )

            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "PortForwardingService",
                    f"Error checking process details for port {port}: {str(e)}",
                )

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "PortForwardingService",
                f"No tunnel to {destination_server_ip} found on port {port}",
            )
            return False

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "PortForwardingService",
                f"Error in targeted tunnel killing: {str(e)}",
            )
            return False

    async def _kill_manual_tunnel(self, dut_id: str, port: int) -> bool:
        """
        Kill manual SSH tunnel by finding and killing the process.

        Args:
            dut_id: DUT ID.
            port: Port to kill.
        """
        try:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "PortForwardingService",
                f"Attempting to kill SSH tunnel on port {port}",
            )

            # Method 1: Find and kill SSH processes with the specific port forwarding
            cmd = f"ps aux | grep 'ssh.*-L.*{port}:' | grep -v grep"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0 and result.stdout.strip():
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "PortForwardingService",
                    f"Found SSH processes using port {port}: {result.stdout.strip()}",
                )

                # Kill the SSH process
                kill_cmd = f"pkill -f 'ssh.*-L.*{port}:'"
                kill_result = subprocess.run(
                    kill_cmd, shell=True, capture_output=True, text=True
                )

                if kill_result.returncode == 0 or kill_result.returncode == -15:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "PortForwardingService",
                        f"Successfully killed SSH tunnel on port {port} using pkill (returncode: {kill_result.returncode})",
                    )
                    return True
                else:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PortForwardingService",
                        f"pkill failed for port {port}: {kill_result.stderr}",
                    )

            # Method 2: Try to kill by port number using lsof and kill
            try:
                lsof_cmd = f"lsof -ti :{port}"
                lsof_result = subprocess.run(
                    lsof_cmd, shell=True, capture_output=True, text=True
                )

                if lsof_result.returncode == 0 and lsof_result.stdout.strip():
                    pids = lsof_result.stdout.strip().split("\n")
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "PortForwardingService",
                        f"Found processes using port {port}: PIDs {pids}",
                    )

                    for pid in pids:
                        if pid.strip():
                            kill_pid_cmd = f"kill -9 {pid.strip()}"
                            kill_pid_result = subprocess.run(
                                kill_pid_cmd, shell=True, capture_output=True, text=True
                            )

                            if kill_pid_result.returncode == 0:
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "INFO",
                                    "PortForwardingService",
                                    f"Successfully killed process {pid} using port {port}",
                                )
                            else:
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "WARNING",
                                    "PortForwardingService",
                                    f"Failed to kill process {pid}: {kill_pid_result.stderr}",
                                )

                    return True
                else:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "PortForwardingService",
                        f"No processes found using port {port} via lsof",
                    )

            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "PortForwardingService",
                    f"lsof method failed for port {port}: {str(e)}",
                )

            # Method 3: Try to kill any process using the port with fuser
            try:
                fuser_cmd = f"fuser -k {port}/tcp"
                fuser_result = subprocess.run(
                    fuser_cmd, shell=True, capture_output=True, text=True
                )

                if fuser_result.returncode == 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "PortForwardingService",
                        f"Successfully killed processes using port {port} with fuser",
                    )
                    return True
                else:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "PortForwardingService",
                        f"fuser failed for port {port}: {fuser_result.stderr}",
                    )

            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "PortForwardingService",
                    f"fuser method failed for port {port}: {str(e)}",
                )

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "PortForwardingService",
                f"All methods failed to kill tunnel on port {port}",
            )
            return False

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "PortForwardingService",
                f"Error killing manual tunnel: {str(e)}",
            )
            return False

    async def _check_port_in_use(self, port: int, dut_id: str = None) -> bool:
        """
        Check if a port is already in use.

        Args:
            port: Port to check.
            dut_id: DUT ID.
        """
        try:
            import socket

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("localhost", port))
                if dut_id:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "PortForwardingService",
                        f"Port {port} socket test result: {result} (0=in use, other=free)",
                    )
                return result == 0
        except Exception as e:
            if dut_id:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "PortForwardingService",
                    f"Port {port} socket test exception: {str(e)}",
                )
            return False

    async def cleanup_all_tunnels(self, dut_id: str) -> None:
        """
        Cleanup all active port forwarding tunnels.

        Args:
            dut_id: DUT ID.
        """
        try:
            for tunnel_key, tunnel_info in list(self.active_tunnels.items()):
                try:
                    tunnel_port = tunnel_info.get("port")
                    if tunnel_port:
                        await self._kill_manual_tunnel(dut_id, tunnel_port)
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "PortForwardingService",
                            f"Cleaned up tunnel: {tunnel_key}",
                        )
                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PortForwardingService",
                        f"Failed to cleanup tunnel {tunnel_key}: {str(e)}",
                    )

            self.active_tunnels.clear()

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "PortForwardingService",
                f"Error during tunnel cleanup: {str(e)}",
            )

    def get_active_tunnels(self) -> dict:
        """
        Get information about active tunnels.

        Returns:
            Dictionary of active tunnels.
        """
        return self.active_tunnels.copy()
