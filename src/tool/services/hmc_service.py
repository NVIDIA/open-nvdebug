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
through port forwarding, SSH tunneling, and aggregation methods. Like legacy
nvdebug, it sets up the infrastructure so existing Redfish calls work
transparently.
"""

import asyncio
import ipaddress
import logging
from typing import Any, Dict, Optional, Tuple

from ..utils.command_safety import validate_ping_target
from .port_forwarding_service import PortForwardingService

logger = logging.getLogger(__name__)


class HMCService:
    """
    Manage HMC service operations for the NVDebug runtime.

    The type coordinates ``setup_hmc_port_forwarding``,
    ``get_redfish_connection_info``, ``is_hmc_active``, ``cleanup_hmc_access``,
    and ``get_hmc_redfish_url`` and retains the state those operations share
    between calls. Resource ownership remains inside the instance until the
    matching close, exit, or cleanup operation completes.
    """

    def __init__(self, logger=None, dut_manager=None):
        """
        Initialize the HMC service.

        The initializer records ``active_forwarding_port``,
        ``hmc_connection_info``, ``logger``, and ``port_forwarding_service`` for
        later operations and establishes the instance invariants before any
        public method runs.

        Args:
            logger: Sanitized logger used for operator-visible diagnostics.
            dut_manager: Optional DUT manager; ``None`` selects the function's
                default behavior.
        """
        self.port_forwarding_service = PortForwardingService(
            logger=logger, dut_manager=dut_manager
        )
        self.active_forwarding_port: Optional[int] = None
        self.hmc_connection_info: Optional[dict] = None
        self.forwarding_owned_by_tool = True
        self.logger = logger
        self._setup_locks: Dict[str, asyncio.Lock] = {}

    def register_external_hmc_forwarding(
        self,
        local_host: str,
        local_port: int,
        hmc_ip: str,
        hmc_remote_port: int,
        hmc_use_https: bool,
        hmc_username: Optional[str] = None,
        hmc_password: Optional[str] = None,
    ) -> int:
        """
        Register a caller-managed local HMC tunnel without taking ownership.

        The method validates and records only the endpoint needed for Redfish
        access. It never creates a process, reserves a port, or adds the route
        to ``PortForwardingService``; consequently normal HMC cleanup must not
        stop the caller's tunnel.

        Args:
            local_host: Local address on which the external tunnel listens.
            local_port: Local TCP port exposed by the external tunnel.
            hmc_ip: Original HMC destination represented by the tunnel.
            hmc_remote_port: Original HMC Redfish destination port.
            hmc_use_https: Whether the forwarded HMC endpoint uses HTTPS.
            hmc_username: Optional HMC Redfish username.
            hmc_password: Optional sensitive HMC Redfish password.

        Returns:
            The validated external local listener port.

        Raises:
            ValueError: If the local host or either port is malformed.
            RuntimeError: If this service already owns a tunnel and therefore
                cannot safely be repurposed as an external endpoint holder.
        """
        if self.port_forwarding_service.active_tunnels:
            raise RuntimeError(
                "Cannot replace an owned HMC tunnel with an external endpoint"
            )
        if isinstance(local_port, bool) or isinstance(hmc_remote_port, bool):
            raise ValueError("HMC forwarding ports must be integers")
        try:
            normalized_local_port = int(local_port)
            normalized_remote_port = int(hmc_remote_port)
        except (TypeError, ValueError) as exc:
            raise ValueError("HMC forwarding ports must be integers") from exc
        if not 1 <= normalized_local_port <= 65535:
            raise ValueError("HMC local forwarding port must be between 1 and 65535")
        if not 1 <= normalized_remote_port <= 65535:
            raise ValueError("HMC remote port must be between 1 and 65535")

        if local_host is None:
            normalized_host = ""
        elif not isinstance(local_host, str):
            raise ValueError("HMC local forwarding host must be a string")
        else:
            normalized_host = local_host.strip()
        if normalized_host in {"", "*"}:
            normalized_host = "127.0.0.1"
        else:
            address_text = normalized_host.strip("[]")
            try:
                parsed_address = ipaddress.ip_address(address_text)
            except ValueError:
                pass
            else:
                if parsed_address.is_unspecified:
                    normalized_host = (
                        "::1" if parsed_address.version == 6 else "127.0.0.1"
                    )
        try:
            validated_host = validate_ping_target(normalized_host)
        except (TypeError, ValueError) as exc:
            raise ValueError("HMC local forwarding host is invalid") from exc
        host_without_brackets = (
            normalized_host[1:-1]
            if normalized_host.startswith("[") and normalized_host.endswith("]")
            else normalized_host
        )
        if validated_host != host_without_brackets:
            raise ValueError("HMC local forwarding host must not include a port")
        normalized_host = validated_host
        if ":" in normalized_host and not normalized_host.startswith("["):
            normalized_host = f"[{normalized_host}]"

        self.forwarding_owned_by_tool = False
        self.active_forwarding_port = normalized_local_port
        self.hmc_connection_info = {
            "forwarded_host": normalized_host,
            "forwarded_port": normalized_local_port,
            "use_https": bool(hmc_use_https),
            "original_hmc_ip": hmc_ip,
            "original_hmc_port": normalized_remote_port,
            "hmc_username": hmc_username,
            "hmc_password": hmc_password,
        }
        return normalized_local_port

    def get_live_owned_forwarding_port(
        self,
        dut_id: str,
        bmc_ip: str,
        bmc_ssh_port: int,
        hmc_ip: str,
        hmc_remote_port: int,
        local_host: str,
        local_port: Optional[int],
        hmc_use_https: bool,
    ) -> Optional[int]:
        """
        Return the local port only when the complete owned route is live.

        Cached connection metadata alone is not sufficient evidence of reuse.
        The tracked SSH process, immutable process identity, listener ownership,
        local bind, jump endpoint, and HMC destination must all still match the
        currently requested route. Externally managed routes are never reused
        through this ownership path.

        Args:
            dut_id: Stable DUT identifier associated with the owned tunnel.
            bmc_ip: BMC SSH endpoint through which the HMC is reached.
            bmc_ssh_port: SSH port for the BMC forwarding endpoint.
            hmc_ip: Destination HMC address carried by the tunnel.
            hmc_remote_port: Destination HMC Redfish port.
            local_host: Local interface on which the tunnel listens.
            local_port: Requested local forwarding port, or ``None`` for the
                service default.
            hmc_use_https: Whether the forwarded HMC endpoint uses HTTPS.

        Returns:
            The verified local listener port, or ``None`` when the cached route
            is absent, stale, malformed, external, or belongs to different
            endpoints.
        """
        if not self.forwarding_owned_by_tool or isinstance(local_port, bool):
            return None
        try:
            expected_local_port = 18888 if local_port is None else int(local_port)
            expected_bmc_ssh_port = int(bmc_ssh_port)
            expected_hmc_port = int(hmc_remote_port)
        except (TypeError, ValueError):
            return None
        if not 1 <= expected_local_port <= 65535:
            return None
        if self.active_forwarding_port != expected_local_port:
            return None

        connection_info = self.hmc_connection_info
        if not isinstance(connection_info, dict):
            return None
        try:
            if (
                connection_info.get("original_hmc_ip") != hmc_ip
                or int(connection_info.get("original_hmc_port")) != expected_hmc_port
                or bool(connection_info.get("use_https")) != bool(hmc_use_https)
            ):
                return None
        except (TypeError, ValueError):
            return None

        tracked = self.port_forwarding_service.get_tracked_tunnel_info(
            dut_id,
            bmc_ip,
            hmc_ip,
            expected_local_port,
        )
        if not isinstance(tracked, dict):
            return None
        try:
            route_matches = (
                int(tracked.get("ssh_port")) == expected_bmc_ssh_port
                and int(tracked.get("remote_port")) == expected_hmc_port
                and self.port_forwarding_service._registry_host(
                    str(tracked.get("local_host", ""))
                )
                == self.port_forwarding_service._registry_host(local_host)
            )
        except (TypeError, ValueError):
            return None
        if not route_matches:
            return None
        if not self.port_forwarding_service.is_tracked_tunnel_live(
            dut_id,
            bmc_ip,
            hmc_ip,
            expected_local_port,
        ):
            return None
        return expected_local_port

    async def ensure_hmc_port_forwarding(
        self,
        dut_id: str,
        bmc_ip: str,
        bmc_ssh_username: str,
        bmc_ssh_password: Optional[str],
        hmc_ip: str,
        hmc_username: Optional[str] = None,
        hmc_password: Optional[str] = None,
        bmc_ssh_port: int = 22,
        bmc_ssh_key_path: Optional[str] = None,
        bmc_ssh_passwordless: bool = False,
        hmc_http_port: int = 80,
        hmc_https_port: int = 443,
        hmc_use_https: bool = False,
        force_setup: bool = False,
        local_port: Optional[int] = None,
        tunnel_config: Optional[Dict[str, Any]] = None,
        bmc_ssh_host_key_alias: Optional[str] = None,
    ) -> Tuple[bool, Optional[int], str]:
        """
        Reuse an exact live HMC route unless its owner explicitly requests replacement.

        Setup is serialized per DUT so concurrent checks cannot start competing
        SSH children on the same local port. A cached route is reused only after
        ``get_live_owned_forwarding_port`` proves the complete route and process
        ownership. A forced refresh and stale-state repair both use the ordinary
        ownership-aware cleanup path before replacement. Untracked listeners
        never become eligible for cleanup solely because force was requested.

        Args:
            dut_id: Stable DUT identifier used for ownership and serialization.
            bmc_ip: BMC SSH endpoint through which the HMC is reached.
            bmc_ssh_username: Username for the BMC SSH endpoint.
            bmc_ssh_password: Sensitive BMC SSH password, never logged.
            hmc_ip: Destination HMC address carried by the tunnel.
            hmc_username: Optional HMC Redfish username.
            hmc_password: Optional sensitive HMC Redfish password.
            bmc_ssh_port: SSH port for the BMC forwarding endpoint.
            bmc_ssh_key_path: Optional BMC SSH private-key path.
            bmc_ssh_passwordless: Whether passwordless BMC SSH is configured.
            hmc_http_port: HMC Redfish HTTP destination port.
            hmc_https_port: HMC Redfish HTTPS destination port.
            hmc_use_https: Whether the forwarded HMC endpoint uses HTTPS.
            force_setup: Replace even a live verified route owned by this service.
            local_port: Requested local forwarding port, or ``None`` for the
                service default.
            tunnel_config: Validated SSH tunnel configuration.
            bmc_ssh_host_key_alias: Optional canonical BMC host-key alias.

        Returns:
            A tuple of success, selected local port, and operator-facing status.
        """
        setup_lock = self._setup_locks.setdefault(dut_id, asyncio.Lock())
        async with setup_lock:
            remote_port = hmc_https_port if hmc_use_https else hmc_http_port
            local_host = (tunnel_config or {}).get("TUNNEL_LOCAL_HOST", "localhost")
            live_port = self.get_live_owned_forwarding_port(
                dut_id=dut_id,
                bmc_ip=bmc_ip,
                bmc_ssh_port=bmc_ssh_port,
                hmc_ip=hmc_ip,
                hmc_remote_port=remote_port,
                local_host=local_host,
                local_port=local_port,
                hmc_use_https=hmc_use_https,
            )
            if live_port is not None and not force_setup:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HMCService",
                    f"Reusing owned HMC port forwarding on localhost:{live_port}",
                )
                return True, live_port, "Reused existing owned HMC port forwarding"

            if live_port is not None and force_setup:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HMCService",
                    f"Force replacing owned HMC port forwarding on localhost:{live_port}",
                )

            owns_state = (
                self.forwarding_owned_by_tool
                and self.active_forwarding_port is not None
            ) or any(
                tunnel.get("dut_id") == dut_id
                for tunnel in self.port_forwarding_service.active_tunnels.values()
            )
            if owns_state and not await self.cleanup_hmc_access(dut_id):
                return False, None, "Could not clean up owned HMC forwarding"

            return await self.setup_hmc_port_forwarding(
                dut_id=dut_id,
                bmc_ip=bmc_ip,
                bmc_ssh_username=bmc_ssh_username,
                bmc_ssh_password=bmc_ssh_password,
                hmc_ip=hmc_ip,
                hmc_username=hmc_username,
                hmc_password=hmc_password,
                bmc_ssh_port=bmc_ssh_port,
                bmc_ssh_key_path=bmc_ssh_key_path,
                bmc_ssh_passwordless=bmc_ssh_passwordless,
                hmc_http_port=hmc_http_port,
                hmc_https_port=hmc_https_port,
                hmc_use_https=hmc_use_https,
                force_setup=force_setup,
                local_port=local_port,
                tunnel_config=tunnel_config,
                bmc_ssh_host_key_alias=bmc_ssh_host_key_alias,
            )

    async def setup_hmc_port_forwarding(
        self,
        dut_id: str,
        bmc_ip: str,
        bmc_ssh_username: str,
        bmc_ssh_password: Optional[str],
        hmc_ip: str,
        hmc_username: Optional[str] = None,
        hmc_password: Optional[str] = None,
        bmc_ssh_port: int = 22,
        bmc_ssh_key_path: Optional[str] = None,
        bmc_ssh_passwordless: bool = False,
        hmc_http_port: int = 80,
        hmc_https_port: int = 443,
        hmc_use_https: bool = False,
        force_setup: bool = False,
        local_port: Optional[int] = None,
        tunnel_config: Optional[Dict[str, Any]] = None,
        bmc_ssh_host_key_alias: Optional[str] = None,
    ) -> Tuple[bool, Optional[int], str]:
        """
        Setup transparent HMC port forwarding infrastructure.

        The implementation uses ``dut_id``, ``bmc_ip``, ``bmc_ssh_username``,
        ``bmc_ssh_password``, and ``hmc_ip`` to setup transparent HMC port
        forwarding infrastructure. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. It
        updates ``active_forwarding_port`` and ``hmc_connection_info`` on the
        instance as part of that state transition.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            bmc_ip: Text supplied as BMC IP in the format accepted by this
                function.
            bmc_ssh_username: Text supplied as BMC SSH username in the format
                accepted by this function.
            bmc_ssh_password: Sensitive value supplied through the approved
                input boundary and never logged.
            hmc_ip: Text supplied as HMC IP in the format accepted by this
                function.
            hmc_username: Optional HMC username; ``None`` selects the function's
                default behavior.
            hmc_password: Sensitive value supplied through the approved input
                boundary and never logged.
            bmc_ssh_port: Numeric BMC SSH port used while the operation performs
                bounded accounting.
            bmc_ssh_key_path: Optional filesystem location used as the BMC SSH
                key path for this operation.
            bmc_ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            hmc_http_port: Numeric HMC HTTP port used while the operation
                performs bounded accounting.
            hmc_https_port: Numeric HMC HTTPS port used while the operation
                performs bounded accounting.
            hmc_use_https: Whether HMC use HTTPS is enabled or required for this
                operation.
            force_setup: Whether force setup is enabled or required for this
                operation.
            local_port: Optional local port; ``None`` selects the function's
                default behavior.
            tunnel_config: Optional Tunnel config governing setup transparent
                HMC port forwarding infrastructure.
            bmc_ssh_host_key_alias: Optional BMC SSH host key alias; ``None``
                selects the function's default behavior.

        Returns:
            A tuple containing ``success flag``, ``integer count``, and
            ``message text`` in that order.
        """
        # Keep setup chatter in the DUT runtime log; live progress owns stdout.
        message = f"Setting up port forwarding to HMC {hmc_ip}:{hmc_https_port if hmc_use_https else hmc_http_port}"
        await self.logger.write_to_dut_runtime_log(
            dut_id, "INFO", "HMCService", message
        )

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "HMCService",
            "[HMC DEBUG] setup_hmc_port_forwarding called",
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
                "[HMC DEBUG] About to setup port forwarding to HMC",
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

            (
                success,
                bound_port,
                message,
            ) = await self.port_forwarding_service.setup_port_forwarding(
                dut_id=dut_id,
                ssh_server_ip=bmc_ip,
                ssh_username=bmc_ssh_username,
                ssh_password=bmc_ssh_password,
                destination_server_ip=hmc_ip,
                ssh_port=bmc_ssh_port,
                ssh_key_path=bmc_ssh_key_path,
                ssh_passwordless=bmc_ssh_passwordless,
                remote_port=(hmc_https_port if hmc_use_https else hmc_http_port),
                remote_tcp_protocol="https" if hmc_use_https else "http",
                local_ports=local_ports,
                force_setup=force_setup,
                tunnel_config=tunnel_config,
                host_key_alias=bmc_ssh_host_key_alias,
            )

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HMCService",
                f"[HMC DEBUG] Port forwarding setup result: success={success}, bound_port={bound_port}, message={message}",
            )

            if success and bound_port:
                self.forwarding_owned_by_tool = True
                self.active_forwarding_port = bound_port
                configured_local_host = (tunnel_config or {}).get(
                    "TUNNEL_LOCAL_HOST", "localhost"
                )
                normalized_local_host = PortForwardingService._registry_host(
                    configured_local_host
                )
                try:
                    local_address = ipaddress.ip_address(normalized_local_host)
                except ValueError:
                    local_address = None
                if normalized_local_host == "127.0.0.1":
                    forwarded_host = "localhost"
                elif local_address is not None and local_address.is_unspecified:
                    forwarded_host = (
                        "[::1]" if local_address.version == 6 else "localhost"
                    )
                elif ":" in normalized_local_host:
                    forwarded_host = f"[{normalized_local_host}]"
                else:
                    forwarded_host = normalized_local_host
                # Store connection info for transparent access
                self.hmc_connection_info = {
                    "forwarded_host": forwarded_host,
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
                    f"HMC port forwarding established: {forwarded_host}:{bound_port} -> {hmc_ip}:{hmc_https_port if hmc_use_https else hmc_http_port}",
                )
                return (
                    True,
                    bound_port,
                    f"HMC port forwarding established via port {bound_port}",
                )
            else:
                # Keep setup failures in the DUT runtime log; callers surface failure summaries.
                error_message = f"Port forwarding failed: {message}"
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "ERROR", "HMCService", error_message
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
        Get connection info for Redfish calls to use transparently.

        Returns connection details that existing Redfish service can use

        Returns:
            A mapping containing the ``host``, ``port``, ``use_https``,
            ``username``, and ``password`` fields.
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

        The implementation uses current instance state to check if HMC port
        forwarding is active. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path.

        Returns:
            Whether the if HMC port forwarding is active operation succeeds.
        """
        return (
            self.active_forwarding_port is not None
            and self.hmc_connection_info is not None
        )

    async def cleanup_hmc_access(self, dut_id: str) -> bool:
        """
        Cleanup HMC port forwarding.

        The implementation uses ``dut_id`` to cleanup HMC port forwarding. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. It updates ``active_forwarding_port`` and
        ``hmc_connection_info`` on the instance as part of that state
        transition.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            Whether the cleanup HMC port forwarding operation succeeds.
        """
        try:
            owns_tracked_tunnel = any(
                tunnel.get("dut_id") == dut_id
                for tunnel in self.port_forwarding_service.active_tunnels.values()
            )
            if (
                self.forwarding_owned_by_tool
                and self.active_forwarding_port is not None
            ) or owns_tracked_tunnel:
                # Cleanup only tool-owned tunnels. External routes are references.
                await self.port_forwarding_service.cleanup_all_tunnels(dut_id)
                residual_owned_tunnels = any(
                    tunnel.get("dut_id") == dut_id
                    for tunnel in self.port_forwarding_service.active_tunnels.values()
                )
                if residual_owned_tunnels:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HMCService",
                        "HMC access cleanup retained an owned forwarding tunnel",
                    )
                    return False
            was_external = (
                self.active_forwarding_port is not None
                and not self.forwarding_owned_by_tool
                and not owns_tracked_tunnel
            )
            self.forwarding_owned_by_tool = False
            self.active_forwarding_port = None
            self.hmc_connection_info = None
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HMCService",
                (
                    "Released externally managed HMC endpoint without stopping it"
                    if was_external
                    else "HMC access cleanup completed"
                ),
            )
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

        The implementation uses ``bound_port`` and ``endpoint`` to get the
        Redfish URL for HMC access through port forwarding.

        Args:
            bound_port: Numeric bound port used while the operation performs
                bounded accounting.
            endpoint: Validated remote resource identifier used for endpoint.

        Returns:
            The canonical HMC Redfish URL text.
        """
        return f"https://localhost:{bound_port}{endpoint}"

    async def check_hmc_ready_gpio(
        self,
        dut_manager,
        dut_id: str,
    ) -> Tuple[bool, str]:
        """
        Check HMC ready GPIO status using existing BMC SSH service.

        Use existing BMC SSH service to execute GPIO command.

        Args:
            dut_manager: DUT manager object whose ``execute_bmc_command`` state
                is read while performing HMC ready GPIO status using existing
                BMC SSH service.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing ``success flag`` and ``message text`` in that
            order.
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
        Reset HMC to default factory settings using existing Redfish service.

        The service automatically uses port forwarding if the DUT is configured
        for it. If port forwarding is not enabled, it uses direct BMC
        connection.

        Args:
            dut_manager: DUT manager object whose ``execute_redfish_request``
                and ``get_dut`` state is read while performing reset HMC to
                default factory settings using existing Redfish service.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc_id: Stable HMC identifier used to correlate configuration, logs,
                and results.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        try:
            # Get the DUT to check its configuration
            dut = dut_manager.get_dut(dut_id)

            # Use existing Redfish service - it will automatically use port forwarding
            # if the DUT is configured for it via get_redfish_connection_info()
            endpoint = f"/redfish/v1/Managers/{hmc_id}/Actions/Manager.ResetToDefaults"
            payload = {}

            request_result = await dut_manager.execute_redfish_request(
                dut_id, "POST", endpoint, payload, timeout=timeout
            )

            if isinstance(request_result, tuple):
                if len(request_result) >= 4:
                    success, response_data, *_ = request_result
                elif len(request_result) == 3:
                    success, response_data, _ = request_result
                elif len(request_result) == 2:
                    success, response_data = request_result
                elif len(request_result) == 1:
                    success = request_result[0]
                    response_data = None
                else:
                    success = False
                    response_data = "Unexpected response format"
            else:
                success = bool(request_result)
                response_data = None

            if success:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HMCService",
                    "HMC reset to defaults successful",
                )
                return True, "HMC reset to defaults successful"
            else:
                failure_detail = (
                    response_data if response_data is not None else "Unknown error"
                )
                return False, f"HMC reset to defaults failed: {failure_detail}"

        except Exception as e:
            return False, f"HMC reset to defaults error: {str(e)}"
