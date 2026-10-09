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

This service provides SSH proxy tunneling functionality for HMC access, allowing
BMC connectivity through host systems via SSH tunnels. For general SSH proxy
(jump box) scenarios, it sets up TCP tunnels for Redfish and SSH. IPMI/RMCP+
uses UDP and is executed remotely on the proxy instead of being misrepresented
as an OpenSSH TCP forwarding route.
"""

import asyncio
import logging
import shlex
import socket
from typing import Any, Dict, List, Optional, Tuple

from ..utils.ssh_security import (
    DEFAULT_SSH_TUNNEL_PREFIX,
    normalize_ssh_tunnel_prefix,
    openssh_host_key_options,
    resolve_ssh_tunnel_options,
)
from .port_forwarding_service import PortForwardingService

logger = logging.getLogger(__name__)

DEFAULT_SSH_PROXY_TUNNEL_OPTIONS = (
    "-4 -o LogLevel=ERROR -o ConnectTimeout=10 "
    "-o ServerAliveInterval=5 -o ServerAliveCountMax=2 "
    "-o PreferredAuthentications=keyboard-interactive,password -fNT"
)


class SSHProxyService:
    """
    Manage SSH proxy service operations for the NVDebug runtime.

    The type coordinates ``_candidate_ports``, ``_route_identity_matches``,
    ``get_live_tunnel_ports``, ``has_tracked_tunnels``, and
    ``setup_ssh_proxy_tunneling`` and retains the state those operations share
    between calls. Resource ownership remains inside the instance until the
    matching close, exit, or cleanup operation completes.
    """

    def __init__(self, logger=None, dut_manager=None):
        """
        Initialize a ``SSHProxyService`` instance.

        The initializer records ``_setup_locks``, ``active_tunnels``,
        ``logger``, and ``port_forwarding_service`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            logger: Sanitized logger used for operator-visible diagnostics.
            dut_manager: Optional DUT manager; ``None`` selects the function's
                default behavior.
        """
        self.port_forwarding_service = None
        if dut_manager:
            # Import here to avoid circular imports
            self.port_forwarding_service = PortForwardingService(
                logger=logger, dut_manager=dut_manager
            )

        self.active_tunnels: Dict[str, Dict[str, Any]] = {}  # dut_id -> tunnel_info
        self.logger = logger
        self._setup_locks: Dict[str, asyncio.Lock] = {}

    @staticmethod
    def _candidate_ports(preferred: int) -> List[int]:
        """
        Return a deterministic fallback set for process-wide reservation.

        The implementation uses ``preferred`` to produce a deterministic
        fallback set for process-wide reservation.

        Args:
            preferred: Numeric preferred used while the operation performs
                bounded accounting.

        Returns:
            The validated ``candidates``.
        """

        candidates = [int(preferred)]
        candidates.extend(
            port for port in range(18000, 18200) if port != int(preferred)
        )
        return candidates

    @staticmethod
    def _route_identity_matches(
        details: Dict[str, Any], expected: Dict[str, Any]
    ) -> bool:
        """
        Compare a cached route with the complete currently requested route.

        The implementation uses ``details`` and ``expected`` to compare a cached
        route with the complete currently requested route.

        Args:
            details: Mapping supplying fields for compare a cached route with
                the complete currently requested route.
            expected: Mapping supplying fields for compare a cached route with
                the complete currently requested route.

        Returns:
            Whether the compare a cached route with the complete currently
            requested route operation succeeds.
        """

        try:
            return (
                details.get("remote_host") == expected.get("remote_host")
                and int(details.get("remote_port")) == int(expected.get("remote_port"))
                and details.get("protocol") == expected.get("protocol")
            )
        except (TypeError, ValueError):
            return False

    def get_live_tunnel_ports(
        self,
        dut_id: str,
        *,
        expected_proxy_host: Optional[str] = None,
        expected_proxy_port: Optional[int] = None,
        expected_routes: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, int]:
        """
        Return only routes backed by a currently owned listening process.

        The implementation uses ``dut_id``, ``expected_proxy_host``,
        ``expected_proxy_port``, and ``expected_routes`` to produce only routes
        backed by a currently owned listening process.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            expected_proxy_host: Optional expected proxy host; ``None`` selects
                the function's default behavior.
            expected_proxy_port: Optional expected proxy port; ``None`` selects
                the function's default behavior.
            expected_routes: Optional expected routes; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing live tunnel ports.
        """

        if not self.port_forwarding_service:
            return {}
        tunnel_info = self.active_tunnels.get(dut_id, {})
        proxy_host = tunnel_info.get("proxy_host")
        tracked_tunnels = tunnel_info.get("tunnels", {})
        if not proxy_host or not isinstance(tracked_tunnels, dict):
            return {}
        if expected_proxy_host is not None and proxy_host != expected_proxy_host:
            return {}
        try:
            if expected_proxy_port is not None and int(
                tunnel_info.get("proxy_port")
            ) != int(expected_proxy_port):
                return {}
        except (TypeError, ValueError):
            return {}

        live_ports: Dict[str, int] = {}
        port_fields = {
            "redfish": "redfish_port",
            "bmc_ssh": "bmc_ssh_port",
            "host_ssh": "host_ssh_port",
        }
        for tunnel_type, port_field in port_fields.items():
            details = tracked_tunnels.get(tunnel_type)
            if not isinstance(details, dict):
                continue
            local_port = details.get("local_port")
            remote_host = details.get("remote_host")
            if local_port is None or not remote_host:
                continue
            if isinstance(local_port, bool):
                continue
            try:
                normalized_local_port = int(local_port)
            except (TypeError, ValueError):
                continue
            if not 1 <= normalized_local_port <= 65535:
                continue
            expected_route = (expected_routes or {}).get(tunnel_type)
            if expected_route is not None and not self._route_identity_matches(
                details, expected_route
            ):
                continue
            tracked = self.port_forwarding_service.get_tracked_tunnel_info(
                dut_id,
                proxy_host,
                remote_host,
                normalized_local_port,
            )
            if expected_route is not None:
                if tracked is None:
                    continue
                try:
                    if int(tracked.get("remote_port")) != int(
                        expected_route["remote_port"]
                    ) or int(tracked.get("ssh_port")) != int(expected_proxy_port):
                        continue
                except (KeyError, TypeError, ValueError):
                    continue
            if self.port_forwarding_service.is_tracked_tunnel_live(
                dut_id,
                proxy_host,
                remote_host,
                normalized_local_port,
            ):
                live_ports[port_field] = normalized_local_port
        return live_ports

    def has_tracked_tunnels(self, dut_id: str) -> bool:
        """
        Return whether this service still owns metadata or a child for a DUT.

        The implementation uses ``dut_id`` to determine whether this service
        still owns metadata or a child for a DUT.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            Whether this service still owns metadata or a child for a DUT.
        """

        if dut_id in self.active_tunnels:
            return True
        if not self.port_forwarding_service:
            return False
        return any(
            tunnel.get("dut_id") == dut_id
            for tunnel in self.port_forwarding_service.active_tunnels.values()
        )

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
        bmc_ssh_port: int = 22,
        host_ssh_port: int = 22,
        force_setup: bool = False,
        tunnel_config: Optional[Dict[str, Any]] = None,
        required_tunnels: Optional[List[str]] = None,
    ) -> Tuple[bool, Dict[str, int], str]:
        """
        Serialize tunnel-set mutations for one DUT.

        After applying local validation, the function forwards ``dut_id``,
        ``bmc_ip``, ``host_ip``, ``ssh_proxy_host``, and ``ssh_proxy_username``
        to ``self._setup_ssh_proxy_tunneling_unlocked`` and preserves its return
        and exception contract. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            bmc_ip: Text supplied as BMC IP in the format accepted by this
                function.
            host_ip: Optional host IP; ``None`` selects the function's default
                behavior.
            ssh_proxy_host: Optional SSH proxy host; ``None`` selects the
                function's default behavior.
            ssh_proxy_username: Optional SSH proxy username; ``None`` selects
                the function's default behavior.
            ssh_proxy_password: Sensitive value supplied through the approved
                input boundary and never logged.
            ssh_proxy_key_path: Optional filesystem location used as the SSH
                proxy key path for this operation.
            ssh_proxy_passwordless: Sensitive value supplied through the
                approved input boundary and never logged.
            ssh_proxy_port: Numeric SSH proxy port used while the operation
                performs bounded accounting.
            bmc_redfish_port: Numeric BMC Redfish port used while the operation
                performs bounded accounting.
            bmc_use_https: Whether BMC use HTTPS is enabled or required for this
                operation.
            bmc_ipmi_port: Numeric BMC IPMI port used while the operation
                performs bounded accounting.
            bmc_ssh_port: Numeric BMC SSH port used while the operation performs
                bounded accounting.
            host_ssh_port: Numeric host SSH port used while the operation
                performs bounded accounting.
            force_setup: Whether force setup is enabled or required for this
                operation.
            tunnel_config: Optional Tunnel config governing serialize tunnel-set
                mutations for one DUT.
            required_tunnels: Optional required tunnels; ``None`` selects the
                function's default behavior.

        Returns:
            A tuple containing the fields that represent setup SSH proxy
            tunneling.
        """

        lock = self._setup_locks.setdefault(str(dut_id), asyncio.Lock())
        async with lock:
            return await self._setup_ssh_proxy_tunneling_unlocked(
                dut_id=dut_id,
                bmc_ip=bmc_ip,
                host_ip=host_ip,
                ssh_proxy_host=ssh_proxy_host,
                ssh_proxy_username=ssh_proxy_username,
                ssh_proxy_password=ssh_proxy_password,
                ssh_proxy_key_path=ssh_proxy_key_path,
                ssh_proxy_passwordless=ssh_proxy_passwordless,
                ssh_proxy_port=ssh_proxy_port,
                bmc_redfish_port=bmc_redfish_port,
                bmc_use_https=bmc_use_https,
                bmc_ipmi_port=bmc_ipmi_port,
                bmc_ssh_port=bmc_ssh_port,
                host_ssh_port=host_ssh_port,
                force_setup=force_setup,
                tunnel_config=tunnel_config,
                required_tunnels=required_tunnels,
            )

    async def _setup_ssh_proxy_tunneling_unlocked(
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
        bmc_ssh_port: int = 22,
        host_ssh_port: int = 22,
        force_setup: bool = False,
        tunnel_config: Optional[Dict[str, Any]] = None,
        required_tunnels: Optional[List[str]] = None,
    ) -> Tuple[bool, Dict[str, int], str]:
        """
        Setup SSH proxy tunneling for Redfish and SSH connections.

        IPMI/RMCP+ is deliberately excluded because OpenSSH ``-L`` forwards TCP,
        while LAN IPMI uses UDP. DUTManager executes ``ipmitool`` on the proxy
        host for that transport.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            bmc_ip: Text supplied as BMC IP in the format accepted by this
                function.
            host_ip: Optional host IP; ``None`` selects the function's default
                behavior.
            ssh_proxy_host: Optional SSH proxy host; ``None`` selects the
                function's default behavior.
            ssh_proxy_username: Optional SSH proxy username; ``None`` selects
                the function's default behavior.
            ssh_proxy_password: Sensitive value supplied through the approved
                input boundary and never logged.
            ssh_proxy_key_path: Optional filesystem location used as the SSH
                proxy key path for this operation.
            ssh_proxy_passwordless: Sensitive value supplied through the
                approved input boundary and never logged.
            ssh_proxy_port: Numeric SSH proxy port used while the operation
                performs bounded accounting.
            bmc_redfish_port: Numeric BMC Redfish port used while the operation
                performs bounded accounting.
            bmc_use_https: Whether BMC use HTTPS is enabled or required for this
                operation.
            bmc_ipmi_port: Numeric BMC IPMI port used while the operation
                performs bounded accounting.
            bmc_ssh_port: Numeric BMC SSH port used while the operation performs
                bounded accounting.
            host_ssh_port: Numeric host SSH port used while the operation
                performs bounded accounting.
            force_setup: Whether force setup is enabled or required for this
                operation.
            tunnel_config: Optional Tunnel config governing setup SSH proxy
                tunneling for Redfish and SSH connections.
            required_tunnels: Optional required tunnels; ``None`` selects the
                function's default behavior.

        Returns:
            A tuple containing the setup-success flag, allocated local ports,
            and status message.
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

        available_tunnels = set()
        if bmc_ip:
            available_tunnels.update({"redfish", "bmc_ssh"})
        if host_ip:
            available_tunnels.add("host_ssh")
        requested_tunnels = (
            set(available_tunnels)
            if required_tunnels is None
            else set(required_tunnels)
        )
        if "ipmi" in requested_tunnels:
            return (
                False,
                {},
                "IPMI/RMCP+ uses UDP and cannot use an OpenSSH TCP tunnel; "
                "run ipmitool remotely on the SSH proxy",
            )
        unsupported = requested_tunnels - available_tunnels
        if unsupported:
            return (
                False,
                {},
                "Requested SSH proxy tunnel(s) lack a configured target: "
                + ", ".join(sorted(unsupported)),
            )
        if not requested_tunnels:
            return False, {}, "No SSH proxy transport was requested"

        target_bmc_ssh_port = int(bmc_ssh_port or 22)
        target_host_ssh_port = int(host_ssh_port or 22)
        expected_routes = {
            "redfish": {
                "remote_host": bmc_ip,
                "remote_port": int(bmc_redfish_port),
                "protocol": "https" if bmc_use_https else "http",
            },
            "bmc_ssh": {
                "remote_host": bmc_ip,
                "remote_port": target_bmc_ssh_port,
                "protocol": "tcp",
            },
            "host_ssh": {
                "remote_host": host_ip,
                "remote_port": target_host_ssh_port,
                "protocol": "tcp",
            },
        }
        tunnel_config = dict(tunnel_config or {})
        if self.port_forwarding_service and self.port_forwarding_service.dut_manager:
            # The DUT owns the host-key policy for this tunnel. A lookup that
            # fails, or a DUT whose configuration is not a mapping, leaves the
            # operator-selected policy unknown; substituting an empty mapping
            # here would silently resolve to the ``insecure`` default below and
            # discard a selected ``strict`` policy. Refuse this one tunnel
            # instead, using the same refusal triple as every other arm so the
            # caller records an ordinary proxy-setup failure and collection
            # continues for the remaining routes and DUTs.
            try:
                dut_config = self.port_forwarding_service.dut_manager.get_dut(
                    dut_id
                ).config
            except (AttributeError, KeyError, RuntimeError, ValueError) as exc:
                return (
                    False,
                    {},
                    "Refused SSH proxy tunnel setup because the SSH host key "
                    f"policy for DUT {dut_id} could not be resolved "
                    f"({type(exc).__name__})",
                )
            if not isinstance(dut_config, dict):
                return (
                    False,
                    {},
                    "Refused SSH proxy tunnel setup because the SSH host key "
                    f"policy for DUT {dut_id} could not be resolved "
                    "(DUT configuration is not a mapping)",
                )
            # A DUT's general tunnel options belong to its direct/HMC tunnel
            # paths. Proxy tunnels retain their connection-liveness and
            # authentication defaults unless this API receives an explicit
            # SSH_TUNNEL_OPTIONS override in tunnel_config.
            for key in (
                "ssh_host_key_policy",
                "ssh_known_hosts_file",
            ):
                if tunnel_config.get(key) is None and dut_config.get(key) is not None:
                    tunnel_config[key] = dut_config[key]

        host_key_policy = tunnel_config.get("ssh_host_key_policy", "insecure")
        known_hosts_file = tunnel_config.get("ssh_known_hosts_file")

        existing_info = self.active_tunnels.get(dut_id, {})
        raw_existing_tunnels = existing_info.get("tunnels", {})
        existing_tunnels = (
            dict(raw_existing_tunnels) if isinstance(raw_existing_tunnels, dict) else {}
        )
        rebuild_reason = ""
        if existing_info:
            try:
                proxy_identity_matches = existing_info.get(
                    "proxy_host"
                ) == ssh_proxy_host and int(existing_info.get("proxy_port")) == int(
                    ssh_proxy_port
                )
            except (TypeError, ValueError):
                proxy_identity_matches = False
            if not proxy_identity_matches:
                rebuild_reason = "SSH proxy endpoint changed"

        if not rebuild_reason:
            # Validate every sibling route owned by this service, not only the
            # subset requested by this call.  Otherwise a partial setup after
            # a DUT endpoint change could leave an old Redfish/SSH listener
            # alive and silently reuse it later.
            for tunnel_type, details in existing_tunnels.items():
                expected_route = expected_routes.get(tunnel_type)
                if expected_route is None:
                    rebuild_reason = (
                        f"{tunnel_type} is not a supported current proxy route"
                    )
                    break
                if not expected_route.get("remote_host"):
                    rebuild_reason = f"{tunnel_type} target is no longer configured"
                    break
                if not isinstance(details, dict) or not self._route_identity_matches(
                    details, expected_route
                ):
                    rebuild_reason = f"{tunnel_type} destination changed"
                    break
                try:
                    local_port = int(details["local_port"])
                except (KeyError, TypeError, ValueError):
                    rebuild_reason = f"{tunnel_type} route metadata is incomplete"
                    break
                tracked = self.port_forwarding_service.get_tracked_tunnel_info(
                    dut_id,
                    ssh_proxy_host,
                    expected_route["remote_host"],
                    local_port,
                )
                try:
                    tracked_identity_matches = (
                        tracked is not None
                        and int(tracked.get("remote_port"))
                        == int(expected_route["remote_port"])
                        and int(tracked.get("ssh_port")) == int(ssh_proxy_port)
                    )
                except (TypeError, ValueError):
                    tracked_identity_matches = False
                if not tracked_identity_matches:
                    rebuild_reason = f"{tunnel_type} owned route identity changed"
                    break
                if not self.port_forwarding_service.is_tracked_tunnel_live(
                    dut_id,
                    ssh_proxy_host,
                    expected_route["remote_host"],
                    local_port,
                ):
                    rebuild_reason = f"{tunnel_type} owned route is no longer live"
                    break

        if rebuild_reason:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "SSHProxyService",
                f"Rebuilding SSH proxy routes: {rebuild_reason}",
            )
            # Sweep through the PortForwardingService's exact ownership data,
            # not through new configuration values.  This cleans the old
            # proxy host as well as route changes without broad process scans.
            await self.port_forwarding_service.cleanup_all_tunnels(dut_id)
            residual_owned_tunnels = any(
                tunnel.get("dut_id") == dut_id
                for tunnel in self.port_forwarding_service.active_tunnels.values()
            )
            if residual_owned_tunnels:
                return (
                    False,
                    {},
                    "Refused to replace stale SSH proxy routes because exact "
                    "owned-process cleanup did not complete",
                )
            self.active_tunnels.pop(dut_id, None)
            existing_info = {}
            existing_tunnels = {}
        elif existing_info and not existing_tunnels:
            self.active_tunnels.pop(dut_id, None)
            existing_info = {}

        # Validate the new proxy only after stale exact-owned routes have been
        # swept.  A newly configured but unreachable proxy must not leave old
        # listeners alive under obsolete routing policy.
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
            host_key_policy,
            known_hosts_file,
        )
        if not test_success:
            return (
                False,
                {},
                f"SSH proxy connection test failed for {ssh_proxy_host}:{ssh_proxy_port}. Please verify credentials and connectivity.",
            )

        message = (
            f"Setting up SSH proxy tunneling through {ssh_proxy_host}:{ssh_proxy_port}"
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id, "INFO", "SSHProxyService", message
        )
        if (
            hasattr(self.logger, "orchestrator")
            and self.logger.orchestrator
            and hasattr(self.logger.orchestrator, "sanitized_console")
        ):
            self.logger.orchestrator.sanitized_console.print_info(
                f"[SSH Proxy] {message}"
            )

        tunnel_order = ("redfish", "bmc_ssh", "host_ssh")
        missing_tunnels = [
            tunnel_type
            for tunnel_type in tunnel_order
            if tunnel_type in requested_tunnels and tunnel_type not in existing_tunnels
        ]
        preferred_ports = {
            "redfish": existing_info.get("redfish_port"),
            "bmc_ssh": existing_info.get("bmc_ssh_port", existing_info.get("ssh_port")),
            "host_ssh": existing_info.get("host_ssh_port"),
        }
        if missing_tunnels:
            tunnel_ports = await self._find_available_ports(
                dut_id, len(missing_tunnels)
            )
            if not tunnel_ports:
                return (
                    False,
                    {},
                    "Could not find available local ports for tunneling",
                )
            for tunnel_type, preferred_port in zip(missing_tunnels, tunnel_ports):
                preferred_ports[tunnel_type] = preferred_port

        redfish_port = preferred_ports["redfish"]
        bmc_ssh_port = preferred_ports["bmc_ssh"]
        host_ssh_port = preferred_ports["host_ssh"]

        # Setup tunnel configuration
        local_host = tunnel_config.get("TUNNEL_LOCAL_HOST", "localhost")
        # Omit BatchMode=yes so keyboard-interactive auth works (same as proxy test)
        force_ipv4 = not PortForwardingService._route_uses_ipv6_literal(
            local_host,
            ssh_proxy_host,
            bmc_ip,
            host_ip,
        )
        proxy_tunnel_options = tunnel_config.get("SSH_TUNNEL_OPTIONS")
        if proxy_tunnel_options is None:
            proxy_tunnel_options = DEFAULT_SSH_PROXY_TUNNEL_OPTIONS
            if not force_ipv4:
                proxy_tunnel_options = proxy_tunnel_options.removeprefix("-4 ")
        ssh_options = resolve_ssh_tunnel_options(
            proxy_tunnel_options,
            host_key_policy,
            known_hosts_file,
            force_ipv4=force_ipv4,
        )
        ssh_prefix = normalize_ssh_tunnel_prefix(
            tunnel_config.get("SSH_TUNNEL_PREFIX", DEFAULT_SSH_TUNNEL_PREFIX)
        )
        forwarding_tunnel_config = {
            "TUNNEL_LOCAL_HOST": local_host,
            "SSH_TUNNEL_OPTIONS": ssh_options,
            "SSH_TUNNEL_PREFIX": ssh_prefix,
            "ssh_host_key_policy": host_key_policy,
            "ssh_known_hosts_file": known_hosts_file,
        }

        success_count = len(requested_tunnels.intersection(existing_tunnels))
        created_tunnel_types = []
        tunnel_info = {
            "redfish_port": redfish_port,
            "bmc_ssh_port": bmc_ssh_port,
            "host_ssh_port": host_ssh_port,
            "proxy_host": ssh_proxy_host,
            "proxy_port": ssh_proxy_port,
            "tunnels": existing_tunnels,
        }

        # Setup Redfish tunnel (BMC HTTP/HTTPS based on bmc_use_https)
        if "redfish" in requested_tunnels and "redfish" not in existing_tunnels:
            redfish_protocol = "https" if bmc_use_https else "http"
            redfish_success, bound_redfish_port, redfish_msg = (
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
                    local_ports=self._candidate_ports(redfish_port),
                    remote_tcp_protocol=redfish_protocol,
                    force_setup=force_setup,
                    tunnel_config=dict(forwarding_tunnel_config),
                )
            )

            if redfish_success:
                redfish_port = int(bound_redfish_port)
                tunnel_info["redfish_port"] = redfish_port
                tunnel_info["tunnels"]["redfish"] = {
                    "local_port": redfish_port,
                    "remote_host": bmc_ip,
                    "remote_port": bmc_redfish_port,
                    "protocol": redfish_protocol,
                }
                created_tunnel_types.append("redfish")
                success_count += 1
                self.active_tunnels[dut_id] = tunnel_info
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

        # Setup BMC SSH tunnel
        if "bmc_ssh" in requested_tunnels and "bmc_ssh" not in existing_tunnels:
            bmc_ssh_success, bound_bmc_ssh_port, bmc_ssh_msg = (
                await self.port_forwarding_service.setup_port_forwarding(
                    dut_id=dut_id,
                    ssh_server_ip=ssh_proxy_host,
                    ssh_username=ssh_proxy_username,
                    ssh_password=ssh_proxy_password,
                    destination_server_ip=bmc_ip,
                    ssh_port=ssh_proxy_port,
                    ssh_key_path=ssh_proxy_key_path,
                    ssh_passwordless=ssh_proxy_passwordless,
                    remote_port=target_bmc_ssh_port,
                    local_ports=self._candidate_ports(bmc_ssh_port),
                    remote_tcp_protocol="tcp",
                    force_setup=force_setup,
                    tunnel_config=dict(forwarding_tunnel_config),
                )
            )

            if bmc_ssh_success:
                bmc_ssh_port = int(bound_bmc_ssh_port)
                tunnel_info["bmc_ssh_port"] = bmc_ssh_port
                tunnel_info["tunnels"]["bmc_ssh"] = {
                    "local_port": bmc_ssh_port,
                    "remote_host": bmc_ip,
                    "remote_port": target_bmc_ssh_port,
                    "protocol": "tcp",
                }
                created_tunnel_types.append("bmc_ssh")
                success_count += 1
                self.active_tunnels[dut_id] = tunnel_info
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "SSHProxyService",
                    f"BMC SSH tunnel established: localhost:{bmc_ssh_port} -> {bmc_ip}:{target_bmc_ssh_port} via {ssh_proxy_host}",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "SSHProxyService",
                    f"Failed to establish BMC SSH tunnel: {bmc_ssh_msg}",
                )

        # Setup Host SSH tunnel (separate from BMC SSH)
        if "host_ssh" in requested_tunnels and "host_ssh" not in existing_tunnels:
            host_ssh_success, bound_host_ssh_port, host_ssh_msg = (
                await self.port_forwarding_service.setup_port_forwarding(
                    dut_id=dut_id,
                    ssh_server_ip=ssh_proxy_host,
                    ssh_username=ssh_proxy_username,
                    ssh_password=ssh_proxy_password,
                    destination_server_ip=host_ip,
                    ssh_port=ssh_proxy_port,
                    ssh_key_path=ssh_proxy_key_path,
                    ssh_passwordless=ssh_proxy_passwordless,
                    remote_port=target_host_ssh_port,
                    local_ports=self._candidate_ports(host_ssh_port),
                    remote_tcp_protocol="tcp",
                    force_setup=force_setup,
                    tunnel_config=dict(forwarding_tunnel_config),
                )
            )

            if host_ssh_success:
                host_ssh_port = int(bound_host_ssh_port)
                tunnel_info["host_ssh_port"] = host_ssh_port
                tunnel_info["tunnels"]["host_ssh"] = {
                    "local_port": host_ssh_port,
                    "remote_host": host_ip,
                    "remote_port": target_host_ssh_port,
                    "protocol": "tcp",
                }
                created_tunnel_types.append("host_ssh")
                success_count += 1
                self.active_tunnels[dut_id] = tunnel_info
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "SSHProxyService",
                    f"Host SSH tunnel established: localhost:{host_ssh_port} -> {host_ip}:{target_host_ssh_port} via {ssh_proxy_host}",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "SSHProxyService",
                    f"Failed to establish Host SSH tunnel: {host_ssh_msg}",
                )

        expected_count = len(requested_tunnels)
        if expected_count and success_count == expected_count:
            self.active_tunnels[dut_id] = tunnel_info
            tunnel_ports_dict = {
                "redfish_port": redfish_port,
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

        # A partially configured proxy changes transport behavior in surprising
        # ways. Roll back only tunnels this service successfully created.
        for tunnel_type in created_tunnel_types:
            tunnel_details = tunnel_info["tunnels"][tunnel_type]
            killed = await self.port_forwarding_service.kill_port_forwarding(
                dut_id=dut_id,
                ssh_server_ip=ssh_proxy_host,
                destination_server_ip=tunnel_details["remote_host"],
                port=tunnel_details["local_port"],
            )
            if killed:
                tunnel_info["tunnels"].pop(tunnel_type, None)

        if tunnel_info["tunnels"]:
            self.active_tunnels[dut_id] = tunnel_info
        else:
            self.active_tunnels.pop(dut_id, None)
        return False, {}, "Failed to establish the complete SSH proxy tunnel set"

    async def get_tunnel_connection_info(self, dut_id: str) -> Dict[str, Any]:
        """
        Get connection info for tunnels (similar to HMC get_connection_info).

        Preserve compatibility with tunnel records created before
        transport-specific ownership metadata was introduced.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing tunnel connection info.
        """
        if dut_id not in self.active_tunnels:
            return {}

        tunnel_info = self.active_tunnels[dut_id]
        tracked_tunnels = tunnel_info.get("tunnels")
        if not isinstance(tracked_tunnels, dict):
            # Preserve compatibility with tunnel records created before
            # transport-specific ownership metadata was introduced.
            tracked_tunnels = {
                tunnel_type: {}
                for tunnel_type, port_name in (
                    ("redfish", "redfish_port"),
                    ("bmc_ssh", "bmc_ssh_port"),
                    ("host_ssh", "host_ssh_port"),
                )
                if tunnel_info.get(port_name) is not None
            }
            if (
                "bmc_ssh" not in tracked_tunnels
                and tunnel_info.get("ssh_port") is not None
            ):
                tracked_tunnels["bmc_ssh"] = {}

        connection_info: Dict[str, Any] = {}
        if "redfish" in tracked_tunnels:
            protocol = tracked_tunnels["redfish"].get("protocol", "https")
            connection_info["redfish"] = {
                "host": "localhost",
                "port": tunnel_info.get("redfish_port"),
                "use_https": protocol == "https",
                "protocol": protocol,
            }
        if "bmc_ssh" in tracked_tunnels:
            bmc_ssh_port = tunnel_info.get("bmc_ssh_port", tunnel_info.get("ssh_port"))
            bmc_ssh_info = {
                "host": "localhost",
                "port": bmc_ssh_port,
                "protocol": "tcp",
            }
            connection_info["ssh"] = dict(bmc_ssh_info)
            connection_info["bmc_ssh"] = bmc_ssh_info
        if "host_ssh" in tracked_tunnels:
            connection_info["host_ssh"] = {
                "host": "localhost",
                "port": tunnel_info.get("host_ssh_port"),
                "protocol": "tcp",
            }

        return connection_info

    async def cleanup_tunnels(self, dut_id: str) -> bool:
        """
        Serialize cleanup with setup mutations for the same DUT.

        After applying local validation, the function forwards ``dut_id`` to
        ``self._cleanup_tunnels_unlocked`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            Whether the serialize cleanup with setup mutations for the same DUT
            operation succeeds.
        """

        lock = self._setup_locks.setdefault(str(dut_id), asyncio.Lock())
        async with lock:
            return await self._cleanup_tunnels_unlocked(dut_id)

    async def _cleanup_tunnels_unlocked(self, dut_id: str) -> bool:
        """
        Clean up SSH proxy tunnels for a DUT.

        The implementation uses ``dut_id`` to clean up SSH proxy tunnels for a
        DUT. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            Whether the clean up SSH proxy tunnels for a DUT operation succeeds.
        """
        if dut_id not in self.active_tunnels:
            if not self.port_forwarding_service:
                return True
            await self.port_forwarding_service.cleanup_all_tunnels(dut_id)
            return not any(
                tunnel.get("dut_id") == dut_id
                for tunnel in self.port_forwarding_service.active_tunnels.values()
            )

        tunnel_info = self.active_tunnels[dut_id]
        success = True

        # Clean up each tunnel
        for tunnel_type, tunnel_details in list(tunnel_info["tunnels"].items()):
            try:
                if self.port_forwarding_service:
                    killed = await self.port_forwarding_service.kill_port_forwarding(
                        dut_id=dut_id,
                        ssh_server_ip=tunnel_info["proxy_host"],
                        destination_server_ip=tunnel_details["remote_host"],
                        port=tunnel_details["local_port"],
                    )
                    if killed:
                        tunnel_info["tunnels"].pop(tunnel_type, None)
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
                            f"Owned cleanup refused or failed for {tunnel_type} tunnel on port {tunnel_details['local_port']}",
                        )
                        success = False
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

        if self.port_forwarding_service:
            await self.port_forwarding_service.cleanup_all_tunnels(dut_id)
            residual_owned_tunnels = any(
                tunnel.get("dut_id") == dut_id
                for tunnel in self.port_forwarding_service.active_tunnels.values()
            )
            if not residual_owned_tunnels:
                # The exact-owner sweep is authoritative.  A foreground child
                # can exit between the targeted kill and the residual sweep;
                # do not leave phantom transport metadata in that race.
                tunnel_info["tunnels"].clear()
                self.active_tunnels.pop(dut_id, None)
                return True
            success = False
        elif not tunnel_info["tunnels"]:
            self.active_tunnels.pop(dut_id, None)
        return success

    def cleanup_tunnels_sync(self, dut_id: str) -> bool:
        """
        Exact proxy cleanup after the originating event loop has closed.

        The implementation uses ``dut_id`` to exact proxy cleanup after the
        originating event loop has closed.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            Whether the exact proxy cleanup after the originating event loop has
            closed operation succeeds.
        """

        tunnel_info = self.active_tunnels.get(dut_id)
        if not tunnel_info:
            if not self.port_forwarding_service:
                return True
            return self.port_forwarding_service.cleanup_all_tunnels_sync(dut_id)
        if not self.port_forwarding_service:
            return False

        for tunnel_type, tunnel_details in list(tunnel_info["tunnels"].items()):
            killed = self.port_forwarding_service.kill_port_forwarding_sync(
                dut_id=dut_id,
                ssh_server_ip=tunnel_info["proxy_host"],
                destination_server_ip=tunnel_details["remote_host"],
                port=tunnel_details["local_port"],
            )
            if killed:
                tunnel_info["tunnels"].pop(tunnel_type, None)
        self.port_forwarding_service.cleanup_all_tunnels_sync(dut_id)
        residual_owned_tunnels = any(
            tunnel.get("dut_id") == dut_id
            for tunnel in self.port_forwarding_service.active_tunnels.values()
        )
        if residual_owned_tunnels:
            return False
        tunnel_info["tunnels"].clear()
        self.active_tunnels.pop(dut_id, None)
        return True

    async def _find_available_ports(
        self, dut_id: str, count: int
    ) -> Optional[List[int]]:
        """
        Find available local ports for tunneling.

        Search from current_port onwards, ensuring no overlap with previously
        found ports.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            count: Numeric count used by the operation's bounded accounting.

        Returns:
            The validated ``ports``, or ``None`` when no value qualifies.
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
        host_key_policy: str = "insecure",
        known_hosts_file: Optional[str] = None,
    ) -> bool:
        """
        Test SSH proxy connection with credentials to avoid hanging.

        Use port forwarding service's dut_manager to execute the test command.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            ssh_proxy_host: Text supplied as SSH proxy host in the format
                accepted by this function.
            ssh_proxy_port: Numeric SSH proxy port used while the operation
                performs bounded accounting.
            ssh_proxy_username: Text supplied as SSH proxy username in the
                format accepted by this function.
            ssh_proxy_password: Sensitive value supplied through the approved
                input boundary and never logged.
            ssh_proxy_key_path: Optional filesystem location used as the SSH
                proxy key path for this operation.
            ssh_proxy_passwordless: Sensitive value supplied through the
                approved input boundary and never logged.
            host_key_policy: Host key policy governing test SSH proxy connection
                with credentials to avoid hanging.
            known_hosts_file: Optional filesystem location used as the known
                hosts file for this operation.

        Returns:
            Whether the test SSH proxy connection with credentials to avoid
            hanging operation succeeds.
        """
        try:
            test_cmd = self._build_ssh_proxy_test_command(
                ssh_proxy_host=ssh_proxy_host,
                ssh_proxy_port=ssh_proxy_port,
                ssh_proxy_username=ssh_proxy_username,
                ssh_proxy_password=ssh_proxy_password,
                ssh_proxy_key_path=ssh_proxy_key_path,
                ssh_proxy_passwordless=ssh_proxy_passwordless,
                host_key_policy=host_key_policy,
                known_hosts_file=known_hosts_file,
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
                    test_cmd,
                    timeout=15,
                    use_shell=False,
                    input_val=(
                        f"{ssh_proxy_password}\n"
                        if not (ssh_proxy_key_path or ssh_proxy_passwordless)
                        else None
                    ),
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
        host_key_policy: str = "insecure",
        known_hosts_file: Optional[str] = None,
    ) -> List[str]:
        """
        Build the SSH proxy connection-test command for the selected auth mode.

        The implementation uses ``ssh_proxy_host``, ``ssh_proxy_port``,
        ``ssh_proxy_username``, ``ssh_proxy_password``, and
        ``ssh_proxy_key_path`` to build the SSH proxy connection-test command
        for the selected auth mode.

        Args:
            ssh_proxy_host: Text supplied as SSH proxy host in the format
                accepted by this function.
            ssh_proxy_port: Numeric SSH proxy port used while the operation
                performs bounded accounting.
            ssh_proxy_username: Text supplied as SSH proxy username in the
                format accepted by this function.
            ssh_proxy_password: Sensitive value supplied through the approved
                input boundary and never logged.
            ssh_proxy_key_path: Optional filesystem location used as the SSH
                proxy key path for this operation.
            ssh_proxy_passwordless: Sensitive value supplied through the
                approved input boundary and never logged.
            host_key_policy: Host key policy governing SSH proxy connection-test
                command for the selected auth mode.
            known_hosts_file: Optional filesystem location used as the known
                hosts file for this operation.

        Returns:
            The SSH proxy test command returned in operation-defined order.
        """
        base_options = [
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
            *shlex.split(openssh_host_key_options(host_key_policy, known_hosts_file)),
            "-o",
            "LogLevel=ERROR",
        ]
        destination = f"{ssh_proxy_username}@{ssh_proxy_host}"

        if ssh_proxy_key_path:
            ssh_invocation = [
                "ssh",
                *base_options,
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-i",
                str(ssh_proxy_key_path),
            ]
        elif ssh_proxy_passwordless:
            ssh_invocation = [
                "ssh",
                *base_options,
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ]
        else:
            # Do NOT use BatchMode=yes for password mode: it can prevent
            # keyboard-interactive auth, which sshpass can otherwise satisfy.
            ssh_invocation = [
                "sshpass",
                "-d",
                "0",
                "ssh",
                *base_options,
                "-o",
                "PreferredAuthentications=keyboard-interactive,password",
            ]

        return [
            *ssh_invocation,
            "-p",
            str(int(ssh_proxy_port)),
            "--",
            destination,
            "echo",
            "SSH_PROXY_TEST_SUCCESS",
        ]
