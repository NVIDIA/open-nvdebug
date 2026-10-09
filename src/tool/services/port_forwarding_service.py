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
import re
import shlex
import signal
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..utils.managed_filesystem import run_managed_filesystem_operation
from ..utils.secret_env import scrubbed_subprocess_environment
from ..utils.ssh_security import (
    DEFAULT_SSH_TUNNEL_PREFIX,
    normalize_ssh_tunnel_prefix,
    resolve_ssh_tunnel_options,
)
from ..utils.ssh_tunnel_takeover import stop_matching_ssh_listener

logger = logging.getLogger(__name__)

# This token is emitted only for an explicit empty/"*" TUNNEL_LOCAL_HOST;
# the configured default remains loopback-only ("localhost").
_IPV4_WILDCARD = "0.0.0.0"  # nosec B104
_IPV6_WILDCARD = "::"


class PortForwardingService:
    """
    Service for managing port forwarding connections.

    The type coordinates ``_registry_host``, ``_socket_endpoints``,
    ``_reservation_conflicts``, ``_route_uses_ipv6_literal``, and
    ``_reserve_local_port`` and retains the state those operations share between
    calls. Resource ownership remains inside the instance until the matching
    close, exit, or cleanup operation completes.
    """

    _SAFE_SSH_OPTIONS = frozenset(
        {
            "addressfamily",
            "batchmode",
            "compression",
            "connecttimeout",
            "connectionattempts",
            "ciphers",
            "exitonforwardfailure",
            "hostkeyalgorithms",
            "identitiesonly",
            "identityagent",
            "kbdinteractiveauthentication",
            "kexalgorithms",
            "loglevel",
            "macs",
            "passwordauthentication",
            "preferredauthentications",
            "pubkeyacceptedalgorithms",
            "serveralivecountmax",
            "serveraliveinterval",
            "stricthostkeychecking",
            "tcpkeepalive",
            "userknownhostsfile",
        }
    )
    _SAFE_SSH_FLAGS = frozenset({"4", "6", "f", "N", "n", "T"})
    _PORT_REGISTRY_LOCK = threading.Lock()
    _RESERVED_PORTS: Dict[Tuple[str, int], str] = {}
    _READINESS_POLL_INTERVAL = 0.05
    _TERMINATE_TIMEOUT = 5.0

    def __init__(self, logger=None, dut_manager=None):
        """
        Initialize the Port Forwarding Service.

        The initializer records ``active_tunnels``, ``dut_manager``, and
        ``logger`` for later operations and establishes the instance invariants
        before any public method runs.

        Args:
            logger: Sanitized logger used for operator-visible diagnostics.
            dut_manager: Optional DUT manager; ``None`` selects the function's
                default behavior.
        """
        self.active_tunnels = {}  # Track active port forwarding sessions
        self.logger = logger
        self.dut_manager = dut_manager

    @staticmethod
    def _registry_host(local_host: str) -> str:
        """
        Normalize equivalent local bind spellings for reservations.

        The implementation uses ``local_host`` to normalize equivalent local
        bind spellings for reservations. The source value keeps its ownership
        while the normalized representation is returned separately.

        Args:
            local_host: Text supplied as local host in the format accepted by
                this function.

        Returns:
            The canonical registry host text.
        """

        normalized = str(local_host or "").strip()
        if normalized.startswith("[") and normalized.endswith("]"):
            normalized = normalized[1:-1]
        if normalized in {"localhost", "127.0.0.1"}:
            return "127.0.0.1"
        if normalized in {"", "*"}:
            return _IPV4_WILDCARD
        return normalized

    @classmethod
    def _socket_endpoints(
        cls, local_host: str, port: int, *, for_connect: bool
    ) -> List[Tuple[int, int, int, Any]]:
        """
        Resolve family-aware bind or readiness-probe socket endpoints.

        The implementation uses ``local_host``, ``port``, and ``for_connect`` to
        resolve family-aware bind or readiness-probe socket endpoints.

        Args:
            local_host: Text supplied as local host in the format accepted by
                this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            for_connect: Whether for connect is enabled or required for this
                operation.

        Returns:
            The validated ``endpoints``.
        """

        normalized_host = cls._registry_host(local_host)
        if for_connect:
            if normalized_host == _IPV4_WILDCARD:
                normalized_host = "127.0.0.1"
            elif normalized_host == _IPV6_WILDCARD:
                normalized_host = "::1"

        endpoints: List[Tuple[int, int, int, Any]] = []
        seen = set()
        for family, socket_type, protocol, _, socket_address in socket.getaddrinfo(
            normalized_host,
            int(port),
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        ):
            endpoint_key = (family, socket_type, protocol, socket_address)
            if endpoint_key in seen:
                continue
            seen.add(endpoint_key)
            endpoints.append((family, socket_type, protocol, socket_address))
        return endpoints

    @classmethod
    def _reservation_conflicts(cls, local_host: str, port: int) -> bool:
        """
        Return whether an equivalent or wildcard reservation already exists.

        The implementation uses ``local_host`` and ``port`` to determine whether
        an equivalent or wildcard reservation already exists.

        Args:
            local_host: Text supplied as local host in the format accepted by
                this function.
            port: Numeric port used while the operation performs bounded
                accounting.

        Returns:
            Whether an equivalent or wildcard reservation already exists.
        """

        wildcard_hosts = {_IPV4_WILDCARD, _IPV6_WILDCARD}
        registry_host = cls._registry_host(local_host)
        for (reserved_host, reserved_port), _ in cls._RESERVED_PORTS.items():
            if reserved_port != int(port):
                continue
            if (
                reserved_host == registry_host
                or reserved_host in wildcard_hosts
                or registry_host in wildcard_hosts
            ):
                return True
        return False

    @classmethod
    def _route_uses_ipv6_literal(cls, *hosts: Optional[str]) -> bool:
        """
        Return whether any SSH route endpoint is an IPv6 literal.

        After applying local validation, the function forwards ``hosts`` to
        ``any`` and preserves its return and exception contract.

        Args:
            hosts: Additional positional values forwarded in caller-provided
                order.

        Returns:
            Whether any SSH route endpoint is an IPv6 literal.
        """

        return any(
            ":" in cls._registry_host(host) for host in hosts if host is not None
        )

    @classmethod
    def _reserve_local_port(cls, local_host: str, port: int, owner_token: str) -> bool:
        """
        Atomically reserve a free local port within this NVDebug process.

        The implementation uses ``local_host``, ``port``, and ``owner_token`` to
        atomically reserve a free local port within this NVDebug process.

        Args:
            local_host: Text supplied as local host in the format accepted by
                this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            owner_token: Text supplied as owner token in the format accepted by
                this function.

        Returns:
            Whether the atomically reserve a free local port within this NVDebug
            process operation succeeds.
        """

        registry_key = (cls._registry_host(local_host), int(port))
        with cls._PORT_REGISTRY_LOCK:
            if cls._reservation_conflicts(local_host, port):
                return False

            try:
                endpoints = cls._socket_endpoints(
                    local_host, int(port), for_connect=False
                )
                if not endpoints:
                    return False
                for family, socket_type, protocol, socket_address in endpoints:
                    with socket.socket(family, socket_type, protocol) as probe:
                        probe.bind(socket_address)
            except (OSError, socket.gaierror):
                return False

            cls._RESERVED_PORTS[registry_key] = owner_token
            return True

    @classmethod
    def _release_local_port(cls, local_host: str, port: int, owner_token: str) -> None:
        """
        Release only the caller's own in-process port reservation.

        The implementation uses ``local_host``, ``port``, and ``owner_token`` to
        release only the caller's own in-process port reservation.

        Args:
            local_host: Text supplied as local host in the format accepted by
                this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            owner_token: Text supplied as owner token in the format accepted by
                this function.
        """

        registry_key = (cls._registry_host(local_host), int(port))
        with cls._PORT_REGISTRY_LOCK:
            if cls._RESERVED_PORTS.get(registry_key) == owner_token:
                del cls._RESERVED_PORTS[registry_key]

    @staticmethod
    def _read_process_start_time(pid: int) -> Optional[str]:
        """
        Return Linux's immutable process start tick for PID reuse protection.

        The implementation uses ``pid`` to produce Linux's immutable process
        start tick for PID reuse protection.

        Args:
            pid: Numeric process identifier used while the operation performs
                bounded accounting.

        Returns:
            The canonical process start time text, or ``None`` when the
            requested value is unavailable.
        """

        try:
            fields = Path(f"/proc/{int(pid)}/stat").read_text(encoding="utf-8").split()
        except (OSError, ValueError):
            return None
        return fields[21] if len(fields) > 21 else None

    @classmethod
    def _snapshot_process_group(cls, pgid: int) -> Dict[int, str]:
        """
        Capture immutable identities for live members of one process group.

        The command name is parenthesized and may itself contain spaces, so
        fields after the final ')' are the stable split.

        Args:
            pgid: Numeric process-group identifier used while the operation
                performs bounded accounting.

        Returns:
            A mapping containing snapshot process group.
        """

        members: Dict[int, str] = {}
        try:
            proc_entries = list(Path("/proc").iterdir())
        except OSError:
            return members
        for proc_entry in proc_entries:
            if not proc_entry.name.isdigit():
                continue
            try:
                stat_text = (proc_entry / "stat").read_text(encoding="utf-8")
                # The command name is parenthesized and may itself contain
                # spaces, so fields after the final ')' are the stable split.
                stat_fields = stat_text[stat_text.rfind(")") + 2 :].split()
                state = stat_fields[0]
                process_group = int(stat_fields[2])
                start_time = stat_fields[19]
            except (IndexError, OSError, ValueError):
                continue
            if state != "Z" and process_group == int(pgid):
                members[int(proc_entry.name)] = start_time
        return members

    @staticmethod
    def _process_group_exists(pgid: int) -> bool:
        """
        Check process-group existence without delivering a signal.

        Permission failures still prove that the group exists. Other
        indeterminate errors fail closed and retain ownership metadata.

        Args:
            pgid: Numeric process-group identifier used while the operation
                performs bounded accounting.

        Returns:
            Whether the process-group existence without delivering a signal
            operation succeeds.
        """

        try:
            os.killpg(int(pgid), 0)
        except ProcessLookupError:
            return False
        except (OSError, ValueError):
            # Permission failures still prove that the group exists.  Other
            # indeterminate errors fail closed and retain ownership metadata.
            return True
        return True

    async def _start_tunnel_process(
        self, argv: List[str], password_input: Optional[str]
    ) -> asyncio.subprocess.Process:
        """
        Start a foreground tunnel in its own process group.

        Password material is written through stdin and never appears in argv.

        Args:
            argv: Entries supplied as ``argv`` without transferring container
                ownership.
            password_input: Sensitive value supplied through the approved input
                boundary and never logged.

        Returns:
            The validated ``process``.
        """

        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=(
                asyncio.subprocess.PIPE
                if password_input is not None
                else asyncio.subprocess.DEVNULL
            ),
            # A tunnel is long-lived and has no output contract. Piped output
            # can fill an asyncio buffer and block SSH indefinitely after the
            # readiness check returns, so discard it at the OS boundary.
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
            env=scrubbed_subprocess_environment(),
        )
        if password_input is not None and process.stdin is not None:
            try:
                process.stdin.write(password_input.encode("utf-8"))
                await process.stdin.drain()
                process.stdin.close()
            except BaseException:
                try:
                    os.killpg(int(process.pid), signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
                try:
                    await asyncio.shield(process.wait())
                except BaseException:
                    pass
                raise
        return process

    async def _wait_for_tunnel_ready(
        self,
        process: asyncio.subprocess.Process,
        local_host: str,
        port: int,
        timeout: float,
        pgid: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Wait until the owned process is listening or exits.

        Confirm ownership remains stable for another scheduling turn.

        Args:
            process: Process object whose ``communicate``, ``pid``, and
                ``returncode`` state is read while performing wait until the
                owned process is listening or exits.
            local_host: Text supplied as local host in the format accepted by
                this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            pgid: Optional process-group identifier; ``None`` selects the
                function's default behavior.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """

        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(float(timeout), 0.0)
        while loop.time() < deadline:
            if process.returncode is not None:
                _, stderr = await process.communicate()
                if isinstance(stderr, bytes) and stderr:
                    return False, stderr.decode("utf-8", errors="replace")
                return False, "SSH tunnel exited before becoming ready"

            if (
                await self._check_port_in_use(port, local_host=local_host)
                and pgid is not None
                and self._listener_owned_by_process_group(
                    int(process.pid), int(pgid), int(port)
                )
            ):
                # Confirm ownership remains stable for another scheduling turn.
                await asyncio.sleep(self._READINESS_POLL_INTERVAL)
                if (
                    process.returncode is None
                    and self._listener_owned_by_process_group(
                        int(process.pid), int(pgid), int(port)
                    )
                ):
                    return True, ""

            await asyncio.sleep(self._READINESS_POLL_INTERVAL)

        return False, f"timed out waiting for local port {port}"

    @staticmethod
    def _listening_socket_inodes(port: int) -> set[str]:
        """
        Read Linux TCP tables for listener socket inodes on one port.

        The implementation uses ``port`` to read Linux TCP tables for listener
        socket inodes on one port. Parsing or I/O must finish before the
        validated representation is made available to the caller.

        Args:
            port: Numeric port used while the operation performs bounded
                accounting.

        Returns:
            The validated ``inodes``.
        """

        inodes: set[str] = set()
        expected_port = f"{int(port):04X}"
        for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
            try:
                lines = table.read_text(encoding="utf-8").splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) <= 9 or fields[3] != "0A":
                    continue
                local_address = fields[1]
                if local_address.rsplit(":", 1)[-1].upper() == expected_port:
                    inodes.add(fields[9])
        return inodes

    @classmethod
    def _listener_owned_by_process_group(
        cls, leader_pid: int, pgid: int, port: int
    ) -> bool:
        """
        Prove that a listener fd belongs to the tracked launcher tree.

        ``sshpass`` supervises an ``ssh`` child that creates its own session and
        process group for the pseudo-terminal. The launcher's process group
        therefore anchors ownership, while the listener may belong to any live
        descendant in that exact process tree.

        Args:
            leader_pid: Numeric leader process identifier used while the
                operation performs bounded accounting.
            pgid: Numeric process-group identifier used while the operation
                performs bounded accounting.
            port: Numeric port used while the operation performs bounded
                accounting.

        Returns:
            Whether the prove that a listener fd belongs to the tracked launcher
            tree operation succeeds.
        """

        listening_inodes = cls._listening_socket_inodes(port)
        if not listening_inodes:
            return False

        try:
            if os.getpgid(int(leader_pid)) != int(pgid):
                return False
        except (OSError, ProcessLookupError):
            return False

        pending = [int(leader_pid)]
        seen: set[int] = set()
        owned_inodes: set[str] = set()
        while pending:
            pid = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)

            children_path = Path(f"/proc/{pid}/task/{pid}/children")
            try:
                pending.extend(
                    int(child)
                    for child in children_path.read_text(encoding="utf-8").split()
                )
            except (OSError, ValueError):
                pass

            fd_path = Path(f"/proc/{pid}/fd")
            try:
                descriptors = list(fd_path.iterdir())
            except OSError:
                continue
            for descriptor in descriptors:
                try:
                    target = os.readlink(descriptor)
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    owned_inodes.add(target[8:-1])

        return bool(listening_inodes.intersection(owned_inodes))

    def _owned_process_matches(self, tunnel_info: Dict[str, Any]) -> bool:
        """
        Verify the exact tracked process, group, and start identity.

        The implementation uses ``tunnel_info`` to verify the exact tracked
        process, group, and start identity. Every required invariant is checked
        before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            tunnel_info: Mapping supplying fields for exact tracked process,
                group, and start identity.

        Returns:
            Whether the exact tracked process, group, and start identity
            operation succeeds.
        """

        process = tunnel_info.get("process")
        pid = tunnel_info.get("pid")
        pgid = tunnel_info.get("pgid")
        if process is None or pid is None or pgid is None:
            return False
        if getattr(process, "pid", None) != pid or process.returncode is not None:
            return False
        try:
            if os.getpgid(pid) != pgid:
                return False
        except (OSError, ProcessLookupError):
            return False

        expected_start = tunnel_info.get("process_start_time")
        if expected_start is None:
            return False
        return self._read_process_start_time(pid) == expected_start

    def _owned_process_group_matches(self, tunnel_info: Dict[str, Any]) -> bool:
        """
        Verify the leader or a previously recorded member of the owned group.

        The implementation uses ``tunnel_info`` to verify the leader or a
        previously recorded member of the owned group. Every required invariant
        is checked before a successful value is returned; invalid input follows
        the function's explicit exception path.

        Args:
            tunnel_info: Mapping supplying fields for leader or a previously
                recorded member of the owned group.

        Returns:
            Whether the leader or a previously recorded member of the owned
            group operation succeeds.
        """

        if self._owned_process_matches(tunnel_info):
            return True
        pgid = tunnel_info.get("pgid")
        tracked_members = tunnel_info.get("process_group_start_times")
        if pgid is None or not isinstance(tracked_members, dict):
            return False
        for raw_pid, expected_start in tracked_members.items():
            try:
                pid = int(raw_pid)
                if os.getpgid(pid) != int(pgid):
                    continue
            except (OSError, ProcessLookupError, ValueError):
                continue
            if self._read_process_start_time(pid) == expected_start:
                return True
        return False

    def _owned_process_has_exited(self, tunnel_info: Dict[str, Any]) -> bool:
        """
        Return true only when the complete tracked process group is gone.

        The implementation uses ``tunnel_info`` to produce true only when the
        complete tracked process group is gone.

        Args:
            tunnel_info: Mapping supplying fields for true only when the
                complete tracked process group is gone.

        Returns:
            Whether the true only when the complete tracked process group is
            gone operation succeeds.
        """

        pgid = tunnel_info.get("pgid")
        if pgid is None:
            return False
        return not self._process_group_exists(int(pgid))

    async def _wait_for_process_group_exit(
        self, tunnel_info: Dict[str, Any], timeout: float
    ) -> bool:
        """
        Wait for the complete owned group, including sshpass children, to exit.

        The implementation uses ``tunnel_info`` and ``timeout`` to wait for the
        complete owned group, including sshpass children, to exit. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            tunnel_info: Mapping supplying fields for wait for the complete
                owned group, including sshpass children, to exit.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.

        Returns:
            Whether the wait for the complete owned group, including sshpass
            children, to exit operation succeeds.
        """

        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(float(timeout), 0.0)
        while loop.time() < deadline:
            if self._owned_process_has_exited(tunnel_info):
                return True
            await asyncio.sleep(self._READINESS_POLL_INTERVAL)
        return self._owned_process_has_exited(tunnel_info)

    async def _stop_owned_tunnel_info(self, tunnel_info: Dict[str, Any]) -> bool:
        """
        Terminate only a tunnel whose exact owned identity still matches.

        The implementation uses ``tunnel_info`` to terminate only a tunnel whose
        exact owned identity still matches. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Cleanup in the ``finally`` path runs for successful, failed, and
        cancelled execution.

        Args:
            tunnel_info: Mapping supplying fields for terminate only a tunnel
                whose exact owned identity still matches.

        Returns:
            Whether the terminate only a tunnel whose exact owned identity still
            matches operation succeeds.
        """

        local_host = tunnel_info.get("local_host", "localhost")
        port = tunnel_info.get("port")
        owner_token = tunnel_info.get("owner_token")
        stopped = False
        try:
            if not self._owned_process_group_matches(tunnel_info):
                stopped = self._owned_process_has_exited(tunnel_info)
            else:
                process = tunnel_info["process"]
                pgid = int(tunnel_info["pgid"])
                current_members = self._snapshot_process_group(pgid)
                if current_members:
                    tunnel_info["process_group_start_times"] = current_members
                os.killpg(pgid, signal.SIGTERM)
                try:
                    await asyncio.wait_for(
                        process.wait(), timeout=self._TERMINATE_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    pass
                stopped = await self._wait_for_process_group_exit(
                    tunnel_info, self._TERMINATE_TIMEOUT
                )
                if not stopped and self._owned_process_group_matches(tunnel_info):
                    os.killpg(pgid, signal.SIGKILL)
                    stopped = await self._wait_for_process_group_exit(
                        tunnel_info, self._TERMINATE_TIMEOUT
                    )
        except ProcessLookupError:
            stopped = self._owned_process_has_exited(tunnel_info)
        except OSError:
            stopped = False
        finally:
            if stopped and port is not None and owner_token:
                self._release_local_port(local_host, port, owner_token)
        return stopped

    def _stop_owned_tunnel_info_sync(self, tunnel_info: Dict[str, Any]) -> bool:
        """
        Exact cleanup usable after the originating asyncio loop is closed.

        The implementation uses ``tunnel_info`` to exact cleanup usable after
        the originating asyncio loop is closed. Cleanup in the ``finally`` path
        runs for successful, failed, and cancelled execution.

        Args:
            tunnel_info: Mapping supplying fields for exact cleanup usable after
                the originating asyncio loop is closed.

        Returns:
            Whether the exact cleanup usable after the originating asyncio loop
            is closed operation succeeds.
        """

        local_host = tunnel_info.get("local_host", "localhost")
        port = tunnel_info.get("port")
        owner_token = tunnel_info.get("owner_token")
        stopped = False
        try:
            if not self._owned_process_group_matches(tunnel_info):
                stopped = self._owned_process_has_exited(tunnel_info)
            else:
                pgid = int(tunnel_info["pgid"])
                current_members = self._snapshot_process_group(pgid)
                if current_members:
                    tunnel_info["process_group_start_times"] = current_members
                os.killpg(pgid, signal.SIGTERM)
                deadline = time.monotonic() + self._TERMINATE_TIMEOUT
                while time.monotonic() < deadline:
                    if self._owned_process_has_exited(tunnel_info):
                        stopped = True
                        break
                    time.sleep(self._READINESS_POLL_INTERVAL)
                if not stopped and self._owned_process_group_matches(tunnel_info):
                    os.killpg(pgid, signal.SIGKILL)
                    deadline = time.monotonic() + self._TERMINATE_TIMEOUT
                    while time.monotonic() < deadline:
                        if self._owned_process_has_exited(tunnel_info):
                            stopped = True
                            break
                        time.sleep(self._READINESS_POLL_INTERVAL)
        except ProcessLookupError:
            stopped = self._owned_process_has_exited(tunnel_info)
        except OSError:
            stopped = False
        finally:
            if stopped and port is not None and owner_token:
                self._release_local_port(local_host, port, owner_token)
        return stopped

    async def setup_port_forwarding(
        self,
        dut_id: str,
        ssh_server_ip: str,
        ssh_username: str,
        ssh_password: Optional[str],
        destination_server_ip: str,
        ssh_port: int = 22,
        ssh_key_path: Optional[str] = None,
        ssh_passwordless: bool = False,
        remote_port: Optional[int] = None,
        local_ports: list = None,
        remote_tcp_protocol: str = "https",
        force_setup: bool = False,
        timeout: Optional[int] = None,
        tunnel_config: Optional[Dict[str, Any]] = None,
        host_key_alias: Optional[str] = None,
    ) -> Tuple[bool, Optional[int], str]:
        """
        Setup port forwarding using SSH tunnel.

        The implementation uses ``dut_id``, ``ssh_server_ip``, ``ssh_username``,
        ``ssh_password``, and ``destination_server_ip`` to setup port forwarding
        using SSH tunnel. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. If the function
        cannot setup port forwarding using SSH tunnel, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            ssh_server_ip: Text supplied as SSH server IP in the format accepted
                by this function.
            ssh_username: Text supplied as SSH username in the format accepted
                by this function.
            ssh_password: Sensitive value supplied through the approved input
                boundary and never logged.
            destination_server_ip: Text supplied as destination server IP in the
                format accepted by this function.
            ssh_port: Numeric SSH port used while the operation performs bounded
                accounting.
            ssh_key_path: Optional filesystem location used as the SSH key path
                for this operation.
            ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            remote_port: Optional remote port; ``None`` selects the function's
                default behavior.
            local_ports: Optional local ports; ``None`` selects the function's
                default behavior.
            remote_tcp_protocol: Text supplied as remote TCP protocol in the
                format accepted by this function.
            force_setup: Replace an exactly tracked tunnel or a verified matching
                same-user SSH listener from another run. Arbitrary listeners and
                shared SSH connections are never terminated.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            tunnel_config: Optional Tunnel config governing setup port
                forwarding using SSH tunnel.
            host_key_alias: Optional host key alias; ``None`` selects the
                function's default behavior.

        Returns:
            A tuple containing ``success flag``, ``integer count``, and ``status
            or message text`` in that order.

        Raises:
            RuntimeError: If could not establish immutable SSH tunnel process
                identity.
        """
        try:
            local_ports = list(local_ports or [18888])
            if remote_port is None:
                remote_port = 443 if remote_tcp_protocol == "https" else 80
            if not ssh_username:
                return False, None, "SSH username not configured"
            if not (ssh_key_path or ssh_passwordless or ssh_password):
                return (
                    False,
                    None,
                    "SSH password, key path, or passwordless auth required for port forwarding",
                )

            tunnel_config = dict(tunnel_config or {})
            local_host = tunnel_config.get("TUNNEL_LOCAL_HOST", "localhost")
            ssh_options = resolve_ssh_tunnel_options(
                tunnel_config.get("SSH_TUNNEL_OPTIONS"),
                tunnel_config.get("ssh_host_key_policy", "insecure"),
                tunnel_config.get("ssh_known_hosts_file"),
                force_ipv4=not self._route_uses_ipv6_literal(
                    local_host,
                    ssh_server_ip,
                    destination_server_ip,
                ),
            )
            ssh_prefix = normalize_ssh_tunnel_prefix(
                tunnel_config.get("SSH_TUNNEL_PREFIX", DEFAULT_SSH_TUNNEL_PREFIX)
            )
            effective_host_key_alias = (
                host_key_alias
                if host_key_alias is not None
                else tunnel_config.get("ssh_host_key_alias")
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "PortForwardingService",
                f"Setting up owned port forwarding: {ssh_username}@{ssh_server_ip}:{ssh_port} -> {destination_server_ip}:{remote_port}",
            )

            last_error = ""
            for raw_port in local_ports:
                port = int(raw_port)
                tunnel_key = f"{ssh_server_ip}:{destination_server_ip}:{port}"
                owner_token = (
                    f"{id(self)}:{dut_id}:{ssh_server_ip}:"
                    f"{destination_server_ip}:{remote_port}:{port}:"
                    f"{uuid.uuid4().hex}"
                )

                if force_setup and tunnel_key in self.active_tunnels:
                    killed = await self.kill_port_forwarding(
                        dut_id, ssh_server_ip, destination_server_ip, port
                    )
                    if not killed:
                        last_error = (
                            f"refused to replace {tunnel_key}: tracked process "
                            "identity no longer matches"
                        )
                        continue

                ssh_cmd = self._build_ssh_tunnel_command(
                    ssh_server_ip=ssh_server_ip,
                    ssh_username=ssh_username,
                    ssh_password=ssh_password,
                    destination_server_ip=destination_server_ip,
                    ssh_port=ssh_port,
                    ssh_key_path=ssh_key_path,
                    ssh_passwordless=ssh_passwordless,
                    local_host=local_host,
                    local_port=port,
                    remote_port=remote_port,
                    ssh_options=ssh_options,
                    ssh_prefix=ssh_prefix,
                    host_key_alias=effective_host_key_alias,
                )

                reserved = self._reserve_local_port(local_host, port, owner_token)
                if (
                    not reserved
                    and force_setup
                    and not self._reservation_conflicts(local_host, port)
                ):
                    stop_event = threading.Event()
                    ssh_argv = ssh_cmd[ssh_cmd.index("ssh") :]
                    stopped = await run_managed_filesystem_operation(
                        stop_matching_ssh_listener,
                        ssh_argv,
                        port,
                        self._TERMINATE_TIMEOUT,
                        stop_event,
                        cancellation_event=stop_event,
                    )
                    if stopped:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "PortForwardingService",
                            f"Stopped verified matching SSH listener on port {port}; "
                            "establishing a new owned tunnel",
                        )
                        reserved = self._reserve_local_port(
                            local_host, port, owner_token
                        )

                if not reserved:
                    if force_setup:
                        last_error = (
                            f"Local port {port} is unavailable; --force-port-fw "
                            "requires a verified matching SSH tunnel owned by "
                            "this local user. Stop the owning process or select "
                            "a different local port."
                        )
                        await self.logger.write_to_dut_runtime_log(
                            dut_id, "WARNING", "PortForwardingService", last_error
                        )
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "PortForwardingService",
                        f"Local port {port} is reserved or externally occupied; skipping",
                    )
                    continue

                tunnel_info: Optional[Dict[str, Any]] = None
                try:
                    password_input = (
                        f"{ssh_password}\n"
                        if not (ssh_key_path or ssh_passwordless)
                        else None
                    )
                    process = await self._start_tunnel_process(ssh_cmd, password_input)
                    pid = int(process.pid)
                    pgid = os.getpgid(pid)
                    process_start_time = self._read_process_start_time(pid)
                    tunnel_info = {
                        "dut_id": dut_id,
                        "port": port,
                        "local_host": local_host,
                        "argv": tuple(ssh_cmd),
                        "process": process,
                        "pid": pid,
                        "pgid": pgid,
                        "process_start_time": process_start_time,
                        "owner_token": owner_token,
                        "ssh_server_ip": ssh_server_ip,
                        "ssh_port": int(ssh_port),
                        "destination_server_ip": destination_server_ip,
                        "remote_port": remote_port,
                    }
                    if process_start_time is None:
                        os.killpg(pgid, signal.SIGKILL)
                        await process.wait()
                        raise RuntimeError(
                            "Could not establish immutable SSH tunnel process identity"
                        )

                    ready, last_error = await self._wait_for_tunnel_ready(
                        process, local_host, port, timeout or 30, pgid=pgid
                    )
                    if not ready:
                        stopped = await self._stop_owned_tunnel_info(tunnel_info)
                        if not stopped:
                            self.active_tunnels[tunnel_key] = tunnel_info
                            last_error = (
                                f"{last_error}; exact cleanup was refused, "
                                "retaining tunnel ownership for later cleanup"
                            )
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "PortForwardingService",
                            f"Tunnel on port {port} did not become ready: {last_error}",
                        )
                        if not stopped:
                            return False, None, last_error
                        continue

                    group_members = self._snapshot_process_group(pgid)
                    if not group_members:
                        stopped = await self._stop_owned_tunnel_info(tunnel_info)
                        if not stopped:
                            self.active_tunnels[tunnel_key] = tunnel_info
                        return (
                            False,
                            None,
                            "Could not establish immutable SSH tunnel process-group identity",
                        )
                    tunnel_info["process_group_start_times"] = group_members
                    self.active_tunnels[tunnel_key] = tunnel_info
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "PortForwardingService",
                        f"Port forwarding established: {local_host}:{port} -> {destination_server_ip}:{remote_port} (PID {pid}, PGID {pgid})",
                    )
                    return (
                        True,
                        port,
                        f"Port forwarding setup successful via port {port}",
                    )
                except BaseException as exc:
                    cleanup_refused = False
                    if tunnel_info is not None:
                        stopped = await self._stop_owned_tunnel_info(tunnel_info)
                        if not stopped:
                            self.active_tunnels[tunnel_key] = tunnel_info
                            cleanup_refused = True
                    else:
                        self._release_local_port(local_host, port, owner_token)
                    if not isinstance(exc, Exception) or isinstance(exc, ValueError):
                        raise
                    last_error = str(exc)
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PortForwardingService",
                        f"Failed to start owned tunnel on port {port}: {exc}",
                    )
                    if cleanup_refused:
                        return (
                            False,
                            None,
                            f"{exc}; exact cleanup was refused, retaining "
                            "tunnel ownership for later cleanup",
                        )

            suffix = f": {last_error}" if last_error else ""
            return (
                False,
                None,
                "Failed to bind any unoccupied local port for SSH forwarding"
                f"{suffix}",
            )
        except ValueError as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "PortForwardingService",
                f"Invalid SSH tunnel configuration: {e}",
            )
            return False, None, str(e)
        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "PortForwardingService",
                f"Port forwarding setup failed: {str(e)}",
            )
            return False, None, f"Port forwarding setup failed: {str(e)}"

    @classmethod
    def _parse_ssh_options(cls, ssh_options: str) -> List[str]:
        """
        Parse the legacy option string into a constrained SSH argv fragment.

        The implementation uses ``ssh_options`` to parse the legacy option
        string into a constrained SSH argv fragment. Parsing or I/O must finish
        before the validated representation is made available to the caller. If
        the function cannot parse the legacy option string into a constrained
        SSH argv fragment, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            ssh_options: Text supplied as SSH options in the format accepted by
                this function.

        Returns:
            The validated ``parsed``.

        Raises:
            ValueError: If SSH_TUNNEL_OPTIONS contains invalid quoting;
                SSH_TUNNEL_OPTIONS contains an unsupported flag;
                SSH_TUNNEL_OPTIONS has an incomplete -o option; or
                SSH_TUNNEL_OPTIONS accepts SSH flags and -o options only; or
                another input invariant is violated.
        """
        try:
            tokens = shlex.split(ssh_options or "")
        except ValueError as exc:
            raise ValueError("SSH_TUNNEL_OPTIONS contains invalid quoting") from exc

        parsed: List[str] = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token.startswith("-") and not token.startswith("-o"):
                flags = token[1:]
                if not flags or any(flag not in cls._SAFE_SSH_FLAGS for flag in flags):
                    raise ValueError("SSH_TUNNEL_OPTIONS contains an unsupported flag")
                parsed.extend(f"-{flag}" for flag in flags)
                index += 1
                continue

            if token == "-o":
                index += 1
                if index >= len(tokens):
                    raise ValueError("SSH_TUNNEL_OPTIONS has an incomplete -o option")
                option = tokens[index]
            elif token.startswith("-o") and len(token) > 2:
                option = token[2:].removeprefix("=")
            else:
                raise ValueError(
                    "SSH_TUNNEL_OPTIONS accepts SSH flags and -o options only"
                )

            option_name = re.split(r"[=\s]", option, maxsplit=1)[0].lower()
            if option_name not in cls._SAFE_SSH_OPTIONS:
                raise ValueError("SSH_TUNNEL_OPTIONS contains an unsupported option")
            parsed.extend(["-o", option])
            index += 1

        return parsed

    @staticmethod
    def _replace_ssh_option(options: List[str], name: str, value: str) -> List[str]:
        """
        Replace one parsed ``-o`` option without preserving an unsafe override.

        The implementation uses ``options``, ``name``, and ``value`` to replace
        one parsed ``-o`` option without preserving an unsafe override.

        Args:
            options: Entries supplied as ``options`` without transferring
                container ownership.
            name: Stable name used for lookup and operator-facing diagnostics.
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The validated ``replaced``.
        """
        replaced: List[str] = []
        index = 0
        while index < len(options):
            if options[index] == "-o" and index + 1 < len(options):
                option_name = re.split(r"[=\s]", options[index + 1], maxsplit=1)[
                    0
                ].lower()
                if option_name == name.lower():
                    index += 2
                    continue
                replaced.extend(options[index : index + 2])
                index += 2
                continue
            replaced.append(options[index])
            index += 1
        replaced.extend(["-o", f"{name}={value}"])
        return replaced

    @classmethod
    def _password_prefix_argv(cls, ssh_prefix: str) -> List[str]:
        """
        Return the canonical descriptor-safe password prefix argv.

        After applying local validation, the function forwards ``ssh_prefix`` to
        ``split`` and preserves its return and exception contract.

        Args:
            ssh_prefix: Text supplied as SSH prefix in the format accepted by
                this function.

        Returns:
            The password prefix argument vector returned in operation-defined
            order.
        """

        return normalize_ssh_tunnel_prefix(ssh_prefix).split()

    @classmethod
    def _build_ssh_tunnel_command(
        cls,
        ssh_server_ip: str,
        ssh_username: str,
        ssh_password: Optional[str],
        destination_server_ip: str,
        ssh_port: int,
        ssh_key_path: Optional[str],
        ssh_passwordless: bool,
        local_host: str,
        local_port: int,
        remote_port: int,
        ssh_options: str,
        ssh_prefix: str,
        host_key_alias: Optional[str] = None,
    ) -> List[str]:
        """
        Build shell-free argv for a tunnel using the selected authentication mode.

        The service owns the foreground process. Never allow OpenSSH to
        daemonize and sever the process identity needed for exact cleanup.

        Args:
            ssh_server_ip: Text supplied as SSH server IP in the format accepted
                by this function.
            ssh_username: Text supplied as SSH username in the format accepted
                by this function.
            ssh_password: Sensitive value supplied through the approved input
                boundary and never logged.
            destination_server_ip: Text supplied as destination server IP in the
                format accepted by this function.
            ssh_port: Numeric SSH port used while the operation performs bounded
                accounting.
            ssh_key_path: filesystem location used as the SSH key path for this
                operation.
            ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            local_host: Text supplied as local host in the format accepted by
                this function.
            local_port: Numeric local port used while the operation performs
                bounded accounting.
            remote_port: Numeric remote port used while the operation performs
                bounded accounting.
            ssh_options: Text supplied as SSH options in the format accepted by
                this function.
            ssh_prefix: Text supplied as SSH prefix in the format accepted by
                this function.
            host_key_alias: Optional host key alias; ``None`` selects the
                function's default behavior.

        Returns:
            The SSH tunnel command returned in operation-defined order.
        """
        effective_options = cls._parse_ssh_options(ssh_options)
        # The service owns the foreground process. Never allow OpenSSH to
        # daemonize and sever the process identity needed for exact cleanup.
        effective_options = [option for option in effective_options if option != "-f"]
        effective_options = cls._replace_ssh_option(
            effective_options, "ExitOnForwardFailure", "yes"
        )
        if host_key_alias:
            # This value comes from the resolved logical DUT endpoint, not from
            # SSH_TUNNEL_OPTIONS.  The latter deliberately cannot override it.
            effective_options = cls._replace_ssh_option(
                effective_options, "HostKeyAlias", str(host_key_alias)
            )
            effective_options = cls._replace_ssh_option(
                effective_options, "CheckHostIP", "no"
            )
            effective_options = cls._replace_ssh_option(
                effective_options, "NoHostAuthenticationForLocalhost", "no"
            )
        for required_flag in ("-N", "-T"):
            if required_flag not in effective_options:
                effective_options.append(required_flag)

        if ssh_key_path:
            effective_options = cls._replace_ssh_option(
                effective_options, "PreferredAuthentications", "publickey"
            )
            effective_options = cls._replace_ssh_option(
                effective_options, "IdentitiesOnly", "yes"
            )
            effective_options = cls._replace_ssh_option(
                effective_options, "BatchMode", "yes"
            )
            ssh_invocation = ["ssh", *effective_options, "-i", str(ssh_key_path)]
        elif ssh_passwordless:
            effective_options = cls._replace_ssh_option(
                effective_options, "PreferredAuthentications", "publickey"
            )
            effective_options = cls._replace_ssh_option(
                effective_options, "BatchMode", "yes"
            )
            ssh_invocation = ["ssh", *effective_options]
        else:
            ssh_invocation = [
                *cls._password_prefix_argv(ssh_prefix),
                "ssh",
                *effective_options,
            ]

        def forward_host(host: str) -> str:
            """
            Return the forward host.

            The implementation uses ``host`` to produce the forward host.

            Args:
                host: Text supplied as host in the format accepted by this
                    function.

            Returns:
                The canonical forward host text.
            """
            normalized = cls._registry_host(host)
            return f"[{normalized}]" if ":" in normalized else normalized

        forward = (
            f"{forward_host(local_host)}:{int(local_port)}:"
            f"{forward_host(destination_server_ip)}:{int(remote_port)}"
        )
        return [
            *ssh_invocation,
            "-L",
            forward,
            "-p",
            str(int(ssh_port)),
            "--",
            f"{ssh_username}@{ssh_server_ip}",
        ]

    async def kill_port_forwarding(
        self,
        dut_id: str,
        ssh_server_ip: str,
        destination_server_ip: str,
        port: Optional[int] = None,
    ) -> bool:
        """
        Kill port forwarding tunnel.

        The implementation uses ``dut_id``, ``ssh_server_ip``,
        ``destination_server_ip``, and ``port`` to kill port forwarding tunnel.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            ssh_server_ip: Text supplied as SSH server IP in the format accepted
                by this function.
            destination_server_ip: Text supplied as destination server IP in the
                format accepted by this function.
            port: Optional port; ``None`` selects the function's default
                behavior.

        Returns:
            Whether the kill port forwarding tunnel operation succeeds.
        """
        try:
            matching = []
            for tunnel_key, tunnel_info in self.active_tunnels.items():
                if (
                    tunnel_info.get("dut_id") == dut_id
                    and tunnel_info.get("ssh_server_ip") == ssh_server_ip
                    and tunnel_info.get("destination_server_ip")
                    == destination_server_ip
                    and (port is None or tunnel_info.get("port") == int(port))
                ):
                    matching.append((tunnel_key, tunnel_info))

            killed_count = 0
            for tunnel_key, tunnel_info in matching:
                if await self._stop_owned_tunnel_info(tunnel_info):
                    self.active_tunnels.pop(tunnel_key, None)
                    killed_count += 1
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "PortForwardingService",
                        f"Stopped owned tunnel {tunnel_key}",
                    )
                else:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PortForwardingService",
                        f"Refused to stop tunnel {tunnel_key}: tracked process identity no longer matches",
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

    def kill_port_forwarding_sync(
        self,
        dut_id: str,
        ssh_server_ip: str,
        destination_server_ip: str,
        port: Optional[int] = None,
    ) -> bool:
        """
        Synchronous exact cleanup for shutdown after an event loop closes.

        The implementation uses ``dut_id``, ``ssh_server_ip``,
        ``destination_server_ip``, and ``port`` to synchronous exact cleanup for
        shutdown after an event loop closes.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            ssh_server_ip: Text supplied as SSH server IP in the format accepted
                by this function.
            destination_server_ip: Text supplied as destination server IP in the
                format accepted by this function.
            port: Optional port; ``None`` selects the function's default
                behavior.

        Returns:
            Whether the synchronous exact cleanup for shutdown after an event
            loop closes operation succeeds.
        """

        matching = []
        for tunnel_key, tunnel_info in self.active_tunnels.items():
            if (
                tunnel_info.get("dut_id") == dut_id
                and tunnel_info.get("ssh_server_ip") == ssh_server_ip
                and tunnel_info.get("destination_server_ip") == destination_server_ip
                and (port is None or tunnel_info.get("port") == int(port))
            ):
                matching.append((tunnel_key, tunnel_info))

        stopped_count = 0
        for tunnel_key, tunnel_info in matching:
            if self._stop_owned_tunnel_info_sync(tunnel_info):
                self.active_tunnels.pop(tunnel_key, None)
                stopped_count += 1
        return stopped_count > 0

    async def _kill_ssh_tunnel_on_port(self, dut_id: str, port: int) -> bool:
        """
        Compatibility wrapper which stops only an exactly tracked tunnel.

        After applying local validation, the function forwards ``dut_id`` and
        ``port`` to ``self._kill_manual_tunnel`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            port: Numeric port used while the operation performs bounded
                accounting.

        Returns:
            Whether the compatibility wrapper which stops only an exactly
            tracked tunnel operation succeeds.
        """

        return await self._kill_manual_tunnel(dut_id, port)

    async def _kill_targeted_tunnel(
        self, dut_id: str, port: int, destination_server_ip: str
    ) -> bool:
        """
        Stop an owned tunnel only when destination and port both match.

        The implementation uses ``dut_id``, ``port``, and
        ``destination_server_ip`` to stop an owned tunnel only when destination
        and port both match. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            port: Numeric port used while the operation performs bounded
                accounting.
            destination_server_ip: Text supplied as destination server IP in the
                format accepted by this function.

        Returns:
            Whether the stop an owned tunnel only when destination and port both
            match operation succeeds.
        """

        for tunnel_key, tunnel_info in list(self.active_tunnels.items()):
            if (
                tunnel_info.get("dut_id") == dut_id
                and tunnel_info.get("port") == int(port)
                and tunnel_info.get("destination_server_ip") == destination_server_ip
            ):
                stopped = await self._stop_owned_tunnel_info(tunnel_info)
                if stopped:
                    self.active_tunnels.pop(tunnel_key, None)
                return stopped
        return False

    async def _kill_manual_tunnel(self, dut_id: str, port: int) -> bool:
        """
        Stop only this service's tracked tunnel on the requested port.

        The implementation uses ``dut_id`` and ``port`` to stop only this
        service's tracked tunnel on the requested port. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            port: Numeric port used while the operation performs bounded
                accounting.

        Returns:
            Whether the stop only this service's tracked tunnel on the requested
            port operation succeeds.
        """

        for tunnel_key, tunnel_info in list(self.active_tunnels.items()):
            if tunnel_info.get("dut_id") == dut_id and tunnel_info.get("port") == int(
                port
            ):
                stopped = await self._stop_owned_tunnel_info(tunnel_info)
                if stopped:
                    self.active_tunnels.pop(tunnel_key, None)
                return stopped
        return False

    async def _check_port_in_use(
        self,
        port: int,
        dut_id: Optional[str] = None,
        local_host: str = "localhost",
    ) -> bool:
        """
        Check if a port is already in use.

        The implementation uses ``port``, ``dut_id``, and ``local_host`` to
        check if a port is already in use. Every required invariant is checked
        before a successful value is returned; invalid input follows the
        function's explicit exception path. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            port: Numeric port used while the operation performs bounded
                accounting.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            local_host: Text supplied as local host in the format accepted by
                this function.

        Returns:
            Whether the if a port is already in use operation succeeds.
        """
        try:
            results = []
            for family, socket_type, protocol, socket_address in self._socket_endpoints(
                local_host, int(port), for_connect=True
            ):
                with socket.socket(family, socket_type, protocol) as probe:
                    probe.settimeout(1)
                    result = probe.connect_ex(socket_address)
                    results.append(result)
                    if result == 0:
                        if dut_id:
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "PortForwardingService",
                                f"Port {port} socket test result: 0 (in use)",
                            )
                        return True
            if dut_id:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "PortForwardingService",
                    f"Port {port} socket test results: {results} (all nonzero=free)",
                )
            return False
        except Exception as e:
            if dut_id:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "PortForwardingService",
                    f"Port {port} socket test exception: {str(e)}",
                )
            return False

    def get_tracked_tunnel_info(
        self,
        dut_id: str,
        ssh_server_ip: str,
        destination_server_ip: str,
        port: int,
    ) -> Optional[Dict[str, Any]]:
        """
        Return the exact tracked forwarding record for one route.

        The implementation uses ``dut_id``, ``ssh_server_ip``,
        ``destination_server_ip``, and ``port`` to produce the exact tracked
        forwarding record for one route.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            ssh_server_ip: Text supplied as SSH server IP in the format accepted
                by this function.
            destination_server_ip: Text supplied as destination server IP in the
                format accepted by this function.
            port: Numeric port used while the operation performs bounded
                accounting.

        Returns:
            The validated ``tunnel_info``, or ``None`` when no value qualifies.
        """

        for tunnel_info in self.active_tunnels.values():
            if (
                tunnel_info.get("dut_id") == dut_id
                and tunnel_info.get("ssh_server_ip") == ssh_server_ip
                and tunnel_info.get("destination_server_ip") == destination_server_ip
                and tunnel_info.get("port") == int(port)
            ):
                return tunnel_info
        return None

    def is_tracked_tunnel_live(
        self,
        dut_id: str,
        ssh_server_ip: str,
        destination_server_ip: str,
        port: int,
    ) -> bool:
        """
        Prove that a tracked route still owns its listener and process.

        The implementation uses ``dut_id``, ``ssh_server_ip``,
        ``destination_server_ip``, and ``port`` to prove that a tracked route
        still owns its listener and process.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            ssh_server_ip: Text supplied as SSH server IP in the format accepted
                by this function.
            destination_server_ip: Text supplied as destination server IP in the
                format accepted by this function.
            port: Numeric port used while the operation performs bounded
                accounting.

        Returns:
            Whether the prove that a tracked route still owns its listener and
            process operation succeeds.
        """

        tunnel_info = self.get_tracked_tunnel_info(
            dut_id,
            ssh_server_ip,
            destination_server_ip,
            port,
        )
        if tunnel_info is None or not self._owned_process_matches(tunnel_info):
            return False
        return self._listener_owned_by_process_group(
            int(tunnel_info["pid"]),
            int(tunnel_info["pgid"]),
            int(tunnel_info["port"]),
        )

    async def cleanup_all_tunnels(self, dut_id: str) -> None:
        """
        Cleanup all active port forwarding tunnels.

        The implementation uses ``dut_id`` to cleanup all active port forwarding
        tunnels. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        try:
            for tunnel_key, tunnel_info in list(self.active_tunnels.items()):
                if tunnel_info.get("dut_id") != dut_id:
                    continue
                try:
                    stopped = await self._stop_owned_tunnel_info(tunnel_info)
                    if stopped:
                        self.active_tunnels.pop(tunnel_key, None)
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "PortForwardingService",
                            f"Cleaned up tunnel: {tunnel_key}",
                        )
                    else:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "PortForwardingService",
                            f"Refused cleanup for {tunnel_key}: tracked process identity no longer matches",
                        )
                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PortForwardingService",
                        f"Failed to cleanup tunnel {tunnel_key}: {str(e)}",
                    )

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "PortForwardingService",
                f"Error during tunnel cleanup: {str(e)}",
            )

    def cleanup_all_tunnels_sync(self, dut_id: str) -> bool:
        """
        Clean up owned tunnels without awaiting loop-bound Process objects.

        The implementation uses ``dut_id`` to clean up owned tunnels without
        awaiting loop-bound Process objects.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            Whether the clean up owned tunnels without awaiting loop-bound
            Process objects operation succeeds.
        """

        success = True
        found = False
        for tunnel_key, tunnel_info in list(self.active_tunnels.items()):
            if tunnel_info.get("dut_id") != dut_id:
                continue
            found = True
            if self._stop_owned_tunnel_info_sync(tunnel_info):
                self.active_tunnels.pop(tunnel_key, None)
            else:
                success = False
        return success if found else True

    def get_active_tunnels(self) -> dict:
        """
        Get information about active tunnels.

        After applying local validation, the function forwards current instance
        state to ``self.active_tunnels.copy`` and preserves its return and
        exception contract.

        Returns:
            A mapping containing active tunnels.
        """
        return self.active_tunnels.copy()
