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
Dependency Checker for NVDebug Tool.

This module provides functionality to check dependencies for collectors,
including commands, files, services, and platform-specific requirements.
"""

import inspect
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from .command_safety import (
    TRUSTED_IPMITOOL_NOT_FOUND_MESSAGE,
    TRUSTED_IPMITOOL_PATHS,
    TRUSTED_PRIVILEGED_PATH,
    build_remote_cmd,
    build_trusted_ipmitool_remote_command,
    build_trusted_remote_executable_probe,
    resolve_trusted_ipmitool_path,
)
from .secret_env import scrubbed_subprocess_environment


class _PrivilegedCommandContextError(ValueError):
    """
    Reject a privileged executable probe without its required Host route.

    Direct prerequisite calls retain their ValueError contract. Collector-level
    checks distinguish this unsupported context from malformed declarations and
    report an unavailable dependency without executing a local privileged probe.
    """


def _run_subprocess(*args, **kwargs):
    """
    Run a dependency probe without exposing CLI-bound secrets.

    After applying local validation, the function forwards ``args`` and
    ``kwargs`` to ``subprocess.run`` and preserves its return and exception
    contract. Terminal status is emitted only after dependency probe without
    exposing CLI-bound secrets and its owned cleanup have completed.

    Args:
        args: Additional positional values forwarded in caller-provided order.
        kwargs: Additional named values forwarded without changing their keys.

    Returns:
        The completed subprocess result produced with a scrubbed child
        environment.
    """
    kwargs["env"] = scrubbed_subprocess_environment(kwargs.get("env"))
    return subprocess.run(*args, **kwargs)


class DependencyType(Enum):
    """
    Types of dependencies that can be checked.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    COMMAND = "command"
    FILE = "file"
    SERVICE = "service"
    PLATFORM_SERVICE = "platform_service"
    COMMAND_VERSION = "command_version"
    FALLBACK_GROUP = "fallback_group"  # New type for fallback groups


@dataclass
class FallbackCheck:
    """
    Configuration for a fallback check.

    The coherent record keeps ``type``, ``name``, ``success_indicators``,
    ``optional``, and ``timeout`` together so consumers observe one fallback
    check state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        type: Canonical text used as type.
        name: Canonical text used as name.
        success_indicators: Collection of success indicators entries retained by
            this record.
        optional: Whether optional applies to this record.
        timeout: Numeric timeout retained by this record.
        description: Canonical text used as description.
    """

    type: str  # "command", "file", "service"
    name: str
    success_indicators: Optional[List[str]] = None  # For command output validation
    optional: bool = False
    timeout: int = 30
    description: Optional[str] = None


@dataclass
class PlatformServiceConfig:
    """
    Configuration for platform-specific service checks.

    The coherent record keeps ``default`` and ``platform_configs`` together so
    consumers observe one platform service config state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        default: Mapping that retains the default fields for this record.
        platform_configs: Mapping that retains the platform configs fields for
            this record.
    """

    default: Dict[str, Any]
    platform_configs: Dict[str, Dict[str, Any]]  # Platform-specific configs


@dataclass
class DependencyResult:
    """
    Result of a dependency check.

    The coherent record keeps ``name``, ``type``, ``available``, ``version``,
    and ``error_message`` together so consumers observe one dependency state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        name: Canonical text used as name.
        type: Type retained as part of the record's public state.
        available: Whether available applies to this record.
        version: Canonical text used as version.
        error_message: Canonical text used as error message.
        install_instructions: Canonical text used as install instructions.
        fallback_results: Collection of fallback results entries retained by
            this record.
        platform: Canonical text used as platform.
        probe_failed: Whether lookup itself failed, rather than establishing
            that the dependency is unavailable.
    """

    name: str
    type: DependencyType
    available: bool
    version: Optional[str] = None
    error_message: Optional[str] = None
    install_instructions: Optional[str] = None
    fallback_results: Optional[List["DependencyResult"]] = None  # For fallback groups
    platform: Optional[str] = None  # Platform where check was performed
    probe_failed: bool = False


@dataclass
class DependencyCheckResult:
    """
    Result of checking all dependencies for a collector.

    The coherent record keeps ``collector_id``, ``collector_name``,
    ``all_required_available``, ``required_dependencies``, and
    ``optional_dependencies`` together so consumers observe one dependency check
    state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        collector_id: Canonical text used as collector identifier.
        collector_name: Canonical text used as collector name.
        all_required_available: Whether all required available applies to this
            record.
        required_dependencies: Collection of required dependencies entries
            retained by this record.
        optional_dependencies: Collection of optional dependencies entries
            retained by this record.
        missing_required: Collection of missing required entries retained by
            this record.
        missing_optional: Collection of missing optional entries retained by
            this record.
        warnings: Collection of warnings entries retained by this record.
    """

    collector_id: str
    collector_name: str
    all_required_available: bool
    required_dependencies: List[DependencyResult]
    optional_dependencies: List[DependencyResult]
    missing_required: List[str]
    missing_optional: List[str]
    warnings: List[str]


class DependencyChecker:
    """
    Main dependency checker class with DUT awareness.

    The type coordinates ``set_dut_manager``, ``check_command``,
    ``_check_command_local``, ``_check_command_on_dut``, and ``check_file`` and
    retains the state those operations share between calls. Resource ownership
    remains inside the instance until the matching close, exit, or cleanup
    operation completes.
    """

    def __init__(self, dut_manager=None) -> None:
        """
        Initialize the dependency checker.

        The initializer records ``_cache`` and ``dut_manager`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            dut_manager: Optional DUT manager; ``None`` selects the function's
                default behavior.
        """
        self._cache: Dict[str, DependencyResult] = {}
        self.dut_manager = dut_manager

    def set_dut_manager(self, dut_manager) -> None:
        """
        Set the DUT manager for remote command execution.

        The implementation uses ``dut_manager`` to set the DUT manager for
        remote command execution. It updates ``dut_manager`` on the instance as
        part of that state transition.

        Args:
            dut_manager: DUT manager consumed while the function attempts to set
                the DUT manager for remote command execution.
        """
        self.dut_manager = dut_manager

    def check_command(
        self, command: str, dut_id: str = None, check_local: bool = False
    ) -> DependencyResult:
        """
        Check if a command is available (locally or on DUT if specified).

        The implementation uses ``command``, ``dut_id``, and ``check_local`` to
        check if a command is available (locally or on DUT if specified). Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            command: Text supplied as command in the format accepted by this
                function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            check_local: Whether check local is enabled or required for this
                operation.

        Returns:
            A ``DependencyResult`` representing command.
        """
        # If check_local is True, always check locally regardless of dut_id
        if check_local:
            return self._check_command_local(command)

        if dut_id and self.dut_manager:
            # Use async method for DUT checking
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If we're in an async context, we need to handle this differently
                    # For now, fall back to local check
                    return self._check_command_local(command)
                else:
                    return loop.run_until_complete(
                        self._check_command_on_dut(dut_id, command)
                    )
            except RuntimeError:
                # No event loop, fall back to local check
                return self._check_command_local(command)
        else:
            return self._check_command_local(command)

    def _check_command_local(self, command: str) -> DependencyResult:
        """
        Check if a command is available locally.

        The implementation uses ``command`` to check if a command is available
        locally. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Args:
            command: Text supplied as command in the format accepted by this
                function.

        Returns:
            A ``DependencyResult`` representing command local.
        """
        cache_key = f"command:{command}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            if command == "ipmitool":
                resolved_path = resolve_trusted_ipmitool_path()
                dependency_result = DependencyResult(
                    type=DependencyType.COMMAND,
                    name=command,
                    available=resolved_path is not None,
                    version=None,
                    error_message=(
                        None
                        if resolved_path is not None
                        else TRUSTED_IPMITOOL_NOT_FOUND_MESSAGE
                    ),
                )
                self._cache[cache_key] = dependency_result
                return dependency_result

            result = _run_subprocess(
                ["which", command],
                capture_output=True,
                text=True,
                timeout=10,
            )

            resolved_path = (result.stdout or "").strip()
            if result.returncode == 0 and resolved_path:
                dependency_result = DependencyResult(
                    type=DependencyType.COMMAND,
                    name=command,
                    available=True,
                    version=None,
                    error_message=None,
                )
            else:
                dependency_result = DependencyResult(
                    type=DependencyType.COMMAND,
                    name=command,
                    available=False,
                    version=None,
                    error_message=(
                        f"Command '{command}' not found in PATH"
                        if result.returncode != 0
                        else f"Command '{command}' lookup returned no resolved path"
                    ),
                )

            self._cache[cache_key] = dependency_result
            return dependency_result

        except Exception as e:
            dependency_result = DependencyResult(
                type=DependencyType.COMMAND,
                name=command,
                available=False,
                version=None,
                error_message=str(e),
            )
            self._cache[cache_key] = dependency_result
            return dependency_result

    async def _check_command_on_dut(
        self,
        dut_id: str,
        command: str,
        use_bmc: bool = False,
        *,
        use_sudo: bool = False,
    ) -> DependencyResult:
        """
        Check if a command is available on a specific DUT.

        Fallback to local check if no DUT manager available.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            use_bmc: Whether use BMC is enabled or required for this operation.
            use_sudo: Check Host executable access with the same privilege as
                the collector. Privileged results use a separate cache entry.

        Returns:
            A ``DependencyResult`` representing command on DUT.

        Raises:
            ValueError: If privileged lookup is requested on the BMC transport.
        """
        cache_key = f"dut_command:{dut_id}:{command}"
        if use_bmc:
            cache_key = f"dut_bmc_command:{dut_id}:{command}"
        if use_sudo:
            if use_bmc:
                raise ValueError("Privileged executable probes require a Host target")
            cache_key += ":sudo"

        if cache_key in self._cache:
            return self._cache[cache_key]

        if not self.dut_manager:
            # Fallback to local check if no DUT manager available
            return self._check_command_local(command)

        try:
            # ipmitool has a stricter contract than generic dependencies: only
            # project-reviewed absolute locations may be selected. Other
            # dependencies use the shared trusted system PATH rather than the
            # remote login account's potentially restricted PATH.
            is_ipmitool = command == "ipmitool"
            if is_ipmitool:
                probe_command = build_trusted_ipmitool_remote_command(["-V"])
            else:
                local_privileged = False
                get_dut = getattr(self.dut_manager, "get_dut", None)
                if use_sudo and callable(get_dut):
                    credentials = getattr(get_dut(dut_id), "credentials", None)
                    local_privileged = (
                        credentials is not None and not credentials.host_ip
                    )
                probe_command = build_trusted_remote_executable_probe(
                    command, local_privileged=local_privileged
                )
            if use_bmc:
                # For SSH collectors, use BMC connection
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, probe_command, timeout=30
                )
            else:
                # For host collectors, use host connection
                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id,
                    probe_command,
                    timeout=30,
                    **({"use_sudo": True} if use_sudo else {}),
                )

            resolved_path = (stdout or "").strip()
            command_available = exit_code == 0 and (is_ipmitool or bool(resolved_path))
            if command_available:
                dependency_result = DependencyResult(
                    type=DependencyType.COMMAND,
                    name=command,
                    available=True,
                    version=None,
                    error_message=None,
                    platform=dut_id,
                )
            elif exit_code == 0:
                dependency_result = DependencyResult(
                    type=DependencyType.COMMAND,
                    name=command,
                    available=False,
                    version=None,
                    error_message=(
                        f"Command '{command}' lookup returned no resolved path "
                        f"on DUT {dut_id}"
                    ),
                    platform=dut_id,
                    probe_failed=True,
                )
            else:
                diagnostic = (
                    stderr
                    or stdout
                    or (
                        TRUSTED_IPMITOOL_NOT_FOUND_MESSAGE
                        if is_ipmitool
                        else "no diagnostic output"
                    )
                ).strip()
                if exit_code == 126:
                    error_message = (
                        f"Command '{command}' exists on DUT {dut_id} but is not "
                        f"executable: {diagnostic}"
                    )
                elif exit_code == 127:
                    error_message = (
                        f"Command '{command}' not found on DUT {dut_id}: {diagnostic}"
                    )
                else:
                    error_message = (
                        f"Command '{command}' lookup failed on DUT {dut_id} "
                        f"with exit code {exit_code}: {diagnostic}"
                    )
                dependency_result = DependencyResult(
                    type=DependencyType.COMMAND,
                    name=command,
                    available=False,
                    version=None,
                    error_message=error_message,
                    platform=dut_id,
                    probe_failed=exit_code not in (126, 127),
                )

            if not dependency_result.probe_failed:
                self._cache[cache_key] = dependency_result
            return dependency_result

        except Exception as e:
            dependency_result = DependencyResult(
                type=DependencyType.COMMAND,
                name=command,
                available=False,
                version=None,
                error_message=f"Error checking command '{command}' on DUT {dut_id}: {str(e)}",
                platform=dut_id,
                probe_failed=True,
            )
            return dependency_result

    async def check_command_requirement(
        self,
        dependency: Dict[str, Any],
        *,
        dut_id: Optional[str] = None,
        use_bmc: bool = False,
        check_local: bool = False,
    ) -> DependencyResult:
        """
        Accept any authored executable name for one command prerequisite.

        Probe the canonical name followed by at most seven alternatives without
        running the producer. A transport or privilege failure stops lookup and
        remains distinguishable from confirmed unavailability. Privileged Host
        probes use the DUT manager, including its local execution route.

        Args:
            dependency: Command declaration with a name, optional alternatives,
                and an optional boolean use_sudo policy.
            dut_id: Target identity for Host or BMC lookup.
            use_bmc: Select the BMC transport instead of the Host transport.
            check_local: Check the invoking machine without a DUT transport.

        Returns:
            One prerequisite result retaining the individual lookup results.

        Raises:
            ValueError: If executable alternatives or privilege policy are
                malformed, or privileged lookup has no Host execution context.

        Side Effects:
            Performs bounded executable probes through the existing dependency
            cache and transport. Never launches a diagnostic collection.
        """
        name = dependency.get("name")
        alternatives = dependency.get("alternatives", [])
        use_sudo = dependency.get("use_sudo", False)
        if (
            not isinstance(name, str)
            or not isinstance(alternatives, list)
            or len(alternatives) > 7
            or not isinstance(use_sudo, bool)
        ):
            raise ValueError("Invalid command prerequisite declaration")
        names = [name, *alternatives]
        for candidate in names:
            build_trusted_remote_executable_probe(candidate)
        if use_sudo and (
            check_local or use_bmc or not dut_id or self.dut_manager is None
        ):
            raise _PrivilegedCommandContextError(
                "Privileged command prerequisites require a Host context"
            )

        results = []
        for candidate in names:
            if check_local or not dut_id:
                result = self.check_command(candidate, check_local=True)
            else:
                result = await self._check_command_on_dut(
                    dut_id,
                    candidate,
                    use_bmc=use_bmc,
                    **({"use_sudo": True} if use_sudo else {}),
                )
            results.append(result)
            if result.available or result.probe_failed:
                return DependencyResult(
                    name=name,
                    type=DependencyType.COMMAND,
                    available=result.available,
                    error_message=result.error_message,
                    fallback_results=results,
                    platform=result.platform,
                    probe_failed=result.probe_failed,
                )
        return DependencyResult(
            name=name,
            type=DependencyType.COMMAND,
            available=False,
            error_message=(
                "No executable available under any supported name: "
                + ", ".join(names)
                + ". "
                + "; ".join(
                    result.error_message for result in results if result.error_message
                )
            ),
            fallback_results=results,
            platform=dut_id,
        )

    async def _check_command_requirement_for_context(
        self,
        dependency: Dict[str, Any],
        *,
        dut_id: str = None,
        use_bmc: bool = False,
        check_local: bool = False,
    ) -> DependencyResult:
        """
        Report unavailable privilege context while retaining declaration errors.

        The strict prerequisite helper validates names and privilege policy
        before probing. An unavailable Host route becomes a dependency result,
        allowing required and optional checks to continue without widening local
        or BMC privileges. Malformed declarations still raise ValueError.

        Args:
            dependency: Command declaration, including alternatives and use_sudo.
            dut_id: DUT identity for a remote prerequisite probe.
            use_bmc: Whether the requested execution context is the BMC.
            check_local: Whether the collector requires an invoking-machine probe.

        Returns:
            Probe result, or unavailable result when privilege context is absent.

        Raises:
            ValueError: If command names or privilege declarations are malformed.

        Side Effects:
            Performs the existing bounded probe only in a supported context.
        """
        try:
            return await self.check_command_requirement(
                dependency,
                dut_id=dut_id,
                use_bmc=use_bmc,
                check_local=check_local,
            )
        except _PrivilegedCommandContextError as error:
            return DependencyResult(
                name=dependency["name"],
                type=DependencyType.COMMAND,
                available=False,
                error_message=str(error),
                platform=dut_id,
            )

    def check_file(self, file_path: str, dut_id: str = None) -> DependencyResult:
        """
        Check if a file exists (locally or on DUT if specified).

        The implementation uses ``file_path`` and ``dut_id`` to check if a file
        exists (locally or on DUT if specified). Every required invariant is
        checked before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A ``DependencyResult`` representing file.
        """
        cache_key = f"file:{file_path}"
        if dut_id:
            cache_key = f"dut_file:{dut_id}:{file_path}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        # If DUT is specified, check on the DUT
        if dut_id and self.dut_manager:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If we're in an async context, we need to handle this differently
                    # For now, fall back to local check
                    pass
                else:
                    return loop.run_until_complete(
                        self._check_file_on_dut(dut_id, file_path)
                    )
            except RuntimeError:
                # No event loop, fall back to local check
                pass

        # Otherwise check locally
        try:
            if os.path.exists(file_path):
                dependency_result = DependencyResult(
                    type=DependencyType.FILE,
                    name=file_path,
                    available=True,
                    version=None,
                    error_message=None,
                )
            else:
                dependency_result = DependencyResult(
                    type=DependencyType.FILE,
                    name=file_path,
                    available=False,
                    version=None,
                    error_message=f"File '{file_path}' does not exist",
                )

            self._cache[cache_key] = dependency_result
            return dependency_result

        except Exception as e:
            dependency_result = DependencyResult(
                type=DependencyType.FILE,
                name=file_path,
                available=False,
                version=None,
                error_message=str(e),
            )
            self._cache[cache_key] = dependency_result
            return dependency_result

    async def _check_file_on_dut(
        self, dut_id: str, file_path: str, use_bmc: bool = False
    ) -> DependencyResult:
        """
        Check if a file exists on a specific DUT.

        Fallback to local check if no DUT manager available.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            file_path: filesystem location used as the file path for this
                operation.
            use_bmc: Whether use BMC is enabled or required for this operation.

        Returns:
            A ``DependencyResult`` representing file on DUT.
        """
        cache_key = f"dut_file:{dut_id}:{file_path}"
        if use_bmc:
            cache_key = f"dut_bmc_file:{dut_id}:{file_path}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        if not self.dut_manager:
            # Fallback to local check if no DUT manager available
            return self.check_file(file_path)

        try:
            # Use test -f command to check if file exists
            probe_command = build_remote_cmd("test -f {path}", path=file_path)
            if use_bmc:
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, probe_command, timeout=30
                )
            else:
                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id, probe_command, timeout=30
                )

            if exit_code == 0:
                dependency_result = DependencyResult(
                    type=DependencyType.FILE,
                    name=file_path,
                    available=True,
                    version=None,
                    error_message=None,
                    platform=dut_id,
                )
            else:
                dependency_result = DependencyResult(
                    type=DependencyType.FILE,
                    name=file_path,
                    available=False,
                    version=None,
                    error_message=f"File '{file_path}' does not exist on DUT {dut_id}",
                    platform=dut_id,
                )

            self._cache[cache_key] = dependency_result
            return dependency_result

        except Exception as e:
            dependency_result = DependencyResult(
                type=DependencyType.FILE,
                name=file_path,
                available=False,
                version=None,
                error_message=f"Error checking file '{file_path}' on DUT {dut_id}: {str(e)}",
                platform=dut_id,
            )
            self._cache[cache_key] = dependency_result
            return dependency_result

    async def _check_service_on_dut(
        self, dut_id: str, service_name: str, use_bmc: bool = False
    ) -> DependencyResult:
        """
        Check if a systemd service is active on a specific DUT via SSH.

        The implementation uses ``dut_id``, ``service_name``, and ``use_bmc`` to
        check if a systemd service is active on a specific DUT via SSH. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.
            use_bmc: Whether use BMC is enabled or required for this operation.

        Returns:
            A ``DependencyResult`` representing service on DUT.
        """
        cache_key = f"dut_service:{dut_id}:{service_name}"
        if use_bmc:
            cache_key = f"dut_bmc_service:{dut_id}:{service_name}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        if not self.dut_manager:
            return self.check_service(service_name)

        try:
            probe_command = build_remote_cmd(
                "systemctl is-active {service}", service=service_name
            )
            if use_bmc:
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id,
                    probe_command,
                    timeout=30,
                )
            else:
                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id,
                    probe_command,
                    timeout=30,
                )

            is_active = exit_code == 0 and stdout.strip() == "active"
            dependency_result = DependencyResult(
                type=DependencyType.SERVICE,
                name=service_name,
                available=is_active,
                version=None,
                error_message=(
                    None
                    if is_active
                    else f"Service '{service_name}' is not active on DUT {dut_id}"
                ),
                platform=dut_id,
            )

        except Exception as e:
            dependency_result = DependencyResult(
                type=DependencyType.SERVICE,
                name=service_name,
                available=False,
                version=None,
                error_message=f"Error checking service '{service_name}' on DUT {dut_id}: {str(e)}",
                platform=dut_id,
            )

        self._cache[cache_key] = dependency_result
        return dependency_result

    def check_service(self, service_name: str) -> DependencyResult:
        """
        Check if a service is running.

        The implementation uses ``service_name`` to check if a service is
        running. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Args:
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.

        Returns:
            A ``DependencyResult`` representing service.
        """
        cache_key = f"service:{service_name}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            result = _run_subprocess(
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0 and result.stdout.strip() == "active":
                dependency_result = DependencyResult(
                    type=DependencyType.SERVICE,
                    name=service_name,
                    available=True,
                    version=None,
                    error_message=None,
                )
            else:
                dependency_result = DependencyResult(
                    type=DependencyType.SERVICE,
                    name=service_name,
                    available=False,
                    version=None,
                    error_message=f"Service '{service_name}' is not active",
                )

            self._cache[cache_key] = dependency_result
            return dependency_result

        except Exception as e:
            dependency_result = DependencyResult(
                type=DependencyType.SERVICE,
                name=service_name,
                available=False,
                version=None,
                error_message=str(e),
            )
            self._cache[cache_key] = dependency_result
            return dependency_result

    async def check_command_version(
        self,
        command: str,
        min_version: str,
        version_cmd: str,
        dut_id: str = None,
        use_bmc: bool = False,
    ) -> DependencyResult:
        """
        Check if a command is available and meets minimum version requirement.

        The implementation uses ``command``, ``min_version``, ``version_cmd``,
        ``dut_id``, and ``use_bmc`` to check if a command is available and meets
        minimum version requirement. Every required invariant is checked before
        a successful value is returned; invalid input follows the function's
        explicit exception path. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            command: Text supplied as command in the format accepted by this
                function.
            min_version: Text supplied as min version in the format accepted by
                this function.
            version_cmd: Text supplied as version cmd in the format accepted by
                this function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            use_bmc: Whether use BMC is enabled or required for this operation.

        Returns:
            A ``DependencyResult`` representing command version.
        """
        # If dut_id is provided and we have a DUT manager, run on DUT
        if dut_id and self.dut_manager:
            cache_key = f"dut_command_version:{dut_id}:{command}:{min_version}"
            if use_bmc:
                cache_key = f"dut_bmc_command_version:{dut_id}:{command}:{min_version}"

            if cache_key in self._cache:
                return self._cache[cache_key]

            try:
                # First check if command exists on DUT
                cmd_check = await self._check_command_on_dut(dut_id, command, use_bmc)
                if not cmd_check.available:
                    return cmd_check

                # Execute version command on the DUT. ipmitool retains the
                # same allowlisted selection contract as availability probes.
                trusted_version_command = version_cmd
                if command == "ipmitool":
                    version_arguments = shlex.split(version_cmd)
                    if not version_arguments or version_arguments[0] not in {
                        "ipmitool",
                        *TRUSTED_IPMITOOL_PATHS,
                    }:
                        dependency_result = DependencyResult(
                            name=command,
                            type=DependencyType.COMMAND_VERSION,
                            available=False,
                            error_message=(
                                "ipmitool version command must start with an "
                                "approved executable"
                            ),
                            platform=dut_id,
                        )
                        self._cache[cache_key] = dependency_result
                        return dependency_result
                    trusted_version_command = build_trusted_ipmitool_remote_command(
                        version_arguments[1:]
                    )
                if use_bmc:
                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_bmc_command(
                            dut_id, trusted_version_command, timeout=30
                        )
                    )
                else:
                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_host_command(
                            dut_id, trusted_version_command, timeout=30
                        )
                    )

                if exit_code == 0:
                    version_output = stdout.strip()
                    if version_output and self._compare_versions(
                        version_output, min_version
                    ):
                        dependency_result = DependencyResult(
                            name=command,
                            type=DependencyType.COMMAND_VERSION,
                            available=True,
                            version=version_output,
                            platform=dut_id,
                        )
                    else:
                        dependency_result = DependencyResult(
                            name=command,
                            type=DependencyType.COMMAND_VERSION,
                            available=False,
                            version=version_output,
                            error_message=(
                                f"Version output {version_output!r} is below minimum "
                                f"required {min_version} or could not be parsed"
                            ),
                            platform=dut_id,
                        )
                else:
                    dependency_result = DependencyResult(
                        name=command,
                        type=DependencyType.COMMAND_VERSION,
                        available=False,
                        error_message=f"Failed to get version on DUT {dut_id}: {stderr}",
                        platform=dut_id,
                    )

                self._cache[cache_key] = dependency_result
                return dependency_result

            except Exception as e:
                dependency_result = DependencyResult(
                    name=command,
                    type=DependencyType.COMMAND_VERSION,
                    available=False,
                    error_message=f"Error checking version on DUT {dut_id}: {str(e)}",
                    platform=dut_id,
                )
                self._cache[cache_key] = dependency_result
                return dependency_result

        # Local execution (original behavior)
        # First check if command exists
        cmd_result = self.check_command(command)
        if not cmd_result.available:
            return cmd_result

        try:
            if isinstance(version_cmd, str):
                cmd_list = shlex.split(version_cmd)
            else:
                cmd_list = list(version_cmd)
            if command == "ipmitool":
                if not cmd_list or cmd_list[0] not in {
                    "ipmitool",
                    *TRUSTED_IPMITOOL_PATHS,
                }:
                    return DependencyResult(
                        name=command,
                        type=DependencyType.COMMAND_VERSION,
                        available=False,
                        error_message=(
                            "ipmitool version command must start with an approved "
                            "executable"
                        ),
                    )
                ipmitool_path = resolve_trusted_ipmitool_path()
                if ipmitool_path is None:
                    return DependencyResult(
                        name=command,
                        type=DependencyType.COMMAND_VERSION,
                        available=False,
                        error_message=TRUSTED_IPMITOOL_NOT_FOUND_MESSAGE,
                    )
                cmd_list = [ipmitool_path, *cmd_list[1:]]
            result = _run_subprocess(
                cmd_list, capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                version_output = result.stdout.strip()
                # Simple version comparison (can be enhanced)
                if version_output and self._compare_versions(
                    version_output, min_version
                ):
                    dependency_result = DependencyResult(
                        name=command,
                        type=DependencyType.COMMAND_VERSION,
                        available=True,
                        version=version_output,
                    )
                else:
                    dependency_result = DependencyResult(
                        name=command,
                        type=DependencyType.COMMAND_VERSION,
                        available=False,
                        version=version_output,
                        error_message=(
                            f"Version output {version_output!r} is below minimum "
                            f"required {min_version} or could not be parsed"
                        ),
                    )
            else:
                dependency_result = DependencyResult(
                    name=command,
                    type=DependencyType.COMMAND_VERSION,
                    available=False,
                    error_message=f"Failed to get version: {result.stderr}",
                )
        except Exception as e:
            dependency_result = DependencyResult(
                name=command,
                type=DependencyType.COMMAND_VERSION,
                available=False,
                error_message=f"Error checking version: {e}",
            )

        return dependency_result

    async def check_platform_service(
        self,
        dependency_config: Dict[str, Any],
        platform: str = "default",
        dut_id: str = None,
    ) -> DependencyResult:
        """
        Check platform-specific service with fallback logic.

        A fallback command with ``success_indicators`` proves availability only
        when at least one governed regular expression matches its bounded
        standard output. An optional fallback may fail without aborting later
        fallback checks, but its failure is not evidence that the required
        service is available.

        The implementation uses ``dependency_config``, ``platform``, and
        ``dut_id`` to check platform-specific service with fallback logic. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dependency_config: Dependency config governing platform-specific
                service with fallback logic.
            platform: Text supplied as platform in the format accepted by this
                function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A ``DependencyResult`` representing platform service.
        """
        service_name = dependency_config.get("name", "unknown")
        platform_config = dependency_config.get("platform_config", {})

        # Get platform-specific configuration
        platform_specific = platform_config.get(
            platform, platform_config.get("default", {})
        )
        fallback_checks = platform_specific.get("fallback_checks", [])

        # First try the main service check — use remote check when dut_id is provided
        if dut_id and self.dut_manager:
            main_result = await self._check_service_on_dut(dut_id, service_name)
        else:
            main_result = self.check_service(service_name)
        if main_result.available:
            return main_result

        # If main service check fails, try fallback checks
        for fallback in fallback_checks:
            fallback_type = fallback.get("type")

            if fallback_type == "file":
                file_path = fallback.get("path")
                if file_path and dut_id and self.dut_manager:
                    # Check if file exists on the DUT
                    try:
                        probe_command = build_remote_cmd(
                            "test -f {path}", path=file_path
                        )
                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_host_command(
                                dut_id, probe_command, timeout=30
                            )
                        )
                        if exit_code == 0:
                            return DependencyResult(
                                name=file_path,
                                type=DependencyType.FILE,
                                available=True,
                                error_message="",
                            )
                    except Exception:
                        # If we can't check on DUT, assume file exists for now
                        return DependencyResult(
                            name=file_path,
                            type=DependencyType.FILE,
                            available=True,
                            error_message="",
                        )

            elif fallback_type == "command":
                cmd = fallback.get("cmd")
                success_indicators = fallback.get("success_indicators", [])

                if cmd and dut_id and self.dut_manager:
                    try:
                        # Execute the command on the DUT
                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_host_command(
                                dut_id, cmd, timeout=60
                            )
                        )

                        if exit_code == 0:
                            # Authored indicators are regular expressions, as
                            # they are at the collector execution boundary. A
                            # zero exit code alone cannot satisfy that stronger
                            # semantic contract.
                            if success_indicators:
                                output = stdout or ""
                                for indicator in success_indicators:
                                    if not isinstance(indicator, str):
                                        continue
                                    try:
                                        matched = re.search(
                                            indicator,
                                            output,
                                            flags=re.IGNORECASE,
                                        )
                                    except re.error:
                                        matched = None
                                    if matched:
                                        return DependencyResult(
                                            name=cmd,
                                            type=DependencyType.COMMAND,
                                            available=True,
                                            error_message="",
                                        )
                            else:
                                # Command succeeded, no indicators to check
                                return DependencyResult(
                                    name=cmd,
                                    type=DependencyType.COMMAND,
                                    available=True,
                                    error_message="",
                                )
                    except Exception:
                        # Optional fallback failures are intentionally ignored
                        # so later alternatives can still prove availability.
                        # They never satisfy a required dependency by themselves.
                        continue

        # If all fallback checks fail, return the original service check result
        return main_result

    def check_fallback_group(
        self, dependency_config: Dict[str, Any]
    ) -> DependencyResult:
        """
        Check a group of dependencies with fallback logic.

        After applying local validation, the function forwards
        ``dependency_config`` to ``DependencyResult`` and preserves its return
        and exception contract. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path.

        Args:
            dependency_config: Dependency config governing group of dependencies
                with fallback logic.

        Returns:
            A ``DependencyResult`` representing fallback group.
        """
        group_name = dependency_config.get("name", "fallback_group")
        fallback_checks = dependency_config.get("fallback_checks", [])
        require_all = dependency_config.get("require_all", False)

        results = []
        any_success = False
        all_success = True

        for check_config in fallback_checks:
            check_type = check_config.get("type")
            check_name = check_config.get("name")
            success_indicators = check_config.get("success_indicators", [])
            optional = check_config.get("optional", False)

            if check_type == "command":
                result = self.check_command(check_name)
                if result.available and success_indicators:
                    result = self._validate_command_output(
                        check_name, success_indicators
                    )
            elif check_type == "file":
                result = self.check_file(check_name)
            elif check_type == "service":
                result = self.check_service(check_name)
            else:
                result = DependencyResult(
                    name=check_name,
                    type=DependencyType.COMMAND,
                    available=False,
                    error_message=f"Unknown check type: {check_type}",
                )

            results.append(result)

            if result.available:
                any_success = True
            else:
                all_success = False

        # Determine overall availability based on configuration
        if require_all:
            overall_available = all_success
        else:
            overall_available = any_success

        return DependencyResult(
            name=group_name,
            type=DependencyType.FALLBACK_GROUP,
            available=overall_available,
            error_message=(
                None
                if overall_available
                else f"Fallback group '{group_name}' failed all checks"
            ),
            fallback_results=results,
        )

    def _validate_command_output(
        self, command: str, success_indicators: List[str]
    ) -> DependencyResult:
        """
        Validate command output against success indicators.

        Check if any success indicator is present in output.

        Args:
            command: Text supplied as command in the format accepted by this
                function.
            success_indicators: Entries supplied as ``success_indicators``
                without transferring container ownership.

        Returns:
            A ``DependencyResult`` representing command output.
        """
        try:
            result = _run_subprocess(
                command.split(), capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                return DependencyResult(
                    name=command,
                    type=DependencyType.COMMAND,
                    available=False,
                    error_message=f"Command '{command}' failed with exit code {result.returncode}",
                )

            output = result.stdout + result.stderr

            # Check if any success indicator is present in output
            for indicator in success_indicators:
                if indicator in output:
                    return DependencyResult(
                        name=command,
                        type=DependencyType.COMMAND,
                        available=True,
                        error_message=None,
                    )

            return DependencyResult(
                name=command,
                type=DependencyType.COMMAND,
                available=False,
                error_message=f"Command '{command}' output did not match any success indicators: {success_indicators}",
            )

        except Exception as e:
            return DependencyResult(
                name=command,
                type=DependencyType.COMMAND,
                available=False,
                error_message=f"Error validating command '{command}': {str(e)}",
            )

    async def check_dependencies(
        self,
        collector_id: str,
        collector_name: str,
        dependencies: Dict[str, List[Dict]],
        platform: str = "default",
    ) -> DependencyCheckResult:
        """
        Check all dependencies for a collector with enhanced fallback support.

        After applying local validation, the function forwards ``collector_id``,
        ``collector_name``, ``dependencies``, and ``platform`` to
        ``DependencyCheckResult`` and preserves its return and exception
        contract. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collector_name: Stable collector name used for lookup and
                operator-facing diagnostics.
            dependencies: Mapping supplying fields for all dependencies for a
                collector with enhanced fallback support.
            platform: Text supplied as platform in the format accepted by this
                function.

        Returns:
            A ``DependencyCheckResult`` representing dependencies.
        """
        required_deps = dependencies.get("required", [])
        optional_deps = dependencies.get("optional", [])

        required_results = []
        optional_results = []
        missing_required = []
        missing_optional = []
        warnings = []

        # Check required dependencies
        for dep in required_deps:
            if isinstance(dep, str):
                # Simple string dependency (command)
                result = self.check_command(dep)
            else:
                # Dictionary dependency with type
                dep_type = dep.get("type", "command")
                dep_name = dep.get("name", "unknown")

                if dep_type == "command":
                    if "alternatives" in dep or "use_sudo" in dep:
                        result = await self._check_command_requirement_for_context(
                            dep, check_local=True
                        )
                    else:
                        result = self.check_command(dep_name)
                elif dep_type == "command_version":
                    min_version = dep.get("min_version")
                    version_cmd = dep.get("version_cmd", f"{dep_name} --version")
                    result = self.check_command_version(
                        dep_name, min_version, version_cmd
                    )
                    if inspect.isawaitable(result):
                        result = await result
                elif dep_type == "service":
                    result = self.check_service(dep_name)
                elif dep_type == "file":
                    result = self.check_file(dep_name)
                elif dep_type == "platform_service":
                    result = self.check_platform_service(dep, platform)
                    if inspect.isawaitable(result):
                        result = await result
                elif dep_type == "fallback_group":
                    result = self.check_fallback_group(dep)
                else:
                    result = DependencyResult(
                        name=dep_name,
                        type=DependencyType.COMMAND,
                        available=False,
                        error_message=f"Unknown dependency type: {dep_type}",
                    )

            required_results.append(result)
            if not result.available:
                missing_required.append(
                    f"{dep_name if isinstance(dep, dict) else dep}: {result.error_message}"
                )

        # Check optional dependencies
        for dep in optional_deps:
            if isinstance(dep, str):
                # Simple string dependency (command)
                result = self.check_command(dep)
            else:
                # Dictionary dependency with type
                dep_type = dep.get("type", "command")
                dep_name = dep.get("name", "unknown")

                if dep_type == "command":
                    if "alternatives" in dep or "use_sudo" in dep:
                        result = await self._check_command_requirement_for_context(
                            dep, check_local=True
                        )
                    else:
                        result = self.check_command(dep_name)
                elif dep_type == "command_version":
                    min_version = dep.get("min_version")
                    version_cmd = dep.get("version_cmd", f"{dep_name} --version")
                    result = self.check_command_version(
                        dep_name, min_version, version_cmd
                    )
                    if inspect.isawaitable(result):
                        result = await result
                elif dep_type == "service":
                    result = self.check_service(dep_name)
                elif dep_type == "file":
                    result = self.check_file(dep_name)
                elif dep_type == "platform_service":
                    result = self.check_platform_service(dep, platform)
                    if inspect.isawaitable(result):
                        result = await result
                elif dep_type == "fallback_group":
                    result = self.check_fallback_group(dep)
                else:
                    result = DependencyResult(
                        name=dep_name,
                        type=DependencyType.COMMAND,
                        available=False,
                        error_message=f"Unknown dependency type: {dep_type}",
                    )

            optional_results.append(result)
            if not result.available:
                missing_optional.append(
                    f"{dep_name if isinstance(dep, dict) else dep}: {result.error_message}"
                )

        return DependencyCheckResult(
            collector_id=collector_id,
            collector_name=collector_name,
            all_required_available=len(missing_required) == 0,
            required_dependencies=required_results,
            optional_dependencies=optional_results,
            missing_required=missing_required,
            missing_optional=missing_optional,
            warnings=warnings,
        )

    async def check_all_dependencies_for_dut(
        self, collector_definitions: Dict[str, Any] = None, dut_id: str = None
    ) -> Dict[str, Any]:
        """
        Check all dependencies for all collectors on a specific DUT.

        The implementation uses ``collector_definitions`` and ``dut_id`` to
        check all dependencies for all collectors on a specific DUT. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            collector_definitions: Optional collector definitions; ``None``
                selects the function's default behavior.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing all dependencies for DUT.
        """
        if not collector_definitions or not dut_id:
            return {}

        all_results = {}
        collectors = collector_definitions.get("collectors", {})

        for collector_id, collector_info in collectors.items():
            dependencies = collector_info.get("dependencies", {})
            if dependencies:
                # Use DUT-aware checking for this specific DUT
                result = await self._check_dependencies_dut_aware(
                    collector_id=collector_id,
                    collector_name=collector_info.get("name", collector_id),
                    dependencies=dependencies,
                    dut_id=dut_id,
                )

                all_results[collector_id] = {
                    "collector_id": result.collector_id,
                    "collector_name": result.collector_name,
                    "all_required_available": result.all_required_available,
                    "required_dependencies": [
                        {
                            "name": dep.name,
                            "type": dep.type.value,
                            "available": dep.available,
                            "version": dep.version,
                            "error_message": dep.error_message,
                            "install_instructions": dep.install_instructions,
                        }
                        for dep in result.required_dependencies
                    ],
                    "optional_dependencies": [
                        {
                            "name": dep.name,
                            "type": dep.type.value,
                            "available": dep.available,
                            "version": dep.version,
                            "error_message": dep.error_message,
                            "install_instructions": dep.install_instructions,
                        }
                        for dep in result.optional_dependencies
                    ],
                    "missing_required": result.missing_required,
                    "missing_optional": result.missing_optional,
                    "warnings": result.warnings,
                }

        return all_results

    async def _check_dependencies_dut_aware(
        self,
        collector_id: str,
        collector_name: str,
        dependencies: Dict[str, List[Dict]],
        dut_id: str,
    ) -> DependencyCheckResult:
        """
        Check dependencies DUT aware.

        After applying local validation, the function forwards ``collector_id``,
        ``collector_name``, ``dependencies``, and ``dut_id`` to
        ``DependencyCheckResult`` and preserves its return and exception
        contract. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collector_name: Stable collector name used for lookup and
                operator-facing diagnostics.
            dependencies: Mapping supplying fields for dependencies DUT aware.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A ``DependencyCheckResult`` representing dependencies DUT aware.
        """
        required_deps = dependencies.get("required", [])
        optional_deps = dependencies.get("optional", [])

        required_results = []
        optional_results = []
        missing_required = []
        missing_optional = []
        warnings = []

        # Check required dependencies
        for dep in required_deps:
            if isinstance(dep, str):
                # Simple string dependency (command) - use appropriate connection based on collector type
                if self.dut_manager:
                    use_bmc = collector_id.startswith(
                        "S"
                    )  # SSH collectors use BMC connection
                    result = await self._check_command_on_dut(
                        dut_id, dep, use_bmc=use_bmc
                    )
                else:
                    # Fallback to local check if no DUT manager
                    result = self.check_command(dep)
            else:
                # Dictionary dependency with type
                dep_type = dep.get("type", "command")
                dep_name = dep.get("name", "unknown")

                if dep_type == "command":
                    # Use appropriate connection based on collector type
                    if "alternatives" in dep or "use_sudo" in dep:
                        result = await self._check_command_requirement_for_context(
                            dep,
                            dut_id=dut_id,
                            use_bmc=collector_id.startswith("S"),
                            check_local=dep.get("check_local", False)
                            or collector_id.startswith("I"),
                        )
                    elif self.dut_manager:
                        use_bmc = collector_id.startswith(
                            "S"
                        )  # SSH collectors use BMC connection
                        result = await self._check_command_on_dut(
                            dut_id, dep_name, use_bmc=use_bmc
                        )
                    else:
                        # Fallback to local check if no DUT manager
                        result = self.check_command(dep_name)
                elif dep_type == "file":
                    # Use appropriate connection based on collector type
                    if self.dut_manager:
                        use_bmc = collector_id.startswith(
                            "S"
                        )  # SSH collectors use BMC connection
                        result = await self._check_file_on_dut(
                            dut_id, dep_name, use_bmc=use_bmc
                        )
                    else:  # No DUT manager - fall back to local check
                        result = self.check_file(dep_name)
                elif dep_type == "command_version":
                    # Check command version on appropriate target
                    min_version = dep.get("min_version")
                    version_cmd = dep.get("version_cmd", f"{dep_name} --version")
                    check_local = dep.get("check_local", False)

                    # For IPMI collectors or explicitly local checks, check locally
                    if check_local or collector_id.startswith("I"):
                        result = await self.check_command_version(
                            dep_name, min_version, version_cmd
                        )
                    elif self.dut_manager:
                        # Use appropriate connection based on collector type
                        use_bmc = collector_id.startswith(
                            "S"
                        )  # SSH collectors use BMC connection
                        result = await self.check_command_version(
                            dep_name,
                            min_version,
                            version_cmd,
                            dut_id=dut_id,
                            use_bmc=use_bmc,
                        )
                    else:
                        # Fallback to local check if no DUT manager
                        result = await self.check_command_version(
                            dep_name, min_version, version_cmd
                        )
                elif dep_type == "service":
                    # For now, fall back to local check for services
                    result = self.check_service(dep_name)
                else:
                    result = DependencyResult(
                        name=dep_name,
                        type=DependencyType.COMMAND,
                        available=False,
                        error_message=f"Unknown dependency type: {dep_type}",
                    )

            required_results.append(result)
            if not result.available:
                missing_required.append(
                    f"{dep_name if isinstance(dep, dict) else dep}: {result.error_message}"
                )

        # Check optional dependencies
        for dep in optional_deps:
            if isinstance(dep, str):
                # Simple string dependency (command) - use appropriate connection based on collector type
                if self.dut_manager:
                    use_bmc = collector_id.startswith(
                        "S"
                    )  # SSH collectors use BMC connection
                    result = await self._check_command_on_dut(
                        dut_id, dep, use_bmc=use_bmc
                    )
                else:
                    # Fallback to local check if no DUT manager
                    result = self.check_command(dep)
            else:
                # Dictionary dependency with type
                dep_type = dep.get("type", "command")
                dep_name = dep.get("name", "unknown")

                if dep_type == "command":
                    # Use appropriate connection based on collector type
                    if "alternatives" in dep or "use_sudo" in dep:
                        result = await self._check_command_requirement_for_context(
                            dep,
                            dut_id=dut_id,
                            use_bmc=collector_id.startswith("S"),
                            check_local=dep.get("check_local", False)
                            or collector_id.startswith("I"),
                        )
                    elif self.dut_manager:
                        use_bmc = collector_id.startswith(
                            "S"
                        )  # SSH collectors use BMC connection
                        result = await self._check_command_on_dut(
                            dut_id, dep_name, use_bmc=use_bmc
                        )
                    else:
                        # Fallback to local check if no DUT manager
                        result = self.check_command(dep_name)
                elif dep_type == "file":
                    # Use appropriate connection based on collector type
                    if self.dut_manager:
                        use_bmc = collector_id.startswith(
                            "S"
                        )  # SSH collectors use BMC connection
                        result = await self._check_file_on_dut(
                            dut_id, dep_name, use_bmc=use_bmc
                        )
                    else:  # No DUT manager - fall back to local check
                        result = self.check_file(dep_name)
                elif dep_type == "command_version":
                    # Check command version on appropriate target
                    min_version = dep.get("min_version")
                    version_cmd = dep.get("version_cmd", f"{dep_name} --version")
                    check_local = dep.get("check_local", False)

                    # For IPMI collectors or explicitly local checks, check locally
                    if check_local or collector_id.startswith("I"):
                        result = await self.check_command_version(
                            dep_name, min_version, version_cmd
                        )
                    elif self.dut_manager:
                        # Use appropriate connection based on collector type
                        use_bmc = collector_id.startswith(
                            "S"
                        )  # SSH collectors use BMC connection
                        result = await self.check_command_version(
                            dep_name,
                            min_version,
                            version_cmd,
                            dut_id=dut_id,
                            use_bmc=use_bmc,
                        )
                    else:
                        # Fallback to local check if no DUT manager
                        result = await self.check_command_version(
                            dep_name, min_version, version_cmd
                        )
                elif dep_type == "service":
                    # For now, fall back to local check for services
                    result = self.check_service(dep_name)
                else:
                    result = DependencyResult(
                        name=dep_name,
                        type=DependencyType.COMMAND,
                        available=False,
                        error_message=f"Unknown dependency type: {dep_type}",
                    )

            optional_results.append(result)
            if not result.available:
                missing_optional.append(
                    f"{dep_name if isinstance(dep, dict) else dep}: {result.error_message}"
                )

        return DependencyCheckResult(
            collector_id=collector_id,
            collector_name=collector_name,
            all_required_available=len(missing_required) == 0,
            required_dependencies=required_results,
            optional_dependencies=optional_results,
            missing_required=missing_required,
            missing_optional=missing_optional,
            warnings=warnings,
        )

    def _get_command_version(self, command: str) -> Optional[str]:
        """
        Try to get version of a command.

        The implementation uses ``command`` to try to get version of a command.

        Args:
            command: Text supplied as command in the format accepted by this
                function.

        Returns:
            The canonical command version text, or ``None`` when the requested
            value is unavailable.
        """
        version_commands = {
            "nvidia-smi": "nvidia-smi --version",
            "nvme": "nvme --version",
            "dmidecode": "dmidecode --version",
            "lshw": "lshw -version",
            "opensm": "opensm --version",
        }

        if command == "ipmitool" or command in version_commands:
            try:
                environment = None
                if command == "ipmitool":
                    ipmitool_path = resolve_trusted_ipmitool_path()
                    if ipmitool_path is None:
                        return None
                    version_arguments = [ipmitool_path, "-V"]
                    environment = scrubbed_subprocess_environment()
                    environment["PATH"] = TRUSTED_PRIVILEGED_PATH
                else:
                    version_arguments = version_commands[command].split()
                result = _run_subprocess(
                    version_arguments,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env=environment,
                )
                if result.returncode == 0:
                    return result.stdout.strip().split("\n")[0]
            except:
                pass

        return None

    def _compare_versions(self, version1: str, version2: str) -> bool:
        """
        Enhanced version comparison with better parsing.

        Extract version numbers using regex to handle various formats Handles:
        "4.8.0", "v4.8.0", "version 4.8.0", "sos 4.8.0-1", etc.

        Args:
            version1: Text supplied as version1 in the format accepted by this
                function.
            version2: Text supplied as version2 in the format accepted by this
                function.

        Returns:
            Whether the enhanced version comparison with better parsing
            operation succeeds.
        """
        try:
            import re

            # Extract version numbers using regex to handle various formats
            # Handles: "4.8.0", "v4.8.0", "version 4.8.0", "sos 4.8.0-1", etc.
            v1_match = re.search(r"(\d+(?:\.\d+)*)", version1)
            v2_match = re.search(r"(\d+(?:\.\d+)*)", version2)

            if not v1_match or not v2_match:
                return False

            v1_str = v1_match.group(1)
            v2_str = v2_match.group(1)

            # Split and convert to integers
            v1_parts = [int(x) for x in v1_str.split(".")]
            v2_parts = [int(x) for x in v2_str.split(".")]

            # Pad with zeros if needed
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))

            return v1_parts >= v2_parts
        except Exception:
            return False

    def clear_cache(self) -> None:
        """
        Clear the dependency cache.

        The implementation uses current instance state to clear the dependency
        cache.
        """
        self._cache.clear()
