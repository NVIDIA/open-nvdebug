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
Dependency Checker for NVDebug Tool

This module provides functionality to check dependencies for collectors,
including commands, files, services, and platform-specific requirements.
"""

import inspect
import os
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class DependencyType(Enum):
    """
    Types of dependencies that can be checked.

    Attributes:
        COMMAND: Command dependency
        FILE: File dependency
        SERVICE: Service dependency
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

    Attributes:
        type: Type of the fallback check
        name: Name of the fallback check
        success_indicators: Success indicators for the fallback check
        optional: Whether the fallback check is optional
        timeout: Timeout for the fallback check
        description: Description of the fallback check
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

    Attributes:
        default: Default configuration for the platform
        platform_configs: Platform-specific configurations
    """

    default: Dict[str, Any]
    platform_configs: Dict[str, Dict[str, Any]]  # Platform-specific configs


@dataclass
class DependencyResult:
    """
    Result of a dependency check.

    Attributes:
        name: Name of the dependency
        type: Type of the dependency
        available: Whether the dependency is available
        version: Version of the dependency
        error_message: Error message for the dependency
        install_instructions: Installation instructions for the dependency
        fallback_results: Fallback results for the dependency
        platform: Platform where the dependency was checked
    """

    name: str
    type: DependencyType
    available: bool
    version: Optional[str] = None
    error_message: Optional[str] = None
    install_instructions: Optional[str] = None
    fallback_results: Optional[List["DependencyResult"]] = None  # For fallback groups
    platform: Optional[str] = None  # Platform where check was performed


@dataclass
class DependencyCheckResult:
    """
    Result of checking all dependencies for a collector.

    Attributes:
        collector_id: ID of the collector
        collector_name: Name of the collector
        all_required_available: Whether all required dependencies are available
        required_dependencies: Required dependencies
        optional_dependencies: Optional dependencies
        missing_required: Missing required dependencies
        missing_optional: Missing optional dependencies
        warnings: Warnings
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

    Attributes:
        dut_manager: DUT manager for remote command execution
    """

    def __init__(self, dut_manager=None) -> None:
        """
        Initialize the dependency checker.

        Args:
            dut_manager: DUT manager for remote command execution
        """
        self._cache: Dict[str, DependencyResult] = {}
        self.dut_manager = dut_manager

    def set_dut_manager(self, dut_manager) -> None:
        """
        Set the DUT manager for remote command execution.

        Args:
            dut_manager: DUT manager for remote command execution
        """
        self.dut_manager = dut_manager

    def check_command(
        self, command: str, dut_id: str = None, check_local: bool = False
    ) -> DependencyResult:
        """
        Check if a command is available (locally or on DUT if specified).

        Args:
            command: Command to check
            dut_id: ID of the DUT to check
            check_local: Whether to check locally
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

        Args:
            command: Command to check
        """
        cache_key = f"command:{command}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            result = subprocess.run(
                ["which", command],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
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
                    error_message=f"Command '{command}' not found in PATH",
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
        self, dut_id: str, command: str, use_bmc: bool = False
    ) -> DependencyResult:
        """
        Check if a command is available on a specific DUT.

        Args:
            dut_id: ID of the DUT to check
            command: Command to check
            use_bmc: Whether to use BMC connection
        """
        cache_key = f"dut_command:{dut_id}:{command}"
        if use_bmc:
            cache_key = f"dut_bmc_command:{dut_id}:{command}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        if not self.dut_manager:
            # Fallback to local check if no DUT manager available
            return self._check_command_local(command)

        try:
            # Use DUT manager to execute 'which' command on the remote DUT
            if use_bmc:
                # For SSH collectors, use BMC connection
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, f"which {command}", timeout=30
                )
            else:
                # For host collectors, use host connection
                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id, f"which {command}", timeout=30
                )

            if exit_code == 0:
                dependency_result = DependencyResult(
                    type=DependencyType.COMMAND,
                    name=command,
                    available=True,
                    version=None,
                    error_message=None,
                    platform=dut_id,
                )
            else:
                dependency_result = DependencyResult(
                    type=DependencyType.COMMAND,
                    name=command,
                    available=False,
                    version=None,
                    error_message=f"Command '{command}' not found on DUT {dut_id}: {stderr}",
                    platform=dut_id,
                )

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
            )
            self._cache[cache_key] = dependency_result
            return dependency_result

    def check_file(self, file_path: str, dut_id: str = None) -> DependencyResult:
        """
        Check if a file exists (locally or on DUT if specified).

        Args:
            file_path: Path to the file to check
            dut_id: ID of the DUT to check
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

        Args:
            dut_id: ID of the DUT to check
            file_path: Path to the file to check
            use_bmc: Whether to use BMC connection
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
            if use_bmc:
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, f"test -f {file_path}", timeout=30
                )
            else:
                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id, f"test -f {file_path}", timeout=30
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

        Args:
            dut_id: ID of the DUT to check
            service_name: Name of the systemd service
            use_bmc: Whether to use BMC connection (for SSH/BMC collectors)
        """
        cache_key = f"dut_service:{dut_id}:{service_name}"
        if use_bmc:
            cache_key = f"dut_bmc_service:{dut_id}:{service_name}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        if not self.dut_manager:
            return self.check_service(service_name)

        try:
            if use_bmc:
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, f"systemctl is-active {service_name}", timeout=30
                )
            else:
                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id, f"systemctl is-active {service_name}", timeout=30
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

        Args:
            service_name: Name of the service to check
        """
        cache_key = f"service:{service_name}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            result = subprocess.run(
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

        Args:
            command: Command to check
            min_version: Minimum version required
            version_cmd: Command to check the version
            dut_id: Optional DUT ID - if provided, runs on DUT; otherwise runs locally
            use_bmc: Whether to use BMC connection (only used if dut_id is provided)
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

                # Execute version command on the DUT
                if use_bmc:
                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_bmc_command(
                            dut_id, version_cmd, timeout=30
                        )
                    )
                else:
                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_host_command(
                            dut_id, version_cmd, timeout=30
                        )
                    )

                if exit_code == 0:
                    version_output = stdout.strip()
                    if self._compare_versions(version_output, min_version):
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
                            error_message=f"Version {version_output} is below minimum required {min_version}",
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
            # Execute version command - parse string commands safely with shlex
            import shlex

            if isinstance(version_cmd, str):
                cmd_list = shlex.split(version_cmd)
            else:
                cmd_list = version_cmd
            result = subprocess.run(
                cmd_list, capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                version_output = result.stdout.strip()
                # Simple version comparison (can be enhanced)
                if self._compare_versions(version_output, min_version):
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
                        error_message=f"Version {version_output} is below minimum required {min_version}",
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

        Args:
            dependency_config: Configuration for the platform-specific service
            platform: Platform to check
            dut_id: ID of the DUT to check
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
                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_host_command(
                                dut_id, f"test -f {file_path}", timeout=30
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
                optional = fallback.get("optional", False)

                if cmd and dut_id and self.dut_manager:
                    try:
                        # Execute the command on the DUT
                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_host_command(
                                dut_id, cmd, timeout=60
                            )
                        )

                        if exit_code == 0:
                            # If command succeeded and we have success indicators, validate output
                            if success_indicators and stdout:
                                output_lower = stdout.lower()
                                for indicator in success_indicators:
                                    if indicator.lower() in output_lower:
                                        return DependencyResult(
                                            name=cmd,
                                            type=DependencyType.COMMAND,
                                            available=True,
                                            error_message="",
                                        )
                                # If no indicators matched but command succeeded, still consider it available
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
                        elif optional:
                            # Optional commands are considered available even if they fail
                            return DependencyResult(
                                name=cmd,
                                type=DependencyType.COMMAND,
                                available=True,
                                error_message="",
                            )
                    except Exception:
                        if optional:
                            # Optional commands are considered available even if they fail
                            return DependencyResult(
                                name=cmd,
                                type=DependencyType.COMMAND,
                                available=True,
                                error_message="",
                            )

        # If all fallback checks fail, return the original service check result
        return main_result

    def check_fallback_group(
        self, dependency_config: Dict[str, Any]
    ) -> DependencyResult:
        """
        Check a group of dependencies with fallback logic.

        Args:
            dependency_config: Configuration for the group of dependencies
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

        Args:
            command: Command to check
            success_indicators: Success indicators to check against
        """
        try:
            result = subprocess.run(
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

        Args:
            collector_id: ID of the collector
            collector_name: Name of the collector
            dependencies: Dependencies to check
            platform: Platform to check
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

        Args:
            collector_definitions: Collector definitions
            dut_id: ID of the DUT to check
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
        Check dependencies for a collector using DUT-aware methods (for all collector types).

        Args:
            collector_id: ID of the collector
            collector_name: Name of the collector
            dependencies: Dependencies to check
            dut_id: ID of the DUT to check
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
                    if self.dut_manager:
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
                    if self.dut_manager:
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

        Args:
            command: Command to get the version of
        """
        version_commands = {
            "nvidia-smi": "nvidia-smi --version",
            "ipmitool": "ipmitool -V",
            "nvme": "nvme --version",
            "dmidecode": "dmidecode --version",
            "lshw": "lshw -version",
            "opensm": "opensm --version",
        }

        if command in version_commands:
            try:
                result = subprocess.run(
                    version_commands[command].split(),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    return result.stdout.strip().split("\n")[0]
            except:
                pass

        return None

    def _compare_versions(self, version1: str, version2: str) -> bool:
        """
        Enhanced version comparison with better parsing.

        Args:
            version1: First version to compare
            version2: Second version to compare
        """
        try:
            import re

            # Extract version numbers using regex to handle various formats
            # Handles: "4.8.0", "v4.8.0", "version 4.8.0", "sos 4.8.0-1", etc.
            v1_match = re.search(r"(\d+(?:\.\d+)*)", version1)
            v2_match = re.search(r"(\d+(?:\.\d+)*)", version2)

            if not v1_match or not v2_match:
                # If we can't parse versions, log and assume OK
                return True

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
            # If version comparison fails, log the issue but assume it's OK
            # This prevents dependency failures due to version parsing issues
            return True

    def clear_cache(self) -> None:
        """
        Clear the dependency cache.

        Args:
            None
        """
        self._cache.clear()
