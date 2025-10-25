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
Host Service - Handles all Host-related collector operations.

Provides collectors for host OS-based log collection including system logs,
diagnostic commands, and file collection via SSH or local access.
"""
import shlex
import asyncio
import json
import logging
import os
import re
import shlex
import shutil
import tarfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ..utils.temp_dir_config import create_temp_directory, get_tool_temp_dir
from ..utils.timeout_config import get_collector_timeout, get_nvos_tech_dump_timeout
from .base_service import BaseService

logger = logging.getLogger(__name__)


class HostService(BaseService):
    """
    Service for Host operations.

    Provides collectors for host OS-based log collection including system logs,
    diagnostic commands, and file collection via SSH or local access.
    """

    def __init__(self, service_name: str, orchestrator: Any) -> None:
        """
        Initialize Host service.

        Args:
            service_name: Name of the service.
            orchestrator: Orchestrator instance.
        """
        super().__init__(service_name, orchestrator)

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """Validate Host connection.

        Args:
            dut_id: DUT ID.
        """
        return await self.dut_manager.get_dut(dut_id).test_host_connection()

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

    # Validation methods
    async def _validate_host_connection(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Validate host connection - check preflight results first, then run test if needed.

        Args:
            dut_id: DUT ID.
        """
        # First check if we have preflight results
        dut = self.dut_manager.get_dut(dut_id)
        preflight_results = getattr(dut, "preflight_results", {})

        if preflight_results:
            host_service_result = preflight_results.get("services", {}).get("host", {})
            if host_service_result:
                preflight_status = host_service_result.get("status", "unknown")
                preflight_message = host_service_result.get("message", "")

                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Found preflight results for host connection: status={preflight_status}, message={preflight_message}",
                    dut_id,
                )

                if preflight_status == "pass":
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"Using preflight results for host validation - connection already verified",
                        dut_id,
                    )
                    return {
                        "success": True,
                        "reason": f"Preflight verified: {preflight_message}",
                        "context": {
                            "host_available": True,
                            "preflight_used": True,
                            "successful_operations": 1,
                            "total_operations": 1,
                        },
                    }
                elif preflight_status == "fail":
                    await self._log_runtime(
                        "WARN",
                        "HostService",
                        f"Preflight failed for host connection: {preflight_message}",
                        dut_id,
                    )
                    return {
                        "success": False,
                        "reason": f"Preflight failed: {preflight_message}",
                        "context": {
                            "host_available": False,
                            "preflight_used": True,
                            "successful_operations": 0,
                            "total_operations": 1,
                        },
                    }

        # No preflight results or unknown status - run connection test
        await self._log_runtime(
            "DEBUG",
            "HostService",
            "No preflight results found or unknown status - running host connection test",
            dut_id,
        )

        success, message = await self.validate_connection(dut_id)

        # Log the validation result
        if success:
            await self._log_runtime(
                "INFO",
                "HostService",
                f"Host connection validation passed: {message}",
                dut_id,
            )
        else:
            await self._log_runtime(
                "ERROR",
                "HostService",
                f"Host connection validation failed: {message}",
                dut_id,
            )

        return {
            "success": success,
            "reason": message,
            "context": {
                "host_available": success,
                "preflight_used": False,
                "successful_operations": 1 if success else 0,
                "total_operations": 1,
            },
        }

    async def _validate_ssh_connection(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Validate SSH connection - check preflight results first, then run test if needed.

        Args:
            dut_id: DUT ID.
        """
        # First check if we have preflight results
        dut = self.dut_manager.get_dut(dut_id)
        preflight_results = getattr(dut, "preflight_results", {})

        if preflight_results:
            ssh_service_result = preflight_results.get("services", {}).get("ssh", {})
            if ssh_service_result:
                preflight_status = ssh_service_result.get("status", "unknown")
                preflight_message = ssh_service_result.get("message", "")

                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Found preflight results for SSH connection: status={preflight_status}, message={preflight_message}",
                    dut_id,
                )

                if preflight_status == "pass":
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"Using preflight results for SSH validation - connection already verified",
                        dut_id,
                    )
                    return {
                        "success": True,
                        "reason": f"Preflight verified: {preflight_message}",
                        "context": {
                            "ssh_available": True,
                            "preflight_used": True,
                            "successful_operations": 1,
                            "total_operations": 1,
                        },
                    }
                elif preflight_status == "fail":
                    await self._log_runtime(
                        "WARN",
                        "HostService",
                        f"Preflight failed for SSH connection: {preflight_message}",
                        dut_id,
                    )
                    return {
                        "success": False,
                        "reason": f"Preflight failed: {preflight_message}",
                        "context": {
                            "ssh_available": False,
                            "preflight_used": True,
                            "successful_operations": 0,
                            "total_operations": 1,
                        },
                    }

        # No preflight results or unknown status - run connection test
        await self._log_runtime(
            "DEBUG",
            "HostService",
            "No preflight results found or unknown status - running SSH connection test",
            dut_id,
        )

        success, message = await self.dut_manager.get_dut(dut_id).test_ssh_connection()

        # Log the validation result
        if success:
            await self._log_runtime(
                "INFO",
                "HostService",
                f"SSH connection validation passed: {message}",
                dut_id,
            )
        else:
            await self._log_runtime(
                "ERROR",
                "HostService",
                f"SSH connection validation failed: {message}",
                dut_id,
            )

        return {
            "success": success,
            "reason": message,
            "context": {
                "ssh_available": success,
                "preflight_used": False,
                "successful_operations": 1 if success else 0,
                "total_operations": 1,
            },
        }

    async def collect_host_unified(
        self, dut_id: str, function_tag: str, collection_type: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Unified Host collection method that handles all core collection patterns.

        Args:
            dut_id: DUT identifier
            function_tag: Function tag for output files
            collection_type: Type of collection (commands, device_based, log_collection, file_collection, advanced)
            **kwargs: Additional parameters

        Returns:
            Dict with success status, output files, and context
        """
        collector_name = f"{function_tag}_{collection_type}"
        await self._log_collection_start(dut_id, collector_name)

        # Route to appropriate collection handler
        if collection_type == "commands":
            return await self._handle_host_commands_collection(
                dut_id, function_tag, **kwargs
            )
        elif collection_type == "device_based":
            return await self._handle_host_device_based_collection(
                dut_id, function_tag, **kwargs
            )
        elif collection_type == "log_collection":
            return await self._handle_host_log_collection(
                dut_id, function_tag, **kwargs
            )
        elif collection_type == "file_collection":
            return await self._handle_host_file_collection(
                dut_id, function_tag, **kwargs
            )
        elif collection_type == "advanced":
            return await self._handle_host_advanced_collection(
                dut_id, function_tag, **kwargs
            )
        elif collection_type == "fabric_manager_log":
            return await self._handle_host_fabric_manager_log(
                dut_id, function_tag, **kwargs
            )
        elif collection_type == "generic_log":
            # Extract the log type from kwargs or use a default
            log_type = kwargs.get("log_type", "unknown")
            return await self._handle_generic_log_collection(dut_id, log_type, **kwargs)
        elif collection_type == "file_search_and_archive":
            return await self._handle_host_file_search_and_archive(
                dut_id, function_tag, **kwargs
            )
        elif collection_type == "device_based_log_collection":
            return await self._handle_host_device_based_log_collection(
                dut_id, function_tag, **kwargs
            )
        elif collection_type == "system_info_collection":
            return await self._handle_host_system_info_collection(
                dut_id, function_tag, **kwargs
            )
        elif collection_type == "nvos_commands":
            return await self._handle_host_nvos_commands(dut_id, function_tag, **kwargs)
        elif collection_type == "composite":
            return await self._handle_host_composite_collection(
                dut_id, function_tag, **kwargs
            )
        else:
            return self._create_error_response(
                f"Unknown collection_type: {collection_type}"
            )

    async def _handle_host_fabric_manager_log(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle fabric manager log collection with generic, YAML-driven platform-specific logic.

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for output files.
        """
        return await self._handle_generic_log_collection(
            dut_id, "fabric_manager", **kwargs
        )

    # ============================================================================
    # 10.3 COMMON UTILITY FUNCTIONS FOR HANDLERS
    # ============================================================================

    def _wrap_for_shell(self, cmd: str) -> str:
        """
        Wrap command in bash -lc when shell features are detected and not already wrapped.
        """
        stripped = cmd.strip()
        needs_shell = (
            stripped.startswith("command ")
            or "|" in cmd
            or ";" in cmd
            or "&&" in cmd
            or "$(" in cmd
            or "`" in cmd
        )
        if needs_shell and not stripped.startswith("bash -lc"):
            return f"bash -lc \"{cmd.replace('\\', '\\\\').replace('\"', '\\\"')}\""
        return cmd

    async def _execute_command_and_save(
        self,
        dut_id: str,
        command: str,
        file_name: str,
        operation_name: str,
        operation_type: str,
        output_pattern: str,
        filtered_kwargs: Dict[str, Any],
        use_sudo: bool = False,
        timeout: int = 300,
        content_processor: Optional[Callable] = None,
        **kwargs,
    ) -> Tuple[bool, Optional[str]]:
        """
        Unified utility to execute a command with logging and save the output.

        Args:
            dut_id: DUT identifier
            command: Command to execute
            file_name: Name for the output file
            operation_name: Name for logging
            operation_type: Type for logging
            output_pattern: Output pattern for file naming
            filtered_kwargs: Filtered kwargs for data saving
            use_sudo: Whether to use sudo
            timeout: Command timeout
            content_processor: Optional function to process content before saving
            **kwargs: Additional arguments for execute_host_command

        Returns:
            Tuple of (success, file_path)
        """
        await self._log_collection_start(dut_id, operation_name)

        # Add sudo to command if needed
        if use_sudo and not command.strip().startswith("sudo"):
            command = f"sudo {command}"

        # INFO-level visibility before execution
        await self._write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "HostService",
            f"Executing command: {command} (timeout={timeout}, use_sudo={use_sudo})",
        )

        # Execute command
        exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
            dut_id, command, timeout, use_sudo=use_sudo, **kwargs
        )

        # INFO-level visibility after execution
        await self._write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "HostService",
            f"Command completed: exit_code={exit_code}",
        )

        success = exit_code == 0

        if success:
            await self._log_collection_success(dut_id, operation_type, operation_name)

            # Process content if processor provided, otherwise use stdout
            if content_processor:
                content = content_processor(command, exit_code, stdout, stderr)
            else:
                content = stdout

            # Save data
            file_path = await self._save_data_with_common_pattern(
                dut_id,
                content,
                file_name,
                output_pattern=output_pattern,
                substitutions={"file_name": file_name},
                **filtered_kwargs,
            )

            return True, file_path
        else:
            await self._log_collection_failure(
                dut_id,
                operation_type,
                operation_name,
                f"exit_code: {exit_code}",
                collector_id=kwargs.get("collector_id"),
            )
            return False, None

    # ============================================================================
    # 10.2 INTERNAL COLLECTION HANDLERS
    # ============================================================================

    async def _handle_host_commands_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle simple host commands collection.

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for output files.
        """

        async def _commands_collection():
            commands = kwargs.get("commands", [])
            collection_level = kwargs.get("collection_level", "L1")
            use_sudo = kwargs.get("use_sudo", False)

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            output_files = []
            results = []
            error_messages = []

            # Get configurable timeout from collector definition and DUT config
            collector_id = kwargs.get("collector_id", "")
            collector_def = kwargs.get("collector_def", {})
            dut_config = self.dut_manager.get_dut_config(dut_id)

            # Use generic timeout resolution that handles all timeout_config types
            default_timeout = get_collector_timeout(
                collector_id, collector_def, dut_config, 300
            )

            for i, command_item in enumerate(commands):
                # Handle both string commands and command dictionaries
                if isinstance(command_item, str):
                    command = command_item
                    file_name = f"host_command_{i+1}.txt"
                    timeout = default_timeout
                    ignore_errors = False
                else:
                    # Handle collection level variations
                    if "collection_level_handling" in command_item:
                        level_commands = command_item["collection_level_handling"]
                        command = level_commands.get(
                            collection_level, command_item["command"]
                        )
                    else:
                        command = command_item["command"]

                    file_name = command_item.get("file_name", f"host_command_{i+1}.txt")
                    timeout = command_item.get("timeout", default_timeout)
                    ignore_errors = command_item.get("ignore_errors", False)

                # Execute command with logging and save using common utility
                success, file_path = await self._execute_command_and_save(
                    dut_id=dut_id,
                    command=command,
                    file_name=file_name,
                    operation_name=f"command_{i+1}",
                    operation_type="command",
                    output_pattern=output_pattern,
                    filtered_kwargs=filtered_kwargs,
                    use_sudo=use_sudo,
                    timeout=timeout,
                    content_processor=self._create_command_output_content,
                )

                if file_path:
                    output_files.append(file_path)

                results.append(
                    {
                        "command": command,
                        "success": success,
                        "file_name": file_name,
                        "collection_level": collection_level,
                    }
                )

                # Handle ignore_errors
                if not success and not ignore_errors:
                    error_messages.append(f"Command failed: {command}")

            # Determine success metrics
            successful_operations = sum(
                1 for result in results if result.get("success", False)
            )
            total_operations = len(commands)

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} Commands",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=len(error_messages),
                output_files=output_files,
                additional_details={
                    "Total commands": len(commands),
                    "Collection level": collection_level,
                    "Commands executed": [
                        cmd.get("command", cmd) if isinstance(cmd, dict) else cmd
                        for cmd in commands
                    ],
                },
                kwargs=kwargs,
                collection_type="commands",
                ignore_empty_results=True,
            )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="host_commands",
                additional_context={
                    "total_commands": len(commands),
                    "collection_level": collection_level,
                    "results": results,
                },
            )

        return await self._execute_with_error_handling(
            dut_id, "host_commands", _commands_collection
        )

    async def run_host_device_based_commands(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle device-based host commands collection (public method for collector definitions).

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for output files.
        """
        return await self._handle_host_device_based_collection(
            dut_id, function_tag, **kwargs
        )

    async def _handle_host_device_based_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle device-based host commands collection.

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for output files.
        """

        async def _device_based_collection():
            device_detection = kwargs.get("device_detection", {})
            device_commands = kwargs.get("device_commands", [])
            use_sudo = kwargs.get("use_sudo", False)

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            output_files = []
            detected_devices = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            # Detect devices
            detection_cmd = device_detection["command"]
            device_pattern = device_detection["device_pattern"]
            skip_message = device_detection.get("skip_message", "No devices found")

            await self._log_collection_start(dut_id, "device_detection")

            exit_code, output, stderr = await self.dut_manager.execute_host_command(
                dut_id, detection_cmd, use_sudo=use_sudo
            )

            # Debug logging
            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                f"Device detection command: {detection_cmd}, exit_code: {exit_code}, output: {output[:500]}, stderr: {stderr[:500]}",
            )

            if exit_code != 0:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[f"Device detection failed: {stderr}"],
                    operation_name="device_detection",
                    additional_context={"detection_command": detection_cmd},
                )

            # Parse device list
            pattern = re.compile(device_pattern)
            matches = pattern.findall(output)

            # Debug logging
            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                f"Device pattern: {device_pattern}, matches found: {matches}",
            )

            if not matches:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="device_based_collection",
                    additional_context={
                        "devices_found": 0,
                        "reason": skip_message,
                        "detection_pattern": device_pattern,
                    },
                )

            # Execute commands for each device
            for device_id in matches:
                detected_devices.append(device_id)

                for cmd_config in device_commands:
                    cmd_type = cmd_config["type"]
                    command_template = cmd_config["command_template"]
                    file_template = cmd_config["file_template"]

                    # Format command and filename
                    command = command_template.format(device_index=device_id)
                    filename = file_template.format(device_index=device_id)

                    await self._log_collection_start(
                        dut_id, f"device_command_{device_id}_{cmd_type}"
                    )

                    exit_code, output, stderr = (
                        await self.dut_manager.execute_host_command(
                            dut_id, command, use_sudo=use_sudo
                        )
                    )

                    total_operations += 1

                    if exit_code == 0:
                        await self._log_collection_success(
                            dut_id, "device_command", f"{device_id}_{cmd_type}"
                        )

                        file_path = await self._save_data_with_common_pattern(
                            dut_id,
                            output,
                            filename,
                            output_pattern=output_pattern,
                            substitutions={"file_name": filename},
                            **filtered_kwargs,
                        )
                        if file_path:
                            output_files.append(file_path)
                            successful_operations += 1
                    else:
                        await self._log_collection_failure(
                            dut_id,
                            "device_command",
                            f"{device_id}_{cmd_type}",
                            collector_id=kwargs.get("collector_id"),
                        )
                        error_messages.append(
                            f"Device command failed: {device_id}_{cmd_type} - exit_code: {exit_code}"
                        )

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} Device Collection",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=len(error_messages),
                output_files=output_files,
                additional_details={
                    "Detection command": detection_cmd,
                    "Device pattern": device_pattern,
                    "Device commands": [
                        cmd.get("command_template", cmd.get("command", ""))
                        for cmd in device_commands
                    ],
                    "Devices found": len(detected_devices),
                    "Devices processed": detected_devices,
                },
                kwargs=kwargs,
                collection_type="device_based_collection",
                ignore_empty_results=False,  # Device-based collection should fail if no devices found
            )

            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id", "unknown"),
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="device_based_collection",
                additional_context={
                    "devices_found": len(detected_devices),
                    "devices_processed": detected_devices,
                    "detection_pattern": device_pattern,
                },
            )

        return await self._execute_with_error_handling(
            dut_id, "host_device_based", _device_based_collection
        )

    async def _handle_host_log_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle host log collection - generic method for any log collection type.

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for output files.
        """

        async def _log_collection():
            # Generic parameter names - can be used for any log collection type
            log_commands = kwargs.get(
                "log_commands", kwargs.get("journalctl_commands", [])
            )  # Support both for backward compatibility
            log_patterns = kwargs.get("log_patterns", [])
            use_sudo = kwargs.get("use_sudo", False)

            # Get generic labels from collector definition or use defaults
            command_type_label = kwargs.get("command_type_label", "log commands")
            pattern_type_label = kwargs.get("pattern_type_label", "log patterns")

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            output_files = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            # Execute log commands (generic - can be journalctl, dmesg, or any other log command)
            for cmd_config in log_commands:
                command = cmd_config["command"]
                file_name = cmd_config["file_name"]
                collection_level = cmd_config.get("collection_level", "L1")
                timeout = cmd_config.get("timeout", 500)

                total_operations += 1

                # Execute log command with logging and save
                success, file_path = await self._execute_command_and_save(
                    dut_id=dut_id,
                    command=command,
                    file_name=file_name,
                    operation_name=f"log_command_{file_name}",
                    operation_type="log_command",
                    output_pattern=output_pattern,
                    filtered_kwargs=filtered_kwargs,
                    use_sudo=use_sudo,
                    timeout=timeout,
                )

                if file_path:
                    output_files.append(file_path)
                    successful_operations += 1
                else:
                    error_messages.append(f"Journalctl command failed: {command}")

            # Collect log files
            for pattern in log_patterns:
                total_operations += 1
                await self._log_collection_start(dut_id, f"log_file_{pattern}")

                # Check if file exists
                test_command = f"test -f {pattern}"
                exit_code, _, _ = await self.dut_manager.execute_host_command(
                    dut_id, test_command, use_sudo=use_sudo
                )
                success = exit_code == 0

                if success:
                    # Read log file
                    cat_command = f"cat {pattern}"
                    success, file_path = await self._execute_command_and_save(
                        dut_id=dut_id,
                        command=cat_command,
                        file_name=f"log_file_{pattern.replace('/', '_')}.txt",
                        operation_name=f"log_file_{pattern}",
                        operation_type="log_file",
                        output_pattern=output_pattern,
                        filtered_kwargs=filtered_kwargs,
                        use_sudo=use_sudo,  # cat doesn't need sudo
                    )

                    if file_path:
                        output_files.append(file_path)
                        successful_operations += 1
                    else:
                        error_messages.append(f"Failed to read log file: {pattern}")
                else:
                    await self._log_collection_failure(
                        dut_id,
                        "log_file",
                        pattern,
                        "File not found",
                        collector_id=kwargs.get("collector_id"),
                    )
                    error_messages.append(f"Log file not found: {pattern}")

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} Log Collection",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=len(error_messages),
                output_files=output_files,
                additional_details={
                    f"{command_type_label.title()}": len(log_commands),
                    f"{pattern_type_label.title()}": len(log_patterns),
                    f"{command_type_label.title()} executed": [
                        cmd.get("command", cmd) if isinstance(cmd, dict) else cmd
                        for cmd in log_commands
                    ],
                    f"{pattern_type_label.title()} searched": log_patterns,
                },
                kwargs=kwargs,
                collection_type="log_collection",
                ignore_empty_results=True,
            )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="log_collection",
                additional_context={
                    f"{command_type_label}": len(log_commands),
                    f"{pattern_type_label}": len(log_patterns),
                },
            )

        return await self._execute_with_error_handling(
            dut_id, "host_log_collection", _log_collection
        )

    async def _handle_host_composite_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Execute a generic, YAML-driven composite host collection.

        This handler executes a sequence of optional stages defined entirely in the
        collector definition. Typical stages include hardware detection, dependency
        checks, selecting and running one or more command scenarios, and downloading
        any artifacts to the log directory. Behavior (commands, timeouts, flags,
        temp directories, and output naming) is controlled via kwargs populated from
        the YAML. The function aggregates results, counts each successful stage as a
        successful operation, and returns a standardized result payload.
        """

        async def _composite_collection():
            use_sudo = kwargs.get("use_sudo", False)
            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            output_files: List[str] = []
            error_messages: List[str] = []
            successful_operations = 0
            total_operations = 0

            # 1) Hardware detection (generic, command configurable via YAML)
            hd = kwargs.get("hardware_detection", {})
            if hd.get("enabled"):
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    "composite: hardware_detection start",
                )
                total_operations += 1
                query = (hd.get("query") or {})
                vendor_ids = set((query.get("vendor_ids") or []))
                device_classes = set((query.get("device_classes") or []))
                name_patterns = (query.get("name_patterns") or [])
                skip_message = hd.get(
                    "skip_message",
                    "Required hardware not detected. Skipping collection.",
                )

                # Run hardware probe command once and evaluate
                hd_cmd = hd.get("command", "lspci -nn")
                exit_code, hd_out, _ = await self.dut_manager.execute_host_command(
                    dut_id, hd_cmd, use_sudo=use_sudo
                )
                if exit_code != 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        "composite: hardware_detection failed to run lspci",
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=1,
                        output_files=[],
                        error_messages=["Failed to run lspci for hardware detection"],
                        operation_name="composite_collection",
                        additional_context={"reason": "lspci failed"},
                    )

                lines = hd_out.splitlines()
                found = False
                for line in lines:
                    # Match vendor ids like [10de:xxxx]
                    lower_line = line.lower()
                    if vendor_ids and any(f"[{vid}" in lower_line for vid in vendor_ids):
                        found = True
                    # Match class codes like '0200' (Ethernet)
                    if device_classes and any(dc in lower_line for dc in device_classes):
                        found = True
                    # Match name patterns substrings
                    if name_patterns and any(np.lower() in lower_line for np in name_patterns):
                        found = True
                    if found:
                        break

                if not found:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        f"composite: hardware_detection skip - {skip_message}",
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=1,
                        output_files=[],
                        error_messages=[],
                        operation_name="composite_collection",
                        additional_context={"message": skip_message},
                    )

                # Count hardware detection as success when hardware is present
                successful_operations += 1
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    "composite: hardware_detection pass",
                )

            # 2) Dependency checks (generic, with shell wrapping)
            dep_checks = kwargs.get("dependency_checks", [])
            if isinstance(dep_checks, list) and dep_checks:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"composite: dependency_checks start - count={len(dep_checks)}",
                )
                total_operations += 1
                for check in dep_checks:
                    cmd = check.get("command")
                    if not cmd:
                        continue
                    wrapped_cmd = self._wrap_for_shell(cmd)
                    exit_code, _, _ = await self.dut_manager.execute_host_command(
                        dut_id, wrapped_cmd, use_sudo=use_sudo
                    )
                    if exit_code != 0:
                        desc = check.get("description", "Dependency check failed")
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "HostService",
                            f"composite: dependency_check fail - cmd='{cmd}', desc='{desc}'",
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=1,
                            output_files=[],
                            error_messages=[desc],
                            operation_name="composite_collection",
                            additional_context={"failed_check": cmd},
                        )

                # All dependency checks passed
                successful_operations += 1
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    "composite: dependency_checks pass",
                )

            # 3) Determine scenario (config_exists / combined / individual)
            temp_dir = kwargs.get("temp_dir", "/tmp/nvdebug_composite")
            await self.dut_manager.execute_host_command(
                dut_id, f"mkdir -p {temp_dir}", use_sudo=use_sudo
            )

            config_file_check = kwargs.get("config_file_check", {})
            config_exists = False
            test_cmd = config_file_check.get("test_command")
            if test_cmd:
                exit_code, _, _ = await self.dut_manager.execute_host_command(
                    dut_id, test_cmd, use_sudo=use_sudo
                )
                config_exists = exit_code == 0

            cfg = kwargs.get("config", {})
            use_combined_command = cfg.get("use_combined_command", True)
            flags_list = list(cfg.get("flags", []) or [])
            flags = " ".join(flags_list) if flags_list else ""
            options = cfg.get("sos_command_options", [])
            options_combined = ",".join(options) if options else ""

            scenarios = kwargs.get("command_scenarios", {})
            chosen = None
            if config_exists and scenarios.get("config_exists"):
                chosen = scenarios["config_exists"]
            elif (not config_exists) and use_combined_command and scenarios.get(
                "config_missing_combined"
            ):
                chosen = scenarios["config_missing_combined"]
            elif (not config_exists) and scenarios.get("config_missing_individual"):
                chosen = scenarios["config_missing_individual"]

            if not chosen:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=["No suitable command scenario found"],
                    operation_name="composite_collection",
                )

            # Build the command from template
            template = chosen.get("command_template", "")
            # Apply generic ensure_flags from YAML (e.g., ["--batch"]) to avoid interactivity
            ensure_flags = list((cfg.get("ensure_flags") or []))
            for required_flag in ensure_flags:
                if required_flag not in flags_list and required_flag not in template:
                    flags_list.append(required_flag)
            flags = " ".join(flags_list) if flags_list else ""
            scenario_key = (
                "config_exists"
                if config_exists
                else ("config_missing_combined" if use_combined_command else "config_missing_individual")
            )
            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"composite: command_scenarios chosen={scenario_key}",
            )
            command = (
                template.replace("{temp_dir}", temp_dir)
                .replace("{flags}", flags)
                .replace("{options}", options_combined)
            )

            # For individual scenario, we may need to run per-option
            commands_to_run: List[str] = []
            if "{option}" in template and options:
                for opt in options:
                    commands_to_run.append(
                        template.replace("{temp_dir}", temp_dir)
                        .replace("{flags}", flags)
                        .replace("{option}", opt)
                    )
            else:
                commands_to_run.append(command)

            # Execute commands
            aggregated_stdout: List[str] = []
            for cmd in commands_to_run:
                total_operations += 1
                wrapped_cmd = self._wrap_for_shell(cmd)
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    "composite: executing command",
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id, wrapped_cmd, use_sudo=use_sudo, timeout=chosen.get("timeout", 600)
                )
                if exit_code != 0:
                    error_messages.append(f"Command failed: {cmd}")
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        f"composite: command failed - exit_code={exit_code}",
                    )
                else:
                    successful_operations += 1
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        "composite: command pass",
                    )
                if stdout:
                    aggregated_stdout.append(stdout)

            # 4) Download everything from temp_dir
            list_cmd = f"bash -lc \"ls -1d {temp_dir}/* 2>/dev/null\""
            exit_code, out, _ = await self.dut_manager.execute_host_command(
                dut_id, list_cmd, use_sudo=use_sudo
            )
            if exit_code == 0 and out and out.strip():
                files = [f.strip() for f in out.strip().split("\n") if f.strip()]
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"composite: download start - files={len(files)}",
                )
                for remote_file in files:
                    transfer_success, transfer_error = (
                        await self.dut_manager.transfer_host_files(
                            dut_id, remote_file, "/tmp", copy_to_destination=False
                        )
                    )
                    if not transfer_success:
                        error_messages.append(
                            f"Failed to download: {remote_file} - {transfer_error}"
                        )
                        continue
                    local_file = f"/tmp/{os.path.basename(remote_file)}"
                    if self.logger and os.path.exists(local_file):
                        final_name = os.path.basename(remote_file)
                        # Determine final output file name:
                        # - If output_pattern contains '*', replace it with the actual file name
                        # - Else if pattern contains variable placeholders like {file_name}, apply substitutions
                        # - Else fall back to the actual file name
                        if output_pattern and "*" in output_pattern:
                            final_output_name = output_pattern.replace("*", final_name)
                        elif output_pattern and "{" in output_pattern and "}" in output_pattern:
                            final_output_name = self.get_output_filename(
                                output_pattern,
                                None,
                                "",
                                {"file_name": final_name},
                            )
                        elif output_pattern:
                            final_output_name = output_pattern
                        else:
                            final_output_name = final_name

                        file_path_out = await self.logger.create_collector_log_file(
                            dut_id,
                            "host",
                            kwargs.get("collector_id", ""),
                            final_output_name,
                        )
                        with open(local_file, "rb") as f:
                            data = f.read()
                        with open(file_path_out, "wb") as f:
                            f.write(data)
                        output_files.append(str(file_path_out))
                        try:
                            os.remove(local_file)
                        except Exception:
                            pass
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"composite: download complete - files={len(output_files)}",
                )

            # Optionally write aggregated stdout to a file if requested
            stdout_file_name = (cfg or {}).get("stdout_file_name")
            if stdout_file_name and aggregated_stdout and self.logger:
                # Always write stdout to the explicit stdout file name
                file_path_out = await self.logger.create_collector_log_file(
                    dut_id,
                    "host",
                    kwargs.get("collector_id", ""),
                    stdout_file_name,
                )
                try:
                    with open(file_path_out, "w", encoding="utf-8", errors="ignore") as f:
                        f.write("\n".join(aggregated_stdout))
                    output_files.append(str(file_path_out))
                except Exception:
                    error_messages.append("Failed to write aggregated stdout file")

            success = successful_operations > 0 and not error_messages
            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="composite_collection",
            )

        return await self._execute_with_error_handling(
            dut_id, "host_composite_collection", _composite_collection
        )

    async def _handle_host_file_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle host file collection.

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for output files.
        """

        async def _file_collection():
            """
            Handle host file collection.

            Args:
                dut_id: DUT ID.
                function_tag: Function tag for output files.
            """
            file_patterns = kwargs.get("file_patterns", [])
            use_sudo = kwargs.get("use_sudo", False)
            ignore_empty_results = kwargs.get("ignore_empty_results", False)

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            output_files = []
            collected_files = []
            error_messages = []
            successful_operations = 0
            total_operations = 0
            empty_patterns = []
            # Opt-in flag: only when true, use glob enumeration + download (binary-safe)
            use_glob_enumeration = kwargs.get("use_glob_enumeration", False)

            for pattern in file_patterns:
                total_operations += 1
                await self._log_collection_start(dut_id, f"file_pattern_{pattern}")

                # Auto-enable enumeration for absolute globs if not explicitly set (defensive fallback)
                auto_enable = False
                if not use_glob_enumeration and "*" in pattern and pattern.startswith("/"):
                    auto_enable = True

                effective_enumeration = use_glob_enumeration or auto_enable

                # Debug visibility
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"file_collection: pattern={pattern}, use_glob_enumeration={use_glob_enumeration}, auto_enable={auto_enable}",
                )

                if effective_enumeration:
                    # Enumerate files using shell glob expansion (absolute patterns supported)
                    escaped_pattern = shlex.quote(pattern)
                    list_command = f"bash -lc \"ls -1d {escaped_pattern} 2>/dev/null\""
                    exit_code, output, _ = await self.dut_manager.execute_host_command(
                        dut_id, list_command, use_sudo=use_sudo
                    )

                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        f"file_collection: ls exit_code={exit_code}, bytes={len(output or '')}",
                    )

                    if exit_code == 0 and output and output.strip():
                        files = [f.strip() for f in output.strip().split("\n") if f.strip()]
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "HostService",
                            f"file_collection: enumerated {len(files)} files (first): {files[:5]}",
                        )
                        for remote_file in files:
                            transfer_success, transfer_error = (
                                await self.dut_manager.transfer_host_files(
                                    dut_id, remote_file, "/tmp", copy_to_destination=False
                                )
                            )

                            if not transfer_success:
                                await self._log_collection_failure(
                                    dut_id,
                                    "file_download",
                                    remote_file,
                                    transfer_error or "transfer failed",
                                    collector_id=kwargs.get("collector_id"),
                                )
                                error_messages.append(
                                    f"Failed to download file: {remote_file} - {transfer_error}"
                                )
                                continue

                            local_file = f"/tmp/{os.path.basename(remote_file)}"
                            try:
                                if self.logger:
                                    final_filename = os.path.basename(remote_file)
                                    file_path_out = await self.logger.create_collector_log_file(
                                        dut_id,
                                        "host",
                                        filtered_kwargs.get("collector_id", ""),
                                        self.get_output_filename(
                                            output_pattern,
                                            final_filename,
                                            "",
                                            {"file_name": final_filename},
                                        ),
                                    )
                                    with open(local_file, "rb") as f:
                                        data = f.read()
                                    with open(file_path_out, "wb") as f:
                                        f.write(data)
                                    output_files.append(str(file_path_out))
                                    collected_files.append(remote_file)
                                    successful_operations += 1
                                    await self._log_collection_success(
                                        dut_id, "file_download", remote_file
                                    )
                                else:
                                    error_messages.append(
                                        f"Logger unavailable; cannot save file {remote_file}"
                                    )
                            finally:
                                try:
                                    if os.path.exists(local_file):
                                        os.remove(local_file)
                                except Exception:
                                    pass
                    else:
                        empty_patterns.append(pattern)
                        if ignore_empty_results:
                            await self._log_collection_success(
                                dut_id, "file_pattern", pattern, "No files found (expected)"
                            )
                            successful_operations += 1
                        else:
                            await self._log_collection_failure(
                                dut_id,
                                "file_pattern",
                                pattern,
                                "No files found",
                                collector_id=kwargs.get("collector_id"),
                            )
                            error_messages.append(f"No files found for pattern: {pattern}")
                else:
                    # Default: find files and read as text (legacy behavior)
                    find_command = (
                        f"find / -name '{pattern}' -type f 2>/dev/null | head -10"
                    )
                    exit_code, output, _ = await self.dut_manager.execute_host_command(
                        dut_id, find_command, use_sudo=use_sudo
                    )
                    success = exit_code == 0

                    if success and output.strip():
                        files = output.strip().split("\n")
                        for file_path in files:
                            if file_path:
                                cat_command = f"cat '{file_path}' 2>/dev/null"
                                exit_code, content, _ = (
                                    await self.dut_manager.execute_host_command(
                                        dut_id, cat_command
                                    )
                                )
                                success = exit_code == 0

                                if success:
                                    await self._log_collection_success(
                                        dut_id, "file_collection", file_path
                                    )

                                    filename = f"host_file_{len(collected_files)}.txt"
                                    file_content = f"File: {file_path}\nContent:\n{content}"
                                    file_path_out = (
                                        await self._save_data_with_common_pattern(
                                            dut_id,
                                            file_content,
                                            filename,
                                            output_pattern=output_pattern,
                                            substitutions={"file_name": filename},
                                            **filtered_kwargs,
                                        )
                                    )
                                    if file_path_out:
                                        output_files.append(file_path_out)
                                        collected_files.append(file_path)
                                        successful_operations += 1
                                    else:
                                        error_messages.append(
                                            f"Failed to save file: {file_path}"
                                        )
                                else:
                                    await self._log_collection_failure(
                                        dut_id,
                                        "file_collection",
                                        file_path,
                                        collector_id=kwargs.get("collector_id"),
                                    )
                                    error_messages.append(
                                        f"Failed to read file: {file_path}"
                                    )
                    else:
                        empty_patterns.append(pattern)
                        if ignore_empty_results:
                            await self._log_collection_success(
                                dut_id, "file_pattern", pattern, "No files found (expected)"
                            )
                            successful_operations += 1
                        else:
                            await self._log_collection_failure(
                                dut_id,
                                "file_pattern",
                                pattern,
                                "No files found",
                                collector_id=kwargs.get("collector_id"),
                            )
                            error_messages.append(
                                f"No files found for pattern: {pattern}"
                            )

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} File Collection",
                total_operations=len(file_patterns),
                successful_operations=successful_operations,
                failed_operations=len(error_messages),
                output_files=output_files,
                additional_details={
                    "file_patterns": file_patterns,
                    "collected_files": collected_files,
                    "empty_patterns": empty_patterns,
                },
                kwargs=kwargs,
                collection_type="file_collection",
                ignore_empty_results=ignore_empty_results,
            )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="file_collection",
                additional_context={
                    "patterns_searched": len(file_patterns),
                    "files_collected": len(collected_files),
                    "empty_patterns": len(empty_patterns),
                    "ignore_empty_results": ignore_empty_results,
                },
            )

        return await self._execute_with_error_handling(
            dut_id, "host_file_collection", _file_collection
        )

    async def _handle_host_advanced_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle advanced host collection with file generation and retrieval.

        Args:
            dut_id: DUT identifier
            function_tag: Function tag for output files
            **kwargs: Additional arguments

        Returns:
            Dictionary with success status and collected files
        """
        await self._log_collection_start(dut_id, "Advanced Host Collection")

        output_files = []
        status_list = []
        error_messages = []
        successful_operations = 0
        total_operations = 0
        # Track where sudo prompts were observed to report in context
        sudo_prompt_locations: List[str] = []

        # Extract parameters from kwargs
        initial_commands = kwargs.get("initial_commands", [])
        command_modes = kwargs.get("command_modes", [])
        use_sudo = kwargs.get("use_sudo", False)

        # Extract output pattern parameters using common function
        output_pattern, substitutions, filtered_kwargs = (
            self._extract_output_pattern_params(kwargs)
        )

        # Get configurable timeout from collector definition and DUT config
        collector_id = kwargs.get("collector_id", "")
        collector_def = kwargs.get("collector_def", {})
        dut_config = self.dut_manager.get_dut_config(dut_id)

        # Get tool config for timeout fallback
        tool_config = self.orchestrator.config_manager.get_tool_config()

        # Use generic timeout resolution that handles all timeout_config types
        default_timeout = get_collector_timeout(
            collector_id, collector_def, dut_config, 300, tool_config
        )

        # Run initial commands (typically help commands that don't generate files)
        if isinstance(initial_commands, list):
            for cmd_config in initial_commands:
                total_operations += 1
                command = cmd_config["command"]
                file_name = cmd_config["file_name"]
                expect_file = cmd_config.get("expect_file", False)

                # Execute command with detailed logging
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Executing initial command with use_sudo={use_sudo}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG", "HostService", f"Initial command: {command}", dut_id
                )

                timeout = cmd_config.get("timeout", default_timeout)

                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id, command, timeout=timeout, use_sudo=use_sudo
                )

                # Log detailed execution results
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Initial command completed - exit_code={exit_code}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"stdout length={len(stdout)}, stderr length={len(stderr)}",
                    dut_id,
                )
                if stdout:
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        f"stdout preview: {stdout[:200]}...",
                        dut_id,
                    )
                prompt_detected = False
                if stderr:
                    await self._log_runtime(
                        "DEBUG", "HostService", f"stderr: {stderr}", dut_id
                    )

                    # Check for sudo password prompt issues in initial commands
                    if "[sudo] password for" in stderr:
                        prompt_detected = True
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "HostService",
                            f"Initial command detected sudo password prompt in stderr - this may indicate authentication issues",
                        )
                        # Treat as warning only; do not mark as error to avoid partial status
                        sudo_prompt_locations.append("initial")

                success = exit_code == 0

                if success:
                    await self._log_collection_success(
                        dut_id, "command", f"Initial: {command}"
                    )

                    # Save stdout to file
                    file_path = await self._save_data_with_common_pattern(
                        dut_id,
                        stdout,
                        file_name,
                        output_pattern=output_pattern,
                        substitutions={"file_name": file_name},
                        **filtered_kwargs,
                    )
                    output_files.append(file_path)
                    successful_operations += 1
                else:
                    # Log both stdout and stderr for failed commands
                    error_details = f"exit_code: {exit_code}"
                    if stdout:
                        error_details += f", stdout: {stdout}"
                    if stderr:
                        error_details += f", stderr: {stderr}"
                    await self._log_collection_failure(
                        dut_id,
                        "command",
                        f"Initial: {command}",
                        error_details,
                        collector_id=kwargs.get("collector_id"),
                    )
                    error_messages.append(
                        f"Initial command failed: {command} - {error_details}"
                    )
                    # If sudo prompt was detected alongside failure, record it explicitly as an error context
                    if prompt_detected:
                        error_messages.append(
                            "Initial command encountered sudo password prompt"
                        )

                status_list.append(success)

        # Run command modes (typically generate files that need to be retrieved)
        if isinstance(command_modes, list):
            await self._log_runtime(
                "INFO",
                "HostService",
                f"Starting execution of {len(command_modes)} command modes",
                dut_id,
            )

            for i, mode_config in enumerate(command_modes, 1):
                total_operations += 1
                mode_name = mode_config.get("mode", f"mode_{i}")
                command = mode_config["command"]
                file_name = mode_config["file_name"]
                timeout = mode_config.get("timeout", 1800)
                expect_file = mode_config.get("expect_file", True)
                config_key = mode_config.get("config_key")
                decompress = mode_config.get(
                    "decompress", False
                )  # Default to preserving compression

                await self._log_runtime(
                    "INFO",
                    "HostService",
                    f"=== Starting Mode {i}/{len(command_modes)}: {mode_name} ===",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Mode config: command='{command}', file_name='{file_name}', timeout={timeout}, expect_file={expect_file}, config_key={config_key}, decompress={decompress}",
                    dut_id,
                )

                # Check if this mode should be run based on config
                if config_key:
                    try:
                        dut_config = self.dut_manager.get_dut_config(dut_id)
                        tool_config = self.orchestrator.config_manager.get_tool_config()

                        # Determine if the DUT explicitly set this key in its YAML
                        is_explicit = False
                        try:
                            dut_obj = self.dut_manager.get_dut(dut_id)
                            is_explicit = dut_obj.has_explicit_config_key(config_key)
                        except Exception:
                            # Fallback heuristic: consider present in dut_config as explicit
                            is_explicit = config_key in dut_config

                        # Resolve effective value: DUT explicit setting wins; otherwise fallback to tool config
                        effective_value = (
                            dut_config.get(config_key)
                            if is_explicit
                            else dut_config.get(config_key, tool_config.get(config_key, False))
                        )

                        if not bool(effective_value):
                            await self._log_runtime(
                                "INFO",
                                "HostService",
                                f"Skipping mode '{mode_name}' - config_key '{config_key}' is False",
                                dut_id,
                            )
                            continue
                        else:
                            await self._log_runtime(
                                "DEBUG",
                                "HostService",
                                f"Mode '{mode_name}' enabled - config_key '{config_key}' resolved to True (explicit={is_explicit})",
                                dut_id,
                            )
                    except Exception as e:
                        await self._log_runtime(
                            "WARN",
                            "HostService",
                            f"Could not access config for mode '{mode_name}', skipping: {str(e)}",
                            dut_id,
                        )
                        continue

                await self._log_runtime(
                    "DEBUG", "HostService", f"Mode: {mode_name} - {command}", dut_id
                )

                # Execute command with detailed logging
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Executing command with use_sudo={use_sudo}, timeout={timeout}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG", "HostService", f"Command: {command}", dut_id
                )

                # Record start time for timing
                start_time = time.time()

                # Pre-execution diagnostics for H11
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Running pre-execution diagnostics for mode '{mode_name}'",
                    dut_id,
                )

                # Check current working directory and user context
                pwd_cmd = "pwd && whoami && id"
                pwd_exit_code, pwd_stdout, _ = (
                    await self.dut_manager.execute_host_command(
                        dut_id, pwd_cmd, timeout=30, use_sudo=False
                    )
                )
                if pwd_exit_code == 0:
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        f"Pre-execution context: {pwd_stdout.strip()}",
                        dut_id,
                    )

                # Check if nvidia-bug-report.sh exists and is executable
                if "nvidia-bug-report.sh" in command:
                    nv_check_cmd = "which nvidia-bug-report.sh && ls -la $(which nvidia-bug-report.sh) 2>/dev/null || echo 'nvidia-bug-report.sh not found'"
                    nv_exit_code, nv_stdout, _ = (
                        await self.dut_manager.execute_host_command(
                            dut_id, nv_check_cmd, timeout=30, use_sudo=False
                        )
                    )
                    if nv_exit_code == 0:
                        await self._log_runtime(
                            "DEBUG",
                            "HostService",
                            f"nvidia-bug-report.sh availability: {nv_stdout.strip()}",
                            dut_id,
                        )

                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id, command, timeout=timeout, use_sudo=use_sudo
                )

                # Log detailed execution results
                end_time = time.time()
                execution_time = end_time - start_time
                await self._log_runtime(
                    "INFO",
                    "HostService",
                    f"Mode '{mode_name}' command completed in {execution_time:.2f} seconds",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Command completed - exit_code={exit_code}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"stdout length={len(stdout)}, stderr length={len(stderr)}",
                    dut_id,
                )
                if stdout:
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        f"stdout preview: {stdout[:200]}...",
                        dut_id,
                    )
                prompt_detected = False
                if stderr:
                    await self._log_runtime(
                        "DEBUG", "HostService", f"stderr: {stderr}", dut_id
                    )

                    # Check for sudo password prompt issues
                    if "[sudo] password for" in stderr:
                        prompt_detected = True
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "HostService",
                            f"Mode '{mode_name}' detected sudo password prompt in stderr - this may indicate authentication issues",
                        )
                        # Treat as warning only; do not mark as error to avoid partial status
                        sudo_prompt_locations.append(f"mode:{mode_name}")

                success = exit_code == 0

                # Post-execution diagnostics
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Running post-execution diagnostics for mode '{mode_name}'",
                    dut_id,
                )

                # Check what files were created in /tmp
                if "nvidia-bug-report" in command:
                    tmp_check_cmd = "ls -la /tmp/nvidia-bug-report* 2>/dev/null || echo 'No nvidia-bug-report files found in /tmp'"
                    tmp_exit_code, tmp_stdout, _ = (
                        await self.dut_manager.execute_host_command(
                            dut_id, tmp_check_cmd, timeout=30, use_sudo=False
                        )
                    )
                    if tmp_exit_code == 0:
                        await self._log_runtime(
                            "DEBUG",
                            "HostService",
                            f"Files created in /tmp: {tmp_stdout.strip()}",
                            dut_id,
                        )

                # Check disk space and /tmp directory status
                disk_check_cmd = "df -h /tmp && ls -ld /tmp"
                disk_exit_code, disk_stdout, _ = (
                    await self.dut_manager.execute_host_command(
                        dut_id, disk_check_cmd, timeout=30, use_sudo=False
                    )
                )
                if disk_exit_code == 0:
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        f"Disk space and /tmp status: {disk_stdout.strip()}",
                        dut_id,
                    )

                if success:
                    await self._log_collection_success(
                        dut_id, "command", f"Mode: {mode_name}"
                    )
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"Mode '{mode_name}' command succeeded (exit_code=0)",
                        dut_id,
                    )

                    # Handle file transfer if expect_file is True
                    if expect_file:
                        await self._log_runtime(
                            "INFO",
                            "HostService",
                            f"Mode '{mode_name}' expects file output, starting file transfer process",
                            dut_id,
                        )

                    # Save stdout to file
                    stdout_file_path = await self._save_data_with_common_pattern(
                        dut_id,
                        stdout,
                        f"{file_name}_stdout.log",
                        output_pattern=output_pattern,
                        substitutions={"file_name": f"{file_name}_stdout.log"},
                        **filtered_kwargs,
                    )
                    output_files.append(stdout_file_path)
                    successful_operations += 1

                    # If we expect a file to be generated, try to retrieve it
                    if expect_file:
                        # Extract the output file name from the command
                        output_file_match = re.search(
                            r"--output-file\s+([^\s\"]+)", command
                        )
                        if output_file_match:
                            remote_file = output_file_match.group(1)
                            # If the file is in /tmp, use the full path
                            if not remote_file.startswith("/"):
                                remote_file = f"/tmp/{remote_file}"

                            await self._log_runtime(
                                "DEBUG",
                                "HostService",
                                f"Extracted remote_file from command: {remote_file}",
                                dut_id,
                            )

                            # Get file extensions to try from configuration
                            file_extensions = mode_config.get(
                                "file_extensions",
                                [
                                    ".gz",
                                    ".tar.gz",
                                    ".tgz",
                                    ".zip",
                                    ".bz2",
                                    ".xz",
                                    ".7z",
                                    ".rar",
                                    "",
                                ],
                            )  # Comprehensive default list
                            await self._log_runtime(
                                "DEBUG",
                                "HostService",
                                f"Will try file extensions: {file_extensions}",
                                dut_id,
                            )

                            # Try to download the file with multiple fallback methods
                            download_success = False

                            for extension in file_extensions:
                                if download_success:
                                    break

                                # Construct the remote file path with extension
                                if extension:
                                    extended_remote_file = f"{remote_file}{extension}"
                                else:
                                    extended_remote_file = remote_file

                                await self._log_runtime(
                                    "DEBUG",
                                    "HostService",
                                    f"Attempting to transfer file with extension '{extension}': {extended_remote_file}",
                                    dut_id,
                                )

                                # Pre-transfer diagnostics
                                await self._log_runtime(
                                    "DEBUG",
                                    "HostService",
                                    f"Running pre-transfer diagnostics for file: {extended_remote_file}",
                                    dut_id,
                                )

                                # Check file existence and permissions before transfer
                                file_check_cmd = f"test -f '{extended_remote_file}' && ls -la '{extended_remote_file}' || echo 'File does not exist'"
                                file_check_exit_code, file_check_stdout, _ = (
                                    await self.dut_manager.execute_host_command(
                                        dut_id,
                                        file_check_cmd,
                                        timeout=30,
                                        use_sudo=False,
                                    )
                                )
                                if file_check_exit_code == 0:
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"Pre-transfer file check: {file_check_stdout.strip()}",
                                        dut_id,
                                    )

                                # Method 1: Direct transfer
                                transfer_success, transfer_error = (
                                    await self.dut_manager.transfer_host_files(
                                        dut_id,
                                        extended_remote_file,
                                        "/tmp",
                                        copy_to_destination=False,
                                    )
                                )
                                await self._log_runtime(
                                    "DEBUG",
                                    "HostService",
                                    f"Method 1 (Direct) - success: {transfer_success}, error: {transfer_error}",
                                    dut_id,
                                )

                                if not transfer_success:
                                    # Method 2: Check if file exists and has content
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"Method 1 failed, trying Method 2 (File check)",
                                        dut_id,
                                    )
                                    file_check_cmd = f"test -f {extended_remote_file} && test -s {extended_remote_file}"
                                    exit_code, _, stderr = (
                                        await self.dut_manager.execute_host_command(
                                            dut_id,
                                            file_check_cmd,
                                            timeout=60,
                                            use_sudo=use_sudo,
                                        )
                                    )
                                    if exit_code == 0:
                                        await self._log_runtime(
                                            "DEBUG",
                                            "HostService",
                                            f"File exists and has content, retrying transfer",
                                            dut_id,
                                        )
                                        transfer_success, transfer_error = (
                                            await self.dut_manager.transfer_host_files(
                                                dut_id,
                                                extended_remote_file,
                                                "/tmp",
                                                copy_to_destination=False,
                                            )
                                        )
                                        await self._log_runtime(
                                            "DEBUG",
                                            "HostService",
                                            f"Method 2 (Retry) - success: {transfer_success}, error: {transfer_error}",
                                            dut_id,
                                        )

                                if not transfer_success:
                                    # Method 3: Copy to temp location with permissions
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"Method 2 failed, trying Method 3 (Temp copy with permissions)",
                                        dut_id,
                                    )

                                    # Create temp directory using configurable path
                                    tool_config = await self.orchestrator.get_dut_specific_tool_config(
                                        dut_id
                                    )
                                    base_temp_dir = get_tool_temp_dir(
                                        tool_config, "/tmp"
                                    )
                                    temp_dir = f"{base_temp_dir}/nvdebug_transfer"
                                    mkdir_cmd = f"mkdir -p {temp_dir}"
                                    exit_code, _, stderr = (
                                        await self.dut_manager.execute_host_command(
                                            dut_id,
                                            mkdir_cmd,
                                            timeout=60,
                                            use_sudo=use_sudo,
                                        )
                                    )
                                    if exit_code == 0:
                                        # Set permissions
                                        chmod_cmd = f"chmod 777 {temp_dir}"
                                        await self.dut_manager.execute_host_command(
                                            dut_id,
                                            chmod_cmd,
                                            timeout=60,
                                            use_sudo=use_sudo,
                                        )

                                        # Copy file to temp location
                                        temp_file = f"{temp_dir}/{os.path.basename(extended_remote_file)}"
                                        cp_cmd = (
                                            f"cp {extended_remote_file} {temp_file}"
                                        )
                                        exit_code, _, stderr = (
                                            await self.dut_manager.execute_host_command(
                                                dut_id,
                                                cp_cmd,
                                                timeout=60,
                                                use_sudo=use_sudo,
                                            )
                                        )
                                        if exit_code == 0:
                                            # Set file permissions
                                            chmod_file_cmd = f"chmod 644 {temp_file}"
                                            await self.dut_manager.execute_host_command(
                                                dut_id,
                                                chmod_file_cmd,
                                                timeout=60,
                                                use_sudo=use_sudo,
                                            )

                                            # Try transfer from temp location
                                            transfer_success, transfer_error = (
                                                await self.dut_manager.transfer_host_files(
                                                    dut_id,
                                                    temp_file,
                                                    "/tmp",
                                                    copy_to_destination=False,
                                                )
                                            )
                                            await self._log_runtime(
                                                "DEBUG",
                                                "HostService",
                                                f"Method 3 (Temp copy) - success: {transfer_success}, error: {transfer_error}",
                                                dut_id,
                                            )

                                            # Clean up temp file
                                            await self.dut_manager.execute_host_command(
                                                dut_id,
                                                f"rm -f {temp_file}",
                                                timeout=60,
                                                use_sudo=use_sudo,
                                            )

                                if transfer_success:
                                    # Read the downloaded file content and save it
                                    downloaded_file = (
                                        f"/tmp/{os.path.basename(extended_remote_file)}"
                                    )
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"Checking if downloaded file exists: {downloaded_file}",
                                        dut_id,
                                    )
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"File exists: {os.path.exists(downloaded_file)}",
                                        dut_id,
                                    )
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"File exists: {os.path.exists(downloaded_file)}",
                                        dut_id,
                                    )
                                    if os.path.exists(downloaded_file):
                                        try:
                                            await self._log_runtime(
                                                "DEBUG",
                                                "HostService",
                                                f"Reading downloaded file: {downloaded_file}",
                                                dut_id,
                                            )
                                            with open(downloaded_file, "rb") as f:
                                                file_content = f.read()
                                            await self._log_runtime(
                                                "DEBUG",
                                                "HostService",
                                                f"Read {len(file_content)} bytes from file",
                                                dut_id,
                                            )
                                            await self._log_runtime(
                                                "DEBUG",
                                                "HostService",
                                                f"Read {len(file_content)} bytes from file",
                                                dut_id,
                                            )

                                            if decompress:
                                                # Decode bytes to string for text files (decompress)
                                                file_content_str = (
                                                    self._process_command_output(
                                                        file_content
                                                    )
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"Successfully decoded {len(file_content_str)} characters from bytes",
                                                )

                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"Saving decompressed file content with file_name: {file_name}",
                                                )
                                                final_path = await self._save_data_with_common_pattern(
                                                    dut_id,
                                                    file_content_str,
                                                    file_name,
                                                    output_pattern=output_pattern,
                                                    substitutions={
                                                        "file_name": file_name
                                                    },
                                                    **filtered_kwargs,
                                                )
                                            else:
                                                # Keep the file as binary/compressed (default behavior)
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"Preserving compression for file: {file_name}",
                                                )

                                                # Get the final filename using the same pattern logic
                                                # Extract the actual extension from the remote file (e.g., .gz, .log, etc.)
                                                # This makes it generic to handle any file extension
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"=== Filename Generation Debug ===",
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"extended_remote_file: {extended_remote_file}",
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"file_name from config: {file_name}",
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"output_pattern: {output_pattern}",
                                                )

                                                actual_extension = os.path.splitext(
                                                    extended_remote_file
                                                )[1]
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"os.path.splitext result: {os.path.splitext(extended_remote_file)}",
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"extracted extension: '{actual_extension}'",
                                                )

                                                # Get base filename from pattern, then append the actual extension
                                                base_filename = (
                                                    self.get_output_filename(
                                                        output_pattern,
                                                        file_name,
                                                        "",
                                                        {"file_name": file_name},
                                                    )
                                                )
                                                final_filename = (
                                                    f"{base_filename}{actual_extension}"
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"get_output_filename result: {final_filename}",
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"=== End Filename Generation Debug ===",
                                                )

                                                # Save binary content directly to file
                                                if self.logger:
                                                    file_path = await self.logger.create_collector_log_file(
                                                        dut_id,
                                                        "host",
                                                        filtered_kwargs.get(
                                                            "collector_id", ""
                                                        ),
                                                        final_filename,
                                                    )
                                                    with open(file_path, "wb") as f:
                                                        f.write(file_content)
                                                    final_path = str(file_path)
                                                    await self._write_to_dut_runtime_log(
                                                        dut_id,
                                                        "DEBUG",
                                                        "HostService",
                                                        f"Binary file saved to: {final_path}",
                                                    )
                                                else:
                                                    await self._write_to_dut_runtime_log(
                                                        dut_id,
                                                        "ERROR",
                                                        "HostService",
                                                        "No logger available to save binary file",
                                                    )
                                                    final_path = None
                                            await self._write_to_dut_runtime_log(
                                                dut_id,
                                                "DEBUG",
                                                "HostService",
                                                f"File saved to: {final_path}",
                                            )
                                            output_files.append(final_path)
                                            download_success = True

                                            # Clean up downloaded file
                                            os.remove(downloaded_file)

                                            # Clean up remote file
                                            await self.dut_manager.execute_host_command(
                                                dut_id,
                                                f"rm -f {extended_remote_file}",
                                                timeout=60,
                                                use_sudo=use_sudo,
                                            )
                                        except Exception as e:
                                            await self._log_collection_failure(
                                                dut_id,
                                                "file_read",
                                                f"Mode: {mode_config.get('mode', 'unknown')}",
                                                f"Failed to read downloaded file {downloaded_file}: {str(e)}",
                                                collector_id=kwargs.get("collector_id"),
                                            )

                            if not download_success:
                                await self._write_to_dut_runtime_log(
                                    dut_id,
                                    "DEBUG",
                                    "HostService",
                                    f"All file extension attempts failed for {remote_file}",
                                )
                                await self._log_collection_failure(
                                    dut_id,
                                    "file_download",
                                    f"Mode: {mode_config.get('mode', 'unknown')}",
                                    f"Failed to download {remote_file} with any extension",
                                    collector_id=kwargs.get("collector_id"),
                                )
                                if expect_file:
                                    success = False
                                    await self._write_to_dut_runtime_log(
                                        dut_id,
                                        "ERROR",
                                        "HostService",
                                        f"Mode '{mode_name}' marked as FAILED due to file transfer failure",
                                    )
                                    error_messages.append(
                                        f"Mode '{mode_name}' failed: File transfer failed for {remote_file} with all extensions"
                                    )
                else:
                    # Log both stdout and stderr for failed commands
                    error_details = f"exit_code: {exit_code}"
                    if stdout:
                        error_details += f", stdout: {stdout}"
                    if stderr:
                        error_details += f", stderr: {stderr}"
                    await self._log_collection_failure(
                        dut_id,
                        "command",
                        f"Mode: {mode_name}",
                        error_details,
                        collector_id=kwargs.get("collector_id"),
                    )
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        f"Mode '{mode_name}' command failed: {error_details}",
                    )
                    error_messages.append(
                        f"Mode command failed: {mode_name} - {error_details}"
                    )
                    if prompt_detected:
                        error_messages.append(
                            f"Mode '{mode_name}' encountered sudo password prompt"
                        )

                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"=== Completed Mode {i}/{len(command_modes)}: {mode_name} (success={success}) ===",
                )
                status_list.append(success)

        # Determine overall status
        # For collectors, we need to distinguish between command success and file transfer success
        # If any mode fails due to file transfer issues, we should report partial success or failure
        successful_modes = sum(status_list)
        total_modes = len(status_list)

        # Check if we have any file transfer failures in error messages
        has_file_transfer_failures = any(
            "File transfer failed" in msg for msg in error_messages
        )

        if successful_modes == 0:
            # Complete failure - no modes succeeded
            overall_success = False
        elif has_file_transfer_failures:
            # Some modes succeeded but file transfers failed - report as partial success
            if successful_modes == total_modes:
                # All commands succeeded but some file transfers failed - partial success
                overall_success = True
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "HostService",
                    f"Collection completed with file transfer failures - reporting as partial success",
                )
            else:
                # Some commands failed AND some file transfers failed - failure
                overall_success = False
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    f"Collection failed - {successful_modes}/{total_modes} modes succeeded but file transfers also failed",
                )
        else:
            # All modes succeeded and no file transfer failures
            overall_success = True

        # Use the standardized collection summary from base service
        await self._log_collection_summary(
            dut_id=dut_id,
            collection_name="Advanced Host Collection",
            total_operations=total_modes,
            successful_operations=successful_modes,
            failed_operations=total_modes - successful_modes,
            output_files_count=len(output_files),
            additional_details={
                "Overall success": overall_success,
                "File transfer failures": has_file_transfer_failures,
                "Sudo prompt detected": bool(sudo_prompt_locations),
                "Sudo prompt locations": sudo_prompt_locations,
            },
        )

        if overall_success:
            # Determine if this is partial success due to file transfer failures
            if has_file_transfer_failures:
                await self._log_collection_success(
                    dut_id, "advanced_collection", "Advanced Host Collection (Partial)"
                )
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "HostService",
                    f"Advanced collection completed with PARTIAL SUCCESS - {successful_modes}/{total_modes} modes successful, but some file transfers failed",
                )
                return await self._create_standardized_collector_result(
                    successful_operations=successful_modes,
                    total_operations=total_modes,
                    output_files=output_files,
                    error_messages=error_messages,
                    operation_name="advanced_collection",
                    additional_context={
                        "message": "Advanced collection completed with partial success due to file transfer failures",
                        "successful_modes": successful_modes,
                        "total_modes": total_modes,
                        "has_file_transfer_failures": True,
                        "sudo_prompt_detected": bool(sudo_prompt_locations),
                        "sudo_prompt_locations": sudo_prompt_locations,
                    },
                )
            else:
                await self._log_collection_success(
                    dut_id, "advanced_collection", "Advanced Host Collection"
                )
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"Advanced collection completed successfully with {successful_modes}/{total_modes} modes successful",
                )
                return await self._create_standardized_collector_result(
                    successful_operations=successful_modes,
                    total_operations=total_modes,
                    output_files=output_files,
                    error_messages=error_messages,
                    operation_name="advanced_collection",
                    additional_context={
                        "message": "Advanced collection completed successfully",
                        "successful_modes": successful_modes,
                        "total_modes": total_modes,
                        "sudo_prompt_detected": bool(sudo_prompt_locations),
                        "sudo_prompt_locations": sudo_prompt_locations,
                    },
                )
        else:
            # Collection failed - either all commands failed or file transfers failed
            failure_reason = (
                "All commands failed"
                if successful_modes == 0
                else "File transfer failures"
            )
            await self._log_collection_failure(
                dut_id,
                "advanced_collection",
                "Advanced Host Collection",
                failure_reason,
                collector_id=kwargs.get("collector_id"),
            )
            await self._write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "HostService",
                f"Advanced collection failed - {failure_reason}",
            )
            return await self._create_standardized_collector_result(
                successful_operations=successful_modes,
                total_operations=total_modes,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="advanced_collection",
                additional_context={
                    "message": f"Advanced collection failed: {failure_reason}",
                    "failure_reason": failure_reason,
                    "successful_modes": successful_modes,
                    "total_modes": total_modes,
                    "sudo_prompt_detected": bool(sudo_prompt_locations),
                    "sudo_prompt_locations": sudo_prompt_locations,
                },
            )

    # ============================================================================
    # 10.3 EXISTING METHODS (Keep for backward compatibility)
    # ============================================================================

    async def _handle_host_file_search_and_archive(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Generic handler for file search and archive operations (used by H16, etc.).

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for output files.
        """

        async def _file_search_and_archive():
            """
            Handle file search and archive operations.

            Args:
                dut_id: DUT ID.
                function_tag: Function tag for output files.
            """
            file_pattern = kwargs.get("file_pattern", "*")
            search_config = kwargs.get("search_config", {})
            archive_config = kwargs.get("archive_config", {})
            use_sudo = kwargs.get("use_sudo", True)
            ignore_empty_results = kwargs.get("ignore_empty_results", False)

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Starting file search and archive with pattern: {file_pattern}",
            )

            # Step 1: File search
            search_directories = search_config.get("directories", ["/"])
            search_exclusions = search_config.get("exclusions", [])
            max_depth = search_config.get("max_depth", 10)

            # Build find command with exclusions
            find_command = (
                f"find {' '.join(search_directories)} -name '{file_pattern}' -type f"
            )
            if search_exclusions:
                for exclusion in search_exclusions:
                    find_command += f" -not -path '{exclusion}'"
            find_command += f" 2>/dev/null | head -{max_depth}"

            exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                dut_id, find_command, timeout=300, use_sudo=use_sudo
            )

            if exit_code != 0 or not stdout.strip():
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "HostService",
                    f"No files matching '{file_pattern}' found",
                )

                # Handle summary generation using helper function
                output_files = await self._handle_collection_summary_generation(
                    dut_id=dut_id,
                    function_tag=function_tag,
                    collection_name=f"{function_tag} File Search",
                    total_operations=1,
                    successful_operations=0,
                    failed_operations=1,
                    output_files=[],
                    additional_details={
                        "file_pattern": file_pattern,
                        "search_directories": search_directories,
                        "found_files": [],  # No files found in this case
                    },
                    kwargs=kwargs,
                    collection_type="file_search_and_archive",
                    ignore_empty_results=ignore_empty_results,
                )

                return await self._create_standardized_collector_result(
                    successful_operations=1 if ignore_empty_results else 0,
                    total_operations=1,
                    output_files=output_files,
                    error_messages=(
                        []
                        if ignore_empty_results
                        else [f"No files matching '{file_pattern}' found"]
                    ),
                    operation_name="file_search_and_archive",
                    additional_context={
                        "message": f"No files matching '{file_pattern}' found, skipped",
                        "file_pattern": file_pattern,
                        "search_directories": search_directories,
                        "ignore_empty_results": ignore_empty_results,
                    },
                )

            found_files = [f.strip() for f in stdout.strip().split("\n") if f.strip()]
            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Found {len(found_files)} files: {found_files}",
            )

            # Step 2: Process files based on configuration
            output_files = []
            status_list = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            for file_path in found_files:
                total_operations += 1
                await self._write_to_dut_runtime_log(
                    dut_id, "INFO", "HostService", f"Processing file: {file_path}"
                )

                # Get working directory
                dir_command = f"dirname {file_path}"
                exit_code, stdout, _ = await self.dut_manager.execute_host_command(
                    dut_id, dir_command, timeout=60, use_sudo=use_sudo
                )

                if exit_code != 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        f"Failed to get directory for {file_path}",
                    )
                    error_messages.append(f"Failed to get directory for {file_path}")
                    status_list.append(False)

                    # Create error log file for failed operations
                    error_log_path = await self._create_error_log_file(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                        error_message=f"Failed to get directory for {file_path}",
                        context={
                            "file_path": file_path,
                            "operation": "file_collection",
                            "exit_code": exit_code,
                        },
                    )

                    # Add error log file to output files
                    if error_log_path:
                        output_files.append(error_log_path)
                    continue

                working_dir = stdout.strip()

                # Apply processing logic based on configuration
                processing_success, saved_file_path = await self._process_file_with_config(
                    dut_id,
                    file_path,
                    working_dir,
                    search_config,
                    archive_config,
                    output_pattern,
                    filtered_kwargs,
                    use_sudo,
                )

                if processing_success:
                    status_list.append(True)
                    successful_operations += 1
                    # Track at least one data artifact so finalize doesn't mark as skipped
                    if saved_file_path:
                        output_files.append(saved_file_path)
                else:
                    status_list.append(False)
                    error_messages.append(f"Failed to process file: {file_path}")

                    # Create error log file for failed operations
                    error_log_path = await self._create_error_log_file(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                        error_message=f"Failed to process file: {file_path}",
                        context={
                            "file_path": file_path,
                            "operation": "file_processing",
                        },
                    )

                    # Add error log file to output files
                    if error_log_path:
                        output_files.append(error_log_path)

            # Determine overall status
            overall_success = any(status_list)
            successful_files = sum(status_list)
            total_files = len(found_files)

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"File search and archive completed: {successful_files}/{total_files} files successful",
            )

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} File Search",
                total_operations=total_files,
                successful_operations=successful_files,
                failed_operations=len(error_messages),
                output_files=output_files,
                additional_details={
                    "file_pattern": file_pattern,
                    "search_directories": search_directories,
                    "found_files": found_files,
                },
                kwargs=kwargs,
                collection_type="file_search_and_archive",
                ignore_empty_results=ignore_empty_results,
            )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="file_search_and_archive",
                additional_context={
                    "message": "File search and archive completed",
                    "files_found": total_files,
                    "successful_files": successful_files,
                    "total_files": total_files,
                    "ignore_empty_results": ignore_empty_results,
                },
            )

        return await self._execute_with_error_handling(
            dut_id, "file_search_and_archive", _file_search_and_archive
        )

    async def _handle_host_device_based_log_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Generic handler for device-based log collection (used by H17, etc.).

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for output files.
        """

        async def _device_based_log_collection():
            """
            Handle device-based log collection.

            Args:
                dut_id: DUT ID.
                function_tag: Function tag for output files.
            """
            device_detection = kwargs.get("device_detection", {})
            log_commands = kwargs.get("log_commands", [])
            use_sudo = kwargs.get("use_sudo", True)

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            await self._write_to_dut_runtime_log(
                dut_id, "INFO", "HostService", "Starting device-based log collection"
            )

            # Step 1: Device detection
            detection_command = device_detection.get("command", "")
            device_pattern = device_detection.get("device_pattern", r"(\S+)")
            skip_message = device_detection.get("skip_message", "No devices found")

            if not detection_command:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    "No device detection command specified",
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=["No device detection command specified"],
                    operation_name="device_based_log_collection",
                    additional_context={"device_detection": device_detection},
                )

            exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                dut_id, detection_command, timeout=60, use_sudo=use_sudo
            )

            if exit_code != 0:
                await self._write_to_dut_runtime_log(
                    dut_id, "WARN", "HostService", f"Device detection failed: {stderr}"
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[f"Device detection failed: {stderr}"],
                    operation_name="device_based_log_collection",
                    additional_context={
                        "message": skip_message,
                        "detection_command": detection_command,
                    },
                )

            # Parse device list
            matches = re.findall(device_pattern, stdout, re.MULTILINE)

            if not matches:
                await self._write_to_dut_runtime_log(
                    dut_id, "INFO", "HostService", "No devices found"
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="device_based_log_collection",
                    additional_context={
                        "message": skip_message,
                        "device_pattern": device_pattern,
                    },
                )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Found {len(matches)} devices: {matches}",
            )

            # Get configurable timeout from collector definition and DUT config
            collector_id = kwargs.get("collector_id", "")
            collector_def = kwargs.get("collector_def", {})
            dut_config = self.dut_manager.get_dut_config(dut_id)
            default_timeout = get_collector_timeout(
                collector_id, collector_def, dut_config, 300
            )

            # Step 2: Collect logs for each device
            output_files = []
            status_list = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            for device in matches:
                total_operations += 1
                device_name = os.path.basename(device)
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"Collecting logs for device: {device_name}",
                )

                # Create temporary directory on host using configurable path
                tool_config = await self.orchestrator.get_dut_specific_tool_config(
                    dut_id
                )
                base_temp_dir = get_tool_temp_dir(tool_config, "/tmp")
                host_temp_dir = f"{base_temp_dir}/nvdebug_logs_{device_name}"
                mkdir_cmd = f"mkdir -p {host_temp_dir}"
                exit_code, _, stderr = await self.dut_manager.execute_host_command(
                    dut_id, mkdir_cmd, timeout=60, use_sudo=use_sudo
                )

                if exit_code != 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        f"Failed to create temp directory: {stderr}",
                    )
                    error_messages.append(
                        f"Failed to create temp directory for {device_name}: {stderr}"
                    )
                    status_list.append(False)

                    # Create error log file for failed operations
                    error_log_path = await self._create_error_log_file(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                        error_message=f"Failed to create temp directory for {device_name}: {stderr}",
                        context={
                            "device_name": device_name,
                            "operation": "temp_directory_creation",
                            "exit_code": exit_code,
                        },
                    )

                    # Add error log file to output files
                    if error_log_path:
                        output_files.append(error_log_path)
                    continue

                # Set permissions
                chmod_cmd = f"chmod 755 {host_temp_dir}"
                await self.dut_manager.execute_host_command(
                    dut_id, chmod_cmd, timeout=60, use_sudo=use_sudo
                )

                # Execute log commands for this device
                device_success = True

                for cmd_config in log_commands:
                    command_template = cmd_config.get("command_template", "")
                    file_template = cmd_config.get("file_template", "")
                    description = cmd_config.get("description", "Log command")
                    timeout = cmd_config.get("timeout", default_timeout)
                    direct_file_output = cmd_config.get("direct_file_output", False)

                    # Substitute device variables in command and filename
                    filename = file_template.format(
                        device=device, device_name=device_name
                    )
                    host_output_file = f"{host_temp_dir}/{filename}"
                    command = command_template.format(
                        device=device,
                        device_name=device_name,
                        output_file=host_output_file,
                    )

                    if direct_file_output:
                        # Command already includes output file
                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_host_command(
                                dut_id, command, timeout=timeout, use_sudo=use_sudo
                            )
                        )
                    else:
                        # Wrap command to redirect output
                        full_cmd = f"{command} > {host_output_file}"
                        wrapped_cmd = f"bash -c {shlex.quote(full_cmd)}"
                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_host_command(
                                dut_id, wrapped_cmd, timeout=timeout, use_sudo=use_sudo
                            )
                        )

                    if exit_code != 0:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "HostService",
                            f"Failed to collect {description} for {device_name}: {stderr}",
                        )
                        device_success = False
                        continue

                    # Set file permissions
                    chmod_cmd = f"chmod 644 {host_output_file}"
                    await self.dut_manager.execute_host_command(
                        dut_id, chmod_cmd, timeout=60, use_sudo=use_sudo
                    )

                    # Download the file directly to the collector's output directory
                    # Create device-specific subdirectory in the collector output directory
                    # Use the same approach as _save_data_with_common_pattern to get collector directory
                    collector_id = kwargs.get("collector_id")
                    original_collector_id = await self._get_original_collector_id(
                        dut_id, collector_id
                    )

                    # DEBUG: Log file path determination in HostService
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        f"File path determination - collector_id: {collector_id}, original_collector_id: {original_collector_id}",
                    )

                    if original_collector_id != "unknown":
                        file_collector_id = original_collector_id
                        if original_collector_id != collector_id:
                            await self._log_runtime(
                                "WARNING",
                                "HostService",
                                f"Using original collector ID '{original_collector_id}' for file paths while current context is '{collector_id}'",
                            )
                    else:
                        file_collector_id = collector_id

                    temp_file_path = await self.logger.create_collector_log_file(
                        dut_id, "host", file_collector_id, "temp.bin"
                    )
                    collector_output_dir = str(temp_file_path.parent)
                    device_output_dir = os.path.join(
                        collector_output_dir, f"device_{device_name}"
                    )
                    os.makedirs(device_output_dir, exist_ok=True)

                    transfer_success, transfer_error = (
                        await self.dut_manager.transfer_host_files(
                            dut_id,
                            host_output_file,
                            device_output_dir,
                            copy_to_destination=False,
                        )
                    )

                    if not transfer_success:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "HostService",
                            f"Failed to download {filename}: {transfer_error}",
                        )
                        device_success = False

                # Clean up temporary directory on host
                await self.dut_manager.execute_host_command(
                    dut_id, f"rm -rf {host_temp_dir}", timeout=60, use_sudo=use_sudo
                )

                if device_success:
                    # Files are already in the correct location in the collector output directory
                    # Just verify the device directory exists and has files
                    temp_file_path = await self.logger.create_collector_log_file(
                        dut_id, "host", kwargs.get("collector_id", "H17"), "temp.bin"
                    )
                    collector_output_dir = str(temp_file_path.parent)
                    device_output_dir = os.path.join(
                        collector_output_dir, f"device_{device_name}"
                    )

                    if os.path.exists(device_output_dir):
                        try:
                            # Count the files in the device directory
                            file_count = len(
                                [
                                    f
                                    for f in os.listdir(device_output_dir)
                                    if os.path.isfile(
                                        os.path.join(device_output_dir, f)
                                    )
                                ]
                            )
                            if file_count > 0:
                                # Add the device directory path to output files
                                output_files.append(device_output_dir)
                                status_list.append(True)
                                successful_operations += 1
                        except Exception as e:
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "ERROR",
                                "HostService",
                                f"Error processing device directory for {device_name}: {str(e)}",
                            )
                            error_messages.append(
                                f"Error processing device directory for {device_name}: {str(e)}"
                            )
                            status_list.append(False)

                            # Create error log file for failed operations
                            error_log_path = await self._create_error_log_file(
                                dut_id=dut_id,
                                collector_id=kwargs.get("collector_id"),
                                error_message=f"Error processing device directory for {device_name}: {str(e)}",
                                context={
                                    "device_name": device_name,
                                    "operation": "device_directory_processing",
                                    "error": str(e),
                                },
                            )

                            # Add error log file to output files
                            if error_log_path:
                                output_files.append(error_log_path)
                    else:
                        error_messages.append(
                            f"No local device directory found for {device_name}"
                        )
                        status_list.append(False)

                        # Create error log file for failed operations
                        error_log_path = await self._create_error_log_file(
                            dut_id=dut_id,
                            collector_id=kwargs.get("collector_id"),
                            error_message=f"No local device directory found for {device_name}",
                            context={
                                "device_name": device_name,
                                "operation": "device_directory_check",
                            },
                        )

                        # Add error log file to output files
                        if error_log_path:
                            output_files.append(error_log_path)
                else:
                    error_messages.append(f"Device processing failed for {device_name}")
                    status_list.append(False)

                    # Create error log file for failed operations
                    error_log_path = await self._create_error_log_file(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                        error_message=f"Device processing failed for {device_name}",
                        context={
                            "device_name": device_name,
                            "operation": "device_processing",
                        },
                    )

                    # Add error log file to output files
                    if error_log_path:
                        output_files.append(error_log_path)

            # Determine overall status
            overall_success = any(status_list)
            successful_devices = sum(status_list)
            total_devices = len(matches)

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Device-based log collection completed: {successful_devices}/{total_devices} devices successful",
            )

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} Device Log Collection",
                total_operations=total_devices,
                successful_operations=successful_devices,
                failed_operations=len(error_messages),
                output_files=output_files,
                additional_details={
                    "Detection command": detection_command,
                    "Device pattern": device_pattern,
                    "Devices found": len(matches),
                    "Log commands": [cmd.get("command", "") for cmd in log_commands],
                },
                kwargs=kwargs,
                collection_type="device_based_log_collection",
                ignore_empty_results=False,  # Device-based collection should fail if no devices found
            )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="device_based_log_collection",
                additional_context={
                    "message": "Device-based log collection completed",
                    "devices_found": total_devices,
                    "successful_devices": successful_devices,
                    "total_devices": total_devices,
                },
            )

        return await self._execute_with_error_handling(
            dut_id, "device_based_log_collection", _device_based_log_collection
        )

    async def _handle_host_system_info_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Generic handler for system information collection (used by H18, H19, etc.).

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for output files.
        """

        async def _system_info_collection():
            """
            Handle system information collection.

            Args:
                dut_id: DUT ID.
                function_tag: Function tag for output files.
            """
            system_info_type = kwargs.get("system_info_type", "basic")
            collection_type = (
                system_info_type  # Use system_info_type for backward compatibility
            )
            # Get collection level from DUT config or tool config, fallback to L1
            collection_level = kwargs.get("collection_level", "L1")

            # Try to get collection level from DUT manager if available
            if hasattr(self, "dut_manager") and self.dut_manager:
                try:
                    # Get collection level from the specific DUT being processed
                    dut_config = self.dut_manager.get_dut_config(dut_id)
                    if dut_config and "collection_level" in dut_config:
                        collection_level = dut_config["collection_level"]
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"Using collection level from DUT config: {collection_level}",
                        )
                except Exception as e:
                    await self._write_to_dut_runtime_log(
                        "system",
                        "WARNING",
                        "HostService",
                        f"Could not get collection level from DUT config: {e}, using default: {collection_level}",
                    )

            use_sudo = kwargs.get("use_sudo", True)

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Starting {collection_type} system information collection (Level: {collection_level})",
            )

            output_files = []
            status_list = []
            error_messages = []
            detailed_error_messages = (
                []
            )  # Track ALL failed commands for partial error logs
            successful_operations = 0
            total_operations = 0

            # Get collection configuration from YAML parameters (fully YAML-driven)
            collection_config = kwargs.get("collection_commands", [])

            if not collection_config:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    f"No collection_commands provided in YAML for {collection_type}. This collector must be fully YAML-driven.",
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[
                        f"No collection_commands provided in YAML for {collection_type}. This collector must be fully YAML-driven."
                    ],
                    operation_name="system_info_collection",
                    additional_context={"collection_type": collection_type},
                )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Using YAML-provided configuration with {len(collection_config)} commands",
            )

            # Execute collection commands with level-based filtering
            for cmd_config in collection_config:
                command = cmd_config.get("command")
                file_name = cmd_config.get("file_name")
                description = cmd_config.get("description", "System info command")
                timeout = cmd_config.get("timeout", 60)
                ignore_errors = cmd_config.get("ignore_errors", False)
                level_requirement = cmd_config.get(
                    "level_requirement", "L1"
                )  # Default to L1

                if not command or not file_name:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "HostService",
                        f"Skipping command with missing 'command' or 'file_name': {cmd_config}",
                    )
                    continue

                # Check if command should run based on collection level
                # Level filtering logic:
                # - L1 level: Only runs L1 commands
                # - L2 level: Runs both L1 and L2 commands
                # - L3 level: Runs L1, L2, and L3 commands (future)
                if level_requirement == "L2" and collection_level not in ["L2", "L3"]:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Skipping L2 command '{description}' (current level: {collection_level})",
                    )
                    continue

                elif level_requirement == "L1" and collection_level not in [
                    "L1",
                    "L2",
                    "L3",
                ]:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Skipping L1 command '{description}' (current level: {collection_level})",
                    )
                    continue

                # Only count operations that actually get executed
                total_operations += 1

                await self._write_to_dut_runtime_log(
                    dut_id, "DEBUG", "HostService", f"Executing: {description}"
                )

                success, file_path = await self._execute_command_and_save(
                    dut_id=dut_id,
                    command=command,
                    file_name=file_name,
                    operation_name="system_info",
                    operation_type="system_info",
                    output_pattern=output_pattern,
                    filtered_kwargs=filtered_kwargs,
                    use_sudo=use_sudo,
                    timeout=timeout,
                )

                if success and file_path:
                    output_files.append(file_path)
                    status_list.append(True)
                    successful_operations += 1
                else:
                    # Always add to detailed error messages for partial error logs
                    detailed_error_messages.append(f"{description}: {command}")
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Added to detailed_error_messages: {description}: {command}",
                    )

                    if ignore_errors:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "HostService",
                            f"Command failed (ignored): {description}",
                        )
                        status_list.append(
                            True
                        )  # Count as success if errors are ignored
                        successful_operations += 1
                    else:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "HostService",
                            f"Command failed: {description}",
                        )
                        error_messages.append(f"{description}: {command}")
                        status_list.append(False)

                        # Create error log file for failed operations
                        error_log_path = await self._create_error_log_file(
                            dut_id=dut_id,
                            collector_id=kwargs.get("collector_id"),
                            error_message=f"System info command failed: {description}",
                            context={
                                "command": command,
                                "description": description,
                                "operation": "system_info_command",
                            },
                        )

                        # Add error log file to output files
                        if error_log_path:
                            output_files.append(error_log_path)

            # Determine overall status
            overall_success = any(status_list)
            successful_commands = sum(status_list)
            total_commands = total_operations  # Use actual executed operations count

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"System information collection completed: {successful_commands}/{total_commands} commands successful",
            )

            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                f"detailed_error_messages count: {len(detailed_error_messages)}, content: {detailed_error_messages}",
            )

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} System Info Collection",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=len(error_messages),
                output_files=output_files,
                additional_details={
                    "Collection type": collection_type,
                    "Collection level": collection_level,
                    "Total commands": total_commands,
                    "Successful commands": successful_commands,
                    "Collection commands": [
                        cmd.get("command", cmd) if isinstance(cmd, dict) else cmd
                        for cmd in collection_config
                    ],
                },
                kwargs=kwargs,
                collection_type="system_info_collection",
                ignore_empty_results=True,
            )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=detailed_error_messages,  # Use detailed errors for partial logs
                operation_name="system_info_collection",
                additional_context={
                    "message": f"{collection_type.capitalize()} system information collection completed",
                    "collection_type": collection_type,
                    "collection_level": collection_level,
                    "successful_commands": successful_commands,
                    "total_commands": total_commands,
                    "detailed_errors": detailed_error_messages,  # Also include in context
                },
            )

        return await self._execute_with_error_handling(
            dut_id, "system_info_collection", _system_info_collection
        )

    async def _process_file_with_config(
        self,
        dut_id: str,
        file_path: str,
        working_dir: str,
        search_config: Dict,
        archive_config: Dict,
        output_pattern: str,
        filtered_kwargs: Dict,
        use_sudo: bool,
    ) -> Tuple[bool, Optional[str]]:
        """Process a single file according to configuration.

        Args:
            dut_id: DUT ID.
            file_path: Path to the file.
            working_dir: Working directory.
            search_config: Search configuration.
            archive_config: Archive configuration.
            output_pattern: Output pattern.
            filtered_kwargs: Filtered kwargs.
            use_sudo: Use sudo.
        """

        folders_to_check = search_config.get("folders_to_check", [])
        sub_folder_name = search_config.get("sub_folder_name", "")
        log_dir_pattern = search_config.get("log_dir_pattern", "*logs*")

        # Check for specified folders in working directory
        for folder in folders_to_check:
            folder_path = f"{working_dir}/{folder}"

            # Check if folder exists
            test_cmd = f"test -d '{folder_path}'"
            exit_code, _, _ = await self.dut_manager.execute_host_command(
                dut_id, test_cmd, timeout=60, use_sudo=use_sudo
            )

            if exit_code != 0:
                continue  # Folder doesn't exist, try next

            await self._write_to_dut_runtime_log(
                dut_id, "INFO", "HostService", f"Found folder: {folder_path}"
            )

            # Handle subdirectories
            if folder.startswith("dgx_"):
                sub_folder_path = f"{folder_path}/{sub_folder_name}"
                test_cmd = f"test -d '{sub_folder_path}'"
                exit_code, _, _ = await self.dut_manager.execute_host_command(
                    dut_id, test_cmd, timeout=60, use_sudo=use_sudo
                )

                if exit_code != 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "HostService",
                        f"Subdirectory '{sub_folder_name}' not found in {folder_path}",
                    )
                    continue

                folder_path = sub_folder_path
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"Navigated to subdirectory: {folder_path}",
                )

            # Find log directories
            find_cmd = (
                f"find '{folder_path}' -type d -name '{log_dir_pattern}' 2>/dev/null"
            )
            exit_code, stdout, _ = await self.dut_manager.execute_host_command(
                dut_id, find_cmd, timeout=60, use_sudo=use_sudo
            )

            if exit_code != 0 or not stdout.strip():
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "HostService",
                    f"No '{log_dir_pattern}' directories found in {folder_path}",
                )
                continue

            log_dirs = [d.strip() for d in stdout.strip().split("\n") if d.strip()]

            # Create archive of log directories using configurable temp directory
            # Use -h flag to follow symlinks (dereference) to ensure actual data is archived
            # Important: -h must come before -f, not after it
            tool_config = await self.orchestrator.get_dut_specific_tool_config(dut_id)
            base_temp_dir = get_tool_temp_dir(tool_config, "/tmp")
            archive_name = (
                f"{base_temp_dir}/logs_{os.path.basename(working_dir)}_{folder}.tar.gz"
            )
            # Pre-clear any existing archive to avoid collisions/permissions issues
            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                f"Pre-clearing any existing archive '{archive_name}'",
            )
            await self.dut_manager.execute_host_command(
                dut_id, f"rm -f '{archive_name}'", timeout=60, use_sudo=use_sudo
            )
            tar_command = f"tar -h -czf '{archive_name}' " + " ".join(
                f"'{log_dir}'" for log_dir in log_dirs
            )

            exit_code, _, stderr = await self.dut_manager.execute_host_command(
                dut_id, tar_command, timeout=300, use_sudo=use_sudo
            )

            if exit_code != 0:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    f"Failed to create archive '{archive_name}': {stderr}",
                )
                return False, None

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Created archive '{archive_name}' on host",
            )

            # Diagnostic: Check archive details and system info
            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                f"Running diagnostic commands for archive: '{archive_name}'",
            )

            # Check current user and groups
            whoami_cmd = "whoami && id && groups"
            whoami_exit_code, whoami_stdout, _ = (
                await self.dut_manager.execute_host_command(
                    dut_id, whoami_cmd, timeout=30, use_sudo=False
                )
            )
            if whoami_exit_code == 0:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Current user info: {whoami_stdout.strip()}",
                )

            # Check /tmp directory permissions
            tmp_perms_cmd = "ls -ld /tmp && ls -la /tmp | head -10"
            tmp_exit_code, tmp_stdout, _ = await self.dut_manager.execute_host_command(
                dut_id, tmp_perms_cmd, timeout=30, use_sudo=False
            )
            if tmp_exit_code == 0:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"/tmp directory info: {tmp_stdout.strip()}",
                )

            # Check if archive exists and get detailed info
            archive_info_cmd = f"test -f '{archive_name}' && echo 'Archive exists' || echo 'Archive not found'"
            archive_test_exit_code, archive_test_stdout, _ = (
                await self.dut_manager.execute_host_command(
                    dut_id, archive_info_cmd, timeout=30, use_sudo=False
                )
            )
            if archive_test_exit_code == 0:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Archive existence check: {archive_test_stdout.strip()}",
                )

            # Fix permissions for SFTP access (if using sudo)
            if use_sudo:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Archive created with sudo, fixing permissions for SFTP access: '{archive_name}'",
                )

                # First check current ownership
                ls_command = f"ls -la '{archive_name}'"
                ls_exit_code, ls_stdout, _ = (
                    await self.dut_manager.execute_host_command(
                        dut_id, ls_command, timeout=30, use_sudo=False
                    )
                )
                if ls_exit_code == 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Archive ownership before chown: {ls_stdout.strip()}",
                    )

                # Change ownership to current user
                chown_command = f"chown $USER:$USER '{archive_name}'"
                chown_exit_code, chown_stdout, chown_stderr = (
                    await self.dut_manager.execute_host_command(
                        dut_id, chown_command, timeout=60, use_sudo=use_sudo
                    )
                )

                if chown_exit_code != 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "HostService",
                        f"Failed to change ownership of archive '{archive_name}': {chown_stderr}",
                    )
                    # Continue anyway - the fallback mechanisms might still work
                else:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        f"Successfully changed ownership of archive '{archive_name}' for SFTP access",
                    )

                    # Verify ownership change
                    ls_exit_code, ls_stdout, _ = (
                        await self.dut_manager.execute_host_command(
                            dut_id, ls_command, timeout=30, use_sudo=False
                        )
                    )
                    if ls_exit_code == 0:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"Archive ownership after chown: {ls_stdout.strip()}",
                        )

                        # Additional verification: Check if we can read the file
                        read_test_cmd = f"head -c 100 '{archive_name}' > /dev/null && echo 'File readable' || echo 'File not readable'"
                        read_test_exit_code, read_test_stdout, _ = (
                            await self.dut_manager.execute_host_command(
                                dut_id, read_test_cmd, timeout=30, use_sudo=False
                            )
                        )
                        if read_test_exit_code == 0:
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "HostService",
                                f"Archive readability test: {read_test_stdout.strip()}",
                            )

                        # Check file size and type
                        file_info_cmd = (
                            f"file '{archive_name}' && stat '{archive_name}'"
                        )
                        file_info_exit_code, file_info_stdout, _ = (
                            await self.dut_manager.execute_host_command(
                                dut_id, file_info_cmd, timeout=30, use_sudo=False
                            )
                        )
                        if file_info_exit_code == 0:
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "HostService",
                                f"Archive file info: {file_info_stdout.strip()}",
                            )

            # Download the archive
            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                f"Attempting to download archive: '{archive_name}'",
            )

            transfer_success, transfer_error = (
                await self.dut_manager.transfer_host_files(
                    dut_id, archive_name, "/tmp", copy_to_destination=False
                )
            )

            if not transfer_success:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    f"Failed to download archive '{archive_name}': {transfer_error}",
                )

                # Enhanced debugging for download failures
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Running post-failure diagnostics for archive: '{archive_name}'",
                )

                # Check if file still exists and its current state
                final_check_cmd = f"ls -la '{archive_name}' 2>/dev/null || echo 'File no longer exists'"
                final_check_exit_code, final_check_stdout, _ = (
                    await self.dut_manager.execute_host_command(
                        dut_id, final_check_cmd, timeout=30, use_sudo=False
                    )
                )
                if final_check_exit_code == 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Final archive state: {final_check_stdout.strip()}",
                    )

                # Check SFTP service status and connectivity
                sftp_test_cmd = (
                    "which sftp && echo 'SFTP available' || echo 'SFTP not found'"
                )
                sftp_test_exit_code, sftp_test_stdout, _ = (
                    await self.dut_manager.execute_host_command(
                        dut_id, sftp_test_cmd, timeout=30, use_sudo=False
                    )
                )
                if sftp_test_exit_code == 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"SFTP availability: {sftp_test_stdout.strip()}",
                    )

                # Log additional debugging info for permission issues
                if "Permission denied" in str(transfer_error):
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Permission denied error detected. Archive may still be owned by root or have incorrect permissions.",
                    )

                    # Try to get more detailed permission info
                    perm_debug_cmd = f"getfacl '{archive_name}' 2>/dev/null || echo 'ACL not available'"
                    perm_debug_exit_code, perm_debug_stdout, _ = (
                        await self.dut_manager.execute_host_command(
                            dut_id, perm_debug_cmd, timeout=30, use_sudo=False
                        )
                    )
                    if perm_debug_exit_code == 0:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"Archive ACL info: {perm_debug_stdout.strip()}",
                        )

                return False, None
            else:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"Successfully downloaded archive: '{archive_name}'",
                )

            # Clean up remote archive
            await self.dut_manager.execute_host_command(
                dut_id, f"rm -f '{archive_name}'", timeout=60, use_sudo=use_sudo
            )

            # Extract and save locally
            local_archive = f"/tmp/{os.path.basename(archive_name)}"
            if os.path.exists(local_archive):
                try:
                    extract_dir = (
                        f"/tmp/extract_{os.path.basename(working_dir)}_{folder}"
                    )
                    os.makedirs(extract_dir, exist_ok=True)

                    with tarfile.open(local_archive, "r:gz") as tar:
                        tar.extractall(
                            path=extract_dir,
                            filter=lambda m, p: self._safe_tar_filter(m, p),
                        )

                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        f"Extracted archive to {extract_dir}",
                    )

                    # Move extracted logs into the designated output directory and create an index file
                    index_file_path = await self._save_data_with_common_pattern(
                        dut_id,
                        f"Logs extracted to: {extract_dir}",
                        f"logs_{os.path.basename(working_dir)}_{folder}.txt",
                        output_pattern=output_pattern,
                        substitutions={
                            "file_name": f"logs_{os.path.basename(working_dir)}_{folder}"
                        },
                        **filtered_kwargs,
                    )

                    # Derive destination directory next to the index file and move extracted data there
                    saved_dir = None
                    if index_file_path and os.path.exists(extract_dir):
                        dest_dir = os.path.join(
                            os.path.dirname(index_file_path),
                            f"logs_{os.path.basename(working_dir)}_{folder}"
                        )
                        # Ensure clean destination
                        try:
                            if os.path.exists(dest_dir):
                                shutil.rmtree(dest_dir, ignore_errors=True)
                            shutil.move(extract_dir, dest_dir)
                            saved_dir = dest_dir
                        except Exception as move_err:
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "WARN",
                                "HostService",
                                f"Failed to move extracted logs to output dir: {move_err}",
                            )

                    # Clean up local files
                    os.remove(local_archive)

                    # Do not remove extracted data if we successfully moved it
                    if not saved_dir:
                        shutil.rmtree(extract_dir, ignore_errors=True)

                    # Return success and the index file as a data artifact
                    return True, index_file_path

                except Exception as e:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        f"Error processing archive: {str(e)}",
                    )
                    return False, None
            else:
                return False, None

        return False, None

    async def _handle_host_nvos_commands(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle NVOS commands collection - supports both regular commands and file-generating commands.

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for output files.
        """

        commands = kwargs.get("commands", [])
        use_sudo = kwargs.get("use_sudo", False)
        timeout = kwargs.get("timeout", 300)

        # Extract output pattern parameters using common function
        output_pattern, substitutions, filtered_kwargs = (
            self._extract_output_pattern_params(kwargs)
        )

        output_files = []
        success_count = 0
        error_messages = []
        successful_operations = 0
        total_operations = 0

        await self._write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "HostService",
            f"Starting NVOS commands collection with {len(commands)} commands",
        )

        for i, command in enumerate(commands):
            total_operations += 1
            try:
                # Create safe filename from command
                safe_cmd = command.replace(" ", "_").replace("/", "_")
                command_name = safe_cmd

                # Generate output filename
                if output_pattern:
                    filename = self.substitute_output_pattern_variables(
                        output_pattern,
                        {**substitutions, "command_name": command_name, "index": i + 1},
                    )
                else:
                    filename = f"{function_tag}_{command_name}.txt"

                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Executing NVOS command {i+1}/{len(commands)}: {command}",
                )

                # Check if this is a file-generating command based on YAML config
                file_generating_commands = kwargs.get("file_generating_commands", {})
                is_file_generating = file_generating_commands.get(command, False)

                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"File-generating check: command='{command}', file_generating_commands={list(file_generating_commands.keys())}, is_file_generating={is_file_generating}",
                )

                if is_file_generating:
                    # Handle file-generating commands
                    file_path = await self._handle_nvos_file_generating_command(
                        dut_id,
                        command,
                        filename,
                        output_pattern,
                        substitutions,
                        filtered_kwargs,
                        use_sudo,
                        timeout,
                        kwargs.get("file_generating_commands", {}),
                    )
                    if file_path:
                        output_files.append(file_path)
                        success_count += 1
                        successful_operations += 1
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "HostService",
                            f"Successfully executed file-generating NVOS command: {command}",
                        )
                    else:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "HostService",
                            f"Failed to execute file-generating NVOS command: {command}",
                        )
                        error_messages.append(
                            f"Failed to execute file-generating NVOS command: {command}"
                        )
                else:
                    # Handle regular NVOS show commands using DUT manager
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"About to call execute_nvos_command for: {command}",
                    )
                    success, output = await self.dut_manager.execute_nvos_command(
                        dut_id, command, timeout=timeout, use_sudo=use_sudo
                    )
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"execute_nvos_command returned: success={success}, output_type={type(output)}",
                    )

                    if success and output is not None:
                        # Save the output
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"About to save output for command: {command}, filename: {filename}, output_type: {type(output)}, output_length: {len(str(output)) if output else 0}",
                        )
                        file_path = await self._save_data_with_common_pattern(
                            dut_id,
                            output,
                            filename,
                            output_pattern=output_pattern,
                            substitutions={
                                **substitutions,
                                "command_name": command_name,
                                "index": i + 1,
                            },
                            **filtered_kwargs,
                        )
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"_save_data_with_common_pattern returned: {file_path}",
                        )
                        if file_path:
                            output_files.append(file_path)
                            success_count += 1
                            successful_operations += 1
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "INFO",
                                "HostService",
                                f"Successfully executed NVOS command: {command}",
                            )
                        else:
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "ERROR",
                                "HostService",
                                f"Failed to save output for NVOS command: {command}",
                            )
                            error_messages.append(
                                f"Failed to save output for NVOS command: {command}"
                            )
                    else:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "HostService",
                            f"NVOS command failed: {command}",
                        )
                        error_messages.append(f"NVOS command failed: {command}")

            except Exception as e:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    f"Exception executing NVOS command {command}: {str(e)}",
                )
                error_messages.append(
                    f"Exception executing NVOS command {command}: {str(e)}"
                )

        success = success_count > 0
        await self._write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "HostService",
            f"NVOS commands collection completed: {success_count}/{len(commands)} successful",
        )

        # Handle summary generation using helper function
        output_files = await self._handle_collection_summary_generation(
            dut_id=dut_id,
            function_tag=function_tag,
            collection_name=f"{function_tag} NVOS Commands",
            total_operations=total_operations,
            successful_operations=successful_operations,
            failed_operations=len(error_messages),
            output_files=output_files,
            additional_details={
                "Total commands": len(commands),
                "Successful commands": success_count,
                "Commands executed": commands,
                "File generating commands": kwargs.get("file_generating_commands", {}),
            },
            kwargs=kwargs,
            collection_type="nvos_commands",
            ignore_empty_results=True,
        )

        return await self._create_standardized_collector_result(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="nvos_commands",
            additional_context={
                "total_commands": len(commands),
                "successful_commands": success_count,
                "failed_commands": len(commands) - success_count,
            },
        )

    async def _handle_nvos_file_generating_command(
        self,
        dut_id: str,
        command: str,
        filename: str,
        output_pattern: str,
        substitutions: Dict[str, Any],
        filtered_kwargs: Dict[str, Any],
        use_sudo: bool,
        timeout: int,
        file_generating_config: Dict[str, Any],
    ) -> Optional[str]:
        """
        Handle NVOS commands that generate files (like tech-support).

        Args:
            dut_id: DUT ID.
            command: Command to execute.
            filename: Filename to use.
            output_pattern: Output pattern.
            substitutions: Substitutions.
            filtered_kwargs: Filtered kwargs.
            use_sudo: Use sudo.
            timeout: Timeout.
            file_generating_config: File generating config.
        """
        try:
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"_handle_nvos_file_generating_command called with command='{command}', filename='{filename}', timeout={timeout}, use_sudo={use_sudo}",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"File generating config: {file_generating_config}",
                dut_id,
            )

            # Execute the command using the NVOS wrapper (for consistency)
            # Note: File-generating commands return text, not JSON, but the wrapper handles this
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"About to execute file-generating command: {command}",
                dut_id,
            )
            success, output = await self.dut_manager.execute_nvos_command(
                dut_id, command, timeout=timeout, use_sudo=use_sudo
            )
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"execute_nvos_command returned: success={success}, output_type={type(output)}, output_length={len(str(output)) if output else 0}",
                dut_id,
            )

            if not success:
                await self._log_runtime(
                    "ERROR",
                    "HostService",
                    f"File-generating command failed: {command}",
                    dut_id,
                )
                return None

            # For file-generating commands, output will be the raw stdout text
            stdout = output if isinstance(output, str) else str(output)
            await self._log_runtime(
                "DEBUG", "HostService", f"Command stdout: {stdout}", dut_id
            )

            # Get file generation config for this command
            command_config = file_generating_config.get(command, {})
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"Command config for '{command}': {command_config}",
                dut_id,
            )
            file_pattern = command_config.get(
                "file_pattern", r"Generated tech-support (\S*)"
            )
            remote_path_template = command_config.get(
                "remote_path_template", "/host/dump/{filename}"
            )
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"Using file_pattern: '{file_pattern}', remote_path_template: '{remote_path_template}'",
                dut_id,
            )

            # Parse the output to find the generated file

            file_match = re.search(file_pattern, stdout)
            await self._log_runtime(
                "DEBUG", "HostService", f"Regex search result: {file_match}", dut_id
            )
            if not file_match:
                await self._log_runtime(
                    "ERROR",
                    "HostService",
                    f"Could not find generated file name in output: {stdout}",
                    dut_id,
                )
                return None

            generated_file = file_match.group(1)
            remote_path = remote_path_template.format(filename=generated_file)
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"Extracted generated_file: '{generated_file}', remote_path: '{remote_path}'",
                dut_id,
            )

            await self._log_runtime(
                "INFO", "HostService", f"File generated: {generated_file}", dut_id
            )

            # Download the generated file
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"About to transfer file from remote_path='{remote_path}' to local '/tmp'",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"Calling dut_manager.transfer_host_files with dut_id='{dut_id}', remote_path='{remote_path}', local_dir='/tmp', copy_to_destination=False",
                dut_id,
            )

            transfer_success, transfer_error = (
                await self.dut_manager.transfer_host_files(
                    dut_id, remote_path, "/tmp", copy_to_destination=False
                )
            )

            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"transfer_host_files returned: success={transfer_success}, error='{transfer_error}'",
                dut_id,
            )

            if not transfer_success:
                await self._log_runtime(
                    "ERROR",
                    "HostService",
                    f"Failed to transfer generated file: {transfer_error}",
                    dut_id,
                )
                return None

            # Save the downloaded file
            local_file = f"/tmp/{generated_file}"
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"Checking if local file exists: {local_file}",
                dut_id,
            )
            if os.path.exists(local_file):
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Local file exists, reading content...",
                    dut_id,
                )
                # Read the actual file content
                with open(local_file, "rb") as f:
                    file_content = f.read()

                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Read file content: {len(file_content)} bytes",
                    dut_id,
                )

                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"About to save file content using _save_data_with_common_pattern",
                    dut_id,
                )
                file_path = await self._save_data_with_common_pattern(
                    dut_id,
                    file_content,
                    generated_file,
                    output_pattern=output_pattern,
                    substitutions=substitutions,
                    **filtered_kwargs,
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"_save_data_with_common_pattern returned: {file_path}",
                    dut_id,
                )

                # Clean up local file
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Cleaning up local file: {local_file}",
                    dut_id,
                )
                os.remove(local_file)

                await self._log_runtime(
                    "INFO",
                    "HostService",
                    f"Successfully saved generated file: {generated_file}",
                    dut_id,
                )

                return file_path
            else:
                await self._log_runtime(
                    "ERROR",
                    "HostService",
                    f"Generated file not found locally after transfer: {local_file}",
                    dut_id,
                )
                return None

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "HostService",
                f"Exception during file-generating command: {str(e)}",
                dut_id,
            )
            return None

    def _extract_output_pattern_params(
        self, kwargs: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """
        Extract output pattern parameters from kwargs.

        Args:
            kwargs: Keyword arguments.
        """

        output_pattern = kwargs.pop("output_pattern", None)
        substitutions = kwargs.pop("substitutions", {})
        return output_pattern, substitutions, kwargs

    def _create_error_response(
        self,
        error_message: str,
        output_files: List[str] = None,
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Create a standardized error response.

        Args:
            error_message: Error message.
            output_files: Output files.
            context: Context.
        """
        return {
            "success": False,
            "error_message": error_message,
            "output_files": output_files or [],
            "context": context or {},
        }

    async def _handle_generic_log_collection(
        self, dut_id: str, collection_type: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Generic log collection method that can handle any type of log collection
        with platform-specific configurations.

        Args:
            dut_id: DUT ID.
            collection_type: Type of log collection (e.g., 'fabric_manager', 'subnet_manager')
            **kwargs: Additional parameters including platform_config

        Returns:
            Dict containing collection results.
        """
        output_files = []
        output_pattern, substitutions, filtered_kwargs = (
            self._extract_output_pattern_params(kwargs)
        )
        error_messages = []
        successful_operations = 0
        total_operations = 0

        async def _generic_log_collection():
            """
            Handle generic log collection.

            Args:
                dut_id: DUT ID.
                collection_type: Collection type.
                **kwargs: Additional parameters including platform_config.
            """
            nonlocal total_operations, successful_operations, output_files, error_messages
            use_sudo = kwargs.get("use_sudo", True)

            # Dynamically determine platform from DUT's baseboard
            platform = "default"
            if self.dut_manager:
                dut = self.dut_manager.get_dut(dut_id)
                if dut and hasattr(dut, "config"):
                    baseboard = dut.config.get("baseboard", "")
                    if baseboard:
                        # Use BaseboardManager to get platform type
                        baseboard_manager = self.dut_manager._get_baseboard_manager()
                        if baseboard_manager:
                            platform = (
                                baseboard_manager.get_baseboard_type(baseboard)
                                or "default"
                            )

            await self._log_runtime(
                "INFO",
                "HostService",
                f"Starting generic log collection for type: {collection_type}, platform: {platform}",
                dut_id,
            )

            # Get platform configuration
            platform_config = kwargs.get("platform_config", {})

            # Get log type specific configuration
            log_types = platform_config.get("log_types", {})
            log_type_config = log_types.get(collection_type, {})

            # Merge platform-specific overrides
            platform_overrides = platform_config.get("platform_overrides", {})
            platform_override = platform_overrides.get(platform, {})

            # Build final configuration by merging defaults, log type config, and platform overrides
            final_config = {
                "service_name": log_type_config.get("service_name"),
                "service_check_required": log_type_config.get(
                    "service_check_required", False
                ),
                "skip_on_service_not_found": log_type_config.get(
                    "skip_on_service_not_found", False
                ),
                "log_paths": log_type_config.get("log_paths", []),
                "fallback_commands": log_type_config.get("fallback_commands", []),
                "force_fallback": platform_config.get(
                    "force_fallback", {"default": False}
                ),
                "stop_on_first_success": platform_config.get(
                    "stop_on_first_success", False
                ),
                "collect_all_available": platform_config.get(
                    "collect_all_available", True
                ),
                "use_sudo": platform_config.get("use_sudo", True),
                "timeout": platform_config.get("timeout", 60),
            }

            # Apply platform overrides
            for key, value in platform_override.items():
                if key == "log_paths":
                    # Replace log paths with platform-specific ones
                    final_config["log_paths"] = [
                        path.format(log_type=collection_type) for path in value
                    ]
                elif key == "force_fallback":
                    final_config["force_fallback"] = value
                else:
                    final_config[key] = value

            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                f"Final config: {final_config}",
            )

            # Step 1: Service status check (if required)
            service_name = final_config["service_name"]
            service_check_required = final_config["service_check_required"]
            skip_on_service_not_found = final_config["skip_on_service_not_found"]

            if service_check_required and service_name:
                await self._log_runtime(
                    "INFO",
                    "HostService",
                    f"Checking service status: {service_name}",
                    dut_id,
                )

                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id,
                    f"systemctl status {service_name}",
                    timeout=60,
                    use_sudo=use_sudo,
                )

                if exit_code == 4:  # Service not found
                    await self._log_runtime(
                        "WARN",
                        "HostService",
                        f"Service '{service_name}' not found",
                        dut_id,
                    )

                    if skip_on_service_not_found:
                        # Get platform-specific force_fallback setting
                        force_fallback_config = final_config["force_fallback"]
                        if isinstance(force_fallback_config, dict):
                            force_fallback = force_fallback_config.get(
                                platform, force_fallback_config.get("default", False)
                            )
                        else:
                            force_fallback = force_fallback_config

                        if force_fallback:
                            await self._log_runtime(
                                "INFO",
                                "HostService",
                                f"Service not found, but force_fallback=True for platform {platform}. Will try log files and fallback commands.",
                                dut_id,
                            )
                            # Continue to Step 2 (log file collection) and Step 3 (fallback commands)
                        else:
                            await self._log_runtime(
                                "INFO",
                                "HostService",
                                f"Service not found, trying fallback commands only",
                                dut_id,
                            )

                            # Try fallback commands instead of skipping
                            fallback_commands = final_config["fallback_commands"]
                            if fallback_commands:
                                await self._log_runtime(
                                    "INFO",
                                    "HostService",
                                    f"Executing {len(fallback_commands)} fallback commands",
                                    dut_id,
                                )

                                for i, fallback_cmd in enumerate(fallback_commands):
                                    total_operations += 1
                                    cmd = fallback_cmd.get("command")
                                    file_name = fallback_cmd.get(
                                        "file_name", f"fallback_{i+1}.log"
                                    )
                                    description = fallback_cmd.get(
                                        "description", f"Fallback command {i+1}"
                                    )
                                    timeout = fallback_cmd.get("timeout", 60)

                                    await self._log_runtime(
                                        "INFO",
                                        "HostService",
                                        f"Executing fallback command {i+1}/{len(fallback_commands)}: {description}",
                                        dut_id,
                                    )

                                    success, file_path = (
                                        await self._execute_command_and_save(
                                            dut_id=dut_id,
                                            command=cmd,
                                            file_name=file_name,
                                            operation_name=f"{collection_type}_fallback",
                                            operation_type=collection_type,
                                            output_pattern=output_pattern,
                                            filtered_kwargs=filtered_kwargs,
                                            use_sudo=use_sudo,
                                            timeout=timeout,
                                        )
                                    )

                                    if success and file_path:
                                        output_files.append(file_path)
                                        successful_operations += 1
                                        await self._log_runtime(
                                            "INFO",
                                            "HostService",
                                            f"Fallback command succeeded: {description}",
                                            dut_id,
                                        )
                                        if final_config["stop_on_first_success"]:
                                            break
                                    else:
                                        await self._log_runtime(
                                            "WARN",
                                            "HostService",
                                            f"Fallback command failed: {description}",
                                            dut_id,
                                        )

                                if output_files:
                                    return await self._create_standardized_collector_result(
                                        successful_operations=successful_operations,
                                        total_operations=total_operations,
                                        output_files=output_files,
                                        error_messages=error_messages,
                                        operation_name="generic_log_collection",
                                        additional_context={
                                            "message": f"Service not found, but {len(output_files)} fallback commands succeeded"
                                        },
                                    )
                                else:
                                    return await self._create_standardized_collector_result(
                                        successful_operations=0,
                                        total_operations=total_operations,
                                        output_files=[],
                                        error_messages=error_messages,
                                        operation_name="generic_log_collection",
                                        additional_context={
                                            "message": f"Service '{service_name}' not found and all fallback commands failed"
                                        },
                                    )
                            else:
                                return await self._create_standardized_collector_result(
                                    successful_operations=0,
                                    total_operations=1,  # Service check counts as one operation
                                    output_files=[],
                                    error_messages=error_messages,
                                    operation_name="generic_log_collection",
                                    additional_context={
                                        "message": f"Service '{service_name}' not found, no fallback commands configured"
                                    },
                                )
                    else:
                        await self._log_runtime(
                            "INFO",
                            "HostService",
                            f"Continuing with log collection despite service not found",
                            dut_id,
                        )
                elif exit_code != 0:
                    await self._log_runtime(
                        "WARN",
                        "HostService",
                        f"Service '{service_name}' check failed (exit_code={exit_code}): {stderr}",
                        dut_id,
                    )
                    # Continue with collection even if service check fails
                else:
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"Service '{service_name}' is running",
                        dut_id,
                    )

            # Step 2: Try each configured log path
            collection_success = False
            log_paths = final_config["log_paths"]

            # If no log paths are configured, we still need to count this as an operation
            if not log_paths:
                total_operations += 1

            for i, log_path in enumerate(log_paths):
                total_operations += 1
                await self._log_runtime(
                    "INFO",
                    "HostService",
                    f"Attempting to collect from log path {i+1}/{len(log_paths)}: {log_path}",
                    dut_id,
                )

                # Check if file exists first
                check_cmd = f"test -f {log_path}"
                exit_code, _, _ = await self.dut_manager.execute_host_command(
                    dut_id, check_cmd, timeout=30, use_sudo=use_sudo
                )

                if exit_code != 0:
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        f"Log file does not exist: {log_path}",
                        dut_id,
                    )
                    continue

                # Try to collect the log file
                file_name = f"{collection_type}_{i+1}.log"
                success, file_path = await self._execute_command_and_save(
                    dut_id=dut_id,
                    command=f"cat {log_path}",
                    file_name=file_name,
                    operation_name=collection_type,
                    operation_type=collection_type,
                    output_pattern=output_pattern,
                    filtered_kwargs=filtered_kwargs,
                    use_sudo=use_sudo,
                    timeout=final_config["timeout"],
                )

                if success and file_path:
                    output_files.append(file_path)
                    collection_success = True
                    successful_operations += 1
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"Successfully collected {collection_type} log from {log_path}",
                        dut_id,
                    )

                    # If configured to stop on first success
                    if final_config["stop_on_first_success"]:
                        await self._log_runtime(
                            "INFO",
                            "HostService",
                            f"Stopping collection after first successful log (stop_on_first_success=True)",
                            dut_id,
                        )
                        break
                else:
                    await self._log_runtime(
                        "WARN",
                        "HostService",
                        f"Failed to collect from {log_path}",
                        dut_id,
                    )
                    error_messages.append(
                        f"Failed to collect from log path: {log_path}"
                    )

            # Step 3: Handle fallback commands (if configured)
            fallback_commands = final_config["fallback_commands"]

            # Get platform-specific force_fallback setting
            force_fallback_config = final_config["force_fallback"]
            if isinstance(force_fallback_config, dict):
                force_fallback = force_fallback_config.get(
                    platform, force_fallback_config.get("default", False)
                )
            else:
                force_fallback = force_fallback_config

            # If no fallback commands are configured, we still need to count this as an operation
            if not fallback_commands:
                total_operations += 1

            if fallback_commands and (not collection_success or force_fallback):
                if force_fallback:
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"Executing {len(fallback_commands)} fallback commands due to force_fallback=True (platform: {platform})",
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"Trying {len(fallback_commands)} fallback commands",
                        dut_id,
                    )

                for i, cmd_config in enumerate(fallback_commands):
                    total_operations += 1
                    command = cmd_config.get("command")
                    file_name = cmd_config.get(
                        "file_name", f"{collection_type}_fallback_{i+1}.log"
                    )
                    description = cmd_config.get(
                        "description", f"Fallback command {i+1}"
                    )

                    if not command:
                        continue

                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"Executing fallback command: {description}",
                        dut_id,
                    )

                    success, file_path = await self._execute_command_and_save(
                        dut_id=dut_id,
                        command=command,
                        file_name=file_name,
                        operation_name=f"{collection_type}_fallback",
                        operation_type=f"{collection_type}_fallback",
                        output_pattern=output_pattern,
                        filtered_kwargs=filtered_kwargs,
                        use_sudo=use_sudo,
                        timeout=cmd_config.get("timeout", final_config["timeout"]),
                    )

                    if success and file_path:
                        output_files.append(file_path)
                        collection_success = True
                        successful_operations += 1
                        await self._log_runtime(
                            "INFO",
                            "HostService",
                            f"Fallback command succeeded: {description}",
                            dut_id,
                        )
                        # Don't break - continue to try all fallback commands to collect all possible logs
                    else:
                        await self._log_runtime(
                            "WARN",
                            "HostService",
                            f"Fallback command failed: {description}",
                            dut_id,
                        )
                        error_messages.append(f"Fallback command failed: {description}")

            # Step 4: Final status determination
            if collection_success:
                await self._log_runtime(
                    "INFO",
                    "HostService",
                    f"{collection_type} log collection completed successfully with {len(output_files)} files",
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=successful_operations,
                    total_operations=total_operations,
                    output_files=output_files,
                    error_messages=error_messages,
                    operation_name="generic_log_collection",
                    additional_context={
                        "message": f"{collection_type} log collection completed",
                        "platform": platform,
                        "files_collected": len(output_files),
                    },
                )
            else:
                await self._log_runtime(
                    "ERROR",
                    "HostService",
                    f"Failed to collect {collection_type} logs from any configured path",
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=total_operations,
                    output_files=output_files,
                    error_messages=error_messages,
                    operation_name="generic_log_collection",
                    additional_context={
                        "message": f"Failed to collect {collection_type} logs from any configured path"
                    },
                )

        return await _generic_log_collection()
