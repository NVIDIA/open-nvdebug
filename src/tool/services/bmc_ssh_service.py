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
BMC SSH Service - Handles all BMC SSH-related collector operations.

Provides SSH-based collectors for BMC access including command execution,
file transfer, and log collection via SSH protocol.
"""

import asyncio
import base64
import datetime
import glob
import json
import logging
import os
import posixpath
import re
import secrets
import shlex
import time
import traceback
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..utils.command_safety import build_remote_cmd
from ..utils.streaming import format_stream_window_component, normalize_stream_window
from ..utils.tar_utils import get_tar_command
from .base_service import BaseService

logger = logging.getLogger(__name__)


class BMCSSHService(BaseService):
    """
    Service for BMC SSH operations.

    Provides collectors for BMC SSH-based log collection including command
    execution, file transfers, and system diagnostics over SSH.

    Inherits from:
        BaseService: Base service with standardized collector patterns.
    """

    def __init__(self, service_name: str, orchestrator: Any) -> None:
        """
        Initialize BMC SSH service.

        Args:
            service_name (str): Service name.
            orchestrator (Any): Orchestrator instance.
        """
        super().__init__(service_name, orchestrator)

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """
        Validate BMC SSH connection.

        Args:
            dut_id (str): DUT identifier.

        Returns:
            Tuple[bool, str]: (Success status, message).
        """
        return await self.dut_manager.get_dut(dut_id).test_ssh_connection()

    # Validation methods
    async def _validate_bmc_connection(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Validate BMC SSH connection - check preflight results first, then run test if needed.

        Args:
            dut_id (str): DUT identifier.
            **kwargs: Additional keyword arguments.
        """
        try:
            # First check if we have preflight results
            dut = self.dut_manager.get_dut(dut_id)
            preflight_results = getattr(dut, "preflight_results", {})

            if preflight_results:
                ssh_service_result = preflight_results.get("services", {}).get(
                    "ssh", {}
                )
                if ssh_service_result:
                    preflight_status = ssh_service_result.get("status", "unknown")
                    preflight_message = ssh_service_result.get("message", "")

                    await self._log_runtime(
                        "DEBUG",
                        "BMCSSHService",
                        f"Found preflight results for BMC SSH connection: status={preflight_status}, message={preflight_message}",
                        dut_id,
                    )

                    if preflight_status == "pass":
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            "Using preflight results for BMC SSH validation - connection already verified",
                            dut_id,
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=1,
                            total_operations=1,
                            output_files=[],
                            error_messages=[],
                            operation_name="bmc_ssh_validation",
                            additional_context={
                                "validation_message": f"Preflight verified: {preflight_message}",
                                "bmc_ssh_available": True,
                                "preflight_used": True,
                            },
                        )
                    elif preflight_status == "fail":
                        await self._log_runtime(
                            "WARN",
                            "BMCSSHService",
                            f"Preflight failed for BMC SSH connection: {preflight_message}",
                            dut_id,
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=1,
                            output_files=[],
                            error_messages=[f"Preflight failed: {preflight_message}"],
                            operation_name="bmc_ssh_validation",
                            additional_context={
                                "validation_message": f"Preflight failed: {preflight_message}",
                                "bmc_ssh_available": False,
                                "preflight_used": True,
                            },
                        )

            # No preflight results or unknown status - run connection test
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                "No preflight results found or unknown status - running BMC SSH connection test",
                dut_id,
            )

            success, message = await self.validate_connection(dut_id)

            # Log the validation result
            if success:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"BMC SSH connection validation passed: {message}",
                    dut_id,
                )
            else:
                await self._log_runtime(
                    "ERROR",
                    "BMCSSHService",
                    f"BMC SSH connection validation failed: {message}",
                    dut_id,
                )

            return await self._create_standardized_collector_result(
                successful_operations=1 if success else 0,
                total_operations=1,
                output_files=[],
                error_messages=[] if success else [message],
                operation_name="bmc_ssh_validation",
                additional_context={
                    "validation_message": message,
                    "bmc_ssh_available": success,
                    "preflight_used": False,
                },
            )
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"SSH validation exception: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"SSH validation error: {str(e)}"],
                operation_name="bmc_ssh_validation",
                additional_context={"bmc_ssh_available": False},
                dut_id=dut_id,
                collector_id="bmc_ssh_validation",
            )

    async def _validate_ssh_connection(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Validate SSH connection (alias for BMC connection).

        Args:
            dut_id: The DUT identifier
            **kwargs: Additional keyword arguments
        """
        return await self._validate_bmc_connection(dut_id, **kwargs)

    async def _validate_bmc_ssh_connection(
        self, dut_id: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Validate BMC SSH connection (alternative name).

        Args:
            dut_id: The DUT identifier
            **kwargs: Additional keyword arguments
        """
        return await self._validate_bmc_connection(dut_id, **kwargs)

    async def _validate_hmc_ssh_connection(
        self, dut_id: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Validate direct HMC SSH connectivity for collectors that target the HMC.

        Args:
            dut_id: The DUT identifier
            **kwargs: Additional keyword arguments
        """
        collector_id = kwargs.get("collector_id", "hmc_ssh_validation")

        try:
            if not self.dut_manager or not self.dut_manager.is_hmc_present(dut_id):
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=["HMC IP not configured for this DUT"],
                    operation_name="hmc_ssh_validation",
                    additional_context={
                        "hmc_ssh_available": False,
                        "hmc_present": False,
                    },
                    dut_id=dut_id,
                    collector_id=collector_id,
                )

            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id,
                "true",
                timeout=30,
                hmc=True,
            )

            success = exit_code == 0
            message = (
                "HMC SSH connection validation passed"
                if success
                else f"HMC SSH connection validation failed: {stderr or stdout or 'unknown error'}"
            )

            await self._log_runtime(
                "INFO" if success else "ERROR",
                "BMCSSHService",
                message,
                dut_id,
            )

            return await self._create_standardized_collector_result(
                successful_operations=1 if success else 0,
                total_operations=1,
                output_files=[],
                error_messages=[] if success else [message],
                operation_name="hmc_ssh_validation",
                additional_context={
                    "validation_message": message,
                    "hmc_ssh_available": success,
                    "hmc_present": True,
                },
                dut_id=dut_id,
                collector_id=collector_id,
            )
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"HMC SSH validation exception: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"HMC SSH validation error: {str(e)}"],
                operation_name="hmc_ssh_validation",
                additional_context={
                    "hmc_ssh_available": False,
                    "hmc_present": True,
                },
                dut_id=dut_id,
                collector_id=collector_id,
            )

    async def _render_command_template(
        self,
        dut_id: str,
        command_template: str,
        config_keys: Optional[Dict[str, str]] = None,
        config_key_defaults: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Render a command template using DUT/baseboard configuration values.

        Args:
            dut_id: DUT identifier
            command_template: Template string (e.g., "cat {firmware_path}")
            config_keys: Mapping of template variables to config keys
            config_key_defaults: Optional defaults for template variables

        Returns:
            Rendered command string or None if rendering fails.
        """
        if not command_template:
            return None

        if not config_keys:
            return command_template

        merged_config = await self._get_merged_config(dut_id)
        resolved_values: Dict[str, str] = {}
        missing_placeholders: List[str] = []

        for placeholder, config_key in config_keys.items():
            value = None
            if merged_config:
                value = merged_config.get(config_key)

            if value is None and config_key_defaults:
                default_value = config_key_defaults.get(placeholder)
                if default_value is not None:
                    value = default_value

            if value is None:
                missing_placeholders.append(f"{placeholder}->{config_key}")
                continue

            resolved_values[placeholder] = str(value)

        if missing_placeholders:
            await self._log_runtime(
                "WARN",
                "BMCSSHService",
                "Missing values for command template placeholders: "
                + ", ".join(missing_placeholders),
                dut_id,
            )
            return None

        try:
            rendered_command = command_template.format(**resolved_values)
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                f"Rendered command template '{command_template}' -> '{rendered_command}'",
                dut_id,
            )
            return rendered_command
        except KeyError as exc:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"Failed to render command template '{command_template}': {exc}",
                dut_id,
            )
            return None

    # Execution methods
    async def run_bmc_command(
        self,
        dut_id: str,
        command: str,
        collection_level: str = "L1",
        baseboard_commands: Optional[Dict[str, str]] = None,
        command_template: Optional[str] = None,
        config_keys: Optional[Dict[str, str]] = None,
        config_key_defaults: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run BMC SSH command with collection level handling.

        Args:
            dut_id: The DUT identifier
            command: The command to run
            collection_level: The collection level
            baseboard_commands: Optional mapping of baseboard/group names to commands
            command_template: Template to build the command from configuration values
            config_keys: Mapping of template variables to configuration keys
            config_key_defaults: Optional defaults for missing configuration values
            **kwargs: Additional keyword arguments
        """
        try:
            collector_id = kwargs.get("collector_id")
            timeout = kwargs.get(
                "timeout",
                await self._get_collector_timeout(collector_id or "", dut_id, 300),
            )
            use_hmc_ip = kwargs.get("use_hmc_ip", False)
            # Start timing for this BMC command
            if self.timing_manager:
                self.timing_manager.start_request(f"BMC_SSH: {command}")

            template_source = None
            using_command_template = False
            using_command_as_template = False
            if command_template:
                template_source = command_template
                using_command_template = True
            elif config_keys:
                template_source = command
                using_command_as_template = True

            if template_source:
                rendered_command = await self._render_command_template(
                    dut_id,
                    template_source,
                    config_keys=config_keys,
                    config_key_defaults=config_key_defaults,
                )
                if rendered_command:
                    command = rendered_command
                else:
                    if using_command_as_template:
                        error_message = (
                            f"Failed to render command template '{template_source}' "
                            "due to missing configuration values."
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=1,
                            output_files=[],
                            error_messages=[error_message],
                            operation_name="bmc_ssh_command",
                            additional_context={
                                "command_template": template_source,
                                "config_keys": config_keys,
                            },
                            dut_id=dut_id,
                            collector_id=collector_id,
                        )
                    else:
                        await self._log_runtime(
                            "WARN",
                            "BMCSSHService",
                            f"Falling back to provided command '{command}' because template rendering failed.",
                            dut_id,
                            collector_id=collector_id,
                        )

            # Apply baseboard-specific command override if provided
            if baseboard_commands:
                try:
                    dut = self.dut_manager.get_dut(dut_id)
                    baseboard = ""
                    baseboard_type = ""

                    if dut:
                        baseboard = dut.config.get("baseboard", "")
                        baseboard_manager = self.dut_manager._get_baseboard_manager()
                        if baseboard_manager and baseboard:
                            baseboard_type = (
                                baseboard_manager.get_baseboard_type(baseboard) or ""
                            )

                    selected_command = None
                    if baseboard and baseboard in baseboard_commands:
                        selected_command = baseboard_commands[baseboard]
                    elif baseboard_type and baseboard_type in baseboard_commands:
                        selected_command = baseboard_commands[baseboard_type]
                    elif "default" in baseboard_commands:
                        selected_command = baseboard_commands["default"]

                    if selected_command:
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"Using baseboard-specific command for '{baseboard or baseboard_type}': {selected_command}",
                            dut_id,
                        )
                        command = selected_command
                except Exception as override_error:
                    await self._log_runtime(
                        "WARN",
                        "BMCSSHService",
                        f"Failed to apply baseboard command override: {override_error}",
                        dut_id,
                    )

            # Handle collection level variations if provided
            if "collection_level_handling" in kwargs:
                level_commands = kwargs["collection_level_handling"]
                if collection_level in level_commands:
                    command = level_commands[collection_level]

            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, command, timeout=timeout, hmc=use_hmc_ip
            )

            # End timing for this BMC command
            if self.timing_manager:
                self.timing_manager.end_request(f"BMC_SSH: {command}")

            # Log command result using common utility
            await self._log_command_result(
                command,
                exit_code,
                stdout,
                stderr,
                "bmc_ssh",
                dut_id,
                kwargs.get("collector_id"),
                log_errors=True,
            )

            # Create output file with generalization using common utility
            content = self._create_command_output_content(
                command, exit_code, stdout, stderr
            )
            file_path = await self.write_output_with_generalization(
                dut_id,
                kwargs.get("collector_id", ""),
                content,
                output_pattern=kwargs.get("output_pattern") or kwargs.get("filename"),
                function_tag=kwargs.get("function_tag", "bmc_command"),
            )

            # Check if we should ignore command failures
            ignore_errors = kwargs.get("ignore_errors", False)

            # If command failed and we're not ignoring errors, return failure
            if exit_code != 0 and not ignore_errors:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[file_path] if file_path else [],
                    error_messages=[f"SSH command failed: {command}"],
                    operation_name="bmc_ssh_command",
                    additional_context={
                        "command": command,
                        "collection_level": collection_level,
                        "exit_code": exit_code,
                        "output": self._process_command_output(stdout),
                        "stderr": self._process_command_output(stderr),
                    },
                )

            # Command succeeded or we're ignoring errors
            return await self._create_standardized_collector_result(
                successful_operations=1,
                total_operations=1,
                output_files=[file_path] if file_path else [],
                error_messages=[],
                operation_name="bmc_ssh_command",
                additional_context={
                    "command": command,
                    "collection_level": collection_level,
                    "command_success": exit_code == 0,
                    "exit_code": exit_code,
                    "output": self._process_command_output(stdout),
                    "stderr": self._process_command_output(stderr),
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="bmc_ssh_command",
                additional_context={"command": command},
                dut_id=dut_id,
                collector_id="bmc_ssh_command",
            )

    async def run_bmc_commands(
        self,
        dut_id: str,
        commands: List[Union[str, Dict[str, Any]]],
        collection_level: str = "L1",
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run multiple BMC SSH commands with collection level handling.

        Args:
            dut_id: The DUT identifier
            commands: The commands to run
            collection_level: The collection level
            **kwargs: Additional keyword arguments
        """
        try:
            results = []
            output_files = []
            error_messages = []
            successful_operations = 0
            total_operations = 0
            collection_level = kwargs.get("collection_level", "L1")
            use_hmc_ip = kwargs.get("use_hmc_ip", False)

            for i, command_item in enumerate(commands):
                total_operations += 1
                # Handle both string commands and command dictionaries
                if isinstance(command_item, str):
                    command = command_item
                    file_name = f"bmc_command_{i+1}.txt"
                    timeout = await self._get_collector_timeout(
                        kwargs.get("collector_id", ""), dut_id, 300
                    )
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

                    file_name = command_item.get("file_name", f"bmc_command_{i+1}.txt")
                    timeout = command_item.get(
                        "timeout",
                        await self._get_collector_timeout(
                            kwargs.get("collector_id", ""), dut_id, 300
                        ),
                    )
                    ignore_errors = command_item.get("ignore_errors", False)

                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, command, timeout, hmc=use_hmc_ip
                )

                # Create output file with generalization using common utility
                content = self._create_command_output_content(
                    command, exit_code, stdout, stderr
                )
                file_path = await self.write_output_with_generalization(
                    dut_id,
                    kwargs.get("collector_id", ""),
                    content,
                    output_pattern=kwargs.get("output_pattern")
                    or kwargs.get("filename"),
                    function_tag=file_name,
                )
                output_files.append(file_path)

                command_success = exit_code == 0
                if command_success:
                    successful_operations += 1
                else:
                    error_messages.append(
                        f"BMC command failed: {command} (exit_code: {exit_code})"
                    )

                results.append(
                    {
                        "command": command,
                        "success": command_success,
                        "output": self._process_command_output(stdout),
                        "stderr": self._process_command_output(stderr),
                        "exit_code": exit_code,
                        "file_name": file_name,
                        "collection_level": collection_level,
                    }
                )

                # Handle ignore_errors
                if exit_code != 0 and not ignore_errors:
                    return await self._create_standardized_collector_result(
                        successful_operations=successful_operations,
                        total_operations=total_operations,
                        output_files=output_files,
                        error_messages=error_messages,
                        operation_name="bmc_ssh_commands",
                        additional_context={
                            "total_commands": len(commands),
                            "results": results,
                        },
                    )

            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id", "unknown"),
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="bmc_ssh_commands",
                additional_context={
                    "total_commands": len(commands),
                    "collection_level": collection_level,
                    "results": results,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=len(commands),
                output_files=[],
                error_messages=[f"Exception in BMC commands: {str(e)}"],
                operation_name="bmc_ssh_commands",
                additional_context={"commands": commands},
                dut_id=dut_id,
                collector_id="bmc_ssh_commands",
            )

    async def run_bmc_file_collection(
        self, dut_id: str, file_patterns: List[str], **kwargs
    ) -> Dict[str, Any]:
        """
        Collect files from BMC via SSH.

        Args:
            dut_id: The DUT identifier
            file_patterns: The file patterns to collect
            **kwargs: Additional keyword arguments
        """
        try:
            output_files = []
            collected_files = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            for pattern in file_patterns:
                total_operations += 1
                # Use find command to locate files
                find_command = build_remote_cmd(
                    "find / -name {pattern} -type f 2>/dev/null | head -10",
                    pattern=pattern,
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, find_command
                )

                if exit_code == 0 and stdout.strip():
                    files = stdout.strip().split("\n")
                    for file_path in files:
                        if file_path:
                            # Read file content
                            cat_command = build_remote_cmd(
                                "cat {path} 2>/dev/null", path=file_path
                            )
                            exit_code, content, stderr = (
                                await self.dut_manager.execute_bmc_command(
                                    dut_id, cat_command
                                )
                            )

                            if exit_code == 0:
                                filename = f"bmc_file_{len(collected_files)}.txt"
                                file_content = f"File: {file_path}\nContent:\n{content}"
                                file_path_out = (
                                    await self.write_output_with_generalization(
                                        dut_id,
                                        kwargs.get("collector_id", ""),
                                        file_content,
                                        output_pattern=kwargs.get("filename"),
                                        function_tag=filename,
                                        substitutions={"command_name": filename},
                                    )
                                )
                                output_files.append(file_path_out)
                                collected_files.append(file_path)
                                successful_operations += 1
                            else:
                                error_messages.append(
                                    f"Failed to read file: {file_path}"
                                )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="bmc_ssh_file_collection",
                additional_context={
                    "patterns_searched": len(file_patterns),
                    "files_collected": len(collected_files),
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="bmc_ssh_file_collection",
                additional_context={},
                dut_id=dut_id,
                collector_id="bmc_ssh_file_collection",
            )

    async def run_bmc_log_collection(
        self,
        dut_id: str,
        log_commands: List[Dict[str, Any]],
        log_patterns: List[str],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Collect logs from BMC via SSH.

        Args:
            dut_id: The DUT identifier
            log_commands: The log commands to run
            log_patterns: The log patterns to collect
            **kwargs: Additional keyword arguments
        """
        try:
            output_files = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            # Execute log commands
            for cmd_config in log_commands:
                total_operations += 1
                command = cmd_config["command"]
                file_name = cmd_config["file_name"]
                timeout = cmd_config.get("timeout", 300)

                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, command, timeout
                )

                if exit_code == 0:
                    file_path = await self.write_output_with_generalization(
                        dut_id,
                        kwargs.get("collector_id", ""),
                        stdout,
                        output_pattern=kwargs.get("filename"),
                        function_tag=file_name,
                        substitutions={"command_name": file_name},
                    )
                    output_files.append(file_path)
                    successful_operations += 1
                else:
                    error_messages.append(f"Log command failed: {command}")

            # Collect log files
            for pattern in log_patterns:
                total_operations += 1
                # Check if file exists
                test_command = build_remote_cmd("test -f {path}", path=pattern)
                exit_code, _, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, test_command
                )

                if exit_code == 0:
                    # Read log file
                    cat_command = build_remote_cmd("cat {path}", path=pattern)
                    exit_code, content, stderr = (
                        await self.dut_manager.execute_bmc_command(dut_id, cat_command)
                    )

                    if exit_code == 0:
                        filename = f"bmc_log_{pattern.replace('/', '_')}.txt"
                        file_path = await self.write_output_with_generalization(
                            dut_id,
                            kwargs.get("collector_id", ""),
                            content,
                            output_pattern=kwargs.get("filename"),
                            function_tag=filename,
                            substitutions={"command_name": filename},
                        )
                        output_files.append(file_path)
                        successful_operations += 1
                    else:
                        error_messages.append(f"Failed to read log file: {pattern}")

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="bmc_ssh_log_collection",
                additional_context={
                    "log_commands": len(log_commands),
                    "log_patterns": len(log_patterns),
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="bmc_ssh_log_collection",
                additional_context={},
                dut_id=dut_id,
                collector_id="bmc_ssh_log_collection",
            )

    async def run_bmc_device_based_commands(
        self,
        dut_id: str,
        device_detection: Dict[str, Any],
        device_commands: List[Dict[str, Any]],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run BMC commands based on detected devices.

        Args:
            dut_id: The DUT identifier
            device_detection: The device detection configuration
            device_commands: The device commands to run
            **kwargs: Additional keyword arguments
        """
        try:
            output_files = []
            detected_devices = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            # Detect devices
            detection_cmd = device_detection["command"]
            device_pattern = device_detection["device_pattern"]
            skip_message = device_detection.get("skip_message", "No devices found")

            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, detection_cmd
            )

            if exit_code != 0:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[f"Device detection failed: {stderr or stdout}"],
                    operation_name="bmc_device_based_commands",
                    additional_context={"detection_command": detection_cmd},
                    dut_id=dut_id,
                    collector_id="bmc_device_based_commands",
                )

            # Parse device list
            pattern = re.compile(device_pattern)
            matches = pattern.findall(stdout)

            if not matches:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="bmc_device_based_commands",
                    additional_context={
                        "reason": skip_message,
                        "devices_found": 0,
                    },
                    dut_id=dut_id,
                    collector_id="bmc_device_based_commands",
                )

            # Execute commands for each device
            for device_id in matches:
                total_operations += 1
                detected_devices.append(device_id)

                for cmd_config in device_commands:
                    cmd_type = cmd_config["type"]
                    command_template = cmd_config["command_template"]
                    file_template = cmd_config["file_template"]

                    # Format command and filename
                    command = command_template.format(device_index=device_id)
                    filename = file_template.format(device_index=device_id)

                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_bmc_command(dut_id, command)
                    )

                    if exit_code == 0:
                        file_path = await self.write_output_with_generalization(
                            dut_id,
                            kwargs.get("collector_id", ""),
                            stdout,
                            output_pattern=kwargs.get("filename"),
                            function_tag=filename,
                            substitutions={"command_name": filename},
                        )
                        output_files.append(file_path)
                        successful_operations += 1
                    else:
                        error_messages.append(
                            f"Device command failed: {device_id}_{cmd_type}"
                        )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="bmc_device_based_commands",
                additional_context={
                    "devices_found": len(detected_devices),
                    "devices_processed": detected_devices,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="bmc_advanced_command",
                additional_context={},
                dut_id=dut_id,
                collector_id="bmc_advanced_command",
            )

    async def run_bmc_advanced_command(
        self,
        dut_id: str,
        command_scenarios: Dict[str, Any],
        platform_specific: Dict[str, Any],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run advanced BMC command with platform-specific handling.

        Args:
            dut_id: The DUT identifier
            command_scenarios: The command scenarios to run
            platform_specific: The platform-specific configuration
            **kwargs: Additional keyword arguments
        """
        try:
            output_files = []

            # Get platform info using YAML-driven detection
            platform_detection_config = kwargs.get("platform_detection_config")
            platform_info = await self._get_platform_info(
                dut_id, platform_detection_config
            )
            platform_type = platform_info.get("platform_type", "unknown")

            # Select appropriate scenario
            if platform_type in command_scenarios:
                scenario = command_scenarios[platform_type]
            elif "default" in command_scenarios:
                scenario = command_scenarios["default"]
            else:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[
                        f"No command scenario found for platform {platform_type}"
                    ],
                    operation_name="bmc_advanced_command",
                    additional_context={"platform_type": platform_type},
                )

            # Execute scenario
            command = scenario["command"]
            timeout = scenario.get(
                "timeout",
                await self._get_collector_timeout(
                    kwargs.get("collector_id", ""), dut_id, 300
                ),
            )

            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, command, timeout
            )

            if exit_code == 0:
                filename = f"bmc_advanced_{platform_type}.txt"
                file_path = await self.write_output_with_generalization(
                    dut_id,
                    kwargs.get("collector_id", ""),
                    stdout,
                    output_pattern=kwargs.get("filename"),
                    function_tag=filename,
                    substitutions={"command_name": filename},
                )
                output_files.append(file_path)

            return await self._create_standardized_collector_result(
                successful_operations=1 if exit_code == 0 else 0,
                total_operations=1,
                output_files=output_files,
                error_messages=(
                    []
                    if exit_code == 0
                    else [f"Advanced command failed with exit code {exit_code}"]
                ),
                operation_name="bmc_advanced_command",
                additional_context={
                    "platform_type": platform_type,
                    "scenario_used": scenario.get("name", "unknown"),
                    "exit_code": exit_code,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="bmc_advanced_command",
                additional_context={},
                dut_id=dut_id,
                collector_id="bmc_advanced_command",
            )

    async def _get_merged_config(self, dut_id: str) -> Dict[str, Any]:
        """
        Get merged configuration for a DUT.

        Merges configurations in order of precedence:
        1. Baseboard config (lowest priority)
        2. Tool config (medium priority)
        3. DUT config (highest priority)

        Args:
            dut_id: DUT identifier

        Returns:
            Merged configuration dictionary
        """
        # Get DUT config
        dut = self.dut_manager.get_dut(dut_id)
        if not dut:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"DUT '{dut_id}' not found",
                dut_id,
            )
            return {}

        dut_config = dut.config

        # Get baseboard config
        baseboard_manager = self.dut_manager._get_baseboard_manager()
        baseboard_type = dut.config.get("baseboard")
        await self._log_runtime(
            "DEBUG",
            "BMCSSHService",
            f"DUT config keys: {list(dut.config.keys())}, baseboard: {baseboard_type}",
            dut_id,
        )

        baseboard_config = (
            baseboard_manager.get_baseboard_config(baseboard_type)
            if baseboard_manager
            else {}
        )

        # Merge configurations in order of precedence:
        # 1. Baseboard config (lowest priority)
        # 2. Tool config (medium priority)
        # 3. DUT config (highest priority)

        # Get tool config (global merged with DUT-specific overrides)
        tool_config = {}
        try:
            if self.orchestrator and hasattr(self.orchestrator, "config_manager"):
                tool_config = await self.orchestrator.get_dut_specific_tool_config(
                    dut_id
                )
        except Exception as e:
            await self._log_runtime(
                "WARNING",
                "BMCSSHService",
                f"Failed to get tool config for merge: {e}",
                dut_id,
            )

        # Start with baseboard config
        merged_config = baseboard_config.copy()

        # Merge tool config on top (tool config overrides baseboard)
        merged_config.update(tool_config)

        # Merge DUT config on top (DUT config takes highest precedence)
        merged_config.update(dut_config)

        # Special handling for i2c_config - merge nested configs with proper precedence
        baseboard_i2c_config = baseboard_config.get("i2c_config", {})
        tool_i2c_config = tool_config.get("i2c_config", {})
        dut_i2c_config = dut_config.get("i2c_config", {})

        # Merge i2c_config: baseboard (lowest) -> tool_config (medium) -> dut_config (highest)
        merged_i2c_config = {
            **baseboard_i2c_config,
            **tool_i2c_config,
            **dut_i2c_config,
        }
        merged_config["i2c_config"] = merged_i2c_config

        await self._log_runtime(
            "DEBUG",
            "BMCSSHService",
            f"i2c_config merge sources - baseboard: {len(baseboard_i2c_config)} keys, "
            f"tool_config: {len(tool_i2c_config)} keys, dut_config: {len(dut_i2c_config)} keys, "
            f"merged: {len(merged_i2c_config)} keys",
            dut_id,
        )

        await self._log_runtime(
            "DEBUG",
            "BMCSSHService",
            f"Merged config keys: {list(merged_config.keys())}",
            dut_id,
        )

        return merged_config

    async def _apply_i2c_collector_override(
        self,
        dut_id: str,
        i2c_config: Dict[str, Any],
        collector_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Overlay platform-specific I2C collector configuration when present.

        Baseboard configs can define ``I2C_COLLECTOR_OVERRIDES`` inside
        ``i2c_config``. Overrides are keyed by collector ``function_tag`` or
        collector id and replace YAML stage command/config fields for platforms
        whose telemetry is exposed through alternate paths.
        """
        merged_config = await self._get_merged_config(dut_id)
        merged_i2c_config = merged_config.get("i2c_config", {})
        overrides = merged_i2c_config.get("I2C_COLLECTOR_OVERRIDES", {})
        if not isinstance(overrides, dict):
            return i2c_config

        override_key = None
        for candidate in (i2c_config.get("function_tag"), collector_id):
            if candidate and candidate in overrides:
                override_key = candidate
                break

        if not override_key:
            return i2c_config

        override_config = overrides.get(override_key)
        if not isinstance(override_config, dict):
            return i2c_config

        resolved_i2c_config = dict(i2c_config)
        resolved_i2c_config.update(override_config)
        await self._log_runtime(
            "INFO",
            "BMCSSHService",
            f"Applied I2C collector override for {override_key}",
            dut_id,
        )
        return resolved_i2c_config

    async def _resolve_config_keys(
        self, dut_id: str, config_keys: Dict[str, str]
    ) -> Tuple[Dict[str, str], List[str]]:
        """
        Resolve config keys to actual values using merged configuration.

        Args:
            dut_id: DUT identifier
            config_keys: Dictionary mapping variable names to config key names
                        e.g., {"bus1": "HGX_I2C1_BUS_ADDRESS", "fpga_reg": "FPGA_REGISTER_TABLE_ADDRESS"}

        Returns:
            Tuple of:
            - Dictionary mapping variable names to resolved values
              e.g., {"bus1": "11", "fpga_reg": "0x0b"}
            - List of unresolved variable names (for skip detection)
        """
        merged_config = await self._get_merged_config(dut_id)
        resolved_config = {}
        unresolved_keys = []

        # Get the i2c_config section from merged config
        i2c_config = merged_config.get("i2c_config", {})

        for var_name, config_key in config_keys.items():
            if config_key in i2c_config:
                resolved_config[var_name] = str(i2c_config[config_key])
                await self._log_runtime(
                    "DEBUG",
                    "BMCSSHService",
                    f"Resolved {var_name} = {config_key} -> {i2c_config[config_key]}",
                    dut_id,
                )
            else:
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    f"Config key '{config_key}' not found in i2c_config for variable '{var_name}'",
                    dut_id,
                )
                unresolved_keys.append(f"{var_name} ({config_key})")
                # Don't add unresolved placeholders - we'll skip execution instead

        return resolved_config, unresolved_keys

    async def _expand_i2c_device_commands(
        self,
        dut_id: str,
        device_command_config: Dict[str, Any],
        resolved_config: Dict[str, str],
    ) -> Tuple[List[str], List[str], List[str], List[str]]:
        """
        Expand config-driven device commands into concrete commands.

        Args:
            dut_id: The DUT identifier
            device_command_config: Configuration describing the device list and
                per-device operations
            resolved_config: Resolved scalar config values

        Returns:
            Tuple of:
            - commands to execute
            - command names
            - command groups
            - configuration/expansion errors
        """
        merged_config = await self._get_merged_config(dut_id)
        i2c_config = merged_config.get("i2c_config", {})

        devices_key = device_command_config.get("devices_key")
        if not devices_key:
            return [], [], [], ["device_commands missing required 'devices_key'"]

        devices = i2c_config.get(devices_key)
        if devices is None:
            return (
                [],
                [],
                [],
                [f"device list key '{devices_key}' not found in i2c_config"],
            )

        if not isinstance(devices, list):
            return (
                [],
                [],
                [],
                [
                    f"device list '{devices_key}' must be a list, got {type(devices).__name__}"
                ],
            )

        command_template = device_command_config.get("command_template")
        operations = device_command_config.get("operations", [])
        name_template = device_command_config.get(
            "name_template", "{device_name}_{name_suffix}"
        )
        required_device_keys = device_command_config.get(
            "required_device_keys", ["name", "addr", "bus"]
        )

        if not command_template:
            return [], [], [], ["device_commands missing required 'command_template'"]

        if not operations:
            return [], [], [], ["device_commands missing required 'operations'"]

        commands_to_batch: List[str] = []
        command_names: List[str] = []
        command_group_names: List[str] = []
        errors: List[str] = []

        for device_index, device in enumerate(devices, start=1):
            if not isinstance(device, dict):
                errors.append(
                    f"device entry #{device_index} in '{devices_key}' must be a mapping"
                )
                continue

            missing_device_keys = [
                key for key in required_device_keys if key not in device
            ]
            if missing_device_keys:
                errors.append(
                    f"device entry #{device_index} in '{devices_key}' missing keys: {', '.join(missing_device_keys)}"
                )
                continue

            template_values = {
                **resolved_config,
                **{key: str(value) for key, value in device.items()},
                "device_index": str(device_index),
                "device_name": str(device.get("name", f"device_{device_index}")),
            }

            for operation in operations:
                if not isinstance(operation, dict):
                    errors.append(
                        f"operation entry for '{template_values['device_name']}' must be a mapping"
                    )
                    continue

                operation_values = {
                    key: str(value) for key, value in operation.items()
                }
                all_values = {**template_values, **operation_values}

                try:
                    processed_cmd = command_template.format(**all_values)
                    cmd_name = name_template.format(**all_values)
                except KeyError as exc:
                    errors.append(
                        f"missing template value {exc!s} for device '{template_values['device_name']}'"
                    )
                    continue

                commands_to_batch.append(processed_cmd)
                command_names.append(cmd_name)
                command_group_names.append(
                    str(operation.get("group", device_command_config.get("group", "")))
                )

        return commands_to_batch, command_names, command_group_names, errors

    async def run_bmc_i2c_commands(
        self,
        dut_id: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run I2C commands with YAML-driven configuration.

        Args:
            dut_id: The DUT identifier
            **kwargs: Additional keyword arguments
        """
        start_time = time.time()
        timing_data = []

        try:
            output_files = []
            results = []

            # Collect all commands for batching
            commands_to_batch = []
            command_names = []
            command_group_names = []

            # Extract i2c_config from kwargs (params from YAML)
            # The params are passed directly in kwargs, not under a "params" key
            i2c_config = {
                k: v
                for k, v in kwargs.items()
                if k
                not in [
                    "dut_id",
                    "collector_id",
                    "collection_level",
                    "service_name",
                    "collector_def",
                    "bmc_ssh_available",
                    "output_pattern",
                ]
            }

            # Debug logging
            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"run_bmc_i2c_commands called with dut_id={dut_id}, i2c_config={i2c_config}",
                dut_id,
            )

            i2c_config = await self._apply_i2c_collector_override(
                dut_id,
                i2c_config,
                kwargs.get("collector_id"),
            )

            # Resolve config keys to actual values
            config_keys = i2c_config.get("config_keys", {})
            resolved_config, unresolved_keys = await self._resolve_config_keys(
                dut_id, config_keys
            )

            # If there are unresolved config keys, skip this collector
            # This handles the case where the baseboard doesn't have i2c_config defined
            if unresolved_keys:
                missing_keys_str = ", ".join(unresolved_keys)
                skip_message = (
                    f"Required I2C configuration keys not defined for this baseboard: {missing_keys_str}. "
                    f"Please add these values to the baseboard's i2c_config in baseboards.yaml."
                )
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    skip_message,
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="bmc_i2c_commands",
                    additional_context={
                        "status": "skipped",
                        "reason": skip_message,
                        "unresolved_config_keys": unresolved_keys,
                    },
                    dut_id=dut_id,
                    collector_id=kwargs.get("collector_id"),
                )

            # Handle base command (e.g., i2cdetect -l)
            base_command = i2c_config.get("base_command")
            if base_command:
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, base_command
                )

                if exit_code == 0:
                    file_path = await self.write_output_with_generalization(
                        dut_id,
                        kwargs.get("collector_id", ""),
                        stdout,
                        output_pattern=kwargs.get("output_pattern"),
                        function_tag=kwargs.get("function_tag", "i2c_base"),
                    )
                    output_files.append(file_path)
                    results.append({"command": base_command, "success": True})
                else:
                    results.append(
                        {
                            "command": base_command,
                            "success": False,
                            "error": stderr,
                        }
                    )

            # Handle scan commands (e.g., i2cdetect -y {bus})
            scan_commands = i2c_config.get("scan_commands", False)
            if scan_commands and base_command:
                # Parse I2C bus numbers from base command output
                pattern = r"i2c-(\d+)"
                i2c_numbers = set(re.findall(pattern, stdout))

                for i2c_number in i2c_numbers:
                    scan_cmd = f"i2cdetect -y {i2c_number}"
                    exit_code, scan_stdout, scan_stderr = (
                        await self.dut_manager.execute_bmc_command(dut_id, scan_cmd)
                    )

                    if exit_code == 0:
                        file_path = await self.write_output_with_generalization(
                            dut_id,
                            kwargs.get("collector_id", ""),
                            scan_stdout,
                            output_pattern=None,  # Don't use output_pattern for scan commands to avoid overwrites
                            function_tag=f"SSH_S7_i2c_device_bus_scan{i2c_number}",
                        )
                        output_files.append(file_path)
                        results.append({"command": scan_cmd, "success": True})
                    else:
                        results.append(
                            {
                                "command": scan_cmd,
                                "success": False,
                                "error": scan_stderr,
                            }
                        )

            # Handle command groups (e.g., temperature, power, etc.)
            command_groups = i2c_config.get("command_groups", {})
            for group_name, group_commands in command_groups.items():
                for cmd_config in group_commands:
                    cmd_name = cmd_config["name"]
                    cmd_template = cmd_config["cmd"]

                    # Handle single command or command list
                    if isinstance(cmd_template, str):
                        commands_to_run = [cmd_template]
                    elif isinstance(cmd_template, list):
                        commands_to_run = cmd_template
                    else:
                        continue

                    # Execute each command in the sequence
                    for cmd in commands_to_run:
                        # Replace variables with resolved values
                        processed_cmd = cmd
                        for var_name, value in resolved_config.items():
                            processed_cmd = processed_cmd.replace(
                                f"{{{var_name}}}", value
                            )

                        # Collect commands for batching
                        commands_to_batch.append(processed_cmd)
                        command_names.append(cmd_name)
                        command_group_names.append(group_name)

            # Handle direct commands list
            commands = i2c_config.get("commands", [])
            for cmd_config in commands:
                cmd_name = cmd_config["name"]
                cmd_template = cmd_config["cmd"]

                # Handle single command or command list
                if isinstance(cmd_template, str):
                    commands_to_run = [cmd_template]
                elif isinstance(cmd_template, list):
                    commands_to_run = cmd_template
                else:
                    continue

                # Execute each command in the sequence
                for cmd in commands_to_run:
                    # Replace variables with resolved values
                    processed_cmd = cmd
                    await self._log_runtime(
                        "DEBUG",
                        "BMCSSHService",
                        f"Processing command: {cmd}, resolved_config: {resolved_config}",
                        dut_id,
                    )
                    for var_name, value in resolved_config.items():
                        processed_cmd = processed_cmd.replace(f"{{{var_name}}}", value)
                        await self._log_runtime(
                            "DEBUG",
                            "BMCSSHService",
                            f"Replaced {{{var_name}}} with {value}, processed_cmd: {processed_cmd}",
                            dut_id,
                        )

                    # Collect commands for batching
                    commands_to_batch.append(processed_cmd)
                    command_names.append(cmd_name)
                    command_group_names.append("")  # Direct commands don't have groups

            # Handle config-driven device command expansion
            device_command_config = i2c_config.get("device_commands")
            if device_command_config:
                (
                    expanded_commands,
                    expanded_names,
                    expanded_groups,
                    expansion_errors,
                ) = await self._expand_i2c_device_commands(
                    dut_id, device_command_config, resolved_config
                )

                if expansion_errors:
                    missing_keys_str = "; ".join(expansion_errors)
                    skip_message = (
                        "Required I2C device configuration is not defined correctly for this baseboard: "
                        f"{missing_keys_str}. Please update the baseboard's i2c_config in baseboards.yaml."
                    )
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        skip_message,
                        dut_id,
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=0,
                        output_files=[],
                        error_messages=[],
                        operation_name="bmc_i2c_commands",
                        additional_context={
                            "status": "skipped",
                            "reason": skip_message,
                            "device_command_errors": expansion_errors,
                        },
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                    )

                commands_to_batch.extend(expanded_commands)
                command_names.extend(expanded_names)
                command_group_names.extend(expanded_groups)

            # Execute all collected commands in batch (sequentially, not in parallel)
            if commands_to_batch:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Executing {len(commands_to_batch)} I2C commands sequentially in a single SSH session",
                    dut_id,
                )

                batch_start_time = time.time()
                batch_results = await self.dut_manager.execute_bmc_commands_batched(
                    dut_id,
                    commands_to_batch,
                    timeout=await self._get_collector_timeout(
                        kwargs.get("collector_id", ""), dut_id, 300
                    ),
                )
                batch_end_time = time.time()
                batch_duration = batch_end_time - batch_start_time

                # Process batch results
                fatal_stderr_markers = [
                    "no access privilege",
                    "permission denied",
                    "access denied",
                    "not authorized",
                ]
                fatal_stderr_patterns = [
                    re.compile(
                        rf"(?<![\w-]){re.escape(marker)}(?![\w-])", re.IGNORECASE
                    )
                    for marker in fatal_stderr_markers
                ]

                for i, (exit_code, stdout, stderr) in enumerate(batch_results):
                    cmd_name = (
                        command_names[i] if i < len(command_names) else f"command_{i}"
                    )
                    cmd_group = (
                        command_group_names[i] if i < len(command_group_names) else ""
                    )
                    cmd_duration = batch_duration / len(
                        batch_results
                    )  # Approximate per-command time

                    stderr_str = (stderr or "").strip()
                    stderr_has_fatal = any(
                        pattern.search(stderr_str) for pattern in fatal_stderr_patterns
                    )
                    cmd_success = (exit_code == 0) and not stderr_has_fatal

                    timing_data.append(
                        {
                            "command": cmd_name,
                            "duration": cmd_duration,
                            "success": cmd_success,
                        }
                    )

                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"Batched I2C command result - {cmd_name}: exit_code: {exit_code}, stdout: '{stdout}', stderr: '{stderr}', duration: {cmd_duration:.3f}s",
                        dut_id,
                    )

                    if cmd_success:
                        file_path = await self.write_output_with_generalization(
                            dut_id,
                            kwargs.get("collector_id", ""),
                            stdout,
                            output_pattern=kwargs.get("output_pattern"),
                            function_tag=cmd_name,
                            substitutions={
                                "command_name": cmd_name,
                                "group": cmd_group,
                            },
                        )
                        output_files.append(file_path)
                        results.append(
                            {
                                "command": commands_to_batch[i],
                                "success": True,
                                "name": cmd_name,
                                "stdout": stdout,
                                "stderr": stderr,
                                "exit_code": exit_code,
                            }
                        )
                    else:
                        if stderr_has_fatal:
                            error_detail = (
                                stderr_str
                                or "stderr indicated access privilege failure"
                            )
                            error_msg = (
                                f"Command failed due to stderr content: {error_detail}"
                            )
                        else:
                            error_msg = (
                                f"Command failed with exit_code {exit_code}: {stderr}"
                            )
                        results.append(
                            {
                                "command": commands_to_batch[i],
                                "success": False,
                                "error": error_msg,
                                "name": cmd_name,
                                "stdout": stdout,
                                "stderr": stderr,
                                "exit_code": exit_code,
                            }
                        )

            # Determine overall success
            successful_commands = [r for r in results if r.get("success", False)]
            failed_commands = [r for r in results if not r.get("success", False)]

            # Check if we should continue on failure
            continue_on_failure = i2c_config.get("continue_on_failure", False)

            if continue_on_failure:
                # If continue_on_failure is True, succeed if any command worked
                overall_success = len(successful_commands) > 0
            else:
                # If continue_on_failure is False, all commands must succeed
                overall_success = len(failed_commands) == 0

            # A failure that means "address not populated on this bus" (ENXIO /
            # "No such device or address", emitted by i2c_msg_xfer when i2ctransfer
            # prefixes it as "Sending messages failed: ..."). Treat this as
            # device-absent, not as a tool error.
            def _is_device_absent(err_text: str) -> bool:
                if not err_text:
                    return False
                markers = (
                    "No such device or address",
                    "Sending messages failed",
                )
                return any(m in err_text for m in markers)

            all_device_absent = bool(failed_commands) and all(
                _is_device_absent(str(cmd.get("error", "")) + " " + str(cmd.get("stderr", "")))
                for cmd in failed_commands
            )

            # Create detailed reason for failure
            if not overall_success and failed_commands:
                if all_device_absent:
                    reason = (
                        f"All {len(failed_commands)} I2C probes returned "
                        "'No such device or address' — configured PDB/HSC device "
                        "addresses are not populated on this baseboard"
                    )
                else:
                    failure_reasons = [
                        f"{cmd.get('name', 'unknown')}: {cmd.get('error', 'No specific command error reason provided')}"
                        for cmd in failed_commands
                    ]
                    reason = f"All I2C commands failed: {'; '.join(failure_reasons)}"
            elif overall_success:
                reason = f"Completed successfully ({len(successful_commands)}/{len(results)} commands)"
            else:
                reason = "No commands executed"

            # Generate timing summary
            total_time = time.time() - start_time
            successful_timing = [t for t in timing_data if t["success"]]
            failed_timing = [t for t in timing_data if not t["success"]]

            timing_summary = f"""
=== I2C COMMAND TIMING SUMMARY ===
Total execution time: {total_time:.3f}s
Commands executed: {len(timing_data)}
Successful commands: {len(successful_timing)}
Failed commands: {len(failed_timing)}

Command breakdown:
"""

            for cmd_timing in timing_data:
                cmd_status = "SUCCESS" if cmd_timing["success"] else "ERROR"
                timing_summary += f"  {cmd_status} {cmd_timing['command']}: {cmd_timing['duration']:.3f}s\n"

            if successful_timing:
                avg_success_time = sum(t["duration"] for t in successful_timing) / len(
                    successful_timing
                )
                timing_summary += (
                    f"\nAverage successful command time: {avg_success_time:.3f}s"
                )

            if failed_timing:
                avg_failed_time = sum(t["duration"] for t in failed_timing) / len(
                    failed_timing
                )
                timing_summary += (
                    f"\nAverage failed command time: {avg_failed_time:.3f}s"
                )

            await self._log_runtime("INFO", "BMCSSHService", timing_summary, dut_id)

            await self._log_runtime(
                "INFO" if overall_success else "ERROR",
                "BMCSSHService",
                f"I2C commands summary: {len(successful_commands)}/{len(results)} successful. {reason}",
                dut_id,
            )

            # Create structured JSON output with all command details
            json_output = {
                "collector_info": {
                    "collector_id": kwargs.get("collector_id", ""),
                    "function_tag": kwargs.get("function_tag", "i2c_commands"),
                    "timestamp": datetime.datetime.now().isoformat(),
                    "dut_id": dut_id,
                },
                "execution_summary": {
                    "total_commands": len(results),
                    "successful_commands": len(successful_commands),
                    "failed_commands": len(failed_commands),
                    "overall_success": overall_success,
                    "continue_on_failure": continue_on_failure,
                    "total_execution_time": total_time,
                    "reason": reason,
                },
                "commands": [],
            }

            # Add detailed command information
            for i, result in enumerate(results):
                cmd_info = {
                    "command_name": result.get("name", f"command_{i}"),
                    "full_command": result.get("command", ""),
                    "success": result.get("success", False),
                    "output_file": output_files[i] if i < len(output_files) else None,
                    "exit_code": result.get("exit_code", -1),
                    "stdout": result.get("stdout", ""),
                    "stderr": result.get("stderr", ""),
                }

                # Add timing information if available
                if i < len(timing_data):
                    cmd_info["execution_time"] = timing_data[i]["duration"]

                # Add error information if command failed
                if not result.get("success", False):
                    cmd_info["error"] = result.get("error", "Unknown error")

                json_output["commands"].append(cmd_info)

            # Save structured JSON output with proper handling of special characters
            try:
                json_content = json.dumps(json_output, indent=2, ensure_ascii=False)
            except (TypeError, ValueError) as e:
                # Fallback: convert any non-serializable content to strings
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    f"JSON serialization issue, using fallback: {str(e)}",
                    dut_id,
                )

                # Recursively convert any non-serializable objects to strings
                def make_serializable(obj):
                    """
                    Make an object serializable.

                    Args:
                        obj: The object to make serializable
                    """
                    if isinstance(obj, dict):
                        return {k: make_serializable(v) for k, v in obj.items()}
                    elif isinstance(obj, list):
                        return [make_serializable(item) for item in obj]
                    elif isinstance(obj, (str, int, float, bool, type(None))):
                        return obj
                    else:
                        return str(obj)

                safe_json_output = make_serializable(json_output)
                json_content = json.dumps(
                    safe_json_output, indent=2, ensure_ascii=False
                )
            json_file_path = await self.write_output_with_generalization(
                dut_id,
                kwargs.get("collector_id", ""),
                json_content,
                output_pattern="SSH_{function_tag}_structured.json",
                function_tag=kwargs.get("function_tag", "i2c_commands"),
                substitutions={
                    "function_tag": kwargs.get("function_tag", "i2c_commands")
                },
            )

            # Add JSON file to output files list
            if json_file_path:
                output_files.append(json_file_path)

            # Create detailed error messages for individual command failures
            detailed_error_messages = []
            if (
                failed_commands
            ):  # Always create detailed errors if there are failed commands
                for cmd in failed_commands:
                    cmd_name = cmd.get("name", "unknown_command")
                    cmd_error = cmd.get("error", "No specific error provided")
                    detailed_error_messages.append(f"{cmd_name}: {cmd_error}")

            additional_context = {
                "total_commands": len(results),
                "successful_commands": len(successful_commands),
                "command_groups_processed": list(command_groups.keys()),
                "timing_data": timing_data,
                "total_time": total_time,
                "results": results,
                "structured_json_file": json_file_path,
            }

            # When every failure is "device not populated", mark the collector
            # skipped so finalize_collector's skip_message path surfaces a
            # graceful "device not present" message instead of a hard failure.
            # This applies regardless of continue_on_failure: absence of the
            # hardware on this baseboard is not a tool error.
            if failed_commands and not successful_commands and all_device_absent:
                additional_context["status"] = "skipped"
                additional_context["reason"] = reason
                additional_context["all_devices_absent"] = True

            return await self._create_standardized_collector_result(
                successful_operations=len(successful_commands),
                total_operations=len(results),
                output_files=output_files,
                error_messages=detailed_error_messages,
                operation_name="bmc_i2c_commands",
                additional_context=additional_context,
            )
        except Exception as e:
            error_traceback = traceback.format_exc()

            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"run_bmc_i2c_commands exception: {str(e)}",
                dut_id,
            )
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"Traceback: {error_traceback}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[f"Exception in run_bmc_i2c_commands: {str(e)}"],
                operation_name="bmc_i2c_commands",
                additional_context={"results": []},
                dut_id=dut_id,
                collector_id="bmc_i2c_commands",
            )

    async def run_bmc_file_transfer(
        self,
        dut_id: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Transfer files from BMC using SFTP or fallback to hexdump with retry logic.

        Args:
            dut_id: The DUT identifier
            **kwargs: Additional keyword arguments
        """
        try:
            # Extract parameters directly from kwargs (hook execution passes them directly)
            source_path = kwargs.get("source_path", "/var/log/")
            archive_name = kwargs.get("archive_name", "file_transfer")
            # Use archive_name for output file naming — it is per-hook and not overridden by
            # the shared context (which sets function_tag to the collector name).
            function_tag = archive_name or kwargs.get("function_tag", "file_transfer")
            use_sftp = kwargs.get("use_sftp", True)
            fallback_hexdump = kwargs.get("fallback_hexdump", True)
            retry_count = kwargs.get("retry_count", 3)
            retry_delay = kwargs.get("retry_delay", 5)
            chunk_size_kb = kwargs.get("chunk_size_kb", 2000)
            max_file_size_mb = kwargs.get("max_file_size_mb", 10)
            config_keys = kwargs.get("config_keys", {})
            key_files = kwargs.get("key_files", [])

            # Get DUT config for variable substitution (now includes proper tool config overrides)
            dut_config = self.dut_manager.get_dut_config(dut_id)

            # Get BMC temp dir from merged DUT config (includes tool config overrides)
            bmc_temp_dir = dut_config.get("BMC_TEMP_DIR", "/tmp")
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                f"Using BMC_TEMP_DIR from merged config: {bmc_temp_dir}",
                dut_id,
            )
            archive_timestamp = datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
            tempfilename = f"{archive_name}_{archive_timestamp}.tar.gz"

            # Create timestamp substitution for output pattern
            timestamp_substitutions = {"timestamp": archive_timestamp}
            output_pattern = kwargs.get("output_pattern")
            if self.logger and getattr(self.logger, "_get_tool_config_value", None):
                if self.logger._get_tool_config_value("streaming_only", False):
                    try:
                        begin_dt, end_dt = normalize_stream_window(
                            self.logger._get_tool_config_value("stream_begin"),
                            self.logger._get_tool_config_value("stream_end"),
                        )
                        begin_component = format_stream_window_component(begin_dt)
                        end_component = format_stream_window_component(end_dt)
                        if output_pattern:
                            output_pattern = output_pattern.replace(
                                "_{timestamp}", f"_{begin_component}_{end_component}"
                            ).replace(
                                "{timestamp}", f"{begin_component}_{end_component}"
                            )
                    except ValueError as e:
                        await self._log_runtime(
                            "ERROR",
                            "BMCSSHService",
                            f"Invalid streaming window for BMC file transfer: {str(e)}",
                            dut_id,
                        )
                        raise
                    except Exception as e:
                        logger.exception(
                            "Unexpected error while normalizing streaming window for BMC file transfer on DUT %s",
                            dut_id,
                        )
                        await self._log_runtime(
                            "ERROR",
                            "BMCSSHService",
                            f"Unexpected error while applying streaming window for BMC file transfer: {str(e)}",
                            dut_id,
                        )
                        raise

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Starting file transfer for {source_path} with retry_count={retry_count}",
                dut_id,
            )

            output_files = []

            # Check if temp directory is writable
            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Checking if temp directory {bmc_temp_dir} is writable...",
                dut_id,
            )

            test_command = build_remote_cmd(
                "touch {dir}/.test && rm {dir}/.test", dir=bmc_temp_dir
            )
            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, test_command
            )

            if exit_code != 0:
                await self._log_runtime(
                    "ERROR",
                    "BMCSSHService",
                    f"Temp directory {bmc_temp_dir} is not writable: {stderr}",
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[f"Temp directory {bmc_temp_dir} is not writable"],
                    operation_name="bmc_file_transfer",
                    additional_context={"temp_dir": bmc_temp_dir},
                    dut_id=dut_id,
                    collector_id="bmc_file_transfer",
                )

            source_exists_cmd = build_remote_cmd("test -e {path}", path=source_path)
            exit_code, _, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, source_exists_cmd
            )
            primary_source_path = source_path
            used_fallback = False
            fallback_source_path = kwargs.get("fallback_source_path")
            if exit_code != 0 and fallback_source_path:
                fallback_exists_cmd = build_remote_cmd(
                    "test -e {path}", path=fallback_source_path
                )
                fb_exit_code, _, _ = await self.dut_manager.execute_bmc_command(
                    dut_id, fallback_exists_cmd
                )
                if fb_exit_code == 0:
                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"Primary source path {source_path} not present on BMC; "
                        f"falling back to {fallback_source_path}",
                        dut_id,
                    )
                    source_path = fallback_source_path
                    used_fallback = True
                    exit_code = 0
            if exit_code != 0:
                if fallback_source_path:
                    skip_reason = (
                        f"Neither primary path {primary_source_path} nor fallback "
                        f"{fallback_source_path} present on BMC; skipping file transfer"
                    )
                else:
                    skip_reason = (
                        f"Source path {source_path} is not present on BMC; skipping file transfer"
                    )
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    skip_reason,
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="bmc_file_transfer",
                    additional_context={
                        "status": "skipped",
                        "reason": skip_reason,
                        "source_path": primary_source_path,
                        "fallback_source_path": fallback_source_path,
                        "source_path_missing": True,
                    },
                    dut_id=dut_id,
                    collector_id="bmc_file_transfer",
                )

            source_is_directory = True
            if used_fallback:
                is_dir_cmd = build_remote_cmd("test -d {path}", path=source_path)
                is_dir_exit_code, _, _ = await self.dut_manager.execute_bmc_command(
                    dut_id, is_dir_cmd
                )
                source_is_directory = is_dir_exit_code == 0

            # Check size of source directory (following symlinks to get true size)
            size_command = build_remote_cmd("du -sh {path}", path=source_path)
            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, size_command
            )
            if exit_code == 0:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Source directory size (following symlinks): {stdout.strip()}",
                    dut_id,
                )

            # Check available space in temp directory
            df_command = f"df -h {bmc_temp_dir} | tail -1"
            exit_code, df_output, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, df_command
            )
            if exit_code == 0:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Available space in {bmc_temp_dir}: {df_output.strip()}",
                    dut_id,
                )

            # Check for symlinks in source directory
            symlink_check = build_remote_cmd(
                "find {path} -maxdepth 2 -type l -ls 2>/dev/null | head -5",
                path=source_path,
            )
            exit_code, symlink_output, _ = await self.dut_manager.execute_bmc_command(
                dut_id, symlink_check
            )
            if exit_code == 0 and symlink_output.strip():
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Found symlinks in {source_path} (will be dereferenced during archive creation):\n{symlink_output.strip()}",
                    dut_id,
                )

            if use_sftp:
                # Try SFTP with retry logic
                for attempt in range(retry_count + 1):
                    try:
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"SFTP attempt {attempt + 1}/{retry_count + 1}",
                            dut_id,
                        )

                        # Create archive with -h flag to follow symlinks (dereference)
                        # This ensures symlinks like /var/log/journal -> /var/emmc/user-logs/journal-logs
                        # are followed and the actual data is archived, not just the symlink.
                        # Note: This will increase archive size but ensures the archive is self-contained
                        # and usable by end users. If space is limited, the command will fail gracefully.
                        # Important: -h must come before -f, or after the filename, not between them

                        # Get tar command with fallback to bundled busybox
                        try:
                            tar_cmd = get_tar_command()
                        except RuntimeError as e:
                            await self._log_runtime(
                                "ERROR",
                                "BMCSSHService",
                                f"tar not available: {e}",
                                dut_id,
                            )
                            return {"error": f"tar not available: {e}"}

                        temp_path = f"{bmc_temp_dir}/{tempfilename}"
                        if source_is_directory:
                            sftp_command = build_remote_cmd(
                                f"{tar_cmd} -h -czf {{dest}} -C {{src}} .",
                                dest=temp_path,
                                src=source_path,
                            )
                        else:
                            src_parent = posixpath.dirname(source_path) or "/"
                            src_basename = posixpath.basename(source_path)
                            sftp_command = build_remote_cmd(
                                f"{tar_cmd} -h -czf {{dest}} -C {{parent}} {{name}}",
                                dest=temp_path,
                                parent=src_parent,
                                name=src_basename,
                            )
                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_bmc_command(
                                dut_id, sftp_command
                            )
                        )

                        # If dereferencing symlinks fails due to missing targets (e.g., dangling README link), retry without -h
                        if exit_code != 0 and (
                            "No such file or directory" in stderr
                            or "error exit delayed from previous errors" in stderr
                        ):
                            await self._log_runtime(
                                "WARNING",
                                "BMCSSHService",
                                "Archive creation failed while dereferencing symlinks; retrying without -h to include symlinks as links",
                                dut_id,
                            )
                            if source_is_directory:
                                fallback_cmd = build_remote_cmd(
                                    f"{tar_cmd} -czf {{dest}} -C {{src}} .",
                                    dest=temp_path,
                                    src=source_path,
                                )
                            else:
                                src_parent = posixpath.dirname(source_path) or "/"
                                src_basename = posixpath.basename(source_path)
                                fallback_cmd = build_remote_cmd(
                                    f"{tar_cmd} -czf {{dest}} -C {{parent}} {{name}}",
                                    dest=temp_path,
                                    parent=src_parent,
                                    name=src_basename,
                                )
                            exit_code2, stdout2, stderr2 = (
                                await self.dut_manager.execute_bmc_command(
                                    dut_id, fallback_cmd
                                )
                            )
                            # busybox tar may return 1 on permission denials; treat as partial success
                            if exit_code2 == 0 or (
                                exit_code2 == 1 and "Permission denied" in stderr2
                            ):
                                if exit_code2 == 1:
                                    await self._log_runtime(
                                        "WARNING",
                                        "BMCSSHService",
                                        "Fallback archive created with warnings - some files skipped due to permission errors",
                                        dut_id,
                                    )
                                # Normalize to success for downstream logic
                                exit_code = 0
                            else:
                                await self._log_runtime(
                                    "WARNING",
                                    "BMCSSHService",
                                    f"Fallback archive without -h failed: {stderr2}",
                                    dut_id,
                                )

                        # tar exit codes: 0=success, 1=some files differed (incl. permission denied), 2=fatal error
                        # Accept exit code 1 as partial success if archive was created (BusyBox tar behavior)
                        if exit_code == 0 or (
                            exit_code == 1 and "Permission denied" in stderr
                        ):
                            if exit_code == 1:
                                await self._log_runtime(
                                    "WARNING",
                                    "BMCSSHService",
                                    "Archive created with warnings - some files skipped due to permission errors",
                                    dut_id,
                                )
                            await self._log_runtime(
                                "INFO",
                                "BMCSSHService",
                                f"Archive created successfully at {temp_path}",
                                dut_id,
                            )

                            # Download the archive using the legacy approach: hexdump for binary-safe transfer
                            # This is the proven method from the legacy nvdebug code
                            await self._log_runtime(
                                "INFO",
                                "BMCSSHService",
                                "Using hexdump method for binary-safe file transfer (legacy approach)",
                                dut_id,
                            )

                            # Get file size first
                            size_cmd = build_remote_cmd(
                                "ls -l {path} | awk '{{print $5}}'", path=temp_path
                            )
                            exit_code, size_output, stderr = (
                                await self.dut_manager.execute_bmc_command(
                                    dut_id, size_cmd
                                )
                            )

                            file_size = 0
                            if exit_code == 0 and size_output:
                                try:
                                    file_size = int(size_output.strip())
                                    await self._log_runtime(
                                        "INFO",
                                        "BMCSSHService",
                                        f"Archive size: {file_size} bytes",
                                        dut_id,
                                    )
                                except Exception as e:
                                    await self._log_runtime(
                                        "WARNING",
                                        "BMCSSHService",
                                        f"Error determining file size: {str(e)}",
                                        dut_id,
                                    )

                            # Use hexdump for binary-safe transfer (legacy method)
                            hexdump_cmd = f"hexdump -v -e '1/1 \"%02x\"' {temp_path}"
                            exit_code, hex_data, stderr = (
                                await self.dut_manager.execute_bmc_command(
                                    dut_id, hexdump_cmd
                                )
                            )

                            if exit_code == 0 and hex_data:
                                try:
                                    # Convert hex back to binary using the legacy method
                                    hex_data_clean = hex_data.strip()
                                    archive_data = bytes.fromhex(hex_data_clean)

                                    await self._log_runtime(
                                        "INFO",
                                        "BMCSSHService",
                                        f"Hexdump transfer successful, size: {len(archive_data)} bytes",
                                        dut_id,
                                    )
                                except Exception as e:
                                    await self._log_runtime(
                                        "WARNING",
                                        "BMCSSHService",
                                        f"Failed to convert hex to binary: {str(e)}",
                                        dut_id,
                                    )
                                    archive_data = None
                            else:
                                await self._log_runtime(
                                    "WARNING",
                                    "BMCSSHService",
                                    f"Hexdump transfer failed: {stderr}",
                                    dut_id,
                                )
                                archive_data = None

                            if exit_code == 0 and archive_data:
                                file_path = await self.write_output_with_generalization(
                                    dut_id,
                                    kwargs.get("collector_id", ""),
                                    archive_data,
                                    output_pattern=output_pattern,
                                    function_tag=function_tag,
                                    default_extension=".tar.gz",
                                    substitutions=timestamp_substitutions,
                                    binary_mode=True,
                                )
                                output_files.append(file_path)

                                await self._log_runtime(
                                    "INFO",
                                    "BMCSSHService",
                                    f"SFTP file transfer successful: {file_path}",
                                    dut_id,
                                )

                                # Clean up temp file
                                cleanup_command = build_remote_cmd(
                                    "rm -f {path}", path=temp_path
                                )
                                await self.dut_manager.execute_bmc_command(
                                    dut_id, cleanup_command
                                )

                                return await self._create_standardized_collector_result(
                                    successful_operations=1,
                                    total_operations=1,
                                    output_files=output_files,
                                    error_messages=[],
                                    operation_name="bmc_file_transfer",
                                    additional_context={
                                        "transfer_method": "SFTP",
                                        "source_path": source_path,
                                        "used_fallback_source_path": used_fallback,
                                    },
                                )
                            else:
                                await self._log_runtime(
                                    "WARNING",
                                    "BMCSSHService",
                                    f"SFTP download failed on attempt {attempt + 1}: {stderr}",
                                    dut_id,
                                )
                        else:
                            # Provide helpful error message for common failures
                            error_msg = f"SFTP archive creation failed on attempt {attempt + 1}: {stderr}"
                            if (
                                "No space left on device" in stderr
                                or "no space left" in stderr.lower()
                            ):
                                error_msg += f"\n  → BMC temp directory {bmc_temp_dir} may be full. Consider freeing space or using a different temp directory."
                            elif "Cannot stat" in stderr or "No such file" in stderr:
                                error_msg += f"\n  → Some files or symlink targets in {source_path} may be missing or inaccessible."

                            await self._log_runtime(
                                "WARNING",
                                "BMCSSHService",
                                error_msg,
                                dut_id,
                            )

                    except Exception as e:
                        await self._log_runtime(
                            "WARNING",
                            "BMCSSHService",
                            f"SFTP transfer failed on attempt {attempt + 1}: {str(e)}",
                            dut_id,
                        )

                    # Wait before retry (except on last attempt)
                    if attempt < retry_count:
                        await asyncio.sleep(retry_delay)
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"Waiting {retry_delay} seconds before retry...",
                            dut_id,
                        )

            # If SFTP failed, try binary-safe hexdump fallback for key files
            if fallback_hexdump and key_files:
                try:
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        f"SFTP/tar archive failed. Falling back to binary-safe hexdump transfer of {len(key_files)} key files",
                        dut_id,
                    )

                    collected_files = []
                    failed_files = []

                    for file_path in key_files:
                        try:
                            # First check if file exists to avoid unnecessary errors
                            check_command = build_remote_cmd(
                                "test -f {path}", path=file_path
                            )
                            check_exit_code, _, _ = (
                                await self.dut_manager.execute_bmc_command(
                                    dut_id, check_command
                                )
                            )

                            if check_exit_code != 0:
                                # File doesn't exist, skip it without logging as error
                                await self._log_runtime(
                                    "DEBUG",
                                    "BMCSSHService",
                                    f"Key file {file_path} does not exist on BMC, skipping",
                                    dut_id,
                                )
                                continue

                            # Use binary-safe hexdump that can be converted back
                            # -v = no asterisk abbreviation, -e = format string
                            hexdump_command = build_remote_cmd(
                                "hexdump -v -e '1/1 \"%02x\"' {path}",
                                path=file_path,
                            )
                            exit_code, hex_data, stderr = (
                                await self.dut_manager.execute_bmc_command(
                                    dut_id, hexdump_command
                                )
                            )

                            if exit_code == 0 and hex_data:
                                try:
                                    # Convert hex back to binary
                                    hex_data_clean = hex_data.strip()
                                    binary_data = bytes.fromhex(hex_data_clean)

                                    # Generate filename from the source path
                                    safe_filename = file_path.replace("/", "_").lstrip(
                                        "_"
                                    )
                                    output_pattern_single = kwargs.get(
                                        "output_pattern", ""
                                    ).replace(".tar.gz", f"_{safe_filename}")

                                    saved_file = await self.write_output_with_generalization(
                                        dut_id,
                                        kwargs.get("collector_id", ""),
                                        binary_data,
                                        output_pattern=output_pattern_single,
                                        function_tag=f"{function_tag}_hexdump_fallback",
                                        substitutions=timestamp_substitutions,
                                        binary_mode=True,
                                    )

                                    if saved_file:
                                        collected_files.append((file_path, saved_file))
                                        output_files.append(saved_file)
                                        await self._log_runtime(
                                            "INFO",
                                            "BMCSSHService",
                                            f"Successfully transferred {file_path} via hexdump (size: {len(binary_data)} bytes)",
                                            dut_id,
                                        )
                                except Exception as e:
                                    failed_files.append(file_path)
                                    await self._log_runtime(
                                        "ERROR",
                                        "BMCSSHService",
                                        f"Failed to convert hexdump for {file_path}: {str(e)}",
                                        dut_id,
                                    )
                            else:
                                failed_files.append(file_path)
                                await self._log_runtime(
                                    "ERROR",
                                    "BMCSSHService",
                                    f"Hexdump command failed for {file_path}: {stderr}",
                                    dut_id,
                                )
                        except Exception as e:
                            failed_files.append(file_path)
                            await self._log_runtime(
                                "ERROR",
                                "BMCSSHService",
                                f"Exception during hexdump transfer of {file_path}: {str(e)}",
                                dut_id,
                            )

                    if collected_files:
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"Hexdump fallback collected {len(collected_files)}/{len(key_files)} key files",
                            dut_id,
                        )

                        # Return as PARTIAL success - we got individual files, not full archive
                        error_msgs = []
                        if failed_files:
                            error_msgs.append(
                                f"Failed to transfer {len(failed_files)} files: {', '.join(failed_files)}"
                            )
                        error_msgs.append(
                            f"WARNING: Only collected {len(key_files)} key files (not full {source_path} directory)"
                        )

                        return await self._create_standardized_collector_result(
                            successful_operations=len(collected_files),
                            total_operations=len(key_files)
                            + 1,  # +1 for full archive we wanted
                            output_files=output_files,
                            error_messages=error_msgs,
                            operation_name="bmc_file_transfer",
                            additional_context={
                                "transfer_method": "hexdump_fallback_binary",
                                "collected_files": [f for f, _ in collected_files],
                                "failed_files": failed_files,
                                "warning": f"Collected only {len(key_files)} key files, not full directory archive",
                            },
                        )

                except Exception as e:
                    await self._log_runtime(
                        "ERROR",
                        "BMCSSHService",
                        f"Hexdump fallback failed: {str(e)}",
                        dut_id,
                    )

            # Provide more detailed error information
            error_details = []
            if not key_files:
                error_details.append("No files found to transfer")
            else:
                error_details.append(f"SFTP failed for {len(key_files)} files")
                if fallback_hexdump:
                    error_details.append("Hexdump fallback also failed")

            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"File transfer failed: {'; '.join(error_details)}"],
                operation_name="bmc_file_transfer",
                additional_context={"error_details": error_details},
                dut_id=dut_id,
                collector_id="bmc_file_transfer",
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"File transfer failed: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"File transfer failed: {str(e)}"],
                operation_name="bmc_file_transfer",
                additional_context={},
            )

    async def upload_file_to_bmc(
        self,
        dut_id: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Upload a local file to the BMC via existing transfer infrastructure.
        Supports wildcard patterns to find versioned files.

        Args:
            dut_id: The DUT identifier
            **kwargs: Additional keyword arguments
                - local_path: Path pattern to the local file (supports wildcards, required)
                - remote_path: Destination directory on the BMC (required)
                - create_remote_dir: Whether to create remote directory if it doesn't exist (default: True)
                - make_executable: Whether to make the file executable after upload (default: False)

        Returns:
            Dict[str, Any]: Standardized collector result with uploaded_script_path in additional_context
        """
        try:
            # Get parameters
            local_path_pattern = kwargs.get("local_path")
            remote_dir = kwargs.get("remote_path")
            create_remote_dir = kwargs.get("create_remote_dir", True)
            make_executable = kwargs.get("make_executable", False)

            if not local_path_pattern:
                raise ValueError("local_path parameter is required")
            if not remote_dir:
                raise ValueError("remote_path parameter is required")

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Starting file upload: {local_path_pattern} -> {remote_dir}",
                dut_id,
            )

            # Find local file using glob pattern
            matching_files = glob.glob(local_path_pattern)

            if not matching_files:
                error_msg = f"No files found matching pattern: {local_path_pattern}"
                await self._log_runtime(
                    "ERROR",
                    "BMCSSHService",
                    error_msg,
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[error_msg],
                    operation_name="upload_file_to_bmc",
                    additional_context={
                        "local_path_pattern": local_path_pattern,
                        "remote_path": remote_dir,
                    },
                )

            # Use the first matching file
            local_file = matching_files[0]
            local_filename = os.path.basename(local_file)
            remote_file_path = os.path.join(remote_dir, local_filename)

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Found file to upload: {local_file} -> {remote_file_path}",
                dut_id,
            )

            # Create remote directory if requested
            if create_remote_dir:
                mkdir_command = f"mkdir -p {remote_dir}"
                await self._log_runtime(
                    "DEBUG",
                    "BMCSSHService",
                    f"Creating remote directory: {mkdir_command}",
                    dut_id,
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, mkdir_command
                )
                if exit_code != 0:
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        f"Failed to create remote directory (may already exist): {stderr}",
                        dut_id,
                    )

            # Upload file using DUT manager's transfer_files method with fallbacks
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                f"Uploading file using DUT manager: {local_file} -> {remote_dir}",
                dut_id,
            )

            upload_success = False
            upload_method = None

            # Method 1: Try using DUT manager's transfer_files with SFTP (preferred, has retry logic)
            try:
                await self._log_runtime(
                    "DEBUG",
                    "BMCSSHService",
                    f"Attempting SFTP upload via transfer_files to {remote_file_path}",
                    dut_id,
                )

                # Use transfer_files with copy_to_destination=True to upload
                success, error_msg = await self.dut_manager.transfer_files(
                    dut_id=dut_id,
                    sources=local_file,
                    destination_directory=remote_dir,
                    copy_to_destination=True,  # Upload TO remote
                    max_retries=3,
                )

                if success:
                    upload_success = True
                    upload_method = "SFTP"
                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"SFTP upload successful: {remote_file_path}",
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        f"SFTP upload failed: {error_msg}. Trying fallback methods...",
                        dut_id,
                    )
            except Exception as e:
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    f"SFTP upload exception: {str(e)}. Trying fallback methods...",
                    dut_id,
                )

            # Method 1.5: Try direct cat upload for text files (faster than base64 for scripts)
            if not upload_success:
                try:
                    await self._log_runtime(
                        "DEBUG",
                        "BMCSSHService",
                        f"Attempting direct cat upload to {remote_file_path}",
                        dut_id,
                    )

                    # Read file content
                    with open(local_file, "rb") as f:
                        file_content = f.read()

                    # Try to decode as text - if it works, it's a text file
                    try:
                        text_content = file_content.decode("utf-8")
                        # Escape single quotes for shell safety
                        escaped_content = text_content.replace("'", "'\"'\"'")

                        # For large files, use a heredoc instead of echo to avoid command line limits
                        if len(text_content) > 50000:  # 50KB threshold
                            # Create a random EOF marker that's not in the content
                            import random
                            import string

                            max_attempts = 10
                            for attempt in range(max_attempts):
                                eof_marker = "NVDEBUG_EOF_" + secrets.token_hex(8)
                                if eof_marker not in text_content:
                                    break
                            else:
                                # Very unlikely - use timestamp-based marker
                                import time

                                eof_marker = f"NVDEBUG_EOF_{int(time.time() * 1000000)}"

                            # Upload using heredoc (cat << 'EOF' - single quotes prevent variable expansion)
                            upload_command = (
                                build_remote_cmd(
                                    "cat > {path} << '{eof}'\n",
                                    path=remote_file_path,
                                    eof=eof_marker,
                                )
                                + text_content
                                + "\n"
                                + eof_marker
                            )
                            exit_code, stdout, stderr = (
                                await self.dut_manager.execute_bmc_command(
                                    dut_id, upload_command, timeout=180
                                )
                            )
                        else:
                            # For smaller files, use echo
                            upload_command = (
                                f"echo '{escaped_content}' > {remote_file_path}"
                            )
                            exit_code, stdout, stderr = (
                                await self.dut_manager.execute_bmc_command(
                                    dut_id, upload_command, timeout=60
                                )
                            )

                        if exit_code == 0:
                            upload_success = True
                            upload_method = "cat"
                            await self._log_runtime(
                                "INFO",
                                "BMCSSHService",
                                f"Direct cat upload successful: {remote_file_path}",
                                dut_id,
                            )
                        else:
                            raise Exception(f"Cat upload failed: {stderr}")
                    except UnicodeDecodeError:
                        # Binary file - skip cat method
                        raise Exception("File is binary, skipping cat upload")

                except Exception as e:
                    await self._log_runtime(
                        "DEBUG",
                        "BMCSSHService",
                        f"Cat upload not applicable: {str(e)}. Trying base64...",
                        dut_id,
                    )

            # Method 2: Fallback to base64 encoding (more compatible)
            if not upload_success:
                try:
                    await self._log_runtime(
                        "DEBUG",
                        "BMCSSHService",
                        f"Attempting base64 upload to {remote_file_path}",
                        dut_id,
                    )

                    # Check if base64 command exists FIRST (fail fast)
                    check_cmd = "command -v base64 || which base64"
                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_bmc_command(dut_id, check_cmd)
                    )
                    if exit_code != 0:
                        raise Exception("base64 command not available on BMC")

                    # Read file and encode to base64
                    with open(local_file, "rb") as f:
                        file_content = f.read()

                    encoded_content = base64.b64encode(file_content).decode("ascii")

                    # Split into larger chunks (most BMCs handle 50KB+ command lines)
                    chunk_size = 20000  # 20KB chunks for faster upload
                    chunks = [
                        encoded_content[i : i + chunk_size]
                        for i in range(0, len(encoded_content), chunk_size)
                    ]

                    # Remove file if exists
                    rm_command = build_remote_cmd("rm -f {path}", path=remote_file_path)
                    await self.dut_manager.execute_bmc_command(dut_id, rm_command)

                    # Write chunks
                    for i, chunk in enumerate(chunks):
                        # Escape single quotes in the chunk
                        escaped_chunk = chunk.replace("'", "'\\''")
                        if i == 0:
                            echo_command = (
                                f"echo '{escaped_chunk}' > {remote_file_path}.b64"
                            )
                        else:
                            echo_command = (
                                f"echo '{escaped_chunk}' >> {remote_file_path}.b64"
                            )

                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_bmc_command(
                                dut_id, echo_command
                            )
                        )
                        if exit_code != 0:
                            raise Exception(f"Failed to write chunk {i}: {stderr}")

                    # Decode base64 file
                    decode_command = build_remote_cmd(
                        "base64 -d {path}.b64 > {path} && rm {path}.b64",
                        path=remote_file_path,
                    )
                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_bmc_command(
                            dut_id, decode_command
                        )
                    )

                    if exit_code == 0:
                        upload_success = True
                        upload_method = "base64"
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"Base64 upload successful: {remote_file_path}",
                            dut_id,
                        )
                    else:
                        await self._log_runtime(
                            "WARNING",
                            "BMCSSHService",
                            f"Base64 upload failed: {stderr}. Trying hex fallback...",
                            dut_id,
                        )
                except Exception as e:
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        f"Base64 upload exception: {str(e)}. Trying hex fallback...",
                        dut_id,
                    )

            # Method 3: Last resort - hexdump method (most compatible but slower)
            if not upload_success:
                try:
                    await self._log_runtime(
                        "DEBUG",
                        "BMCSSHService",
                        f"Attempting hex upload to {remote_file_path}",
                        dut_id,
                    )

                    # Check if xxd command exists FIRST (fail fast)
                    check_cmd = "command -v xxd || which xxd"
                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_bmc_command(dut_id, check_cmd)
                    )
                    if exit_code != 0:
                        raise Exception("xxd command not available on BMC")

                    # Read file as hex
                    with open(local_file, "rb") as f:
                        file_content = f.read()

                    hex_content = file_content.hex()

                    # Split into larger chunks for faster upload
                    chunk_size = 20000  # 20KB chunks
                    chunks = [
                        hex_content[i : i + chunk_size]
                        for i in range(0, len(hex_content), chunk_size)
                    ]

                    # Remove file if exists
                    rm_command = build_remote_cmd("rm -f {path}", path=remote_file_path)
                    await self.dut_manager.execute_bmc_command(dut_id, rm_command)

                    # Write chunks
                    for i, chunk in enumerate(chunks):
                        escaped_chunk = chunk.replace("'", "'\\''")
                        if i == 0:
                            echo_command = (
                                f"echo '{escaped_chunk}' > {remote_file_path}.hex"
                            )
                        else:
                            echo_command = (
                                f"echo '{escaped_chunk}' >> {remote_file_path}.hex"
                            )

                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_bmc_command(
                                dut_id, echo_command
                            )
                        )
                        if exit_code != 0:
                            raise Exception(f"Failed to write hex chunk {i}: {stderr}")

                    # Convert hex to binary
                    convert_command = build_remote_cmd(
                        "xxd -r -p {path}.hex {path} && rm {path}.hex",
                        path=remote_file_path,
                    )
                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_bmc_command(
                            dut_id, convert_command
                        )
                    )

                    if exit_code == 0:
                        upload_success = True
                        upload_method = "hexdump"
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"Hex upload successful: {remote_file_path}",
                            dut_id,
                        )
                    else:
                        raise Exception(f"Hex conversion failed: {stderr}")

                except Exception as e:
                    await self._log_runtime(
                        "ERROR",
                        "BMCSSHService",
                        f"All upload methods failed. Last error: {str(e)}",
                        dut_id,
                    )

            if not upload_success:
                error_msg = "File upload failed: All methods (SCP, base64, hex) failed"
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[error_msg],
                    operation_name="upload_file_to_bmc",
                    additional_context={
                        "local_file": local_file,
                        "remote_path": remote_file_path,
                    },
                )

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"File uploaded successfully using {upload_method}: {remote_file_path}",
                dut_id,
            )

            # Make executable if requested
            if make_executable:
                chmod_command = f"chmod +x {remote_file_path}"
                await self._log_runtime(
                    "DEBUG",
                    "BMCSSHService",
                    f"Making file executable: {chmod_command}",
                    dut_id,
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, chmod_command
                )
                if exit_code != 0:
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        f"Failed to make file executable: {stderr}",
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"File made executable: {remote_file_path}",
                        dut_id,
                    )

            # Return success with uploaded script path in context for next hook
            return await self._create_standardized_collector_result(
                successful_operations=1,
                total_operations=1,
                output_files=[],
                error_messages=[],
                operation_name="upload_file_to_bmc",
                additional_context={
                    "uploaded_script_path": remote_file_path,  # Pass to next hook
                    "local_file": local_file,
                    "remote_path": remote_file_path,
                    "upload_method": upload_method,
                    "status": "success",
                },
            )

        except Exception as e:
            error_msg = f"File upload failed: {str(e)}"
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                error_msg,
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                f"Upload error traceback: {traceback.format_exc()}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[error_msg],
                operation_name="upload_file_to_bmc",
                additional_context={},
            )

    def _expand_hmc_candidate_value(
        self, dut: "DUT", candidate: Any, visited: Optional[set] = None
    ) -> List[str]:
        """
        Expand a candidate value into concrete HMC endpoints.

        Args:
            dut: DUT object providing configuration context.
            candidate: Raw candidate value (string, list, or config key).
            visited: Set used to prevent circular references.
        """
        if visited is None:
            visited = set()

        results: List[str] = []

        if candidate is None:
            return results

        if isinstance(candidate, (list, tuple, set)):
            for item in candidate:
                results.extend(
                    self._expand_hmc_candidate_value(dut, item, visited.copy())
                )
            return results

        if not isinstance(candidate, str):
            candidate = str(candidate)

        candidate = candidate.strip()
        if not candidate:
            return results

        if candidate in visited:
            return results

        visited.add(candidate)

        config_dict = getattr(dut, "config", {})
        if isinstance(config_dict, dict) and candidate in config_dict:
            config_value = config_dict[candidate]
            results.extend(
                self._expand_hmc_candidate_value(dut, config_value, visited.copy())
            )
            return results

        env_value = os.getenv(candidate)
        if env_value and env_value != candidate:
            results.extend(
                self._expand_hmc_candidate_value(dut, env_value, visited.copy())
            )
            return results

        results.append(candidate)
        return results

    @staticmethod
    def _dedupe_candidates(candidates: List[str]) -> List[str]:
        """
        Deduplicate candidate list while preserving order.
        """
        seen: Set[str] = set()
        ordered: List[str] = []
        for candidate in candidates:
            value = candidate.strip()
            if value and value not in seen:
                seen.add(value)
                ordered.append(value)
        return ordered

    async def _resolve_hmc_ip_with_fallback(self, dut_id: str) -> Optional[str]:
        """
        Resolve an HMC endpoint using candidate fallbacks.
        """
        dut = self.dut_manager.get_dut(dut_id)
        if not dut:
            return None

        if getattr(dut.credentials, "hmc_ip", None) and getattr(
            dut.credentials, "hmc_ip_validated", False
        ):
            return dut.credentials.hmc_ip.strip()

        candidate_sources: List[Any] = [
            getattr(dut.credentials, "hmc_ip", None),
            getattr(dut.credentials, "hmc_ip_candidates", []) or [],
            dut.config.get("HMC_IP_CANDIDATES"),
            dut.config.get("HMC_IP"),
            dut.config.get("hmc_ip"),
        ]

        platform_detection = dut.config.get("platform_detection", {})
        if isinstance(platform_detection, dict):
            candidate_sources.append(platform_detection.get("hmc_ip_candidates"))
            candidate_sources.append(platform_detection.get("hmc_ip"))

        expanded_candidates: List[str] = []
        for source in candidate_sources:
            expanded_candidates.extend(self._expand_hmc_candidate_value(dut, source))

        candidate_list = self._dedupe_candidates(expanded_candidates)
        if not candidate_list:
            await self._log_runtime(
                "WARNING",
                "BMCSSHService",
                "No HMC IP candidates available for fallback resolution",
                dut_id,
            )
            return None

        selected_candidate: Optional[str] = None
        for candidate in candidate_list:
            ping_target = candidate.split(":")[0]
            ping_command = f"ping -c 1 -W 2 {shlex.quote(ping_target)}"
            exit_code, _, _ = await self.dut_manager.execute_bmc_command(
                dut_id, ping_command, timeout=30
            )
            if exit_code == 0:
                selected_candidate = candidate
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Selected reachable HMC endpoint '{candidate}'",
                    dut_id,
                )
                break

            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                f"HMC endpoint '{candidate}' unreachable via BMC ping, trying next candidate",
                dut_id,
            )

        if not selected_candidate:
            selected_candidate = candidate_list[0]
            await self._log_runtime(
                "WARNING",
                "BMCSSHService",
                (
                    f"All HMC endpoint candidates unreachable; falling back to first "
                    f"candidate '{selected_candidate}'"
                ),
                dut_id,
            )

        dut.credentials.hmc_ip = selected_candidate
        dut.credentials.hmc_ip_validated = True

        if selected_candidate not in dut.credentials.hmc_ip_candidates:
            dut.credentials.hmc_ip_candidates.insert(0, selected_candidate)

        dut.config["HMC_IP"] = selected_candidate
        dut.config["hmc_ip"] = selected_candidate

        existing_config_candidates = dut.config.get("HMC_IP_CANDIDATES", [])
        if not isinstance(existing_config_candidates, list):
            existing_config_candidates = []
        dut.config["HMC_IP_CANDIDATES"] = self._dedupe_candidates(
            [selected_candidate] + existing_config_candidates
        )

        if isinstance(platform_detection, dict):
            pd_candidates = platform_detection.get("hmc_ip_candidates", [])
            if not isinstance(pd_candidates, list):
                pd_candidates = []
            platform_detection["hmc_ip_candidates"] = self._dedupe_candidates(
                [selected_candidate] + pd_candidates
            )
            platform_detection["hmc_ip"] = selected_candidate

        return selected_candidate

    async def run_bmc_script(
        self,
        dut_id: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Execute external script on BMC with full YAML-driven configuration.
        This is a generic script execution method that can run any script based on
        YAML parameters. It supports versioned scripts, alternative script names,
        configurable timeouts, and flexible output file patterns.

        Args:
            dut_id: The DUT identifier
            **kwargs: Additional keyword arguments
        """
        try:
            # Check if previous hook uploaded a script (hooks in same stage share context via kwargs)
            uploaded_script_path = kwargs.get("uploaded_script_path")

            # Parameters come directly from hook_params, not nested in "params"
            script_name = kwargs.get("script_name")

            # Use uploaded_script_path if available, otherwise use script_name
            if uploaded_script_path:
                script_name = uploaded_script_path
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Using uploaded script path from previous hook: {script_name}",
                    dut_id,
                )
            elif not script_name:
                raise ValueError("script_name parameter is required")

            function_tag = kwargs.get("function_tag", "script_execution")
            use_hmc_ip = kwargs.get("use_hmc_ip", False)

            # Flag to control automatic file retrieval after script execution
            auto_retrieve_files = kwargs.get("auto_retrieve_files", True)

            # Create or use a known working directory for script output
            # This allows file retrieval even if script times out
            use_working_directory = kwargs.get("use_working_directory", False)
            working_dir = kwargs.get("working_dir")  # Can be passed from previous hook

            # Extract directory and base script name from the script_name parameter
            script_dir = (
                os.path.dirname(script_name) if os.path.dirname(script_name) else "."
            )
            base_script_name = os.path.basename(script_name)

            # Get alternative script names from parameters (optional)
            alternative_scripts = kwargs.get("alternative_scripts", [])

            # Get script timeout from parameters (optional, default 300 seconds)
            script_timeout = kwargs.get("script_timeout", 300)

            # Get output file search pattern from parameters (optional)
            output_file_pattern = kwargs.get(
                "output_file_pattern", "*.tar.gz *.log *.txt"
            )

            # Get script arguments from parameters (optional)
            script_args = kwargs.get("script_args", [])

            # Get search directories for output files (optional, default /tmp)
            output_search_dirs = kwargs.get("output_search_dirs", ["/tmp"])

            # Get script execution mode (optional, default "direct")
            execution_mode = kwargs.get(
                "execution_mode", "direct"
            )  # direct, bash, sh, etc.

            # Get script name pattern for finding versioned scripts (optional)
            # Pattern can include {base_script_name} placeholder and wildcards
            # Default: "{base_script_name}_*.sh" for exact prefix matching
            script_name_pattern = kwargs.get(
                "script_name_pattern", "{base_script_name}_*.sh"
            )

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Starting script execution: {script_name}",
                dut_id,
            )

            output_files = []

            # Create a unique working directory if requested
            if use_working_directory and not working_dir:
                random_suffix = secrets.token_hex(8)
                working_dir = f"/tmp/nvdebug_{random_suffix}"

                # Create the working directory on BMC
                mkdir_cmd = f"mkdir -p {working_dir}"
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, mkdir_cmd
                )

                if exit_code == 0:
                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"Created working directory: {working_dir}",
                        dut_id,
                    )
                    # Store working_dir in kwargs for subsequent hooks
                    kwargs["working_dir"] = working_dir
                    kwargs["working_dir_created"] = True
                else:
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        f"Failed to create working directory {working_dir}: {stderr}",
                        dut_id,
                    )
                    working_dir = None

            # Check if script exists - first try the exact path, then look for versioned scripts
            check_command = build_remote_cmd(
                "test -f {path} && echo 'found' || echo 'not found'", path=script_name
            )
            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, check_command
            )

            if exit_code != 0 or "not found" in stdout:
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    f"One-click script {script_name} not found, trying alternatives with pattern: {script_name_pattern}",
                    dut_id,
                )

                # Try to find versioned scripts using the configured pattern
                # Replace {base_script_name} placeholder with actual base script name
                search_pattern = script_name_pattern.replace(
                    "{base_script_name}", base_script_name
                )
                find_command = build_remote_cmd(
                    "find {dir}/ -name {pattern} 2>/dev/null | head -1",
                    dir=script_dir,
                    pattern=search_pattern,
                )

                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, find_command
                )

                if exit_code == 0 and stdout.strip():
                    script_name = stdout.strip()
                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"Found versioned one-click script: {script_name}",
                        dut_id,
                    )
                else:
                    # Try alternative script names in PATH
                    for alt_script in alternative_scripts:
                        check_command = f"which {alt_script}"
                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_bmc_command(
                                dut_id, check_command
                            )
                        )
                        if exit_code == 0:
                            script_name = alt_script
                            break
                    else:
                        # If no script found, return skipped status
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"No script found for {script_name}, skipping execution",
                            dut_id,
                        )

                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=0,
                            output_files=[],
                            error_messages=[],
                            operation_name="script_execution",
                            additional_context={
                                "status": "skipped",
                                "reason": f"No script found for {script_name}",
                            },
                        )

            # Build the script command based on execution mode and parameters
            if execution_mode == "direct":
                script_command = script_name
            elif execution_mode in ["bash", "sh", "python", "python3"]:
                script_command = f"{execution_mode} {script_name}"
            else:
                script_command = f"{execution_mode} {script_name}"

            # Add script arguments if provided
            if script_args:
                script_command += " " + " ".join(str(arg) for arg in script_args)

            # Add HMC IP if requested (use short flag -i for script compatibility)
            if use_hmc_ip:
                resolved_hmc_ip = await self._resolve_hmc_ip_with_fallback(dut_id)
                if resolved_hmc_ip:
                    script_command += f" -i {resolved_hmc_ip}"
                else:
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        "Unable to determine a reachable HMC endpoint; continuing without -i flag",
                        dut_id,
                    )

            # If working directory is set, pass it to the script via -o flag
            # This tells the script where to write its output files
            pass_working_dir_to_script = kwargs.get("pass_working_dir_to_script", False)
            if working_dir and pass_working_dir_to_script:
                script_command += f" -o {working_dir}"
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Passing working directory to script via -o flag: {working_dir}",
                    dut_id,
                )

            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, script_command, timeout=script_timeout
            )

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Script exit_code={exit_code}, stdout length={len(stdout) if stdout else 0}, stderr length={len(stderr) if stderr else 0}",
                dut_id,
            )

            # Store execution result in context for downstream hooks
            kwargs["script_exit_code"] = exit_code
            kwargs["script_stdout"] = stdout
            kwargs["script_stderr"] = stderr

            # Retrieve files if auto_retrieve_files is True (even on timeout/failure)
            # This ensures we get partial logs even if the script didn't complete successfully
            if auto_retrieve_files:
                # Look for output files created by the script
                # Convert space-separated patterns to find command format
                from tool.utils.command_safety import quote_arg

                patterns = output_file_pattern.split()
                find_conditions = " -o ".join(
                    [f"-name {quote_arg(pattern)}" for pattern in patterns]
                )

                # Search in all specified directories, prioritize working_dir if it exists
                search_dirs_list = output_search_dirs.copy()
                if working_dir and working_dir not in search_dirs_list:
                    # Add working directory as first search location
                    search_dirs_list.insert(0, working_dir)
                search_dirs = " ".join(quote_arg(d) for d in search_dirs_list)
                # Need to wrap find conditions in parentheses when using multiple directories
                # Use head -n 10 for BusyBox compatibility (BMC uses BusyBox)
                # search_dirs and find_conditions are pre-quoted via quote_arg above
                find_command = (
                    "find "
                    + search_dirs
                    + " \\( "
                    + find_conditions
                    + " \\) 2>/dev/null | head -n 10"
                )

                find_exit_code, find_stdout, find_stderr = (
                    await self.dut_manager.execute_bmc_command(dut_id, find_command)
                )

                # Try to retrieve files even if the original script failed/timed out
                if find_exit_code == 0 and find_stdout:
                    files = find_stdout.strip().split("\n")

                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"Found {len(files)} output files (script exit_code={exit_code})",
                        dut_id,
                    )

                    # Check if base64 utility exists on BMC, upload if needed
                    base64_cmd = None

                    # First try busybox base64 (most common on BMC)
                    check_cmd = "busybox base64 --help 2>&1"
                    exit_code_check, stdout_check, _ = (
                        await self.dut_manager.execute_bmc_command(dut_id, check_cmd)
                    )
                    if exit_code_check == 0:
                        base64_cmd = "busybox base64"
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            "Found busybox base64 on BMC",
                            dut_id,
                        )
                    else:
                        # Try standard base64
                        check_cmd = "base64 --help 2>&1"
                        exit_code_check, stdout_check, _ = (
                            await self.dut_manager.execute_bmc_command(
                                dut_id, check_cmd
                            )
                        )
                        if exit_code_check == 0:
                            base64_cmd = "base64"
                            await self._log_runtime(
                                "INFO",
                                "BMCSSHService",
                                "Found standard base64 on BMC",
                                dut_id,
                            )

                    # If no base64 found, use hexdump (universally available)
                    if base64_cmd is None:
                        await self._log_runtime(
                            "WARNING",
                            "BMCSSHService",
                            "No base64 utility found on BMC, will use hexdump for file transfer",
                            dut_id,
                        )
                        # hexdump is much more reliable than base64 on embedded systems
                        # Format: -v (no asterisk for repeated lines), -e '1/1 "%02x"' (hex bytes)
                        base64_cmd = "hexdump -v -e '1/1 \"%02x\"'"

                    for file_path in files:
                        if file_path:
                            try:
                                # Skip SFTP for now (has path issues with nested directories)
                                # Use the base64 command we determined earlier
                                file_data = None
                                download_method = "unknown"

                                # Use the base64 command we found/created earlier
                                if base64_cmd and file_data is None:
                                    # Check if we're using hexdump fallback (not real base64)
                                    if "hexdump" in base64_cmd:
                                        download_command = build_remote_cmd(
                                            f"{base64_cmd} {{path}}",
                                            path=file_path,
                                        )
                                        exit_code, stdout_hex, stderr = (
                                            await self.dut_manager.execute_bmc_command(
                                                dut_id, download_command
                                            )
                                        )

                                        if exit_code == 0 and stdout_hex:
                                            # Convert hex string to bytes
                                            file_data = bytes.fromhex(
                                                stdout_hex.strip()
                                            )
                                            download_method = "hexdump"
                                    else:
                                        # Using base64 (real or our script)
                                        download_command = build_remote_cmd(
                                            f"{base64_cmd} {{path}}",
                                            path=file_path,
                                        )
                                        exit_code, stdout_b64, stderr = (
                                            await self.dut_manager.execute_bmc_command(
                                                dut_id, download_command
                                            )
                                        )

                                        if exit_code == 0 and stdout_b64:
                                            import base64

                                            file_data = base64.b64decode(stdout_b64)
                                            download_method = "base64"

                                if file_data:
                                    # Create a unique output pattern for each downloaded file
                                    # Use the original basename from BMC to preserve filenames
                                    original_basename = os.path.basename(file_path)
                                    output_file_path = await self.write_output_with_generalization(
                                        dut_id,
                                        kwargs.get("collector_id", ""),
                                        file_data,  # bytes
                                        output_pattern=original_basename,  # Use original filename, not the collector's output_pattern
                                        function_tag=function_tag,  # Keep function_tag for directory structure
                                    )
                                    output_files.append(output_file_path)
                                    await self._log_runtime(
                                        "INFO",
                                        "BMCSSHService",
                                        f"Downloaded {os.path.basename(file_path)} ({len(file_data)} bytes) via {download_method}",
                                        dut_id,
                                    )
                                else:
                                    await self._log_runtime(
                                        "ERROR",
                                        "BMCSSHService",
                                        f"Failed to download {os.path.basename(file_path)}",
                                        dut_id,
                                    )
                            except Exception as e:
                                await self._log_runtime(
                                    "ERROR",
                                    "BMCSSHService",
                                    f"Exception downloading {os.path.basename(file_path)}: {str(e)}",
                                    dut_id,
                                )
                                continue

                # Also save the script output (stdout)
                if stdout:
                    script_output_path = await self.write_output_with_generalization(
                        dut_id,
                        kwargs.get("collector_id", ""),
                        stdout,
                        output_pattern="script_stdout.txt",
                        function_tag=function_tag,
                    )
                    output_files.append(script_output_path)

            # Return results based on exit code and whether files were retrieved
            # Even if script failed/timed out, partial success if we got files
            if exit_code == 0:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Script execution successful: {len(output_files)} files",
                    dut_id,
                )

                return await self._create_standardized_collector_result(
                    successful_operations=1,
                    total_operations=1,
                    output_files=output_files,
                    error_messages=[],
                    operation_name="script_execution",
                    additional_context={
                        "reason": f"Script execution completed: {len(output_files)} files",
                        "exit_code": exit_code,
                    },
                )
            else:
                # Script failed or timed out, but we may have retrieved partial files
                error_details = []
                if stderr:
                    error_details.append(f"STDERR: {stderr}")
                if stdout:
                    error_details.append(f"STDOUT: {stdout}")
                if not error_details:
                    error_details.append(
                        f"Script exited with code {exit_code} (no output)"
                    )

                full_error = "\n".join(error_details)

                # Check if we retrieved any files despite the failure
                if output_files:
                    # Partial success - script failed but we got some files
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        f"Script execution failed (exit code {exit_code}), but retrieved {len(output_files)} partial files:\n{full_error}",
                        dut_id,
                    )

                    return await self._create_standardized_collector_result(
                        successful_operations=1,  # Partial success
                        total_operations=1,
                        output_files=output_files,
                        error_messages=[
                            f"Script execution failed/timed out (exit code {exit_code}), but retrieved {len(output_files)} partial files:\n{full_error}"
                        ],
                        operation_name="script_execution",
                        additional_context={
                            "exit_code": exit_code,
                            "stderr": stderr,
                            "stdout": stdout,
                            "partial_success": True,
                            "files_retrieved": len(output_files),
                        },
                    )
                else:
                    # Complete failure - no files retrieved
                    await self._log_runtime(
                        "ERROR",
                        "BMCSSHService",
                        f"Script execution failed with exit code {exit_code}:\n{full_error}",
                        dut_id,
                    )

                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=1,
                        output_files=[],
                        error_messages=[
                            f"Script execution failed (exit code {exit_code}):\n{full_error}"
                        ],
                        operation_name="script_execution",
                        additional_context={
                            "exit_code": exit_code,
                            "stderr": stderr,
                            "stdout": stdout,
                        },
                    )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"Exception in run_bmc_script: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"Exception in run_bmc_script: {str(e)}"],
                operation_name="script_execution",
                additional_context={},
            )

    async def copy_files_from_bmc(
        self,
        dut_id: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Copy files from BMC to local system. This can be used as a standalone hook
        to retrieve files from a known directory (e.g., after script timeout).

        This method can be called:
        1. As a separate hook after run_bmc_script (to retry file retrieval)
        2. In post_processing stage to ensure files are retrieved
        3. With explicit paths when auto_retrieve_files=False was used

        Args:
            dut_id: The DUT identifier
            **kwargs: Parameters including:
                - working_dir: Directory on BMC to search for files (from context)
                - output_file_pattern: File patterns to search for (e.g., "*.tar.gz *.log")
                - output_search_dirs: List of directories to search (default: ["/tmp"])
                - function_tag: Tag for output file naming
                - cleanup_working_dir: Whether to delete working_dir after copy (default: True)
        """
        try:
            # Get parameters
            working_dir = kwargs.get("working_dir")
            output_file_pattern = kwargs.get(
                "output_file_pattern", "*.tar.gz *.log *.txt"
            )
            output_search_dirs = kwargs.get("output_search_dirs", ["/tmp"])
            function_tag = kwargs.get("function_tag", "file_transfer")
            cleanup_working_dir = kwargs.get("cleanup_working_dir", True)

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Starting file retrieval from BMC (working_dir={working_dir})",
                dut_id,
            )

            output_files = []

            # Build search directories list
            search_dirs_list = output_search_dirs.copy()
            if working_dir and working_dir not in search_dirs_list:
                search_dirs_list.insert(0, working_dir)

            # Convert space-separated patterns to find command format
            from tool.utils.command_safety import quote_arg

            patterns = output_file_pattern.split()
            find_conditions = " -o ".join(
                [f"-name {quote_arg(pattern)}" for pattern in patterns]
            )

            # Pre-quote each directory individually for shell safety
            search_dirs = " ".join(quote_arg(d) for d in search_dirs_list)
            # search_dirs and find_conditions are pre-quoted via quote_arg above
            find_command = (
                "find "
                + search_dirs
                + " \\( "
                + find_conditions
                + " \\) 2>/dev/null | head -n 10"
            )

            find_exit_code, find_stdout, find_stderr = (
                await self.dut_manager.execute_bmc_command(dut_id, find_command)
            )

            if find_exit_code == 0 and find_stdout:
                files = find_stdout.strip().split("\n")

                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Found {len(files)} files to retrieve",
                    dut_id,
                )

                # Check if base64 utility exists on BMC
                base64_cmd = None

                # First try busybox base64 (most common on BMC)
                check_cmd = "busybox base64 --help 2>&1"
                exit_code_check, stdout_check, _ = (
                    await self.dut_manager.execute_bmc_command(dut_id, check_cmd)
                )
                if exit_code_check == 0:
                    base64_cmd = "busybox base64"
                else:
                    # Try standard base64
                    check_cmd = "base64 --help 2>&1"
                    exit_code_check, stdout_check, _ = (
                        await self.dut_manager.execute_bmc_command(dut_id, check_cmd)
                    )
                    if exit_code_check == 0:
                        base64_cmd = "base64"

                # If no base64 found, use hexdump (universally available)
                if base64_cmd is None:
                    base64_cmd = "hexdump -v -e '1/1 \"%02x\"'"

                # Retrieve each file
                for file_path in files:
                    if file_path:
                        try:
                            file_data = None
                            download_method = "unknown"

                            # Use the base64 command we found/created earlier
                            if base64_cmd and file_data is None:
                                # Check if we're using hexdump fallback (not real base64)
                                if "hexdump" in base64_cmd:
                                    download_command = build_remote_cmd(
                                        f"{base64_cmd} {{path}}",
                                        path=file_path,
                                    )
                                    exit_code, stdout_hex, stderr = (
                                        await self.dut_manager.execute_bmc_command(
                                            dut_id, download_command
                                        )
                                    )

                                    if exit_code == 0 and stdout_hex:
                                        # Convert hex string to bytes
                                        file_data = bytes.fromhex(stdout_hex.strip())
                                        download_method = "hexdump"
                                else:
                                    # Regular base64
                                    download_command = build_remote_cmd(
                                        f"{base64_cmd} {{path}}",
                                        path=file_path,
                                    )
                                    exit_code, stdout_b64, stderr = (
                                        await self.dut_manager.execute_bmc_command(
                                            dut_id, download_command
                                        )
                                    )

                                    if exit_code == 0 and stdout_b64:
                                        import base64

                                        file_data = base64.b64decode(stdout_b64.strip())
                                        download_method = "base64"

                            if file_data:
                                # Write file to output
                                output_path = (
                                    await self.write_output_with_generalization(
                                        dut_id,
                                        kwargs.get("collector_id", ""),
                                        file_data,
                                        output_pattern=os.path.basename(file_path),
                                        function_tag=function_tag,
                                    )
                                )
                                output_files.append(output_path)

                                await self._log_runtime(
                                    "INFO",
                                    "BMCSSHService",
                                    f"Retrieved file {file_path} using {download_method} ({len(file_data)} bytes)",
                                    dut_id,
                                )
                            else:
                                await self._log_runtime(
                                    "WARNING",
                                    "BMCSSHService",
                                    f"Failed to retrieve file {file_path}",
                                    dut_id,
                                )

                        except Exception as e:
                            await self._log_runtime(
                                "ERROR",
                                "BMCSSHService",
                                f"Error retrieving file {file_path}: {str(e)}",
                                dut_id,
                            )
            else:
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    f"No files found matching pattern '{output_file_pattern}' in {search_dirs_list}",
                    dut_id,
                )

            # Cleanup working directory if requested
            if (
                cleanup_working_dir
                and working_dir
                and kwargs.get("working_dir_created")
            ):
                cleanup_cmd = build_remote_cmd("rm -rf {path}", path=working_dir)
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, cleanup_cmd
                )
                if exit_code == 0:
                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"Cleaned up working directory: {working_dir}",
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        f"Failed to cleanup working directory {working_dir}: {stderr}",
                        dut_id,
                    )

            # Return results
            if output_files:
                return await self._create_standardized_collector_result(
                    successful_operations=len(output_files),
                    total_operations=len(output_files),
                    output_files=output_files,
                    error_messages=[],
                    operation_name="file_transfer",
                    additional_context={
                        "reason": f"Retrieved {len(output_files)} files from BMC",
                        "working_dir": working_dir,
                    },
                )
            else:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=["No files found to retrieve"],
                    operation_name="file_transfer",
                    additional_context={
                        "working_dir": working_dir,
                    },
                )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"Exception in copy_files_from_bmc: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[f"Exception in copy_files_from_bmc: {str(e)}"],
                operation_name="file_transfer",
                additional_context={},
            )

    async def _get_platform_info(
        self,
        dut_id: str,
        platform_detection_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get platform information from BMC using YAML-driven configuration.

        Args:
            dut_id: The DUT identifier
            platform_detection_config: The platform detection configuration
        """
        try:
            # Use YAML-provided platform detection config or fallback to basic detection
            if platform_detection_config:
                commands = platform_detection_config.get(
                    "commands",
                    ["cat /etc/os-release", "uname -a", "cat /proc/version"],
                )
                platform_patterns = platform_detection_config.get(
                    "platform_patterns", {}
                )
            else:
                # Fallback to basic detection if no YAML config provided
                commands = [
                    "cat /etc/os-release",
                    "uname -a",
                    "cat /proc/version",
                ]
                platform_patterns = {
                    "OpenBMC": ["OpenBMC"],
                    "iDRAC": ["iDRAC"],
                    "iLO": ["iLO"],
                    "HMC": ["HMC", "hmc"],
                }

            for command in commands:
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, command
                )
                if exit_code == 0 and stdout.strip():
                    # Use YAML-provided patterns to detect platform
                    for platform_type, patterns in platform_patterns.items():
                        for pattern in patterns:
                            if pattern in stdout:
                                return {
                                    "platform_type": platform_type,
                                    "detection_command": command,
                                }

                    # If no specific platform detected, return generic
                    return {
                        "platform_type": "generic",
                        "info": stdout.strip(),
                        "detection_command": command,
                    }

            return {"platform_type": "unknown"}
        except Exception as e:
            logger.error(f"Failed to get platform info: {e}")
            return {"platform_type": "unknown"}
