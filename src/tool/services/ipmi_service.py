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
IPMI Service - Handles all IPMI-related collector operations.

Provides IPMI-based collectors for BMC access including SEL logs, sensor data,
FRU information, and system diagnostics via ipmitool.
"""

import logging
import re
from typing import Any, Dict, List, Tuple, Union

from .base_service import BaseService

logger = logging.getLogger(__name__)


_FRU_BLOCK_RE = re.compile(
    r"(?ms)^FRU Device Description.*?(?=^FRU Device Description|\Z)"
)
_DEVICE_NOT_PRESENT = "Device not present"


def _fru_print_partial_success(stdout: str) -> bool:
    """
    Return True when a non-zero ``ipmitool fru print`` exit was caused solely
    by absent FRU slots, and at least one FRU block was collected successfully.

    ``ipmitool`` exits 1 whenever any FRU reports ``Device not present`` (empty
    slot) even if every populated slot was read successfully. On platforms
    like Umbriel B300 slots 9-15 are empty by design, so the command returns
    1 on every run. This helper lets I4 treat that outcome as success.
    """
    if not stdout or _DEVICE_NOT_PRESENT not in stdout:
        return False
    for block in _FRU_BLOCK_RE.findall(stdout):
        body = block.split("\n", 1)[1] if "\n" in block else ""
        body = body.strip()
        if body and not body.startswith(_DEVICE_NOT_PRESENT):
            return True
    return False


class IPMIService(BaseService):
    """
    Service for IPMI operations.
    """

    def __init__(self, service_name: str, orchestrator: Any) -> None:
        """
        Initialize IPMI service.

        Args:
            service_name: Name of the service.
            orchestrator: Orchestrator instance.
        """
        super().__init__(service_name, orchestrator)

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """
        Validate IPMI connection.

        Args:
            dut_id: DUT ID.
        """
        return await self.dut_manager.get_dut(dut_id).test_ipmi_connection()

    # Validation methods
    async def _validate_bmc_connection(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Validate BMC connection.

        Args:
            dut_id: DUT ID.
        """
        try:
            # Check if IPMI connection state indicates it's already connected
            dut = self.dut_manager.get_dut(dut_id)

            # Check if we're in local mode without BMC IP - if so, skip BMC validation
            if dut.config and dut.config.get("local", False):
                has_bmc_ip = dut.credentials and dut.credentials.bmc_ip
                if not has_bmc_ip:
                    await self._log_runtime(
                        "INFO",
                        "IPMIService",
                        f"DUT {dut_id} is in local mode without BMC IP - skipping BMC validation for local IPMI execution",
                        dut_id,
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=1,
                        total_operations=1,
                        output_files=[],
                        error_messages=[],
                        operation_name="ipmi_validation",
                        additional_context={
                            "reason": "Local mode without BMC IP - BMC validation skipped for local IPMI execution",
                            "bmc_available": False,
                            "local_mode": True,
                        },
                    )

            # First check if we have preflight results
            preflight_results = getattr(dut, "preflight_results", {})

            if preflight_results:
                ipmi_service_result = preflight_results.get("services", {}).get(
                    "ipmi", {}
                )
                if ipmi_service_result:
                    preflight_status = ipmi_service_result.get("status", "unknown")
                    preflight_message = ipmi_service_result.get("message", "")

                    await self._log_runtime(
                        "DEBUG",
                        "IPMIService",
                        f"Found preflight results for IPMI connection: status={preflight_status}, message={preflight_message}",
                        dut_id,
                    )

                    if preflight_status == "pass":
                        await self._log_runtime(
                            "INFO",
                            "IPMIService",
                            "Using preflight results for IPMI validation - connection already verified",
                            dut_id,
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=1,
                            total_operations=1,
                            output_files=[],
                            error_messages=[],
                            operation_name="ipmi_validation",
                            additional_context={
                                "validation_message": f"Preflight verified: {preflight_message}",
                                "bmc_available": True,
                                "preflight_used": True,
                            },
                        )
                    elif preflight_status == "fail":
                        await self._log_runtime(
                            "WARN",
                            "IPMIService",
                            f"Preflight failed for IPMI connection: {preflight_message}",
                            dut_id,
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=1,
                            output_files=[],
                            error_messages=[f"Preflight failed: {preflight_message}"],
                            operation_name="ipmi_validation",
                            additional_context={
                                "validation_message": f"Preflight failed: {preflight_message}",
                                "bmc_available": False,
                                "preflight_used": True,
                            },
                        )

            # No preflight results or unknown status - run connection test
            await self._log_runtime(
                "DEBUG",
                "IPMIService",
                "No preflight results found or unknown status - running IPMI connection test",
                dut_id,
            )

            success, message = await self.validate_connection(dut_id)

            # Log the validation result
            if success:
                await self._log_runtime(
                    "INFO",
                    "IPMIService",
                    f"IPMI connection validation passed: {message}",
                    dut_id,
                )
            else:
                await self._log_runtime(
                    "ERROR",
                    "IPMIService",
                    f"IPMI connection validation failed: {message}",
                    dut_id,
                )

            return await self._create_standardized_collector_result(
                successful_operations=1 if success else 0,
                total_operations=1,
                output_files=[],
                error_messages=[] if success else [message],
                operation_name="ipmi_validation",
                additional_context={
                    "validation_message": message,
                    "bmc_available": success,
                    "preflight_used": False,
                },
            )
        except Exception as e:
            await self._log_runtime(
                "ERROR", "IPMIService", f"IPMI validation exception: {str(e)}", dut_id
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"IPMI validation error: {str(e)}"],
                operation_name="ipmi_validation",
                additional_context={"bmc_available": False},
                dut_id=dut_id,
                collector_id="ipmi_validation",
            )

    # Execution methods
    async def run_ipmi_command(
        self, dut_id: str, command: str, collection_level: str = "L1", **kwargs
    ) -> Dict[str, Any]:
        """
        Run IPMI command with collection level handling.

        Args:
            dut_id: DUT ID.
            command: IPMI command to execute.
            collection_level: Collection level.
        """
        await self._log_runtime(
            "INFO", "IPMIService", f"Executing IPMI command: {command}", dut_id
        )
        try:
            # Start timing for this IPMI command
            if self.timing_manager:
                self.timing_manager.start_request(f"IPMI: {command}")

            # Handle collection level variations if provided
            if "collection_level_handling" in kwargs:
                level_commands = kwargs["collection_level_handling"]
                if collection_level in level_commands:
                    command = level_commands[collection_level]

            exit_code, stdout, stderr = await self.dut_manager.execute_ipmi_command(
                dut_id, command
            )

            # End timing for this IPMI command
            if self.timing_manager:
                self.timing_manager.end_request(f"IPMI: {command}")

            # Log command result using common utility
            await self._log_command_result(
                command,
                exit_code,
                stdout,
                stderr,
                "ipmi",
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
                output_pattern=kwargs.get("filename"),
                function_tag=kwargs.get("function_tag", "ipmi_command"),
            )

            # Check if we should ignore command failures
            ignore_errors = kwargs.get("ignore_errors", False)
            ignore_absent_fru = kwargs.get("ignore_absent_fru", False)
            absent_fru_tolerated = (
                ignore_absent_fru
                and exit_code != 0
                and _fru_print_partial_success(stdout)
            )
            success = exit_code == 0 or ignore_errors or absent_fru_tolerated

            if absent_fru_tolerated:
                await self._log_runtime(
                    "WARN",
                    "IPMIService",
                    f"IPMI command '{command}' exited {exit_code} but stdout "
                    "contained valid FRU data; remaining slots reported "
                    "'Device not present' — treating as partial success",
                    dut_id,
                )

            await self._log_runtime(
                "INFO" if success else "ERROR",
                "IPMIService",
                f"IPMI command completed with exit code {exit_code}: {command} (ignore_errors={ignore_errors})",
                dut_id,
            )

            # Create detailed error log if command failed
            error_log_path = ""
            if not success:
                try:
                    error_context = {
                        "operation_name": "ipmi_command",
                        "error_messages": [
                            f"IPMI command failed with exit code {exit_code}"
                        ],
                        "additional_context": {
                            "command": command,
                            "collection_level": collection_level,
                            "exit_code": exit_code,
                            "stdout": self._process_command_output(stdout),
                            "stderr": self._process_command_output(stderr),
                        },
                    }
                    collector_id = (
                        kwargs.get("collector_id")
                        or self._get_current_collector_id()
                        or "ipmi_command"
                    )
                    error_log_path = await self._log_collector_error(
                        dut_id,
                        collector_id,
                        f"IPMI command failed with exit code {exit_code}",
                        error_context,
                    )
                except Exception as log_error:
                    await self._log_runtime(
                        "ERROR",
                        "IPMIService",
                        f"Failed to create error log: {log_error}",
                        dut_id,
                    )

            return await self._create_standardized_collector_result(
                successful_operations=1 if success else 0,
                total_operations=1,
                output_files=[file_path] if file_path else [],
                error_messages=(
                    []
                    if success
                    else [f"IPMI command failed with exit code {exit_code}"]
                ),
                operation_name="ipmi_command",
                additional_context={
                    "command": command,
                    "collection_level": collection_level,
                    "exit_code": exit_code,
                    "output": self._process_command_output(stdout),
                    "stderr": self._process_command_output(stderr),
                    "error_log_path": error_log_path,
                    "absent_fru_tolerated": absent_fru_tolerated,
                },
            )
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "IPMIService",
                f"IPMI command failed with exception: {str(e)}",
                dut_id,
            )

            # Create detailed error log for exception
            error_log_path = ""
            try:
                error_context = {
                    "operation_name": "ipmi_command",
                    "error_messages": [f"IPMI command failed with exception: {str(e)}"],
                    "additional_context": {
                        "command": command,
                        "collection_level": collection_level,
                        "exception": str(e),
                        "exception_type": type(e).__name__,
                    },
                }
                collector_id = (
                    kwargs.get("collector_id")
                    or self._get_current_collector_id()
                    or "ipmi_command"
                )
                error_log_path = await self._log_collector_error(
                    dut_id,
                    collector_id,
                    f"IPMI command failed with exception: {str(e)}",
                    error_context,
                )
            except Exception as log_error:
                await self._log_runtime(
                    "ERROR",
                    "IPMIService",
                    f"Failed to create error log for exception: {log_error}",
                    dut_id,
                )

            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="ipmi_command",
                additional_context={
                    "command": command,
                    "error_log_path": error_log_path,
                },
                dut_id=dut_id,
                collector_id="ipmi_command",
            )

    async def run_ipmi_command_with_nvbmc_handling(
        self, dut_id: str, command: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Run IPMI command with NVBMC-specific handling (legacy-compatible).

        Args:
            dut_id: DUT ID.
            command: IPMI command to execute.
        """
        try:
            # Run the original command once (like legacy code)
            exit_code, stdout, stderr = await self.dut_manager.execute_ipmi_command(
                dut_id, command
            )

            # Create output file with generalization using common utility
            content = self._create_command_output_content(
                command, exit_code, stdout, stderr
            )
            file_path = await self.write_output_with_generalization(
                dut_id,
                kwargs.get("collector_id", ""),
                content,
                output_pattern=kwargs.get("filename"),
                function_tag=kwargs.get("function_tag", "ipmi_command"),
            )

            # Legacy NVBMC logic: Check for specific patterns that indicate success
            success = exit_code == 0
            normalized_exit_code = exit_code

            # If exit code is non-zero, check for NVBMC-specific success patterns
            if not success and stdout:
                # Check for session info patterns (legacy logic)
                if "session handle" in stdout:
                    success = True
                    normalized_exit_code = (
                        0  # Normalize exit code for downstream compatibility
                    )
                # Check for NVBMC error patterns that should be treated as success
                elif any(
                    pattern in stdout
                    for pattern in [
                        "Invalid completion code received: Invalid command",
                        "Discovered IPMB address 0x0",
                    ]
                ):
                    success = True
                    normalized_exit_code = (
                        0  # Normalize exit code for downstream compatibility
                    )

            return await self._create_standardized_collector_result(
                successful_operations=1 if success else 0,
                total_operations=1,
                output_files=[file_path] if file_path else [],
                error_messages=(
                    []
                    if success
                    else [f"IPMI command failed with exit code {normalized_exit_code}"]
                ),
                operation_name="ipmi_command",
                additional_context={
                    "command": command,
                    "nvbmc_handling": True,
                    "exit_code": normalized_exit_code,
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
                operation_name="ipmi_command",
                additional_context={"command": command},
                dut_id=dut_id,
                collector_id="ipmi_command",
            )

    async def run_ipmi_command_with_file_output(
        self, dut_id: str, command: str, output_file: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Run IPMI command with specific file output.

        Args:
            dut_id: DUT ID.
            command: IPMI command to execute.
            output_file: Output file.
        """
        try:
            exit_code, stdout, stderr = await self.dut_manager.execute_ipmi_command(
                dut_id, command
            )

            # Create output file with generalization using common utility
            content = self._create_command_output_content(
                command, exit_code, stdout, stderr
            )
            file_path = await self.write_output_with_generalization(
                dut_id,
                kwargs.get("collector_id", ""),
                content,
                output_pattern=kwargs.get("filename"),
                function_tag=kwargs.get("function_tag", "ipmi_command"),
            )

            # Check if we should ignore command failures
            ignore_errors = kwargs.get("ignore_errors", False)
            success = exit_code == 0 or ignore_errors

            return await self._create_standardized_collector_result(
                successful_operations=1 if success else 0,
                total_operations=1,
                output_files=[file_path] if file_path else [],
                error_messages=(
                    []
                    if success
                    else [f"IPMI command failed with exit code {exit_code}"]
                ),
                operation_name="ipmi_command",
                additional_context={
                    "command": command,
                    "output_file": output_file,
                    "ignore_errors": ignore_errors,
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
                operation_name="ipmi_command",
                additional_context={"command": command},
                dut_id=dut_id,
                collector_id="ipmi_command",
            )

    async def run_ipmi_commands(
        self,
        dut_id: str,
        commands: List[Union[str, Dict[str, Any]]],
        collection_level: str = "L1",
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run multiple IPMI commands with collection level handling.

        Args:
            dut_id: DUT ID.
            commands: List of IPMI commands to execute.
            collection_level: Collection level.
        """
        try:
            results = []
            output_files = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            for i, command_item in enumerate(commands):
                total_operations += 1
                # Handle both string commands and command dictionaries
                if isinstance(command_item, str):
                    command = command_item
                    file_name = f"ipmi_command_{i+1}.txt"
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

                    file_name = command_item.get("file_name", f"ipmi_command_{i+1}.txt")
                    timeout = command_item.get(
                        "timeout",
                        await self._get_collector_timeout(
                            kwargs.get("collector_id", ""), dut_id, 300
                        ),
                    )
                    ignore_errors = command_item.get("ignore_errors", False)

                exit_code, stdout, stderr = await self.dut_manager.execute_ipmi_command(
                    dut_id, command, timeout
                )

                # Create output file with generalization using common utility
                content = self._create_command_output_content(
                    command, exit_code, stdout, stderr
                )
                file_path = await self.write_output_with_generalization(
                    dut_id,
                    kwargs.get("collector_id", ""),
                    content,
                    output_pattern=kwargs.get("filename"),
                    function_tag=file_name,
                    substitutions={"command_name": file_name},
                )
                output_files.append(file_path)

                command_success = exit_code == 0
                if command_success:
                    successful_operations += 1
                else:
                    error_messages.append(
                        f"IPMI command failed: {command} (exit_code: {exit_code})"
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
                        operation_name="ipmi_commands",
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
                operation_name="ipmi_commands",
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
                error_messages=[f"Exception in IPMI commands: {str(e)}"],
                operation_name="ipmi_commands",
                additional_context={"commands": commands},
                dut_id=dut_id,
                collector_id="ipmi_commands",
            )
