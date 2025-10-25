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
Async-safe logging system for the NVDebug Tool.

Provides thread-safe and async-safe logging with support for structured logs,
progress tracking, and detailed debug information for concurrent operations.
"""

import asyncio
import contextvars
import json
import logging
import os
import re
import sys
import fcntl
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Context variable for async-safe collector ID tracking
# This allows each async task to maintain its own collector_id without interference
_collector_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "collector_context", default=None
)

from ..utils.constants import ASCII_HEADER
from ..utils.enums import (
    CollectorServiceMapping,
    PreflightChecks,
    get_main_preflight_names,
)
from ..utils.json_utils import safe_json_dump, safe_json_dumps

logger = logging.getLogger(__name__)


class StreamToLogger:
    """
    Redirect stdout/stderr to logger and console with progress bar filtering.

    Args:
        logger: Logger instance
        level: Logging level
        original_stream: Original stream to redirect to
    """

    def __init__(self, logger, level, original_stream=None):
        """
        Initialize the StreamToLogger.

        Args:
            logger: Logger instance
            level: Logging level
            original_stream: Original stream to redirect to
        """
        self.logger = logger
        self.level = level
        self.original_stream = original_stream
        self.line_buffer = ""
        self.last_progress_line = ""

    def _is_progress_bar_line(self, line):
        """
        Check if a line is a progress bar update.

        Args:
            line: Line to check
        """
        # Progress bar indicators
        progress_indicators = [
            "⠋",
            "⠙",
            "⠹",
            "⠸",
            "⠼",
            "⠴",
            "⠦",
            "⠧",
            "⠇",
            "⠏",
            "━",
            "╺",
            "╸",
        ]

        # Check for progress bar patterns
        has_spinner = any(indicator in line for indicator in progress_indicators)
        has_percentage = "%" in line
        has_progress_chars = "━" in line or "╺" in line or "╸" in line
        has_time_remaining = "0:00:" in line

        # If it looks like a progress bar, filter it
        return has_spinner and (
            has_percentage or has_progress_chars or has_time_remaining
        )

    def write(self, message):
        """
        Write message to logger, filtering progress bars.

        Args:
            message: Message to write.
        """
        if message and not message.isspace():
            self.line_buffer += message
            if self.line_buffer.endswith("\n"):
                line = self.line_buffer.rstrip()

                # Check if this is a progress bar line
                if self._is_progress_bar_line(line):
                    # Only log the first occurrence of a progress bar line
                    if line != self.last_progress_line:
                        # Log progress start as a structured event
                        if "Preflight" in line:
                            self.logger.log(
                                self.level,
                                f"PROGRESS: {line.split(' - ')[0] if ' - ' in line else line}",
                            )
                        elif "Parallel Collectors" in line or "redfish:" in line:
                            self.logger.log(self.level, f"PROGRESS: {line}")
                        self.last_progress_line = line
                else:
                    # Regular line - log normally
                    self.logger.log(self.level, line)
                    self.last_progress_line = ""  # Reset progress tracking

                # Always write to original console
                if self.original_stream:
                    self.original_stream.write(self.line_buffer)
                    self.original_stream.flush()
                self.line_buffer = ""

    def flush(self):
        """
        Flush any buffered content to the logger.
        """
        if self.line_buffer:
            line = self.line_buffer.rstrip()

            # Check if this is a progress bar line
            if not self._is_progress_bar_line(line):
                # Only log non-progress lines
                self.logger.log(self.level, line)

            # Always write to original console
            if self.original_stream:
                self.original_stream.write(self.line_buffer)
                self.original_stream.flush()
            self.line_buffer = ""


class AsyncSafeLogger:
    """
    Async-safe logging system with structured output.

    Provides thread-safe and async-safe logging with support for DUT-specific logs,
    structured metadata, collector tracking, and stdout/stderr capture.

    Attributes:
        base_log_dir: Base directory for all logs.
        orchestrator: Workflow orchestrator instance.
        sanitizer: Log sanitizer for sensitive data.
        debug_mode: Whether debug mode is enabled.
        verbose_mode: Whether verbose mode is enabled.
    """

    def __init__(
        self,
        base_log_dir: str,
        orchestrator=None,
        sanitizer=None,
        debug_mode: bool = False,
        verbose_mode: bool = False,
    ) -> None:
        self.base_log_dir = Path(base_log_dir)
        self.base_log_dir.mkdir(parents=True, exist_ok=True)
        self.orchestrator = orchestrator
        self.debug_mode = debug_mode
        self.verbose_mode = verbose_mode

        # Runtime log file
        self.runtime_file_handle: Optional[Any] = None
        self.runtime_lock = asyncio.Lock()

        # Error log file
        self.error_file_handle: Optional[Any] = None
        self.error_lock = asyncio.Lock()

        # Metadata directory
        self.metadata_dir = self.base_log_dir / ".metadata"
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

        # DUT-specific log directories
        self.dut_log_dirs: Dict[str, Path] = {}
        self.dut_runtime_files: Dict[str, Any] = {}  # Added for per-DUT runtime logs
        self.dut_runtime_lock = (
            asyncio.Lock()
        )  # Lock for DUT runtime log synchronization

        # Tracking dictionaries
        self.collector_results: Dict[str, Any] = {}
        self.preflight_results: Dict[str, Any] = {}
        self.execution_summary: Dict[str, Union[List[Any], int, None]] = {
            "total_collectors": 0,
            "successful_collectors": 0,
            "failed_collectors": 0,
            "partial_collectors": 0,
            "skipped_collectors": 0,
        }

        # Collector status tracking
        self.collector_status: Dict[str, Dict[str, Any]] = {}

        # Original stdout/stderr for restoration
        self.original_stdout = None
        self.original_stderr = None
        self.stdout_logger = None
        self.stderr_logger = None

        # Sanitizer for sensitive data
        self.sanitizer = sanitizer

        # Per-file asyncio locks for metadata writes
        self._metadata_file_locks: Dict[str, asyncio.Lock] = {}

    async def start(self) -> None:
        """
        Start the logging system and capture stdout/stderr.

        Initializes log files, writes headers, and sets up stream capture.
        """
        async with self.runtime_lock:
            if self.runtime_file_handle is None:
                # Create runtime log file with new name
                runtime_file = self.base_log_dir / ".nvdebug_stdout.log"
                self.runtime_file_handle = open(runtime_file, "w")

                # Create error log file
                error_file = self.base_log_dir / "error.log"
                self.error_file_handle = open(error_file, "w")

                # Write ASCII header first (before stream capture)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                header_lines = [
                    ASCII_HEADER,
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] {'=' * 80}",
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] NVDebug Tool - Runtime Log",
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] Started at: {datetime.now().isoformat()}",
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] {'=' * 80}",
                ]

                for line in header_lines:
                    self.runtime_file_handle.write(line + "\n")
                self.runtime_file_handle.flush()

                # Setup stdout/stderr capture after writing header
                await self._setup_stream_capture()

    async def _setup_stream_capture(self) -> None:
        """
        Setup stdout/stderr capture.

        Configures logging handlers and redirects stdout/stderr to log files.
        """
        # Create loggers for stdout/stderr
        stdout_logger = logging.getLogger("stdout")
        stderr_logger = logging.getLogger("stderr")

        # Create handlers that write to our runtime log
        stdout_handler = logging.StreamHandler(self.runtime_file_handle)
        stderr_handler = logging.StreamHandler(self.runtime_file_handle)

        # Set formatters
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
        )
        stdout_handler.setFormatter(formatter)
        stderr_handler.setFormatter(formatter)

        # Setup loggers
        stdout_logger.addHandler(stdout_handler)
        stderr_logger.addHandler(stderr_handler)
        stdout_logger.setLevel(logging.INFO)
        stderr_logger.setLevel(logging.ERROR)

        # Store original streams
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr

        # Create stream redirectors with original streams
        self.stdout_logger = StreamToLogger(
            stdout_logger, logging.INFO, self.original_stdout
        )
        self.stderr_logger = StreamToLogger(
            stderr_logger, logging.ERROR, self.original_stderr
        )

        # Redirect streams
        sys.stdout = self.stdout_logger
        sys.stderr = self.stderr_logger

    async def stop(self) -> None:
        """
        Stop the logging system and restore stdout/stderr.

        Closes all log files, restores streams, and writes footers.
        """
        async with self.runtime_lock:
            # Close per-DUT runtime files
            for dut_id, dut_runtime_handle in self.dut_runtime_files.items():
                try:
                    # Check if "Completed at:" timestamp was already written
                    # (to avoid duplicates when cleanup writes timestamps early)
                    log_path = self.log_dir / dut_id / "nvdebug_runtime_output.txt"
                    timestamp_already_written = False
                    if log_path.exists():
                        try:
                            with open(log_path, "r", encoding="utf-8") as f:
                                content = f.read()
                                if "Completed at:" in content:
                                    timestamp_already_written = True
                        except Exception:
                            pass

                    # Only write footer if not already written
                    if not timestamp_already_written:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                        footer_lines = [
                            f"[{timestamp}] [INFO] [DUT:{dut_id}] {'=' * 80}",
                            f"[{timestamp}] [INFO] [DUT:{dut_id}] DUT Runtime Log - {dut_id} - Completed",
                            f"[{timestamp}] [INFO] [DUT:{dut_id}] Completed at: {datetime.now().isoformat()}",
                            f"[{timestamp}] [INFO] [DUT:{dut_id}] {'=' * 80}",
                        ]

                        for line in footer_lines:
                            dut_runtime_handle.write(line + "\n")
                        dut_runtime_handle.flush()

                    # Always close the file
                    dut_runtime_handle.close()
                except Exception as e:
                    # Log error but continue with other cleanup
                    pass

            # Restore original streams
            if self.original_stdout:
                sys.stdout = self.original_stdout
            if self.original_stderr:
                sys.stderr = self.original_stderr

            # Flush and close loggers
            if self.stdout_logger:
                self.stdout_logger.flush()
            if self.stderr_logger:
                self.stderr_logger.flush()

            # Write footer (directly since we already have the lock)
            if (
                self.runtime_file_handle is not None
                and not self.runtime_file_handle.closed
            ):
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                footer_lines = [
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] {'=' * 80}",
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] Completed at: {datetime.now().isoformat()}",
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] {'=' * 80}",
                ]
                for line in footer_lines:
                    self.runtime_file_handle.write(line + "\n")
                self.runtime_file_handle.flush()

            # Close file handles
            if (
                self.runtime_file_handle is not None
                and not self.runtime_file_handle.closed
            ):
                self.runtime_file_handle.close()
                self.runtime_file_handle = None

            if self.error_file_handle is not None and not self.error_file_handle.closed:
                self.error_file_handle.close()
                self.error_file_handle = None

    async def write_dut_metadata(self, dut_id: str, metadata: Dict[str, Any]) -> None:
        """
        Write simple DUT-level metadata.json under each DUT's .metadata directory.

        Args:
            dut_id: DUT ID.
            metadata: Metadata dictionary to write.
        """
        try:
            # Ensure per-DUT metadata directory
            dut_dir = self.base_log_dir / dut_id / ".metadata"
            dut_dir.mkdir(parents=True, exist_ok=True)
            metadata_file = dut_dir / "metadata.json"

            # Load existing metadata if file exists
            existing_payload = {}
            if metadata_file.exists():
                try:
                    with open(metadata_file, "r", encoding="utf-8") as f:
                        existing_data = json.load(f)
                        existing_payload = existing_data.get("payload", {})
                except Exception:
                    # If file is corrupted, start fresh
                    existing_payload = {}

            # Merge new metadata with existing metadata
            merged_payload = {**existing_payload, **metadata}

            # Wrap payload with minimal envelope for compatibility
            payload = {
                "metadata": {
                    "created_at": datetime.now().isoformat() + "Z",
                    "last_updated": datetime.now().isoformat() + "Z",
                },
                "payload": merged_payload,
            }

            # Write file
            with open(metadata_file, "w", encoding="utf-8") as f:
                safe_json_dump(payload, f, indent=4)
        except Exception as e:
            # Best-effort: log error to runtime
            try:
                await self.write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "AsyncSafeLogger",
                    f"Failed to write DUT metadata for {dut_id}: {e}",
                )
            except Exception:
                pass

    async def log_collector_output(
        self, collector_id: str, dut_id: str, content: str
    ) -> None:
        """
        Log collector output to a collector-specific file.

        Args:
            collector_id: Collector ID.
            dut_id: DUT ID.
            content: Content to log.
        """
        try:
            # Create collector log file
            file_path = await self.create_collector_log_file(
                dut_id,
                self._get_collector_group(collector_id),
                collector_id,
                "output.log",
            )

            # Write content
            async with asyncio.Lock():
                with open(file_path, "a") as f:
                    f.write(f"{content}\n")
        except Exception as e:
            # Best-effort: log error to runtime
            try:
                await self.write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "AsyncSafeLogger",
                    f"Failed to log collector output for {collector_id} on {dut_id}: {e}",
                )
            except Exception:
                pass

    async def write_collector_status_file(
        self, collector_id: str, dut_id: str, status: str, reason: str
    ) -> None:
        """
        Write collector status to a structured status.json file with comprehensive details.

        Args:
            collector_id: Collector ID.
            dut_id: DUT ID.
            status: Status string.
            reason: Reason for the status.
        """
        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncSafeLogger",
            f"write_collector_status_file called for {collector_id} on {dut_id} with status {status}",
        )

        try:
            # Get collector info for command details
            collector_info = None
            command_info = {}
            if hasattr(self, "orchestrator") and self.orchestrator:
                collector_info = self.orchestrator.get_collector_info(collector_id)

                # Extract command information from collector definition
                if collector_info and "stages" in collector_info:
                    execution_stage = collector_info.get("stages", {}).get(
                        "execution", {}
                    )
                    if "hooks" in execution_stage:
                        for hook in execution_stage["hooks"]:
                            if "method" in hook:
                                command_info["method"] = hook["method"]
                            if "params" in hook:
                                # Clean up params to avoid circular references and verbose output
                                params = hook["params"]
                                if isinstance(params, dict):
                                    # Keep only essential params, remove circular references
                                    clean_params = {}
                                    for key, value in params.items():
                                        if key in [
                                            "uri",
                                            "command",
                                            "function_tag",
                                            "collection_name",
                                            "error_message",
                                        ]:
                                            clean_params[key] = value
                                        elif key == "output_pattern":
                                            command_info["output_file"] = value
                                    command_info["params"] = clean_params
                                else:
                                    command_info["params"] = {}
                            if "output_pattern" in hook:
                                command_info["output_file"] = hook["output_pattern"]
                            break

            # Get output files from stored collector results
            output_files = []
            result_key = f"{dut_id}:{collector_id}"
            if result_key in self.collector_results:
                output_files = self.collector_results[result_key].get(
                    "output_files", []
                )
                # Remove duplicates while preserving order
                seen = set()
                unique_output_files = []
                for file_path in output_files:
                    if file_path not in seen:
                        seen.add(file_path)
                        unique_output_files.append(file_path)
                output_files = unique_output_files

            # Get detailed collector result information
            result_key = f"{dut_id}:{collector_id}"
            collector_result = self.collector_results.get(result_key, {})

            # Debug logging to see what context information we have
            await self.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AsyncLogger",
                f"Collector result for {collector_id}: {collector_result}",
            )

            # Extract detailed information from collector result
            successful_operations = collector_result.get("context", {}).get(
                "successful_operations", 0
            )
            total_operations = collector_result.get("context", {}).get(
                "total_operations", 0
            )
            error_messages = collector_result.get("context", {}).get(
                "error_messages", []
            )
            execution_time = collector_result.get("execution_time", None)

            # Debug logging to see what we extracted
            await self.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AsyncLogger",
                f"Extracted context for {collector_id}: successful_operations={successful_operations}, total_operations={total_operations}, error_messages={error_messages}",
            )

            # Use detailed reason from collector result if available, otherwise use the passed reason
            detailed_reason = collector_result.get("reason", reason)
            if detailed_reason and detailed_reason != "Completed successfully":
                final_reason = detailed_reason
            else:
                final_reason = reason

            # Create comprehensive status.json structure
            status_data = {
                "collector_id": collector_id,
                "collector_name": (
                    collector_info.get("name", collector_id)
                    if collector_info
                    else collector_id
                ),
                "dut_id": dut_id,
                "timestamp": datetime.now().isoformat(),
                "status": status,
                "reason": final_reason,
                "execution_summary": {
                    "successful_operations": successful_operations,
                    "total_operations": total_operations,
                    "success_rate": (
                        f"{successful_operations}/{total_operations}"
                        if total_operations > 0
                        else "0/0"
                    ),
                    "error_count": len(error_messages),
                    "execution_time_seconds": execution_time,
                },
                "error_details": error_messages if error_messages else [],
                "stages": {},
                "output_files": output_files,
                "collector_group": self._get_collector_group(collector_id),
                "collection_level": (
                    collector_info.get("collection_level", "unknown")
                    if collector_info
                    else "unknown"
                ),
            }

            # Extract all stages and their commands from collector definition
            if collector_info and "stages" in collector_info:
                for stage_name, stage_data in collector_info["stages"].items():
                    stage_commands = []
                    if "hooks" in stage_data:
                        for hook in stage_data["hooks"]:
                            # Clean up params to avoid circular references and verbose output
                            params = hook.get("params", {})
                            if isinstance(params, dict):
                                clean_params = {}
                                for key, value in params.items():
                                    if key in [
                                        "uri",
                                        "command",
                                        "function_tag",
                                        "collection_name",
                                        "error_message",
                                        "skip_message",
                                    ]:
                                        clean_params[key] = value
                            else:
                                clean_params = {}

                            command_info = {
                                "method": hook.get("method", ""),
                                "params": clean_params,
                                "required": hook.get("required", False),
                            }
                            if "output_pattern" in hook:
                                command_info["output_file"] = hook["output_pattern"]
                            stage_commands.append(command_info)

                    # Determine stage status based on overall collector status and stage type
                    stage_status = "executed"
                    if status == "error":
                        stage_status = "failed"
                    elif status == "partial":
                        # For partial results, determine stage status based on stage importance
                        if stage_name == "execution":
                            stage_status = (
                                "partial"  # Main execution stage had partial success
                            )
                        elif stage_name in ["validation", "preflight"]:
                            stage_status = "failed"  # Validation/preflight failures cause partial results
                        else:
                            stage_status = "executed"  # Other stages may have succeeded
                    elif status == "skipped":
                        stage_status = "skipped"

                    status_data["stages"][stage_name] = {
                        "commands": stage_commands,
                        "status": stage_status,
                        "command_count": len(stage_commands),
                        "required_commands": len(
                            [
                                cmd
                                for cmd in stage_commands
                                if cmd.get("required", False)
                            ]
                        ),
                    }

            # Create collector directory and status.json file
            group = self._get_collector_group(collector_id)
            collector_name = (
                collector_info.get("name", collector_id)
                if collector_info
                else collector_id
            )
            service_prefix = group.capitalize()
            collector_dir = (
                self.base_log_dir
                / dut_id
                / group
                / f"{service_prefix}_{collector_id}_{collector_name}"
            )
            collector_dir.mkdir(parents=True, exist_ok=True)

            status_file = collector_dir / "status.json"

            # Write status.json
            async with asyncio.Lock():
                with open(status_file, "w") as f:
                    safe_json_dump(status_data, f, indent=2)

        except Exception as e:
            # Best-effort: log error to runtime
            try:
                await self.write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "AsyncSafeLogger",
                    f"Failed to write collector status file for {collector_id} on {dut_id}: {e}",
                )
            except Exception:
                pass

    async def _print_to_console(self, level: str, component: str, message: str) -> None:
        """
        Print log message to console using Rich console (compatible with progress bars).

        Args:
            level: Logging level
            component: Component name
            message: Message to print
        """
        try:
            # Use the orchestrator's console if available, otherwise create a new one
            if self.orchestrator and hasattr(self.orchestrator, "console"):
                console = self.orchestrator.console
            else:
                from rich.console import Console

                console = Console()

            # Choose color based on log level
            if level.upper() == "ERROR":
                style = "bold red"
            elif level.upper() == "WARNING":
                style = "bold yellow"
            elif level.upper() == "INFO":
                style = "bold blue"
            elif level.upper() == "DEBUG":
                style = "dim white"
            else:
                style = ""

            # Format the message
            timestamp = datetime.now().strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] [{level}] [{component}] {message}"

            # Print to console (this works with Rich progress bars)
            console.print(formatted_message, style=style)

        except Exception:
            # Fallback to print if Rich console fails
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [{level}] [{component}] {message}")

    async def log_runtime(self, level: str, component: str, message: str) -> None:
        """
        Log runtime messages.

        Args:
            level: Logging level
            component: Component name
            message: Message to log
        """
        # Skip DEBUG level messages if debug mode is not enabled
        if level.upper() == "DEBUG" and not self.debug_mode:
            return

        # Print to console based on log level and mode
        if level.upper() == "INFO" and self.verbose_mode:
            # INFO messages only when verbose mode is enabled
            await self._print_to_console(level, component, message)
        elif level.upper() == "DEBUG" and self.verbose_mode and self.debug_mode:
            # DEBUG messages only when BOTH verbose AND debug mode are enabled
            await self._print_to_console(level, component, message)
        elif level.upper() in ["WARNING", "ERROR"] and self.verbose_mode:
            # WARNING and ERROR messages only when verbose mode is enabled
            await self._print_to_console(level, component, message)

        # Sanitize message if sanitizer is available
        if self.sanitizer:
            message = self.sanitizer.sanitize(message)

        async with self.runtime_lock:
            # Always write to global runtime log
            if (
                self.runtime_file_handle is not None
                and not self.runtime_file_handle.closed
            ):
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                log_entry = f"[{timestamp}] [{level}] [{component}] {message}\n"
                self.runtime_file_handle.write(log_entry)
                self.runtime_file_handle.flush()

            # If this is a DUT-specific message, also write to DUT runtime log
            if component.startswith("DUT:"):
                dut_id = component[4:]  # Remove "DUT:" prefix
                if dut_id in self.dut_runtime_files:
                    dut_runtime_handle = self.dut_runtime_files[dut_id]
                    if not dut_runtime_handle.closed:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                        log_entry = f"[{timestamp}] [{level}] [{component}] {message}\n"
                        dut_runtime_handle.write(log_entry)
                        dut_runtime_handle.flush()

    async def log_error(
        self,
        error_type: str,
        error_message: str,
        dut_id: Optional[str] = None,
        collector_id: Optional[str] = None,
    ) -> None:
        """
        Log error messages to both runtime and error logs.

        Args:
            error_type: Error type
            error_message: Error message
            dut_id: DUT ID
            collector_id: Collector ID
        """
        # Sanitize error message if sanitizer is available
        if self.sanitizer:
            error_message = self.sanitizer.sanitize(error_message)

        component = (
            f"{dut_id}:{collector_id}" if dut_id and collector_id else error_type
        )

        if dut_id and dut_id != "unknown":
            # Log to runtime log
            await self.write_to_dut_runtime_log(
                dut_id, "ERROR", component, error_message
            )
        else:
            await self.log_runtime("ERROR", component, error_message)

        # Log to error log
        async with self.error_lock:
            if self.error_file_handle is not None and not self.error_file_handle.closed:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                error_entry = f"[{timestamp}] [{component}] {error_message}\n"
                self.error_file_handle.write(error_entry)
                self.error_file_handle.flush()

    async def setup_dut_logging(self, dut_id: str) -> None:
        """
        Setup logging for a specific DUT.

        Args:
            dut_id: DUT ID
        """
        try:
            dut_log_dir = self.base_log_dir / dut_id
            dut_log_dir.mkdir(parents=True, exist_ok=True)

            # Create subdirectories
            for subdir in ["redfish", "ipmi", "host", "ssh", "error-logs"]:
                (dut_log_dir / subdir).mkdir(exist_ok=True)

            # Create per-DUT runtime log file
            dut_runtime_file = dut_log_dir / "nvdebug_runtime_output.txt"

            # Write header first (create/truncate file)
            with open(dut_runtime_file, "w") as header_handle:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                header_lines = [
                    ASCII_HEADER,
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] {'=' * 80}",
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] DUT Runtime Log - {dut_id}",
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] Started at: {datetime.now().isoformat()}",
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] {'=' * 80}",
                ]

                for line in header_lines:
                    header_handle.write(line + "\n")
                header_handle.flush()

            # Now open in append mode for subsequent writes
            dut_runtime_handle = open(dut_runtime_file, "a")

            self.dut_log_dirs[dut_id] = dut_log_dir
            self.dut_runtime_files[dut_id] = dut_runtime_handle

            # Create .metadata directory and initialize metadata files
            metadata_dir = dut_log_dir / ".metadata"
            metadata_dir.mkdir(exist_ok=True)
            await self._initialize_metadata_files(dut_id)

            await self.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "AsyncSafeLogger",
                f"Logging directory created: {dut_log_dir}",
            )
        except Exception as e:
            await self.log_error(
                "LOGGING_ERROR",
                f"Error setting up DUT logging for {dut_id}: {e}",
            )

    def get_dut_log_dir(self, dut_id: str) -> Path:
        """
        Get the log directory for a specific DUT.

        Args:
            dut_id: DUT ID
        """
        return self.base_log_dir / dut_id

    def get_dut_metadata_dir(self, dut_id: str) -> Path:
        """
        Get the metadata directory for a specific DUT.

        Args:
            dut_id: DUT ID
        """
        if dut_id not in self.dut_log_dirs:
            # Create DUT log directory if it doesn't exist
            dut_log_dir = self.base_log_dir / dut_id
            dut_log_dir.mkdir(parents=True, exist_ok=True)
            self.dut_log_dirs[dut_id] = dut_log_dir

        dut_log_dir = self.dut_log_dirs[dut_id]
        metadata_dir = dut_log_dir / ".metadata"
        metadata_dir.mkdir(parents=True, exist_ok=True)
        return metadata_dir

    def _get_lock_for_path(self, path: Path) -> asyncio.Lock:
        """
        Get or create a shared asyncio lock for a given file path.

        Args:
            path: The file path for which to retrieve a lock.

        Returns:
            An asyncio.Lock instance unique to the file path.
        """
        key = str(path)
        lock = self._metadata_file_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._metadata_file_locks[key] = lock
        return lock

    async def _log_simple(self, level: str, message: str, dut_id: Optional[str] = None) -> None:
        """
        Log a message to DUT runtime log if dut_id is provided, otherwise to global runtime.

        Args:
            level: Logging level (DEBUG, INFO, WARN, ERROR)
            message: Message string
            dut_id: Optional DUT identifier
        """
        try:
            if dut_id:
                await self.write_to_dut_runtime_log(dut_id, level, "AsyncLogger", message)
            else:
                await self.log_runtime(level, "AsyncLogger", message)
        except Exception:
            # Best-effort logging only
            pass

    def _merge_dependency_metadata(
        self,
        existing_data: Dict[str, Any],
        incoming_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Merge incoming dependency metadata into existing data and recompute summary.

        Args:
            existing_data: Existing metadata dict (may be empty or partial)
            incoming_data: Newly generated metadata dict

        Returns:
            Merged metadata dict with updated summary
        """
        if not isinstance(existing_data, dict):
            existing_data = {}

        # Ensure required top-level structures exist
        existing_data.setdefault("metadata", {})
        existing_data.setdefault("collectors", {})
        existing_data.setdefault(
            "status_fields", incoming_data.get("status_fields", {})
        )

        # Merge collectors (new data overwrites same collector id)
        existing_data["collectors"].update(incoming_data.get("collectors", {}))

        # Preserve or set created_at
        created_at = (
            existing_data["metadata"].get("created_at")
            or incoming_data.get("metadata", {}).get("created_at")
            or datetime.now().isoformat() + "Z"
        )
        existing_data["metadata"]["created_at"] = created_at
        # Always update last_updated to now
        existing_data["metadata"]["last_updated"] = datetime.now().isoformat() + "Z"

        # Recalculate summary
        summary = {
            "total_checks": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "not_applicable": 0,
            "required_failed": 0,
            "optional_failed": 0,
        }
        for coll_data in existing_data.get("collectors", {}).values():
            for dep in coll_data.get("dependencies", []):
                status_val = dep.get("status", "skipped")
                summary["total_checks"] += 1
                summary[status_val] = summary.get(status_val, 0) + 1
                if status_val == "failed":
                    if dep.get("required"):
                        summary["required_failed"] += 1
                    else:
                        summary["optional_failed"] += 1
        existing_data["summary"] = summary

        return existing_data

    def _get_current_collector_id_from_orchestrator(self) -> str:
        """
        Get the current collector ID from orchestrator context if available

        Priority order (highest to lowest):
        1. Context variable (async-safe, per-task)
        2. Orchestrator current_collector_id (global, subject to races)
        3. Orchestrator execution context (global, subject to races)

        Args:
            None
        """
        try:
            # First, try to get from context variable (async-safe)
            context_collector_id = _collector_context.get()
            if context_collector_id:
                return context_collector_id

            # Fallback to orchestrator (may have race conditions in concurrent execution)
            if hasattr(self, "orchestrator") and self.orchestrator:
                # Check if orchestrator has current collector context
                if (
                    hasattr(self.orchestrator, "current_collector_id")
                    and self.orchestrator.current_collector_id
                ):
                    return self.orchestrator.current_collector_id

                # Check if orchestrator has current execution context
                if (
                    hasattr(self.orchestrator, "current_execution_context")
                    and self.orchestrator.current_execution_context
                ):
                    return self.orchestrator.current_execution_context.get(
                        "collector_id", "unknown"
                    )
        except Exception:
            pass

        return "unknown"

    def _validate_cid_context_consistency(
        self, collector_id: str, component: str, message: str
    ) -> None:
        """
        Validate that CID context is consistent with the actual operation being performed

        This validation checks for cross-contamination but filters out false positives caused
        by legitimate async concurrency where the global collector_id context may change
        between when a file operation starts and when it logs completion.

        Args:
            collector_id: Collector ID
            component: Component name
            message: Message to validate
        """
        try:
            # Check for potential cross-contamination indicators
            if "Starting collector" in message and "R" in collector_id:
                # Extract the target collector ID from the message
                match = re.search(r"Starting collector ([A-Z]\d+)", message)
                if match:
                    target_collector_id = match.group(1)
                    if target_collector_id != collector_id:
                        # Log a warning about potential cross-contamination
                        print(
                            f"WARNING: CID context mismatch detected - logging as {collector_id} but starting {target_collector_id}"
                        )

            # Check for file path mismatches - but be smart about async concurrency
            if "Saved" in message:
                # Extract collector ID from file path (supports multiple path patterns)
                file_collector_id = None
                group_prefix = None

                # Try Redfish pattern
                match = re.search(r"redfish/Redfish_([A-Z]\d+)_", message)
                if match:
                    file_collector_id = match.group(1)
                    group_prefix = "R"

                # Try SSH pattern
                if not file_collector_id:
                    match = re.search(r"ssh/Ssh_([A-Z]\d+)_", message)
                    if match:
                        file_collector_id = match.group(1)
                        group_prefix = "S"

                # Try Host pattern
                if not file_collector_id:
                    match = re.search(r"host/Host_([A-Z]\d+)_", message)
                    if match:
                        file_collector_id = match.group(1)
                        group_prefix = "H"

                # Try IPMI pattern
                if not file_collector_id:
                    match = re.search(r"ipmi/Ipmi_([A-Z]\d+)_", message)
                    if match:
                        file_collector_id = match.group(1)
                        group_prefix = "I"

                if file_collector_id and file_collector_id != collector_id:
                    # Check if this is a cross-group mismatch (e.g., SSH logging to Redfish directory)
                    # This would be a REAL bug, not just async context switching
                    collector_group_prefix = collector_id[0] if collector_id else None

                    if (
                        collector_group_prefix
                        and group_prefix
                        and collector_group_prefix != group_prefix
                    ):
                        pass
                        # False positives are being printed. Disabling for now.
                        # REAL CROSS-CONTAMINATION: Different collector groups!
                        # Example: S5 (SSH) saving files to redfish/ directory
                        # print(
                        #     f"ERROR: Cross-group file contamination detected - {collector_id} ({collector_group_prefix}-group) "
                        #     f"saving to {file_collector_id} ({group_prefix}-group) directory!"
                        # )
                    # else: Same group, different collector ID - likely async race condition, ignore

        except Exception:
            # Don't let validation break logging
            pass

    async def write_to_dut_runtime_log(
        self,
        dut_id: str,
        level: str,
        component: str,
        message: str,
        collector_id: str = None,
    ) -> None:
        """
        Write to DUT-specific runtime log file with automatic collector ID detection.

        Args:
            dut_id: DUT ID
            level: Logging level
            component: Component name
            message: Message to write
            collector_id: Collector ID
        """
        # Skip DEBUG level messages if debug mode is not enabled
        if level.upper() == "DEBUG" and not self.debug_mode:
            return

        # Setup logging outside the lock to avoid deadlock
        if dut_id not in self.dut_runtime_files:
            await self.setup_dut_logging(dut_id)

        async with self.dut_runtime_lock:
            dut_runtime_handle = self.dut_runtime_files[dut_id]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            # Auto-detect collector_id if not provided
            if collector_id is None:
                collector_id = self._get_current_collector_id_from_orchestrator()

            # Validate CID context consistency (debug mode only to avoid performance impact)
            # Now uses context variables for async-safe tracking, reducing false positives
            if self.debug_mode and collector_id and collector_id != "unknown":
                self._validate_cid_context_consistency(collector_id, component, message)

            # DEBUG: Log CID context for debugging (DISABLED - causes massive performance impact)
            # if self.debug_mode:
            #     asyncio.create_task(
            #         self.log_runtime(
            #             "DEBUG",
            #             "AsyncSafeLogger",
            #             f"Logging with CID: {collector_id}, component: {component}",
            #         )
            #     )

            # Format: [timestamp] [level] [CID:xxx] [component] message
            if collector_id and collector_id != "unknown":
                log_entry = f"[{timestamp}] [{level}] [CID:{collector_id}] [{component}] {message}\n"
            else:
                log_entry = f"[{timestamp}] [{level}] [{component}] {message}\n"

            try:
                # Write log entry directly (no need to seek to end of file)
                dut_runtime_handle.write(log_entry)
                dut_runtime_handle.flush()
            except Exception as e:
                await self.log_error(
                    "LOGGING_ERROR",
                    f"Failed to write to DUT runtime log for {dut_id}: {e}",
                )

    async def write_to_dut_log(
        self, dut_id: str, level: str, component: str, message: str
    ) -> None:
        """
        Write to DUT-specific log file.

        Args:
            dut_id: DUT ID
            level: Logging level
            component: Component name
            message: Message to write
        """
        if dut_id not in self.dut_runtime_files:
            await self.setup_dut_logging(dut_id)

        # Also write to DUT runtime log
        await self.write_to_dut_runtime_log(dut_id, level, component, message)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] [{level}] [{component}] {message}\n"

        # Determine if this is a collector log (R1, R2, etc.) or a service log
        if component.startswith(("R", "I", "S", "H", "C")) and len(component) <= 3:
            # This is a collector - use proper structure
            group = self._get_collector_group(component)

            # Get collector name from orchestrator if available
            collector_name = component
            try:
                if hasattr(self, "orchestrator") and self.orchestrator:
                    collector_info = self.orchestrator.get_collector_info(component)
                    if collector_info and "name" in collector_info:
                        collector_name = collector_info["name"]
                    else:
                        # Fallback: use group name if no collector name found
                        collector_name = group
            except Exception:
                # Fallback: use group name if any error occurs
                collector_name = group

            collector_dir = (
                self.dut_log_dirs[dut_id] / group / f"{component}_{collector_name}"
            )
            collector_dir.mkdir(parents=True, exist_ok=True)
            log_file = collector_dir / "collector.log"
        else:
            # This is a service log - use direct DUT directory
            log_file = self.dut_log_dirs[dut_id] / f"{component}.log"

        try:
            with open(log_file, "a") as f:
                f.write(log_entry)
        except Exception as e:
            await self.log_error(
                "LOGGING_ERROR", f"Failed to write to DUT log {log_file}: {e}"
            )

    def _get_collector_group(self, collector_id: str) -> str:
        """
        Get collector group from ID.

        Args:
            collector_id: Collector ID
        """
        return CollectorServiceMapping.get_service_from_collector_id(collector_id)

    async def create_collector_log_file(
        self, dut_id: str, group: str, collector_id: str, filename: str
    ) -> Path:
        """
        Create a log file for a specific collector.

        Args:
            dut_id: DUT ID
            group: Collector group
            collector_id: Collector ID
            filename: Filename
        """
        # Get collector name and output pattern from orchestrator if available
        collector_name = collector_id
        output_filename = filename
        try:
            # Try to get collector info from orchestrator
            if hasattr(self, "orchestrator") and self.orchestrator:
                collector_info = self.orchestrator.get_collector_info(collector_id)
                if collector_info:
                    if "name" in collector_info:
                        collector_name = collector_info["name"]
                    # Only use output_pattern if the filename still contains variable placeholders
                    # This allows pre-substituted filenames to be respected
                    # Use regex to detect any variable pattern like {variable_name}
                    variable_pattern = re.compile(r"\{[^}]+\}")
                    has_variables = variable_pattern.search(filename) is not None

                    if (
                        "stages" in collector_info
                        and "execution" in collector_info["stages"]
                        and has_variables
                    ):
                        execution_stage = collector_info["stages"]["execution"]
                        if "hooks" in execution_stage:
                            for hook in execution_stage["hooks"]:
                                if "output_pattern" in hook:
                                    output_filename = hook["output_pattern"]
                                    break
                else:
                    # Fallback: use group name if no collector name found
                    collector_name = group
        except Exception as e:
            # Fallback: use group name if any error occurs
            collector_name = group

        # Create directory structure: logs/dut_id/group/Service_collector_id_name/ (standard format)
        # Standard format: Redfish_R8_firmware_inventory, Host_H1_node_dmesg, etc.
        service_prefix = group.capitalize()
        collector_dir = (
            self.base_log_dir
            / dut_id
            / group
            / f"{service_prefix}_{collector_id}_{collector_name}"
        )
        collector_dir.mkdir(parents=True, exist_ok=True)

        return collector_dir / output_filename

    async def create_config_files(
        self,
        dut_id: str,
        tool_config: Dict[str, Any],
        dut_config: Dict[str, Any],
    ) -> None:
        """
        Create config.json and dut_config.json files for a DUT.

        Args:
            dut_id: DUT ID
            tool_config: Tool configuration
            dut_config: DUT configuration
        """
        try:
            dut_dir = self.get_dut_log_dir(dut_id)

            # Create config.json (tool configuration) with sanitization
            config_file = dut_dir / "config.json"

            # Sanitize the tool config if sanitizer is available
            sanitized_tool_config = tool_config.copy()
            if self.sanitizer:
                # Recursively sanitize all string values in the tool config
                sanitized_tool_config = self._sanitize_config_dict(tool_config)

            with open(config_file, "w") as f:
                json.dump(sanitized_tool_config, f, indent=4)

            # Create dut_config.json (DUT configuration) with sanitization
            dut_config_file = dut_dir / "dut_config.json"

            # Sanitize the DUT config if sanitizer is available
            sanitized_dut_config = dut_config.copy()
            if self.sanitizer:
                # Recursively sanitize all string values in the DUT config
                sanitized_dut_config = self._sanitize_config_dict(dut_config)

            with open(dut_config_file, "w") as f:
                json.dump(sanitized_dut_config, f, indent=4)

        except Exception as e:
            await self.log_error(
                "LOGGING_ERROR",
                f"Error creating config files for DUT {dut_id}: {e}",
            )

    def _sanitize_config_dict(self, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively sanitize all string values in a configuration dictionary

        Args:
            config_dict: Configuration dictionary to sanitize

        Returns:
            Sanitized configuration dictionary
        """
        if not self.sanitizer:
            return config_dict

        sanitized = {}
        for key, value in config_dict.items():
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_config_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    (
                        self._sanitize_config_dict(item)
                        if isinstance(item, dict)
                        else (
                            self.sanitizer.sanitize(str(item))
                            if isinstance(item, str)
                            else item
                        )
                    )
                    for item in value
                ]
            elif isinstance(value, str):
                sanitized[key] = self.sanitizer.sanitize(value)
            else:
                sanitized[key] = value
        return sanitized

    async def create_log_signature(
        self, dut_id: str, platform: str = None, baseboard: str = None
    ) -> None:
        """
        Create .log_signature.txt file with version and platform information.

        Args:
            dut_id: DUT ID
            platform: Platform
            baseboard: Baseboard
        """
        try:
            from ..version import __build_hash__, __version__

            dut_dir = self.get_dut_log_dir(dut_id)
            signature_file = dut_dir / ".log_signature.txt"

            # Get current timestamp
            from datetime import datetime

            build_date = datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")

            # Build signature content
            signature_content = f"""NVDebug Tool Version {__version__}
Build date: {build_date}
Platform: {platform or 'unknown'}
Baseboard: {baseboard or 'unknown'}
"""

            # Create signature file in DUT directory
            with open(signature_file, "w") as f:
                f.write(signature_content)

            # Also create root-level signature file
            root_signature_file = self.base_log_dir / ".log_signature.txt"
            with open(root_signature_file, "w") as f:
                f.write(signature_content)

        except Exception as e:
            await self.log_error(
                "LOGGING_ERROR",
                f"Error creating log signature for DUT {dut_id}: {e}",
            )

    async def create_structured_log(self, dut_id: str) -> None:
        """
        Create nvdebug_runtime_output_structured.txt with organized log output.

        Args:
            dut_id: DUT ID
        """
        try:
            dut_dir = self.get_dut_log_dir(dut_id)
            structured_log_file = dut_dir / "nvdebug_runtime_output_structured.txt"

            # Get the regular runtime log content
            runtime_log_file = dut_dir / "nvdebug_runtime_output.txt"
            if not runtime_log_file.exists():
                logger.warning(f"Runtime log file not found for DUT {dut_id}")
                return

            with open(runtime_log_file, "r") as f:
                runtime_content = f.read()

            # Create structured content with headers
            from datetime import datetime

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            structured_content = f"""================================================================================
NVDEBUGTOOL ORGANIZED LOG - {timestamp}
================================================================================

======================================== MAIN PROCESS LOGS ========================================

{runtime_content}

======================================== COLLECTOR RESULTS SUMMARY ========================================

Group      ID       Collector Name                                Status     Execution Time 
------------------------------------------------------------------------------------------------------------------

--- REDFISH COLLECTORS ---

"""

            # Add collector results from metadata
            metadata_file = dut_dir / ".metadata" / "redfish.json"
            if metadata_file.exists():
                try:
                    with open(metadata_file, "r") as f:
                        redfish_metadata = json.load(f)

                    collectors = redfish_metadata.get("collectors", {})
                    for collector_id, collector_info in collectors.items():
                        if isinstance(collector_info, dict):
                            name = collector_info.get("name", collector_id)
                            status = collector_info.get("status", "Unknown")
                            execution_time = collector_info.get("execution_time", 0.0)
                            # Handle both string and numeric execution_time values
                            if isinstance(execution_time, str):
                                if execution_time and execution_time != "":
                                    try:
                                        execution_time_float = float(execution_time)
                                        time_str = (
                                            f"{execution_time_float:.2f}s"
                                            if execution_time_float > 0
                                            else "N/A"
                                        )
                                    except (ValueError, TypeError):
                                        time_str = "N/A"
                                else:
                                    time_str = "N/A"
                            else:
                                time_str = (
                                    f"{execution_time:.2f}s"
                                    if execution_time > 0
                                    else "N/A"
                                )
                            structured_content += f"redfish    {collector_id:<8} {name:<40} {status:<10} {time_str}\n"
                except Exception as e:
                    await self.log_error(
                        "LOGGING_ERROR",
                        f"Error reading redfish metadata for structured log: {e}",
                    )

            structured_content += "================================================================================\n"
            structured_content += "END OF ORGANIZED LOG\n"
            structured_content += "================================================================================\n"

            with open(structured_log_file, "w") as f:
                f.write(structured_content)

        except Exception as e:
            await self.log_error(
                "LOGGING_ERROR",
                f"Error creating structured log for DUT {dut_id}: {e}",
            )

    async def _initialize_metadata_files(self, dut_id: str) -> None:
        """
        Initialize metadata files for a DUT.

        Args:
            dut_id: DUT ID
        """
        try:
            metadata_dir = self.get_dut_log_dir(dut_id) / ".metadata"

            # Initialize preflight.json with all possible preflight checks
            preflight_data = {
                "metadata": {
                    "created_at": datetime.now().isoformat() + "Z",
                    "last_updated": datetime.now().isoformat() + "Z",
                },
                "preflights": {},
            }

            # Add all preflight checks with default "Skipped" status
            from ..utils.enums import get_main_preflight_names

            for preflight_name in get_main_preflight_names():
                preflight_data["preflights"][preflight_name] = {
                    "status": "Skipped",
                    "reason": "Preflight check was not executed",
                    "created_at": datetime.now().isoformat() + "Z",
                    "updated_at": None,
                }

            preflight_file = metadata_dir / "preflight.json"
            with open(preflight_file, "w") as f:
                json.dump(preflight_data, f, indent=4)

            # Initialize other metadata files
            metadata_files = [
                "redfish.json",
                "ipmi.json",
                "host.json",
                "health_check.json",
                "ssh.json",
            ]

            for filename in metadata_files:
                file_path = metadata_dir / filename
                if not file_path.exists():
                    # Create empty metadata structure
                    empty_metadata = {
                        "metadata": {
                            "created_at": datetime.now().isoformat() + "Z",
                            "last_updated": datetime.now().isoformat() + "Z",
                        },
                        "status_fields": {
                            "description": "Possible status values for collectors",
                            "values": {
                                "Passed": "Collection completed successfully",
                                "Failed": "Collection failed",
                                "Skipped": "Collection was skipped",
                                "NotRan": "Collection was not included in current collection map",
                                "Partial": "Collection partially succeeded",
                            },
                            "collector_fields": {
                                "id": "Unique identifier for the collector (e.g., R1, H2)",
                                "name": "Name of the collector",
                                "status": "Result status of the collection",
                                "reason": "Detailed message about the collection result",
                                "execution_time": "Time taken to execute the collector",
                                "output_files": "List of output files generated by the collector",
                            },
                        },
                        "collectors": {},
                        "summary": {
                            "total_collectors": 0,
                            "passed": 0,
                            "failed": 0,
                            "skipped": 0,
                            "not_ran": 0,
                            "partial": 0,
                        },
                    }

                    with open(file_path, "w") as f:
                        json.dump(empty_metadata, f, indent=4)

        except Exception as e:
            await self.log_error(
                "LOGGING_ERROR",
                f"Error initializing metadata files for DUT {dut_id}: {e}",
            )

    async def write_collector_output(
        self,
        dut_id: str,
        group: str,
        collector_id: str,
        filename: str,
        content: Union[str, bytes],
    ) -> Path:
        """
        Write output content to a collector log file.

        Args:
            dut_id: DUT ID
            group: Collector group
            collector_id: Collector ID
            filename: Filename
            content: Content to write
        """
        file_path = await self.create_collector_log_file(
            dut_id, group, collector_id, filename
        )

        async with asyncio.Lock():
            if isinstance(content, bytes):
                # Write binary data
                with open(file_path, "wb") as f:
                    f.write(content)
            else:
                # Write text data
                with open(file_path, "w") as f:
                    f.write(content)

        return file_path

    def _format_structured_error(
        self,
        collector_id: str,
        collector_name: str,
        dut_id: str,
        error_message: str,
        context: dict = None,
    ) -> str:
        """
        Format a structured error message with rich context for better debugging.

        Args:
            collector_id: Collector identifier
            collector_name: Human-readable collector name
            dut_id: Device under test identifier
            error_message: The main error message
            context: Additional context dictionary

        Returns:
            Formatted error message string
        """
        lines = []

        # Header section
        lines.append("=" * 80)
        lines.append(f"COLLECTOR ERROR REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Basic information
        lines.append("BASIC INFORMATION:")
        lines.append(f"  Collector ID: {collector_id}")
        lines.append(f"  Collector Name: {collector_name}")
        lines.append(f"  DUT: {dut_id}")
        lines.append(f"  Timestamp: {datetime.now().isoformat()}")
        lines.append("")

        # Error summary
        lines.append("ERROR SUMMARY:")
        lines.append(f"  {error_message}")
        lines.append("")

        # Add context information if available
        if context:
            lines.append("DETAILED CONTEXT:")

            # Operation details
            if "operation_name" in context:
                lines.append(f"  Operation: {context['operation_name']}")

            if "target_baseboard" in context:
                lines.append(f"  Target Baseboard: {context['target_baseboard']}")

            if "devices_processed" in context:
                lines.append(f"  Devices Processed: {context['devices_processed']}")

            if "successful_operations" in context and "total_operations" in context:
                lines.append(
                    f"  Success Rate: {context['successful_operations']}/{context['total_operations']}"
                )

            # Detailed error information for partial collections
            if "detailed_errors" in context and context["detailed_errors"]:
                lines.append("")
                lines.append("FAILED OPERATIONS:")
                detailed_errors = context["detailed_errors"]
                if isinstance(detailed_errors, list):
                    for i, error in enumerate(detailed_errors, 1):
                        if isinstance(error, str):
                            # Split long error messages into multiple lines for readability
                            error_lines = error.split("\n")
                            lines.append(f"  {i}. {error_lines[0]}")
                            for additional_line in error_lines[1:]:
                                if additional_line.strip():
                                    lines.append(f"     {additional_line.strip()}")
                        else:
                            lines.append(f"  {i}. {str(error)}")
                else:
                    lines.append(f"  {detailed_errors}")

            # Timing information
            if "execution_time" in context:
                lines.append(f"  Execution Time: {context['execution_time']:.2f}s")

            # Request details (for diagnostic collection errors)
            if "result" in context and isinstance(context["result"], dict):
                result = context["result"]

                # Check if this is a diagnostic collection result with request info
                if "context" in result and isinstance(result["context"], dict):
                    result_context = result["context"]

                    # Request URI
                    if "request_uri" in result_context:
                        lines.append("")
                        lines.append("REQUEST DETAILS:")
                        lines.append(f"  URI: {result_context['request_uri']}")

                        # Request payload (formatted as multi-line JSON)
                        if "request_payload" in result_context:
                            payload = result_context["request_payload"]
                            lines.append("  Payload:")
                            try:
                                if isinstance(payload, dict):
                                    formatted_payload = json.dumps(payload, indent=4)
                                else:
                                    # Try to parse as JSON first
                                    parsed_payload = json.loads(str(payload))
                                    formatted_payload = json.dumps(
                                        parsed_payload, indent=4
                                    )

                                # Indent each line of the payload
                                for line in formatted_payload.split("\n"):
                                    lines.append(f"    {line}")
                            except (json.JSONDecodeError, TypeError):
                                # If not valid JSON, just show as string
                                lines.append(f"    {payload}")

                        # Response data (formatted as multi-line JSON)
                        if "response_data" in result_context:
                            response_data = result_context["response_data"]
                            lines.append("  Response:")
                            try:
                                if isinstance(response_data, dict):
                                    formatted_response = json.dumps(
                                        response_data, indent=4
                                    )
                                else:
                                    # Try to parse as JSON first
                                    parsed_response = json.loads(str(response_data))
                                    formatted_response = json.dumps(
                                        parsed_response, indent=4
                                    )

                                # Indent each line of the response
                                for line in formatted_response.split("\n"):
                                    lines.append(f"    {line}")
                            except (json.JSONDecodeError, TypeError):
                                # If not valid JSON, just show as string
                                lines.append(f"    {response_data}")

                    # Handle failed entity contexts (for diagnostic collection)
                    if "failed_entity_contexts" in result_context:
                        lines.append("")
                        lines.append("FAILED ENTITY CONTEXTS:")
                        failed_entities = result_context["failed_entity_contexts"]
                        for entity_id, entity_context in failed_entities.items():
                            lines.append(f"  Entity: {entity_id}")
                            if "request_uri" in entity_context:
                                lines.append(
                                    f"    URI: {entity_context['request_uri']}"
                                )
                            if "request_payload" in entity_context:
                                payload = entity_context["request_payload"]
                                lines.append("    Payload:")
                                try:
                                    if isinstance(payload, dict):
                                        formatted_payload = json.dumps(
                                            payload, indent=6
                                        )
                                    else:
                                        parsed_payload = json.loads(str(payload))
                                        formatted_payload = json.dumps(
                                            parsed_payload, indent=6
                                        )
                                    for line in formatted_payload.split("\n"):
                                        lines.append(f"      {line}")
                                except (json.JSONDecodeError, TypeError):
                                    lines.append(f"      {payload}")
                            if "error_message" in entity_context:
                                lines.append(
                                    f"    Error: {entity_context['error_message']}"
                                )
                            lines.append("")

                    # Handle failed service contexts (for custom service executor)
                    if "failed_service_contexts" in result_context:
                        lines.append("")
                        lines.append("FAILED SERVICE CONTEXTS:")
                        failed_services = result_context["failed_service_contexts"]
                        for service_id, service_context in failed_services.items():
                            lines.append(f"  Service: {service_id}")
                            if "request_uri" in service_context:
                                lines.append(
                                    f"    URI: {service_context['request_uri']}"
                                )
                            if "request_payload" in service_context:
                                payload = service_context["request_payload"]
                                lines.append("    Payload:")
                                try:
                                    if isinstance(payload, dict):
                                        formatted_payload = json.dumps(
                                            payload, indent=6
                                        )
                                    else:
                                        parsed_payload = json.loads(str(payload))
                                        formatted_payload = json.dumps(
                                            parsed_payload, indent=6
                                        )
                                    for line in formatted_payload.split("\n"):
                                        lines.append(f"      {line}")
                                except (json.JSONDecodeError, TypeError):
                                    lines.append(f"      {payload}")
                            if "timeout" in service_context:
                                lines.append(
                                    f"    Timeout: {service_context['timeout']}s"
                                )
                            if "max_retries" in service_context:
                                lines.append(
                                    f"    Max Retries: {service_context['max_retries']}"
                                )
                            lines.append("")

            # Error details
            if "error_messages" in context and context["error_messages"]:
                lines.append("")
                lines.append("ERROR DETAILS:")
                error_messages = context["error_messages"]
                if isinstance(error_messages, list):
                    for i, error_msg in enumerate(error_messages, 1):
                        lines.append(f"  {i}. {error_msg}")
                else:
                    lines.append(f"  {error_messages}")

            # Handle direct payload field (for command executor errors)
            if "payload" in context and context["payload"]:
                lines.append("")
                lines.append("REQUEST PAYLOAD:")
                payload = context["payload"]
                try:
                    if isinstance(payload, dict):
                        formatted_payload = json.dumps(payload, indent=4)
                    else:
                        # Try to parse as JSON first
                        parsed_payload = json.loads(str(payload))
                        formatted_payload = json.dumps(parsed_payload, indent=4)

                    # Indent each line of the payload
                    for line in formatted_payload.split("\n"):
                        lines.append(f"  {line}")
                except (json.JSONDecodeError, TypeError):
                    # If not valid JSON, just show as string
                    lines.append(f"  {payload}")

            # Additional context
            if "additional_context" in context:
                additional = context["additional_context"]
                if isinstance(additional, dict) and additional:
                    lines.append("")
                    lines.append("ADDITIONAL CONTEXT:")
                    for key, value in additional.items():
                        lines.append(f"  {key}: {value}")

            lines.append("")

        # Footer
        lines.append("=" * 80)
        lines.append("END OF ERROR REPORT")
        lines.append("=" * 80)

        return "\n".join(lines)

    async def write_error_log(
        self, dut_id: str, collector_id: str, error_message: str, context: dict = None
    ) -> Path:
        """
        Write error message to error-logs directory.

        Args:
            dut_id: DUT ID
            collector_id: Collector ID
            error_message: Error message
            context: Context
        """
        # Create error-logs directory path
        error_logs_dir = self.base_log_dir / dut_id / "error-logs"
        error_logs_dir.mkdir(parents=True, exist_ok=True)

        # Get collector name from orchestrator if available
        collector_name = collector_id
        if hasattr(self, "orchestrator") and self.orchestrator:
            try:
                collector_def = self.orchestrator.get_all_collectors().get(collector_id)
                if collector_def:
                    collector_name = collector_def.get("name", collector_id)
            except Exception:
                pass

        # Create error log file path
        error_filename = f"{collector_id}_{collector_name}_error.log"
        file_path = error_logs_dir / error_filename

        # Create structured error message with rich context
        structured_error = self._format_structured_error(
            collector_id, collector_name, dut_id, error_message, context
        )

        async with asyncio.Lock():
            # Check if file already exists to determine if we need a separator
            file_exists = file_path.exists()

            # If file exists, add a separator before the new error
            if file_exists:
                separator = "\n\n" + "=" * 80 + "\n"
                separator += "ADDITIONAL ERROR ENTRY"
                separator += "\n" + "=" * 80 + "\n\n"
                structured_error = separator + structured_error

            # Use append mode to accumulate multiple errors
            with open(file_path, "a") as f:
                f.write(structured_error)

        return file_path

    async def log_collector_result(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str = "",
        execution_time: float = 0.0,
        output_files: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        discovered_files: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """
        Log collector execution result.

        Args:
            dut_id: DUT ID
            collector_id: Collector ID
            status: Status
            reason: Reason
            execution_time: Execution time
            output_files: Output files
            context: Context
            discovered_files: Discovered files organized by folder
        """
        # Debug: Log entry point
        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncLogger",
            f"log_collector_result called for {collector_id}: status={status}, reason='{reason}', context_keys={list(context.keys()) if context else []}, discovered_files_keys={list(discovered_files.keys()) if discovered_files else []}",
        )

        if output_files is None:
            output_files = []

        # Update execution summary
        if isinstance(self.execution_summary["total_collectors"], int):
            self.execution_summary["total_collectors"] += 1

        if status == "success" and isinstance(
            self.execution_summary["successful_collectors"], int
        ):
            self.execution_summary["successful_collectors"] += 1
        elif status == "error" and isinstance(
            self.execution_summary["failed_collectors"], int
        ):
            self.execution_summary["failed_collectors"] += 1
        elif status == "partial" and isinstance(
            self.execution_summary["partial_collectors"], int
        ):
            self.execution_summary["partial_collectors"] += 1
        elif status == "skipped" and isinstance(
            self.execution_summary["skipped_collectors"], int
        ):
            self.execution_summary["skipped_collectors"] += 1

        # Store result
        result_key = f"{dut_id}:{collector_id}"
        self.collector_results[result_key] = {
            "dut_id": dut_id,
            "collector_id": collector_id,
            "status": status,
            "reason": reason,
            "execution_time": execution_time,
            "output_files": output_files,
            "context": context or {},
            "timestamp": datetime.now().isoformat(),
        }

        # Update collector status
        await self._update_collector_status(
            dut_id, collector_id, status, reason, execution_time, discovered_files
        )

        # Log the result
        await self.write_to_dut_runtime_log(
            dut_id,
            (
                "INFO"
                if status == "success"
                else "ERROR" if status == "error" else "WARN"
            ),
            collector_id,
            f"Status: {status}, Reason: {reason}, Time: {execution_time:.2f}s",
        )

    async def _update_collector_status(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str,
        execution_time: float = 0.0,
        discovered_files: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """
        Update collector status in metadata.

        Args:
            dut_id: DUT ID.
            collector_id: Collector ID.
            status: Status string.
            reason: Reason for status.
            execution_time: Execution time in seconds.
            discovered_files: Optional dictionary of discovered files.
        """
        # Debug: Log what discovered_files we received
        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncLogger",
            f"_update_collector_status for {collector_id}: discovered_files={'None' if discovered_files is None else f'{len(discovered_files)} folders with {sum(len(v) for v in discovered_files.values())} files'}",
        )

        group = self._get_collector_group(collector_id)

        if group not in self.collector_status:
            self.collector_status[group] = {}

        if dut_id not in self.collector_status[group]:
            self.collector_status[group][dut_id] = {
                "total": 0,
                "successful": 0,
                "failed": 0,
                "skipped": 0,
                "collectors": {},
            }

        dut_status = self.collector_status[group][dut_id]
        dut_status["total"] += 1

        # Get existing files if collector entry already exists
        existing_files = []
        if collector_id in dut_status["collectors"]:
            existing_files = dut_status["collectors"][collector_id].get("files", [])
            await self.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AsyncLogger",
                f"_update_collector_status: Found {len(existing_files)} existing files for {collector_id}",
            )

        # Flatten discovered files into a single list
        files_list = []
        if discovered_files:
            await self.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AsyncLogger",
                f"_update_collector_status: Processing discovered_files for {collector_id}: {len(discovered_files)} folders",
            )
            for folder_path, files in discovered_files.items():
                files_list.extend(files)
                await self.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "AsyncLogger",
                    f"_update_collector_status: Added {len(files)} files from folder {folder_path}",
                )

        # Check for pending file updates from execution summary manager
        if hasattr(self, "orchestrator") and self.orchestrator:
            execution_summary_manager = getattr(
                self.orchestrator, "execution_summary_manager", None
            )
            if execution_summary_manager and hasattr(
                execution_summary_manager, "_pending_file_updates"
            ):
                key = f"{dut_id}:{collector_id}"
                if key in execution_summary_manager._pending_file_updates:
                    pending_files = execution_summary_manager._pending_file_updates[key]
                    await self.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "AsyncLogger",
                        f"_update_collector_status: Found pending file updates for {collector_id}: {len(pending_files)} folders",
                    )
                    for folder_path, files in pending_files.items():
                        files_list.extend(files)
                    # Remove from pending to avoid duplicate processing
                    del execution_summary_manager._pending_file_updates[key]

        # If discovered_files was None/empty and we have existing files, preserve them
        if not files_list and existing_files:
            files_list = existing_files
            await self.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AsyncLogger",
                f"_update_collector_status: Preserving {len(existing_files)} existing files for {collector_id}",
            )

        # Convert file paths to be relative to DUT directory for portability
        # This makes the metadata more portable and consistent
        relative_files_list = []
        dut_path_str = f"{dut_id}/"
        for file_path in files_list:
            # Find the DUT directory in the path and make it relative from there
            if dut_path_str in file_path:
                # Extract everything after the DUT directory
                rel_path = file_path.split(dut_path_str, 1)[1]
                relative_files_list.append(rel_path)
            else:
                # If we can't find the DUT path, keep the original
                relative_files_list.append(file_path)

        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncLogger",
            f"_update_collector_status: Final files_list for {collector_id}: {len(relative_files_list)} files (converted to relative paths)",
        )

        dut_status["collectors"][collector_id] = {
            "status": status,
            "reason": reason,
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat(),
            "files": relative_files_list,
        }

        if status == "success":
            dut_status["successful"] += 1
        elif status == "error":
            dut_status["failed"] += 1
        elif status == "skipped":
            dut_status["skipped"] += 1

        # Write group metadata
        await self._write_group_metadata(group, dut_id)

        # Debug: Log the metadata update
        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncLogger",
            f"Updated collector {collector_id} status to {status} in group {group} for DUT {dut_id}",
        )

    async def initialize_all_collector_metadata(self, dut_id: str) -> None:
        """
        Initialize all collector metadata files upfront with all collectors.

        Args:
            dut_id: DUT ID.
        """
        if not self.orchestrator:
            return

        # Get all collector groups
        all_groups = self.orchestrator.get_all_collector_groups()

        for group in all_groups:
            await self._write_group_metadata(group, dut_id)

        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncLogger",
            f"Initialized all collector metadata for DUT {dut_id}",
        )

    async def _write_group_metadata(self, group: str, dut_id: str = None) -> None:
        """
        Write group metadata to JSON file with all collectors for the group.

        Args:
            group: Group name.
            dut_id: DUT ID.
        """
        if dut_id:
            # Write to DUT-specific metadata directory
            dut_metadata_dir = self.base_log_dir / dut_id / ".metadata"
            dut_metadata_dir.mkdir(parents=True, exist_ok=True)
            group_file = dut_metadata_dir / f"{group}.json"
        else:
            # Write to root metadata directory (for backward compatibility)
            group_file = self.metadata_dir / f"{group}.json"

        # Get all collectors for this group from orchestrator
        all_collectors = {}
        if self.orchestrator:
            all_collectors = self.orchestrator.get_collectors_for_group(group)

        # Create group metadata structure
        group_metadata = {
            "metadata": {
                "created_at": datetime.now().isoformat() + "Z",
                "last_updated": datetime.now().isoformat() + "Z",
            },
            "status_fields": {
                "description": "Possible status values for collectors",
                "values": {
                    "Passed": "Collection completed successfully",
                    "Failed": "Collection failed",
                    "Skipped": "Collection was skipped",
                    "NotRan": "Collection was not included in current collection map",
                    "Partial": "Collection partially succeeded",
                },
                "collector_fields": {
                    "id": "Unique identifier for the collector (e.g., R1, H2)",
                    "name": "Name of the collector",
                    "status": "Result status of the collection",
                    "reason": "Detailed message about the collection result",
                    "execution_time": "Time taken to execute the collector",
                    "created_at": "When the collector was first initialized",
                    "updated_at": "When the collector was last updated",
                    "files": "List of files generated by this collector",
                },
            },
            "collectors": {},
        }

        # Initialize ALL collectors with empty status
        for collector_id, collector_info in all_collectors.items():
            # Use lowercase collector ID
            legacy_collector_id = collector_id.lower()
            group_metadata["collectors"][legacy_collector_id] = {
                "id": legacy_collector_id,
                "name": collector_info.get("name", collector_id),
                "status": "",  # Empty status
                "reason": "",
                "execution_time": "",
                "created_at": datetime.now().isoformat() + "Z",
                "updated_at": None,
                "files": [],
            }

        # Update with actual execution results for the specific DUT
        if (
            group in self.collector_status
            and dut_id
            and dut_id in self.collector_status[group]
        ):
            dut_status = self.collector_status[group][dut_id]
            for collector_id, collector_result in dut_status.get(
                "collectors", {}
            ).items():
                # Use lowercase collector ID
                legacy_collector_id = collector_id.lower()
                if legacy_collector_id in group_metadata["collectors"]:
                    status = collector_result.get("status", "NotRan")
                    # Convert status to legacy format
                    legacy_status = (
                        "Passed"
                        if status == "success"
                        else (
                            "Failed"
                            if status == "error"
                            else (
                                "Skipped"
                                if status == "skipped"
                                else ("Partial" if status == "partial" else "NotRan")
                            )
                        )
                    )

                    group_metadata["collectors"][legacy_collector_id].update(
                        {
                            "status": legacy_status,
                            "reason": collector_result.get("reason", ""),
                            "execution_time": collector_result.get(
                                "execution_time", 0.0
                            ),
                            "updated_at": collector_result.get(
                                "timestamp", datetime.now().isoformat() + "Z"
                            ),
                            "files": collector_result.get("files", []),
                        }
                    )

        # Add summary section
        total_collectors = len(group_metadata["collectors"])
        passed = sum(
            1 for c in group_metadata["collectors"].values() if c["status"] == "Passed"
        )
        failed = sum(
            1 for c in group_metadata["collectors"].values() if c["status"] == "Failed"
        )
        skipped = sum(
            1 for c in group_metadata["collectors"].values() if c["status"] == "Skipped"
        )
        not_ran = sum(
            1 for c in group_metadata["collectors"].values() if c["status"] == "NotRan"
        )
        partial = sum(
            1 for c in group_metadata["collectors"].values() if c["status"] == "Partial"
        )

        group_metadata["summary"] = {
            "total_collectors": total_collectors,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "not_ran": not_ran,
            "partial": partial,
        }

        async with asyncio.Lock():
            with open(group_file, "w") as f:
                safe_json_dump(group_metadata, f, indent=4)

    async def _create_root_metadata_aggregator(self) -> None:
        """
        Create root metadata aggregator with tool-wide summary.

        Aggregates metadata from all DUTs into a root-level summary file.
        """
        # Calculate overall statistics across all DUTs
        total_duts = len(self.dut_log_dirs)
        total_collectors = 0
        successful_collectors = 0
        failed_collectors = 0
        skipped_collectors = 0
        not_ran_collectors = 0

        dut_summaries = {}

        # Aggregate statistics from all DUTs
        for dut_id in self.dut_log_dirs:
            dut_summary = {
                "total_collectors": 0,
                "successful_collectors": 0,
                "failed_collectors": 0,
                "skipped_collectors": 0,
                "not_ran_collectors": 0,
                "groups": {},
            }

            # Count collectors by group for this DUT
            for group in ["redfish", "ipmi", "ssh", "host", "health_check"]:
                if (
                    group in self.collector_status
                    and dut_id in self.collector_status[group]
                ):
                    dut_collectors = self.collector_status[group][dut_id].get(
                        "collectors", {}
                    )
                    dut_summary["groups"][group] = len(dut_collectors)

                    for collector_result in dut_collectors.values():
                        status = collector_result.get("status", "NotRan")
                        dut_summary["total_collectors"] += 1
                        total_collectors += 1

                        if status == "success":
                            dut_summary["successful_collectors"] += 1
                            successful_collectors += 1
                        elif status == "error":
                            dut_summary["failed_collectors"] += 1
                            failed_collectors += 1
                        elif status == "skipped":
                            dut_summary["skipped_collectors"] += 1
                            skipped_collectors += 1
                        else:
                            dut_summary["not_ran_collectors"] += 1
                            not_ran_collectors += 1

            # Add timing summary for this DUT if available
            if (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "timing_manager")
            ):
                timing_summary = (
                    self.orchestrator.timing_manager.get_timing_summary_for_metadata()
                )
                if timing_summary and "collectors" in timing_summary:
                    # Calculate timing summary for this DUT
                    dut_collectors = timing_summary["collectors"]
                    dut_timing = {
                        "total_collectors": len(dut_collectors),
                        "max_execution_time": 0.0,
                        "total_execution_time": 0.0,
                        "avg_execution_time": 0.0,
                        "collector_times": {},
                    }

                    for collector_id, collector_data in dut_collectors.items():
                        execution_time = collector_data.get("total_time", 0.0)
                        dut_timing["collector_times"][collector_id] = execution_time
                        dut_timing["total_execution_time"] += execution_time
                        dut_timing["max_execution_time"] = max(
                            dut_timing["max_execution_time"], execution_time
                        )

                    if dut_timing["total_collectors"] > 0:
                        dut_timing["avg_execution_time"] = (
                            dut_timing["total_execution_time"]
                            / dut_timing["total_collectors"]
                        )

                    dut_summary["timing_summary"] = dut_timing

            dut_summaries[dut_id] = dut_summary

        # Create root metadata structure
        root_metadata = {
            "metadata": {
                "created_at": datetime.now().isoformat() + "Z",
                "last_updated": datetime.now().isoformat() + "Z",
                "tool_version": "nvdebugtool",
                "collection_level": "L1",  # TODO: Get from orchestrator
            },
            "payload": {
                # Platform info will be populated by DUT-specific metadata
            },
            "collectors": {
                "Redfish": [],
                "IPMI": [],
                "SSH": [],
                "Host": [],
                "HealthCheck": [],
            },
            "summary": {
                "total_duts": total_duts,
                "total_collectors": total_collectors,
                "successful_collectors": successful_collectors,
                "failed_collectors": failed_collectors,
                "skipped_collectors": skipped_collectors,
                "not_ran_collectors": not_ran_collectors,
                "overall_status": ("Passed" if failed_collectors == 0 else "Failed"),
            },
            "duts": dut_summaries,
        }

        root_file = self.metadata_dir / "metadata.json"

        async with asyncio.Lock():
            with open(root_file, "w") as f:
                safe_json_dump(root_metadata, f, indent=4)

    async def write_dependency_metadata(
        self, dependency_data: Dict[str, Any], dut_id: str = None
    ) -> None:
        """
        Write dependency check metadata.

        Args:
            dependency_data: Dependency data.
            dut_id: DUT ID.
        """
        if dut_id:
            # Write to DUT-specific metadata directory
            dut_metadata_dir = self.base_log_dir / dut_id / ".metadata"
            dut_metadata_dir.mkdir(parents=True, exist_ok=True)
            dep_file = dut_metadata_dir / "dependency_check.json"
        else:
            # Write to root metadata directory (for backward compatibility)
            dep_file = self.metadata_dir / "dependency_check.json"

        # Convert to standard format for dependency results
        legacy_dependency_data = {
            "metadata": {
                "created_at": datetime.now().isoformat() + "Z",
                "last_updated": datetime.now().isoformat() + "Z",
            },
            "status_fields": {
                "description": "Possible status values for dependency checks",
                "values": {
                    "passed": "Dependency check passed successfully",
                    "failed": "Dependency check failed",
                    "skipped": "Dependency check was skipped",
                    "not_applicable": "Dependency check is not applicable for this collector",
                },
                "dependency_types": {
                    "command": "Check for availability of a command in PATH",
                    "command_version": "Check for availability of a command and optionally verify its version",
                    "file": "Check for existence of a file or glob pattern",
                    "service": "Check if a service is running",
                },
                "dependency_fields": {
                    "name": "Name of the dependency being checked",
                    "type": "Type of dependency (command, command_version, file, or service)",
                    "status": "Result status of the check",
                    "message": "Detailed message about the check result (includes installation instructions if available)",
                    "required": "Whether this dependency is required (true) or optional (false)",
                    "install_instructions": "Installation instructions for the dependency (optional)",
                    "min_version": "Minimum required version for command_version type (optional)",
                    "max_version": "Maximum allowed version for command_version type (optional)",
                    "version_cmd": "Custom command to get version for command_version type (optional, defaults to '--version')",
                },
            },
            "collectors": {},
            "summary": {
                "total_checks": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "not_applicable": 0,
                "required_failed": 0,
                "optional_failed": 0,
            },
        }

        # Convert collectors to legacy format
        for collector_id, collector_data in dependency_data.items():
            # Convert to lowercase for legacy format
            legacy_collector_id = collector_id.lower()

            # Convert dependencies to standard format
            dependencies = []

            # Add required dependencies
            for dep in collector_data.get("required_dependencies", []):
                status = "passed" if dep.get("available", False) else "failed"
                dependencies.append(
                    {
                        "name": dep.get("name", ""),
                        "type": dep.get("type", "command"),
                        "status": status,
                        "message": dep.get("error_message", "")
                        or "Dependency check completed successfully",
                        "required": True,
                    }
                )

            # Add optional dependencies
            for dep in collector_data.get("optional_dependencies", []):
                status = "passed" if dep.get("available", False) else "failed"
                dependencies.append(
                    {
                        "name": dep.get("name", ""),
                        "type": dep.get("type", "command"),
                        "status": status,
                        "message": dep.get("error_message", "")
                        or "Dependency check completed successfully",
                        "required": False,
                    }
                )

            legacy_dependency_data["collectors"][legacy_collector_id] = {
                "id": legacy_collector_id,
                "name": collector_data.get("collector_name", ""),
                "updated_at": datetime.now().isoformat() + "Z",
                "dependencies": dependencies,
            }

        # Perform a process-safe, in-process-serialized read-modify-write with flock
        lock = self._get_lock_for_path(dep_file)
        async with lock:
            dep_file.parent.mkdir(parents=True, exist_ok=True)
            with open(dep_file, "a+", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    # Load existing content (if any)
                    f.seek(0)
                    try:
                        existing_data = json.load(f)
                        if not isinstance(existing_data, dict):
                            existing_data = {}
                    except Exception as e:
                        existing_data = {}
                        # Log parse failure but continue with fresh structure
                        await self._log_simple(
                            "WARN",
                            f"Failed to parse dependency metadata {dep_file}: {e}. Rebuilding file.",
                            dut_id,
                        )

                    # Merge and recompute summary
                    before_count = len(existing_data.get("collectors", {}))
                    incoming_count = len(legacy_dependency_data.get("collectors", {}))
                    existing_data = self._merge_dependency_metadata(
                        existing_data, legacy_dependency_data
                    )
                    merged_count = len(existing_data.get("collectors", {}))
                    total_checks = existing_data.get("summary", {}).get("total_checks", 0)

                    # Write back atomically in-place
                    f.seek(0)
                    f.truncate()
                    safe_json_dump(existing_data, f, indent=4)
                    f.flush()
                    os.fsync(f.fileno())
                except Exception as e:
                    # Log any unexpected error in the critical section and re-raise
                    await self.log_error(
                        "DEPENDENCY_METADATA_ERROR",
                        f"Unexpected error updating dependency metadata {dep_file}: {e}",
                        dut_id=dut_id,
                    )
                    raise
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

    async def write_preflight_metadata(
        self, dut_id: str, preflight_data: Dict[str, Any]
    ) -> None:
        """
        Write preflight metadata for a specific DUT.

        Args:
            dut_id: DUT ID.
            preflight_data: Preflight data.
        """
        # Create DUT-specific metadata directory
        dut_metadata_dir = self.base_log_dir / dut_id / ".metadata"
        dut_metadata_dir.mkdir(parents=True, exist_ok=True)

        # Convert to legacy preflight format
        legacy_preflight = {
            "metadata": {
                "created_at": datetime.now().isoformat() + "Z",
                "last_updated": datetime.now().isoformat() + "Z",
            },
            "preflights": {},
        }

        # Define main preflight checks that we actually use
        all_preflights = get_main_preflight_names()

        # Convert services to legacy format
        services = preflight_data.get("services", {})

        # Initialize all preflights with "Skipped" status
        for preflight_name in all_preflights:
            legacy_preflight["preflights"][preflight_name] = {
                "status": "Skipped",
                "reason": "Preflight check was not executed",
                "created_at": datetime.now().isoformat() + "Z",
                "updated_at": None,
            }

        # Update with actual results
        for service_name, service_result in services.items():
            status = service_result.get("status", "unknown")
            # Convert to legacy status format
            legacy_status = (
                "Passed"
                if status == "pass"
                else "Failed" if status == "fail" else "Skipped"
            )

            legacy_preflight["preflights"][service_name.upper()] = {
                "status": legacy_status,
                "reason": service_result.get("message", ""),
                "created_at": datetime.now().isoformat() + "Z",
                "updated_at": None,
            }

        preflight_file = dut_metadata_dir / "preflight.json"
        async with asyncio.Lock():
            with open(preflight_file, "w") as f:
                safe_json_dump(legacy_preflight, f, indent=4)

    async def finalize(self) -> None:
        """
        Finalize logging system and create summary metadata.

        Creates root metadata aggregator, group metadata files, and stops logging.
        """
        await self._create_root_metadata_aggregator()
        await self._create_all_group_files()
        await self.stop()

    async def _create_all_group_files(self) -> None:
        """
        Create metadata files for all collector groups at DUT level.

        Creates metadata files for all possible collector groups (redfish, ipmi,
        ssh, host, health_check) even if not executed, for consistent structure.
        """
        if not self.orchestrator:
            return

        # Define all possible groups
        all_groups = ["redfish", "ipmi", "ssh", "host", "health_check"]

        # Create group files for each DUT only (not at root level)
        for dut_id in self.dut_log_dirs:
            for group in all_groups:
                await self._write_group_metadata(group, dut_id)
