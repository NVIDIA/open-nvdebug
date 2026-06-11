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
Base Service for all collector services.

This module provides the foundation for all collector services with standardized
error handling, logging, and result formatting.

STANDARDIZED COLLECTOR RESULT APPROACH:
=======================================

All collectors should use the standardized result approach to ensure consistent
status reporting and partial success handling:

1. Use _create_standardized_collector_result() for one-call result creation
2. Always save what you capture, even if there are errors
3. Never fail silently - log all errors and exceptions

Standard Result Format:
{
    "success": bool,           # True if ANY data was collected successfully
    "status": str,            # "success", "partial", or "error"
    "reason": str,            # Human-readable reason for status
    "context": {
        "total_files": int,   # Number of files generated
        "output_files": List[str],  # List of file paths
        "successful_operations": int,  # Number of successful operations
        "total_operations": int,      # Total operations attempted
        "error_messages": List[str],  # List of error messages
        ...additional_context...      # Collector-specific context
    }
}

Status Logic:
- success=True, status="success": All operations succeeded
- success=True, status="partial": Some operations succeeded, some failed
- success=False, status="error": No operations succeeded

Example Usage:
```python
# Create standardized result in one call
result = self._create_standardized_collector_result(
    successful_operations=3,
    total_operations=5,
    output_files=["file1.json", "file2.json"],
    error_messages=["Failed to collect from system X"],
    operation_name="collections",
    additional_context={"systems_processed": 3}
)
```
"""

import asyncio
import json
import logging
import os
import re
import textwrap
import traceback
import weakref
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import aiohttp

from ..core.async_logger import _collector_context
from ..utils.dependency_checker import DependencyChecker
from ..utils.enums import CollectorServiceMapping
from ..utils.variable_substitution import VariableSubstitutionService

logger = logging.getLogger(__name__)


class BaseService:
    """
    Base class for all collector services.

    Args:
        service_name: Name of the service
        orchestrator: Orchestrator instance
    """

    def __init__(self, service_name: str, orchestrator: Any) -> None:
        """
        Initialize the BaseService.

        Args:
            service_name: Name of the service
            orchestrator: Orchestrator instance
        """
        self.service_name = service_name
        self.orchestrator = orchestrator
        # Tolerate None orchestrator for lightweight operations (e.g., listing collectors)
        self.dut_manager = None
        self.logger = None
        self.dependency_checker = None
        self.timing_manager = None
        self.variable_engine = None  # Will be created asynchronously
        self._request_response_capture_states = weakref.WeakKeyDictionary()
        if orchestrator is not None:
            self.dut_manager = orchestrator.dut_manager
            self.logger = orchestrator.logger
            # Set up dependency checker with DUT manager
            if (
                hasattr(orchestrator, "dependency_checker")
                and orchestrator.dependency_checker
            ):
                self.dependency_checker = orchestrator.dependency_checker
                self.dependency_checker.set_dut_manager(self.dut_manager)
            else:
                self.dependency_checker = DependencyChecker(self.dut_manager)
            self.timing_manager = orchestrator.timing_manager

    def set_orchestrator(self, orchestrator: Any) -> None:
        """
        Attach orchestrator and backfill dependencies after lazy construction.

        Args:
            orchestrator: Orchestrator instance
        """
        self.orchestrator = orchestrator
        if orchestrator is not None:
            self.dut_manager = orchestrator.dut_manager
            self.logger = orchestrator.logger
            self.dependency_checker = orchestrator.dependency_checker
            self.timing_manager = orchestrator.timing_manager

    async def _update_variable_engine(self, dut_id: str = None) -> None:
        """
        Update variable engine with DUT-specific context.

        Args:
            dut_id: DUT identifier
        """
        # Create variable substitution service asynchronously
        dut_object = None
        if hasattr(self, "orchestrator") and self.orchestrator and dut_id:
            dut_object = getattr(self.orchestrator.dut_manager, "duts", {}).get(dut_id)

        self.variable_engine = await VariableSubstitutionService.create(
            logger=self.logger,
            orchestrator=self.orchestrator,
            config_resolver=None,  # TODO: Get from orchestrator
            dut_object=dut_object,
        )

    def _get_dut_config_value(self, dut_id: str, config_key: str) -> Optional[Any]:
        """
        Retrieve a configuration value for the given DUT.

        Args:
            dut_id: DUT identifier
            config_key: Configuration key to look up

        Returns:
            The configuration value if available, otherwise None.
        """
        if not config_key or not self.dut_manager:
            return None

        try:
            dut = self.dut_manager.get_dut(dut_id)
        except Exception:
            return None

        if not dut or not hasattr(dut, "config"):
            return None

        if config_key in dut.config:
            return dut.config.get(config_key)

        # Fallback to baseboard configuration if not present in DUT config
        if self.dut_manager:
            baseboard_name = dut.config.get("baseboard")
            if baseboard_name:
                manager_getter = getattr(
                    self.dut_manager, "_get_baseboard_manager", None
                )
                baseboard_manager = (
                    manager_getter() if callable(manager_getter) else None
                )
                if baseboard_manager:
                    baseboard_config = baseboard_manager.get_baseboard_config(
                        baseboard_name
                    )
                    if baseboard_config and config_key in baseboard_config:
                        return baseboard_config.get(config_key)

        return None

    async def _log_error(
        self,
        error_type: str,
        message: str,
        dut_id: str = None,
        collector_id: str = None,
    ) -> None:
        """
        Safely log error messages using self.logger if available with automatic DUT ID and collector ID.

        Args:
            error_type: Type of error
            message: Error message
            dut_id: DUT identifier
            collector_id: Collector identifier
        """
        # Auto-detect dut_id if not provided
        if dut_id is None:
            dut_id = self._get_current_dut_id()

        # Auto-detect collector_id if not provided
        if collector_id is None:
            collector_id = self._get_current_collector_id()

        if self.logger:
            try:
                await self.logger.log_error(error_type, message, dut_id, collector_id)
            except Exception as e:
                # Fallback to standard logger if async logger fails
                if dut_id and dut_id != "unknown":
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "BaseService",
                        f"Failed to log error via async logger: {e}",
                    )
                else:
                    logger.error(f"Failed to log error via async logger: {e}")
        else:
            # Fallback to standard logger if self.logger not available
            logger.error(f"{error_type}: {message}")

    def _get_current_collector_id(self) -> str:
        """
        Get the current collector ID from context if available.

        Returns:
            str: Current collector ID
        """
        try:
            # Task-local context variable set by the execution engine — safe under concurrency.
            ctx_id = _collector_context.get()
            if ctx_id:
                return ctx_id

            # Fallback: shared orchestrator globals (race-prone under parallel execution).
            if hasattr(self, "orchestrator") and self.orchestrator:
                if hasattr(self.orchestrator, "current_collector_id"):
                    return self.orchestrator.current_collector_id

                if hasattr(self.orchestrator, "current_execution_context"):
                    return self.orchestrator.current_execution_context.get(
                        "collector_id", "unknown"
                    )
        except Exception:
            pass

        return "unknown"

    async def _get_original_collector_id(
        self, dut_id: str = None, collector_id: str = None
    ) -> str:
        """
        Get the original collector ID for file path determination.

        Args:
            dut_id: DUT identifier
            collector_id: Collector identifier
        """
        try:
            # DEBUG: Log the attempt to get original collector ID
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Getting original collector ID for dut_id={dut_id}, collector_id={collector_id}",
            )

            # Try to get from orchestrator context
            if hasattr(self, "orchestrator") and self.orchestrator:
                # First try to get from per-collector context (new method)
                if (
                    hasattr(self.orchestrator, "get_collector_execution_context")
                    and dut_id
                    and collector_id
                ):
                    context = await self.orchestrator.get_collector_execution_context(
                        dut_id, collector_id
                    )
                    original_collector_id = context.get(
                        "original_collector_id", collector_id
                    )

                    # DEBUG: Log the result
                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Retrieved original_collector_id: {original_collector_id} from context for {dut_id}:{collector_id}",
                    )

                    # Return original_collector_id if available, otherwise the passed collector_id
                    return original_collector_id

                # Fallback to passed collector_id or current collector ID
                fallback_id = collector_id or self._get_current_collector_id()
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Using fallback collector ID: {fallback_id}",
                )
                return fallback_id
        except Exception as e:
            await self._log_runtime(
                "ERROR", "BaseService", f"Error getting original collector ID: {e}"
            )

        await self._log_runtime(
            "DEBUG", "BaseService", "Returning 'unknown' for original collector ID"
        )
        return "unknown"

    def _get_current_dut_id(self) -> str:
        """
        Get the current DUT ID from context if available.

        Returns:
            str: Current DUT ID
        """
        try:
            # Try to get from orchestrator context
            if hasattr(self, "orchestrator") and self.orchestrator:
                # Check if orchestrator has current execution context
                if hasattr(self.orchestrator, "current_execution_context"):
                    return self.orchestrator.current_execution_context.get(
                        "dut_id", "unknown"
                    )
        except Exception:
            pass

        return "unknown"

    async def _log_collection_summary(
        self,
        dut_id: str,
        collection_name: str,
        total_operations: int,
        successful_operations: int,
        failed_operations: int,
        skipped_operations: int = 0,
        output_files_count: int = 0,
        additional_details: Dict[str, Any] = None,
    ) -> None:
        """
        Log a standardized collection summary similar to host service pattern.

        Args:
            dut_id: DUT identifier
            collection_name: Name of the collection operation
            total_operations: Total number of operations attempted
            successful_operations: Number of successful operations
            failed_operations: Number of failed operations
            skipped_operations: Number of skipped operations
            output_files_count: Number of output files generated
            additional_details: Additional details to include in summary
        """
        success_rate = (
            (successful_operations / total_operations * 100)
            if total_operations > 0
            else 0
        )

        # Single-line summary at INFO; full breakdown at DEBUG
        summary = (
            f"{collection_name}: {successful_operations}/{total_operations} succeeded"
        )
        if failed_operations:
            summary += f", {failed_operations} failed"
        if skipped_operations:
            summary += f", {skipped_operations} skipped"
        summary += f" ({output_files_count} files, {success_rate:.0f}%)"

        await self._log_runtime(
            "INFO" if not failed_operations else "WARN",
            self.service_name,
            summary,
            dut_id,
        )

        if additional_details:
            for key, value in additional_details.items():
                await self._log_runtime(
                    "DEBUG", self.service_name, f"{key}: {value}", dut_id
                )

    async def _save_collection_summary_json(
        self,
        dut_id: str,
        collection_name: str,
        total_operations: int,
        successful_operations: int,
        failed_operations: int,
        skipped_operations: int = 0,
        output_files: List[str] = None,
        additional_details: Dict[str, Any] = None,
        output_dir: str = None,
    ) -> str:
        """
        Save a JSON summary file for the collection operation.

        Args:
            dut_id: DUT identifier
            collection_name: Name of the collection operation
            total_operations: Total number of operations attempted
            successful_operations: Number of successful operations
            failed_operations: Number of failed operations
            skipped_operations: Number of skipped operations
            output_files: List of output files generated
            additional_details: Additional details to include in summary
            output_dir: Directory to save the summary file

        Returns:
            Path to the saved summary file
        """
        import json
        import os
        from datetime import datetime

        # Calculate success rate
        success_rate = (
            (successful_operations / total_operations * 100)
            if total_operations > 0
            else 0
        )

        summary_data = {
            "collection_name": collection_name,
            "dut_id": dut_id,
            "timestamp": datetime.now().isoformat(),
            "statistics": {
                "total_operations": total_operations,
                "successful_operations": successful_operations,
                "failed_operations": failed_operations,
                "skipped_operations": skipped_operations,
                "success_rate_percent": round(success_rate, 1),
            },
            "output_files": output_files or [],
            "additional_details": additional_details or {},
        }

        # Determine output directory
        if not output_dir:
            # Try to get the current output directory from the logger
            if (
                hasattr(self, "logger")
                and self.logger
                and hasattr(self.logger, "output_dir")
            ):
                output_dir = str(self.logger.output_dir)
            else:
                output_dir = f"logs/{dut_id}_collection_summary"

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Generate filename
        safe_name = collection_name.lower().replace(" ", "_").replace("/", "_")
        filename = f"{safe_name}_summary.json"
        filepath = os.path.join(output_dir, filename)

        # Save JSON file
        try:
            with open(filepath, "w") as f:
                json.dump(summary_data, f, indent=2)

            await self._log_runtime(
                "INFO",
                self.service_name,
                f"Collection summary saved to: {filepath}",
                dut_id,
            )
            return filepath
        except Exception as e:
            await self._log_runtime(
                "WARNING",
                self.service_name,
                f"Failed to save collection summary: {e}",
                dut_id,
            )
            return ""

    async def _save_collection_summary_text(
        self,
        dut_id: str,
        collection_name: str,
        total_operations: int,
        successful_operations: int,
        failed_operations: int,
        skipped_operations: int = 0,
        output_files: List[str] = None,
        additional_details: Dict[str, Any] = None,
        output_dir: str = None,
    ) -> str:
        """
        Save a text summary file for the collection operation (similar to host service approach).

        Args:
            dut_id: DUT identifier
            collection_name: Name of the collection operation
            total_operations: Total number of operations attempted
            successful_operations: Number of successful operations
            failed_operations: Number of failed operations
            skipped_operations: Number of skipped operations
            output_files: List of output files generated
            additional_details: Additional details to include in summary
            output_dir: Directory to save the summary file

        Returns:
            Path to the saved summary file
        """
        import os
        from datetime import datetime

        # Calculate success rate
        success_rate = (
            (successful_operations / total_operations * 100)
            if total_operations > 0
            else 0
        )

        # Create summary content
        summary_lines = [
            f"{collection_name} Summary",
            "=" * (len(collection_name) + 8),
            "",
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"DUT ID: {dut_id}",
            "",
            "Statistics:",
            f"  Total operations: {total_operations}",
            f"  Successful operations: {successful_operations}",
            f"  Failed operations: {failed_operations}",
        ]

        if skipped_operations > 0:
            summary_lines.append(f"  Skipped operations: {skipped_operations}")

        summary_lines.extend(
            [
                f"  Success rate: {success_rate:.1f}%",
                f"  Output files generated: {len(output_files) if output_files else 0}",
                "",
            ]
        )

        # Add additional details if provided
        if additional_details:
            summary_lines.append("Additional Details:")
            for key, value in additional_details.items():
                summary_lines.append(f"  {key}: {value}")
            summary_lines.append("")

        # Add output files list if provided
        if output_files:
            summary_lines.extend(
                [
                    "Output Files:",
                    *[f"  - {file}" for file in output_files],
                    "",
                ]
            )

        summary_content = "\n".join(summary_lines)

        # Determine output directory
        if not output_dir:
            # Try to get the current output directory from the logger
            if (
                hasattr(self, "logger")
                and self.logger
                and hasattr(self.logger, "output_dir")
            ):
                output_dir = str(self.logger.output_dir)
            else:
                output_dir = f"logs/{dut_id}_collection_summary"

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Generate filename
        safe_name = collection_name.lower().replace(" ", "_").replace("/", "_")
        filename = f"{safe_name}_summary.txt"
        filepath = os.path.join(output_dir, filename)

        # Save text file
        try:
            with open(filepath, "w") as f:
                f.write(summary_content)

            await self._log_runtime(
                "INFO",
                self.service_name,
                f"Collection summary saved to: {filepath}",
                dut_id,
            )
            return filepath
        except Exception as e:
            await self._log_runtime(
                "WARNING",
                self.service_name,
                f"Failed to save collection summary: {e}",
                dut_id,
            )
            return ""

    async def _create_generic_collection_summary(
        self,
        function_tag: str,
        collection_type: str,
        search_info: Dict[str, Any],
        results: Dict[str, Any],
        ignore_empty_results: bool,
        collector_config: Dict[str, Any] = None,
        total_operations: int = None,
        successful_operations: int = None,
    ) -> str:
        """
        Create a standardized summary for any collection operation.

        This is a truly generic function that can be used by any collector
        to provide consistent summary reporting. Collector-specific information
        comes from the collector_config parameter.

        Args:
            function_tag: The function tag/collector name
            collection_type: Type of collection (file_collection, file_search_and_archive, etc.)
            search_info: Information about what was searched (patterns, directories, etc.)
            results: Information about what was found/collected
            ignore_empty_results: Whether empty results are treated as expected
            collector_config: Optional collector configuration for custom messages

        Returns:
            Formatted summary string
        """
        # Get collector-specific information from config
        if collector_config:
            collector_name = collector_config.get("name", function_tag)
            description = collector_config.get(
                "description", f"{collection_type} collection"
            )

            # Custom messages from collector config
            empty_expected_note = collector_config.get(
                "empty_expected_note",
                "No files found. This is expected behavior for this collector.",
            )
            empty_unexpected_note = collector_config.get(
                "empty_unexpected_note",
                "No files found. This may indicate missing files or configuration issues.",
            )
            success_note = collector_config.get(
                "success_note", "Collection completed successfully."
            )
        else:
            collector_name = function_tag
            description = f"{collection_type} collection"
            empty_expected_note = (
                "No files found. This is expected behavior for this collector."
            )
            empty_unexpected_note = "No files found. This may indicate missing files or configuration issues."
            success_note = "Collection completed successfully."

        summary_lines = [
            f"{collector_name.title()} Collection Summary",
            "=" * (len(collector_name) + 20),
            "",
            f"Collection Type: {collection_type}",
            f"Description: {description}",
            "",
        ]

        # Add search information based on collection type
        if collection_type == "file_collection":
            file_patterns = search_info.get("file_patterns", [])
            collected_files = results.get("collected_files", [])
            empty_patterns = results.get("empty_patterns", [])

            summary_lines.extend(
                [
                    f"Total Patterns Searched: {len(file_patterns)}",
                    f"Files Found: {len(collected_files)}",
                    f"Empty Patterns: {len(empty_patterns)}",
                    "",
                ]
            )

            if empty_patterns:
                summary_lines.extend(
                    [
                        "Patterns with no files found:",
                        *[f"- {pattern}" for pattern in empty_patterns],
                        "",
                    ]
                )

            if collected_files:
                summary_lines.extend(
                    [
                        "Files successfully collected:",
                        *[f"- {file}" for file in collected_files],
                        "",
                    ]
                )
            else:
                summary_lines.extend(
                    [
                        "Files successfully collected:",
                        "- None",
                        "",
                    ]
                )

        elif collection_type == "file_search_and_archive":
            file_pattern = search_info.get("file_pattern", "*")
            search_directories = search_info.get("search_directories", [])

            # Collect discovered, processed, and failed files (with graceful fallbacks).
            found_files = search_info.get("found_files") or results.get(
                "found_files", []
            )
            processed_files = search_info.get("processed_files", [])
            failed_files = search_info.get("failed_files", [])

            # Gather error messages so we can infer failed files even when only the summary runs.
            error_messages = search_info.get("error_messages") or results.get(
                "error_messages", []
            )
            if error_messages:
                failed_files_from_errors = []
                for message in error_messages:
                    match = re.search(r"Failed to process file:\s*(.+)", message)
                    if match:
                        failed_files_from_errors.append(match.group(1).strip())
                if failed_files_from_errors:
                    failed_files = (
                        failed_files or []
                    ) + failed_files_from_errors  # merge if already present

            # Ensure lists are unique while preserving order.
            def _dedupe(sequence: List[str]) -> List[str]:
                seen = set()
                ordered = []
                for item in sequence:
                    if item and item not in seen:
                        seen.add(item)
                        ordered.append(item)
                return ordered

            found_files = _dedupe(found_files or [])
            processed_files = _dedupe(processed_files or [])
            failed_files = _dedupe(failed_files or [])

            # If we only know about failures, treat them as discovered files for reporting.
            if not found_files and failed_files:
                found_files = failed_files.copy()

            processed_set = set(processed_files)
            failed_set = set(failed_files)

            summary_lines.extend(
                [
                    f"Search Pattern: {file_pattern}",
                    f"Search Directories: {', '.join(search_directories) or '(none)'}",
                    f"Files Found: {len(found_files)}",
                    "",
                ]
            )

            if found_files:
                summary_lines.append("Files discovered:")
                for file in found_files:
                    suffix = ""
                    if file in failed_set and file in processed_set:
                        suffix = " (processing failed after partial transfer)"
                    elif file in failed_set:
                        suffix = " (processing failed)"
                    elif file in processed_set:
                        suffix = " (processed)"
                    summary_lines.append(f"- {file}{suffix}")
                summary_lines.append("")
            else:
                summary_lines.extend(
                    [
                        "Files discovered:",
                        "- None",
                        "",
                    ]
                )

        # Add appropriate note based on results and configuration
        # Use search_info for emptiness checks so summaries reflect archived content
        has_empty_results = (
            collection_type == "file_collection"
            and (search_info.get("empty_patterns") or [])
        ) or (collection_type == "file_search_and_archive" and not found_files)

        # Determine status note - CHECK EMPTY RESULTS FIRST before operation counts
        # This ensures that when no files are found, we show the appropriate message
        # instead of generic "All operations completed successfully"
        if has_empty_results and ignore_empty_results:
            status_note = empty_expected_note
        elif has_empty_results:
            status_note = empty_unexpected_note
        elif total_operations is not None and successful_operations is not None:
            if total_operations == 0:
                status_note = "No operations attempted."
            elif successful_operations == 0:
                status_note = "All operations failed."
            elif successful_operations < total_operations:
                status_note = f"Partial success: {successful_operations}/{total_operations} operations succeeded."
            else:
                status_note = (
                    f"All {successful_operations} operations completed successfully."
                )
        else:
            status_note = success_note

        summary_lines.extend(
            [
                f"Note: {status_note}",
            ]
        )

        return "\n".join(summary_lines)

    async def _log_runtime(
        self,
        level: str,
        component: str,
        message: str,
        dut_id: str = None,
        collector_id: str = None,
    ) -> None:
        """
        Safely log runtime messages using self.logger if available with automatic DUT ID and collector ID.

        Args:
            level: Level of the message
            component: Component of the message
            message: Message to log
            dut_id: DUT identifier
            collector_id: Collector identifier
        """
        # Auto-detect dut_id if not provided
        if dut_id is None:
            dut_id = self._get_current_dut_id()

        # Auto-detect collector_id if not provided
        if collector_id is None:
            # Try to get from per-collector context first, then fallback to global context
            if (
                dut_id
                and hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "get_collector_execution_context")
            ):
                # Try to get the current collector ID from the global context first
                current_collector_id = self._get_current_collector_id()
                if current_collector_id != "unknown":
                    # Get the per-collector context to find the original collector ID
                    try:
                        context = (
                            await self.orchestrator.get_collector_execution_context(
                                dut_id, current_collector_id
                            )
                        )
                        original_collector_id = context.get(
                            "original_collector_id", current_collector_id
                        )
                        collector_id = original_collector_id
                    except Exception:
                        # Fallback to global context if per-collector context fails
                        collector_id = current_collector_id
                else:
                    collector_id = current_collector_id
            else:
                collector_id = self._get_current_collector_id()

        if self.logger:
            try:
                if dut_id and dut_id != "unknown":
                    await self.logger.write_to_dut_runtime_log(
                        dut_id, level, component, message, collector_id
                    )
                else:
                    await self.logger.log_runtime(level, component, message)
            except Exception as e:
                # Fallback to standard logger if async logger fails
                logger.error(f"Failed to log runtime via async logger: {e}")
                logger.info(f"{level} [{component}] {message}")
        else:
            # Fallback to standard logger if self.logger not available
            logger.info(f"{level} [{component}] {message}")

    def _extract_error_details(self, response: Any) -> str:
        """
        Extract detailed error information from API response (DRY pattern for all services).

        Args:
            response: API response
        """
        error_details = ""

        if isinstance(response, dict):
            # Handle empty response (common with 400 errors)
            if not response or response == {}:
                error_details = "HTTP 400: Empty response - likely unsupported diagnostic data type or invalid payload"
                logger.warning(f"Empty response received: {error_details}")
                return error_details

            # Try common error response patterns
            if "error" in response:
                error_obj = response["error"]
                if isinstance(error_obj, dict):
                    error_code = error_obj.get("code", "Unknown")
                    error_message = error_obj.get("message", str(response))
                    error_details = f"Code: {error_code}, Message: {error_message}"
                    logger.error(f"API Error Response: {error_details}")
                    logger.debug(f"Full error object: {error_obj}")
                else:
                    error_details = f"Error: {error_obj}"
                    logger.error(f"API Error Response: {error_details}")
            elif "code" in response and "message" in response:
                # Direct error response format
                error_details = (
                    f"Code: {response['code']}, Message: {response['message']}"
                )
                logger.error(f"API Error Response: {error_details}")
                logger.debug(f"Full error response: {response}")
            elif "HTTPStatus" in response:
                # Redfish error response format
                status = response.get("HTTPStatus", "Unknown")
                message = response.get("Message", "No message provided")
                error_details = f"HTTP {status}: {message}"
                logger.error(f"Redfish Error Response: {error_details}")
                logger.debug(f"Full Redfish error response: {response}")
            else:
                error_details = str(response)
                logger.warning(
                    f"Unknown error response format in BaseService._extract_error_details: {error_details}"
                )
                logger.debug(f"Full response: {response}")
        else:
            error_details = str(response)
            logger.warning(f"Non-dict error response: {error_details}")

        return error_details

    async def _get_current_timestamp(self) -> str:
        """
        Get current timestamp in ISO format.

        Returns:
            str: Current timestamp in ISO format
        """
        return datetime.now().isoformat()

    async def _save_failures_json(
        self,
        dut_id: str,
        collector_name: str,
        failure_details: list,
        collector_id: str = None,
    ) -> None:
        """
        Save detailed failure information to failures.json file.

        Args:
            dut_id: DUT identifier
            collector_name: Name of the collector
            failure_details: List of failure details
            collector_id: Collector identifier
        """
        if not failure_details:
            return

        try:
            # Create failures data structure
            failures_data = {
                "collector": collector_name,
                "dut_id": dut_id,
                "timestamp": await self._get_current_timestamp(),
                "total_failures": len(failure_details),
                "failures": failure_details,
            }

            # Save to failures.json file
            file_path = await self._save_data_with_common_pattern(
                dut_id,
                failures_data,
                collector_name,
                output_pattern="failures.json",
                substitutions={"collector": collector_name, "dut_id": dut_id},
                collector_id=collector_id,
            )

            if file_path:
                await self._log_runtime(
                    "INFO",
                    "BaseService",
                    f"Saved {len(failure_details)} failure details to {file_path}",
                    dut_id,
                )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Failed to save failures.json: {str(e)}",
                dut_id,
            )

    async def _handle_collector_completion(
        self,
        dut_id: str,
        collector_name: str,
        successful_operations: int,
        total_operations: int,
        output_files: list,
        error_messages: list,
        operation_name: str = "collector",
        additional_context: dict = None,
    ) -> dict:
        """
        Generic helper method for handling collector completion with summary generation and failure tracking

        This method can be used by any collector to:
        1. Generate summary files (text and JSON)
        2. Save detailed failure information to failures.json
        3. Create standardized collector results

        Args:
            dut_id: DUT identifier
            collector_name: Name of the collector
            successful_operations: Number of successful operations
            total_operations: Total number of operations attempted
            output_files: List of output files generated
            error_messages: List of error messages
            operation_name: Name of the operation (default: "collector")
            additional_context: Additional context for the result

        Returns:
            Standardized collector result dictionary
        """
        try:
            # Create detailed failure information for failures.json
            failure_details = []
            if error_messages:
                for i, error_msg in enumerate(error_messages):
                    failure_details.append(
                        {
                            "failure_id": i + 1,
                            "error_message": error_msg,
                            "timestamp": await self._get_current_timestamp(),
                            "collector": collector_name,
                            "dut_id": dut_id,
                        }
                    )

            # Determine status
            if total_operations == 0:
                status = "skipped"
                reason = (
                    f"No operations attempted for {collector_name} - collector skipped"
                )
            elif successful_operations == 0:
                status = "error"
                reason = (
                    f"All {total_operations} operations failed for {collector_name}"
                )
            elif successful_operations < total_operations:
                status = "partial"
                reason = f"{successful_operations}/{total_operations} operations succeeded for {collector_name}"
            else:
                status = "success"
                reason = (
                    f"All {total_operations} operations succeeded for {collector_name}"
                )

            # Log completion
            await self._log_runtime(
                "INFO",
                "BaseService",
                f"Completed {collector_name} - {successful_operations}/{total_operations} operations succeeded ({status})",
                dut_id,
            )

            # Generate summary files
            await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=collector_name,
                collection_name=f"{collector_name} Collection",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=total_operations - successful_operations,
                output_files=output_files,
                additional_details={"error_messages": error_messages},
                kwargs={},
            )

            # Save failures.json if there are failures
            if failure_details:
                await self._save_failures_json(dut_id, collector_name, failure_details)

            # Create standardized result
            result_context = {
                "total_operations": total_operations,
                "successful_operations": successful_operations,
                "status": status,
                "reason": reason,
            }

            if additional_context:
                result_context.update(additional_context)

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name=operation_name,
                additional_context=result_context,
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Exception in _handle_collector_completion: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"Exception in collector completion: {str(e)}"],
                operation_name=operation_name,
                additional_context={},
            )

    async def _extract_error_details_async(
        self, response: Any, dut_id: str = "unknown", context: str = ""
    ) -> str:
        """
        Extract detailed error information from API response with async logging (DRY pattern for all services).

        Args:
            response: API response
            dut_id: DUT identifier
            context: Context of the error
        """
        error_details = ""

        if isinstance(response, dict):
            # Handle empty response (common with 400 errors)
            if not response or response == {}:
                error_details = "HTTP 400: Empty response - likely unsupported diagnostic data type or invalid payload"
                await self._log_runtime(
                    "WARNING",
                    "BaseService",
                    f"{context} Empty response received: {error_details}",
                    dut_id,
                )
                return error_details

            # Try common error response patterns
            if "error" in response:
                error_obj = response["error"]
                if isinstance(error_obj, dict):
                    error_code = error_obj.get("code", "Unknown")
                    error_message = error_obj.get("message", str(response))
                    error_details = f"Code: {error_code}, Message: {error_message}"
                    await self._log_runtime(
                        "ERROR",
                        "BaseService",
                        f"{context} API Error Response: {error_details}",
                        dut_id,
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"{context} Full error object: {error_obj}",
                        dut_id,
                    )
                else:
                    error_details = f"Error: {error_obj}"
                    await self._log_runtime(
                        "ERROR",
                        "BaseService",
                        f"{context} API Error Response: {error_details}",
                        dut_id,
                    )
            elif "code" in response and "message" in response:
                # Direct error response format
                error_details = (
                    f"Code: {response['code']}, Message: {response['message']}"
                )
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"{context} API Error Response: {error_details}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"{context} Full error response: {response}",
                    dut_id,
                )
            elif "HTTPStatus" in response:
                # Redfish error response format
                status = response.get("HTTPStatus", "Unknown")
                message = response.get("Message", "No message provided")
                error_details = f"HTTP {status}: {message}"
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"{context} Redfish Error Response: {error_details}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"{context} Full Redfish error response: {response}",
                    dut_id,
                )
            else:
                error_details = str(response)
                await self._log_runtime(
                    "WARNING",
                    "BaseService",
                    f"{context} Unknown error response format in BaseService._extract_error_details_async: {error_details}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"{context} Full response: {response}",
                    dut_id,
                )
        else:
            error_details = str(response)
            await self._log_runtime(
                "WARNING",
                "BaseService",
                f"{context} Non-dict error response: {error_details}",
                dut_id,
            )

        return error_details

    async def create_redfish_session(self) -> bool:
        """
        Create persistent Redfish session (like legacy nvdebug) - Now uses session pool.

        Args:
            None
        """
        try:
            if self.redfish_session is not None:
                return True  # Session already exists

            await self._log_runtime(
                "INFO", "BaseService", "Testing Redfish session pool"
            )

            # Get connection info (handles HMC transparency)
            connection_info = self.get_redfish_connection_info()

            # Setup authentication for session pool
            username = connection_info["username"]
            password = connection_info["password"]
            if connection_info.get("auth_enabled", True) and username and password:
                self.redfish_auth = aiohttp.BasicAuth(username, password)
            else:
                self.redfish_auth = None

            # Test the session pool with a simple request
            protocol = "https" if connection_info["use_https"] else "http"
            test_url = f"{protocol}://{connection_info['host']}:{connection_info['port']}/redfish/v1"

            # Use the session pool instead of creating a separate session
            if hasattr(self, "dut_manager") and self.dut_manager:
                dut = self.dut_manager.get_dut(self.dut_id)
                if dut and dut.redfish_session_pool:
                    # Test using session pool
                    session_obj = await dut.redfish_session_pool.get_session()
                    if session_obj:
                        try:
                            async with session_obj["session"].get(
                                test_url, auth=session_obj["auth"], ssl=dut.redfish_ssl
                            ) as response:
                                if response.status == 200:
                                    await self._log_runtime(
                                        "INFO",
                                        "BaseService",
                                        "Redfish session pool test successful",
                                    )
                                    return True
                                else:
                                    await self._log_runtime(
                                        "ERROR",
                                        "BaseService",
                                        f"Redfish session pool test failed: HTTP {response.status}",
                                    )
                                    return False
                        except Exception as e:
                            raise e
                    else:
                        await self._log_runtime(
                            "ERROR",
                            "BaseService",
                            "Failed to get session from pool for testing",
                        )
                        return await self._create_fallback_session(connection_info)
                else:
                    await self._log_runtime(
                        "WARNING",
                        "BaseService",
                        "Session pool not available, using fallback",
                    )
                    return await self._create_fallback_session(connection_info)
            else:
                await self._log_runtime(
                    "WARNING",
                    "BaseService",
                    "DUT manager not available, using fallback",
                )
                return await self._create_fallback_session(connection_info)

        except Exception as e:
            await self._log_runtime(
                "ERROR", "BaseService", f"Failed to create Redfish session: {str(e)}"
            )
            return await self._create_fallback_session(connection_info)

    async def _create_fallback_session(self, connection_info: Dict[str, Any]) -> bool:
        """
        Create fallback session when session pool is not available.

        Args:
            connection_info: Connection information
        """
        try:
            await self._log_runtime(
                "INFO", "BaseService", "Creating fallback Redfish session"
            )

            # Get session configuration from DUTManager if available
            session_config = {}
            if self.dut_manager and hasattr(self.dut_manager, "redfish_session_config"):
                session_config = self.dut_manager.redfish_session_config

            # Create connector with configurable settings (fallback to defaults)
            self.redfish_connector = aiohttp.TCPConnector(
                ssl=session_config.get(
                    "ssl_verify", session_config.get("ssl", False)
                ),  # Configurable SSL verification
                limit=session_config.get(
                    "fallback_connection_pool_limit", 15
                ),  # Configurable fallback connection pool size
                limit_per_host=session_config.get(
                    "fallback_connection_pool_limit_per_host", 6
                ),  # Configurable fallback connections per host
                ttl_dns_cache=session_config.get(
                    "ttl_dns_cache", 300
                ),  # Configurable DNS cache TTL
                use_dns_cache=session_config.get(
                    "use_dns_cache", True
                ),  # Configurable DNS caching
                force_close=session_config.get(
                    "force_close", False
                ),  # Configurable connection reuse
                enable_cleanup_closed=session_config.get(
                    "enable_cleanup_closed", True
                ),  # Configurable cleanup
                keepalive_timeout=session_config.get(
                    "keepalive_timeout", 300
                ),  # Configurable keepalive timeout
            )

            # Create session with persistent settings
            self.redfish_session = aiohttp.ClientSession(
                connector=self.redfish_connector,
                timeout=aiohttp.ClientTimeout(
                    total=session_config.get("session_timeout", 300)
                ),  # Configurable session timeout
                headers={"User-Agent": "nvdebug/1.0"},
            )

            # Test the session with a simple request
            protocol = "https" if connection_info["use_https"] else "http"
            test_url = f"{protocol}://{connection_info['host']}:{connection_info['port']}/redfish/v1"

            async with self.redfish_session.get(
                test_url,
                auth=self.redfish_auth,
                ssl=session_config.get("ssl_verify", session_config.get("ssl", False)),
            ) as response:
                if response.status == 200:
                    await self._log_runtime(
                        "INFO",
                        "BaseService",
                        "Fallback Redfish session created successfully",
                    )
                    return True
                else:
                    await self._log_runtime(
                        "ERROR",
                        "BaseService",
                        f"Fallback Redfish session test failed: HTTP {response.status}",
                    )
                    await self.close_redfish_session()
                    return False

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Failed to create fallback Redfish session: {str(e)}",
            )
            await self.close_redfish_session()
            return False

    async def close_redfish_session(self) -> None:
        """
        Close Redfish session (like legacy nvdebug logout).

        Args:
            None
        """
        try:
            if hasattr(self, "redfish_session") and self.redfish_session:
                await self.redfish_session.close()
                self.redfish_session = None
                await self._log_runtime("INFO", "BaseService", "Redfish session closed")

            if hasattr(self, "redfish_connector") and self.redfish_connector:
                await self.redfish_connector.close()
                self.redfish_connector = None

            # Also close any other sessions that might exist
            if hasattr(self, "session") and self.session:
                await self.session.close()
                self.session = None
                await self._log_runtime("INFO", "BaseService", "General session closed")

        except Exception as e:
            await self._log_runtime(
                "ERROR", "BaseService", f"Error closing Redfish session: {str(e)}"
            )

    def normalize_redfish_uri(self, uri: str, ignore_prefix: bool = False) -> str:
        """
        Normalize Redfish URI with prefix handling (like legacy nvdebug).

        Args:
            uri: URI to normalize
            ignore_prefix: Whether to ignore the prefix
        """
        if ignore_prefix:
            return uri

        # Handle prefix substitution like legacy nvdebug
        if (
            self.redfish_default_prefix != "/redfish/v1"
            and not uri.startswith(self.redfish_default_prefix)
            and "redfish/v1" in uri
        ):
            # Substitute prefix up to /redfish/v1 with the configured prefix
            uri = re.sub(r"(\S)*redfish/v1", self.redfish_default_prefix, uri, 1)
            asyncio.create_task(
                self._log_runtime("DEBUG", "BaseService", f"Normalized URI: {uri}")
            )

        return uri

    def reset_redfish_cache(self) -> None:
        """
        Reset Redfish cache (like legacy nvdebug).

        Args:
            None
        """
        self.__redfish_cache.clear()
        asyncio.create_task(
            self._log_runtime("INFO", "BaseService", "Redfish cache cleared")
        )

    def get_redfish_cache(self) -> Dict[str, Any]:
        """
        Get Redfish cache (like legacy nvdebug).

        Args:
            None
        """
        return self.__redfish_cache.copy()

    def _get_cached_response(self, uri: str) -> Optional[Any]:
        """
        Get cached response for URI.

        Args:
            uri: URI to get cached response for
        """
        return self.__redfish_cache.get(uri)

    def _cache_response(self, uri: str, response: Any) -> None:
        """
        Cache response for URI.

        Args:
            uri: URI to cache response for
            response: Response to cache
        """
        self.__redfish_cache[uri] = response

    async def _log_collector_result(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str,
        execution_time: float,
        output_files: List[str] = None,
        context: Dict[str, Any] = None,
        discovered_files: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """
        Safely log collector results using self.logger if available.

        Args:
            dut_id: DUT identifier
            collector_id: Collector identifier
            status: Status of the collector
            reason: Reason for the status
            execution_time: Execution time of the collector
            output_files: List of output files
            context: Context of the collector
            discovered_files: Discovered files organized by folder
        """
        if self.logger:
            try:
                await self.logger.log_collector_result(
                    dut_id,
                    collector_id,
                    status,
                    reason,
                    execution_time,
                    output_files or [],
                    context or {},
                    discovered_files or {},
                )
            except Exception as e:
                # Fallback to standard logger if async logger fails
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Failed to log collector result via async logger: {e}",
                    dut_id,
                )
        else:
            # Fallback to standard logger if self.logger not available
            # Note: This is a fallback when self.logger is not available, so we can't use async logging
            logger.info(f"Collector {collector_id} on {dut_id}: {status} - {reason}")

    async def _write_to_dut_runtime_log(
        self, dut_id: str, level: str, component: str, message: str
    ) -> None:
        """
        Safely write to DUT runtime log using self.logger if available.

        Args:
            dut_id: DUT identifier
            level: Level of the message
            component: Component of the message
            message: Message to log
        """
        if self.logger:
            try:
                await self.logger.write_to_dut_runtime_log(
                    dut_id, level, component, message
                )
            except Exception as e:
                # Fallback to standard logger if async logger fails
                logger.error(f"Failed to write to DUT runtime log: {e}")
                logger.info(f"{level} [{component}] {message}")
        else:
            # Fallback to standard logger if self.logger not available
            logger.info(f"{level} [{component}] {message}")

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """
        Validate connection to DUT (to be implemented by subclasses).

        Args:
            dut_id: DUT identifier
        """
        raise NotImplementedError("Subclasses must implement validate_connection")

    async def _get_collector_timeout(
        self, collector_id: str, dut_id: str = None, default_timeout: int = 300
    ) -> int:
        """
        Get timeout from collector definition with fallback to default.
        Uses the unified timeout system that handles timeout_config parameters.

        Args:
            collector_id: The collector ID
            dut_id: The DUT ID to get configuration for (optional)
            default_timeout: Default timeout in seconds (default: 300)

        Returns:
            int: Timeout in seconds from collector definition or default
        """
        try:
            # Import here to avoid circular imports
            from ..utils.timeout_config import get_collector_timeout

            # Get collector definition from orchestrator
            collector_def = self.orchestrator.get_all_collectors().get(collector_id, {})

            # Get DUT config for timeout overrides
            dut_config = {}
            if hasattr(self, "dut_manager") and self.dut_manager and dut_id:
                # Get the specific DUT's config for timeout settings
                dut_config = self.dut_manager.get_dut_config(dut_id)
            elif hasattr(self, "dut_manager") and self.dut_manager:
                # Fallback: get the first DUT's config if no specific DUT ID provided
                all_dut_ids = self.dut_manager.get_all_dut_ids()
                if all_dut_ids:
                    dut_config = self.dut_manager.get_dut_config(all_dut_ids[0])

            # Get tool config for timeout fallback
            tool_config = self.orchestrator.config_manager.get_tool_config()

            # Use the unified timeout system
            timeout = get_collector_timeout(
                collector_id, collector_def, dut_config, default_timeout, tool_config
            )

            dut_info = f" for DUT {dut_id}" if dut_id else ""
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Using timeout {timeout}s for {collector_id}{dut_info} (from unified timeout system)",
            )
            return timeout

        except Exception as e:
            await self._log_runtime(
                "WARN",
                "BaseService",
                f"Error getting timeout for {collector_id}: {e}, using default {default_timeout}s",
            )
            return default_timeout

    async def execute_collector(
        self, dut_id: str, collector_id: str, collection_level: str = "L1"
    ) -> Dict[str, Any]:
        """
        Execute a collector on a DUT.

        Args:
            dut_id: DUT identifier
            collector_id: Collector identifier
            collection_level: Collection level
        """
        # Update variable engine with DUT-specific context
        await self._update_variable_engine(dut_id)

        start_time = asyncio.get_event_loop().time()
        await self._log_runtime(
            "INFO",
            "BaseService",
            f"Starting collector {collector_id} on DUT {dut_id}",
            dut_id,
        )
        if hasattr(self, "orchestrator") and self.orchestrator:
            try:
                await self.orchestrator.record_execution_order_entry(
                    dut_id, collector_id
                )
            except Exception:
                pass

        # Start timing for this collector
        if self.timing_manager:
            self.timing_manager.start_collector(collector_id, dut_id)

        try:
            # Get collector definition
            collector_def = self.orchestrator.get_all_collectors().get(collector_id)
            if not collector_def:
                error_reason = f"Collector {collector_id} not found in definitions"
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Collector {collector_id} not found in definitions",
                    dut_id,
                )
                await self._log_error(
                    "COLLECTOR_NOT_FOUND", error_reason, dut_id, collector_id
                )

                # Finalize collector with error status
                try:
                    await self.finalize_collector(
                        dut_id,
                        collector_id,
                        "error",
                        error_reason,
                        execution_time=0.0,
                    )
                except Exception as finalize_error:
                    await self._log_error(
                        "FINALIZE_ERROR",
                        f"Failed to finalize collector: {finalize_error}",
                        dut_id,
                        collector_id,
                    )

                if self.timing_manager:
                    self.timing_manager.end_collector(collector_id, "failed")
                return {
                    "success": False,
                    "reason": error_reason,
                    "execution_time": 0.0,
                }

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Found collector definition for {collector_id}",
                dut_id,
            )

            # Initialize context
            context = {
                "dut_id": dut_id,
                "collector_id": collector_id,
                "collection_level": collection_level,
                "service_name": self.service_name,
                "collector_def": collector_def,
                "function_tag": collector_def.get("name", collector_id),
            }

            # Attach baseboard config for downstream hooks (e.g., Redfish discovery)
            baseboard_name = ""
            baseboard_config = None
            if self.dut_manager:
                dut_config = self.dut_manager.get_dut_config(dut_id)
                if dut_config:
                    baseboard_name = dut_config.get(
                        "TargetBaseboard", dut_config.get("baseboard", "")
                    )
                baseboard_manager = None
                if hasattr(self.dut_manager, "_get_baseboard_manager"):
                    baseboard_manager = self.dut_manager._get_baseboard_manager()
                elif hasattr(self.dut_manager, "get_baseboard_manager"):
                    baseboard_manager = self.dut_manager.get_baseboard_manager()
                if baseboard_manager and baseboard_name:
                    baseboard_config = baseboard_manager.get_baseboard_config(
                        baseboard_name
                    )

            if baseboard_config:
                context["baseboard_config"] = baseboard_config
                context["baseboard_specific_config"] = {
                    baseboard_name: baseboard_config
                }

            # Check dependencies
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Checking dependencies for {collector_id}",
                dut_id,
            )
            dependency_result = await self._check_collector_dependencies(
                collector_id, context
            )

            # Store detailed dependency results for metadata writing
            context["dependency_result"] = dependency_result

            # Write dependency results to metadata
            await self._write_collector_dependency_metadata(
                collector_id, dependency_result, dut_id
            )

            if dependency_result["status"] == "fail":
                error_reason = (
                    f"Dependency check failed: {dependency_result['missing_required']}"
                )
                await self._log_runtime(
                    "WARN",
                    "BaseService",
                    f"Dependency check failed for {collector_id}: {dependency_result['missing_required']}",
                    dut_id,
                )

                # Finalize collector with skipped status for dependency failures
                if self.logger:
                    try:
                        await self.finalize_collector(
                            dut_id,
                            collector_id,
                            "skipped",
                            error_reason,
                            execution_time=0.0,
                        )
                    except Exception as finalize_error:
                        await self._log_runtime(
                            "ERROR",
                            "BaseService",
                            f"Failed to finalize collector: {finalize_error}",
                            dut_id,
                        )

                if self.timing_manager:
                    self.timing_manager.end_collector(collector_id, "skipped")
                return {
                    "success": False,
                    "status": "skipped",
                    "reason": error_reason,
                    "execution_time": 0.0,
                }

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Dependencies satisfied for {collector_id}",
                dut_id,
            )

            # Execute stages
            stages = ["validation", "discovery", "execution", "post_processing"]
            output_files = []  # Collect output files from execution stage

            for stage in stages:
                if stage in collector_def.get("stages", {}):
                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Executing stage {stage} for {collector_id}",
                        dut_id,
                    )

                    # Start timing for this stage
                    if self.timing_manager:
                        self.timing_manager.start_stage(stage)

                    stage_result = await self._execute_stage(
                        stage, collector_def, context
                    )

                    # End timing for this stage
                    if self.timing_manager:
                        self.timing_manager.end_stage(stage)

                    if not stage_result["success"]:
                        reason = stage_result.get("reason", "No reason provided")
                        await self._log_runtime(
                            "ERROR",
                            "BaseService",
                            f"Stage {stage} failed for {collector_id}: {reason}",
                            dut_id,
                        )
                        await self._log_error(
                            "STAGE_ERROR",
                            f"Stage {stage} failed for {collector_id}: {reason}",
                            dut_id,
                            collector_id,
                        )

                        error_reason = f"Stage {stage} failed: {reason}"
                        execution_time = asyncio.get_event_loop().time() - start_time

                        # Prepare context for error logging
                        error_context = {
                            "operation_name": f"collector_stage_{stage}",
                            "execution_time": execution_time,
                            "stage": stage,
                            "stage_result": stage_result,
                            "collection_level": collection_level,
                        }

                        # Log error to error-logs directory
                        if self.logger:
                            try:
                                error_log_path = await self._log_collector_error(
                                    dut_id, collector_id, error_reason, error_context
                                )
                            except Exception as log_error:
                                await self._log_runtime(
                                    "ERROR",
                                    "BaseService",
                                    f"Failed to log stage error: {log_error}",
                                    dut_id,
                                )
                                error_log_path = ""

                        # Finalize collector with error status
                        if self.logger:
                            try:
                                await self.finalize_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    error_reason,
                                    execution_time=execution_time,
                                    output_files=(
                                        [error_log_path] if error_log_path else []
                                    ),
                                )
                            except Exception as finalize_error:
                                await self._log_runtime(
                                    "ERROR",
                                    "BaseService",
                                    f"Failed to finalize collector: {finalize_error}",
                                    dut_id,
                                )

                        if self.timing_manager:
                            self.timing_manager.end_collector(collector_id, "failed")
                        return {
                            "success": False,
                            "reason": error_reason,
                            "execution_time": execution_time,
                        }
                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Stage {stage} completed for {collector_id}",
                        dut_id,
                    )

                    # Store stage results with stage-specific keys to avoid overwriting
                    stage_context = stage_result.get("context", {})

                    # FIX: Copy top-level status and reason from stage_result into stage_context
                    # so they can be propagated to the main context through the loop below.
                    # This handles the case where _create_standardized_collector_result returns
                    # status/reason at the top level but not inside the context dict.
                    if "status" in stage_result and "status" not in stage_context:
                        stage_context["status"] = stage_result["status"]
                    if "reason" in stage_result and "reason" not in stage_context:
                        stage_context["reason"] = stage_result["reason"]

                    # FIX: If stage_result is missing status but has success, add status to stage_result and stage_context
                    # This must be done BEFORE the context update loop so the status field gets processed
                    if "status" not in stage_result and "success" in stage_result:
                        # Check if we can determine status from the context or success flag
                        if stage_context.get(
                            "successful_operations"
                        ) and stage_context.get("total_operations"):
                            successful = stage_context.get("successful_operations", 0)
                            total = stage_context.get("total_operations", 0)
                            if successful == 0:
                                stage_result["status"] = "error"
                                stage_context["status"] = "error"
                            elif successful < total:
                                stage_result["status"] = "partial"
                                stage_context["status"] = "partial"
                            else:
                                stage_result["status"] = "success"
                                stage_context["status"] = "success"
                            # print(f"DEBUG: Added missing status to stage_result and stage_context: '{stage_result['status']}' based on {successful}/{total} operations")
                        else:
                            # For stages without operation counts (like validation), use the success flag directly
                            if stage_result.get("success", False):
                                stage_result["status"] = "success"
                                stage_context["status"] = "success"
                            else:
                                stage_result["status"] = "error"
                                stage_context["status"] = "error"

                    context[f"{stage}_result"] = stage_context

                    # Update main context, but be smart about 'reason' and 'status' fields
                    # Allow execution stage to override validation stage reason and status
                    # print(f"DEBUG: Processing context update for stage='{stage}', stage_context keys: {list(stage_context.keys())}")
                    for key, value in stage_context.items():
                        # print(f"DEBUG: Processing key='{key}', value='{value}', stage='{stage}'")
                        if key == "reason" and stage == "validation":
                            # For validation stage, only store reason if it's not a skip message
                            if not any(
                                skip_msg in str(value).lower()
                                for skip_msg in [
                                    "already validated",
                                    "validation skipped",
                                    "skipping validation",
                                ]
                            ):
                                context[key] = value
                                # print(f"DEBUG: Updated context with validation stage reason: '{value}'")
                        elif key == "reason" and stage == "execution":
                            # Execution stage reason always takes precedence
                            context[key] = value
                            # print(f"DEBUG: Updated context with execution stage reason: '{value}'")
                        elif key == "status" and stage == "execution":
                            # Execution stage status always takes precedence
                            context[key] = value
                            # print(f"DEBUG: Updated context with execution stage status: '{value}'")
                        elif key == "skip_reasons":
                            context[f"{stage}_skip_reasons"] = value
                            if stage == "execution":
                                context[key] = value
                        elif key not in context:
                            # For other fields, store if not already present
                            context[key] = value
                            # print(f"DEBUG: Updated context with new field '{key}': '{value}'")

                    # Debug logging after context update
                    # if stage == "execution":
                    #     print(f"DEBUG: context after update: {context.get('status', 'NOT_FOUND')}")

                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Stage {stage} result for {collector_id}: {stage_result}",
                        dut_id,
                    )

                    # Collect output files from execution stage
                    if stage == "execution":
                        stage_context = stage_result.get("context", {})

                        # Preserve the execution stage status for final status determination
                        execution_stage_status = stage_result.get("status")
                        if execution_stage_status:
                            context["execution_stage_status"] = execution_stage_status
                            await self._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"Preserved execution stage status: {execution_stage_status}",
                                dut_id,
                            )

                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Processing execution stage for {collector_id}, stage_context keys: {list(stage_context.keys())}",
                            dut_id,
                        )

                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Full stage_result for {collector_id}: {stage_result}",
                            dut_id,
                        )

                        if "output_files" in stage_context:
                            await self._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"Found {len(stage_context['output_files'])} output files in stage_context: {stage_context['output_files']}",
                                dut_id,
                            )

                            # Check for duplicates before extending
                            original_count = len(output_files)
                            output_files.extend(stage_context["output_files"])
                            new_count = len(output_files)

                            if new_count - original_count != len(
                                stage_context["output_files"]
                            ):
                                await self._log_runtime(
                                    "WARNING",
                                    "BaseService",
                                    f"Duplicate detection: Expected to add {len(stage_context['output_files'])} files, but added {new_count - original_count}",
                                    dut_id,
                                )
                        else:
                            await self._log_runtime(
                                "WARNING",
                                "BaseService",
                                f"No output_files found in stage_context for {collector_id}",
                                dut_id,
                            )

                        # Ensure aggregated output_files are reflected in main context for downstream hooks
                        if output_files:
                            # Deduplicate while preserving order
                            existing_files = context.get("output_files", [])
                            combined_files = existing_files + output_files
                            deduped = list(dict.fromkeys(combined_files))
                            context["output_files"] = deduped
                            await self._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"Synchronized {len(deduped)} output files into main context for {collector_id}",
                                dut_id,
                            )

            await self._log_runtime(
                "DEBUG", "BaseService", f"Finalizing collector {collector_id}", dut_id
            )

            # Debug: Log context overview before status determination
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Status determination for {collector_id}: context_keys={list(context.keys())}, output_files_count={len(output_files)}",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Key context values: status={context.get('status')}, execution_stage_status={context.get('execution_stage_status')}, reason={context.get('reason')}",
                dut_id,
            )

            # Determine final status based on overall collector success, not just stage status
            # Check multiple ways a collector could be skipped, but only if no output files were produced
            # However, if ignore_empty_results is True, don't treat empty output as skipped

            # First check if ignore_empty_results is set
            ignore_empty_results = False
            if "execution_result" in context:
                ignore_empty_results = context.get("execution_result", {}).get(
                    "ignore_empty_results", False
                )

            # If not found in execution_result, check the collector definition
            if not ignore_empty_results:
                collector_info = None
                if hasattr(self, "orchestrator") and self.orchestrator:
                    try:
                        collector_info = self.orchestrator.get_collector_info(
                            collector_id
                        )
                    except Exception:
                        pass

                if collector_info and "stages" in collector_info:
                    execution_stage = collector_info.get("stages", {}).get(
                        "execution", {}
                    )
                    for hook in execution_stage.get("hooks", []):
                        if (
                            "params" in hook
                            and "ignore_empty_results" in hook["params"]
                        ):
                            ignore_empty_results = hook["params"][
                                "ignore_empty_results"
                            ]
                            break

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Collector {collector_id}: ignore_empty_results={ignore_empty_results}, output_files={len(output_files)}",
                dut_id,
            )

            is_skipped = len(output_files) == 0 and (
                ("status" in context and context["status"] == "skipped")
                or (
                    "execution_stage_status" in context
                    and context["execution_stage_status"] == "skipped"
                )
                or any(
                    stage_name in context
                    and isinstance(context[stage_name], dict)
                    and context[stage_name].get("status") == "skipped"
                    for stage_name in ["execution", "post_processing", "validation"]
                )
            )

            # Override is_skipped if ignore_empty_results is True and context indicates success
            if is_skipped and ignore_empty_results:
                # Check if the context indicates this was a successful execution with empty results
                if (
                    context.get("status") == "success"
                    or context.get("execution_stage_status") == "success"
                ):
                    is_skipped = False
                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Collector {collector_id}: Treating empty results as success (ignore_empty_results=True)",
                        dut_id,
                    )

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Skip detection result for {collector_id}: is_skipped={is_skipped}",
                dut_id,
            )

            if is_skipped:
                final_status = "skipped"
                # Debug: Log context structure to understand what's available
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Context keys for skipped collector: {list(context.keys())}",
                    dut_id,
                )

                # Look for skip reason in stage contexts, prioritizing post_processing then execution
                skip_reason = None
                for stage_name in ["post_processing", "execution", "validation"]:
                    if stage_name in context and isinstance(context[stage_name], dict):
                        stage_context = context[stage_name]
                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Stage {stage_name} context: status={stage_context.get('status')}, keys={list(stage_context.keys())}",
                            dut_id,
                        )
                        if stage_context.get("status") == "skipped":
                            # Look for skip_message in the stage's finalize_collector params
                            commands = stage_context.get("commands", [])
                            await self._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"Stage {stage_name} has {len(commands)} commands",
                                dut_id,
                            )
                            for command in commands:
                                if command.get("method") == "finalize_collector":
                                    skip_message = command.get("params", {}).get(
                                        "skip_message"
                                    )
                                    await self._log_runtime(
                                        "DEBUG",
                                        "BaseService",
                                        f"Found finalize_collector with skip_message: {skip_message}",
                                        dut_id,
                                    )
                                    if skip_message:
                                        skip_reason = skip_message
                                        break
                            if skip_reason:
                                break
                            # Fallback to stage reason
                            if stage_context.get("reason"):
                                skip_reason = stage_context["reason"]
                                await self._log_runtime(
                                    "DEBUG",
                                    "BaseService",
                                    f"Using stage reason as fallback: {skip_reason}",
                                    dut_id,
                                )
                                break

                # Additional fallback: look for skip_message in hook parameters directly
                if not skip_reason:
                    for stage_name in ["post_processing", "execution", "validation"]:
                        if f"{stage_name}_hooks" in context:
                            hooks = context[f"{stage_name}_hooks"]
                            for hook in hooks:
                                if hook.get("method") == "finalize_collector":
                                    skip_message = hook.get("params", {}).get(
                                        "skip_message"
                                    )
                                    if skip_message:
                                        skip_reason = skip_message
                                        await self._log_runtime(
                                            "DEBUG",
                                            "BaseService",
                                            f"Found skip_message in hook params: {skip_reason}",
                                            dut_id,
                                        )
                                        break
                            if skip_reason:
                                break

                aggregated_skip_reasons = []
                for key in (
                    "execution_skip_reasons",
                    "skip_reasons",
                    "post_processing_skip_reasons",
                    "validation_skip_reasons",
                ):
                    values = context.get(key, [])
                    if isinstance(values, list):
                        for value in values:
                            if value and value not in aggregated_skip_reasons:
                                aggregated_skip_reasons.append(value)

                if aggregated_skip_reasons:
                    final_reason = "; ".join(aggregated_skip_reasons)
                else:
                    final_reason = skip_reason or context.get(
                        "reason", "Collector was skipped"
                    )
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Collector marked as skipped with final reason: {final_reason}",
                    dut_id,
                )
            else:
                # For non-skipped collectors, determine status based on output and errors
                total_output_files = len(output_files)
                has_errors = len(context.get("error_messages", [])) > 0

                # FIRST: Check if execution stage explicitly marked this as partial
                if context.get("execution_stage_status") == "partial":
                    final_status = "partial"
                    final_reason = context.get(
                        "reason", "Partial success with some errors"
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Using execution_stage_status 'partial' for {collector_id}",
                        dut_id,
                    )
                # If we have output files and the reason indicates success, it should be success
                elif (
                    total_output_files > 0
                    and "successfully" in context.get("reason", "").lower()
                ):
                    final_status = "success"
                    final_reason = context.get("reason", "Completed successfully")
                elif total_output_files > 0 and has_errors:
                    # Has output but also has errors - partial success
                    final_status = "partial"
                    final_reason = context.get(
                        "reason", "Partial success with some errors"
                    )
                elif total_output_files == 0 and has_errors:
                    # No output and has errors - error
                    final_status = "error"
                    final_reason = context.get("reason", "Failed to generate output")
                else:
                    # Fallback to execution stage status if available
                    if "execution_stage_status" in context:
                        final_status = context["execution_stage_status"]
                        final_reason = context.get("reason", "Completed successfully")
                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Using preserved execution stage status as fallback: {final_status}",
                            dut_id,
                        )
                    else:
                        final_status = context.get("status", "success")
                        final_reason = context.get("reason", "Completed successfully")
                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Using context status as fallback: {final_status}",
                            dut_id,
                        )

                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Final status determination: {total_output_files} files, has_errors={has_errors}, status={final_status}",
                    dut_id,
                )

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Finalizing collector {collector_id} with {len(output_files)} output_files: {output_files}",
                dut_id,
            )

            finalize_result = await self.finalize_collector(
                dut_id,
                collector_id,
                final_status,
                final_reason,
                execution_time=asyncio.get_event_loop().time() - start_time,
                output_files=output_files,
            )

            # Update final_status and final_reason with values from finalize_collector
            # This ensures that any status changes in finalize_collector (e.g., "success" -> "skipped")
            # are reflected in the final result
            if finalize_result and "status" in finalize_result:
                final_status = finalize_result["status"]
                final_reason = finalize_result["reason"]
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Updated status from finalize_collector: status={final_status}, reason='{final_reason}'",
                    dut_id,
                )

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Collector {collector_id} completed successfully",
                dut_id,
            )

            # End timing for this collector
            if self.timing_manager:
                self.timing_manager.end_collector(collector_id, "completed")

            # Clean up per-collector execution context
            if (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "clear_collector_execution_context")
            ):
                # DEBUG: Log context cleanup
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Cleaning up execution context for {dut_id}:{collector_id}",
                )
                await self.orchestrator.clear_collector_execution_context(
                    dut_id, collector_id
                )

            result = {
                "success": final_status in ("success", "partial"),
                "status": final_status,
                "reason": final_reason,
                "context": context,
                "execution_time": asyncio.get_event_loop().time() - start_time,
            }

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"execute_collector returning: {list(result.keys())} with status='{result['status']}'",
                dut_id,
            )
            return result

        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            error_msg = f"Collector execution failed: {str(e)}"

            # Clean up per-collector execution context on error
            if (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "clear_collector_execution_context")
            ):
                # DEBUG: Log context cleanup on error
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Cleaning up execution context on error for {dut_id}:{collector_id}",
                )
                await self.orchestrator.clear_collector_execution_context(
                    dut_id, collector_id
                )

            # Prepare context for error logging
            error_context = {
                "operation_name": "collector_execution",
                "execution_time": execution_time,
                "collection_level": collection_level,
                "exception_type": type(e).__name__,
                "exception_message": str(e),
            }

            # Log error using helper method
            await self._log_error("COLLECTOR_ERROR", error_msg, dut_id, collector_id)

            # Finalize with error
            try:
                # Log error to error-logs directory
                error_log_path = await self._log_collector_error(
                    dut_id, collector_id, error_msg, error_context
                )

                await self.finalize_collector(
                    dut_id,
                    collector_id,
                    "error",
                    error_msg,
                    execution_time=execution_time,
                    output_files=[error_log_path] if error_log_path else [],
                )
            except Exception as finalize_error:
                await self._log_error(
                    "FINALIZE_ERROR",
                    f"Failed to finalize collector: {finalize_error}",
                    dut_id,
                    collector_id,
                )

            return {
                "success": False,
                "reason": error_msg,
                "execution_time": execution_time,
            }

    async def _check_collector_dependencies(
        self, collector_id: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check dependencies for a collector using DUT-aware dependency checker.

        Args:
            collector_id: The collector identifier
            context: The context of the collector
        """
        try:
            collector_def = context["collector_def"]
            dependencies = collector_def.get("dependencies", {})
            dut_id = context.get("dut_id", "unknown")

            # Get platform information using BaseboardManager
            platform = "default"
            baseboard = ""
            baseboard_manager = None
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

            # Check required dependencies
            required_deps = dependencies.get("required", [])
            required_results = []
            missing_required = []

            for dep in required_deps:
                if isinstance(dep, dict):
                    dep_type = dep.get("type")
                    dep_name = dep.get("name")
                    check_local = dep.get(
                        "check_local", False
                    )  # New flag for local checking
                    config_key_name = dep.get("config_key")
                    config_default = dep.get("config_default")

                    if config_key_name:
                        config_value = self._get_dut_config_value(
                            dut_id, config_key_name
                        )
                        if config_value is None and config_default is not None:
                            config_value = config_default

                        if config_value is not None:
                            dep_name = str(config_value)
                        else:
                            await self._log_runtime(
                                "WARN",
                                "BaseService",
                                f"[{collector_id}] Required dependency '{dep_type}' "
                                f"requested config '{config_key_name}' but no value was found; "
                                f"falling back to '{dep_name}'",
                                dut_id,
                            )

                    if dep_type and dep_name:
                        # Use DUT-aware dependency checker based on type
                        if dep_type == "command":
                            # For IPMI commands, check locally since they run on the local system
                            if check_local or collector_id.startswith(
                                "I"
                            ):  # IPMI collectors start with "I"
                                result = self.dependency_checker.check_command(
                                    dep_name, check_local=True
                                )
                            else:
                                # For SSH collectors, use BMC connection; for others, use host connection
                                use_bmc = collector_id.startswith(
                                    "S"
                                )  # SSH collectors start with "S"
                                result = (
                                    await self.dependency_checker._check_command_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                        elif dep_type == "service":
                            # For now, fall back to local check for services
                            result = self.dependency_checker.check_service(dep_name)
                        elif dep_type == "file":
                            # For SSH collectors, check files on the BMC
                            if self.dut_manager:
                                use_bmc = collector_id.startswith(
                                    "S"
                                )  # SSH collectors start with "S"
                                result = (
                                    await self.dependency_checker._check_file_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                            else:
                                # Fallback to local check if no DUT manager
                                result = self.dependency_checker.check_file(dep_name)
                        elif dep_type == "command_version":
                            # Check command version on appropriate target
                            min_version = dep.get("min_version")
                            version_cmd = dep.get(
                                "version_cmd", f"{dep_name} --version"
                            )

                            # For IPMI commands, check locally since they run on the local system
                            if check_local or collector_id.startswith("I"):
                                result = (
                                    await self.dependency_checker.check_command_version(
                                        dep_name, min_version, version_cmd
                                    )
                                )
                            else:
                                # For SSH collectors, use BMC connection; for Host collectors, use host connection
                                # Let execute_host_command/execute_bmc_command handle local vs remote routing
                                use_bmc = collector_id.startswith(
                                    "S"
                                )  # SSH collectors start with "S"
                                result = (
                                    await self.dependency_checker.check_command_version(
                                        dep_name,
                                        min_version,
                                        version_cmd,
                                        dut_id=dut_id,
                                        use_bmc=use_bmc,
                                    )
                                )
                        elif dep_type == "platform_service":
                            # Use platform-specific service checking with fallback logic
                            result = (
                                await self.dependency_checker.check_platform_service(
                                    dep, platform, dut_id
                                )
                            )
                        else:
                            # Fallback to regular dependency checker for unknown types
                            result = await self.dependency_checker.check_dependencies(
                                collector_id=collector_id,
                                collector_name=collector_def.get("name", collector_id),
                                dependencies={"required": [dep]},
                                platform=platform,
                            )
                            if hasattr(result, "missing_required"):
                                if result.missing_required:
                                    return {
                                        "status": "fail",
                                        "missing_required": result.missing_required,
                                        "missing_optional": result.missing_optional,
                                        "warnings": result.warnings,
                                        "platform": platform,
                                    }
                                continue
                            else:
                                # Handle case where check_dependencies returns a different format
                                return {
                                    "status": "fail",
                                    "missing_required": [
                                        f"Unsupported dependency type: {dep_type}"
                                    ],
                                    "missing_optional": [],
                                    "warnings": [],
                                    "platform": platform,
                                }

                        # Store the result
                        required_results.append(
                            {
                                "name": dep_name,
                                "type": dep_type,
                                "available": result.available,
                                "error_message": result.error_message,
                                "install_instructions": dep.get("install_instructions"),
                            }
                        )

                        if not result.available:
                            # Adjust error message based on where the check was performed
                            if check_local or (
                                collector_id.startswith("I") and dep_type == "command"
                            ):
                                error_msg = f"Required dependency {dep_name} ({dep_type}) not available on local system: {result.error_message}"
                            else:
                                error_msg = f"Required dependency {dep_name} ({dep_type}) not available on DUT {dut_id}: {result.error_message}"

                            missing_required.append(error_msg)
                else:
                    # Simple string dependency (assumed to be a command)
                    # For IPMI collectors, check locally since they run on the local system
                    if collector_id.startswith("I"):  # IPMI collectors start with "I"
                        result = self.dependency_checker.check_command(
                            dep, check_local=True
                        )
                    else:
                        # For SSH collectors, use BMC connection; for others, use host connection
                        use_bmc = collector_id.startswith(
                            "S"
                        )  # SSH collectors start with "S"
                        result = await self.dependency_checker._check_command_on_dut(
                            dut_id, dep, use_bmc=use_bmc
                        )

                    # Store the result
                    required_results.append(
                        {
                            "name": dep,
                            "type": "command",
                            "available": result.available,
                            "error_message": result.error_message,
                            "install_instructions": None,
                        }
                    )

                    if not result.available:
                        # Adjust error message based on where the check was performed
                        if collector_id.startswith("I"):
                            error_msg = f"Required command {dep} not available on local system: {result.error_message}"
                        else:
                            error_msg = f"Required command {dep} not available on DUT {dut_id}: {result.error_message}"

                        missing_required.append(error_msg)

            # Check optional dependencies
            optional_deps = dependencies.get("optional", [])
            optional_results = []
            missing_optional = []

            for dep in optional_deps:
                if isinstance(dep, dict):
                    dep_type = dep.get("type", "command")
                    dep_name = dep.get("name")
                    check_local = dep.get("check_local", False)

                    if dep_name:
                        # Use similar logic as required dependencies
                        if dep_type == "command":
                            if check_local or collector_id.startswith("I"):
                                result = self.dependency_checker.check_command(
                                    dep_name, check_local=True
                                )
                            else:
                                use_bmc = collector_id.startswith("S")
                                result = (
                                    await self.dependency_checker._check_command_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                        elif dep_type == "file":
                            if collector_id.startswith("S"):
                                result = (
                                    await self.dependency_checker._check_file_on_dut(
                                        dut_id, dep_name
                                    )
                                )
                            else:
                                result = self.dependency_checker.check_file(dep_name)
                        else:
                            result = self.dependency_checker.check_service(dep_name)

                        # Store the result
                        optional_results.append(
                            {
                                "name": dep_name,
                                "type": dep_type,
                                "available": result.available,
                                "error_message": result.error_message,
                                "install_instructions": dep.get("install_instructions"),
                            }
                        )

                        if not result.available:
                            if check_local or (
                                collector_id.startswith("I") and dep_type == "command"
                            ):
                                error_msg = f"Optional dependency {dep_name} ({dep_type}) not available on local system: {result.error_message}"
                            else:
                                error_msg = f"Optional dependency {dep_name} ({dep_type}) not available on DUT {dut_id}: {result.error_message}"
                            missing_optional.append(error_msg)
                else:
                    # Simple string dependency
                    if collector_id.startswith("I"):
                        result = self.dependency_checker.check_command(
                            dep, check_local=True
                        )
                    else:
                        use_bmc = collector_id.startswith("S")
                        result = await self.dependency_checker._check_command_on_dut(
                            dut_id, dep, use_bmc=use_bmc
                        )

                    # Store the result
                    optional_results.append(
                        {
                            "name": dep,
                            "type": "command",
                            "available": result.available,
                            "error_message": result.error_message,
                            "install_instructions": None,
                        }
                    )

                    if not result.available:
                        if collector_id.startswith("I"):
                            error_msg = f"Optional command {dep} not available on local system: {result.error_message}"
                        else:
                            error_msg = f"Optional command {dep} not available on DUT {dut_id}: {result.error_message}"
                        missing_optional.append(error_msg)

            # Return detailed results
            return {
                "status": "pass" if not missing_required else "fail",
                "missing_required": missing_required,
                "missing_optional": missing_optional,
                "warnings": [],
                "platform": platform,
                "required_dependencies": required_results,
                "optional_dependencies": optional_results,
            }

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "BaseService",
                f"Error checking dependencies for {collector_id}: {e}",
            )
            return {
                "status": "error",
                "missing_required": [f"Error: {e}"],
                "missing_optional": [],
                "warnings": [],
                "platform": "unknown",
            }

    async def _write_collector_dependency_metadata(
        self, collector_id: str, dependency_result: Dict[str, Any], dut_id: str
    ) -> None:
        """
        Write dependency results for a single collector to metadata (legacy behavior).

        Args:
            collector_id: The collector identifier
            dependency_result: The dependency result
            dut_id: The DUT identifier
        """
        try:
            if not self.logger:
                return

            # Get collector definition for name
            collector_def = self.orchestrator.get_all_collectors().get(collector_id)
            collector_name = (
                collector_def.get("name", collector_id)
                if collector_def
                else collector_id
            )

            # Convert dependency result to the format expected by write_dependency_metadata
            dependency_data = {
                collector_id: {
                    "collector_id": collector_id,
                    "collector_name": collector_name,
                    "all_required_available": dependency_result["status"] == "pass",
                    "required_dependencies": dependency_result.get(
                        "required_dependencies", []
                    ),
                    "optional_dependencies": dependency_result.get(
                        "optional_dependencies", []
                    ),
                    "missing_required": dependency_result.get("missing_required", []),
                    "missing_optional": dependency_result.get("missing_optional", []),
                    "warnings": dependency_result.get("warnings", []),
                }
            }

            # Write to DUT-specific metadata directory
            await self.logger.write_dependency_metadata(dependency_data, dut_id)

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Wrote dependency metadata for collector {collector_id} to DUT {dut_id}",
                dut_id,
            )

        except Exception as e:
            await self._log_runtime(
                "WARNING",
                "BaseService",
                f"Failed to write dependency metadata for collector {collector_id}: {e}",
                dut_id,
            )

    async def _execute_stage(
        self, stage: str, collector_def: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a specific stage.

        Args:
            stage: The stage to execute
            collector_def: The collector definition
            context: The context of the collector
        """
        try:
            stage_config = collector_def["stages"][stage]
            hooks = stage_config.get("hooks", [])

            stage_context = context.copy()
            last_hook_result = None
            stage_skip_reasons = list(stage_context.get("skip_reasons", []))

            for hook in hooks:
                stage_context["current_stage"] = stage
                hook_result = await self._execute_hook(hook, stage_context)
                last_hook_result = hook_result  # Keep track of the last hook result

                # Debug logging for hook results
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Stage {stage} hook {hook.get('method', 'unknown')} result: success={hook_result.get('success')}, status={hook_result.get('status', 'not_set')}",
                    context.get("dut_id"),
                )

                if not hook_result["success"]:
                    return {
                        "success": False,
                        "reason": f"Hook {hook.get('method', 'unknown')} failed: {hook_result.get('reason', 'No specific hook error reason provided')}",
                    }
                if (
                    hook_result.get("status") == "skipped"
                    and hook_result.get("reason")
                    and hook_result["reason"] not in stage_skip_reasons
                ):
                    stage_skip_reasons.append(hook_result["reason"])
                # Update context with hook results
                stage_context.update(hook_result.get("context", {}))

                # Handle both patterns: output_files at top level AND in context
                top_level_files = hook_result.get("output_files", [])
                context_files = hook_result.get("context", {}).get("output_files", [])

                # Combine both sources (avoid duplicates)
                all_files = list(set(top_level_files + context_files))

                if all_files:
                    if "output_files" not in stage_context:
                        stage_context["output_files"] = []
                    stage_context["output_files"].extend(all_files)

            # Preserve status from the last hook result or context
            result = {
                "success": True,  # Default to True, will be overridden if needed
                "context": stage_context,
            }

            # Use the status from the last hook result if available
            if last_hook_result and "status" in last_hook_result:
                result["status"] = last_hook_result["status"]
                # For partial and skipped status, success should still be True
                if last_hook_result["status"] in ["success", "partial", "skipped"]:
                    result["success"] = True
                else:
                    result["success"] = False
                # Preserve the reason from the hook result
                if "reason" in last_hook_result:
                    result["reason"] = last_hook_result["reason"]
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Stage {stage} using hook result status: {last_hook_result['status']}",
                    context.get("dut_id"),
                )
            elif "status" in stage_context:
                result["status"] = stage_context["status"]
                # For partial and skipped status, success should still be True
                if stage_context["status"] in ["success", "partial", "skipped"]:
                    result["success"] = True
                else:
                    result["success"] = False
                # Preserve the reason from the stage context
                if "reason" in stage_context:
                    result["reason"] = stage_context["reason"]
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Stage {stage} using context status: {stage_context['status']}",
                    context.get("dut_id"),
                )

            if stage_skip_reasons:
                stage_context["skip_reasons"] = stage_skip_reasons

            # Debug logging for final stage result
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Stage {stage} final result: success={result.get('success')}, status={result.get('status', 'not_set')}",
                context.get("dut_id"),
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "reason": f"Stage {stage} execution error: {str(e)}",
            }

    async def _execute_hook(
        self, hook: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a hook method.

        Args:
            hook: The hook to execute
            context: The context of the collector
        """
        try:
            method_name = hook.get("method")
            if not method_name:
                return {
                    "success": False,
                    "reason": "Hook missing method name",
                }

            # Log hook execution start
            dut_id = context.get("dut_id", "unknown")
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Starting hook execution: {method_name}",
                dut_id,
            )

            # Start timing for this hook
            if self.timing_manager:
                self.timing_manager.start_hook(method_name)

            # Get method from service
            method = getattr(self, method_name, None)
            if not method:
                if self.timing_manager:
                    self.timing_manager.end_hook(method_name)
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Method {method_name} not found in {self.service_name}",
                    dut_id,
                )
                return {
                    "success": False,
                    "reason": f"Method {method_name} not found in {self.service_name}",
                }

            # Prepare parameters
            hook_params = hook.get("params", {})

            # Debug: Log raw hook params before processing
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Raw hook params before processing: {list(hook_params.keys())}",
                dut_id,
            )

            # Merge context into hook params without overwriting explicit hook config.
            hook_params = {**context, **hook_params}

            # Check for output_pattern at hook level and add to params
            if "output_pattern" in hook:
                hook_params["output_pattern"] = hook["output_pattern"]

            # Log hook parameters (excluding sensitive data)
            safe_params = {
                k: v
                for k, v in hook_params.items()
                if k not in ["password", "token", "secret"]
            }
            # Get collector ID for better logging
            collector_id = safe_params.get("collector_id", "unknown")
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"[{collector_id}] Hook {method_name} parameters: {safe_params}",
                dut_id,
            )

            # Special handling for finalize_collector method
            if method_name == "finalize_collector":
                # Ensure required arguments are present
                if "dut_id" not in hook_params:
                    hook_params["dut_id"] = context.get("dut_id")
                if "collector_id" not in hook_params:
                    hook_params["collector_id"] = context.get("collector_id")
                if "status" not in hook_params:
                    # Check if status is available in context from previous stage
                    if "status" in context:
                        hook_params["status"] = context["status"]
                    else:
                        hook_params["status"] = (
                            "success"  # Default to success for post_processing
                        )
                if "reason" not in hook_params:
                    # Check if reason is available in context from previous stage
                    if "reason" in context:
                        hook_params["reason"] = context["reason"]
                    else:
                        hook_params["reason"] = "Completed successfully"
                if "execution_time" not in hook_params:
                    hook_params["execution_time"] = 0.0
            else:
                # Apply parameter mapping for all other methods
                hook_params = await self._apply_parameter_mapping(
                    method_name, hook_params, context
                )

                # Add baseboard manager to hook params for all methods
                hook_params["baseboard_manager"] = (
                    self.dut_manager._get_baseboard_manager()
                )

            # Generalized collector directory resolution for all services
            hook_params = await self._resolve_collector_directory_variables(
                hook_params, context
            )

            # Determine if request/response capture should be enabled for this hook
            capture_config = hook.get("store_request_response", None)
            capture_requested = method_name != "finalize_collector"
            capture_options: Dict[str, Any] = {}

            if isinstance(capture_config, dict):
                capture_requested = True
                capture_options = capture_config.copy()
            elif capture_config is not None:
                capture_requested = bool(capture_config)

            current_stage = context.get("current_stage")
            if (
                capture_config is None
                and current_stage in ("validation", "discovery")
                and (
                    method_name.startswith("_validate_")
                    or method_name.startswith("_discover_")
                )
            ):
                capture_requested = True

            if hook.get("request_response_output_pattern"):
                capture_options["output_pattern"] = hook[
                    "request_response_output_pattern"
                ]
            if hook.get("request_response_function_tag"):
                capture_options["function_tag"] = hook["request_response_function_tag"]

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"[{collector_id}] Executing method: {method_name}",
                dut_id,
            )

            # Debug: Log method parameters before execution
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"[{collector_id}] Method {method_name} called with params: {list(hook_params.keys())}",
                dut_id,
            )
            if method_name == "finalize_collector":
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"[{collector_id}] finalize_collector params: status={hook_params.get('status', 'NOT_SET')}, reason={hook_params.get('reason', 'NOT_SET')}, skip_message={hook_params.get('skip_message', 'NOT_SET')}",
                    dut_id,
                )

            capture_token = None
            result = None
            capture_result = None
            hook_exception = None

            try:
                if capture_requested:
                    capture_token = await self._begin_request_response_capture(
                        context, method_name, capture_options
                    )

                if asyncio.iscoroutinefunction(method):
                    result = await method(**hook_params)
                else:
                    result = method(**hook_params)

                # Debug: Log method result
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"[{collector_id}] Method {method_name} returned: {type(result).__name__} with keys: {list(result.keys()) if isinstance(result, dict) else 'N/A'}",
                    dut_id,
                )

                # Log hook execution result
                if isinstance(result, dict) and "success" in result:
                    success = result.get("success", False)
                    reason = result.get("reason", "No reason provided")
                    await self._log_runtime(
                        "INFO" if success else "ERROR",
                        "BaseService",
                        f"[{collector_id}] Hook {method_name} completed: success={success}, reason={reason}",
                        dut_id,
                    )

                    # Log context if present
                    if "context" in result and result["context"]:
                        context_summary = {
                            k: v
                            for k, v in result["context"].items()
                            if k not in ["password", "token", "secret"]
                            and not isinstance(v, (list, dict))
                        }
                        if context_summary:
                            await self._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"[{collector_id}] Hook {method_name} context: {context_summary}",
                                dut_id,
                            )
                else:
                    await self._log_runtime(
                        "INFO",
                        "BaseService",
                        f"[{collector_id}] Hook {method_name} completed with simple result",
                        dut_id,
                    )

            except Exception as e:
                hook_exception = e
                raise
            finally:
                if self.timing_manager:
                    self.timing_manager.end_hook(method_name)

                if capture_token:
                    try:
                        capture_result = await self._finalize_request_response_capture(
                            capture_token,
                            context,
                            method_name,
                            capture_options,
                            result,
                            hook_exception,
                        )
                    except Exception as capture_error:
                        capture_result = None
                        await self._log_runtime(
                            "ERROR",
                            "BaseService",
                            f"[{collector_id}] Failed to finalize request/response capture for {method_name}: {capture_error}",
                            dut_id,
                        )

            # Check if the result indicates success/failure
            if isinstance(result, dict) and "success" in result:
                final_result = result
            else:
                # Method returned a simple result, treat as success
                final_result = {
                    "success": True,
                    "context": (
                        result if isinstance(result, dict) else {"result": result}
                    ),
                }

            if capture_result and capture_result[0] and isinstance(final_result, dict):
                self._attach_capture_metadata(
                    final_result,
                    capture_result,
                    method_name,
                    current_stage,
                    context,
                )

            return final_result

        except Exception as e:
            return {
                "success": False,
                "reason": f"Hook execution error: {str(e)}",
            }

    def _attach_capture_metadata(
        self,
        target_result: Dict[str, Any],
        capture_result: Tuple[str, Dict[str, Any]],
        method_name: str,
        current_stage: Optional[str],
        context: Dict[str, Any],
    ) -> None:
        """
        Append request/response capture metadata to a hook result structure.
        """
        file_path, capture_data = capture_result
        capture_data = capture_data or {}

        output_files = target_result.setdefault("output_files", [])
        if file_path not in output_files:
            output_files.append(file_path)

        context_block = target_result.setdefault("context", {})
        output_files_block = context_block.setdefault("output_files", [])
        if file_path not in output_files_block:
            output_files_block.append(file_path)

        logs_block = context_block.setdefault("request_response_logs", {})
        capture_key = capture_data.get("key")
        if not capture_key:
            stage_hint = capture_data.get("stage")
            stage_name = stage_hint or current_stage or context.get("current_stage")
            method_key = method_name.strip("_")
            capture_key = f"{stage_name}:{method_key}" if stage_name else method_key
        logs_block[capture_key] = capture_data.get("requests", [])

    def _sanitize_for_capture(self, value: Any, depth: int = 4) -> Any:
        """
        Convert arbitrary data into a JSON-serializable structure for request/response capture files.
        """
        if depth <= 0:
            return str(value)

        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, bytes):
            return {
                "type": "bytes",
                "length": len(value),
                "note": "binary content omitted",
            }

        if isinstance(value, (list, tuple)):
            return [self._sanitize_for_capture(item, depth - 1) for item in value]

        if isinstance(value, dict):
            return {
                str(key): self._sanitize_for_capture(val, depth - 1)
                for key, val in value.items()
            }

        return str(value)

    async def _begin_request_response_capture(
        self,
        context: Dict[str, Any],
        method_name: str,
        options: Dict[str, Any],
    ) -> Optional[asyncio.Task]:
        """
        Enable request/response capture for the current coroutine.
        """
        task = asyncio.current_task()
        if not task:
            return None

        stack = self._request_response_capture_states.setdefault(task, [])
        state = {
            "collector_id": context.get("collector_id"),
            "dut_id": context.get("dut_id"),
            "stage": context.get("current_stage")
            or options.get("stage")
            or context.get("stage")
            or "unknown_stage",
            "method": method_name,
            "options": options.copy(),
            "requests": [],
            "started_at": datetime.utcnow().isoformat() + "Z",
        }
        stack.append(state)

        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"Enabled request/response capture for {state['stage']}::{method_name}",
            context.get("dut_id"),
        )
        return task

    def _record_request_response(
        self,
        request_info: Dict[str, Any],
        response_info: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Append a request/response pair to the capture buffer for the current coroutine.
        """
        task = asyncio.current_task()
        if not task:
            return

        stack = self._request_response_capture_states.get(task)
        if not stack:
            return

        state = stack[-1] if stack else None
        if not state:
            return

        entry: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "request": self._sanitize_for_capture(request_info),
        }

        if response_info is not None:
            entry["response"] = self._sanitize_for_capture(response_info)

        if metadata:
            entry["metadata"] = self._sanitize_for_capture(metadata)

        state["requests"].append(entry)

    async def _finalize_request_response_capture(
        self,
        token: Optional[asyncio.Task],
        context: Dict[str, Any],
        method_name: str,
        options: Dict[str, Any],
        hook_result: Optional[Dict[str, Any]],
        error: Optional[BaseException],
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Flush captured request/response pairs to disk and return metadata.
        """
        task = token or asyncio.current_task()
        if not task:
            return None

        stack = self._request_response_capture_states.get(task)
        if not stack:
            return None

        state = stack.pop()
        if not stack:
            self._request_response_capture_states.pop(task, None)

        if not state.get("requests"):
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"No request/response data captured for {state.get('stage', 'unknown_stage')}::{method_name}",
                context.get("dut_id"),
            )
            return None

        capture_data: Dict[str, Any] = {
            "collector_id": state.get("collector_id") or context.get("collector_id"),
            "stage": state.get("stage")
            or context.get("current_stage")
            or "unknown_stage",
            "hook": method_name,
            "started_at": state.get("started_at"),
            "captured_at": datetime.utcnow().isoformat() + "Z",
            "requests": state.get("requests", []),
        }

        if isinstance(hook_result, dict):
            capture_data["hook_result"] = {
                key: hook_result.get(key)
                for key in ("success", "status", "reason")
                if hook_result.get(key) is not None
            }

        if error:
            capture_data["hook_error"] = {
                "type": type(error).__name__,
                "message": str(error),
            }

        merged_options = state.get("options", {}).copy()
        if options:
            merged_options.update(options)
        capture_data["options"] = merged_options

        stage_name = capture_data["stage"] or "stage"
        method_slug = method_name.strip("_") or method_name
        capture_key = merged_options.get("capture_key") or f"{stage_name}:{method_slug}"
        capture_data["key"] = capture_key

        output_pattern = merged_options.get("output_pattern")
        function_tag = merged_options.get("function_tag")

        method_slug_for_tag = method_slug.replace(" ", "_")
        if not function_tag:
            function_tag = f"request_{method_slug_for_tag}"
        if not output_pattern:
            output_pattern = f"diagnostic/request_{method_slug_for_tag}.json"

        target_dut_id = state.get("dut_id") or context.get("dut_id")
        if not target_dut_id:
            await self._log_runtime(
                "WARN",
                "BaseService",
                f"Unable to write request/response capture for {method_name} without dut_id",
                context.get("dut_id"),
            )
            return None

        target_collector_id = (
            state.get("collector_id")
            or context.get("collector_id")
            or self._get_current_collector_id()
            or ""
        )

        file_path = await self.write_output_with_generalization(
            target_dut_id,
            target_collector_id,
            capture_data,
            output_pattern=output_pattern,
            function_tag=function_tag,
            default_extension=".json",
        )

        if not file_path:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Failed to write request/response capture file for {method_name}",
                target_dut_id,
            )
            return None

        capture_data["file_path"] = file_path

        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"Wrote request/response capture for {method_name} to {file_path}",
            target_dut_id,
        )

        return file_path, capture_data

    async def _get_output_directory(self, dut_id: str) -> str:
        """
        Get the base output directory for the current collection session.

        Args:
            dut_id: DUT identifier

        Returns:
            Base output directory path, or "/tmp" as fallback
        """
        if hasattr(self.logger, "base_log_dir") and self.logger.base_log_dir:
            return self.logger.base_log_dir
        else:
            await self._log_runtime(
                "WARN",
                "BaseService",
                "Cannot get output directory - logger not available, using /tmp fallback",
                dut_id,
            )
            return "/tmp"

    async def _resolve_collector_directory_variables(
        self, hook_params: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Resolve {collector_dir} and {log_dir} variables in hook parameters.
        This provides a centralized way for all services to handle collector-specific log directories.
        """
        try:
            dut_id = context.get("dut_id")
            collector_id = context.get("collector_id")

            if not dut_id or not collector_id:
                return hook_params  # Can't resolve without DUT and collector info

            # Check if any parameter contains collector directory variables
            needs_resolution = False
            for value in hook_params.values():
                if isinstance(value, str) and (
                    "{collector_dir}" in value or "{log_dir}" in value
                ):
                    needs_resolution = True
                    break

            if not needs_resolution:
                return hook_params  # No variables to resolve

            # Get collector directory using the logger
            if self.logger:
                # Get the service group from the collector ID
                service_group = self._get_collector_group(collector_id)

                # CRITICAL FIX: Use original collector ID for file path determination
                # This prevents cross-contamination when one collector takes over another's execution
                original_collector_id = await self._get_original_collector_id(
                    dut_id, collector_id
                )

                # DEBUG: Log file path determination process
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"File path determination - collector_id: {collector_id}, original_collector_id: {original_collector_id}",
                )

                if original_collector_id != "unknown":
                    file_collector_id = original_collector_id

                    # VALIDATION: Log warning if there's a mismatch between current and original collector
                    if original_collector_id != collector_id:
                        await self._log_runtime(
                            "WARNING",
                            "BaseService",
                            f"Cross-contamination prevention: Using original collector ID '{original_collector_id}' for file paths while current context is '{collector_id}'",
                            dut_id,
                        )
                else:
                    file_collector_id = collector_id
                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Using current collector_id for file paths: {file_collector_id}",
                    )

                # Create a temporary file to get the collector directory
                temp_file_path = await self.logger.create_collector_log_file(
                    dut_id, service_group, file_collector_id, "temp.bin"
                )
                collector_dir = str(temp_file_path.parent)

                # Create substitution context
                substitution_context = {
                    "collector_dir": collector_dir,
                    "log_dir": collector_dir,  # Backward compatibility
                }

                # Update variable engine with DUT context if needed
                if self.variable_engine is None:
                    await self._update_variable_engine(dut_id)

                # Apply variable substitution to all string parameters
                resolved_params = {}
                for key, value in hook_params.items():
                    if isinstance(value, str) and (
                        "{collector_dir}" in value or "{log_dir}" in value
                    ):
                        # Use variable substitution service
                        if self.variable_engine:
                            resolved_value = (
                                await self.variable_engine.substitute_variables(
                                    value,
                                    substitution_context,
                                    dut_id,
                                    allow_missing=True,
                                )
                            )
                        else:
                            # Fallback to simple replacement
                            resolved_value = value.replace(
                                "{collector_dir}", collector_dir
                            )
                            resolved_value = resolved_value.replace(
                                "{log_dir}", collector_dir
                            )

                        resolved_params[key] = resolved_value

                        # Log the substitution for debugging
                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Resolved {key}: {value} -> {resolved_value}",
                            dut_id,
                        )
                    else:
                        resolved_params[key] = value

                return resolved_params

            return hook_params  # No logger available, return as-is

        except Exception as e:
            # Log error but don't fail the hook execution
            await self._log_runtime(
                "WARN",
                "BaseService",
                f"Failed to resolve collector directory variables: {e}",
            )
            return hook_params  # Return original parameters on error

    async def finalize_collector(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str,
        execution_time: float = 0.0,
        output_files: Optional[List[str]] = None,
        discovered_files: Optional[Dict[str, List[str]]] = None,
        detailed_context: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Finalize collector execution.

        Args:
            dut_id: The DUT identifier
            collector_id: The collector identifier
            status: The status of the collector
            reason: The reason for the collector status
            execution_time: The execution time of the collector
            output_files: The output files of the collector
            discovered_files: The discovered files of the collector
            detailed_context: The detailed context of the collector
            **kwargs: Additional keyword arguments
        """
        # Log entry point for all finalize_collector calls
        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"finalize_collector called for {collector_id}: status={status}, reason='{reason}', output_files_count={len(output_files) if output_files else 0}",
            dut_id,
        )
        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"finalize_collector kwargs for {collector_id}: {list(kwargs.keys())}",
            dut_id,
        )
        try:
            if output_files is None:
                output_files = []
            if discovered_files is None:
                discovered_files = {}

            # Check for output files in execution_result if not provided directly
            actual_output_files = output_files
            if not actual_output_files and "execution_result" in kwargs:
                exec_result = kwargs["execution_result"]
                if isinstance(exec_result, dict) and "output_files" in exec_result:
                    actual_output_files = exec_result.get("output_files", [])
                    if actual_output_files:
                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Found {len(actual_output_files)} output files in execution_result for {collector_id}",
                            dut_id,
                        )

            # Convert output_files to discovered_files format if discovered_files is empty
            # This ensures metadata gets properly populated with file paths
            if not discovered_files and actual_output_files:
                import os

                discovered_files = {}
                for file_path in actual_output_files:
                    # Group files by their parent directory
                    folder = os.path.dirname(file_path)
                    if folder not in discovered_files:
                        discovered_files[folder] = []
                    discovered_files[folder].append(file_path)
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Converted {len(actual_output_files)} output files to discovered_files format for {collector_id}: {len(discovered_files)} folders",
                    dut_id,
                )

            # Optional follow-up hooks can legitimately report "skipped" after a primary
            # collection hook already produced data (for example DGX-only sub-collections).
            # Do not let that downgrade the collector when real output files exist.
            if status == "skipped" and actual_output_files:
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Preserving successful collector status for {collector_id} because {len(actual_output_files)} output file(s) were produced before a later skipped hook",
                    dut_id,
                )
                status = "success"
                if reason == "Not a DGX platform":
                    reason = "Completed successfully (DGX-specific sub-collection not applicable)"
                elif not reason:
                    reason = "Completed successfully"

            # For skipped collectors, correct the reason early if it's generic
            # Only apply this correction if the collector was actually skipped:
            # - Has skip_message AND
            # - Status is explicitly 'skipped' OR (no output files AND not explicitly successful)
            # IMPORTANT: Don't apply skip_message if we have output files and success status
            is_actually_skipped = (
                "skip_message" in kwargs
                and kwargs["skip_message"]
                and (
                    status == "skipped"  # Explicitly skipped status
                    or (
                        # Generic success reason but no actual output
                        reason in ["Completed successfully", "success"]
                        and (not actual_output_files or len(actual_output_files) == 0)
                    )
                )
            )

            if is_actually_skipped:
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Correcting generic reason '{reason}' for collector {collector_id} - found skip_message",
                    dut_id,
                )

                reason = kwargs["skip_message"]
                # Also correct the status if this is actually a skipped collector
                if status == "success":
                    status = "skipped"
                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Corrected status from 'success' to 'skipped' for {collector_id}",
                        dut_id,
                    )
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Using skip_message as reason: {reason}",
                    dut_id,
                )

            # Check for ignore_empty_results case: status is success but no files collected
            # Keep success but surface the expected-empty reason when applicable; allow overrides
            elif status == "success":
                # Check if ignore_empty_results is set (from execution_result or collector definition)
                ignore_empty = False
                if "execution_result" in kwargs:
                    exec_result = kwargs.get("execution_result", {})
                    ignore_empty = exec_result.get("ignore_empty_results", False)

                # If not found in execution_result, check the collector definition
                if (
                    not ignore_empty
                    and hasattr(self, "orchestrator")
                    and self.orchestrator
                ):
                    collector_info = self.orchestrator.get_collector_info(collector_id)
                    if collector_info and "stages" in collector_info:
                        execution_stage = collector_info.get("stages", {}).get(
                            "execution", {}
                        )
                        for hook in execution_stage.get("hooks", []):
                            if (
                                "params" in hook
                                and "ignore_empty_results" in hook["params"]
                            ):
                                ignore_empty = hook["params"]["ignore_empty_results"]
                                break

                # If ignore_empty_results is set, check if we only have summary files
                if ignore_empty:
                    # Filter out summary files - they're metadata, not actual collected data
                    # Summary files typically end with "_summary.txt"
                    real_data_files = (
                        [
                            f
                            for f in actual_output_files
                            if not (
                                f.endswith("_summary.txt")
                                or f.endswith("_summary.json")
                                or "summary" in os.path.basename(f).lower()
                            )
                        ]
                        if actual_output_files
                        else []
                    )

                    # If no real data files collected (only summary files or nothing),
                    # keep the collector marked as success but allow overrides.
                    if not real_data_files or len(real_data_files) == 0:
                        # Look for overrides in kwargs or execution_result
                        status_override = kwargs.get("status_override")
                        reason_override = kwargs.get("reason_override")
                        if not status_override and "execution_result" in kwargs:
                            er = kwargs.get("execution_result", {})
                            status_override = er.get("status_override")
                            reason_override = er.get("reason_override", reason_override)

                        # Also honor overrides defined in post_processing hooks (collector definition)
                        if (
                            (not status_override or not reason_override)
                            and hasattr(self, "orchestrator")
                            and self.orchestrator
                        ):
                            collector_info = self.orchestrator.get_collector_info(
                                collector_id
                            )
                            post_hooks = (
                                collector_info.get("stages", {})
                                .get("post_processing", {})
                                .get("hooks", [])
                                if collector_info
                                else []
                            )
                            for hook in post_hooks:
                                if hook.get("method") == "finalize_collector":
                                    params = hook.get("params", {})
                                    status_override = status_override or params.get(
                                        "status_override"
                                    )
                                    reason_override = reason_override or params.get(
                                        "reason_override"
                                    )
                                    break

                        if status_override:
                            status = status_override
                        if reason_override:
                            reason = reason_override

                        # If the reason already indicates an empty-target completion, honor it.
                        if "No URIs to collect; treating as success" in reason:
                            return {
                                "status": status,
                                "reason": reason,
                                "context": kwargs.get("execution_result", {}).get(
                                    "context", {}
                                ),
                            }

                        # Try to get collector_config from multiple sources
                        collector_config = kwargs.get("collector_config", {})

                        # If not in kwargs, try to get from orchestrator's collector definition
                        if (
                            not collector_config
                            and hasattr(self, "orchestrator")
                            and self.orchestrator
                        ):
                            collector_info = self.orchestrator.get_collector_info(
                                collector_id
                            )
                            if collector_info and "stages" in collector_info:
                                execution_stage = collector_info.get("stages", {}).get(
                                    "execution", {}
                                )
                                for hook in execution_stage.get("hooks", []):
                                    if (
                                        "params" in hook
                                        and "collector_config" in hook["params"]
                                    ):
                                        collector_config = hook["params"][
                                            "collector_config"
                                        ]
                                        break

                        empty_note = collector_config.get("empty_expected_note")

                        if empty_note:
                            reason = empty_note
                        else:
                            reason = "No data collected (expected behavior)"

                        if reason_override:
                            reason = reason_override
                        if status_override:
                            status = status_override
                        else:
                            # Default behavior: treat as success when empty results are explicitly allowed.
                            # This avoids flagging "healthy system / no dumps" collectors as skipped.
                            status = "success"

                        await self._log_runtime(
                            "INFO",
                            "BaseService",
                            f"Collector {collector_id}: No data files collected (only {len(actual_output_files)} summary files) with ignore_empty_results=True; treating as {status}",
                            dut_id,
                        )
                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Using empty_expected_note/override as reason: {reason}",
                            dut_id,
                        )

            # Additional fallback: look for skip reason in detailed_context if not found above
            elif (
                detailed_context
                and status == "skipped"
                and reason in ["Completed successfully", "success"]
            ):
                # Look for skip reason in stage contexts
                for stage_name in ["post_processing", "execution", "validation"]:
                    if stage_name in detailed_context and isinstance(
                        detailed_context[stage_name], dict
                    ):
                        stage_context = detailed_context[stage_name]
                        if stage_context.get("status") == "skipped":
                            # Look for skip_message in finalize_collector params
                            commands = stage_context.get("commands", [])
                            for command in commands:
                                if command.get("method") == "finalize_collector":
                                    skip_message = command.get("params", {}).get(
                                        "skip_message"
                                    )
                                    if skip_message:
                                        reason = skip_message
                                        await self._log_runtime(
                                            "DEBUG",
                                            "BaseService",
                                            f"Found skip_message in detailed_context: {reason}",
                                            dut_id,
                                        )
                                        break
                            if (
                                reason != "Completed successfully"
                                and reason != "success"
                            ):
                                break

            # Use detailed_context if provided, otherwise try to extract from logger or kwargs
            context = detailed_context or {}

            # Check if we have execution_result in kwargs first
            if not context and "execution_result" in kwargs:
                context = kwargs["execution_result"]
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Using execution_result from kwargs for {collector_id}: {len(context)} keys: {list(context.keys())}",
                    dut_id,
                )

            if not context and hasattr(self, "logger") and self.logger:
                result_key = f"{dut_id}:{collector_id}"
                collector_result = getattr(self.logger, "collector_results", {}).get(
                    result_key, {}
                )
                context = collector_result.get("context", {})
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Extracted context from logger for {collector_id}: {len(context)} keys",
                    dut_id,
                )
            elif context:
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Using provided detailed_context for {collector_id}: {len(context)} keys",
                    dut_id,
                )
            else:
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"No context available for {collector_id}",
                    dut_id,
                )

            # Update status tracker with discovered files if available
            if (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "status_tracker")
                and self.orchestrator.status_tracker
            ):
                await self.orchestrator.status_tracker.complete_collector(
                    dut_id,
                    collector_id,
                    status,
                    reason,
                    execution_time,
                    output_files,
                    discovered_files,
                    context,
                )

            # Create status.json file for this collector
            try:
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"About to create status.json for collector {collector_id} with status {status}",
                    dut_id,
                )
                try:
                    await self.logger.write_collector_status_file(
                        collector_id, dut_id, status, reason
                    )
                except Exception as e:
                    await self._log_runtime(
                        "ERROR",
                        "BaseService",
                        f"Exception in write_collector_status_file for {collector_id}: {e}",
                        dut_id,
                    )
                    raise
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Successfully created status.json for collector {collector_id}",
                    dut_id,
                )
            except Exception as e:
                await self._log_runtime(
                    "WARN",
                    "BaseService",
                    f"Failed to create status.json for collector {collector_id}: {e}",
                    dut_id,
                )

            # Add execution summary entry (but avoid duplicates)
            # Check if this collector already has an execution summary entry to avoid duplicates
            # Allow updates if the status has changed (e.g., from skipped to partial)
            duplicate_check_key = f"execution_summary_added_{dut_id}_{collector_id}"
            previous_status_key = f"execution_summary_status_{dut_id}_{collector_id}"

            should_add_entry = False
            if hasattr(self, duplicate_check_key):
                previous_status = getattr(self, previous_status_key, None)
                if previous_status == status:
                    # Skip duplicate entry with same status
                    pass
                else:
                    # Status changed, add new entry
                    should_add_entry = True
            else:
                # First time adding entry for this collector
                should_add_entry = True

            if should_add_entry and hasattr(self, "orchestrator") and self.orchestrator:
                # For skipped collectors, create error log file (like legacy nvdebug)
                # But don't create error log if this is a temporary "skipped" that will become "partial"
                if status == "skipped" and len(output_files) == 0:
                    try:
                        # Extract collection_level from context or use default
                        collection_level = context.get("collection_level", "L1")
                        skip_context = {
                            "operation_name": "collector_skip",
                            "skip_reason": reason,
                            "collection_level": collection_level,
                        }
                        error_log_path = await self.logger.write_error_log(
                            dut_id, collector_id, f"SKIPPED: {reason}", skip_context
                        )
                        # Include error log path in output files for execution summary
                        # Check if error log is already in actual_output_files to avoid duplicates
                        error_log_str = str(error_log_path)
                        if error_log_str not in actual_output_files:
                            output_files_with_error_log = actual_output_files + [
                                error_log_str
                            ]
                        else:
                            # Error log already in list, don't add duplicate
                            output_files_with_error_log = actual_output_files
                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Adding execution summary entry for SKIPPED collector {collector_id}",
                            dut_id,
                        )
                        try:
                            await self.orchestrator.add_execution_summary_entry(
                                dut_id,
                                collector_id,
                                status,
                                output_files_with_error_log,
                                reason,
                            )
                            # Mark that we've added an entry for this collector (only after success)
                            setattr(self, duplicate_check_key, True)
                            setattr(self, previous_status_key, status)
                        except Exception as summary_ex:
                            await self._log_runtime(
                                "ERROR",
                                "BaseService",
                                f"Failed to add execution summary entry for SKIPPED collector {collector_id}: {summary_ex}",
                                dut_id,
                            )
                    except Exception as e:
                        await self._log_runtime(
                            "WARNING",
                            "BaseService",
                            f"Failed to create error log for skipped collector {collector_id}: {e}",
                            dut_id,
                        )
                        # Fall back to normal execution summary entry
                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Adding execution summary entry for SKIPPED collector {collector_id} (fallback)",
                            dut_id,
                        )
                        try:
                            await self.orchestrator.add_execution_summary_entry(
                                dut_id,
                                collector_id,
                                status,
                                actual_output_files,
                                reason,
                            )
                            # Mark that we've added an entry for this collector (only after success)
                            setattr(self, duplicate_check_key, True)
                            setattr(self, previous_status_key, status)
                        except Exception as summary_ex:
                            await self._log_runtime(
                                "ERROR",
                                "BaseService",
                                f"Failed to add execution summary entry for SKIPPED collector {collector_id} (fallback): {summary_ex}",
                                dut_id,
                            )
                elif status == "partial":
                    # For partial collectors, create detailed error log showing which commands failed
                    try:
                        # Extract detailed information from context
                        # Check if we have execution_result with I2C command details
                        execution_result = context.get("execution_result", {})
                        if execution_result and "total_commands" in execution_result:
                            # Use I2C command data
                            successful_operations = execution_result.get(
                                "successful_commands", 0
                            )
                            total_operations = execution_result.get("total_commands", 0)
                            # Extract detailed error messages from failed commands
                            detailed_errors = []
                            results = execution_result.get("results", [])
                            for result in results:
                                if not result.get("success", True):
                                    cmd_name = result.get("name", "unknown_command")
                                    cmd_error = result.get(
                                        "error", "No specific error provided"
                                    )
                                    detailed_errors.append(f"{cmd_name}: {cmd_error}")
                            error_messages = detailed_errors
                        else:
                            # Fallback to standard context fields
                            successful_operations = context.get(
                                "successful_operations", 0
                            )
                            total_operations = context.get("total_operations", 0)
                            error_messages = context.get("error_messages", [])

                        collection_level = context.get("collection_level", "L1")

                        # Create detailed partial collection context
                        partial_context = {
                            "operation_name": "partial_collection",
                            "successful_operations": successful_operations,
                            "total_operations": total_operations,
                            "collection_level": collection_level,
                        }

                        # Add detailed error information if available
                        if error_messages:
                            partial_context["detailed_errors"] = error_messages

                        # Create a more informative error message for partial collections
                        partial_message = f"PARTIAL: {successful_operations} out of {total_operations} operations succeeded"
                        if error_messages:
                            failed_count = total_operations - successful_operations
                            # Extract just the command names from error messages for summary
                            failed_commands = []
                            for error_msg in error_messages:
                                if ":" in error_msg:
                                    cmd_name = error_msg.split(":")[0].strip()
                                    failed_commands.append(cmd_name)

                            if failed_commands:
                                # Show first few failed commands in the summary, truncate if too many
                                if len(failed_commands) <= 5:
                                    failed_list = ", ".join(failed_commands)
                                    partial_message += f". Failed: {failed_list}"
                                else:
                                    failed_list = ", ".join(failed_commands[:5])
                                    partial_message += f". Failed: {failed_list} (+{len(failed_commands)-5} more)"
                            else:
                                partial_message += (
                                    f" ({failed_count} operations failed)"
                                )

                        error_log_path = await self.logger.write_error_log(
                            dut_id, collector_id, partial_message, partial_context
                        )
                        # Include error log path in output files for execution summary
                        # Check if error log is already in actual_output_files to avoid duplicates
                        error_log_str = str(error_log_path)
                        if error_log_str not in actual_output_files:
                            output_files_with_error_log = actual_output_files + [
                                error_log_str
                            ]
                        else:
                            # Error log already in list, don't add duplicate
                            output_files_with_error_log = actual_output_files
                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Adding execution summary entry for PARTIAL collector {collector_id}",
                            dut_id,
                        )
                        try:
                            await self.orchestrator.add_execution_summary_entry(
                                dut_id,
                                collector_id,
                                status,
                                output_files_with_error_log,
                                partial_message,
                            )
                            # Mark that we've added an entry for this collector (only after success)
                            setattr(self, duplicate_check_key, True)
                            setattr(self, previous_status_key, status)
                            # Update the reason for console output and final logging
                            reason = partial_message
                        except Exception as summary_ex:
                            await self._log_runtime(
                                "ERROR",
                                "BaseService",
                                f"Failed to add execution summary entry for PARTIAL collector {collector_id}: {summary_ex}",
                                dut_id,
                            )
                    except Exception as e:
                        await self._log_runtime(
                            "WARNING",
                            "BaseService",
                            f"Failed to create error log for partial collector {collector_id}: {e}",
                            dut_id,
                        )
                        # Fall back to normal execution summary entry
                        await self._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Adding execution summary entry for PARTIAL collector {collector_id} (fallback)",
                            dut_id,
                        )
                        try:
                            await self.orchestrator.add_execution_summary_entry(
                                dut_id,
                                collector_id,
                                status,
                                actual_output_files,
                                (
                                    partial_message
                                    if "partial_message" in locals()
                                    else reason
                                ),
                            )
                            # Mark that we've added an entry for this collector (only after success)
                            setattr(self, duplicate_check_key, True)
                            setattr(self, previous_status_key, status)
                        except Exception as summary_ex:
                            await self._log_runtime(
                                "ERROR",
                                "BaseService",
                                f"Failed to add execution summary entry for PARTIAL collector {collector_id} (fallback): {summary_ex}",
                                dut_id,
                            )
                else:
                    try:
                        await self.orchestrator.add_execution_summary_entry(
                            dut_id, collector_id, status, actual_output_files, reason
                        )
                        # Mark that we've added an entry for this collector (only after success)
                        setattr(self, duplicate_check_key, True)
                        setattr(self, previous_status_key, status)
                    except Exception as summary_ex:
                        await self._log_runtime(
                            "ERROR",
                            "BaseService",
                            f"Failed to add execution summary entry for collector {collector_id} with status {status}: {summary_ex}",
                            dut_id,
                        )
            else:
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Cannot add execution summary entry for collector {collector_id}: orchestrator not available",
                    dut_id,
                )

            # Log collector result using helper method (after all corrections)
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Logging final collector result for {collector_id}: status={status}, reason='{reason}', discovered_files_keys={list(discovered_files.keys()) if discovered_files else []}",
                dut_id,
            )
            await self._log_collector_result(
                dut_id,
                collector_id,
                status,
                reason,
                execution_time,
                output_files,
                context,
                discovered_files,
            )

            # Final summary debug log
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"finalize_collector COMPLETED for {collector_id}: final_status={status}, final_reason='{reason}', execution_summary_added={hasattr(self, f'execution_summary_added_{dut_id}_{collector_id}')}",
                dut_id,
            )

            return {
                "success": status in ["success", "partial", "skipped"],
                "status": status,
                "reason": reason,
                "execution_time": execution_time,
                "output_files": output_files,
                "discovered_files": discovered_files,
            }

        except Exception as e:
            await self._log_error(
                "FINALIZE_ERROR",
                f"Error finalizing collector {collector_id}: {e}",
                dut_id,
                collector_id,
            )
            return {
                "success": False,
                "status": "error",
                "reason": f"Finalization error: {str(e)}",
                "execution_time": execution_time,
                "output_files": output_files or [],
                "discovered_files": discovered_files or {},
            }

    def _get_collector_group(self, collector_id: str) -> str:
        """
        Get collector group from ID.

        Args:
            collector_id: Collector identifier
        """
        return CollectorServiceMapping.get_service_from_collector_id(collector_id)

    async def _write_collector_output(
        self, dut_id: str, collector_id: str, content: str, filename: str = "output.txt"
    ) -> str:
        """
        Write collector output to file.

        Args:
            dut_id: DUT identifier
            collector_id: Collector identifier
            content: Content to write
            filename: Filename to write
        """
        try:
            group = self._get_collector_group(collector_id)
            if self.logger:
                file_path = await self.logger.write_collector_output(
                    dut_id, group, collector_id, filename, content
                )
                return str(file_path)
            else:
                # Fallback if logger not available
                return ""
        except Exception as e:
            await self._log_error(
                "OUTPUT_ERROR",
                f"Error writing collector output: {e}",
                dut_id,
                collector_id,
            )
            return ""

    async def _log_collector_error(
        self, dut_id: str, collector_id: str, error_message: str, context: dict = None
    ) -> str:
        """
        Log collector error and return the error log path.

        Args:
            dut_id: DUT identifier
            collector_id: Collector identifier
            error_message: Error message
            context: Context of the error
        """
        try:
            # Write error to error-logs directory
            if self.logger:
                error_log_path = await self.logger.write_error_log(
                    dut_id, collector_id, error_message, context
                )
                return str(error_log_path) if error_log_path else ""
            else:
                # Fallback if logger not available
                return ""
        except Exception as e:
            await self._log_error(
                "ERROR_LOG_ERROR",
                f"Error logging collector error: {e}",
                dut_id,
                collector_id,
            )
            return ""

    async def _create_error_log_file(
        self, dut_id: str, collector_id: str, error_message: str, context: dict = None
    ) -> str:
        """
        Create error log file and return the path - wrapper around _log_collector_error.

        Args:
            dut_id: DUT identifier
            collector_id: Collector identifier
            error_message: Error message
            context: Context of the error
        """
        return await self._log_collector_error(
            dut_id, collector_id, error_message, context
        )

    async def write_output_file(
        self, dut_id: str, collector_id: str, filename: str, content: Union[str, bytes]
    ) -> str:
        """
        Write output content to a file.

        Args:
            dut_id: DUT identifier
            collector_id: Collector identifier
            filename: Filename to write
            content: Content to write
        """
        try:
            # Debug logging
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "BaseService",
                f"write_output_file: collector_id='{collector_id}', filename='{filename}', content_length={len(content) if content else 0}",
            )
            # print(f"DEBUG: write_output_file called with collector_id='{collector_id}', filename='{filename}'")

            # Ensure collector_id is not empty
            if not collector_id:
                await self._log_runtime(
                    "WARN",
                    "BaseService",
                    f"Empty collector_id for {filename}, using service name",
                    dut_id,
                )
                collector_id = self.service_name

            group = self._get_collector_group(collector_id)
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"write_output_file: group='{group}', collector_id='{collector_id}'",
                dut_id,
            )

            if self.logger:
                if hasattr(self.logger, "_apply_stream_window_to_filename"):
                    filename = self.logger._apply_stream_window_to_filename(
                        collector_id, filename
                    )
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"About to call logger.write_collector_output with dut_id='{dut_id}', group='{group}', collector_id='{collector_id}', filename='{filename}'",
                    dut_id,
                )

                file_path = await self.logger.write_collector_output(
                    dut_id, group, collector_id, filename, content
                )

                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"logger.write_collector_output returned: {file_path} (type: {type(file_path)})",
                    dut_id,
                )

                result = str(file_path)
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"write_output_file returning: '{result}'",
                    dut_id,
                )
                return result
            else:
                # Fallback if logger not available
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Logger is None - cannot write output file {filename}",
                    dut_id,
                )
                return ""
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Exception in write_output_file for {filename}: {str(e)}",
                dut_id,
            )
            # Also log the full exception details
            import traceback

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Full traceback: {traceback.format_exc()}",
                dut_id,
            )
            return ""

    async def substitute_variables(
        self, template: str, context: Dict[str, Any], dut_id: str = None, **kwargs
    ) -> str:
        """
        Substitute variables in a template string using the variable substitution service.

        Args:
            template: String containing variable placeholders like {variable_name}
            context: Dictionary containing variable values
            dut_id: DUT ID for logging
            **kwargs: Additional arguments to pass to the variable service

        Returns:
            String with variables substituted
        """
        # Create variable engine if it doesn't exist
        if self.variable_engine is None:
            await self._update_variable_engine(dut_id)

        try:
            return await self.variable_engine.substitute_variables(
                template, context, dut_id, **kwargs
            )
        except Exception as e:
            await self._log_runtime(
                "ERROR", "BaseService", f"Variable substitution failed: {e}", dut_id
            )
            # Return original template on error
            return template

    async def get_variable_engine_stats(self, dut_id: str = None) -> Dict[str, Any]:
        """
        Get statistics from the variable substitution service.

        Args:
            dut_id: DUT identifier
        """
        # Create variable engine if it doesn't exist
        if self.variable_engine is None:
            await self._update_variable_engine(dut_id)

        return await self.variable_engine.get_cache_stats(dut_id)

    async def clear_variable_cache(self, dut_id: str = None) -> None:
        """
        Clear the variable substitution cache.

        Args:
            dut_id: DUT identifier
        """
        # Create variable engine if it doesn't exist
        if self.variable_engine is None:
            await self._update_variable_engine(dut_id)

        await self.variable_engine.clear_cache(dut_id)

    def substitute_output_pattern_variables(
        self,
        output_pattern: str,
        substitutions: Dict[str, str] = None,
        fallback_name: str = None,
    ) -> str:
        """
        Substitute variables in an output pattern with provided values.
        If no variables are present, returns the pattern as-is.

        Args:
            output_pattern: The pattern containing variables like {variable_name}
            substitutions: Dictionary mapping variable names to values (optional)
            fallback_name: Fallback filename if no substitutions are made (optional)

        Returns:
            String with variables substituted, or the original pattern if no variables present
        """
        if not output_pattern:
            return fallback_name or "output.json"

        # If no substitutions provided, return pattern as-is
        if not substitutions:
            return output_pattern

        result = output_pattern

        # Apply each substitution
        for variable, value in substitutions.items():
            placeholder = f"{{{variable}}}"
            if placeholder in result:
                result = result.replace(placeholder, str(value))

        # If no substitutions were made, return the original pattern
        # This handles both static strings and patterns with no matching variables
        return result

    def get_output_filename(
        self,
        output_pattern: str = None,
        function_tag: str = None,
        default_extension: str = ".txt",
        substitutions: Dict[str, str] = None,
    ) -> str:
        """
        Generic method to get the final output filename from output_pattern or function_tag.

        Args:
            output_pattern: The output pattern from the collector definition (optional)
            function_tag: The function tag to use as fallback (optional)
            default_extension: Default file extension to append if function_tag is used
            substitutions: Dictionary of variable substitutions (optional)

        Returns:
            Final filename to use for output
        """
        if output_pattern:
            # Use provided substitutions or default to command_name
            if substitutions is None and function_tag:
                substitutions = {"command_name": function_tag}

            # The method now handles both static patterns and variable substitution automatically
            return self.substitute_output_pattern_variables(
                output_pattern, substitutions
            )
        elif function_tag:
            # Fallback to function_tag with default extension
            return f"{function_tag}{default_extension}"
        else:
            # Ultimate fallback
            return f"output{default_extension}"

    async def write_output_with_generalization(
        self,
        dut_id: str,
        collector_id: str,
        content: Any,
        output_pattern: str = None,
        function_tag: str = None,
        default_extension: str = ".txt",
        substitutions: Dict[str, str] = None,
        **kwargs,
    ) -> str:
        """
        Single function to handle all output file writing with generalization.
        This replaces the repetitive pattern of getting filename and writing file.

        Args:
            dut_id: DUT identifier
            collector_id: Collector identifier
            content: Content to write to file
            output_pattern: Output pattern from collector definition (optional)
            function_tag: Function tag for fallback (optional)
            default_extension: Default file extension (optional)
            substitutions: Variable substitutions (optional)
            **kwargs: Additional parameters

        Returns:
            Path to the created file
        """
        try:
            # Convert content to string based on type
            if isinstance(content, bytes):
                # Keep bytes as-is for binary data
                content_str = content
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "BaseService",
                    f"Content is bytes, keeping as binary data, length: {len(content_str)}",
                )
            elif isinstance(content, dict):
                import json

                content_str = json.dumps(content, indent=2)
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "BaseService",
                    f"Converted dict content to JSON string, length: {len(content_str)}",
                )
            elif isinstance(content, (list, tuple)):
                content_str = json.dumps(content, indent=2)
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "BaseService",
                    f"Converted {type(content).__name__} content to JSON string, length: {len(content_str)}",
                )
            elif isinstance(content, (int, float, bool)):
                content_str = str(content)
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Converted {type(content).__name__} content to string: {content_str}",
                    dut_id,
                )
            elif isinstance(content, str):
                content_str = content
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Content is already string, length: {len(content_str)}",
                    dut_id,
                )
            elif content is None:
                content_str = ""
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    "Content is None, using empty string",
                    dut_id,
                )
            else:
                # For any other type, try to convert to string
                content_str = str(content)
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Converted unknown type {type(content).__name__} to string, length: {len(content_str)}",
                    dut_id,
                )

            # Debug logging
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"write_output_with_generalization: collector_id='{collector_id}', function_tag='{function_tag}', output_pattern='{output_pattern}', content_type={type(content)}, content_length={len(content_str)}",
                dut_id,
            )

            # Get the final filename using generalization
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"About to call get_output_filename with output_pattern='{output_pattern}', function_tag='{function_tag}', substitutions={substitutions}",
                dut_id,
            )

            final_filename = self.get_output_filename(
                output_pattern, function_tag, default_extension, substitutions
            )

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"get_output_filename returned: '{final_filename}'",
                dut_id,
            )

            # Write the file
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"About to call write_output_file with final_filename='{final_filename}'",
                dut_id,
            )

            result = await self.write_output_file(
                dut_id, collector_id, final_filename, content_str
            )

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"write_output_with_generalization returning: '{result}'",
                dut_id,
            )

            return result
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Exception in write_output_with_generalization: {str(e)}",
                dut_id,
            )
            # Also log the full exception details
            import traceback

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Full traceback: {traceback.format_exc()}",
                dut_id,
            )
            return ""

    def _get_hook_parameter_mapping(self, method_name: str) -> Dict[str, str]:
        """
        Get parameter mapping configuration for a method.

        Returns:
            Dictionary mapping hook parameter names to method parameter names
        """
        # Define parameter mappings for different methods
        mappings = {
            # Redfish service methods
            "get_redfish_response_to_file": {
                # No parameter mapping needed - uri maps to uri directly
            },
            "collect_redfish_expand_with_traversal": {
                # No parameter mapping needed - base_uri maps to base_uri directly
                # expand_level maps to expand_level directly
            },
            "collect_redfish_collection_with_members": {
                "base_uri": "collection_uri",
                "function_tag": "entity_type",
            },
            "collect_redfish_uri_list": {
                "uri_list_key": "uri_list",  # Will be processed specially
                "function_tag": "entity_type",
            },
            "collect_redfish_chassis_with_filter": {
                "chassis_filter": "filter_criteria",  # Will be processed specially
            },
            "collect_redfish_unified": {
                "additional_member_collections": "additional_member_collections",
            },
            # Host service methods
            "run_host_commands": {
                "commands": "commands",
                "function_tag": "function_tag",
            },
            # IPMI service methods
            "run_ipmi_command": {
                "command": "command",
                "function_tag": "function_tag",
            },
            "run_ipmi_commands": {
                "commands": "commands",
                "function_tag": "function_tag",
            },
            "run_ipmi_command_with_nvbmc_handling": {
                "command": "command",
                "function_tag": "function_tag",
                "nvbmc_platforms": "nvbmc_platforms",
            },
            "run_ipmi_command_with_file_output": {
                "command": "command",
                "function_tag": "function_tag",
            },
            # BMC SSH service methods
            "run_bmc_command": {
                "command": "command",
                "function_tag": "function_tag",
                "baseboard_commands": "baseboard_commands",
            },
            "run_bmc_commands": {
                "commands": "commands",
                "function_tag": "function_tag",
            },
            "run_bmc_file_transfer": {
                "source_path": "source_path",
                "archive_name": "archive_name",
                "function_tag": "function_tag",
                "use_sftp": "use_sftp",
                "fallback_hexdump": "fallback_hexdump",
                "key_files": "key_files",
                "retry_count": "retry_count",
                "retry_delay": "retry_delay",
                "chunk_size_kb": "chunk_size_kb",
                "max_file_size_mb": "max_file_size_mb",
                "config_keys": "config_keys",
            },
            "run_bmc_script": {
                "script_name": "script_name",
                "script_name_pattern": "script_name_pattern",
                "function_tag": "function_tag",
                "use_hmc_ip": "use_hmc_ip",
                "auto_retrieve_files": "auto_retrieve_files",
                "use_working_directory": "use_working_directory",
                "working_dir": "working_dir",
                "pass_working_dir_to_script": "pass_working_dir_to_script",
                "script_timeout": "script_timeout",
                "output_file_pattern": "output_file_pattern",
                "output_search_dirs": "output_search_dirs",
                "execution_mode": "execution_mode",
                "script_args": "script_args",
                "alternative_scripts": "alternative_scripts",
            },
            "copy_files_from_bmc": {
                "working_dir": "working_dir",
                "output_file_pattern": "output_file_pattern",
                "output_search_dirs": "output_search_dirs",
                "function_tag": "function_tag",
                "cleanup_working_dir": "cleanup_working_dir",
            },
            "run_bmc_platform_specific": {
                "platform": "platform",
                "commands": "commands",
                "function_tag": "function_tag",
            },
        }

        return mappings.get(method_name, {})

    async def _apply_parameter_mapping(
        self, method_name: str, hook_params: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Apply parameter mapping and special processing for a method.

        Args:
            method_name: Name of the method being called
            hook_params: Parameters from the hook
            context: Current execution context

        Returns:
            Processed parameters ready for method call
        """
        mapping = self._get_hook_parameter_mapping(method_name)
        processed_params = hook_params.copy()

        # Debug: Log parameter mapping
        dut_id = context.get("dut_id", "unknown")
        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"Parameter mapping for {method_name}: {mapping}",
            dut_id,
        )
        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"Original hook_params: {list(hook_params.keys())}",
            dut_id,
        )

        # Apply standard parameter mappings
        for hook_param, method_param in mapping.items():
            if hook_param in processed_params:
                value = processed_params.pop(hook_param)

                # Special processing for certain parameters
                if (
                    method_name == "collect_redfish_uri_list"
                    and hook_param == "uri_list_key"
                ):
                    # For now, use empty list - would need config resolution
                    processed_params[method_param] = []
                elif (
                    method_name == "collect_redfish_chassis_with_filter"
                    and hook_param == "chassis_filter"
                ):
                    # Convert to filter criteria format
                    processed_params[method_param] = {"filter": value}
                else:
                    # Standard mapping
                    processed_params[method_param] = value

        # Add common parameters if not present
        if "dut_id" not in processed_params:
            processed_params["dut_id"] = context.get("dut_id")
        if "collector_id" not in processed_params:
            processed_params["collector_id"] = context.get("collector_id")

        # Handle output_pattern consistently
        if "output_pattern" in hook_params:
            processed_params["filename"] = hook_params["output_pattern"]
        elif "output_pattern" in processed_params:
            processed_params["filename"] = processed_params.pop("output_pattern")

        return processed_params

    def _process_command_output(
        self, output: Union[str, bytes, None], encoding: str = "utf-8"
    ) -> str:
        """
        Process command output to ensure it's in string format.
        Matches legacy nvdebug implementation.

        Args:
            output: The command output to process (can be str, bytes, or None)
            encoding: The encoding to use for bytes decoding (default: utf-8)

        Returns:
            str: The processed output as a string
        """
        if output is None:
            return ""

        if isinstance(output, bytes):
            try:
                # First try UTF-8 with replace
                return output.decode(encoding, errors="replace")
            except Exception:
                try:
                    # Try latin1 as fallback - it can handle all byte values
                    return output.decode("latin1", errors="replace")
                except Exception:
                    # Last resort - hex representation
                    return f"hex:{output.hex()}"

        # Handle case where output is already a string
        if isinstance(output, str):
            return output

        # For any other type, try string conversion with error handling
        try:
            return str(output)
        except Exception:
            return f"<unconvertible output of type {type(output).__name__}>"

    def _format_command_error(
        self,
        command: str,
        exit_code: int,
        stdout: Union[str, bytes, None],
        stderr: Union[str, bytes, None],
        command_type: str = "",
        output_file: Optional[str] = None,
    ) -> str:
        """
        Format error messages for command execution failures consistently.
        Matches legacy nvdebug implementation.

        Args:
            command: The command that was executed
            exit_code: The exit/return code from the command
            stdout: The stdout from the command
            stderr: The stderr from the command
            command_type: Optional type of command (SSH, IPMI, etc.)
            output_file: Optional path to file where stdout was written

        Returns:
            str: Formatted error message
        """
        try:
            # Process stdout and stderr
            stdout_msg = self._process_command_output(stdout) if stdout else "<empty>"
            stderr_msg = self._process_command_output(stderr) if stderr else "<empty>"
            cmd_type = f"{command_type}" if command_type else ""

            # Wrap stdout and stderr in curly braces and indent their content by 4 spaces
            indented_stdout = "" + textwrap.indent(stdout_msg, "    ") + ""
            indented_stderr = "" + textwrap.indent(stderr_msg, "    ") + ""

            error_msg = f"""
Error while running {cmd_type} collector
Command   : {command}
Exit Code : {exit_code}
STDERR    :
{indented_stderr}
STDOUT    :
{indented_stdout}
"""
            return error_msg
        except Exception as e:
            return f"Error formatting command output: {str(e)}"

    async def _log_command_result(
        self,
        command: str,
        exit_code: int,
        stdout: Union[str, bytes, None],
        stderr: Union[str, bytes, None],
        command_type: str = "",
        dut_id: Optional[str] = None,
        collector_id: Optional[str] = None,
        log_errors: bool = True,
    ) -> None:
        """
        Log command execution results consistently.
        Matches legacy nvdebug logging pattern.

        Args:
            command: The command that was executed
            exit_code: The exit/return code from the command
            stdout: The stdout from the command
            stderr: The stderr from the command
            command_type: Optional type of command (SSH, IPMI, etc.)
            dut_id: DUT identifier for logging
            collector_id: Collector identifier for logging
            log_errors: Whether to log errors to error file
        """
        if exit_code == 0:
            await self._log_runtime(
                "INFO",
                f"{command_type.upper() if command_type else 'COMMAND'}",
                f"Command run successfully: {command}",
            )
        else:
            if log_errors:
                error_msg = self._format_command_error(
                    command, exit_code, stdout, stderr, command_type
                )
                await self._log_error(
                    f"{command_type.upper() if command_type else 'COMMAND'}_ERROR",
                    error_msg,
                    dut_id,
                    collector_id,
                )

    def _create_command_output_content(
        self,
        command: str,
        exit_code: int,
        stdout: Union[str, bytes, None],
        stderr: Union[str, bytes, None],
    ) -> str:
        """
        Create standardized command output content for file writing.
        Matches legacy nvdebug output format.

        Args:
            command: The command that was executed
            exit_code: The exit/return code from the command
            stdout: The stdout from the command
            stderr: The stderr from the command

        Returns:
            str: Formatted output content for file writing
        """
        stdout_processed = self._process_command_output(stdout) if stdout else ""
        stderr_processed = self._process_command_output(stderr) if stderr else ""

        content = f"Command: {command}\n"
        content += f"Exit Code: {exit_code}\n"
        content += f"Output:\n{stdout_processed}"

        # Include stderr if present
        if stderr_processed:
            content += f"\n\nSTDERR:\n{stderr_processed}"

        return content

    # ============================================================================
    # 11. COMMON UTILITY FUNCTIONS (Shared between services)
    # ============================================================================

    async def _log_collection_start(self, dut_id: str, collector_name: str) -> None:
        """
        Common logging for collection start.

        Args:
            dut_id: DUT identifier
            collector_name: Name of the collector
        """
        await self._log_runtime(
            "INFO", "BaseService", f"Starting {collector_name} collection", dut_id
        )

    def _create_success_response(
        self, output_files: List[str], context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Create standardized success response.

        Args:
            output_files: List of output files
            context: Context of the success
        """
        return {
            "success": True,
            "output_files": output_files,
            "context": context or {},
        }

    def _create_error_response(
        self, reason: str, output_files: List[str] = None
    ) -> Dict[str, Any]:
        """
        Create standardized error response.

        Args:
            reason: Reason for the error
            output_files: List of output files
        """
        return {
            "success": False,
            "reason": reason,
            "output_files": output_files or [],
        }

    async def _log_collection_success(
        self, dut_id: str, collection_type: str, details: str, file_path: str = None
    ) -> None:
        """
        Common logging for collection success.

        Args:
            dut_id: DUT identifier
            collection_type: Type of collection
            details: Details of the collection
            file_path: Path to the file
        """
        message = f"{collection_type} collection succeeded: {details}"
        if file_path:
            message += f" -> {file_path}"
        await self._log_runtime("INFO", "BaseService", message, dut_id)

    async def _log_collection_failure(
        self,
        dut_id: str,
        collection_type: str,
        details: str,
        error: str = None,
        collector_id: str = None,
    ) -> None:
        """
        Common logging for collection failure.

        Args:
            dut_id: DUT identifier
            collection_type: Type of collection
            details: Details of the collection
            error: Error message
            collector_id: Collector identifier
        """
        message = f"{collection_type} collection failed: {details}"
        if error:
            message += f" - {error}"
        await self._log_runtime("ERROR", "BaseService", message, dut_id)

        # Also create detailed error log file for better debugging
        try:
            # Use provided collector_id or fall back to collection_type
            actual_collector_id = collector_id or f"{collection_type}_collection"
            # Create error log file with context
            error_log_path = await self._create_error_log_file(
                dut_id=dut_id,
                collector_id=actual_collector_id,
                error_message=message,
                context={
                    "collection_type": collection_type,
                    "details": details,
                    "error": error,
                    "operation": "collection_failure",
                },
            )
            if error_log_path:
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Created error log file: {error_log_path}",
                    dut_id,
                )
        except Exception as e:
            # Don't let error log creation failure break the main flow
            await self._log_runtime(
                "WARN",
                "BaseService",
                f"Failed to create error log file for {collection_type} collection: {str(e)}",
                dut_id,
            )

    async def _execute_with_error_handling(
        self, dut_id: str, operation_name: str, operation_func, *args, **kwargs
    ) -> Dict[str, Any]:
        """
        Common error handling wrapper for operations.

        Args:
            dut_id: DUT identifier
            operation_name: Name of the operation
            operation_func: Function to execute
        """
        try:
            return await operation_func(*args, **kwargs)
        except Exception as e:
            await self._log_collection_failure(
                dut_id,
                operation_name,
                "Exception occurred",
                str(e),
                collector_id=kwargs.get("collector_id"),
            )
            return self._create_error_response(
                f"Exception in {operation_name}: {str(e)}"
            )

    def _extract_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """
        Extract nested value from dictionary using dot notation.

        Args:
            data: Dictionary to search in
            path: Dot-separated path (e.g., "Members.0.@odata.id")

        Returns:
            Value at path or None if not found
        """
        keys = path.split(".")
        current = data

        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None

        return current

    def _extract_output_pattern_params(
        self, kwargs: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """
        Extract output_pattern and substitutions from kwargs, return filtered kwargs

        Args:
            kwargs: Original kwargs dictionary

        Returns:
            Tuple of (output_pattern, substitutions, filtered_kwargs)
        """
        # Handle case where kwargs might not be a dictionary
        if not isinstance(kwargs, dict):
            return None, {}, {}

        output_pattern = kwargs.get("output_pattern")
        substitutions = kwargs.get("substitutions", {})

        # Remove output_pattern and substitutions from kwargs to avoid conflicts
        filtered_kwargs = {
            k: v
            for k, v in kwargs.items()
            if k not in ["output_pattern", "substitutions"]
        }

        return output_pattern, substitutions, filtered_kwargs

    async def _save_data_with_common_pattern(
        self,
        dut_id: str,
        data: Any,
        function_tag: str,
        output_pattern: str = None,
        substitutions: Dict[str, Any] = None,
        default_extension: str = ".txt",
        **kwargs,
    ) -> Optional[str]:
        """
        Common data saving function with pattern handling

        Args:
            dut_id: DUT identifier
            data: Data to save
            function_tag: Function tag for file naming
            output_pattern: Output pattern for filename
            substitutions: Variable substitutions for pattern
            **kwargs: Additional parameters for write_output_with_generalization

        Returns:
            File path if successful, None otherwise
        """
        try:
            # Log input parameters for debugging
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"_save_data_with_common_pattern called with function_tag='{function_tag}', output_pattern='{output_pattern}', data_type={type(data)}, data_length={len(str(data)) if data else 0}",
                dut_id,
            )

            # Extract collector_id from kwargs to avoid duplicate argument
            collector_id = kwargs.get("collector_id", "")
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Extracted collector_id: '{collector_id}'",
                dut_id,
            )

            # Remove collector_id and list parameters from kwargs to avoid conflicts
            if isinstance(kwargs, dict):
                filtered_kwargs = {
                    k: v
                    for k, v in kwargs.items()
                    if k != "collector_id" and not isinstance(v, list)
                }
            else:
                filtered_kwargs = {}

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"About to call write_output_with_generalization with collector_id='{collector_id}', function_tag='{function_tag}'",
                dut_id,
            )

            # Check if logger is available
            if not self.logger:
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Logger is None - cannot save data for {function_tag}",
                    dut_id,
                )
                return None

            file_path = await self.write_output_with_generalization(
                dut_id,
                collector_id,
                data,
                output_pattern=output_pattern,
                function_tag=function_tag,
                default_extension=default_extension,
                substitutions=substitutions or {},
                **filtered_kwargs,
            )

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"write_output_with_generalization returned: '{file_path}' (type: {type(file_path)})",
                dut_id,
            )

            if not file_path:
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"write_output_with_generalization returned empty/None for {function_tag}",
                    dut_id,
                )
                return None

            # Log the final file path to track folder naming
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Generated file path: '{file_path}' for function_tag='{function_tag}', collector_id='{collector_id}'",
                dut_id,
            )

            return file_path
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Exception in _save_data_with_common_pattern for {function_tag}: {str(e)}",
                dut_id,
            )
            # Also log the full exception details

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Full traceback: {traceback.format_exc()}",
                dut_id,
            )
            return None

    async def _determine_collector_status(
        self,
        successful_operations: int,
        total_operations: int,
        error_messages: List[str] = None,
        operation_name: str = "operations",
        additional_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Standardized function to determine collector status based on partial success logic.

        Args:
            successful_operations: Number of successful operations
            total_operations: Total number of operations attempted
            error_messages: List of error messages (optional)
            operation_name: Name of the operation type for logging (e.g., "collections", "files", "entities")
            additional_context: Additional context that might contain status information

        Returns:
            Dictionary with standardized status information:
            {
                "success": bool,
                 "status": str,  # "success", "partial", "error", or "skipped"
                "reason": str,
                "context": {
                    "successful_operations": int,
                    "total_operations": int,
                    "error_messages": List[str]
                }
            }
        """
        if error_messages is None:
            error_messages = []
        if additional_context is None:
            additional_context = {}

        # Allow explicit status overrides from additional context
        override_status = additional_context.get("status")
        if override_status in {"skipped", "partial", "error", "success"}:
            status = override_status
            if override_status == "skipped":
                success = True  # Skipped is not a failure
                reason = additional_context.get(
                    "reason", f"Collector {operation_name} was skipped"
                )
            elif override_status == "error":
                success = False
                reason = additional_context.get(
                    "reason",
                    self._format_error_messages(error_messages, operation_name),
                )
            elif override_status == "partial":
                success = True
                reason = additional_context.get(
                    "reason",
                    f"Partial success: {successful_operations}/{total_operations} {operation_name} succeeded.\n"
                    + self._format_error_messages(
                        error_messages, operation_name, is_partial=True
                    ),
                )
            else:
                success = True
                reason = additional_context.get(
                    "reason",
                    f"Successfully completed {successful_operations}/{total_operations} {operation_name}",
                )
        elif successful_operations == 0 and total_operations == 0:
            # No operations attempted - treat as skipped
            success = True
            status = "skipped"
            reason = f"No {operation_name} to perform - collector skipped"
        elif successful_operations == 0:
            # Complete failure
            success = False
            status = "error"
            reason = self._format_error_messages(error_messages, operation_name)
        elif successful_operations < total_operations:
            # Partial success
            success = True
            status = "partial"
            reason = (
                f"Partial success: {successful_operations}/{total_operations} {operation_name} succeeded.\n"
                + self._format_error_messages(
                    error_messages, operation_name, is_partial=True
                )
            )
        else:
            # Complete success
            success = True
            status = "success"
            reason = f"Successfully completed {successful_operations}/{total_operations} {operation_name}"

        result = {
            "success": success,
            "status": status,
            "reason": reason,
            "context": {
                "successful_operations": successful_operations,
                "total_operations": total_operations,
                "error_messages": error_messages,
            },
        }

        # Debug logging for status determination
        if hasattr(self, "_log_runtime"):
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Status determination: successful_operations={successful_operations}, total_operations={total_operations}, determined_status={status}, success={success}",
                None,  # No dut_id available in this context
            )

        return result

    def _build_standardized_result(
        self,
        status_info: Dict[str, Any],
        output_files: List[str] = None,
        additional_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Build a standardized result dictionary for collectors.

        Args:
            status_info: Status information from _determine_collector_status
            output_files: List of output files generated
            additional_context: Additional context specific to the collector

        Returns:
            Standardized result dictionary with consistent structure
        """
        if output_files is None:
            output_files = []
        if additional_context is None:
            additional_context = {}

        result = {
            "success": status_info["success"],
            "status": status_info["status"],
            "reason": status_info["reason"],
            "context": {
                "total_files": len(output_files),
                "output_files": output_files,
                **status_info["context"],
                **additional_context,
            },
        }

        return result

    async def _create_standardized_collector_result_internal(
        self,
        successful_operations: int,
        total_operations: int,
        output_files: List[str] = None,
        error_messages: List[str] = None,
        operation_name: str = "operations",
        additional_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Internal method: Create a standardized collector result in one function call.

        This combines status determination and result building into a single,
        easy-to-use function that ensures consistency across all collectors.

        Args:
            successful_operations: Number of successful operations
            total_operations: Total number of operations attempted
            output_files: List of output files generated
            error_messages: List of error messages (optional)
            operation_name: Name of the operation type for logging
            additional_context: Additional context specific to the collector

        Returns:
            Standardized result dictionary with consistent structure:
            {
                "success": bool,
                "status": str,  # "success", "partial", or "error"
                "reason": str,
                "context": {
                    "total_files": int,
                    "output_files": List[str],
                    "successful_operations": int,
                    "total_operations": int,
                    "error_messages": List[str],
                    ...additional_context...
                }
            }
        """
        if output_files is None:
            output_files = []
        if error_messages is None:
            error_messages = []
        if additional_context is None:
            additional_context = {}

        # Determine status
        status_info = await self._determine_collector_status(
            successful_operations,
            total_operations,
            error_messages,
            operation_name,
            additional_context,
        )

        # Build and return standardized result
        return self._build_standardized_result(
            status_info, output_files, additional_context
        )

    async def _create_standardized_collector_result(
        self,
        successful_operations: int,
        total_operations: int,
        output_files: List[str] = None,
        error_messages: List[str] = None,
        operation_name: str = "operations",
        additional_context: Dict[str, Any] = None,
        dut_id: str = None,
        collector_id: str = None,
    ) -> Dict[str, Any]:
        """
        Create a standardized collector result with optional debug logging.

        This is the main method that all collectors should call. It includes
        debug logging when dut_id and collector_id are provided.

        Args:
            successful_operations: Number of successful operations
            total_operations: Total number of operations attempted
            output_files: List of output files generated
            error_messages: List of error messages (optional)
            operation_name: Name of the operation type for logging
            additional_context: Additional context specific to the collector
            dut_id: DUT ID for debug logging (optional)
            collector_id: Collector ID for debug logging (optional)

        Returns:
            Standardized result dictionary with consistent structure
        """
        if output_files is None:
            output_files = []
        if error_messages is None:
            error_messages = []
        if additional_context is None:
            additional_context = {}

        accounting_warning = None
        if successful_operations > total_operations:
            accounting_warning = (
                "Collector accounting anomaly detected: "
                f"successful_operations ({successful_operations}) exceeds "
                f"total_operations ({total_operations}). Clamping to total_operations."
            )
            additional_context.setdefault("accounting_warnings", []).append(
                accounting_warning
            )
            successful_operations = total_operations

        # Auto-detect dut_id and collector_id if not provided
        if dut_id is None:
            dut_id = self._get_current_dut_id()
        if collector_id is None:
            collector_id = self._get_current_collector_id()

        if accounting_warning and hasattr(self, "_log_runtime"):
            await self._log_runtime(
                "WARNING",
                "BaseService",
                accounting_warning,
                dut_id,
            )

        # Add debug logging if dut_id and collector_id are available and not "unknown"
        if (
            dut_id
            and dut_id != "unknown"
            and collector_id
            and collector_id != "unknown"
        ):
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"About to return standardized result for {collector_id} with {len(output_files)} output_files: {output_files}",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"About to return standardized result for {collector_id} with {len(error_messages)} error_messages: {error_messages}",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Successful operations over total operations: {successful_operations}/{total_operations}",
                dut_id,
            )

        # Call the internal method to create the result
        result = await self._create_standardized_collector_result_internal(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name=operation_name,
            additional_context=additional_context,
        )

        # Add debug logging if dut_id and collector_id are available and not "unknown"
        if (
            dut_id
            and dut_id != "unknown"
            and collector_id
            and collector_id != "unknown"
        ):
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Returning standardized result for {collector_id}: success={result.get('success')}, status={result.get('status')}, output_files in context: {result.get('context', {}).get('output_files', [])}",
                dut_id,
            )

        return result

    async def _process_collector_result(
        self,
        result: Dict[str, Any],
        all_output_files: List[str],
        all_status_list: List[bool],
        error_messages: List[str],
        entity_type: str = "entity",
        entity_id: str = "unknown",
        dut_id: str = None,
        collector_id: str = None,
        custom_error_format: str = None,
    ) -> None:
        """
        Common function to process collector results and handle output file aggregation and error logging.

        This function:
        1. Extracts output files from both top-level and context dictionaries
        2. Creates error log files for failed operations
        3. Adds error log files to the output files list
        4. Updates status and error message lists

        Args:
            result: The result dictionary from a collector operation
            all_output_files: List to extend with output files
            all_status_list: List to append success/failure status
            error_messages: List to append error messages
            entity_type: Type of entity (e.g., "nvswitch", "system", "entity")
            entity_id: ID of the entity
            dut_id: DUT ID for error logging (optional)
            collector_id: Collector ID for error logging (optional)
            custom_error_format: Custom error message format (optional)
        """
        # Handle different status types: success, partial, error, skipped
        status = result.get("status", "success")
        success = result.get("success", False)

        if status == "skipped":
            # Treat skipped as successful
            all_status_list.append(True)
        elif status in ["success", "partial"] or success:
            # Collect output files from both top-level and context (like R35 fix)
            top_level_files = result.get("output_files", [])
            context_files = result.get("context", {}).get("output_files", [])
            all_files = list(set(top_level_files + context_files))
            all_output_files.extend(all_files)

            # For partial status, we might have mixed success/failure in status_list
            if status == "partial" and "context" in result:
                status_list = result.get("context", {}).get("status_list", [True])
                all_status_list.extend(status_list)
            else:
                all_status_list.append(True)
        else:
            # Handle failure case (status == "error" or success == False)
            all_status_list.append(False)

            # Use custom error format if provided, otherwise use default
            if custom_error_format:
                error_msg = custom_error_format
            else:
                error_msg = result.get(
                    "reason",
                    f"Failed to collect {entity_type} {entity_id}",
                )

            # Use different error message formats based on entity type
            if entity_type == "entity" and entity_id == "unknown":
                # Generic format for unknown entities
                error_messages.append(error_msg)
            else:
                # Specific format for known entities
                error_messages.append(f"{entity_type} {entity_id}: {error_msg}")

            # Create error log file for failed operations (only if dut_id and collector_id provided)
            if dut_id and collector_id:
                # Check if there are detailed request contexts for this entity
                detailed_context = {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "operation": "collector_operation",
                    "result": result,
                }

                # Add detailed request context if available
                if result.get("context", {}).get("failed_entity_contexts"):
                    # Pass the full failed entity contexts dictionary
                    detailed_context["result"] = {
                        "context": {
                            "failed_entity_contexts": result["context"][
                                "failed_entity_contexts"
                            ],
                            # Also include the specific entity context for this error
                            "current_entity_context": result["context"][
                                "failed_entity_contexts"
                            ].get(entity_id, {}),
                        }
                    }
                elif result.get("context", {}).get("failed_service_contexts"):
                    # Pass the full failed service contexts dictionary
                    detailed_context["result"] = {
                        "context": {
                            "failed_service_contexts": result["context"][
                                "failed_service_contexts"
                            ],
                            # Also include the specific service context for this error
                            "current_service_context": result["context"][
                                "failed_service_contexts"
                            ].get(entity_id, {}),
                        }
                    }

                error_log_path = await self._create_error_log_file(
                    dut_id=dut_id,
                    collector_id=collector_id,
                    error_message=error_msg,
                    context=detailed_context,
                )

                # Add error log file to output files
                if error_log_path:
                    all_output_files.append(error_log_path)

    def _format_error_messages(
        self, error_messages: List[str], operation_name: str, is_partial: bool = False
    ) -> str:
        """
        Format error messages into a readable, structured format.

        Args:
            error_messages: List of error messages
            operation_name: Name of the operation that failed
            is_partial: Whether this is a partial failure (some succeeded, some failed)

        Returns:
            Formatted error message string
        """
        if not error_messages:
            return f"No specific error messages captured for {operation_name}"

        # Group errors by type for better readability
        device_errors = {}
        http_errors = {}
        other_errors = []

        for error_msg in error_messages:
            if ": HTTP " in error_msg:
                # Extract device and HTTP error info
                parts = error_msg.split(": HTTP ", 1)
                if len(parts) == 2:
                    device = parts[0].strip()
                    http_error = parts[1].strip()
                    if device not in http_errors:
                        http_errors[device] = []
                    http_errors[device].append(http_error)
                else:
                    other_errors.append(error_msg)
            elif "_" in error_msg and ": " in error_msg:
                # Device-specific errors
                parts = error_msg.split(": ", 1)
                if len(parts) == 2:
                    device = parts[0].strip()
                    error_detail = parts[1].strip()
                    if device not in device_errors:
                        device_errors[device] = []
                    device_errors[device].append(error_detail)
                else:
                    other_errors.append(error_msg)
            else:
                other_errors.append(error_msg)

        # Build formatted error message
        formatted_parts = []

        if is_partial:
            formatted_parts.append("Failed operations:")
        else:
            formatted_parts.append(f"All {operation_name} failed. Details:")

        # Add HTTP errors (most common and important)
        if http_errors:
            formatted_parts.append("\nHTTP Errors:")
            for device, errors in http_errors.items():
                formatted_parts.append(f"  • {device}:")
                for error in errors:
                    # Parse HTTP error for better readability
                    if error.startswith("HTTP 400:"):
                        formatted_parts.append(
                            f"    - Bad Request: {self._extract_http_error_message(error)}"
                        )
                    elif error.startswith("HTTP 404:"):
                        formatted_parts.append(
                            f"    - Not Found: {self._extract_http_error_message(error)}"
                        )
                    elif error.startswith("HTTP 500:"):
                        formatted_parts.append(
                            f"    - Server Error: {self._extract_http_error_message(error)}"
                        )
                    else:
                        formatted_parts.append(f"    - {error}")

        # Add device-specific errors
        if device_errors:
            formatted_parts.append("\nDevice Errors:")
            for device, errors in device_errors.items():
                formatted_parts.append(f"  • {device}:")
                for error in errors:
                    formatted_parts.append(f"    - {error}")

        # Add other errors
        if other_errors:
            formatted_parts.append("\nOther Errors:")
            for error in other_errors:
                formatted_parts.append(f"  • {error}")

        return "\n".join(formatted_parts)

    def _extract_http_error_message(self, http_error: str) -> str:
        """
        Extract a readable error message from HTTP error response.

        Args:
            http_error: Full HTTP error string

        Returns:
            Simplified, readable error message
        """
        try:
            # Try to extract JSON error message
            if '"message":' in http_error:
                import json

                # Find the JSON part
                json_start = http_error.find("{")
                if json_start != -1:
                    json_part = http_error[json_start:]
                    # Find the end of the JSON (look for matching braces)
                    brace_count = 0
                    json_end = 0
                    for i, char in enumerate(json_part):
                        if char == "{":
                            brace_count += 1
                        elif char == "}":
                            brace_count -= 1
                            if brace_count == 0:
                                json_end = i + 1
                                break

                    if json_end > 0:
                        json_str = json_part[:json_end]
                        try:
                            error_data = json.loads(json_str)
                            if (
                                "error" in error_data
                                and "message" in error_data["error"]
                            ):
                                return error_data["error"]["message"]
                        except json.JSONDecodeError:
                            pass

            # Fallback: extract message from common patterns
            if "ActionParameterValueError" in http_error:
                return "Invalid parameter value in diagnostic request"
            elif "ResourceMissingAtURI" in http_error:
                return "Resource not found at specified URI"
            elif "AuthenticationRequired" in http_error:
                return "Authentication required"
            else:
                # Return first 100 characters as fallback
                return http_error[:100] + "..." if len(http_error) > 100 else http_error

        except Exception:
            # Ultimate fallback
            return http_error[:100] + "..." if len(http_error) > 100 else http_error

    async def _handle_collection_summary_generation(
        self,
        dut_id: str,
        function_tag: str,
        collection_name: str,
        total_operations: int,
        successful_operations: int,
        failed_operations: int,
        output_files: list,
        additional_details: dict,
        kwargs: dict,
        collection_type: str = "generic",
        ignore_empty_results: bool = True,
    ) -> list:
        """
        Handle collection summary generation based on configuration.

        This method can be used by any collector to:
        1. Generate summary files (text and JSON)
        2. Save detailed failure information to failures.json
        3. Create standardized collector results

        Args:
            dut_id: DUT identifier
            function_tag: Function tag for output files
            collection_name: Name for the collection (used in summaries)
            total_operations: Total number of operations attempted
            successful_operations: Number of successful operations
            failed_operations: Number of failed operations
            output_files: List of output files (will be modified)
            additional_details: Additional details for the summary
            kwargs: Collection kwargs containing summary configuration
            collection_type: Type of collection for text summary
            ignore_empty_results: Whether to ignore empty results

        Returns:
            Updated list of output files (may include summary files)
        """
        # Debug logging to track folder naming issues and status determination.

        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"_handle_collection_summary_generation called: function_tag='{function_tag}', collection_name='{collection_name}', total_ops={total_operations}, successful_ops={successful_operations}, failed_ops={failed_operations}",
            dut_id,
        )

        # Log status determination logic
        if total_operations == 0:
            status = "skipped"
        elif successful_operations == 0:
            status = "error"
        elif successful_operations < total_operations:
            status = "partial"
        else:
            status = "success"

        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"Status determination: {successful_operations}/{total_operations} operations -> status='{status}'",
            dut_id,
        )
        """
        Handle collection summary generation based on configuration.

        Args:
            dut_id: DUT identifier
            function_tag: Function tag for output files
            collection_name: Name for the collection (used in summaries)
            total_operations: Total number of operations attempted
            successful_operations: Number of successful operations
            failed_operations: Number of failed operations
            output_files: List of output files (will be modified)
            additional_details: Additional details for the summary
            kwargs: Collection kwargs containing summary configuration
            collection_type: Type of collection for text summary
            ignore_empty_results: Whether to ignore empty results

        Returns:
            Updated list of output files (may include summary files)
        """
        # Extract summary configuration
        generate_summary = kwargs.get(
            "generate_summary", True
        )  # Default to True for backward compatibility
        summary_format = kwargs.get(
            "summary_format", "text"
        )  # Default to text for backward compatibility
        collector_config = kwargs.get("collector_config")

        if not generate_summary:
            return output_files

        # Use standardized collection summary logging
        await self._log_collection_summary(
            dut_id=dut_id,
            collection_name=collection_name,
            total_operations=total_operations,
            successful_operations=successful_operations,
            failed_operations=failed_operations,
            output_files_count=len(output_files),
            additional_details=additional_details,
        )

        # Generate JSON summary if requested
        if summary_format in ["json", "both"]:
            # Extract output pattern parameters for JSON summary
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            # Create JSON summary content
            success_rate = (
                (successful_operations / total_operations * 100)
                if total_operations > 0
                else 0
            )
            summary_data = {
                "collection_name": collection_name,
                "dut_id": dut_id,
                "timestamp": datetime.now().isoformat(),
                "statistics": {
                    "total_operations": total_operations,
                    "successful_operations": successful_operations,
                    "failed_operations": failed_operations,
                    "success_rate_percent": round(success_rate, 1),
                },
                "output_files": output_files,
                "additional_details": additional_details or {},
            }

            summary_filename = f"{function_tag}_{collection_type}_summary"
            # print(f"DEBUG: Creating JSON summary: function_tag='{function_tag}', collection_name='{collection_name}', summary_filename='{summary_filename}'")
            json_summary_file = await self._save_data_with_common_pattern(
                dut_id,
                json.dumps(summary_data, indent=2),
                summary_filename,
                output_pattern=None,  # Don't use the misleading output_pattern
                substitutions={"file_name": summary_filename},
                default_extension=".json",  # Ensure JSON extension
                **filtered_kwargs,
            )

            if json_summary_file:
                output_files.append(json_summary_file)

        # Generate text summary if requested (for backward compatibility)
        if summary_format in ["text", "both"]:
            # Extract output pattern parameters for text summary
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            summary_content = await self._create_generic_collection_summary(
                function_tag,
                collection_type,
                additional_details,  # Use additional_details as search_info
                {"successful_operations": successful_operations},  # Use results dict
                ignore_empty_results,
                collector_config=collector_config,
                total_operations=total_operations,
                successful_operations=successful_operations,
            )

            summary_filename = f"{function_tag}_{collection_type}_summary"
            # print(f"DEBUG: Creating text summary: function_tag='{function_tag}', collection_name='{collection_name}', summary_filename='{summary_filename}'")
            summary_file_path = await self._save_data_with_common_pattern(
                dut_id,
                summary_content,
                summary_filename,
                output_pattern=None,  # Don't use the misleading output_pattern
                substitutions={"file_name": summary_filename},
                default_extension=".txt",
                **filtered_kwargs,
            )

            if summary_file_path:
                output_files.append(summary_file_path)

        return output_files
