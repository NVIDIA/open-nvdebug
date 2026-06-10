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
Workflow Orchestrator - Main orchestrator for the NVDebug Tool.

Coordinates all aspects of log collection including configuration management,
DUT initialization, preflight checks, collector execution, and reporting.
"""

import asyncio
import gc
import logging
import signal
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import aiohttp
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from ..services.dynamic_discovery_service import DiscoveryConfig
from ..services.html_report_service import HTMLReportService
from ..utils.console_output import create_sanitized_console
from ..utils.dependency_checker import DependencyChecker
from ..utils.enums import CollectorServiceMapping
from ..utils.json_utils import safe_json_dump
from ..utils.timing_manager import TimingManager
from .async_logger import AsyncSafeLogger
from .cleanup_manager import CleanupManager
from .collection_status_tracker import CollectionStatusTracker
from .config_manager import ConfigurationManager
from .dut_manager import DUTManager
from .execution_engine import ExecutionEngine
from .execution_summary import ExecutionSummaryManager
from .progress_display import ProgressDisplay
from .progress_state_manager import ProgressStateManager
from .reporting_engine import ReportingEngine

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CollectorClassification:
    normal_sequential: List[str]
    normal_parallel: List[str]
    tail: List[str]


@dataclass(frozen=True)
class DutExecutionPlan:
    dut_id: str
    normal_sequential: List[str]
    normal_parallel: List[str]
    tail: List[str]


class WorkflowOrchestrator:
    """
    Main orchestrator for the NVDebug Tool.

    Coordinates all aspects of log collection including configuration management,
    DUT initialization, preflight checks, collector execution, and reporting.

    Attributes:
        config_manager: Configuration manager instance.
        dut_manager: DUT manager instance.
        logger: Async-safe logger instance.
        timing_manager: Timing manager for performance tracking.
        execution_summary_manager: Execution summary manager.
    """

    def __init__(
        self,
        tool_config=None,
        dut_configs=None,
        log_dir: str = None,
        tool_config_path: str = None,
        dut_config_path: str = None,
        debug_mode: bool = False,
        verbose_mode: bool = False,
        enable_status_tracking: bool = True,
        disable_live_display: bool = False,
        quiet_mode: bool = False,
        sanitized_console=None,
    ) -> None:
        # Support both new object-based and legacy file-based initialization
        if tool_config is not None:
            # New object-based initialization
            self._tool_config_obj = tool_config
            self._dut_configs_obj = dut_configs or []
            self.tool_config_path = None
            self.dut_config_path = None
            # Get debug and verbose from tool_config object directly
            self.debug_mode = getattr(tool_config, "debug", False)
            self.verbose_mode = getattr(tool_config, "verbose", False)
        else:
            # Legacy file-based initialization
            self._tool_config_obj = None
            self._dut_configs_obj = None
            self.tool_config_path = tool_config_path
            self.dut_config_path = dut_config_path
            self.debug_mode = debug_mode
            self.verbose_mode = verbose_mode

        self.log_dir = Path(log_dir) if log_dir else Path("/tmp")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Store quiet mode flag
        self.quiet_mode = quiet_mode

        # Initialize logger first (sanitizer will be set later if available)
        self.logger = AsyncSafeLogger(
            str(self.log_dir),
            self,
            sanitizer=None,
            debug_mode=self.debug_mode,
            verbose_mode=self.verbose_mode,
        )

        # Current execution context tracking for logging
        self.current_collector_id = None
        self.current_execution_context = {}

        # Per-collector context tracking for cross-contamination prevention
        # This is a minimal addition that doesn't break existing functionality
        self.collector_execution_contexts: Dict[str, Dict[str, Any]] = {}

        # Initialize shutdown flag for graceful termination
        self._shutdown_requested = False
        self._signal_handler_called = False

        # Initialize signal handlers for cleanup on interruption
        self._setup_signal_handlers()

        # Initialize managers
        if self._tool_config_obj is not None:
            # Use object-based configuration
            self.config_manager = ConfigurationManager.from_objects(
                self._tool_config_obj,
                self._dut_configs_obj,
                sanitized_console=sanitized_console,
                quiet_mode=self.quiet_mode,
            )
        else:
            # Use file-based configuration (legacy)
            self.config_manager = ConfigurationManager(
                tool_config_path,
                dut_config_path,
                sanitized_console=sanitized_console,
                quiet_mode=self.quiet_mode,
            )

        # In non-quiet mode, pass the async logger to config manager
        if not self.quiet_mode:
            self.config_manager.logger = self.logger
            # Note: Collector categorization will be initialized in async_init()
        self.dut_manager: Optional[DUTManager] = None
        self.dependency_checker = DependencyChecker()
        self.timing_manager = TimingManager(self.log_dir, debug_mode)
        self.execution_summary_manager = ExecutionSummaryManager(self.log_dir)
        # Set logger reference for execution summary manager
        self.execution_summary_manager.logger = self.logger
        self._execution_order_counters: Dict[str, int] = {}
        self._execution_order_entries: Dict[str, List[Dict[str, str]]] = {}

        # Sanitizer will be set by CLI handler if sanitization is enabled
        self.sanitizer = None

        # Console instances - use passed console or create new one
        self.console = sanitized_console.console if sanitized_console else Console()
        self.sanitized_console = (
            sanitized_console
            if sanitized_console
            else create_sanitized_console(self.sanitizer)
        )

        # Initialize collection status tracker (after console is created)
        self.enable_status_tracking = enable_status_tracking
        self.disable_live_display = disable_live_display
        try:
            self.status_tracker = (
                CollectionStatusTracker(self.log_dir, self.console, self.logger)
                if enable_status_tracking
                else None
            )
        except Exception as e:
            # Log the error but don't fail the entire tool
            if self.logger:
                asyncio.create_task(
                    self.logger.log_runtime(
                        "WARN",
                        "WorkflowOrchestrator",
                        f"Failed to initialize status tracker: {e}. Status tracking will be disabled.",
                    )
                )
            self.status_tracker = None
            self.enable_status_tracking = False

    def _get_collector_context_key(self, dut_id: str, collector_id: str) -> str:
        """
        Generate a unique key for collector context.

        Args:
            dut_id: DUT ID.
            collector_id: Collector ID.

        Returns:
            Unique context key.
        """
        return f"{dut_id}:{collector_id}"

    async def set_collector_execution_context(
        self, dut_id: str, collector_id: str, context: Dict[str, Any]
    ) -> None:
        """
        Set execution context for a specific collector.

        Args:
            dut_id: DUT ID.
            collector_id: Collector ID.
            context: Context dictionary to store.
        """
        context_key = self._get_collector_context_key(dut_id, collector_id)
        self.collector_execution_contexts[context_key] = context.copy()

        # Also update the global context for backward compatibility
        self.current_collector_id = collector_id
        self.current_execution_context = context.copy()

    async def get_collector_execution_context(
        self, dut_id: str, collector_id: str
    ) -> Dict[str, Any]:
        """
        Get execution context for a specific collector.

        Args:
            dut_id: DUT ID.
            collector_id: Collector ID.

        Returns:
            Context dictionary or empty dict if not found.
        """
        context_key = self._get_collector_context_key(dut_id, collector_id)
        return self.collector_execution_contexts.get(context_key, {})

    async def clear_collector_execution_context(
        self, dut_id: str, collector_id: str
    ) -> None:
        """
        Clear execution context for a specific collector.

        Args:
            dut_id: DUT ID.
            collector_id: Collector ID.
        """
        context_key = self._get_collector_context_key(dut_id, collector_id)
        if context_key in self.collector_execution_contexts:
            del self.collector_execution_contexts[context_key]

    def set_sanitizer(self, sanitizer) -> None:
        """
        Set the sanitizer for the orchestrator and its logger.

        Args:
            sanitizer: LogSanitizer instance.
        """
        self.sanitizer = sanitizer
        if self.logger:
            self.logger.sanitizer = sanitizer
        # Update the sanitized console to use the new sanitizer
        self.sanitized_console = create_sanitized_console(sanitizer)
        # if sanitizer:
        #     print(f"Sanitizer is enabled")
        # else:
        #     print(f"Sanitizer is disabled")

        # self.logger.log_runtime(
        #     "DEBUG",
        #     "WorkflowOrchestrator",
        #     f"Sanitizer set in orchestrator - enabled: {sanitizer.enabled if sanitizer else False}"
        # )

        # Initialize engines
        self.execution_engine = ExecutionEngine(
            self.config_manager,
            self.dut_manager,
            self.logger,
            orchestrator=self,
            status_tracker=self.status_tracker,
        )
        self.reporting_engine = ReportingEngine(
            self.config_manager, self.dut_manager, self.logger
        )
        self.cleanup_manager = CleanupManager(self.logger)

        # Set orchestrator reference in reporting engine, logger, and execution engine
        self.reporting_engine.orchestrator = self
        if self.logger:
            self.logger.orchestrator = self
        self.execution_engine.orchestrator = self

    async def async_init(self) -> None:
        """
        Async initialization - called after sync __init__.

        Initializes config manager and sets orchestrator references.
        """
        # Initialize config manager async components (needed for both quiet and non-quiet modes)
        await self.config_manager.async_init()

        # Set orchestrator reference for all services after orchestrator is fully initialized
        await self.config_manager.set_orchestrator_reference(self)

    # Configuration delegation methods
    @property
    def tool_config(self) -> Dict[str, Any]:
        """
        Expose tool configuration for backward compatibility with tests.

        Returns:
            Dictionary of tool configuration.
        """
        return self.config_manager.get_tool_config()

    async def get_dut_specific_tool_config(self, dut_id: str) -> Dict[str, Any]:
        """
        Get tool configuration with DUT-specific overrides.

        Args:
            dut_id: DUT ID.

        Returns:
            Dictionary of tool configuration with DUT-specific overrides.
        """
        return await self.config_manager.get_dut_specific_tool_config(dut_id)

    @property
    def collector_definitions(self) -> Dict[str, Any]:
        """
        Expose collector definitions for backward compatibility with tests.

        Returns:
            Dictionary of collector definitions.
        """
        return self.config_manager.get_collector_definitions()

    @property
    def services(self) -> Dict[str, Any]:
        """
        Expose services map for backward compatibility with tests.

        Returns:
            Dictionary of services.
        """
        return self.config_manager.get_services()

    def get_all_collectors(self) -> Dict[str, Any]:
        """
        Get all collector definitions.

        Returns:
            Dictionary of all collector definitions.
        """
        return self.config_manager.get_all_collectors()  # pragma: no cover

    def get_sequential_collectors(self) -> Set[str]:
        """
        Get sequential collector IDs.

        Returns:
            Set of sequential collector IDs.
        """
        return self.config_manager.get_sequential_collectors()

    def get_parallel_collectors(self) -> Set[str]:
        """
        Get parallel collector IDs.

        Returns:
            Set of parallel collector IDs.
        """
        return self.config_manager.get_parallel_collectors()

    def get_collector_info(self, collector_id: str) -> Dict[str, Any]:
        """
        Get collector information by ID.

        Args:
            collector_id: Collector ID.

        Returns:
            Dictionary of collector information.
        """
        return self.config_manager.get_collector_info(collector_id)

    def get_collector_name(self, collector_id: str) -> str:
        """
        Get collector name by ID.

        Args:
            collector_id: Collector ID.

        Returns:
            Collector name.
        """
        collector_info = self.get_collector_info(collector_id)
        return (
            collector_info.get("name", collector_id) if collector_info else collector_id
        )

    def get_collectors_for_group(self, group: str) -> Dict[str, Any]:
        """
        Get all collectors for a specific group.

        Args:
            group: Collector group name.

        Returns:
            Dictionary of collectors in the specified group.
        """
        return self.config_manager.get_collectors_for_group(group)

    def get_all_collector_groups(self) -> List[str]:
        """
        Get all unique collector groups.

        Returns:
            List of all unique collector group names.
        """
        return self.config_manager.get_all_collector_groups()

    async def log_collector_selection_table(self, collector_ids: List[str]) -> None:
        """
        Log a comprehensive table showing all available collectors and their status.

        This method shows all collectors from collector definitions along with clear reasons why
        collectors are or are not being collected.

        Args:
            collector_ids (List[str]): List of requested collector IDs
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"log_collector_selection_table called with {len(collector_ids)} collector IDs: {collector_ids}",
        )
        # Get all collector groups
        all_collector_groups = self.config_manager.get_all_collector_groups()

        # Create Rich table for console display
        table = Table(title="Collector Selection Summary")
        table.add_column("Group", style="cyan", no_wrap=True)
        table.add_column("ID", style="magenta", no_wrap=True)
        table.add_column("Collector Name", style="green")
        table.add_column("Level", style="blue", no_wrap=True)
        table.add_column("Status", style="yellow", no_wrap=True)
        table.add_column("Reason", style="white")

        # Write table header to DUT runtime logs
        if self.dut_manager:
            for dut_id in self.dut_manager.get_all_dut_ids():
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "CollectorSelection",
                    "Comprehensive Execution Summary:",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", "-" * 151
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "CollectorSelection",
                    f"{'Group':<12} {'ID':<8} {'Collector Name':<30} {'Level':<6} {'Status':<15} {'Reason':<80}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", "-" * 145
                )

        # Track statistics
        total_collectors = 0
        included_collectors = 0
        excluded_collectors = 0
        not_applicable_collectors = 0
        not_found_collectors = 0

        # Get baseboard information for applicability checks
        baseboard_info = None
        if self.dut_manager:
            dut_ids = self.dut_manager.get_all_dut_ids()
            if dut_ids:
                baseboards = set()
                for dut_id in dut_ids:
                    dut = self.dut_manager.get_dut(dut_id)
                    if dut and dut.config:
                        baseboard = dut.config.get("baseboard")
                        # Normalize None/empty baseboard to "Unknown" to keep logging/join safe
                        if not baseboard:
                            baseboard = "Unknown"
                        else:
                            baseboard = str(baseboard)
                        baseboards.add(baseboard)

                if len(baseboards) == 1:
                    # Single baseboard environment - use the baseboard for filtering
                    baseboard_info = list(baseboards)[0]
                elif len(baseboards) > 1:
                    # Multi-DUT environment with different baseboards
                    await self.logger.log_runtime(
                        "INFO",
                        "WorkflowOrchestrator",
                        f"Multi-DUT environment detected with baseboards: {', '.join(baseboards)}",
                    )
                    await self.logger.log_runtime(
                        "INFO",
                        "WorkflowOrchestrator",
                        "Each DUT will run only collectors applicable to its specific baseboard",
                    )
                    # For multi-DUT environments, we don't do global baseboard filtering
                    # Each DUT will determine its own applicable collectors during execution
                    baseboard_info = None

        # Get collection level
        collection_level = "L3"  # Default to L3 if not available
        if hasattr(self, "tool_config") and self.tool_config:
            if hasattr(self.tool_config, "collection_level"):
                collection_level = self.tool_config.collection_level
            elif isinstance(self.tool_config, dict):
                collection_level = self.tool_config.get("collection_level", "L3")

        # Log collection level to each DUT's runtime log
        if self.dut_manager:
            for dut_id in self.dut_manager.get_all_dut_ids():
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "CollectorSelection",
                    f"Collection level: {collection_level}",
                )

        # Iterate through all collector groups
        for group in all_collector_groups:
            # Map internal group key to display name using enum
            group_display_name = (
                CollectorServiceMapping.get_display_name_from_group_name(group)
            )

            # Get all collectors for this group
            group_collectors = self.config_manager.get_collectors_for_group(group)

            # Iterate through all collectors in this group
            for collector_id, collector_info in group_collectors.items():
                collector_name = collector_info.get("name", "unknown")

                # Determine status and reason
                status = "Not applicable"
                reason = "Not applicable for current platform/configuration"

                # Check if collector is in the requested list
                if collector_id in collector_ids:
                    # Check baseboard applicability
                    try:
                        is_applicable = self._is_collector_applicable(
                            collector_info, baseboard_info
                        )
                    except ValueError as e:
                        # Baseboard not found in spreadsheet - this is a critical configuration error
                        # Log the error and exit
                        error_msg = str(e)
                        await self.logger.log_runtime(
                            "ERROR",
                            f"CRITICAL: {error_msg}",
                        )
                        if hasattr(self, "logger") and hasattr(self.logger, "console"):
                            self.logger.console.print_error(error_msg)
                        else:
                            print(f"ERROR: {error_msg}")
                        sys.exit(1)

                    if is_applicable:
                        # Check collection level
                        collector_level = collector_info.get("collection_level", "L3")
                        if self._is_collector_level_applicable(
                            collector_level, collection_level
                        ):
                            status = "Included"
                            if baseboard_info:
                                reason = f"Collector is applicable for baseboard '{baseboard_info}'"
                            else:
                                reason = (
                                    "Collector is applicable for current configuration"
                                )
                            included_collectors += 1
                        else:
                            status = "Excluded"
                            reason = (
                                f"Not in current collection level ({collection_level})"
                            )
                            excluded_collectors += 1
                    else:
                        # Check why it's not applicable
                        tags = collector_info.get("tags", {})
                        if isinstance(tags, dict):
                            include_tags = tags.get("include", [])
                            exclude_tags = tags.get("exclude", [])
                        else:
                            include_tags = []
                            exclude_tags = []

                        if exclude_tags:
                            status = "Not applicable"
                            if baseboard_info:
                                reason = f"Not applicable for baseboard '{baseboard_info}' (Tags: {exclude_tags})"
                            else:
                                reason = f"Not applicable for current configuration (Tags: {exclude_tags})"
                        elif include_tags:
                            status = "Not applicable"
                            if baseboard_info:
                                reason = f"Not applicable for baseboard '{baseboard_info}' (BaseboardConstraint)"
                            else:
                                reason = "Not applicable for current configuration (BaseboardConstraint)"
                        else:
                            status = "Not applicable"
                            if baseboard_info:
                                reason = f"Not applicable for baseboard '{baseboard_info}' (BaseboardConstraint)"
                            else:
                                reason = "Not applicable for current configuration (BaseboardConstraint)"

                        not_applicable_collectors += 1
                else:
                    # Collector not requested
                    try:
                        is_applicable = self._is_collector_applicable(
                            collector_info, baseboard_info
                        )
                    except ValueError as e:
                        # Baseboard not found in spreadsheet - this is a critical configuration error
                        # Log the error and exit
                        error_msg = str(e)
                        await self.logger.log_runtime(
                            "ERROR",
                            f"CRITICAL: {error_msg}",
                        )
                        if hasattr(self, "logger") and hasattr(self.logger, "console"):
                            self.logger.console.print_error(error_msg)
                        else:
                            print(f"ERROR: {error_msg}")
                        sys.exit(1)

                    if is_applicable:
                        status = "Not selected"
                        reason = "Collector not included in current selection"
                        not_applicable_collectors += 1
                    else:
                        status = "Not applicable"
                        reason = f"Not applicable for baseboard '{baseboard_info}' (BaseboardConstraint)"
                        not_applicable_collectors += 1

                # Get collector level
                collector_level = collector_info.get("collection_level", "L1")

                # Truncate collector name to fit in columns
                truncated_collector_name = (
                    collector_name[:30] if len(collector_name) > 30 else collector_name
                )

                # For multi-DUT environments, generate reason per DUT
                if self.dut_manager and baseboard_info is None:
                    # Multi-DUT environment - generate reason for each DUT
                    for dut_id in self.dut_manager.get_all_dut_ids():
                        dut = self.dut_manager.get_dut(dut_id)
                        dut_baseboard = "Unknown"
                        if dut and dut.config:
                            dut_baseboard = dut.config.get("baseboard", "Unknown")

                        # Generate DUT-specific reason
                        dut_reason = self._generate_dut_specific_reason(
                            reason, status, dut_baseboard, collector_info
                        )
                        truncated_dut_reason = (
                            dut_reason[:80] if len(dut_reason) > 80 else dut_reason
                        )

                        table_row = (
                            f"{group_display_name:<12} {collector_id:<8} "
                            f"{truncated_collector_name:<30} {collector_level:<6} {status:<15} {truncated_dut_reason:<80}"
                        )

                        log_level = (
                            "INFO" if status in ("Included", "Excluded") else "DEBUG"
                        )
                        await self.logger.write_to_dut_runtime_log(
                            dut_id, log_level, "CollectorSelection", table_row
                        )
                else:
                    # Single DUT or no DUT manager - use global reason
                    truncated_reason = reason[:80] if len(reason) > 80 else reason
                    table_row = (
                        f"{group_display_name:<12} {collector_id:<8} "
                        f"{truncated_collector_name:<30} {collector_level:<6} {status:<15} {truncated_reason:<80}"
                    )

                    log_level = (
                        "INFO" if status in ("Included", "Excluded") else "DEBUG"
                    )
                    await self.logger.log_runtime(
                        log_level, "CollectorSelection", table_row
                    )

                    # Add row to Rich table
                    table.add_row(
                        group_display_name,
                        collector_id,
                        truncated_collector_name,
                        collector_level,
                        status,
                        truncated_reason,
                    )

                    if self.dut_manager:
                        for dut_id in self.dut_manager.get_all_dut_ids():
                            await self.logger.write_to_dut_runtime_log(
                                dut_id, log_level, "CollectorSelection", table_row
                            )

                total_collectors += 1

        # Write summary statistics
        summary_line = (
            f"Total collectors: {total_collectors} | Included: {included_collectors} | "
            f"Excluded: {excluded_collectors} | Not applicable: {not_applicable_collectors} | Not found: {not_found_collectors}"
        )

        # Log summary to DUT runtime logs
        if self.dut_manager:
            for dut_id in self.dut_manager.get_all_dut_ids():
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", "-" * 151
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", summary_line
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", "-" * 151
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "CollectorSelection",
                    f"Total collectors to execute: {included_collectors}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", ""
                )

        # Display Rich table in console only if verbose mode is enabled
        if self.verbose_mode:
            console = Console()
            console.print(table)

    async def add_execution_summary_entry(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        log_paths: List[str],
        custom_reason: Optional[str] = None,
    ) -> None:
        """
        Add an entry to the execution summary.

        Args:
            dut_id: DUT ID.
            collector_id: Collector ID.
            status: Status of the collector.
            log_paths: List of log paths.
            custom_reason: Custom reason for the collector.
        """
        collector_name = self.get_collector_name(collector_id)
        await self.execution_summary_manager.add_entry(
            dut_id,
            collector_name,
            status,
            log_paths,
            custom_reason,
            collector_id,
        )

    async def record_execution_order_entry(
        self, dut_id: str, collector_id: str
    ) -> None:
        if not dut_id:
            return
        if dut_id not in self._execution_order_counters:
            self._execution_order_counters[dut_id] = 0
        self._execution_order_counters[dut_id] += 1
        collector_info = self.get_collector_info(collector_id) or {}
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if dut_id not in self._execution_order_entries:
            self._execution_order_entries[dut_id] = []
        self._execution_order_entries[dut_id].append(
            {
                "order": str(self._execution_order_counters[dut_id]),
                "timestamp": timestamp,
                "id": str(collector_id),
                "name": str(collector_info.get("name", "Unknown")),
                "group": str(collector_info.get("group", "Unknown")),
            }
        )

    def _build_execution_order_table(self, dut_id: str) -> str:
        rows = self._execution_order_entries.get(dut_id, [])
        if not rows:
            return ""
        header = "Order  | Timestamp           | ID    | Name                          | Group\n"
        separator = "------ | ------------------- | ----- | ----------------------------- | -----\n"
        lines = [header, separator]
        for row in rows:
            lines.append(
                f"{row['order'].ljust(5)} | "
                f"{row['timestamp']} | "
                f"{row['id'].ljust(5)} | "
                f"{row['name'].ljust(29)} | "
                f"{row['group']}\n"
            )
        return "".join(lines)

    def _append_execution_order_table_to_runtime_log(self) -> None:
        if not self.dut_manager:
            return
        for dut_id in self.dut_manager.get_all_dut_ids():
            table_text = self._build_execution_order_table(dut_id)
            if not table_text:
                continue
            runtime_log_path = self.log_dir / dut_id / "nvdebug_runtime_output.txt"
            runtime_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(runtime_log_path, "a", encoding="utf-8") as file_handle:
                file_handle.write("\n")
                file_handle.write(table_text)

    def _write_execution_order_metadata(self) -> None:
        if not self.dut_manager:
            return
        for dut_id in self.dut_manager.get_all_dut_ids():
            entries = self._execution_order_entries.get(dut_id, [])
            if not entries:
                continue
            metadata_dir = None
            if self.logger:
                try:
                    metadata_dir = self.logger.get_dut_metadata_dir(dut_id)
                except Exception:
                    metadata_dir = None
            if not metadata_dir:
                metadata_dir = self.log_dir / dut_id / ".metadata"
            metadata_dir.mkdir(parents=True, exist_ok=True)

            payload = {
                "metadata": {
                    "created_at": datetime.now().isoformat() + "Z",
                    "last_updated": datetime.now().isoformat() + "Z",
                },
                "payload": {
                    "execution_order": entries,
                },
            }
            output_path = metadata_dir / "execution_order.json"
            with open(output_path, "w", encoding="utf-8") as file_handle:
                safe_json_dump(payload, file_handle, indent=4)

    async def initialize(self) -> None:
        """
        Initialize the orchestrator (setup DUTs, test connections).

        Initializes DUTs, tests connections, and sets up logging.
        """
        await self.logger.log_runtime(
            "INFO", "WorkflowOrchestrator", "Initializing orchestrator..."
        )

        # Create progress bar for initialization (only in non-quiet mode)
        try:
            if not self.quiet_mode:
                # Use the orchestrator's console
                progress_console = self.console

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=progress_console,
                    transient=False,
                ) as progress:
                    init_task = progress.add_task(
                        "Initializing orchestrator...", total=1
                    )
                    progress.update(
                        init_task,
                        description="Initializing orchestrator...",
                        advance=1,
                        completed=True,
                    )

            else:
                # In quiet mode, create a dummy progress object
                class DummyProgress:
                    def add_task(self, *args, **kwargs):
                        return 0

                    def update(self, *args, **kwargs):
                        pass

                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        pass

                progress = DummyProgress()
                init_task = 0

            # Step 1: Initialize async components
            if not self.quiet_mode:
                progress.update(
                    init_task,
                    description="Initializing async components...",
                    advance=1,
                )
            await self.async_init()

            # Update console to use redirected stdout if available
            if hasattr(self.logger, "original_stdout") and self.logger.original_stdout:
                self.console = Console(file=self.logger.original_stdout)

            # Step 2: Check quiet mode
            if not self.quiet_mode:
                progress.update(
                    init_task,
                    description="Checking initialization mode...",
                    advance=1,
                )

            # In quiet mode, initialize only BaseboardManager for collector filtering
            if self.quiet_mode:
                if not self.quiet_mode:  # pragma: no cover
                    progress.update(
                        init_task,
                        description="Quiet mode - initializing BaseboardManager...",
                        advance=1,
                    )

                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "Quiet mode - initializing BaseboardManager for collector filtering",
                )

                # Create a minimal DUT manager with only BaseboardManager for collector filtering
                try:
                    uri_config_manager = self.config_manager.get_uri_config_manager()
                    tool_config = self.config_manager.get_tool_config()
                    spreadsheet_path = tool_config.get("collector_definitions", {}).get(
                        "spreadsheet_path"
                    )
                    self.dut_manager = DUTManager(
                        self.config_manager.get_dut_config(),
                        str(self.log_dir),
                        uri_config_manager,
                        spreadsheet_path=spreadsheet_path,
                        sanitized_console=self.sanitized_console,
                        tool_config=tool_config,
                        debug_mode=self.debug_mode,
                        redfish_session_config=tool_config.get(
                            "redfish_session_config", {}
                        ),
                        logger=self.logger,
                    )

                    # Initialize only the BaseboardManager, skip DUT connections
                    await self.dut_manager._initialize_baseboard_manager_only()

                except Exception as e:
                    await self.logger.log_runtime(
                        "WARNING",
                        "WorkflowOrchestrator",
                        f"BaseboardManager initialization failed in quiet mode: {e}",
                    )
                    self.dut_manager = None

                if not self.quiet_mode:
                    progress.update(
                        init_task,
                        description="Initialization complete",
                        completed=True,
                    )

                return

            # Step 3: Create DUT manager
            if not self.quiet_mode:
                progress.update(
                    init_task, description="Creating DUT manager...", advance=1
                )

            # Create DUT manager only if needed
            try:
                uri_config_manager = self.config_manager.get_uri_config_manager()
                # Get spreadsheet configuration from config manager
                tool_config = self.config_manager.get_tool_config()
                spreadsheet_path = tool_config.get("collector_definitions", {}).get(
                    "spreadsheet_path"
                )
                self.dut_manager = DUTManager(
                    self.config_manager.get_dut_config(),
                    str(self.log_dir),
                    uri_config_manager,
                    spreadsheet_path=spreadsheet_path,
                    sanitized_console=self.sanitized_console,
                    tool_config=tool_config,
                    debug_mode=self.debug_mode,
                    redfish_session_config=tool_config.get(
                        "redfish_session_config", {}
                    ),
                    logger=self.logger,
                )

                # Step 4: Initialize DUT manager (create DUTs and setup logging)
                if not self.quiet_mode:
                    progress.update(
                        init_task,
                        description="Initializing DUT manager...",
                        advance=1,
                    )
                await self.dut_manager.initialize()

                # Update execution and reporting engines with DUT manager
                self.execution_engine.dut_manager = self.dut_manager
                self.reporting_engine.dut_manager = self.dut_manager

                # Update dependency checker with DUT manager for remote command execution
                self.dependency_checker.set_dut_manager(self.dut_manager)

                # Update orchestrator reference in services after DUT manager is available
                self.config_manager.set_orchestrator(self)
            except Exception as e:
                # For operations that don't need DUT manager (like listing collectors),
                # we can continue without it
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    f"DUT manager initialization failed: {e}",
                )
                self.dut_manager = None

            # Step 5: Setup DUTs and complete initialization
            if self.dut_manager:
                if not self.quiet_mode:
                    progress.update(
                        init_task, description="Setting up DUTs...", advance=1
                    )

                await self.logger.log_runtime(
                    "INFO", "WorkflowOrchestrator", "Setting up DUTs..."
                )

                # Start timing for DUT initialization
                if hasattr(self, "timing_manager") and self.timing_manager:
                    self.timing_manager.start_component("dut_initialization")

                await self.dut_manager.initialize_duts()

                # End timing for DUT initialization
                if hasattr(self, "timing_manager") and self.timing_manager:
                    self.timing_manager.end_component("dut_initialization")

                # Setup logging for each DUT
                for dut_id in self.dut_manager.get_all_dut_ids():
                    await self.logger.setup_dut_logging(dut_id)
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "WorkflowOrchestrator",
                        f"DUT {dut_id} initialized",
                    )

                    # Create config files and log signature for each DUT
                    try:
                        # Get DUT-specific configuration
                        dut_config = self.dut_manager.get_dut_config(dut_id)
                        tool_config = self.config_manager.get_tool_config()

                        # Create config files
                        await self.logger.create_config_files(
                            dut_id, tool_config, dut_config
                        )

                        # Create log signature with platform and baseboard info
                        platform = dut_config.get("platform", "unknown")
                        baseboard = dut_config.get("baseboard", "unknown")
                        await self.logger.create_log_signature(
                            dut_id, platform, baseboard
                        )

                        # Initialize all collector metadata upfront (like legacy code)
                        await self.logger.initialize_all_collector_metadata(dut_id)

                    except Exception as e:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "WorkflowOrchestrator",
                            f"Error creating config files: {e}",
                        )

                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "Orchestrator initialization completed",
                )

                # Skip dependency checking during initialization to avoid hangs with large numbers of DUTs
                # Dependency checking can be done later during preflight checks if needed
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Skipping dependency checking for {len(self.dut_manager.duts)} DUT(s) during initialization (will be done during preflight if needed)",
                )

                if not self.quiet_mode:
                    progress.update(
                        init_task,
                        description="Initialization complete",
                        completed=True,
                        advance=6,
                    )
            else:
                if not self.quiet_mode:
                    progress.update(
                        init_task,
                        description="Initialization complete (no DUT manager)",
                        completed=True,
                        advance=6,
                    )
        except ImportError:
            # Fallback to simple logging if Rich is not available
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Rich not available, using simple logging",
            )

            # Initialize async components
            await self.async_init()

            # Update console to use redirected stdout if available
            if hasattr(self.logger, "original_stdout") and self.logger.original_stdout:
                self.console = Console(file=self.logger.original_stdout)

            # In quiet mode, initialize only BaseboardManager for collector filtering
            if self.quiet_mode:
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "Quiet mode - initializing BaseboardManager for collector filtering",
                )

                # Create a minimal DUT manager with only BaseboardManager for collector filtering
                try:
                    uri_config_manager = self.config_manager.get_uri_config_manager()
                    tool_config = self.config_manager.get_tool_config()
                    spreadsheet_path = tool_config.get("collector_definitions", {}).get(
                        "spreadsheet_path"
                    )
                    self.dut_manager = DUTManager(
                        self.config_manager.get_dut_config(),
                        str(self.log_dir),
                        uri_config_manager,
                        spreadsheet_path=spreadsheet_path,
                        sanitized_console=self.sanitized_console,
                        tool_config=tool_config,
                        debug_mode=self.debug_mode,
                        redfish_session_config=tool_config.get(
                            "redfish_session_config", {}
                        ),
                        logger=self.logger,
                    )

                    # Initialize only the BaseboardManager, skip DUT connections
                    await self.dut_manager._initialize_baseboard_manager_only()

                except Exception as e:
                    await self.logger.log_runtime(
                        "WARNING",
                        "WorkflowOrchestrator",
                        f"BaseboardManager initialization failed in quiet mode: {e}",
                    )
                    self.dut_manager = None

                return

            # Create DUT manager only if needed
            try:
                uri_config_manager = self.config_manager.get_uri_config_manager()
                # Get spreadsheet configuration from config manager
                tool_config = self.config_manager.get_tool_config()
                spreadsheet_path = tool_config.get("collector_definitions", {}).get(
                    "spreadsheet_path"
                )
                self.dut_manager = DUTManager(
                    self.config_manager.get_dut_config(),
                    str(self.log_dir),
                    uri_config_manager,
                    spreadsheet_path=spreadsheet_path,
                    sanitized_console=self.sanitized_console,
                    tool_config=tool_config,
                    debug_mode=self.debug_mode,
                    redfish_session_config=tool_config.get(
                        "redfish_session_config", {}
                    ),
                    logger=self.logger,
                )

                # Initialize DUT manager (create DUTs and setup logging)
                await self.dut_manager.initialize()

                # Update execution and reporting engines with DUT manager
                self.execution_engine.dut_manager = self.dut_manager
                self.reporting_engine.dut_manager = self.dut_manager

                # Update dependency checker with DUT manager for remote command execution
                self.dependency_checker.set_dut_manager(self.dut_manager)

                # Update orchestrator reference in services after DUT manager is available
                self.config_manager.set_orchestrator(self)
            except Exception as e:
                # For operations that don't need DUT manager (like listing collectors),
                # we can continue without it
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    f"DUT manager initialization failed: {e}",
                )
                self.dut_manager = None

            if self.dut_manager:
                await self.logger.log_runtime(
                    "INFO", "WorkflowOrchestrator", "Setting up DUTs..."
                )

                # Start timing for DUT initialization
                if hasattr(self, "timing_manager") and self.timing_manager:
                    self.timing_manager.start_component("dut_initialization")

                await self.dut_manager.initialize_duts()

                # End timing for DUT initialization
                if hasattr(self, "timing_manager") and self.timing_manager:
                    self.timing_manager.end_component("dut_initialization")

                # Setup logging for each DUT
                for dut_id in self.dut_manager.get_all_dut_ids():
                    await self.logger.setup_dut_logging(dut_id)
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "WorkflowOrchestrator",
                        f"DUT {dut_id} initialized",
                    )

                    # Create config files and log signature for each DUT
                    try:
                        # Get DUT-specific configuration
                        dut_config = self.dut_manager.get_dut_config(dut_id)
                        tool_config = self.config_manager.get_tool_config()

                        # Create config files
                        await self.logger.create_config_files(
                            dut_id, tool_config, dut_config
                        )

                        # Create log signature with platform and baseboard info
                        platform = dut_config.get("platform", "unknown")
                        baseboard = dut_config.get("baseboard", "unknown")
                        await self.logger.create_log_signature(
                            dut_id, platform, baseboard
                        )

                        # Initialize all collector metadata upfront (like legacy code)
                        await self.logger.initialize_all_collector_metadata(dut_id)

                    except Exception as e:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "WorkflowOrchestrator",
                            f"Error creating config files: {e}",
                        )

                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "Orchestrator initialization completed",
                )

                # Skip dependency checking during initialization to avoid hangs with large numbers of DUTs
                # Dependency checking can be done later during preflight checks if needed
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Skipping dependency checking for {len(self.dut_manager.duts)} DUT(s) during initialization (will be done during preflight if needed)",
                )

    async def run_preflight_checks(
        self,
        collector_ids: Optional[List[str]] = None,
        show_progress: bool = True,
    ) -> Dict[str, Any]:
        """
        Run preflight checks on all DUTs with comprehensive logging

        Args:
            collector_ids: List of collector IDs that will be executed.
                         Used to determine which services to check in preflight.
        """
        if not self.dut_manager:
            await self.logger.log_runtime(
                "ERROR", "WorkflowOrchestrator", "DUT manager not initialized"
            )
            return {"error": "DUT manager not initialized"}

        # Start timing for preflight checks
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.start_component("preflight_checks")

        # Determine required collector groups from collector IDs
        required_collector_groups = self._get_collector_groups_from_ids(collector_ids)

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Starting preflight checks for collector groups: {required_collector_groups or 'all'}",
        )

        collector_definitions = self.config_manager.get_collector_definitions()

        preflight_results = await self.dut_manager.run_preflight_checks(
            required_collector_groups,
            show_progress=show_progress,
            collector_definitions=collector_definitions,
        )

        # End timing for preflight checks
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.end_component("preflight_checks")

        # Log preflight results to metadata
        await self.reporting_engine.log_preflight_results(preflight_results)

        # Display preflight results table to console
        await self.reporting_engine.log_preflight_results_table(preflight_results)

        # Log summary
        total_duts = len(preflight_results)
        passed_duts = sum(
            1 for r in preflight_results.values() if r.get("overall_status") == "pass"
        )
        failed_duts = sum(
            1 for r in preflight_results.values() if r.get("overall_status") == "fail"
        )

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Preflight checks completed: {passed_duts}/{total_duts} DUTs passed, {failed_duts} failed",
        )

        return preflight_results

    async def run_dependency_checks(
        self,
        collector_ids: Optional[List[str]] = None,
        preflight_results: Optional[Dict[str, Any]] = None,
        filtered_collectors_per_dut: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, List[Dict[str, str]]]:
        """
        Run dependency checks for all collectors on all DUTs.

        Args:
            collector_ids: Optional list of collector IDs to check dependencies for.
                          If None, checks all collectors.
            preflight_results: Optional preflight results to filter collectors.
                              Skips dependency checks for collectors whose service failed.
            filtered_collectors_per_dut: Optional per-DUT mapping of collector IDs.
                          When provided, each DUT only checks dependencies for its own
                          collectors (after baseboard/skip/include/exclude filtering)
                          instead of the union across all DUTs.

        Returns:
            Dictionary mapping DUT ID to list of dicts with keys:
            'dependency', 'type', 'collector_id', 'collector_name', 'target'.
        """
        if not self.dut_manager:
            await self.logger.log_runtime(
                "WARNING",
                "WorkflowOrchestrator",
                "DUT manager not initialized, skipping dependency checks",
            )
            return {}

        collector_definitions = self.config_manager.get_collector_definitions()
        if not collector_definitions:
            await self.logger.log_runtime(
                "WARNING",
                "WorkflowOrchestrator",
                "No collector definitions found, skipping dependency checks",
            )
            return {}

        collectors = collector_definitions.get("collectors", {})
        dut_ids = self.dut_manager.get_all_dut_ids()

        # Filter collectors if specific IDs provided
        if collector_ids:
            collectors = {
                cid: cinfo for cid, cinfo in collectors.items() if cid in collector_ids
            }

        # Build per-DUT filtered collector lists based on preflight results
        # Skip collectors whose service failed: S=ssh, I=ipmi, H=host, R=redfish
        dut_collectors_map = {}
        total_deps = 0

        for dut_id in dut_ids:
            if filtered_collectors_per_dut and dut_id in filtered_collectors_per_dut:
                dut_allowed = set(filtered_collectors_per_dut[dut_id])
                dut_collectors = {
                    cid: cinfo
                    for cid, cinfo in collectors.items()
                    if cid in dut_allowed
                }
            else:
                dut_collectors = collectors.copy()

            # Filter collectors for this specific DUT based on its preflight results
            if preflight_results:
                dut_preflight = preflight_results.get(dut_id, {})
                services = dut_preflight.get("services", {})
                prefixes_to_skip = set()

                # Check which services failed for THIS DUT and map to prefixes
                if services.get("ssh", {}).get("status") != "pass":
                    prefixes_to_skip.add("S")
                if services.get("ipmi", {}).get("status") != "pass":
                    prefixes_to_skip.add("I")
                if services.get("host", {}).get("status") != "pass":
                    prefixes_to_skip.add("H")
                if services.get("redfish", {}).get("status") != "pass":
                    prefixes_to_skip.add("R")

                # Filter out collectors with failed prefixes for THIS DUT
                if prefixes_to_skip:
                    dut_collectors = {
                        cid: cinfo
                        for cid, cinfo in dut_collectors.items()
                        if cid and cid[0].upper() not in prefixes_to_skip
                    }

            # Store filtered collectors for this DUT
            dut_collectors_map[dut_id] = dut_collectors

            # Calculate per-DUT and total dependencies for progress bars
            dut_deps = 0
            for collector_info in dut_collectors.values():
                dependencies = collector_info.get("dependencies", {})
                required_deps = dependencies.get("required", [])
                dut_deps += len(required_deps)
            total_deps += dut_deps

        # Set up console for progress display
        if hasattr(self.logger, "original_stdout") and self.logger.original_stdout:
            console = Console(file=self.logger.original_stdout, force_terminal=True)
        else:
            console = Console(force_terminal=True)

        # Collect missing dependencies per DUT with progress bar
        dependency_results: Dict[str, List[Dict[str, str]]] = {}

        dep_progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10,
        )

        async def _check_deps_for_dut(
            dut_id: str,
            overall_task,
        ) -> tuple:
            """Check all dependencies for a single DUT."""
            missing_deps = []
            seen = set()
            dut = self.dut_manager.get_dut(dut_id)
            is_local_mode = False
            if dut and dut.config:
                is_local_mode = bool(dut.config.get("local", False))

            if dut_id not in dut_collectors_map:
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    f"DUT '{dut_id}' not found in dependency collectors map; "
                    f"skipping dependency checks for this DUT",
                )
            dut_collectors = dut_collectors_map.get(dut_id, {})

            for collector_id, collector_info in dut_collectors.items():
                dependencies = collector_info.get("dependencies", {})
                required_deps = dependencies.get("required", [])
                collector_name = collector_info.get("name", "unknown")

                if not required_deps:
                    continue

                for dep in required_deps:
                    if isinstance(dep, str):
                        dep_name = dep
                        dep_type = "command"
                    else:
                        dep_name = dep.get("name", "unknown")
                        dep_type = dep.get("type", "command")

                    # Determine check target
                    if is_local_mode or collector_id.startswith("I"):
                        target = "local"
                    elif collector_id.startswith("S"):
                        target = "BMC"
                    elif collector_id.startswith("H"):
                        target = "Host"
                    else:
                        target = "local"

                    try:
                        if dep_type == "command":
                            check_local = (
                                dep.get("check_local", False)
                                if isinstance(dep, dict)
                                else False
                            )
                            if (
                                check_local
                                or collector_id.startswith("I")
                                or is_local_mode
                            ):
                                result = self.dependency_checker.check_command(
                                    dep_name, check_local=True
                                )
                            elif (
                                dut_id
                                and self.dependency_checker.dut_manager
                                and not is_local_mode
                            ):
                                use_bmc = collector_id.startswith("S")
                                result = (
                                    await self.dependency_checker._check_command_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                            else:
                                result = self.dependency_checker.check_command(dep_name)
                        elif dep_type == "service":
                            if is_local_mode:
                                result = self.dependency_checker.check_service(dep_name)
                            elif dut_id and self.dependency_checker.dut_manager:
                                use_bmc = collector_id.startswith("S")
                                result = (
                                    await self.dependency_checker._check_service_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                            else:
                                result = self.dependency_checker.check_service(dep_name)
                        elif dep_type == "file":
                            if (
                                dut_id
                                and self.dependency_checker.dut_manager
                                and not is_local_mode
                            ):
                                use_bmc = collector_id.startswith("S")
                                result = (
                                    await self.dependency_checker._check_file_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                            else:
                                result = self.dependency_checker.check_file(dep_name)
                        elif dep_type == "platform_service":
                            dep_config = (
                                dep if isinstance(dep, dict) else {"name": dep_name}
                            )
                            result = (
                                await self.dependency_checker.check_platform_service(
                                    dep_config, "default", dut_id
                                )
                            )
                        else:
                            continue

                        if not result.available:
                            dedup_key = (dep_name, dep_type, collector_id)
                            if dedup_key not in seen:
                                seen.add(dedup_key)
                                missing_deps.append(
                                    {
                                        "dependency": dep_name,
                                        "type": dep_type,
                                        "collector_id": collector_id,
                                        "collector_name": collector_name,
                                        "target": target,
                                    }
                                )

                    except Exception as e:
                        await self.logger.log_runtime(
                            "DEBUG",
                            "WorkflowOrchestrator",
                            f"Error checking dependency {dep_name} on {dut_id}: {e}",
                        )
                        dedup_key = (dep_name, dep_type, collector_id)
                        if dedup_key not in seen:
                            seen.add(dedup_key)
                            missing_deps.append(
                                {
                                    "dependency": dep_name,
                                    "type": dep_type,
                                    "collector_id": collector_id,
                                    "collector_name": collector_name,
                                    "target": target,
                                }
                            )

                    finally:
                        dep_progress.advance(overall_task)

            missing_deps.sort(
                key=lambda d: (d["target"], d["dependency"], d["collector_id"])
            )
            return dut_id, missing_deps

        with dep_progress:
            overall_task = dep_progress.add_task(
                f"[cyan]Dependency Checks ({len(dut_ids)} DUTs, {total_deps} dependencies)",
                total=total_deps,
            )

            all_coros = [
                _check_deps_for_dut(dut_id, overall_task) for dut_id in dut_ids
            ]
            all_results = await asyncio.gather(*all_coros, return_exceptions=True)
            for result in all_results:
                if isinstance(result, Exception):
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"Dependency check failed: {result}",
                    )
                else:
                    dut_id, missing = result
                    dependency_results[dut_id] = missing

        return dependency_results

    async def generate_html_reports(
        self,
        total_runtime: Optional[float] = None,
        collector_ids: Optional[List[str]] = None,
    ) -> bool:
        # Start timing for HTML report generation
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.start_component("html_report_generation")
        """
        Generate HTML reports from collection results

        Args:
            total_runtime: Total runtime of the collection process

        Returns:
            bool: True if reports were generated successfully
        """
        try:
            # Check if shutdown was requested - if so, skip HTML report generation
            if self.is_shutdown_requested():
                await self.logger.log_runtime(
                    "WARN",
                    "WorkflowOrchestrator",
                    "Shutdown requested, skipping HTML report generation",
                )
                self.sanitized_console.print_warning("Skipping HTML report generation")
                return False

            # Check if HTML reports are enabled in configuration
            tool_config = self.config_manager.get_tool_config()
            generate_html = (
                tool_config.get("GENERATE_HTML_REPORTS", True)
                if isinstance(tool_config, dict)
                else getattr(tool_config, "GENERATE_HTML_REPORTS", True)
            )

            if not generate_html:
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "HTML report generation disabled in configuration",
                )
                return True

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Starting HTML report generation...",
            )
            self.sanitized_console.print_info("Starting HTML report generation...")

            # Initialize HTML report service
            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                "Creating HTML report service...",
            )
            html_service = await HTMLReportService.create(
                self.log_dir, total_runtime, self.logger, self, collector_ids
            )
            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                "HTML report service created successfully",
            )

            # Create progress bar for HTML report generation
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=self.console,
                transient=False,
            ) as progress:
                # Add main task for HTML report generation
                main_task = progress.add_task("Generating HTML reports...", total=100)

                # Generate reports with progress updates
                success = await html_service.generate_reports_with_progress(
                    progress, main_task
                )

            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                f"html_service.generate_reports() returned: {success}",
            )

            if success:
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"HTML reports generated successfully in {self.log_dir}/reports",
                )
                self.sanitized_console.print_success(
                    f"HTML reports generated in {self.log_dir}/reports"
                )
            else:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    "Failed to generate HTML reports",
                )
                self.sanitized_console.print_error("Failed to generate HTML reports")

            # End timing for HTML report generation
            if hasattr(self, "timing_manager") and self.timing_manager:
                self.timing_manager.end_component("html_report_generation")

            return success

        except KeyboardInterrupt:
            await self.logger.log_runtime(
                "WARNING",
                "WorkflowOrchestrator",
                "HTML report generation interrupted by user",
            )
            self.sanitized_console.print_warning("HTML report generation interrupted")
            return False
        except Exception as e:
            await self.logger.log_runtime(
                "ERROR",
                "WorkflowOrchestrator",
                f"HTML report generation error: {str(e)}",
            )
            self.sanitized_console.print_error(
                f"HTML report generation error: {str(e)}"
            )
            return False

    async def _generate_spa_report(self) -> bool:
        """Generate SPA report using ManifestService."""
        try:
            from ..services.manifest_service import ManifestService

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Starting SPA report generation...",
            )
            self.sanitized_console.print_info("Starting SPA report generation...")

            # Locate the pre-built SPA dist assets
            spa_dist_dir = Path(__file__).parent.parent / "report_app_dist"
            if not spa_dist_dir.exists():
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    f"SPA dist not found at {spa_dist_dir}. Run 'make build-report-app' first.",
                )
                self.sanitized_console.print_warning(
                    "SPA dist not found. Run 'make build-report-app' first."
                )
                return False

            report_dir = self.log_dir / "reports"
            service = ManifestService(self.log_dir, spa_dist_dir)
            result = await service.generate_report(report_dir)

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                f"SPA report generated at {result}",
            )
            self.sanitized_console.print_success(f"SPA report generated at {result}")
            return True

        except Exception as e:
            await self.logger.log_runtime(
                "ERROR",
                "WorkflowOrchestrator",
                f"SPA report generation error: {str(e)}",
            )
            self.sanitized_console.print_error(f"SPA report generation error: {str(e)}")
            return False

    def _get_collector_groups_from_ids(
        self, collector_ids: Optional[List[str]] = None
    ) -> Optional[List[str]]:
        """
        Determine collector groups from collector IDs

        Args:
            collector_ids: List of collector IDs

        Returns:
            List of collector groups, or None if all groups should be checked
        """
        if not collector_ids:
            return None  # Check all services

        collector_groups = set()

        for collector_id in collector_ids:
            collector_info = self.config_manager.get_collector_info(collector_id)
            group = collector_info.get("group", "").lower()

            if group:
                collector_groups.add(group)

        return list(collector_groups) if collector_groups else None

    async def gather_platform_info(
        self,
        dut_ids: Optional[List[str]] = None,
        preflight_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, str]]:
        """
        Gather platform information from DUTs.

        Args:
            dut_ids: List of DUT IDs.
            preflight_results: Dictionary of preflight results.

        Returns:
            Dictionary of platform information.
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            "gather_platform_info method called",
        )

        if not self.dut_manager:
            await self.logger.log_runtime(
                "ERROR", "WorkflowOrchestrator", "DUT manager not initialized"
            )
            return {}

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            "Starting platform information gathering...",
        )

        # Get all DUTs if none specified
        if not dut_ids:
            dut_ids = self.dut_manager.get_all_dut_ids()

        platform_results = {}

        # Show progress bar for platform information gathering
        total_duts = len(dut_ids)
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Gathering platform information for {total_duts} DUT(s) concurrently...",
        )

        # Create progress display using existing console
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        )

        async def gather_platform_info_for_dut(dut_id: str, progress_task) -> tuple:
            """
            Gather platform info for a single DUT.

            Args:
                dut_id: DUT ID.
                progress_task: Progress task.

            Returns:
                Tuple containing DUT ID and platform information.
            """
            try:
                # Check for shutdown request
                if self.is_shutdown_requested():
                    await self.logger.log_runtime(
                        "WARN",
                        "WorkflowOrchestrator",
                        f"Shutdown requested, skipping platform info gathering for DUT {dut_id}",
                    )
                    return dut_id, {}

                progress.update(
                    progress_task,
                    description=f"Gathering platform info for {dut_id}",
                )

                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Gathering platform info for DUT: {dut_id}",
                )

                # Get preflight results for this specific DUT
                dut_preflight_results = None
                if preflight_results and dut_id in preflight_results:
                    dut_preflight_results = preflight_results[dut_id].get(
                        "services", {}
                    )

                platform_info = await self.dut_manager.gather_platform_info(
                    dut_id, dut_preflight_results
                )

                # Log platform info to DUT runtime
                model = platform_info.get("model", "Unknown")
                partnumber = platform_info.get("partnumber", "Unknown")
                serialnumber = platform_info.get("serialnumber", "Unknown")

                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "PlatformDetection",
                    f"Identified system as Model: {model}, PartNo: {partnumber}, SerialNo: {serialnumber}",
                )

                # Store in metadata
                await self.logger.write_dut_metadata(
                    dut_id,
                    {
                        "PlatformModel": model,
                        "PartNumber": partnumber,
                        "SerialNumber": serialnumber,
                        "DUT_ID": dut_id,
                    },
                )

                return dut_id, platform_info

            except Exception as e:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Failed to gather platform info for DUT {dut_id}: {str(e)}",
                )
                return dut_id, {
                    "model": "Unknown",
                    "partnumber": "Unknown",
                    "serialnumber": "Unknown",
                }

        with progress:
            task = progress.add_task("Gathering platform information", total=total_duts)

            # Run platform info gathering concurrently for all DUTs
            all_tasks = [
                gather_platform_info_for_dut(dut_id, task) for dut_id in dut_ids
            ]
            all_results = await asyncio.gather(*all_tasks, return_exceptions=True)

            results = []
            for j, result in enumerate(all_results):
                if isinstance(result, Exception):
                    dut_id = dut_ids[j]
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"Failed to gather platform info for DUT {dut_id}: {str(result)}",
                    )
                    results.append(
                        (
                            dut_id,
                            {
                                "model": "Unknown",
                                "partnumber": "Unknown",
                                "serialnumber": "Unknown",
                            },
                        )
                    )
                else:
                    results.append(result)

                progress.update(task, advance=1)

            # Process results and update progress
            for i, result in enumerate(results):
                if isinstance(result, Exception):  # pragma: no cover
                    # Handle any exceptions that weren't caught
                    dut_id = dut_ids[i]
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"Unexpected error gathering platform info for DUT {dut_id}: {str(result)}",
                    )
                    platform_results[dut_id] = {
                        "model": "Unknown",
                        "partnumber": "Unknown",
                        "serialnumber": "Unknown",
                    }
                else:
                    dut_id, platform_info = result
                    platform_results[dut_id] = platform_info

                # Update progress
                progress.advance(task)

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Platform information gathering completed for {len(platform_results)} DUTs",
        )

        return platform_results

    async def _check_firmware_inventory_needed(
        self, collector_ids: List[str], dut_ids: List[str]
    ) -> bool:
        """
        Check if any filtered collectors require firmware inventory discovery.

        Analyzes collector definitions to see if they have use_firmware_inventory
        parameters and if any target DUT's baseboard requires firmware inventory.

        Args:
            collector_ids: List of collector IDs to check
            dut_ids: List of DUT IDs to check baseboards for

        Returns:
            True if firmware inventory discovery should be enabled
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"Checking if firmware inventory is needed for collectors: {collector_ids}",
        )

        for collector_id in collector_ids:
            collector_info = self.get_collector_info(collector_id)
            if not collector_info:
                continue

            # Check validation stage hooks for use_firmware_inventory parameter
            stages = collector_info.get("stages", {})
            validation_hooks = stages.get("validation", {}).get("hooks", [])

            for hook in validation_hooks:
                params = hook.get("params", {})
                use_firmware_inventory = params.get("use_firmware_inventory")

                if use_firmware_inventory:
                    # Check if any DUT's baseboard requires firmware inventory
                    for dut_id in dut_ids:
                        dut = self.dut_manager.get_dut(dut_id)
                        baseboard = dut.config.get("baseboard")

                        if baseboard:
                            # Check if this baseboard needs firmware inventory
                            if isinstance(use_firmware_inventory, dict):
                                needs_it = use_firmware_inventory.get(
                                    baseboard
                                ) or use_firmware_inventory.get("default", False)
                                if needs_it:
                                    await self.logger.log_runtime(
                                        "INFO",
                                        "WorkflowOrchestrator",
                                        f"Collector {collector_id} requires firmware inventory for baseboard {baseboard}",
                                    )
                                    return True
                            elif use_firmware_inventory is True:
                                # Simple boolean True means always needed
                                await self.logger.log_runtime(
                                    "INFO",
                                    "WorkflowOrchestrator",
                                    f"Collector {collector_id} requires firmware inventory (always enabled)",
                                )
                                return True

        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            "No collectors require firmware inventory discovery",
        )
        return False

    async def run_dynamic_discovery(
        self,
        dut_ids: Optional[List[str]] = None,
        preflight_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Run dynamic discovery for Redfish resources on DUTs.

        Args:
            dut_ids: List of DUT IDs.
            preflight_results: Dictionary of preflight results.
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            "run_dynamic_discovery method called",
        )

        if not self.dut_manager:
            await self.logger.log_runtime(
                "ERROR", "WorkflowOrchestrator", "DUT manager not initialized"
            )
            return {}

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            "Starting Redfish dynamic discovery...",
        )

        # Get all DUTs if none specified
        if not dut_ids:
            dut_ids = self.dut_manager.get_all_dut_ids()

        discovery_results = {}

        # Show progress bar for dynamic discovery
        total_duts = len(dut_ids)
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Running Redfish dynamic discovery for {total_duts} DUT(s) concurrently...",
        )

        # Create progress display using existing console
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        )

        async def run_dynamic_discovery_for_dut(dut_id: str, progress_task) -> tuple:
            """
            Run dynamic discovery for a single DUT.

            Args:
                dut_id: DUT ID.
                progress_task: Progress task.

            Returns:
                Tuple containing DUT ID and discovery results.
            """
            try:
                # Check for shutdown request
                if self.is_shutdown_requested():
                    await self.logger.log_runtime(
                        "WARN",
                        "WorkflowOrchestrator",
                        f"Shutdown requested, skipping resource discovery for DUT {dut_id}",
                    )
                    return dut_id, {}

                progress.update(
                    progress_task,
                    description=f"Discovering resources for {dut_id}",
                )

                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Running dynamic discovery for DUT: {dut_id}",
                )

                # Get preflight results for this specific DUT
                dut_preflight_results = None
                if preflight_results and dut_id in preflight_results:
                    dut_preflight_results = preflight_results[dut_id].get(
                        "services", {}
                    )

                discovery_result = await self.dut_manager.run_dynamic_discovery(
                    dut_id, dut_preflight_results
                )

                if discovery_result.get("success"):
                    total_resources = discovery_result.get("metadata", {}).get(
                        "total_resources", 0
                    )
                    discovered_resources = discovery_result.get(
                        "discovered_resources", {}
                    )

                    # Categorize resources for better logging
                    collections = []
                    singleton_services = []

                    for resource_name, resource_data in discovered_resources.items():
                        if resource_data.get("success", False):
                            members = resource_data.get("members", [])
                            if len(members) == 1 and members[0] == resource_name:
                                # This is likely a singleton service
                                singleton_services.append(resource_name)
                            else:
                                # This is a collection with multiple members
                                collections.append(f"{resource_name}({len(members)})")
                        else:
                            # Failed discovery
                            collections.append(f"{resource_name}(failed)")

                    # Log detailed summary
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "DynamicDiscovery",
                        f"Dynamic discovery completed - found {total_resources} total resources",
                    )

                    if collections:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "DynamicDiscovery",
                            f"Collections discovered: {', '.join(collections)}",
                        )

                    if singleton_services:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "DynamicDiscovery",
                            f"Singleton services discovered: {', '.join(singleton_services)} (metadata preserved)",
                        )

                    # Store discovery results in metadata (including raw response data)
                    await self.logger.write_dut_metadata(
                        dut_id,
                        {
                            "DynamicDiscovery": {
                                "success": True,
                                "total_resources": total_resources,
                                "discovered_resources": discovered_resources,
                                "raw_response_data": discovery_result.get(
                                    "raw_response_data", {}
                                ),
                                "timestamp": discovery_result.get("metadata", {}).get(
                                    "discovery_timestamp"
                                ),
                            }
                        },
                    )
                else:
                    error_msg = discovery_result.get("error", "Unknown error")
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "DynamicDiscovery",
                        f"Dynamic discovery failed: {error_msg}",
                    )

                    # Store failure in metadata
                    await self.logger.write_dut_metadata(
                        dut_id,
                        {
                            "DynamicDiscovery": {
                                "success": False,
                                "error": error_msg,
                                "timestamp": datetime.now().isoformat(),
                            }
                        },
                    )

                return dut_id, discovery_result

            except Exception as e:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Failed to run dynamic discovery for DUT {dut_id}: {str(e)}",
                )
                return dut_id, {"success": False, "error": str(e)}

        with progress:
            task = progress.add_task(
                "Running Redfish dynamic discovery", total=total_duts
            )

            # Run dynamic discovery concurrently for all DUTs
            all_tasks = [
                run_dynamic_discovery_for_dut(dut_id, task) for dut_id in dut_ids
            ]
            all_results = await asyncio.gather(*all_tasks, return_exceptions=True)

            for j, result in enumerate(all_results):
                if isinstance(result, Exception):
                    dut_id = dut_ids[j]
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"Failed to run dynamic discovery for DUT {dut_id}: {str(result)}",
                    )
                    discovery_results[dut_id] = {
                        "success": False,
                        "error": str(result),
                    }
                else:
                    dut_id, discovery_result = result
                    discovery_results[dut_id] = discovery_result

                progress.advance(task)

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            "Redfish dynamic discovery completed",
        )

        return discovery_results

    async def execute_collectors(
        self,
        filtered_collectors_per_dut: Optional[Dict[str, List[str]]] = None,
        skipped_collectors_per_dut: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        collection_level: str = "L1",
        original_collector_ids: Optional[List[str]] = None,
        preflight_results: Optional[Dict[str, Any]] = None,
        # Legacy parameters for test compatibility
        collector_ids: Optional[List[str]] = None,
        dut_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the collection workflow:
        1. Preflight checks on filtered collectors
        2. Platform info gathering and dynamic discovery
        3. Collector execution

        Filtering and autodetection are handled upstream by run_collection.
        """
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.start_component("collector_execution")

        if not self.dut_manager:
            await self.logger.log_runtime(
                "ERROR", "WorkflowOrchestrator", "DUT manager not initialized"
            )
            return {"error": "DUT manager not initialized"}

        # Resolve DUT IDs
        if not dut_ids:
            dut_ids = self.dut_manager.get_all_dut_ids()

        # If caller passed pre-filtered per-DUT dicts (normal production path),
        # use them directly. Otherwise fall back to filtering here (test callers).
        if filtered_collectors_per_dut is None:
            if collector_ids is None:
                all_collectors = self.get_all_collectors()
                collector_ids = list(all_collectors.keys())

            filtering_results = (
                await self.execution_engine.get_filtered_collectors_per_dut(
                    collector_ids, dut_ids
                )
            )
            filtered_collectors_per_dut = filtering_results["filtered_collectors"]
            skipped_collectors_per_dut = filtering_results["skipped_collectors"]

        if skipped_collectors_per_dut is None:
            skipped_collectors_per_dut = {did: [] for did in dut_ids}

        # Compute union sets
        all_filtered_collectors = list(
            {
                cid
                for dut_cids in filtered_collectors_per_dut.values()
                for cid in dut_cids
            }
        )
        all_skipped_collectors = list(
            {
                s["collector_id"]
                for dut_skipped in skipped_collectors_per_dut.values()
                for s in dut_skipped
            }
        )

        if original_collector_ids is None:
            original_collector_ids = all_filtered_collectors.copy()

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Starting execution: {len(all_filtered_collectors)} collectors across {len(dut_ids)} DUT(s)",
        )

        # Initialize status tracker
        if (
            original_collector_ids
            and dut_ids
            and hasattr(self, "status_tracker")
            and self.status_tracker
        ):
            await self.status_tracker.initialize_collection(
                dut_ids=dut_ids,
                collector_ids=original_collector_ids,
                config_manager=self.config_manager,
            )

        # Step 1: Preflight checks on filtered collectors
        if preflight_results is not None:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 1: Reusing preflight results gathered before autodetection",
            )
        elif all_filtered_collectors:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 1: Running preflight checks on filtered collectors...",
            )

            tool_config = self.config_manager.get_tool_config()
            skip_preflight = (
                tool_config.get("skip_preflight", False)
                if isinstance(tool_config, dict)
                else getattr(tool_config, "skip_preflight", False)
            )
            if not skip_preflight:
                preflight_results = await self.run_preflight_checks(
                    all_filtered_collectors
                )
            else:
                await self.logger.log_runtime(
                    "INFO", "WorkflowOrchestrator", "Skipping preflight checks"
                )
                preflight_results = None
        else:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 1: No collectors to execute - skipping preflight checks",
            )
            preflight_results = None

        # Step 2: Dependency checks (software prerequisites)
        if all_filtered_collectors:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 2: Running dependency checks on filtered collectors...",
            )
            dependency_results = await self.run_dependency_checks(
                all_filtered_collectors,
                preflight_results,
                filtered_collectors_per_dut=filtered_collectors_per_dut,
            )
            await self.reporting_engine.log_dependency_check_table(dependency_results)
        else:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 2: No collectors to execute - skipping dependency checks",
            )

        # Step 3: Platform info gathering and dynamic discovery
        if all_filtered_collectors:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 3: Gathering platform info and running dynamic discovery...",
            )

            # Step 3a: Analyze filtered collectors to determine discovery requirements
            firmware_inventory_needed = await self._check_firmware_inventory_needed(
                all_filtered_collectors, dut_ids
            )

            # Configure discovery service based on collector requirements
            if firmware_inventory_needed:
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "Firmware inventory discovery enabled (required by one or more collectors)",
                )
                discovery_service = self.dut_manager._get_discovery_service()
                config = DiscoveryConfig()
                config.discover_firmware_inventory = True
                discovery_service.set_config(config)

            platform_results = await self.gather_platform_info(
                dut_ids=dut_ids, preflight_results=preflight_results
            )

            discovery_results = await self.run_dynamic_discovery(
                dut_ids=dut_ids, preflight_results=preflight_results
            )
        else:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 3: No collectors to execute - skipping platform info gathering and discovery",
            )
            platform_results = {}
            discovery_results = {}

        # Step 3: Mark skipped collectors in status tracker and create error logs
        if hasattr(self, "status_tracker") and self.status_tracker:
            total_skipped = sum(len(v) for v in skipped_collectors_per_dut.values())
            num_duts_with_skipped = len(skipped_collectors_per_dut)

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                f"Step 4: Processing {total_skipped} skipped collector entries across {num_duts_with_skipped} DUTs...",
            )

            async def _process_skipped_for_dut(
                dut_id: str,
                dut_skipped: list,
            ) -> None:
                """Process all skipped collector entries for a single DUT."""
                for skipped_info in dut_skipped:
                    collector_id = skipped_info["collector_id"]
                    reason = skipped_info["reason"]
                    skip_type = skipped_info.get("skip_type", "config")

                    await self.logger.log_runtime(
                        "DEBUG",
                        "WorkflowOrchestrator",
                        f"Marking collector {collector_id} as skipped for DUT {dut_id}: {reason}",
                    )
                    await self.status_tracker.complete_collector(
                        dut_id,
                        collector_id,
                        "skipped",
                        reason,
                        skip_status_update=True,
                    )

                    # Track pre-execution exclusion type for the footer summary
                    if skip_type == "baseboard":
                        await self.status_tracker.increment_baseboard_excluded(
                            skip_status_update=True
                        )
                    elif skip_type == "config":
                        await self.status_tracker.increment_config_excluded(
                            skip_status_update=True
                        )

                    # Baseboard-non-applicable collectors are silently excluded:
                    # no error log and no execution summary entry.  They are
                    # consistent with how collectors pre-filtered by -g behave
                    # (they never enter the selected list at all).
                    if skip_type == "baseboard":
                        await self.logger.log_runtime(
                            "DEBUG",
                            "WorkflowOrchestrator",
                            f"Collector {collector_id} not applicable for DUT {dut_id} baseboard - silently excluded (no error log, no summary entry)",
                        )
                        continue

                    try:
                        skip_context = {
                            "operation_name": "collector_skip",
                            "skip_reason": reason,
                        }
                        error_log_path = await self.logger.write_error_log(
                            dut_id, collector_id, f"SKIPPED: {reason}", skip_context
                        )
                        await self.logger.log_runtime(
                            "DEBUG",
                            "WorkflowOrchestrator",
                            f"Created error log for skipped collector {collector_id}: {error_log_path}",
                        )

                        await self.add_execution_summary_entry(
                            dut_id,
                            collector_id,
                            "skipped",
                            [str(error_log_path)],
                            reason,
                        )
                    except Exception as e:
                        await self.logger.log_runtime(
                            "WARNING",
                            "WorkflowOrchestrator",
                            f"Failed to create error log for skipped collector {collector_id}: {e}",
                        )

            all_coros = [
                _process_skipped_for_dut(dut_id, dut_skipped)
                for dut_id, dut_skipped in skipped_collectors_per_dut.items()
            ]
            await asyncio.gather(*all_coros, return_exceptions=True)

            # Single bulk status update after all skipped entries are marked
            await self.status_tracker._update_status()

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                f"Step 4 complete: processed {total_skipped} skipped entries across {num_duts_with_skipped} DUTs",
            )

        # Step 5: Execute collectors using the filtered collectors per DUT
        await self.logger.log_runtime(
            "INFO", "WorkflowOrchestrator", "Step 5: Executing filtered collectors..."
        )

        # Use the existing execution logic but with filtered collectors per DUT
        results = await self._execute_filtered_collectors(
            filtered_collectors_per_dut,
            skipped_collectors_per_dut,
            dut_ids,
            collection_level,
            preflight_results,
            original_collector_ids,
        )

        # End timing for collector execution
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.end_component("collector_execution")

        return results

    def _get_execution_scheduler_mode(self) -> str:
        """Return the collector scheduler mode, defaulting to per-DUT execution."""
        tool_config = self.config_manager.get_tool_config()
        if isinstance(tool_config, dict):
            mode = tool_config.get(
                "execution_scheduler",
                tool_config.get("scheduler_mode", "per_dut"),
            )
        else:
            mode = getattr(
                tool_config,
                "execution_scheduler",
                getattr(tool_config, "scheduler_mode", "per_dut"),
            )

        mode = str(mode or "per_dut").strip().lower()
        if mode not in {"per_dut", "legacy_global"}:
            raise ValueError(
                "Invalid execution_scheduler value "
                f"{mode!r}; expected 'per_dut' or 'legacy_global'"
            )
        return mode

    def _get_unique_collectors(
        self, collectors_per_dut: Dict[str, List[str]]
    ) -> List[str]:
        """Return a stable unique collector list from per-DUT collector lists."""
        seen = set()
        ordered = []
        for collector_ids in collectors_per_dut.values():
            for collector_id in collector_ids:
                if collector_id not in seen:
                    seen.add(collector_id)
                    ordered.append(collector_id)
        return ordered

    def _classify_collectors_for_dut(
        self, collector_ids: List[str]
    ) -> CollectorClassification:
        """Split one DUT's collectors into normal sequential, normal parallel, and tail."""
        collector_positions = {cid: idx for idx, cid in enumerate(collector_ids)}
        tail_candidates = []
        normal_collectors = []

        for collector_id in collector_ids:
            collector_info = self.config_manager.get_collector_info(collector_id) or {}
            execution_phase = (
                str(collector_info.get("execution_phase", "")).strip().lower()
            )
            if execution_phase == "tail":
                tail_candidates.append((collector_id, collector_info))
            else:
                normal_collectors.append(collector_id)

        def _tail_sort_key(item):
            collector_id, collector_info = item
            order_value = collector_info.get("execution_order")
            try:
                order = int(order_value)
            except (TypeError, ValueError):
                order = None
            if order is None:
                return (1, collector_positions.get(collector_id, 0))
            return (0, order)

        sequential_collectors = self.get_sequential_collectors()
        parallel_collectors = self.get_parallel_collectors()

        return CollectorClassification(
            normal_sequential=[
                cid for cid in normal_collectors if cid in sequential_collectors
            ],
            normal_parallel=[
                cid for cid in normal_collectors if cid in parallel_collectors
            ],
            tail=[cid for cid, _ in sorted(tail_candidates, key=_tail_sort_key)],
        )

    def _build_dut_execution_plan(
        self, dut_id: str, collector_ids: List[str]
    ) -> DutExecutionPlan:
        classification = self._classify_collectors_for_dut(collector_ids)
        return DutExecutionPlan(
            dut_id=dut_id,
            normal_sequential=classification.normal_sequential,
            normal_parallel=classification.normal_parallel,
            tail=classification.tail,
        )

    def _merge_collector_results(
        self, target: Dict[str, Any], source: Optional[Dict[str, Any]]
    ) -> None:
        """Merge collector-major execution results without dropping DUT entries."""
        if not source:
            return
        for collector_id, collector_result in source.items():
            if not isinstance(collector_result, dict):
                target[collector_id] = collector_result
                continue
            target.setdefault(collector_id, {})
            target[collector_id].update(collector_result)

    def _build_error_results(
        self, collector_ids: List[str], dut_id: str, error: BaseException
    ) -> Dict[str, Dict[str, Dict[str, Any]]]:
        return {
            collector_id: {
                dut_id: {
                    "status": "error",
                    "error": str(error),
                    "execution_time": 0.0,
                }
            }
            for collector_id in collector_ids
        }

    async def _execute_one_dut_plan(
        self, plan: DutExecutionPlan, collection_level: str
    ) -> Dict[str, Dict[str, Any]]:
        """Execute one DUT's normal collectors, then that same DUT's tail collectors."""
        results = {"sequential_results": {}, "parallel_results": {}}
        normal_tasks = []

        if plan.normal_parallel:
            normal_tasks.append(
                (
                    "parallel_results",
                    plan.normal_parallel,
                    asyncio.create_task(
                        self._execute_parallel_collectors_unified(
                            plan.normal_parallel,
                            [plan.dut_id],
                            collection_level,
                            None,
                            self.progress_state,
                        )
                    ),
                )
            )

        if plan.normal_sequential:
            normal_tasks.append(
                (
                    "sequential_results",
                    plan.normal_sequential,
                    asyncio.create_task(
                        self._execute_sequential_collectors_unified(
                            plan.normal_sequential,
                            [plan.dut_id],
                            collection_level,
                            None,
                        )
                    ),
                )
            )

        if normal_tasks:
            normal_results = await asyncio.gather(
                *(task for _, _, task in normal_tasks), return_exceptions=True
            )
            for (result_key, collector_ids, _), result in zip(
                normal_tasks, normal_results
            ):
                if isinstance(result, BaseException):
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"{result_key} failed for DUT {plan.dut_id}: {result}",
                    )
                    self._merge_collector_results(
                        results[result_key],
                        self._build_error_results(collector_ids, plan.dut_id, result),
                    )
                else:
                    self._merge_collector_results(results[result_key], result)

        if plan.tail:
            try:
                tail_results = await self._execute_sequential_collectors_unified(
                    plan.tail,
                    [plan.dut_id],
                    collection_level,
                    None,
                )
                self._merge_collector_results(
                    results["sequential_results"], tail_results
                )
            except Exception as exc:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Tail collector execution failed for DUT {plan.dut_id}: {exc}",
                )
                self._merge_collector_results(
                    results["sequential_results"],
                    self._build_error_results(plan.tail, plan.dut_id, exc),
                )

        return results

    async def _execute_filtered_collectors_per_dut_scheduler(
        self,
        filtered_collectors_per_dut: Dict[str, List[str]],
        skipped_collectors_per_dut: Dict[str, List[Dict[str, Any]]],
        dut_ids: List[str],
        collection_level: str,
        preflight_results: Optional[Dict[str, Any]],
        original_collector_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute collector pipelines independently per DUT."""
        all_filtered_collectors = self._get_unique_collectors(
            filtered_collectors_per_dut
        )

        all_skipped_collectors = set()
        for dut_skipped in skipped_collectors_per_dut.values():
            for skipped_info in dut_skipped:
                all_skipped_collectors.add(skipped_info["collector_id"])

        plans = [
            self._build_dut_execution_plan(
                dut_id, filtered_collectors_per_dut.get(dut_id, [])
            )
            for dut_id in dut_ids
        ]
        total_sequential = sum(
            len(plan.normal_sequential) + len(plan.tail) for plan in plans
        )
        total_parallel = sum(len(plan.normal_parallel) for plan in plans)

        await self._log_to_all(
            "INFO",
            "WorkflowOrchestrator",
            f"Starting per-DUT execution of {len(all_filtered_collectors)} collectors: {', '.join(all_filtered_collectors)}",
            dut_ids,
        )

        results = {
            "sequential_results": {},
            "parallel_results": {},
            "skipped_results": skipped_collectors_per_dut,
            "summary": {
                "total_collectors": len(all_filtered_collectors),
                "skipped_collectors": len(all_skipped_collectors),
                "sequential_collectors": total_sequential,
                "parallel_collectors": total_parallel,
                "duts_processed": len(dut_ids),
            },
        }

        if preflight_results:
            self.execution_engine.set_preflight_results(preflight_results)

        await self._setup_progress_display(
            dut_ids,
            all_filtered_collectors,
            len(all_filtered_collectors),
        )

        try:
            plan_results = await asyncio.gather(
                *[self._execute_one_dut_plan(plan, collection_level) for plan in plans],
                return_exceptions=True,
            )

            for plan, plan_result in zip(plans, plan_results):
                if isinstance(plan_result, BaseException):
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"Per-DUT execution failed for DUT {plan.dut_id}: {plan_result}",
                    )
                    failed_collectors = (
                        plan.normal_parallel + plan.normal_sequential + plan.tail
                    )
                    self._merge_collector_results(
                        results["sequential_results"],
                        self._build_error_results(
                            failed_collectors, plan.dut_id, plan_result
                        ),
                    )
                    continue
                self._merge_collector_results(
                    results["parallel_results"],
                    plan_result.get("parallel_results", {}),
                )
                self._merge_collector_results(
                    results["sequential_results"],
                    plan_result.get("sequential_results", {}),
                )
        finally:
            await self._teardown_progress_display()

        await self.reporting_engine.log_all_results(results, dut_ids)

        total_executed = len(results.get("sequential_results", {})) + len(
            results.get("parallel_results", {})
        )
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Collector execution completed: {total_executed} collector groups executed",
        )

        await self._ensure_all_collectors_in_summary(
            collector_ids=all_filtered_collectors,
            dut_ids=dut_ids,
            results=results,
            preflight_results=preflight_results,
            original_collector_ids=original_collector_ids,
        )

        await self.reporting_engine.log_collector_status_table(
            results, dut_ids, all_filtered_collectors
        )
        await self.reporting_engine.log_execution_results_table(
            results, dut_ids, all_filtered_collectors
        )
        await self.reporting_engine.display_console_collector_summary(
            results, dut_ids, all_filtered_collectors
        )

        await self._log_to_all(
            "INFO",
            "WorkflowOrchestrator",
            f"Completed execution of {len(all_filtered_collectors)} collectors",
            dut_ids,
        )

        if hasattr(self, "status_tracker") and self.status_tracker:
            await self.status_tracker.finalize()

        self._write_execution_order_metadata()

        for dut_id in dut_ids:
            try:
                await self.logger.create_structured_log(dut_id)
            except Exception as e:
                await self.logger.log_runtime(
                    "WARN",
                    "WorkflowOrchestrator",
                    f"Failed to create structured log for DUT {dut_id}: {e}",
                )

        return results

    async def _execute_filtered_collectors(
        self,
        filtered_collectors_per_dut: Dict[str, List[str]],
        skipped_collectors_per_dut: Dict[str, List[Dict[str, Any]]],
        dut_ids: List[str],
        collection_level: str,
        preflight_results: Optional[Dict[str, Any]],
        original_collector_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute collectors using the filtered collectors per DUT.

        Args:
            filtered_collectors_per_dut: Dictionary of filtered collectors per DUT.
            skipped_collectors_per_dut: Dictionary of skipped collectors per DUT.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            preflight_results: Dictionary of preflight results.
            original_collector_ids: Original collector IDs for summary reconciliation.
        """
        scheduler_mode = self._get_execution_scheduler_mode()
        if scheduler_mode == "per_dut":
            return await self._execute_filtered_collectors_per_dut_scheduler(
                filtered_collectors_per_dut,
                skipped_collectors_per_dut,
                dut_ids,
                collection_level,
                preflight_results,
                original_collector_ids,
            )

        # Get union of all filtered collectors for execution
        all_filtered_collectors = set()
        for dut_collectors in filtered_collectors_per_dut.values():
            all_filtered_collectors.update(dut_collectors)
        all_filtered_collectors = list(all_filtered_collectors)

        # Get union of all skipped collectors for tracking
        all_skipped_collectors = set()
        for dut_skipped in skipped_collectors_per_dut.values():
            for skipped_info in dut_skipped:
                all_skipped_collectors.add(skipped_info["collector_id"])
        all_skipped_collectors = list(all_skipped_collectors)

        await self._log_to_all(
            "INFO",
            "WorkflowOrchestrator",
            f"Starting execution of {len(all_filtered_collectors)} collectors: {', '.join(all_filtered_collectors)}",
            dut_ids,
        )

        # Separate sequential and parallel collectors
        # Ensure tail collectors run last based on collector definitions.
        collector_positions = {
            cid: idx for idx, cid in enumerate(all_filtered_collectors)
        }
        tail_candidates = []
        normal_collectors = []
        for collector_id in all_filtered_collectors:
            collector_info = self.config_manager.get_collector_info(collector_id) or {}
            execution_phase = (
                str(collector_info.get("execution_phase", "")).strip().lower()
            )
            if execution_phase == "tail":
                tail_candidates.append((collector_id, collector_info))
            else:
                normal_collectors.append(collector_id)

        def _tail_sort_key(item):
            collector_id, collector_info = item
            order_value = collector_info.get("execution_order")
            try:
                order = int(order_value)
            except (TypeError, ValueError):
                order = None
            if order is None:
                return (1, collector_positions.get(collector_id, 0))
            return (0, order)

        tail_collectors_to_run = [
            collector_id
            for collector_id, _ in sorted(tail_candidates, key=_tail_sort_key)
        ]
        sequential_to_run = [
            cid for cid in normal_collectors if cid in self.get_sequential_collectors()
        ]
        parallel_to_run = [
            cid for cid in normal_collectors if cid in self.get_parallel_collectors()
        ]

        await self._log_to_all(
            "INFO",
            "WorkflowOrchestrator",
            f"Sequential collectors: {len(sequential_to_run) + len(tail_collectors_to_run)}, Parallel collectors: {len(parallel_to_run)}",
            dut_ids,
        )
        if tail_collectors_to_run:
            await self._log_to_all(
                "INFO",
                "WorkflowOrchestrator",
                f"Forced tail collectors (run last): {tail_collectors_to_run}",
                dut_ids,
            )

        # Execute collectors with progress bars
        results = {
            "sequential_results": {},
            "parallel_results": {},
            "skipped_results": skipped_collectors_per_dut,
            "summary": {
                "total_collectors": len(all_filtered_collectors),
                "skipped_collectors": len(all_skipped_collectors),
                "sequential_collectors": len(sequential_to_run)
                + len(tail_collectors_to_run),
                "parallel_collectors": len(parallel_to_run),
                "duts_processed": len(dut_ids),
            },
        }

        if preflight_results:
            self.execution_engine.set_preflight_results(preflight_results)

        total_collectors = (
            len(parallel_to_run) + len(sequential_to_run) + len(tail_collectors_to_run)
        )
        await self._setup_progress_display(
            dut_ids, all_filtered_collectors, total_collectors
        )

        parallel_task = None
        sequential_task = None

        if parallel_to_run:
            parallel_task = asyncio.create_task(
                self._execute_parallel_collectors_unified(
                    parallel_to_run,
                    dut_ids,
                    collection_level,
                    None,
                    self.progress_state,
                )
            )

        if sequential_to_run:
            sequential_task = asyncio.create_task(
                self._execute_sequential_collectors_unified(
                    sequential_to_run,
                    dut_ids,
                    collection_level,
                    None,
                )
            )

        # Wait for both tasks to complete (normal collectors only).
        # Use return_exceptions=True so both groups finish even if one fails —
        # we want to collect whatever logs are available and run all post-execution work.
        if parallel_task and sequential_task:
            parallel_result, sequential_result = await asyncio.gather(
                parallel_task, sequential_task, return_exceptions=True
            )

            if isinstance(parallel_result, BaseException):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Parallel collector execution failed: {parallel_result}",
                )
                results["parallel_results"] = {}
            else:
                results["parallel_results"] = parallel_result

            if isinstance(sequential_result, BaseException):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Sequential collector execution failed: {sequential_result}",
                )
                results["sequential_results"] = {}
            else:
                results["sequential_results"] = sequential_result

        elif parallel_task:
            try:
                results["parallel_results"] = await parallel_task
            except Exception as e:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Parallel collector execution failed: {e}",
                )
                results["parallel_results"] = {}
            results["sequential_results"] = {}

        elif sequential_task:
            try:
                results["sequential_results"] = await sequential_task
            except Exception as e:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Sequential collector execution failed: {e}",
                )
                results["sequential_results"] = {}
            results["parallel_results"] = {}

        else:
            results["parallel_results"] = {}
            results["sequential_results"] = {}

        # Execute forced tail collectors last, in fixed order.
        if tail_collectors_to_run:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                f"Executing forced tail collectors last: {tail_collectors_to_run}",
            )
            try:
                tail_results = await self._execute_sequential_collectors_unified(
                    tail_collectors_to_run,
                    dut_ids,
                    collection_level,
                    None,
                )
                results["sequential_results"].update(tail_results)
            except Exception as exc:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Tail collector execution failed: {exc}",
                )

        await self._teardown_progress_display()

        # Log all results to metadata
        await self.reporting_engine.log_all_results(results, dut_ids)

        # Log execution summary
        total_executed = len(results.get("sequential_results", {})) + len(
            results.get("parallel_results", {})
        )
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Collector execution completed: {total_executed} collector groups executed",
        )

        # Ensure requested collectors are represented in the execution summary
        await self._ensure_all_collectors_in_summary(
            collector_ids=all_filtered_collectors,
            dut_ids=dut_ids,
            results=results,
            preflight_results=preflight_results,
            original_collector_ids=original_collector_ids,
        )

        # Log collector status and execution results to DUT-specific logs (no console output)
        await self.reporting_engine.log_collector_status_table(
            results, dut_ids, all_filtered_collectors
        )
        await self.reporting_engine.log_execution_results_table(
            results, dut_ids, all_filtered_collectors
        )

        # Display summary on console with proper formatting
        # Only collectors that reached the execution stage are shown; pre-execution
        # skips (baseboard constraints, config options) are excluded entirely.
        await self.reporting_engine.display_console_collector_summary(
            results, dut_ids, all_filtered_collectors
        )

        await self._log_to_all(
            "INFO",
            "WorkflowOrchestrator",
            f"Completed execution of {len(all_filtered_collectors)} collectors",
            dut_ids,
        )

        # Finalize status tracker
        if hasattr(self, "status_tracker") and self.status_tracker:
            await self.status_tracker.finalize()

        # Write execution order metadata before structured log generation
        self._write_execution_order_metadata()

        # Create structured log files for each DUT
        for dut_id in dut_ids:
            try:
                await self.logger.create_structured_log(dut_id)
            except Exception as e:
                await self.logger.log_runtime(
                    "WARN",
                    "WorkflowOrchestrator",
                    f"Failed to create structured log for DUT {dut_id}: {e}",
                )

        return results

    async def _execute_parallel_collectors(
        self,
        collector_ids: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task: Any,
    ) -> Dict[str, Any]:
        """
        Wrapper for parallel collector execution (for test compatibility).

        Args:
            collector_ids: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar.
            main_task: Main task.
        """
        return await self.execution_engine.execute_service_based_parallel_collectors(
            collector_ids, dut_ids, collection_level, progress, main_task, None
        )

    async def _execute_parallel_collectors_with_progress(
        self,
        collector_ids: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task: Any,
    ) -> Dict[str, Any]:
        """
        Execute parallel collectors with progress bar management.

        Args:
            collector_ids: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar.
            main_task: Main task.
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"Executing parallel collectors: {len(collector_ids)} collectors for {len(dut_ids)} DUTs",
        )
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"Parallel collector IDs: {collector_ids}",
        )
        try:
            return (
                await self.execution_engine.execute_service_based_parallel_collectors(
                    collector_ids,
                    dut_ids,
                    collection_level,
                    progress,
                    main_task,
                    None,
                )
            )
        finally:
            if progress:
                progress.stop()

    async def _execute_sequential_collectors(
        self,
        collector_ids: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task: Any,
    ) -> Dict[str, Any]:
        """
        Wrapper for sequential collector execution (for test compatibility).

        Args:
            collector_ids: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar.
            main_task: Main task.
        """
        return await self.execution_engine.execute_sequential_collectors_with_progress(
            collector_ids, dut_ids, collection_level, progress, main_task
        )

    async def _execute_sequential_collectors_with_progress(
        self,
        collector_ids: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task: Any,
    ) -> Dict[str, Any]:
        """
        Execute sequential collectors with progress bar management.

        Args:
            collector_ids: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar.
            main_task: Main task.
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"Executing sequential collectors: {len(collector_ids)} collectors for {len(dut_ids)} DUTs",
        )
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"Sequential collector IDs: {collector_ids}",
        )
        try:
            return (
                await self.execution_engine.execute_sequential_collectors_with_progress(
                    collector_ids, dut_ids, collection_level, progress, main_task
                )
            )
        finally:
            if progress:
                progress.stop()

    async def _execute_parallel_collectors_unified(
        self,
        collector_ids: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        progress_state=None,
    ) -> Dict[str, Any]:
        """
        Execute parallel collectors with unified progress bar management.

        Args:
            collector_ids: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar.
            progress_state: Progress state.
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"Executing unified parallel collectors: {len(collector_ids)} collectors for {len(dut_ids)} DUTs",
        )
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"Unified parallel collector IDs: {collector_ids}",
        )
        try:
            # Create a main task for this group of parallel collectors
            main_task = None
            if progress:
                main_task = progress.add_task(
                    f"[cyan]Parallel ({len(collector_ids)} collectors × {len(dut_ids)} DUTs)",
                    total=len(collector_ids)
                    * len(dut_ids),  # Track collector-DUT combinations
                )

            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                "About to call execution_engine.execute_service_based_parallel_collectors",
            )
            return (
                await self.execution_engine.execute_service_based_parallel_collectors(
                    collector_ids,
                    dut_ids,
                    collection_level,
                    progress,
                    main_task,
                    progress_state,
                )
            )
        finally:
            # Don't stop progress here as it's shared with sequential collectors
            pass

    async def _execute_sequential_collectors_unified(
        self,
        collector_ids: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
    ) -> Dict[str, Any]:
        """
        Execute sequential collectors with unified progress bar management.

        Args:
            collector_ids: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar.
        """
        try:
            # Create a main task for this group of sequential collectors
            main_task = None
            if progress:
                main_task = progress.add_task(
                    f"[cyan]Sequential ({len(collector_ids)} collectors × {len(dut_ids)} DUTs)",
                    total=len(collector_ids)
                    * len(dut_ids),  # Track collector-DUT combinations
                )

            # Check execution strategy configuration
            tool_config = self.config_manager.get_tool_config()
            parallel_duts_enabled = (
                tool_config.get("parallel_dut_sequential_collectors", True)
                if isinstance(tool_config, dict)
                else getattr(tool_config, "parallel_dut_sequential_collectors", True)
            )
            service_grouping_enabled = (
                tool_config.get("service_grouped_sequential_collectors", True)
                if isinstance(tool_config, dict)
                else getattr(tool_config, "service_grouped_sequential_collectors", True)
            )

            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                f"Execution strategy decision - parallel_duts_enabled: {parallel_duts_enabled}, service_grouping_enabled: {service_grouping_enabled}, dut_count: {len(dut_ids)}",
            )

            if not parallel_duts_enabled or (
                len(dut_ids) <= 1 and not service_grouping_enabled
            ):
                # Use the original sequential execution method
                await self.logger.log_runtime(
                    "DEBUG",
                    "WorkflowOrchestrator",
                    "Using traditional sequential execution",
                )
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Using traditional sequential execution for collectors across {len(dut_ids)} DUTs",
                )
                return await self.execution_engine.execute_sequential_collectors_with_progress(
                    collector_ids,
                    dut_ids,
                    collection_level,
                    progress,
                    main_task,
                )
            elif service_grouping_enabled:
                # Use service-grouped parallel execution
                await self.logger.log_runtime(
                    "DEBUG",
                    "WorkflowOrchestrator",
                    "Using service-grouped parallel execution",
                )
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Using service-grouped parallel execution for sequential collectors across {len(dut_ids)} DUTs",
                )
                return await self.execution_engine.execute_sequential_collectors_grouped_by_service(
                    collector_ids,
                    dut_ids,
                    collection_level,
                    progress,
                    main_task,
                    self.progress_state,
                )
            else:
                # Use the parallel DUT execution method (without service grouping)
                await self.logger.log_runtime(
                    "DEBUG",
                    "WorkflowOrchestrator",
                    "Using parallel DUT execution",
                )
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Using parallel DUT execution for sequential collectors across {len(dut_ids)} DUTs",
                )
                return await self.execution_engine.execute_sequential_collectors_parallel_duts(
                    collector_ids,
                    dut_ids,
                    collection_level,
                    progress,
                    main_task,
                )
        finally:
            # Don't stop progress here as it's shared with parallel collectors
            pass

    async def _ensure_all_collectors_in_summary(
        self,
        collector_ids: List[str],
        dut_ids: List[str],
        results: Dict[str, Any],
        preflight_results: Optional[Dict[str, Any]] = None,
        original_collector_ids: Optional[List[str]] = None,
    ) -> None:
        """
        Ensure all requested collectors are in execution summary, even if they didn't run.

        Args:
            collector_ids: List of collector IDs.
            dut_ids: List of DUT IDs.
            results: Dictionary of results.
            preflight_results: Dictionary of preflight results.
            original_collector_ids: List of original collector IDs.
        """
        # Track execution per DUT/collector pair. A collector running on one DUT
        # does not imply it ran on every DUT in a heterogeneous rack.
        executed_pairs = set()
        sequential_results = results.get("sequential_results", {})
        parallel_results = results.get("parallel_results", {})

        for collector_id, collector_results in sequential_results.items():
            if isinstance(collector_results, dict):
                for dut_id in collector_results:
                    executed_pairs.add((dut_id, collector_id))
        for collector_id, collector_results in parallel_results.items():
            if isinstance(collector_results, dict):
                for dut_id in collector_results:
                    executed_pairs.add((dut_id, collector_id))

        # Use original collector IDs if provided so requested collectors appear in summary
        if original_collector_ids:
            eligible_collectors = set(original_collector_ids)
            filtered_out_collectors = eligible_collectors - set(collector_ids)
        else:
            eligible_collectors = set(collector_ids)
            filtered_out_collectors = set()

        # Add entries for DUT/collector pairs that didn't run.
        for collector_id in eligible_collectors:
            for dut_id in dut_ids:
                if (dut_id, collector_id) in executed_pairs:
                    continue
                # Get specific preflight failure reason if available
                if collector_id in filtered_out_collectors:
                    reason = "Collector not executed (filtered out before execution)"
                else:
                    reason = "Collector not executed (likely due to preflight failure)"
                if preflight_results and dut_id in preflight_results:
                    # Get service name from collector ID prefix
                    service_name = (
                        CollectorServiceMapping.get_service_from_collector_id(
                            collector_id
                        )
                    )

                    if service_name and service_name != "unknown":
                        dut_preflight = preflight_results[dut_id]
                        if (
                            "services" in dut_preflight
                            and service_name in dut_preflight["services"]
                        ):
                            service_result = dut_preflight["services"][service_name]
                            if service_result.get("status") == "fail":
                                failure_reason = service_result.get(
                                    "message", "Unknown preflight failure"
                                )
                                reason = f"Collector not executed due to {service_name} preflight failure: {failure_reason}"

                # Add to execution summary with "skipped" status
                await self.add_execution_summary_entry(
                    dut_id,
                    collector_id,
                    "skipped",
                    [],
                    reason,
                )

                # Create status.json for skipped collectors
                try:
                    await self.logger.write_collector_status_file(
                        collector_id,
                        dut_id,
                        "skipped",
                        reason,
                    )
                except Exception as e:
                    await self.logger.log_runtime(
                        "WARN",
                        "WorkflowOrchestrator",
                        f"Failed to create status.json for skipped collector {collector_id} on {dut_id}: {e}",
                    )

                # Update collector metadata for skipped collectors
                try:
                    await self.logger._update_collector_status(
                        dut_id,
                        collector_id,
                        "skipped",
                        reason,
                        0.0,
                    )
                except Exception as e:
                    await self.logger.log_runtime(
                        "WARN",
                        "WorkflowOrchestrator",
                        f"Failed to update metadata for skipped collector {collector_id} on {dut_id}: {e}",
                    )

    async def _write_completion_timestamps(self) -> None:
        """
        Write 'Completed at' timestamps to all DUT runtime logs.

        This is called before finalizing the execution summary so that
        the summary can read the complete timestamps to calculate accurate
        execution times.
        """
        if not self.dut_manager:
            return

        from datetime import datetime

        for dut_id in self.dut_manager.get_all_dut_ids():
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                f"DUT:{dut_id}",
                "=" * 80,
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                f"DUT:{dut_id}",
                f"DUT Runtime Log - {dut_id} - Completed",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                f"DUT:{dut_id}",
                f"Completed at: {datetime.now().isoformat()}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                f"DUT:{dut_id}",
                "=" * 80,
            )

    async def cleanup(
        self,
        total_runtime: Optional[float] = None,
        collector_ids: Optional[List[str]] = None,
    ) -> None:
        """
        Clean up resources and finalize logging.

        Args:
            total_runtime: Total runtime.
            collector_ids: List of collector IDs.
        """
        # Start timing for cleanup
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.start_component("cleanup")

        # Check if shutdown was requested
        if self.is_shutdown_requested():
            await self.logger.log_runtime(
                "WARN", "WorkflowOrchestrator", "Starting cleanup after interrupt..."
            )
        else:
            await self.logger.log_runtime(
                "INFO", "WorkflowOrchestrator", "Starting cleanup..."
            )

        # Write "Completed at" timestamps to DUT runtime logs BEFORE finalizing execution summary
        # This ensures the execution summary can calculate correct DUT execution times from the logs
        await self._write_completion_timestamps()

        # Finalize execution summary
        self.execution_summary_manager.finalize()
        summary_paths = self.execution_summary_manager.get_summary_file_paths()
        for dut_id, summary_path in summary_paths.items():
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                f"Execution summary finalized for {dut_id}: {summary_path}",
            )

        # Create DUT metadata files only if DUT manager is available
        if self.dut_manager:
            await self.reporting_engine.create_dut_metadata_files()

        # Perform cleanup operations (this will finalize logger and add timing data)
        if hasattr(self, "cleanup_manager") and self.cleanup_manager:
            await self.cleanup_manager.cleanup(self.log_dir)

        # Clean up DUT manager sessions to prevent "Unclosed client session" warnings
        if self.dut_manager:
            try:
                await self.dut_manager.cleanup()
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "DUT manager cleanup completed",
                )
            except Exception as e:
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    f"Error during DUT manager cleanup: {str(e)}",
                )

        # Clean up all service sessions to prevent "Unclosed client session" warnings
        if hasattr(self, "config_manager") and self.config_manager:
            for service_name, service in self.config_manager.services.items():
                if hasattr(service, "close_redfish_session"):
                    try:
                        await service.close_redfish_session()
                        await self.logger.log_runtime(
                            "INFO",
                            "WorkflowOrchestrator",
                            f"Closed {service_name} session",
                        )
                    except Exception as e:
                        await self.logger.log_runtime(
                            "WARNING",
                            "WorkflowOrchestrator",
                            f"Error closing {service_name} session: {str(e)}",
                        )

                # Also try to close any other sessions that might exist
                if hasattr(service, "session") and service.session:
                    try:
                        await service.session.close()
                        service.session = None
                        await self.logger.log_runtime(
                            "INFO",
                            "WorkflowOrchestrator",
                            f"Closed {service_name} general session",
                        )
                    except Exception as e:
                        await self.logger.log_runtime(
                            "WARNING",
                            "WorkflowOrchestrator",
                            f"Error closing {service_name} general session: {str(e)}",
                        )

        # Get tool config for skip flags
        # Use the tool_config passed to orchestrator if available, otherwise use config manager
        if self._tool_config_obj is not None:
            # Use object-based tool config (has CLI-derived values)
            try:
                skip_html_reports = self._tool_config_obj.get(
                    "skip_html_reports", False
                )
            except:
                skip_html_reports = getattr(
                    self._tool_config_obj, "skip_html_reports", False
                )
        else:
            tool_config = self.config_manager.get_tool_config()
            skip_html_reports = (
                tool_config.get("skip_html_reports", False)
                if isinstance(tool_config, dict)
                else getattr(tool_config, "skip_html_reports", False)
            )

        tool_config = self.config_manager.get_tool_config()
        skip_zip = (
            tool_config.get("skip_zip", False)
            if isinstance(tool_config, dict)
            else getattr(tool_config, "skip_zip", False)
        )

        self._append_execution_order_table_to_runtime_log()

        if isinstance(tool_config, dict):
            output_config = tool_config.get("output", {})
            generate_html = (
                output_config.get("generate_html", True)
                if isinstance(output_config, dict)
                else tool_config.get("GENERATE_HTML_REPORTS", True)
            )
        else:
            generate_html = getattr(tool_config, "GENERATE_HTML_REPORTS", True)
        # Determine report format
        report_format = (
            tool_config.get("report_format", "spa")
            if isinstance(tool_config, dict)
            else getattr(tool_config, "report_format", "spa")
        )

        if not skip_html_reports and generate_html:
            # Generate legacy HTML reports
            if report_format in ("legacy", "both"):
                await self.generate_html_reports(total_runtime, collector_ids)

            # Generate SPA report
            if report_format in ("spa", "both"):
                await self._generate_spa_report()

        # Append execution order table at the end of the DUT runtime log
        self._append_execution_order_table_to_runtime_log()
        # Write execution order metadata json for each DUT
        self._write_execution_order_metadata()

        # Finalize logger (this will close file handles and restore stdout/stderr)
        if hasattr(self, "cleanup_manager") and self.cleanup_manager:
            await self.cleanup_manager.finalize_logger()

        # Create zip archive after logger finalization (all files are closed and flushed)
        zip_archive_path = None
        if not skip_zip:
            if hasattr(self, "cleanup_manager") and self.cleanup_manager:
                zip_archive_path = await self.cleanup_manager.create_final_zip_archive(
                    self.log_dir
                )
            # Store the zip archive path for later use
            self.zip_archive_path = zip_archive_path

        # Final aggressive cleanup to ensure all ClientSessions are closed
        try:

            # Force garbage collection to find any unclosed sessions
            gc.collect()

            # Find any remaining ClientSession objects
            for obj in gc.get_objects():
                if isinstance(obj, aiohttp.ClientSession):
                    if not obj.closed:
                        await self.logger.log_runtime(
                            "WARNING",
                            "WorkflowOrchestrator",
                            f"Found unclosed ClientSession: {obj}, closing it",
                        )
                        try:
                            await obj.close()
                        except Exception as e:
                            await self.logger.log_runtime(
                                "WARNING",
                                "WorkflowOrchestrator",
                                f"Error closing unclosed ClientSession: {str(e)}",
                            )

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Final aggressive cleanup completed",
            )
        except Exception as e:
            await self.logger.log_runtime(
                "WARNING",
                "WorkflowOrchestrator",
                f"Error during final aggressive cleanup: {str(e)}",
            )

        # End timing for cleanup
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.end_component("cleanup")

    def _setup_signal_handlers(self) -> None:
        """
        Setup signal handlers for graceful cleanup on interruption.

        Registers handlers for SIGINT and SIGTERM to enable graceful shutdown.
        """

        def signal_handler(signum, frame):
            """
            Handle interruption signals.

            Args:
                signum: Signal number.
                frame: Current stack frame.

            Raises:
                KeyboardInterrupt: To trigger shutdown.
            """
            # Prevent multiple signal handler calls
            if self._signal_handler_called:
                print(f"\nReceived signal {signum} again, forcing immediate exit...")
                import os

                os._exit(1)

            self._signal_handler_called = True
            print(f"\nReceived signal {signum}, stopping execution...")
            self._shutdown_requested = True

            # Try to interrupt the current event loop
            try:
                loop = asyncio.get_running_loop()
                # Cancel all running tasks to force immediate interruption
                for task in asyncio.all_tasks(loop):
                    if not task.done():
                        task.cancel()
                        # Don't print task cancellation messages - too verbose
            except RuntimeError:
                # No event loop running
                pass

            # Also raise KeyboardInterrupt to be caught by the main function's handler
            # This provides a more immediate response
            raise KeyboardInterrupt("Shutdown requested")

        # Register signal handlers
        signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
        signal.signal(signal.SIGTERM, signal_handler)  # kill command

    async def _emergency_cleanup(self) -> None:
        """
        Emergency cleanup to close all ClientSessions when interrupted.

        Args:
            None
        """
        try:
            # Force garbage collection to find any unclosed sessions
            gc.collect()

            # Find any remaining ClientSession objects and close them
            closed_count = 0
            for obj in gc.get_objects():
                if isinstance(obj, aiohttp.ClientSession):
                    if not obj.closed:
                        try:
                            await obj.close()
                            closed_count += 1
                        except Exception:
                            # Silently handle errors during cleanup
                            pass

            if closed_count > 0:
                print(f"Cleaned up {closed_count} connection(s)")

        except Exception:
            # Silently handle errors during emergency cleanup
            pass

    def is_shutdown_requested(self) -> bool:
        """
        Check if shutdown has been requested via signal handler.

        Returns:
            True if shutdown was requested, False otherwise.
        """
        return self._shutdown_requested

    def is_collector_applicable_for_baseboard(
        self,
        collector: Dict[str, Any],
        baseboard_info: Optional[str],
        node_type: Optional[str] = None,
    ) -> bool:
        """
        Check if a collector is applicable for a specific baseboard.
        This is a public method for use by other components.

        Args:
            collector: Collector information
            baseboard_info: Baseboard information

        Returns:
            True if collector is applicable for baseboard, False otherwise.

        Raises:
            ValueError: If baseboard is not defined in spreadsheet (configuration error)
        """
        try:
            if node_type:
                return self._is_collector_applicable(
                    collector, baseboard_info, node_type
                )
            return self._is_collector_applicable(collector, baseboard_info)
        except ValueError:
            # Re-raise ValueError as-is - it's a critical configuration error
            # that should stop execution. The error message is already formatted.
            raise

    def _generate_dut_specific_reason(
        self,
        original_reason: str,
        status: str,
        dut_baseboard: str,
        collector_info: Dict[str, Any],
    ) -> str:
        """
        Generate a DUT-specific reason message for multi-DUT environments.

        Args:
            original_reason: The original reason message
            status: The collector status
            dut_baseboard: The specific baseboard for this DUT
            collector_info: Collector information

        Returns:
            str: DUT-specific reason message
        """
        if status == "Included":
            return f"Collector is applicable for baseboard '{dut_baseboard}'"
        elif status == "Not applicable":
            # Check if it's due to tags or baseboard constraints
            tags = collector_info.get("tags", {})
            if isinstance(tags, dict):
                include_tags = tags.get("include", [])
                exclude_tags = tags.get("exclude", [])
            else:
                include_tags = []
                exclude_tags = []

            if exclude_tags:
                return f"Not applicable for baseboard '{dut_baseboard}' (Tags: {exclude_tags})"
            elif include_tags:
                return f"Not applicable for baseboard '{dut_baseboard}' (BaseboardConstraint)"
            else:
                return f"Not applicable for baseboard '{dut_baseboard}' (BaseboardConstraint)"
        else:
            # For other statuses, use the original reason
            return original_reason

    def _is_collector_applicable(
        self,
        collector: Dict[str, Any],
        baseboard_info: Optional[str],
        node_type: Optional[str] = None,
    ) -> bool:
        """
        Check if a collector is applicable for the current baseboard.

        Args:
            collector: Collector definition
            baseboard_info: Baseboard information (can be None for multi-DUT scenarios)

        Returns:
            bool: True if collector is applicable
        """
        # Handle multi-DUT scenarios where baseboard_info is None
        # In these cases, baseboard filtering is deferred to per-DUT execution
        if baseboard_info is None:
            # Multi-DUT scenario - allow collector through global filter
            # Per-DUT baseboard filtering will occur during execution
            return True

        # Check for invalid baseboard values (empty string, "unknown", etc.)
        if not baseboard_info or baseboard_info.lower() == "unknown":
            # This is a critical configuration error - baseboard must be configured
            # The tool should not run without proper baseboard configuration
            # Use the same pattern as main.py validation errors
            # Note: We need to get the console from the logger since we don't have direct access to it here
            if hasattr(self.logger, "console"):
                console = self.logger.console
                console.print_error(
                    f"Baseboard not configured or unknown ('{baseboard_info}'). Baseboard is required for collector compatibility."
                )
                console.print_error("Please configure baseboard in DUT config file.")
            else:
                # Fallback to basic error message if console not available
                print(
                    f"ERROR: Baseboard not configured or unknown ('{baseboard_info}'). Baseboard is required for collector compatibility."
                )
                print("ERROR: Please configure baseboard in DUT config file.")
            sys.exit(1)

        baseboard_manager = None
        baseboard_type = None
        if hasattr(self, "dut_manager") and self.dut_manager:
            baseboard_manager = self.dut_manager._get_baseboard_manager()
            if baseboard_manager:
                baseboard_type = baseboard_manager.get_baseboard_type(baseboard_info)
                if not isinstance(baseboard_type, str):
                    baseboard_type = None
        effective_baseboard_names = [baseboard_info]
        effective_baseboard_uppers = [
            member.upper() for member in effective_baseboard_names
        ]

        def _normalize_constraint_values(value):
            normalized = []

            def _flatten(item):
                if item is None:
                    return
                if isinstance(item, str):
                    trimmed = item.strip()
                    if trimmed:
                        normalized.append(trimmed)
                    return
                if isinstance(item, list):
                    for child in item:
                        _flatten(child)
                    return
                if isinstance(item, dict):
                    for key, flag in item.items():
                        include = True
                        if isinstance(flag, bool):
                            include = flag
                        elif isinstance(flag, str):
                            include = flag.strip().lower() not in (
                                "false",
                                "0",
                                "no",
                                "off",
                            )
                        elif isinstance(flag, (int, float)):
                            include = bool(flag)
                        if include:
                            normalized.append(str(key).strip())
                    return
                normalized.append(str(item).strip())

            _flatten(value)
            return [item for item in normalized if item]

        def _constraint_matches(spec: str) -> bool:
            spec_upper = spec.upper()
            if spec_upper in {"ALL", "*"}:
                return True
            if spec_upper in effective_baseboard_uppers:
                return True
            if baseboard_type and baseboard_type.upper() == spec_upper:
                return True
            if node_type and node_type.upper() == spec_upper:
                return True
            if baseboard_manager:
                group_members = baseboard_manager.get_baseboards_in_group(spec)
                group_members_upper = [member.upper() for member in group_members]
                if group_members and any(
                    effective in group_members_upper
                    for effective in effective_baseboard_uppers
                ):
                    return True
            return False

        exclude_baseboards = _normalize_constraint_values(
            collector.get("exclude_baseboards")
        )
        if any(_constraint_matches(spec) for spec in exclude_baseboards):
            return False

        # Check applicable_baseboards field (YAML-based method)
        applicable_baseboards = collector.get("applicable_baseboards", "all")

        # Handle empty/None applicable_baseboards (treat as "all")
        if applicable_baseboards is None or applicable_baseboards == "":
            applicable_baseboards = "all"

        if applicable_baseboards == "all":
            # Applicable to all baseboards
            pass  # Continue to check tags if any
        elif isinstance(applicable_baseboards, list):
            # Use BaseboardManager for proper baseboard type matching
            if hasattr(self, "dut_manager") and self.dut_manager:
                if baseboard_manager:
                    # If baseboard_type is None, check if baseboard_info is a group name
                    # This handles cases where platform detection returns a group name like "NVL"
                    # instead of a specific baseboard name like "GB200 NVL"
                    if baseboard_type is None:
                        all_groups = baseboard_manager.get_all_baseboard_types()
                        if baseboard_info.upper() in [g.upper() for g in all_groups]:
                            # baseboard_info is a valid group name, use it as the type
                            baseboard_type = baseboard_info
                        else:
                            # Baseboard not found in spreadsheet and not a valid group name
                            # This is a configuration error - the spreadsheet needs to be updated
                            try:
                                available_baseboards = sorted(
                                    baseboard_manager.baseboards.keys()
                                )
                            except (AttributeError, TypeError):
                                available_baseboards = []

                            available_str = (
                                f"Available baseboards: {available_baseboards}"
                                if available_baseboards
                                else "No baseboards found in spreadsheet"
                            )

                            error_msg = (
                                f"Baseboard '{baseboard_info}' is not defined in the spreadsheet. "
                                f"This is a configuration error. Please ensure the spreadsheet includes "
                                f"the baseboard. {available_str}"
                            )
                            if hasattr(self, "logger") and hasattr(
                                self.logger, "console"
                            ):
                                self.logger.console.print_error(error_msg)
                            else:
                                print(f"ERROR: {error_msg}")
                            raise ValueError(error_msg)

                    # Check if the baseboard name or type matches any in the applicable list
                    baseboard_found = False
                    for applicable_bb in applicable_baseboards:
                        applicable_bb_upper = applicable_bb.upper()

                        # Check for exact baseboard name match
                        if applicable_bb_upper in effective_baseboard_uppers:
                            baseboard_found = True
                            break

                        # Check for baseboard type match (if we have a type)
                        if (
                            baseboard_type
                            and applicable_bb_upper == baseboard_type.upper()
                        ):
                            baseboard_found = True
                            break
                        if node_type and applicable_bb_upper == node_type.upper():
                            baseboard_found = True
                            break

                    if not baseboard_found:
                        return False
                else:
                    # Fallback to exact string matching if BaseboardManager not available
                    baseboard = baseboard_info.upper()
                    node = node_type.upper() if node_type else None
                    baseboard_found = False
                    for applicable_bb in applicable_baseboards:
                        applicable_upper = applicable_bb.upper()
                        if applicable_upper == baseboard or (
                            node and applicable_upper == node
                        ):
                            baseboard_found = True
                            break
                    if not baseboard_found:
                        return False
            else:
                # Fallback to exact string matching if DUT manager not available
                baseboard = baseboard_info.upper()
                node = node_type.upper() if node_type else None
                baseboard_found = False
                for applicable_bb in applicable_baseboards:
                    applicable_upper = applicable_bb.upper()
                    if applicable_upper == baseboard or (
                        node and applicable_upper == node
                    ):
                        baseboard_found = True
                        break
                if not baseboard_found:
                    return False
        elif isinstance(applicable_baseboards, str):
            # Single baseboard constraint
            if applicable_baseboards.upper() != "ALL":
                # Use BaseboardManager for proper baseboard type matching
                if hasattr(self, "dut_manager") and self.dut_manager:
                    if baseboard_manager:
                        # If baseboard_type is None, check if baseboard_info is a group name
                        # This handles cases where platform detection returns a group name like "NVL"
                        # instead of a specific baseboard name like "GB200 NVL"
                        if baseboard_type is None:
                            all_groups = baseboard_manager.get_all_baseboard_types()
                            if baseboard_info.upper() in [
                                g.upper() for g in all_groups
                            ]:
                                # baseboard_info is a valid group name, use it as the type
                                baseboard_type = baseboard_info
                            else:
                                # Baseboard not found in spreadsheet and not a valid group name
                                # This is a configuration error - the spreadsheet needs to be updated
                                try:
                                    available_baseboards = sorted(
                                        baseboard_manager.baseboards.keys()
                                    )
                                except (AttributeError, TypeError):
                                    available_baseboards = []

                                available_str = (
                                    f"Available baseboards: {available_baseboards}"
                                    if available_baseboards
                                    else "No baseboards found in spreadsheet"
                                )

                                error_msg = (
                                    f"Baseboard '{baseboard_info}' is not defined in the spreadsheet. "
                                    f"This is a configuration error. Please ensure the spreadsheet includes "
                                    f"the baseboard. {available_str}"
                                )
                                if hasattr(self, "logger") and hasattr(
                                    self.logger, "console"
                                ):
                                    self.logger.console.print_error(error_msg)
                                else:
                                    print(f"ERROR: {error_msg}")
                                raise ValueError(error_msg)

                        # Check if it's a group match (baseboard type matches)
                        if (
                            baseboard_type
                            and baseboard_type.upper() == applicable_baseboards.upper()
                        ):
                            return True
                        # Check if it's an individual baseboard match (baseboard name matches)
                        if applicable_baseboards.upper() in effective_baseboard_uppers:
                            return True
                        if node_type and node_type.upper() == applicable_baseboards.upper():
                            return True
                        # If neither matches, it's not applicable
                        return False
                    else:
                        # Fallback to exact string matching
                        applicable_upper = applicable_baseboards.upper()
                        if applicable_upper != baseboard_info.upper() and (
                            not node_type or applicable_upper != node_type.upper()
                        ):
                            return False
                else:
                    # Fallback to exact string matching
                    applicable_upper = applicable_baseboards.upper()
                    if applicable_upper != baseboard_info.upper() and (
                        not node_type or applicable_upper != node_type.upper()
                    ):
                        return False

        # Also check legacy tags format for backward compatibility
        tags = collector.get("tags", {})
        if isinstance(tags, dict):
            include_tags = tags.get("include", [])
            exclude_tags = tags.get("exclude", [])
        else:
            include_tags = []
            exclude_tags = []

        context_for_tags = " ".join(
            part
            for part in [baseboard_info, baseboard_type, node_type]
            if part
        ).upper()

        # Check exclude tags first
        for exclude_tag in exclude_tags:
            if exclude_tag.upper() in context_for_tags:
                return False

        # Check include tags
        if include_tags:
            for include_tag in include_tags:
                if include_tag.upper() in context_for_tags:
                    return True
            return False  # No include tags matched

        return True  # Passed all checks

    def _is_collector_level_applicable(
        self, collector_level: str, current_level: str
    ) -> bool:
        """
        Check if a collector level is applicable for the current collection level.

        L0 collectors are special - they only run when explicitly specified via CLI
        (--collector-id or --include-collectors) and never run by default in any level.

        Args:
            collector_level: Collector's required level
            current_level: Current collection level

        Returns:
            bool: True if collector level is applicable
        """
        # L0 collectors never run by default - they must be explicitly specified
        # They are filtered at the CLI level when specific collector IDs are provided
        if collector_level == "L0":
            return False

        level_mapping = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}

        collector_level_num = level_mapping.get(collector_level, 3)
        current_level_num = level_mapping.get(current_level, 3)

        return collector_level_num <= current_level_num

    def get_all_collectors(
        self, collection_level: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get all collector definitions, optionally filtered by collection level.

        Args:
            collection_level: Optional collection level to filter by (L1, L2, L3).
                            If None, returns all collectors without filtering.

        Returns:
            Dict of collector_id -> collector_info for applicable collectors
        """
        all_collectors = self.config_manager.get_all_collectors()

        # If no collection level specified, return all collectors (backward compatibility)
        if collection_level is None:
            return all_collectors

        # Filter by collection level
        filtered_collectors = {}
        for collector_id, collector_info in all_collectors.items():
            collector_level = collector_info.get("collection_level", "L1")
            if self._is_collector_level_applicable(collector_level, collection_level):
                filtered_collectors[collector_id] = collector_info

        return filtered_collectors

    async def _create_redfish_sessions_with_progress(
        self, dut_ids: List[str], progress, session_task
    ) -> None:
        """
        Create Redfish sessions with progress tracking and shutdown handling.

        Args:
            dut_ids: List of DUT IDs.
            progress: Progress bar.
            session_task: Session task.
        """

        async def create_session_for_dut(dut_id: str) -> tuple:
            """
            Create Redfish session for a single DUT.

            Args:
                dut_id: DUT ID.

            Returns:
                Tuple containing DUT ID and session creation status.
            """
            try:
                dut = self.dut_manager.get_dut(dut_id)
                if dut.connection_state.redfish_connected:
                    # Add timeout to prevent hanging
                    await asyncio.wait_for(
                        dut.create_redfish_session(),
                        timeout=30.0,  # 30 second timeout per DUT
                    )
                    return dut_id, "success"
                else:
                    return dut_id, "skipped"
            except asyncio.TimeoutError:
                await self.logger.log_runtime(
                    "WARN",
                    "WorkflowOrchestrator",
                    f"Timeout creating Redfish session for {dut_id} (30s)",
                )
                return dut_id, "timeout"
            except Exception as e:
                await self.logger.log_runtime(
                    "WARN",
                    "WorkflowOrchestrator",
                    f"Failed to create Redfish session for {dut_id}: {str(e)}",
                )
                return dut_id, "failed"

        # Check if shutdown was requested
        if hasattr(self, "_shutdown_requested") and self._shutdown_requested:
            await self.logger.log_runtime(
                "WARN",
                "WorkflowOrchestrator",
                "Shutdown requested, stopping Redfish session creation",
            )
            return

        # Process all DUTs concurrently
        all_tasks = [create_session_for_dut(dut_id) for dut_id in dut_ids]
        all_results = await asyncio.gather(*all_tasks, return_exceptions=True)

        for j, result in enumerate(all_results):
            if isinstance(result, Exception):
                dut_id = dut_ids[j]
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Unexpected error creating session for DUT {dut_id}: {str(result)}",
                )
                progress.update(session_task, description=f"Error {dut_id}")
            else:
                dut_id, status = result
                if status == "success":
                    progress.update(
                        session_task,
                        description=f"Created session for {dut_id}",
                    )
                elif status == "skipped":
                    progress.update(
                        session_task,
                        description=f"Skipped {dut_id} (no Redfish)",
                    )
                elif status == "timeout":
                    progress.update(session_task, description=f"Timeout {dut_id}")
                else:  # failed
                    progress.update(session_task, description=f"Failed {dut_id}")

            progress.advance(session_task)

    async def _setup_progress_display(
        self,
        dut_ids: List[str],
        all_filtered_collectors: list,
        total_collectors: int,
    ) -> None:
        """Initialize progress state manager and display for collector execution."""
        try:
            progress_state = ProgressStateManager(
                dut_ids, all_filtered_collectors, self.logger, self.console
            )
            self.progress_state = progress_state
            self.progress_display = ProgressDisplay(self.console, self.logger)
            self.progress_display.set_progress_state(progress_state)
            await progress_state.initialize()
        except ImportError:
            self.progress_state = None
            self.progress_display = None

        if total_collectors > 0:
            self.console.print(
                f"\n[bold blue]Executing {total_collectors} Collectors[/bold blue]"
            )
            if self.progress_display:
                self.progress_display.start(dut_ids, total_collectors)
                self.progress_update_task = asyncio.create_task(
                    self._update_progress_periodically()
                )

    async def _teardown_progress_display(self) -> None:
        """Stop progress display and cancel the background update task."""
        if hasattr(self, "progress_display") and self.progress_display:
            await self.progress_display.update()
            self.progress_display.stop()

        if hasattr(self, "progress_update_task") and self.progress_update_task:
            self.progress_update_task.cancel()
            try:
                await self.progress_update_task
            except asyncio.CancelledError:
                pass

    async def _log_to_all(
        self,
        level: str,
        component: str,
        message: str,
        dut_ids: List[str],
    ) -> None:
        """Log a message to both the runtime log and every DUT's runtime log."""
        await self.logger.log_runtime(level, component, message)
        for dut_id in dut_ids:
            await self.logger.write_to_dut_runtime_log(
                dut_id, level, component, message
            )

    async def _update_progress_periodically(self):
        """
        Update progress display periodically.

        Args:
            None
        """
        try:
            await self.logger.log_runtime(
                "DEBUG", "WorkflowOrchestrator", "Progress update task started"
            )
            while True:
                # Check for shutdown request
                if self.is_shutdown_requested():
                    await self.logger.log_runtime(
                        "DEBUG",
                        "WorkflowOrchestrator",
                        "Shutdown requested, stopping progress updates",
                    )
                    break

                await self.logger.log_runtime(
                    "DEBUG",
                    "WorkflowOrchestrator",
                    f"Progress update loop - hasattr progress_display: {hasattr(self, 'progress_display')}",
                )
                if hasattr(self, "progress_display") and self.progress_display:
                    await self.logger.log_runtime(
                        "DEBUG",
                        "WorkflowOrchestrator",
                        f"Progress display object: {self.progress_display}",
                    )
                    await self.logger.log_runtime(
                        "DEBUG",
                        "WorkflowOrchestrator",
                        "Calling progress display update",
                    )
                    await self.progress_display.update()
                else:
                    await self.logger.log_runtime(
                        "DEBUG",
                        "WorkflowOrchestrator",
                        "No progress display available",
                    )
                await asyncio.sleep(0.5)  # Update every 500ms
        except asyncio.CancelledError:
            # Task was cancelled, exit gracefully
            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                "Progress update task cancelled",
            )
            pass
        except Exception as e:
            # Don't let progress update errors break execution
            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                f"Progress update task error: {e}",
            )
            pass
