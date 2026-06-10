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
Reporting Engine for NVDebug Tool.

Handles status table generation, results logging, metadata creation, and HTML
report generation for collection results.
"""

import logging
import re
import sys
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..utils.console_output import create_sanitized_console

logger = logging.getLogger(__name__)
sanitized_console = create_sanitized_console()


class ReportingEngine:
    """
    Manages status reporting, results logging, and metadata creation.

    Handles generation of status tables, HTML reports, and metadata files for
    collection results across multiple DUTs.

    Attributes:
        config_manager: Configuration manager instance.
        dut_manager: DUT manager instance.
        logger: Logger instance.
    """

    def __init__(self, config_manager, dut_manager, logger):
        """
        Initialize reporting engine.

        Args:
            config_manager: Configuration manager.
            dut_manager: DUT manager.
            logger: Logger instance.
        """
        self.config_manager = config_manager
        self.dut_manager = dut_manager
        self.logger = logger

    async def log_collector_status_table(
        self,
        results: Dict[str, Any],
        dut_ids: List[str],
        collector_ids: List[str],
    ) -> None:
        """
        Log collector status table to each DUT's runtime log.

        Args:
            results: Collection results dictionary.
            dut_ids: List of DUT IDs.
            collector_ids: List of collector IDs.
        """
        # Group collectors by service
        service_groups = {}
        for collector_id in collector_ids:
            collector_info = self.config_manager.get_collector_info(collector_id)
            group = collector_info.get("group", "unknown")
            if group not in service_groups:
                service_groups[group] = []
            service_groups[group].append(collector_id)

        # Create DUT-specific tables
        for dut_id in dut_ids:
            # Create status table for this DUT
            table = Table(title=f"Collector Execution Status - {dut_id}")
            table.add_column("Group", style="cyan")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="cyan")
            table.add_column("Status", style="cyan")
            table.add_column("Reason", style="cyan")

            # Process results for each service group for this DUT
            for group, group_collectors in service_groups.items():
                for collector_id in group_collectors:
                    collector_info = self.config_manager.get_collector_info(
                        collector_id
                    )
                    collector_name = collector_info.get("name", "Unknown")
                    # Format collector name properly
                    formatted_name = self._format_collector_name(collector_name)

                    # Get status for this specific DUT
                    status = "not_ran"
                    reason = "Collector not executed (likely due to preflight failure)"

                    # Check sequential results
                    sequential_results = results.get("sequential_results", {})
                    if (
                        collector_id in sequential_results
                        and dut_id in sequential_results[collector_id]
                    ):
                        dut_result = sequential_results[collector_id][dut_id]
                        status = dut_result.get("status", "not_ran")
                        reason = dut_result.get("reason", "")

                    # Check parallel results
                    parallel_results = results.get("parallel_results", {})
                    if (
                        collector_id in parallel_results
                        and dut_id in parallel_results[collector_id]
                    ):
                        dut_result = parallel_results[collector_id][dut_id]
                        status = dut_result.get("status", "not_ran")
                        reason = dut_result.get("reason", "")

                    # Get baseboard info for this DUT
                    dut_config = self.config_manager.get_dut_config().get(dut_id, {})
                    baseboard = dut_config.get("baseboard", "Unknown")

                    # Color code the status
                    status_color = (
                        "green"
                        if status == "success"
                        else (
                            "red"
                            if status == "error"
                            else "yellow" if status == "skipped" else "dim"
                        )
                    )
                    status_text = f"[{status_color}]{status.upper()}[/{status_color}]"

                    # Add row to table
                    table.add_row(
                        group.title(),
                        collector_id,
                        f"{formatted_name} ({baseboard})",
                        status_text,
                        reason,
                    )

            # Capture table for logging only (no console print)
            buffer = StringIO()
            console = Console(file=buffer, record=True)
            console.print(table)
            table_text = buffer.getvalue()
            buffer.close()

            # Write to DUT-specific runtime log
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "CollectorStatus",
                f"Collector execution status for {dut_id}:\n{table_text}",
            )

    async def log_execution_results_table(
        self,
        results: Dict[str, Any],
        dut_ids: List[str],
        collector_ids: List[str] = None,
    ) -> None:
        """
        Log execution results summary table to each DUT's runtime log.

        Args:
            results: Collection results dictionary.
            dut_ids: List of DUT IDs.
            collector_ids: Optional list of collector IDs.
        """
        # Create DUT-specific tables
        for dut_id in dut_ids:
            # Create results table for this DUT
            table = Table(title=f"Execution Results Summary - {dut_id}")
            table.add_column("Collector ID", style="cyan")
            table.add_column("Status", style="cyan")
            table.add_column("Reason", style="cyan")
            table.add_column("Execution Time", style="cyan")

            # Process results for this specific DUT
            dut_collectors = []

            # Process sequential results
            sequential_results = results.get("sequential_results", {})
            for collector_id, collector_results in sequential_results.items():
                if dut_id in collector_results:
                    dut_result = collector_results[dut_id]
                    status = dut_result.get("status", "not_ran")
                    reason = dut_result.get("reason", "")
                    execution_time = dut_result.get("execution_time", 0.0)

                    dut_collectors.append(
                        {
                            "collector_id": collector_id,
                            "status": status,
                            "reason": reason,
                            "execution_time": execution_time,
                        }
                    )

            # Process parallel results
            parallel_results = results.get("parallel_results", {})
            for collector_id, collector_results in parallel_results.items():
                if dut_id in collector_results:
                    dut_result = collector_results[dut_id]
                    status = dut_result.get("status", "not_ran")
                    reason = dut_result.get("reason", "")
                    execution_time = dut_result.get("execution_time", 0.0)

                    dut_collectors.append(
                        {
                            "collector_id": collector_id,
                            "status": status,
                            "reason": reason,
                            "execution_time": execution_time,
                        }
                    )

            # Add collectors that didn't run
            if collector_ids:
                executed_collector_ids = {c["collector_id"] for c in dut_collectors}
                for collector_id in collector_ids:
                    if collector_id not in executed_collector_ids:
                        dut_collectors.append(
                            {
                                "collector_id": collector_id,
                                "status": "not_ran",
                                "reason": "Collector not executed (likely due to preflight failure)",
                                "execution_time": 0.0,
                            }
                        )

            # Add rows to table
            for collector_info in dut_collectors:
                # Color code the status
                status_color = (
                    "green"
                    if collector_info["status"] == "success"
                    else (
                        "red"
                        if collector_info["status"] == "error"
                        else (
                            "yellow" if collector_info["status"] == "skipped" else "dim"
                        )
                    )
                )
                status_text = f"[{status_color}]{collector_info['status'].upper()}[/{status_color}]"

                # Format execution time
                exec_time = (
                    f"{collector_info['execution_time']:.2f}s"
                    if collector_info["execution_time"] > 0
                    else "N/A"
                )

                table.add_row(
                    collector_info["collector_id"],
                    status_text,
                    collector_info["reason"],
                    exec_time,
                )

            # Capture table for logging only (no console print)
            buffer = StringIO()
            console = Console(file=buffer, record=True)
            console.print(table)
            table_text = buffer.getvalue()
            buffer.close()

            # Write to DUT-specific runtime log
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "ExecutionResults",
                f"Execution results summary for {dut_id}:\n{table_text}",
            )

    async def display_console_collector_summary(
        self,
        results: Dict[str, Any],
        dut_ids: List[str],
        collector_ids: List[str],
    ) -> None:
        """
        Display collector execution summary tables on console.

        Args:
            results: Collection results dictionary.
            dut_ids: List of DUT IDs.
            collector_ids: List of collector IDs.
        """
        # Use sanitized console for consistent output
        console = sanitized_console.console

        # For multi-DUT scenarios, show simplified summary table
        if len(dut_ids) > 1:
            await self._display_multi_dut_summary(results, dut_ids, collector_ids)
        else:
            # For single DUT, show detailed table
            await self._display_single_dut_summary(results, dut_ids[0], collector_ids)

    def _get_dut_wall_clock_time(self, dut_id: str) -> float:
        """
        Get actual wall-clock execution time for a DUT from runtime logs.

        Args:
            dut_id: DUT identifier

        Returns:
            float: Wall-clock execution time in seconds, or 0.0 if not found
        """
        try:
            runtime_log_path = (
                Path(self.logger.base_log_dir) / dut_id / "nvdebug_runtime_output.txt"
            )
            if not runtime_log_path.exists():
                return 0.0

            with runtime_log_path.open("r", encoding="utf-8") as f:
                content = f.read()

            # Look for start and end timestamps
            start_match = re.search(
                r"Started at:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)", content
            )
            end_match = re.search(
                r"Completed at:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)", content
            )

            if start_match and end_match:
                start_time = datetime.fromisoformat(start_match.group(1))
                end_time = datetime.fromisoformat(end_match.group(1))
                return (end_time - start_time).total_seconds()

            return 0.0
        except Exception:
            return 0.0

    async def _display_multi_dut_summary(
        self,
        results: Dict[str, Any],
        dut_ids: List[str],
        collector_ids: List[str],
    ) -> None:
        """
        Display simplified summary table for multi-DUT scenarios.

        Args:
            results: Collection results dictionary.
            dut_ids: List of DUT IDs.
            collector_ids: List of collector IDs.
        """
        console = sanitized_console.console

        # Create summary table
        table = Table(title="Multi-DUT Collection Summary")
        table.add_column("DUT ID", style="cyan", no_wrap=True)
        table.add_column("Duration", style="yellow", no_wrap=True)
        table.add_column("Pass", style="green", no_wrap=True)
        table.add_column("Fail", style="red", no_wrap=True)
        table.add_column("Partial", style="yellow", no_wrap=True)
        table.add_column("Skipped", style="dim", no_wrap=True)
        table.add_column("Total", style="white", no_wrap=True)

        # Process results for each DUT
        for dut_id in dut_ids:
            # Count statuses for this DUT
            status_counts = {
                "pass": 0,
                "fail": 0,
                "partial": 0,
                "skipped": 0,
                "total": 0,
            }

            # Process sequential results
            sequential_results = results.get("sequential_results", {})
            for collector_id, collector_results in sequential_results.items():
                if dut_id in collector_results:
                    dut_result = collector_results[dut_id]
                    status = dut_result.get("status", "not_ran")
                    status_counts["total"] += 1

                    if status == "success":
                        status_counts["pass"] += 1
                    elif status == "error":
                        status_counts["fail"] += 1
                    elif status == "partial":
                        status_counts["partial"] += 1
                    elif status == "skipped":
                        status_counts["skipped"] += 1

            # Process parallel results
            parallel_results = results.get("parallel_results", {})
            for collector_id, collector_results in parallel_results.items():
                if dut_id in collector_results:
                    dut_result = collector_results[dut_id]
                    status = dut_result.get("status", "not_ran")
                    status_counts["total"] += 1

                    if status == "success":
                        status_counts["pass"] += 1
                    elif status == "error":
                        status_counts["fail"] += 1
                    elif status == "partial":
                        status_counts["partial"] += 1
                    elif status == "skipped":
                        status_counts["skipped"] += 1

            # Get actual wall-clock time from runtime logs instead of summing parallel times
            wall_clock_time = self._get_dut_wall_clock_time(dut_id)
            duration = f"{wall_clock_time:.1f}s" if wall_clock_time > 0 else "N/A"

            # Add row to table
            table.add_row(
                dut_id,
                duration,
                str(status_counts["pass"]),
                str(status_counts["fail"]),
                str(status_counts["partial"]),
                str(status_counts["skipped"]),
                str(status_counts["total"]),
            )

        # Display the table
        console.print(table)

        # Add summary statistics
        total_duts = len(dut_ids)
        total_collectors = len(collector_ids)
        console.print(
            f"\n[bold]Summary:[/bold] {total_duts} DUT(s) × {total_collectors} collector(s)"
        )
        console.print()

    async def _display_single_dut_summary(
        self,
        results: Dict[str, Any],
        dut_id: str,
        collector_ids: List[str],
    ) -> None:
        """
        Display detailed collector execution summary table for single DUT.

        Args:
            results: Collection results dictionary.
            dut_id: DUT ID.
            collector_ids: List of collector IDs.
        """
        console = sanitized_console.console

        # Create collector status table for this DUT
        table = Table(title=f"Collector Execution Summary - {dut_id}")
        table.add_column("Group", style="cyan", no_wrap=True)
        table.add_column("ID", style="magenta", no_wrap=True)
        table.add_column("Collector Name", style="green")
        table.add_column("Status", no_wrap=True)
        table.add_column("Execution Time", style="yellow", no_wrap=True)
        table.add_column("Reason", style="white", max_width=150, no_wrap=False)

        # Group collectors by service
        service_groups = {}
        for collector_id in collector_ids:
            collector_info = self.config_manager.get_collector_info(collector_id)
            group = collector_info.get("group", "unknown")
            if group not in service_groups:
                service_groups[group] = []
            service_groups[group].append(collector_id)

        # Only collectors that reached the execution stage are shown in the summary.
        # Pre-execution skips (baseboard constraints, config options) are excluded.

        # Process results for each service group for this DUT
        for group, group_collectors in service_groups.items():
            for collector_id in group_collectors:
                collector_info = self.config_manager.get_collector_info(collector_id)
                collector_name = collector_info.get("name", "Unknown")
                formatted_name = self._format_collector_name(collector_name)

                # Default: collector reached execution but no result recorded
                status = "not_ran"
                reason = "Collector not executed (likely due to preflight failure)"
                execution_time = 0.0

                # Check sequential results
                sequential_results = results.get("sequential_results", {})
                if (
                    collector_id in sequential_results
                    and dut_id in sequential_results[collector_id]
                ):
                    dut_result = sequential_results[collector_id][dut_id]
                    status = dut_result.get("status", "not_ran")
                    reason = dut_result.get("reason", "")
                    execution_time = dut_result.get("execution_time", 0.0)

                # Check parallel results
                parallel_results = results.get("parallel_results", {})
                if (
                    collector_id in parallel_results
                    and dut_id in parallel_results[collector_id]
                ):
                    dut_result = parallel_results[collector_id][dut_id]
                    status = dut_result.get("status", "not_ran")
                    reason = dut_result.get("reason", "")
                    execution_time = dut_result.get("execution_time", 0.0)

                # Color code the status using Rich Text
                status_color = (
                    "green"
                    if status == "success"
                    else (
                        "red"
                        if status == "error"
                        else "yellow" if status == "skipped" else "dim"
                    )
                )
                status_text = Text(status.upper(), style=status_color)

                # Format execution time
                exec_time = f"{execution_time:.2f}s" if execution_time > 0 else "N/A"

                # Sanitize the reason text before adding to table
                sanitized_reason = reason
                if (
                    hasattr(self, "orchestrator")
                    and hasattr(self.orchestrator, "sanitized_console")
                    and self.orchestrator.sanitized_console
                    and self.orchestrator.sanitized_console.sanitizer
                ):
                    sanitized_reason = (
                        self.orchestrator.sanitized_console.sanitizer.sanitize(reason)
                    )

                # Add row to table
                table.add_row(
                    group.title(),
                    collector_id,
                    formatted_name,
                    status_text,
                    exec_time,
                    sanitized_reason,  # Sanitized reason text with word wrapping
                )

        # Display the table
        console.print(table)
        console.print()  # Add spacing between DUT tables

    def _format_collector_name(self, name: str) -> str:
        """
        Format collector name from snake_case to Title Case.

        Args:
            name: Collector name to format.

        Returns:
            Formatted collector name with proper casing.
        """
        if not name or name == "Unknown":
            return name

        # Replace underscores with spaces and title case each word
        formatted = name.replace("_", " ").title()

        # Handle special cases for acronyms
        formatted = formatted.replace("Bmc", "BMC")
        formatted = formatted.replace("Ipmi", "IPMI")
        formatted = formatted.replace("Api", "API")
        formatted = formatted.replace("Cpu", "CPU")
        formatted = formatted.replace("Gpu", "GPU")
        formatted = formatted.replace("Pci", "PCI")
        formatted = formatted.replace("Usb", "USB")
        formatted = formatted.replace("Lan", "LAN")
        formatted = formatted.replace("Mc", "MC")

        return formatted

    async def log_single_collector_result(
        self, collector_id: str, dut_id: str, result: Dict[str, Any]
    ) -> None:
        """
        Log result for a single collector execution.

        Args:
            collector_id: Collector ID.
            dut_id: DUT ID.
            result: Execution result dictionary.
        """
        status = result.get("status", "unknown")
        reason = result.get("reason", "")
        execution_time = result.get("execution_time", 0.0)

        # Log to DUT runtime
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "ReportingEngine",
            f"Collector {collector_id}: {status} - {reason}",
        )

        # Create separate status.json file in collector directory
        await self.logger.write_collector_status_file(
            collector_id, dut_id, status, reason
        )

        # Update collector status in group metadata
        try:
            await self.logger._update_collector_status(
                dut_id, collector_id, status, reason, execution_time
            )
        except Exception as e:
            await self.logger.log_runtime(
                "WARN",
                "ReportingEngine",
                f"Failed to update collector status metadata for {collector_id} on {dut_id}: {e}",
            )

    async def log_all_results(
        self, results: Dict[str, Any], dut_ids: List[str]
    ) -> None:
        """
        Log all execution results for sequential and parallel collectors.

        Args:
            results: Dictionary of all collector results.
            dut_ids: List of DUT IDs.
        """
        # Process sequential results
        sequential_results = results.get("sequential_results", {})
        for collector_id, collector_results in sequential_results.items():
            for dut_id in dut_ids:
                if dut_id in collector_results:
                    await self.log_single_collector_result(
                        collector_id, dut_id, collector_results[dut_id]
                    )

        # Process parallel results
        parallel_results = results.get("parallel_results", {})
        for collector_id, collector_results in parallel_results.items():
            for dut_id in dut_ids:
                if dut_id in collector_results:
                    await self.log_single_collector_result(
                        collector_id, dut_id, collector_results[dut_id]
                    )

    async def log_preflight_results_table(
        self, preflight_results: Dict[str, Any]
    ) -> None:
        """
        Log preflight results table to console and DUT runtime logs.

        Args:
            preflight_results: Dictionary of preflight check results per DUT.
        """
        # Get all unique collector groups from the results
        all_groups = set()
        for dut_results in preflight_results.values():
            services = dut_results.get("services", {})
            all_groups.update(services.keys())

        # Sort groups for consistent display
        sorted_groups = sorted(all_groups)

        # Create the matrix-style table: DUT | Redfish | IPMI | SSH | Host | ...
        matrix_table = Table(title="Preflight Results Summary")
        matrix_table.add_column("DUT", style="cyan", width=20)

        # Add a column for each collector group
        for group in sorted_groups:
            matrix_table.add_column(group.title(), justify="center", width=10)

        # Create rows for each DUT
        failure_details = []  # Store failure details for the second table

        for dut_id, dut_results in preflight_results.items():
            services = dut_results.get("services", {})
            row_data = [dut_id]

            # Add status for each collector group
            for group in sorted_groups:
                service_result = services.get(group, {})
                status = service_result.get("status", "unknown")
                message = service_result.get("message", "")

                # Sanitize the message if sanitizer is available
                if (
                    hasattr(self, "orchestrator")
                    and self.orchestrator
                    and hasattr(self.orchestrator, "sanitizer")
                    and self.orchestrator.sanitizer
                ):
                    message = self.orchestrator.sanitizer.sanitize(message)

                # Color code the status using Rich Text objects
                if status == "pass":
                    status_text = Text("PASS", style="green")
                elif status == "fail":
                    status_text = Text("FAIL", style="red")
                    # Store failure details with status for color coding
                    failure_details.append((dut_id, group.title(), message, "fail"))
                elif status == "skip":
                    status_text = Text("SKIP", style="yellow")
                    # Store skip details with status for color coding
                    failure_details.append((dut_id, group.title(), message, "skip"))
                elif status == "interrupted":
                    status_text = Text("STOP", style="magenta")
                else:
                    status_text = Text("? UNK", style="yellow")

                row_data.append(status_text)

            matrix_table.add_row(*row_data)

        # Print matrix table to console
        console = Console(record=True, force_terminal=True)
        console.print(matrix_table)
        matrix_table_text = console.export_text()

        # Log matrix table to each DUT's runtime log
        if (
            hasattr(self, "orchestrator")
            and self.orchestrator
            and self.orchestrator.dut_manager
        ):
            for dut_id in self.orchestrator.dut_manager.get_all_dut_ids():
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "PreflightResults", matrix_table_text
                )

        # Create failure/skip details table if there are any failures or skips
        if failure_details:
            console.print("")  # Add spacing

            failure_table = Table(title="Preflight Failure/Skip Details")
            failure_table.add_column("DUT", style="cyan", width=20)
            failure_table.add_column("Service", style="cyan", width=12)
            failure_table.add_column("Failure/Skip Reason")

            for dut_id, service, reason, status in failure_details:
                # Color code the reason based on status
                if status == "skip":
                    reason_text = Text(reason, style="yellow")
                else:  # fail
                    reason_text = Text(reason, style="red")
                failure_table.add_row(dut_id, service, reason_text)

            console.print(failure_table)
            failure_table_text = console.export_text()

            # Log failure table to each DUT's runtime log
            if (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and self.orchestrator.dut_manager
            ):
                for dut_id in self.orchestrator.dut_manager.get_all_dut_ids():
                    await self.logger.write_to_dut_runtime_log(
                        dut_id, "INFO", "PreflightFailures", failure_table_text
                    )

    async def log_dependency_check_table(
        self, dependency_results: Dict[str, list]
    ) -> None:
        """
        Log dependency check results table to console and DUT runtime logs.

        Args:
            dependency_results: Dictionary mapping DUT ID to list of dicts with keys:
                'dependency', 'type', 'collector_id', 'collector_name', 'target'.
        """
        # Filter to only show DUTs with missing dependencies
        duts_with_missing = {
            dut_id: deps
            for dut_id, deps in dependency_results.items()
            if deps and len(deps) > 0
        }

        if not duts_with_missing:
            console = Console(record=True, force_terminal=True)
            console.print("")
            console.print(
                "[green]✓ Dependency Check: All required dependencies are available[/green]"
            )
            sys.stdout.flush()
            return

        console = Console(record=True, force_terminal=True)
        console.print("")

        for dut_id in sorted(duts_with_missing.keys()):
            missing_deps = duts_with_missing[dut_id]

            dep_table = Table(
                title=f"Missing Dependencies — {dut_id}",
                title_style="bold red",
                border_style="dim",
                show_lines=True,
                pad_edge=True,
            )
            dep_table.add_column("Dependency", style="red", min_width=20)
            dep_table.add_column("Type", style="yellow", min_width=10)
            dep_table.add_column("Checked On", style="magenta", min_width=8)
            dep_table.add_column("Collector", style="cyan", min_width=10)
            dep_table.add_column("Collector Name", style="dim", min_width=20)

            for dep in missing_deps:
                dep_table.add_row(
                    dep["dependency"],
                    dep["type"],
                    dep["target"],
                    dep["collector_id"],
                    dep["collector_name"],
                )

            console.print(dep_table)
            console.print("")

        sys.stdout.flush()
        dep_table_text = console.export_text()

        # Log dependency table to each DUT's runtime log
        if (
            hasattr(self, "orchestrator")
            and self.orchestrator
            and self.orchestrator.dut_manager
        ):
            for dut_id in self.orchestrator.dut_manager.get_all_dut_ids():
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "DependencyCheck", dep_table_text
                )

    async def log_preflight_results(self, preflight_results: Dict[str, Any]) -> None:
        """
        Log preflight results to metadata.

        Args:
            preflight_results: Dictionary of preflight results per DUT.
        """
        for dut_id, dut_results in preflight_results.items():
            await self.logger.write_preflight_metadata(dut_id, dut_results)

    async def create_dut_metadata_files(self) -> None:
        """
        Create metadata files for each DUT.

        Generates DUT-level metadata files with configuration and system information.
        """
        # Start timing for metadata creation
        if (
            hasattr(self, "orchestrator")
            and self.orchestrator
            and hasattr(self.orchestrator, "timing_manager")
            and self.orchestrator.timing_manager
        ):
            self.orchestrator.timing_manager.start_component("metadata_creation")
        dut_config = self.config_manager.get_dut_config()

        for dut_id, dut_config_data in dut_config.items():
            if dut_id == "DUT_Defaults":
                continue

            # Get platform detection results if available
            platform_info = None
            if hasattr(self, "orchestrator") and self.orchestrator:
                platform_info = await self.orchestrator.dut_manager.get_platform_info(
                    dut_id
                )

            # Create metadata for this DUT
            # Use detected model if available, otherwise fall back to baseboard from config
            detected_model = platform_info.get("model") if platform_info else None
            platform_model = (
                detected_model
                if detected_model and detected_model != "Unknown"
                else dut_config_data.get("baseboard", "Unknown")
            )

            metadata = {
                "PlatformModel": platform_model,
                "PartNumber": (
                    platform_info.get("partnumber", "Unknown")
                    if platform_info
                    else dut_config_data.get("part_number", "Unknown")
                ),
                "SerialNumber": (
                    platform_info.get("serialnumber", "Unknown")
                    if platform_info
                    else dut_config_data.get("serial_number", "Unknown")
                ),
                "Baseboard": dut_config_data.get("baseboard", "Unknown"),
                "DUT_ID": dut_id,
            }

            # Add timing data to metadata if available
            if (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "timing_manager")
            ):
                timing_summary = (
                    self.orchestrator.timing_manager.get_timing_summary_for_metadata()
                )
                if timing_summary:
                    metadata["timing_data"] = timing_summary

            # Write metadata file
            await self.logger.write_dut_metadata(dut_id, metadata)

        # End timing for metadata creation
        if (
            hasattr(self, "orchestrator")
            and self.orchestrator
            and hasattr(self.orchestrator, "timing_manager")
            and self.orchestrator.timing_manager
        ):
            self.orchestrator.timing_manager.end_component("metadata_creation")
