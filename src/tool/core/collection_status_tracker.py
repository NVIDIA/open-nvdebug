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
Collection Status Tracker.

This module provides real-time tracking of collector execution status across
multiple DUTs with in-memory state management and persistent file storage for
status information.
"""

import asyncio
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import aiofiles
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


class CollectorStatus(Enum):
    """
    Enumeration of collector status states.

    Attributes:
        PENDING: Collector is queued for execution.
        RUNNING: Collector is currently executing.
        SUCCESS: Collector completed successfully.
        PARTIAL: Collector completed with partial success.
        ERROR: Collector failed with error.
        SKIPPED: Collector was skipped.
        NOT_RAN: Collector did not run.
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_RAN = "not_ran"


@dataclass
class CollectorStatusEntry:
    """
    Data class for collector status entry.

    Attributes:
        dut_id: DUT identifier.
        collector_id: Collector identifier.
        collector_name: Collector name.
        group: Collector group.
    """

    dut_id: str
    collector_id: str
    collector_name: str
    group: str
    level: str
    status: CollectorStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    execution_time: float = 0.0
    timeout: Optional[int] = None
    reason: str = ""
    output_files: List[str] = None
    discovered_files: Dict[str, List[str]] = None
    context: Dict[str, Any] = None

    def __post_init__(self):
        """
        Initialize default values for optional fields after dataclass creation.
        """
        if self.output_files is None:
            self.output_files = []
        if self.discovered_files is None:
            self.discovered_files = {}
        if self.context is None:
            self.context = {}

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert collector status entry to dictionary for JSON serialization.

        Returns:
            Dictionary representation excluding context to prevent recursion.
        """
        # Manually create dict to avoid recursion issues with complex context objects
        data = {
            "dut_id": self.dut_id,
            "collector_id": self.collector_id,
            "collector_name": self.collector_name,
            "group": self.group,
            "level": self.level,
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "execution_time": self.execution_time,
            "timeout": self.timeout,
            "reason": self.reason,
            "output_files": (
                self.output_files[:] if self.output_files else []
            ),  # shallow copy
            "discovered_files": (
                dict(self.discovered_files) if self.discovered_files else {}
            ),  # shallow copy
            # Exclude context to prevent recursion - it can contain complex objects
            # "context": self.context,  # Skip this to avoid recursion
        }
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CollectorStatusEntry":
        """
        Create collector status entry from dictionary.

        Args:
            data: Dictionary representation of status entry.

        Returns:
            CollectorStatusEntry instance.
        """
        data["status"] = CollectorStatus(data["status"])
        if data.get("start_time"):
            data["start_time"] = datetime.fromisoformat(data["start_time"])
        if data.get("end_time"):
            data["end_time"] = datetime.fromisoformat(data["end_time"])
        return cls(**data)


class CollectionStatusTracker:
    """
    Tracks collection status across multiple DUTs with async-safe operations.

    Manages real-time status tracking, file storage, and statistics aggregation
    for collector execution across multiple DUTs.
    """

    def __init__(
        self, output_dir: Path, console: Optional[Console] = None, logger=None
    ):
        self.output_dir = output_dir
        self.logger = logger

        # Ensure we have a valid Rich Console
        if console is not None and hasattr(console, "print"):
            self.console = console
        else:
            # Create a new console if the provided one is invalid
            try:
                self.console = Console()
            except Exception:
                # Fallback to a minimal console if Rich is not available
                self.console = None

        # Global status files (in root .metadata directory)
        self.metadata_dir = output_dir / ".metadata"
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        self.global_status_file = self.metadata_dir / "collection_status.json"
        self.global_summary_file = self.metadata_dir / "collection_status_summary.txt"

        # DUT-specific status files (will be created per DUT)
        self.dut_status_files: Dict[str, Path] = {}  # dut_id -> status file path
        self.dut_summary_files: Dict[str, Path] = {}  # dut_id -> summary file path

        # In-memory state
        self.collector_statuses: Dict[str, CollectorStatusEntry] = (
            {}
        )  # key: f"{dut_id}:{collector_id}"
        self.dut_collectors: Dict[str, Set[str]] = {}  # DUT -> set of collector IDs
        self.collector_groups: Dict[str, Set[str]] = {}  # group -> set of collector IDs

        # Statistics
        self.stats = {
            "total_collectors": 0,
            "pending_collectors": 0,
            "running_collectors": 0,
            "completed_collectors": 0,
            "partial_collectors": 0,
            "failed_collectors": 0,
            "skipped_collectors": 0,
        }

        # File lock for async-safe operations
        self._file_lock = asyncio.Lock()

        # Live display
        self._live_display: Optional[Live] = None
        self._display_enabled = False

    async def initialize_collection(
        self, dut_ids: List[str], collector_ids: List[str], config_manager: Any
    ) -> None:
        """
        Initialize collection tracking for given DUTs and collectors.

        Creates status entries for all DUT-collector combinations and initializes
        status files.

        Args:
            dut_ids: List of DUT IDs.
            collector_ids: List of collector IDs.
            config_manager: Configuration manager instance.
        """
        self.stats["total_collectors"] = len(dut_ids) * len(collector_ids)
        self.stats["pending_collectors"] = self.stats["total_collectors"]

        # Create DUT-specific status file paths
        for dut_id in dut_ids:
            dut_dir = self.output_dir / dut_id
            dut_metadata_dir = dut_dir / ".metadata"
            dut_metadata_dir.mkdir(parents=True, exist_ok=True)

            # JSON status file goes in .metadata (structured data)
            self.dut_status_files[dut_id] = dut_metadata_dir / "collection_status.json"
            # Summary file goes directly in DUT folder (human-readable, easily accessible)
            self.dut_summary_files[dut_id] = dut_dir / "collection_status_summary.txt"

        # Initialize status entries for all DUT-collector combinations
        for dut_id in dut_ids:
            self.dut_collectors[dut_id] = set()

            for collector_id in collector_ids:
                collector_info = config_manager.get_collector_info(collector_id)
                collector_name = collector_info.get("name", "Unknown")
                group = collector_info.get("group", "Unknown")
                level = collector_info.get("collection_level", "L1")

                # Get timeout from collector definition
                timeout = collector_info.get("timeout", None)

                status_entry = CollectorStatusEntry(
                    dut_id=dut_id,
                    collector_id=collector_id,
                    collector_name=collector_name,
                    group=group,
                    level=level,
                    status=CollectorStatus.PENDING,
                    timeout=timeout,
                )

                key = f"{dut_id}:{collector_id}"
                self.collector_statuses[key] = status_entry
                self.dut_collectors[dut_id].add(collector_id)

                if group not in self.collector_groups:
                    self.collector_groups[group] = set()
                self.collector_groups[group].add(key)

        # Save initial status (both global and DUT-specific)
        await self._save_global_status_file()
        await self._save_global_summary_file()
        await self._save_dut_status_files()

        # Debug logging
        for dut_id in dut_ids:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "CollectionStatusTracker",
                f"Initialized collection with {len(dut_ids)} DUTs and {len(collector_ids)} collectors",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "CollectionStatusTracker",
                f"Initial stats: {self.stats}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "CollectionStatusTracker",
                f"Collector statuses keys: {list(self.collector_statuses.keys())}",
            )

        # Start live display if enabled
        if self._display_enabled:
            await self._start_live_display()

    async def start_collector(self, dut_id: str, collector_id: str) -> None:
        """
        Mark a collector as started/running.

        Args:
            dut_id: DUT ID.
            collector_id: Collector ID.
        """
        key = f"{dut_id}:{collector_id}"
        if key in self.collector_statuses:
            entry = self.collector_statuses[key]

            # Update stats before changing status
            if entry.status == CollectorStatus.PENDING:
                self.stats["pending_collectors"] -= 1

            entry.status = CollectorStatus.RUNNING
            entry.start_time = datetime.now()
            self.stats["running_collectors"] += 1

            # Debug logging
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "CollectionStatusTracker",
                f"Started {dut_id}:{collector_id}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "CollectionStatusTracker",
                f"Stats after start: {self.stats}",
            )

            await self._update_status()

    async def complete_collector(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str = "",
        execution_time: float = 0.0,
        output_files: Optional[List[str]] = None,
        discovered_files: Optional[Dict[str, List[str]]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Mark a collector as completed with final status.

        Args:
            dut_id: DUT ID.
            collector_id: Collector ID.
            status: Completion status ('success', 'partial', 'error', 'skipped').
            reason: Reason for the status.
            execution_time: Execution time in seconds.
            output_files: List of output file paths.
            discovered_files: Dictionary of discovered files by type.
            context: Additional context information.
        """
        key = f"{dut_id}:{collector_id}"
        if key in self.collector_statuses:
            entry = self.collector_statuses[key]

            # Check if collector is already completed - allow status updates if status changes
            if entry.status not in [CollectorStatus.PENDING, CollectorStatus.RUNNING]:
                # Map the new status to enum for comparison
                new_status_enum = None
                if status in ["success", "pass", True]:
                    new_status_enum = CollectorStatus.SUCCESS
                elif status in ["partial"]:
                    new_status_enum = CollectorStatus.PARTIAL
                elif status in ["error", "fail", False]:
                    new_status_enum = CollectorStatus.ERROR
                elif status in ["skipped", "not_ran"]:
                    new_status_enum = CollectorStatus.SKIPPED
                else:
                    new_status_enum = CollectorStatus.ERROR

                # If the status is the same, skip duplicate completion
                if entry.status == new_status_enum:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "CollectionStatusTracker",
                        f"Skipping duplicate completion for {dut_id}:{collector_id} - already completed with status {entry.status.name.lower()}",
                    )
                    return
                else:
                    # Status is changing, allow the update and adjust stats
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "CollectionStatusTracker",
                        f"Updating status for {dut_id}:{collector_id} from {entry.status.name.lower()} to {new_status_enum.name.lower()}",
                    )
                    # Decrement the old status count
                    if entry.status == CollectorStatus.SUCCESS:
                        self.stats["completed_collectors"] -= 1
                    elif entry.status == CollectorStatus.PARTIAL:
                        self.stats["partial_collectors"] -= 1
                    elif entry.status == CollectorStatus.ERROR:
                        self.stats["failed_collectors"] -= 1
                    elif entry.status == CollectorStatus.SKIPPED:
                        self.stats["skipped_collectors"] -= 1

            # Track previous status for stats update
            previous_status = entry.status

            # Map status to enum and update stats (we know this is the first completion)
            if status in ["success", "pass", True]:
                entry.status = CollectorStatus.SUCCESS
                self.stats["completed_collectors"] += 1
            elif status in ["partial"]:
                entry.status = CollectorStatus.PARTIAL
                self.stats["partial_collectors"] += 1
            elif status in ["error", "fail", False]:
                entry.status = CollectorStatus.ERROR
                self.stats["failed_collectors"] += 1
            elif status in ["skipped", "not_ran"]:
                entry.status = CollectorStatus.SKIPPED
                self.stats["skipped_collectors"] += 1
            else:
                entry.status = CollectorStatus.ERROR
                self.stats["failed_collectors"] += 1

            # Debug logging for completion
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "CollectionStatusTracker",
                f"Completed {dut_id}:{collector_id} with status '{status}' -> {entry.status.name.lower()}, previous: {previous_status.name.lower() if previous_status else 'None'}",
            )

            entry.end_time = datetime.now()
            entry.execution_time = execution_time
            entry.reason = reason
            if output_files:
                entry.output_files = output_files
            if discovered_files:
                entry.discovered_files = discovered_files
            if context:
                entry.context = context

            # Update running stats based on previous status
            if previous_status == CollectorStatus.RUNNING:
                self.stats["running_collectors"] -= 1
            elif previous_status == CollectorStatus.PENDING:
                self.stats["pending_collectors"] -= 1

            # (Debug logging already added above with more detail)
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "CollectionStatusTracker",
                f"Stats after completion: {self.stats}",
            )

            await self._update_status()

    async def _update_status(self) -> None:
        """
        Update all status files and live display.
        """
        await self._save_global_status_file()
        await self._save_global_summary_file()
        await self._save_dut_status_files()
        await self._save_dut_summary_files()

        if self._display_enabled and self._live_display:
            try:
                self._live_display.update(self._generate_status_table())
            except Exception:
                # If live display update fails, disable it
                self._live_display = None
                self._display_enabled = False

    async def _save_global_status_file(self) -> None:
        """
        Save detailed global status to JSON file in .metadata directory.
        """
        async with self._file_lock:
            try:
                status_data = {
                    "metadata": {
                        "last_updated": datetime.now().isoformat(),
                        "stats": self.stats,
                        "total_duts": len(self.dut_collectors),
                        "total_collectors": len(self.collector_statuses),
                    },
                    "collectors": {
                        key: entry.to_dict()
                        for key, entry in self.collector_statuses.items()
                    },
                }

                async with aiofiles.open(self.global_status_file, "w") as f:
                    await f.write(json.dumps(status_data, indent=2))
            except Exception as e:
                # Log error but don't fail
                print(f"Warning: Failed to save global status file: {e}")

    async def _save_dut_status_files(self) -> None:
        """
        Save DUT-specific status files to JSON.
        """
        async with self._file_lock:
            for dut_id in self.dut_collectors.keys():
                try:
                    # Get collectors for this DUT
                    dut_collectors = {
                        key: entry.to_dict()
                        for key, entry in self.collector_statuses.items()
                        if key.startswith(f"{dut_id}:")
                    }

                    dut_stats = self._get_dut_stats(dut_id)

                    dut_status_data = {
                        "metadata": {
                            "dut_id": dut_id,
                            "last_updated": datetime.now().isoformat(),
                            "stats": dut_stats,
                            "total_collectors": len(dut_collectors),
                        },
                        "collectors": dut_collectors,
                    }

                    status_file = self.dut_status_files.get(dut_id)
                    if status_file:
                        async with aiofiles.open(status_file, "w") as f:
                            await f.write(json.dumps(dut_status_data, indent=2))

                except Exception as e:
                    # Log error but don't fail
                    print(f"Warning: Failed to save DUT status file for {dut_id}: {e}")

    async def _save_global_summary_file(self) -> None:
        """
        Save human-readable global summary to text file in .metadata directory.
        """
        async with self._file_lock:
            try:
                summary_lines = []
                summary_lines.append("Global Collection Status Summary")
                summary_lines.append("=" * 50)
                summary_lines.append(
                    f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                summary_lines.append("")

                # Overall statistics
                summary_lines.append("Overall Statistics:")
                summary_lines.append(
                    f"  Total Collectors: {self.stats['total_collectors']}"
                )
                summary_lines.append(f"  Pending: {self.stats['pending_collectors']}")
                summary_lines.append(f"  Running: {self.stats['running_collectors']}")
                summary_lines.append(
                    f"  Completed: {self.stats['completed_collectors']}"
                )
                summary_lines.append(f"  Failed: {self.stats['failed_collectors']}")
                summary_lines.append(f"  Skipped: {self.stats['skipped_collectors']}")
                summary_lines.append("")

                # Progress percentage
                if self.stats["total_collectors"] > 0:
                    completed = (
                        self.stats["completed_collectors"]
                        + self.stats["failed_collectors"]
                        + self.stats["skipped_collectors"]
                    )
                    progress = (completed / self.stats["total_collectors"]) * 100
                    summary_lines.append(
                        f"Progress: {progress:.1f}% ({completed}/{self.stats['total_collectors']})"
                    )
                    summary_lines.append("")

                # Status by DUT
                summary_lines.append("Status by DUT:")
                for dut_id in sorted(self.dut_collectors.keys()):
                    dut_stats = self._get_dut_stats(dut_id)
                    summary_lines.append(f"  {dut_id}:")
                    summary_lines.append(f"    Total: {dut_stats['total']}")
                    summary_lines.append(f"    Completed: {dut_stats['completed']}")
                    summary_lines.append(f"    Failed: {dut_stats['failed']}")
                    summary_lines.append(f"    Skipped: {dut_stats['skipped']}")
                    summary_lines.append(f"    Running: {dut_stats['running']}")
                    summary_lines.append(f"    Pending: {dut_stats['pending']}")
                    summary_lines.append("")

                # Recent activity (last 10 completed)
                recent_entries = [
                    entry
                    for entry in self.collector_statuses.values()
                    if entry.status
                    in [
                        CollectorStatus.SUCCESS,
                        CollectorStatus.ERROR,
                        CollectorStatus.SKIPPED,
                    ]
                    and entry.end_time
                ]
                recent_entries.sort(key=lambda x: x.end_time, reverse=True)

                if recent_entries:
                    summary_lines.append("Recent Activity (Last 10):")
                    summary_lines.append("")

                    # Create table header
                    summary_lines.append(
                        f"{'DUT':<15} {'Collector':<12} {'Status':<12} {'Group':<10} {'Level':<6} {'End Time':<10} {'Duration':<10}"
                    )
                    summary_lines.append("-" * 90)

                    # Add table rows
                    for entry in recent_entries[:10]:
                        status_icon = (
                            "✓"
                            if entry.status == CollectorStatus.SUCCESS
                            else "✗" if entry.status == CollectorStatus.ERROR else "○"
                        )

                        # Calculate duration
                        duration_str = "N/A"
                        if entry.start_time and entry.end_time:
                            duration = (
                                entry.end_time - entry.start_time
                            ).total_seconds()
                            duration_str = f"{duration:.1f}s"
                        elif entry.execution_time > 0:
                            duration_str = f"{entry.execution_time:.1f}s"

                        # Combine status icon and text
                        status_with_icon = f"{status_icon} {entry.status.value}"

                        summary_lines.append(
                            f"{entry.dut_id:<15} {entry.collector_id:<12} {status_with_icon:<12} {entry.group:<10} {entry.level:<6} {entry.end_time.strftime('%H:%M:%S'):<10} {duration_str:<10}"
                        )
                    summary_lines.append("")

                async with aiofiles.open(self.global_summary_file, "w") as f:
                    await f.write("\n".join(summary_lines))

            except Exception as e:
                # Log error but don't fail
                print(f"Warning: Failed to save global summary file: {e}")

    async def _save_dut_summary_files(self) -> None:
        """
        Save DUT-specific human-readable summary files.
        """
        async with self._file_lock:
            for dut_id in self.dut_collectors.keys():
                try:
                    dut_stats = self._get_dut_stats(dut_id)

                    summary_lines = []
                    summary_lines.append(f"Collection Status Summary - {dut_id}")
                    summary_lines.append("=" * 50)
                    summary_lines.append(
                        f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    summary_lines.append("")

                    # DUT statistics
                    summary_lines.append(f"Statistics for {dut_id}:")
                    summary_lines.append(f"  Total Collectors: {dut_stats['total']}")
                    summary_lines.append(f"  Pending: {dut_stats['pending']}")
                    summary_lines.append(f"  Running: {dut_stats['running']}")
                    summary_lines.append(f"  Completed: {dut_stats['completed']}")
                    summary_lines.append(f"  Failed: {dut_stats['failed']}")
                    summary_lines.append(f"  Skipped: {dut_stats['skipped']}")
                    summary_lines.append("")

                    # Progress percentage for this DUT
                    if dut_stats["total"] > 0:
                        completed = (
                            dut_stats["completed"]
                            + dut_stats["failed"]
                            + dut_stats["skipped"]
                        )
                        progress = (completed / dut_stats["total"]) * 100
                        summary_lines.append(
                            f"Progress: {progress:.1f}% ({completed}/{dut_stats['total']})"
                        )
                        summary_lines.append("")

                    # Collectors for this DUT
                    dut_entries = [
                        entry
                        for key, entry in self.collector_statuses.items()
                        if key.startswith(f"{dut_id}:")
                    ]

                    if dut_entries:
                        summary_lines.append("Collectors:")
                        summary_lines.append("")

                        # Create table header
                        summary_lines.append(
                            f"{'ID':<8} {'Status':<12} {'Group':<10} {'Level':<6} {'Start Time':<10} {'End Time':<10} {'Duration':<10} {'Timeout':<8} {'Systems':<15} {'Reason'}"
                        )
                        summary_lines.append("-" * 113)

                        # Add table rows
                        for entry in sorted(dut_entries, key=lambda x: x.collector_id):
                            status_icon = (
                                "✓"
                                if entry.status == CollectorStatus.SUCCESS
                                else (
                                    "✗"
                                    if entry.status == CollectorStatus.ERROR
                                    else (
                                        "○"
                                        if entry.status == CollectorStatus.SKIPPED
                                        else (
                                            "▶"
                                            if entry.status == CollectorStatus.RUNNING
                                            else "⏳"
                                        )
                                    )
                                )
                            )
                            start_time_str = (
                                entry.start_time.strftime("%H:%M:%S")
                                if entry.start_time
                                else "N/A"
                            )
                            end_time_str = (
                                entry.end_time.strftime("%H:%M:%S")
                                if entry.end_time
                                else "N/A"
                            )

                            # Calculate duration
                            duration_str = "N/A"
                            if entry.start_time and entry.end_time:
                                duration = (
                                    entry.end_time - entry.start_time
                                ).total_seconds()
                                duration_str = f"{duration:.1f}s"
                            elif entry.execution_time > 0:
                                duration_str = f"{entry.execution_time:.1f}s"

                            # Use full reason without truncation
                            reason = entry.reason

                            # Use text-only status
                            status_with_icon = entry.status.value.upper()

                            # Extract timeout information
                            timeout_str = (
                                f"{entry.timeout}s" if entry.timeout else "N/A"
                            )

                            # Extract systems information from context if available
                            systems_info = "N/A"
                            if hasattr(entry, "context") and entry.context:
                                if "filtered_systems" in entry.context:
                                    systems = [
                                        sys.get("id", "unknown")
                                        for sys in entry.context["filtered_systems"]
                                    ]
                                    systems_info = ", ".join(
                                        systems[:3]
                                    )  # Show first 3 systems
                                    if len(systems) > 3:
                                        systems_info += f" (+{len(systems)-3})"
                                elif "entities_processed" in entry.context:
                                    systems_info = f"{entry.context['entities_processed']} entities"
                                elif "successful_collections" in entry.context:
                                    systems_info = f"{entry.context['successful_collections']} successful"

                            summary_lines.append(
                                f"{entry.collector_id:<8} {status_with_icon:<12} {entry.group:<10} {entry.level:<6} {start_time_str:<10} {end_time_str:<10} {duration_str:<10} {timeout_str:<8} {systems_info:<15} {reason}"
                            )

                        summary_lines.append("")

                    summary_file = self.dut_summary_files.get(dut_id)
                    if summary_file:
                        async with aiofiles.open(summary_file, "w") as f:
                            await f.write("\n".join(summary_lines))

                except Exception as e:
                    # Log error but don't fail
                    print(f"Warning: Failed to save DUT summary file for {dut_id}: {e}")

    async def _save_dut_timing_files(self) -> None:
        """
        Save DUT-specific timing.json files with granular timing data.
        """
        async with self._file_lock:
            for dut_id in self.dut_collectors.keys():
                try:
                    # Get all entries for this DUT
                    dut_entries = [
                        entry
                        for key, entry in self.collector_statuses.items()
                        if key.startswith(f"{dut_id}:")
                    ]

                    if not dut_entries:
                        continue

                    # Calculate overall timing
                    start_times = [e.start_time for e in dut_entries if e.start_time]
                    end_times = [e.end_time for e in dut_entries if e.end_time]

                    overall_start = min(start_times) if start_times else None
                    overall_end = max(end_times) if end_times else None
                    wall_clock_duration = (
                        (overall_end - overall_start).total_seconds()
                        if overall_start is not None and overall_end is not None
                        else 0.0
                    )

                    # Get DUT stats
                    dut_stats = self._get_dut_stats(dut_id)

                    # Build collectors timing data
                    collectors_timing = {}
                    for entry in dut_entries:
                        collector_data = {
                            "collector_id": entry.collector_id,
                            "collector_name": entry.collector_name,
                            "group": entry.group,
                            "level": entry.level,
                            "status": entry.status.value,
                            "start_time": (
                                entry.start_time.isoformat()
                                if entry.start_time
                                else None
                            ),
                            "end_time": (
                                entry.end_time.isoformat() if entry.end_time else None
                            ),
                            "duration_seconds": (
                                entry.execution_time
                                if entry.execution_time > 0
                                else (
                                    (entry.end_time - entry.start_time).total_seconds()
                                    if entry.start_time and entry.end_time
                                    else 0.0
                                )
                            ),
                            "timeout_seconds": entry.timeout,
                            "reason": entry.reason if entry.reason else None,
                        }
                        collectors_timing[entry.collector_id] = collector_data

                    # Build service-level timing aggregation
                    by_service = {}
                    for entry in dut_entries:
                        service = entry.group
                        if service not in by_service:
                            by_service[service] = {
                                "total_collectors": 0,
                                "completed": 0,
                                "failed": 0,
                                "partial": 0,
                                "skipped": 0,
                                "total_duration_seconds": 0.0,
                                "collectors": [],
                            }

                        by_service[service]["total_collectors"] += 1
                        by_service[service]["collectors"].append(entry.collector_id)

                        # Count by status
                        if entry.status == CollectorStatus.SUCCESS:
                            by_service[service]["completed"] += 1
                        elif entry.status == CollectorStatus.ERROR:
                            by_service[service]["failed"] += 1
                        elif entry.status == CollectorStatus.PARTIAL:
                            by_service[service]["partial"] += 1
                        elif entry.status == CollectorStatus.SKIPPED:
                            by_service[service]["skipped"] += 1

                        # Add duration (only for completed collectors)
                        if entry.execution_time > 0:
                            by_service[service][
                                "total_duration_seconds"
                            ] += entry.execution_time
                        elif entry.start_time and entry.end_time:
                            duration = (
                                entry.end_time - entry.start_time
                            ).total_seconds()
                            by_service[service]["total_duration_seconds"] += duration

                    # Build timing.json structure
                    timing_data = {
                        "dut_id": dut_id,
                        "generated_at": datetime.now().isoformat(),
                        "overall": {
                            "start_time": (
                                overall_start.isoformat() if overall_start else None
                            ),
                            "end_time": (
                                overall_end.isoformat() if overall_end else None
                            ),
                            "wall_clock_duration_seconds": round(
                                wall_clock_duration, 2
                            ),
                            "total_collectors": dut_stats["total"],
                            "completed": dut_stats["completed"],
                            "failed": dut_stats["failed"],
                            "skipped": dut_stats["skipped"],
                            "pending": dut_stats["pending"],
                            "running": dut_stats["running"],
                        },
                        "collectors": collectors_timing,
                        "by_service": by_service,
                    }

                    # Write to DUT's .metadata/timing.json
                    dut_metadata_dir = self.output_dir / dut_id / ".metadata"
                    dut_metadata_dir.mkdir(parents=True, exist_ok=True)
                    timing_file = dut_metadata_dir / "timing.json"

                    async with aiofiles.open(timing_file, "w") as f:
                        await f.write(json.dumps(timing_data, indent=2))

                except Exception as e:
                    # Log error but don't fail
                    print(f"Warning: Failed to save timing file for {dut_id}: {e}")

    def _get_dut_stats(self, dut_id: str) -> Dict[str, int]:
        """
        Get statistics for a specific DUT.

        Args:
            dut_id: DUT ID.

        Returns:
            Dictionary of statistics (total, completed, failed, skipped, running, pending).
        """
        stats = {
            "total": 0,
            "completed": 0,
            "failed": 0,
            "skipped": 0,
            "running": 0,
            "pending": 0,
        }

        for collector_id in self.dut_collectors.get(dut_id, []):
            key = f"{dut_id}:{collector_id}"
            if key in self.collector_statuses:
                entry = self.collector_statuses[key]
                stats["total"] += 1

                # Map status values to stats keys
                if entry.status == CollectorStatus.SUCCESS:
                    stats["completed"] += 1
                elif entry.status == CollectorStatus.ERROR:
                    stats["failed"] += 1
                elif entry.status == CollectorStatus.SKIPPED:
                    stats["skipped"] += 1
                elif entry.status == CollectorStatus.RUNNING:
                    stats["running"] += 1
                elif entry.status == CollectorStatus.PENDING:
                    stats["pending"] += 1

        return stats

    def _generate_status_table(self) -> Table:
        """
        Generate Rich table for live display.

        Returns:
            Rich Table with collection status information.
        """
        table = Table(title="Collection Status")
        table.add_column("DUT", style="cyan", no_wrap=True)
        table.add_column("Collector", style="green")
        table.add_column("Group", style="blue")
        table.add_column("Level", style="yellow")
        table.add_column("Status", style="white")
        table.add_column("Time", style="magenta")
        table.add_column("Progress", style="white")

        # Add overall progress row
        if self.stats["total_collectors"] > 0:
            completed = (
                self.stats["completed_collectors"]
                + self.stats["failed_collectors"]
                + self.stats["skipped_collectors"]
            )
            progress = (completed / self.stats["total_collectors"]) * 100
            table.add_row(
                "ALL",
                f"{completed}/{self.stats['total_collectors']}",
                "Overall",
                "",
                f"{progress:.1f}%",
                f"{progress:.1f}%",
                f"[{'█' * int(progress/10)}{'░' * (10-int(progress/10))}]",
            )

        # Add recent entries (last 10)
        recent_entries = [
            entry
            for entry in self.collector_statuses.values()
            if entry.status
            in [
                CollectorStatus.SUCCESS,
                CollectorStatus.ERROR,
                CollectorStatus.SKIPPED,
                CollectorStatus.RUNNING,
            ]
        ]
        recent_entries.sort(
            key=lambda x: x.end_time or x.start_time or datetime.min, reverse=True
        )

        for entry in recent_entries[:10]:
            status_color = {
                CollectorStatus.SUCCESS: "green",
                CollectorStatus.ERROR: "red",
                CollectorStatus.SKIPPED: "yellow",
                CollectorStatus.RUNNING: "blue",
                CollectorStatus.PENDING: "white",
            }.get(entry.status, "white")

            time_str = ""
            if entry.end_time:
                time_str = entry.end_time.strftime("%H:%M:%S")
            elif entry.start_time:
                time_str = f"Started {entry.start_time.strftime('%H:%M:%S')}"

            table.add_row(
                entry.dut_id,
                entry.collector_id,
                entry.group,
                entry.level,
                f"[{status_color}]{entry.status.value}[/{status_color}]",
                time_str,
                "",
            )

        return table

    async def enable_live_display(self) -> None:
        """
        Enable live display of collection status.
        """
        self._display_enabled = True
        if self.collector_statuses:  # Only start if already initialized
            await self._start_live_display()

    async def _start_live_display(self) -> None:
        """
        Start the Rich live display.
        """
        if self._live_display is None and self.console is not None:
            try:
                self._live_display = Live(
                    self._generate_status_table(),
                    console=self.console,
                    refresh_per_second=2,
                )
                self._live_display.start()
            except Exception:
                # If live display fails, just disable it
                self._live_display = None
                self._display_enabled = False

    async def stop_live_display(self) -> None:
        """
        Stop the Rich live display.
        """
        if self._live_display:
            self._live_display.stop()
            self._live_display = None
            # Force multiple newlines after stopping the live display to ensure proper spacing
            if self.console:
                self.console.print("\n")  # Force a newline using console.print()

    async def get_status_summary(self) -> Dict[str, Any]:
        """
        Get current status summary with statistics and recent activity.

        Returns:
            Dictionary containing stats, per-DUT stats, and recent activity.
        """
        return {
            "stats": self.stats.copy(),
            "dut_stats": {
                dut_id: self._get_dut_stats(dut_id)
                for dut_id in self.dut_collectors.keys()
            },
            "recent_activity": [
                entry.to_dict()
                for entry in sorted(
                    [e for e in self.collector_statuses.values() if e.end_time],
                    key=lambda x: x.end_time,
                    reverse=True,
                )[:10]
            ],
        }

    async def _mark_remaining_pending_as_skipped(self) -> None:
        """
        Mark any collectors that are still PENDING as SKIPPED.

        This handles collectors that were in the initial list but never executed
        because they were filtered out without being explicitly marked as skipped.
        """
        pending_collectors = [
            (key, entry)
            for key, entry in self.collector_statuses.items()
            if entry.status == CollectorStatus.PENDING
        ]

        if pending_collectors:
            await self.logger.log_runtime(
                "DEBUG",
                "CollectionStatusTracker",
                f"Found {len(pending_collectors)} collectors still in PENDING status at finalization. Marking as SKIPPED.",
            )

            for key, entry in pending_collectors:
                # Mark as skipped
                entry.status = CollectorStatus.SKIPPED
                entry.end_time = datetime.now()
                entry.reason = "Collector was filtered out and not executed"

                # Update stats
                self.stats["pending_collectors"] -= 1
                self.stats["skipped_collectors"] += 1

                await self.logger.write_to_dut_runtime_log(
                    entry.dut_id,
                    "DEBUG",
                    "CollectionStatusTracker",
                    f"Marked {entry.collector_id} as SKIPPED at finalization (was PENDING)",
                )

    async def finalize(self) -> None:
        """
        Finalize the tracker, save final status, and print summary.
        """
        await self.stop_live_display()

        # Mark any remaining PENDING collectors as SKIPPED
        # This handles collectors that were filtered out but not explicitly marked
        await self._mark_remaining_pending_as_skipped()

        await self._save_global_status_file()
        await self._save_global_summary_file()
        await self._save_dut_status_files()
        await self._save_dut_summary_files()
        await self._save_dut_timing_files()

        # Print final summary
        if self.console:
            try:
                # Force a minimal character to ensure proper newline rendering
                # self.console.print(
                #     "[dim]·[/dim]"
                # )
                # Print a dimmed dot to force newline
                self.console.print(
                    Panel(
                        f"Collection Complete!\n"
                        f"Total: {self.stats['total_collectors']} | "
                        f"Completed: {self.stats['completed_collectors']} | "
                        f"Failed: {self.stats['failed_collectors']} | "
                        f"Partial: {self.stats['partial_collectors']} | "
                        f"Skipped: {self.stats['skipped_collectors']}",
                        title="Final Summary",
                        border_style="green",
                    )
                )
            except Exception:
                # If console printing fails, just skip it
                pass
