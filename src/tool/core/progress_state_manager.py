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
Progress State Manager for NVDebug Tool.

Tracks progress and timing information across all DUTs and collectors with
thread-safe state management for concurrent operations.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class CollectorStatus(Enum):
    """
    Status of a collector.

    Attributes:
        PENDING: Collector is queued.
        RUNNING: Collector is executing.
        COMPLETED: Collector finished successfully.
        PARTIAL: Collector completed partially.
        SKIPPED: Collector was skipped.
        FAILED: Collector failed.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class CollectorProgress:
    """
    Progress tracking for a single collector.

    Attributes:
        collector_id (str): Collector identifier.
        dut_id (str): DUT identifier.
        status (CollectorStatus): Current status.
        start_time (Optional[datetime]): Start timestamp.
        end_time (Optional[datetime]): End timestamp.
        execution_time (float): Execution duration in seconds.
        reason (str): Status reason or error message.
    """

    collector_id: str
    dut_id: str
    status: CollectorStatus = CollectorStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    execution_time: float = 0.0
    reason: str = ""

    @property
    def is_completed(self) -> bool:
        """
        Check if collector is completed (success, partial, skipped, or failed).

        Returns:
            bool: True if collector has finished execution.
        """
        return self.status in [
            CollectorStatus.COMPLETED,
            CollectorStatus.PARTIAL,
            CollectorStatus.SKIPPED,
            CollectorStatus.FAILED,
        ]

    @property
    def duration(self) -> float:
        """
        Get duration in seconds.

        Returns:
            Duration in seconds, or 0 if not completed.
        """
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.now() - self.start_time).total_seconds()
        return 0.0


@dataclass
class DUTProgress:
    """
    Progress tracking for a single DUT.

    Attributes:
        dut_id: DUT identifier.
        total_collectors: Total number of collectors.
        completed_collectors: Set of completed collector IDs.
        partial_collectors: Set of partially completed collector IDs.
        failed_collectors: Set of failed collector IDs.
        skipped_collectors: Set of skipped collector IDs.
        running_collectors: Set of currently running collector IDs.
        start_time: Collection start time.
        end_time: Collection end time.
        current_service: Currently executing service.
        current_bucket: Currently executing bucket.
    """

    dut_id: str
    total_collectors: int
    completed_collectors: Set[str] = field(default_factory=set)
    partial_collectors: Set[str] = field(default_factory=set)
    failed_collectors: Set[str] = field(default_factory=set)
    skipped_collectors: Set[str] = field(default_factory=set)
    running_collectors: Set[str] = field(default_factory=set)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    current_service: Optional[str] = None
    current_bucket: Optional[str] = None

    @property
    def completed_count(self) -> int:
        """
        Get count of completed collectors.

        Returns:
            Number of successfully completed collectors.
        """
        return len(self.completed_collectors)

    @property
    def total_completed(self) -> int:
        """
        Get total count of completed collectors (including partial/failed/skipped).

        Returns:
            Total number of collectors that finished execution.
        """
        return (
            len(self.completed_collectors)
            + len(self.partial_collectors)
            + len(self.failed_collectors)
            + len(self.skipped_collectors)
        )

    @property
    def progress_percentage(self) -> float:
        """
        Get progress percentage (0.0 to 100.0).

        Returns:
            Progress percentage.
        """
        if self.total_collectors == 0:
            return 100.0
        return (self.total_completed / self.total_collectors) * 100.0

    @property
    def duration(self) -> float:
        """
        Get total duration in seconds.

        Returns:
            Duration in seconds.
        """
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.now() - self.start_time).total_seconds()
        return 0.0


class ProgressStateManager:
    """
    Manages progress state across all DUTs and collectors.

    Tracks collector execution progress, timing, and status across multiple
    DUTs with thread-safe state management.

    Attributes:
        dut_ids: List of DUT IDs.
        collectors: List of collector IDs.
        total_work: Total number of collector tasks.
        dut_progress: Per-DUT progress tracking.
        collector_progress: Per-collector progress tracking.
    """

    def __init__(
        self,
        dut_ids: List[str],
        collectors: List[str],
        logger=None,
        console=None,
    ):
        self.dut_ids = dut_ids
        self.collectors = collectors
        self.total_work = len(collectors) * len(dut_ids)
        self.logger = logger
        self.console = console

        # Initialize DUT progress tracking
        self.dut_progress: Dict[str, DUTProgress] = {}
        for dut_id in dut_ids:
            self.dut_progress[dut_id] = DUTProgress(
                dut_id=dut_id, total_collectors=len(collectors)
            )

        # Initialize collector progress tracking
        self.collector_progress: Dict[str, Dict[str, CollectorProgress]] = {}
        for collector_id in collectors:
            self.collector_progress[collector_id] = {}
            for dut_id in dut_ids:
                self.collector_progress[collector_id][dut_id] = CollectorProgress(
                    collector_id=collector_id, dut_id=dut_id
                )

        # Overall progress tracking
        self.overall_start_time = datetime.now()
        self.overall_completed = 0
        self.overall_partial = 0
        self.overall_failed = 0
        self.overall_skipped = 0

        # Progress update callbacks
        self._progress_callbacks: List[callable] = []

    async def initialize(self) -> None:
        """
        Initialize the progress state manager (async operations).
        """
        if self.logger:
            await self._logger("INFO", "ProgressStateManager initialized")

    async def _logger(self, level: str, message: str, dut_id: str = None) -> None:
        """
        Log message using the configured logger or fallback to print.

        Args:
            level: Log level.
            message: Message to log.
            dut_id: Optional DUT ID.
        """
        if self.logger:
            try:
                if dut_id:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id, level, "ProgressStateManager", message
                    )
                else:
                    await self.logger.log_runtime(
                        level, "ProgressStateManager", message
                    )
            except Exception:
                # Fallback to print if logger fails
                print(f"{level.upper()}: {message}")
        else:
            print(f"{level.upper()}: {message}")

    def add_progress_callback(self, callback: callable) -> None:
        """
        Add a callback to be called when progress updates.

        Args:
            callback: Callable to invoke on progress updates.
        """
        self._progress_callbacks.append(callback)

    def remove_progress_callback(self, callback: callable) -> None:
        """
        Remove a progress callback.

        Args:
            callback: Callback to remove.
        """
        if callback in self._progress_callbacks:
            self._progress_callbacks.remove(callback)

    def _notify_progress_update(self) -> None:
        """
        Notify all progress callbacks of an update.

        Calls all registered callbacks with the current progress state.
        """
        for callback in self._progress_callbacks:
            try:
                callback(self)
            except Exception:
                # Don't let callback errors break progress tracking
                pass

    def start_dut_collection(self, dut_id: str) -> None:
        """
        Mark DUT collection as started.

        Args:
            dut_id: DUT ID.
        """
        if dut_id in self.dut_progress:
            self.dut_progress[dut_id].start_time = datetime.now()
            self._notify_progress_update()

    def complete_dut_collection(self, dut_id: str) -> None:
        """
        Mark DUT collection as completed.

        Args:
            dut_id: DUT ID.
        """
        if dut_id in self.dut_progress:
            self.dut_progress[dut_id].end_time = datetime.now()
            self._notify_progress_update()

    async def start_collector(
        self,
        dut_id: str,
        collector_id: str,
        service: str = None,
        bucket: str = None,
    ) -> None:
        """
        Mark a collector as started.

        Args:
            dut_id: DUT ID.
            collector_id: Collector ID.
            service: Optional service name.
            bucket: Optional bucket name.
        """
        if dut_id in self.dut_progress and collector_id in self.collector_progress:
            dut_progress = self.dut_progress[dut_id]

            # Start DUT collection timer if this is the first collector
            if dut_progress.start_time is None:
                self.start_dut_collection(dut_id)
                await self._logger(
                    "DEBUG",
                    f"Started DUT {dut_id} collection timer (first collector: {collector_id})",
                    dut_id,
                )

            # Update DUT current context
            dut_progress.current_service = service
            dut_progress.current_bucket = bucket
            dut_progress.running_collectors.add(collector_id)

            # Update collector progress
            collector_progress = self.collector_progress[collector_id][dut_id]
            collector_progress.status = CollectorStatus.RUNNING
            collector_progress.start_time = datetime.now()

            # Log progress update
            await self._logger(
                "DEBUG",
                f"Collector {collector_id} on {dut_id} started. Service: {service}, Bucket: {bucket}",
                dut_id,
            )

            self._notify_progress_update()

    async def complete_collector(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str = "",
        execution_time: float = 0.0,
    ) -> None:
        """
        Mark a collector as completed.

        Args:
            dut_id: DUT ID.
            collector_id: Collector ID.
            status: Completion status.
            reason: Optional reason string.
            execution_time: Execution time in seconds.
        """
        if dut_id in self.dut_progress and collector_id in self.collector_progress:
            # Update DUT progress
            dut_progress = self.dut_progress[dut_id]
            dut_progress.running_collectors.discard(collector_id)

            # Update collector progress
            collector_progress = self.collector_progress[collector_id][dut_id]
            collector_progress.end_time = datetime.now()
            collector_progress.execution_time = execution_time
            collector_progress.reason = reason

            # Debug logging
            await self._logger(
                "DEBUG",
                f"complete_collector called with status: '{status}' for {collector_id} on {dut_id}",
                dut_id,
            )

            # Map status to enum
            if status == "completed" or status == "success":
                collector_progress.status = CollectorStatus.COMPLETED
                dut_progress.completed_collectors.add(collector_id)
                self.overall_completed += 1
                await self._logger(
                    "DEBUG",
                    f"Collector {collector_id} on {dut_id} completed. Overall: {self.overall_completed}, DUT {dut_id}: {len(dut_progress.completed_collectors)}",
                    dut_id,
                )
            elif status == "skipped":
                collector_progress.status = CollectorStatus.SKIPPED
                dut_progress.skipped_collectors.add(collector_id)
                self.overall_skipped += 1
                await self._logger(
                    "DEBUG",
                    f"Collector {collector_id} on {dut_id} skipped. Overall: {self.overall_skipped}",
                    dut_id,
                )
            elif status == "failed" or status == "error":
                collector_progress.status = CollectorStatus.FAILED
                dut_progress.failed_collectors.add(collector_id)
                self.overall_failed += 1
                await self._logger(
                    "DEBUG",
                    f"Collector {collector_id} on {dut_id} failed. Overall: {self.overall_failed}",
                    dut_id,
                )
            elif status == "partial":
                collector_progress.status = CollectorStatus.PARTIAL
                dut_progress.partial_collectors.add(collector_id)
                self.overall_partial += 1
                await self._logger(
                    "DEBUG",
                    f"Collector {collector_id} on {dut_id} partial. Overall: {self.overall_partial}",
                    dut_id,
                )
            else:
                await self._logger(
                    "DEBUG",
                    f"Unknown status '{status}' for {collector_id} on {dut_id}, treating as completed",
                    dut_id,
                )
                collector_progress.status = CollectorStatus.COMPLETED
                dut_progress.completed_collectors.add(collector_id)
                self.overall_completed += 1

            # Check if all collectors for this DUT are complete
            if dut_progress.total_completed >= dut_progress.total_collectors:
                # Mark DUT collection as complete
                self.complete_dut_collection(dut_id)
                await self._logger(
                    "DEBUG",
                    f"DUT {dut_id} collection complete! ({dut_progress.total_completed}/{dut_progress.total_collectors})",
                    dut_id,
                )

            self._notify_progress_update()

    def get_overall_progress(self) -> Dict[str, Any]:
        """
        Get overall progress information.

        Returns:
            Dictionary containing overall progress metrics.
        """
        total_completed = (
            self.overall_completed
            + self.overall_partial
            + self.overall_failed
            + self.overall_skipped
        )
        total_remaining = self.total_work - total_completed

        return {
            "total_work": self.total_work,
            "completed": self.overall_completed,
            "partial": self.overall_partial,
            "failed": self.overall_failed,
            "skipped": self.overall_skipped,
            "remaining": total_remaining,
            "progress_percentage": (
                (total_completed / self.total_work) * 100.0
                if self.total_work > 0
                else 100.0
            ),
            "start_time": self.overall_start_time,
            "duration": (datetime.now() - self.overall_start_time).total_seconds(),
        }

    def get_dut_progress(self, dut_id: str) -> Optional[DUTProgress]:
        """
        Get progress for a specific DUT.

        Args:
            dut_id: DUT ID.

        Returns:
            DUTProgress object or None if not found.
        """
        return self.dut_progress.get(dut_id)

    def get_collector_progress(
        self, collector_id: str, dut_id: str
    ) -> Optional[CollectorProgress]:
        """
        Get progress for a specific collector on a specific DUT.

        Args:
            collector_id: Collector ID.
            dut_id: DUT ID.

        Returns:
            CollectorProgress object or None if not found.
        """
        return self.collector_progress.get(collector_id, {}).get(dut_id)

    def get_current_context(self, dut_id: str) -> Dict[str, Any]:
        """
        Get current execution context for a DUT.

        Args:
            dut_id: DUT ID.

        Returns:
            Dictionary containing current execution context.
        """
        if dut_id not in self.dut_progress:
            return {}

        dut_progress = self.dut_progress[dut_id]
        return {
            "current_service": dut_progress.current_service,
            "current_bucket": dut_progress.current_bucket,
            "running_collectors": list(dut_progress.running_collectors),
            "progress_percentage": dut_progress.progress_percentage,
            "completed_count": dut_progress.completed_count,
            "total_collectors": dut_progress.total_collectors,
        }

    def get_remaining_collectors(
        self, dut_id: str = None, max_display: int = 5
    ) -> List[str]:
        """
        Get list of remaining (pending/running) collectors for a DUT or overall.

        Args:
            dut_id: Optional DUT ID for DUT-specific remaining collectors.
            max_display: Maximum number of collectors to return.

        Returns:
            List of remaining collector IDs.
        """
        remaining = []

        if dut_id:
            # Get remaining collectors for specific DUT
            if dut_id in self.dut_progress:
                dut_progress = self.dut_progress[dut_id]
                for collector_id in self.collectors:
                    if (
                        collector_id not in dut_progress.completed_collectors
                        and collector_id not in dut_progress.failed_collectors
                        and collector_id not in dut_progress.skipped_collectors
                        and collector_id not in dut_progress.partial_collectors
                    ):
                        remaining.append(collector_id)
        else:
            # Get remaining collectors overall (across all DUTs)
            for collector_id in self.collectors:
                collector_completed = True
                for dut_id in self.dut_ids:
                    if dut_id in self.collector_progress[collector_id]:
                        progress = self.collector_progress[collector_id][dut_id]
                        if not progress.is_completed:
                            collector_completed = False
                            break
                if not collector_completed:
                    remaining.append(collector_id)

        # Limit the number of collectors shown to avoid overly long descriptions
        if len(remaining) > max_display:
            return remaining[:max_display] + [
                f"... and {len(remaining) - max_display} more"
            ]
        return remaining

    def get_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive progress summary.

        Returns:
            Dictionary containing overall, per-DUT, and per-collector summaries.
        """
        summary = {
            "overall": self.get_overall_progress(),
            "duts": {},
            "collectors": {},
        }

        # Add DUT summaries
        for dut_id, dut_progress in self.dut_progress.items():
            summary["duts"][dut_id] = {
                "progress_percentage": dut_progress.progress_percentage,
                "completed_count": dut_progress.completed_count,
                "total_collectors": dut_progress.total_collectors,
                "start_time": dut_progress.start_time,
                "end_time": dut_progress.end_time,
                "duration": dut_progress.duration,
                "current_context": self.get_current_context(dut_id),
            }

        # Add collector summaries
        for collector_id, dut_progress in self.collector_progress.items():
            summary["collectors"][collector_id] = {}
            for dut_id, progress in dut_progress.items():
                summary["collectors"][collector_id][dut_id] = {
                    "status": progress.status.value,
                    "start_time": progress.start_time,
                    "end_time": progress.end_time,
                    "execution_time": progress.execution_time,
                    "reason": progress.reason,
                }

        return summary
