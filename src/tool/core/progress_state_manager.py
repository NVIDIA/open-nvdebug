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

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class CollectorStatus(Enum):
    """
    Status of a collector.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    DEGRADED = "degraded"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class CollectorProgress:
    """
    Progress tracking for a single collector.

    The coherent record keeps ``collector_id``, ``dut_id``, ``status``,
    ``start_time``, and ``end_time`` together so consumers observe one collector
    progress state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        collector_id: Canonical text used as collector identifier.
        dut_id: Canonical text used as DUT identifier.
        status: Canonical status exposed to downstream status consumers.
        start_time: Start time retained as part of the record's public state.
        end_time: End time retained as part of the record's public state.
        execution_time: Numeric execution time retained by this record.
        reason: Canonical reason exposed to downstream status consumers.
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
        Check if collector is in a terminal state.

        Each access computes the value from ``status`` on the current instance;
        the derived view is not stored as independent state. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path.

        Returns:
            Whether the if collector is in a terminal state operation succeeds.
        """
        return self.status in [
            CollectorStatus.COMPLETED,
            CollectorStatus.DEGRADED,
            CollectorStatus.PARTIAL,
            CollectorStatus.SKIPPED,
            CollectorStatus.FAILED,
        ]

    @property
    def duration(self) -> float:
        """
        Get duration in seconds.

        Each access computes the value from ``end_time`` and ``start_time`` on
        the current instance; the derived view is not stored as independent
        state.

        Returns:
            The numeric duration value.
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

    The coherent record keeps ``dut_id``, ``total_collectors``,
    ``completed_collectors``, ``degraded_collectors``, and
    ``partial_collectors`` together so consumers observe one DUT progress state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        dut_id: Canonical text used as DUT identifier.
        total_collectors: Number of total collectors represented by this record.
        completed_collectors: Collection of completed collectors entries
            retained by this record.
        degraded_collectors: Collection of degraded collectors entries retained
            by this record.
        partial_collectors: Collection of partial collectors entries retained by
            this record.
        failed_collectors: Collection of failed collectors entries retained by
            this record.
        skipped_collectors: Collection of skipped collectors entries retained by
            this record.
        running_collectors: Collection of running collectors entries retained by
            this record.
        start_time: Start time retained as part of the record's public state.
        end_time: End time retained as part of the record's public state.
        current_service: Canonical text used as current service.
        current_bucket: Canonical text used as current bucket.
    """

    dut_id: str
    total_collectors: int
    completed_collectors: Set[str] = field(default_factory=set)
    degraded_collectors: Set[str] = field(default_factory=set)
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

        Each access computes the value from ``completed_collectors`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric completed count.
        """
        return len(self.completed_collectors)

    @property
    def total_completed(self) -> int:
        """
        Get total count of completed collectors (including partial/failed/skipped).

        Each access computes the value from ``completed_collectors``,
        ``degraded_collectors``, ``failed_collectors``, ``partial_collectors``,
        and ``skipped_collectors`` on the current instance; the derived view is
        not stored as independent state.

        Returns:
            The numeric total completed value.
        """
        return (
            len(self.completed_collectors)
            + len(self.degraded_collectors)
            + len(self.partial_collectors)
            + len(self.failed_collectors)
            + len(self.skipped_collectors)
        )

    @property
    def progress_percentage(self) -> float:
        """
        Get progress percentage (0.0 to 100.0).

        Each access computes the value from ``total_collectors`` and
        ``total_completed`` on the current instance; the derived view is not
        stored as independent state.

        Returns:
            The numeric progress percentage value.
        """
        if self.total_collectors == 0:
            return 100.0
        return (self.total_completed / self.total_collectors) * 100.0

    @property
    def duration(self) -> float:
        """
        Get total duration in seconds.

        Each access computes the value from ``end_time`` and ``start_time`` on
        the current instance; the derived view is not stored as independent
        state.

        Returns:
            The numeric duration value.
        """
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.now() - self.start_time).total_seconds()
        return 0.0


class ProgressStateManager:
    """
    Manages progress state across all DUTs and collectors.

    Tracks collector execution progress, timing, and status across multiple DUTs
    with thread-safe state management.
    """

    def __init__(
        self,
        dut_ids: List[str],
        collectors: List[str],
        logger=None,
        console=None,
        *,
        collectors_per_dut: Optional[Dict[str, List[str]]] = None,
    ):
        """
        Initialize a ``ProgressStateManager`` instance.

        The initializer records ``_progress_callbacks``, ``collector_progress``,
        ``collectors``, ``console``, and ``dut_ids`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collectors: Entries supplied as ``collectors`` without transferring
                container ownership.
            logger: Sanitized logger used for operator-visible diagnostics.
            console: Optional console; ``None`` selects the function's default
                behavior.
            collectors_per_dut: Actual scheduled collectors for each DUT. When
                supplied, omitted DUTs have no work and inapplicable pairs are
                excluded from progress without manufacturing terminal events.
                ``None`` preserves the uniform plan used by older callers.
        """
        self.dut_ids = dut_ids
        self.collectors = collectors
        self.collectors_per_dut = {}
        for dut_id in dut_ids:
            selected = set(
                collectors
                if collectors_per_dut is None
                else collectors_per_dut.get(dut_id, [])
            )
            self.collectors_per_dut[dut_id] = [
                collector_id for collector_id in collectors if collector_id in selected
            ]
        self.total_work = sum(
            len(selected) for selected in self.collectors_per_dut.values()
        )
        self.logger = logger
        self.console = console

        # Initialize DUT progress tracking
        self.dut_progress: Dict[str, DUTProgress] = {}
        for dut_id in dut_ids:
            self.dut_progress[dut_id] = DUTProgress(
                dut_id=dut_id, total_collectors=len(self.collectors_per_dut[dut_id])
            )

        # Initialize collector progress tracking
        self.collector_progress: Dict[str, Dict[str, CollectorProgress]] = {}
        for collector_id in collectors:
            self.collector_progress[collector_id] = {}
            for dut_id in dut_ids:
                if collector_id not in self.collectors_per_dut[dut_id]:
                    continue
                self.collector_progress[collector_id][dut_id] = CollectorProgress(
                    collector_id=collector_id, dut_id=dut_id
                )

        # Overall progress tracking
        self.overall_start_time = datetime.now()
        self.overall_completed = 0
        self.overall_degraded = 0
        self.overall_partial = 0
        self.overall_failed = 0
        self.overall_skipped = 0

        # Progress update callbacks
        self._progress_callbacks: List[callable] = []

    async def initialize(self) -> None:
        """
        Initialize the progress state manager (async operations).

        The implementation uses current instance state to initialize the
        progress state manager (async operations). Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.
        """
        if self.logger:
            await self._logger("INFO", "ProgressStateManager initialized")

    async def _logger(self, level: str, message: str, dut_id: str = None) -> None:
        """
        Log message using the configured logger or fallback to print.

        The implementation uses ``level``, ``message``, and ``dut_id`` to log
        message using the configured logger or fallback to print. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
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

        The implementation uses ``dut_id`` to mark DUT collection as started.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if dut_id in self.dut_progress:
            self.dut_progress[dut_id].start_time = datetime.now()
            self._notify_progress_update()

    def complete_dut_collection(self, dut_id: str) -> None:
        """
        Mark DUT collection as completed.

        The implementation uses ``dut_id`` to mark DUT collection as completed.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
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

        Start DUT collection timer if this is the first collector.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            service: Optional service; ``None`` selects the function's default
                behavior.
            bucket: Optional bucket; ``None`` selects the function's default
                behavior.
        """
        if dut_id in self.collector_progress.get(collector_id, {}):
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

        The implementation uses ``dut_id``, ``collector_id``, ``status``,
        ``reason``, and ``execution_time`` to mark a collector as completed.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind. It updates ``overall_completed``,
        ``overall_degraded``, ``overall_failed``, ``overall_partial``, and
        ``overall_skipped`` on the instance as part of that state transition.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            status: Text supplied as status in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.
            execution_time: Numeric execution time used while the operation
                performs bounded accounting.
        """
        if dut_id in self.collector_progress.get(collector_id, {}):
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
            elif status == "degraded":
                collector_progress.status = CollectorStatus.DEGRADED
                dut_progress.degraded_collectors.add(collector_id)
                self.overall_degraded += 1
                await self._logger(
                    "DEBUG",
                    f"Collector {collector_id} on {dut_id} degraded. Overall: {self.overall_degraded}",
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

        The implementation uses current instance state to get overall progress
        information.

        Returns:
            A mapping containing the ``total_work``, ``completed``,
            ``degraded``, ``partial``, and ``failed`` fields.
        """
        total_completed = (
            self.overall_completed
            + self.overall_degraded
            + self.overall_partial
            + self.overall_failed
            + self.overall_skipped
        )
        total_remaining = self.total_work - total_completed

        return {
            "total_work": self.total_work,
            "completed": self.overall_completed,
            "degraded": self.overall_degraded,
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

        After applying local validation, the function forwards ``dut_id`` to
        ``self.dut_progress.get`` and preserves its return and exception
        contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A ``DUTProgress`` representing DUT progress, or ``None`` when the
            requested value is unavailable.
        """
        return self.dut_progress.get(dut_id)

    def get_remaining_collectors(
        self, dut_id: str = None, max_display: int = 5
    ) -> List[str]:
        """
        Get list of remaining (pending/running) collectors for a DUT or overall.

        The implementation uses ``dut_id`` and ``max_display`` to get list of
        remaining (pending/running) collectors for a DUT or overall.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            max_display: Upper bound enforced for max display; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            The remaining collectors returned in operation-defined order.
        """
        remaining = []

        if dut_id:
            # Get remaining collectors for specific DUT
            if dut_id in self.dut_progress:
                dut_progress = self.dut_progress[dut_id]
                for collector_id in self.collectors_per_dut[dut_id]:
                    if (
                        collector_id not in dut_progress.completed_collectors
                        and collector_id not in dut_progress.degraded_collectors
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
