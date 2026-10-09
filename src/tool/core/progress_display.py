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
Progress Display for NVDebug Tool.

Shows real-time progress bars for collector execution using Rich progress bars
with per-DUT task tracking and overall progress visualization.
"""

from rich.progress import (
    BarColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.text import Text


class StateElapsedColumn(ProgressColumn):
    """
    Render one shared wall-clock timeline for the run and every DUT row.

    Every row uses the state manager's common run start and continues advancing
    until the display stops, even when the scheduler starts or completes DUTs at
    different times. Per-DUT execution and completion durations remain
    available in progress metadata and are not changed by this display-only
    policy.
    """

    def __init__(self, progress_state_getter):
        """
        Initialize a ``StateElapsedColumn`` instance.

        The initializer records ``_progress_state_getter`` for later operations
        and establishes the instance invariants before any public method runs.

        Args:
            progress_state_getter: Progress state getter consumed while the
                function attempts to initialize a ``StateElapsedColumn``
                instance.
        """
        super().__init__()
        self._progress_state_getter = progress_state_getter

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """
        Format duration.

        The implementation uses ``seconds`` to format duration. The source value
        keeps its ownership while the normalized representation is returned
        separately.

        Args:
            seconds: Numeric seconds used while the operation performs bounded
                accounting.

        Returns:
            The canonical duration text.
        """
        seconds = max(0, int(seconds or 0))
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours}:{minutes:02d}:{seconds:02d}"

    @staticmethod
    def _now_for(start_time):
        """
        Return the now for.

        The implementation uses ``start_time`` to produce the now for.

        Args:
            start_time: Start time consumed while the function attempts to
                produce the now for.

        Returns:
            The current timestamp in the timezone used by ``start_time``.
        """
        from datetime import datetime as _state_datetime

        timezone = getattr(start_time, "tzinfo", None)
        return (
            _state_datetime.now(tz=timezone)
            if timezone is not None
            else _state_datetime.now()
        )

    def render(self, task) -> Text:
        """
        Render the current value for operator-facing output.

        After applying local validation, the function forwards ``task`` to
        ``Text`` and preserves its return and exception contract. The source
        value keeps its ownership while the normalized representation is
        returned separately.

        Args:
            task: Task consumed while the function attempts to render the
                current value for operator-facing output.

        Returns:
            Rich text containing the task's current elapsed-time display.
        """
        elapsed = getattr(task, "elapsed", None) or 0.0
        try:
            progress_state = self._progress_state_getter()
            overall_start_time = getattr(progress_state, "overall_start_time", None)
            if overall_start_time is not None:
                elapsed = (
                    self._now_for(overall_start_time) - overall_start_time
                ).total_seconds()
        except (AttributeError, KeyError, TypeError, ValueError):
            # Rich's monotonic task clock remains a safe fallback for callers
            # which have not attached a progress-state manager.
            elapsed = getattr(task, "elapsed", None) or 0.0

        return Text(self._format_duration(elapsed), style="progress.elapsed")


class ProgressDisplay:
    """
    Displays progress bars using the progress state manager.

    Provides real-time visualization of collector execution progress across
    multiple DUTs using Rich progress bars.
    """

    def __init__(self, console, logger=None):
        """
        Initialize progress display.

        The initializer records ``console``, ``dut_tasks``, ``logger``,
        ``overall_task``, and ``progress`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            console: Console consumed while the function attempts to initialize
                progress display.
            logger: Sanitized logger used for operator-visible diagnostics.
        """
        self.console = console
        self.logger = logger
        self.progress = None
        self.overall_task = None
        self.dut_tasks = {}
        self.progress_state = None

    def set_progress_state(self, progress_state):
        """
        Set the progress state manager to track.

        The implementation uses ``progress_state`` to set the progress state
        manager to track. It updates ``progress_state`` on the instance as part
        of that state transition.

        Args:
            progress_state: Progress state consumed while the function attempts
                to set the progress state manager to track.
        """
        self.progress_state = progress_state

    def _format_duration(self, seconds: float) -> str:
        """
        Format duration in seconds to H:MM:SS format.

        The implementation uses ``seconds`` to format duration in seconds to
        H:MM:SS format. The source value keeps its ownership while the
        normalized representation is returned separately.

        Args:
            seconds: Numeric seconds used while the operation performs bounded
                accounting.

        Returns:
            The canonical duration text.
        """
        if seconds <= 0:
            return "0:00:00"

        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)

        return f"{hours}:{minutes:02d}:{secs:02d}"

    def start(self, dut_ids: list, total_collectors: int):
        """
        Start the progress display.

        The implementation uses ``dut_ids`` and ``total_collectors`` to start
        the progress display. It updates ``overall_task`` and ``progress`` on
        the instance as part of that state transition.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            total_collectors: Number of distinct collectors in the plan. Work
                totals come from the attached state so DUT-specific exclusions
                do not inflate the progress bars.
        """
        if not self.progress_state:
            return

        # Create progress bar
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            StateElapsedColumn(lambda: self.progress_state),
            console=self.console,
            auto_refresh=True,
            refresh_per_second=4,
        )

        # Start the progress bar
        self.progress.start()

        # Create overall progress task
        total_work = self.progress_state.get_overall_progress()["total_work"]
        self.overall_task = self.progress.add_task(
            f"[bold blue]Overall Progress ({total_work} operations across {len(dut_ids)} DUTs)",
            total=total_work,
        )

        # Create DUT progress tasks
        for dut_id in dut_ids:
            dut_progress = self.progress_state.get_dut_progress(dut_id)
            task = self.progress.add_task(
                f"[green]{dut_id}[/green]",
                total=dut_progress.total_collectors if dut_progress else 0,
                start=False,
                dut_id=dut_id,
            )
            self.dut_tasks[dut_id] = task

        # Start all DUT tasks
        for task in self.dut_tasks.values():
            self.progress.start_task(task)

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
                        dut_id, level, "ProgressDisplay", message
                    )
                else:
                    await self.logger.log_runtime(level, "ProgressDisplay", message)
            except Exception:
                # Fallback to print if logger fails
                print(f"{level.upper()}: {message}")
        else:
            print(f"{level.upper()}: {message}")

    async def update(self):
        """
        Update progress display from progress state manager.

        The implementation uses current instance state to update progress
        display from progress state manager. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        """
        if not self.progress_state or not self.progress:
            return

        try:
            # Update overall progress
            if self.overall_task is not None:
                overall_progress = self.progress_state.get_overall_progress()
                total_completed = (
                    overall_progress["completed"]
                    + overall_progress["degraded"]
                    + overall_progress["partial"]
                    + overall_progress["failed"]
                    + overall_progress["skipped"]
                )

                self.progress.update(self.overall_task, completed=total_completed)

                # Get remaining collectors for more informative description
                remaining_collectors = self.progress_state.get_remaining_collectors()
                remaining_count = overall_progress["total_work"] - total_completed

                if remaining_count > 0 and remaining_collectors:
                    # Show remaining collector names
                    remaining_text = ", ".join(remaining_collectors)
                    description = f"[bold blue]Overall Progress ({total_completed}/{overall_progress['total_work']}) - {remaining_text} remaining[/bold blue]"
                else:
                    # All completed
                    description = f"[bold blue]Overall Progress ({total_completed}/{overall_progress['total_work']}) - Complete![/bold blue]"

                if overall_progress["failed"] > 0:
                    description += f" - {overall_progress['failed']} failed"
                if overall_progress["degraded"] > 0:
                    description += f" - {overall_progress['degraded']} degraded"
                if overall_progress["partial"] > 0:
                    description += f" - {overall_progress['partial']} partial"
                if overall_progress["skipped"] > 0:
                    description += f" - {overall_progress['skipped']} skipped"
                self.progress.update(self.overall_task, description=description)

            # Update DUT progress
            for dut_id, task in self.dut_tasks.items():
                dut_progress = self.progress_state.get_dut_progress(dut_id)
                if dut_progress:
                    # Update progress count
                    self.progress.update(task, completed=dut_progress.total_completed)

                    # Update description with remaining collectors for this DUT
                    remaining_collectors = self.progress_state.get_remaining_collectors(
                        dut_id
                    )
                    remaining_count = (
                        dut_progress.total_collectors - dut_progress.total_completed
                    )

                    if remaining_count > 0 and remaining_collectors:
                        # Elapsed time is rendered by StateElapsedColumn so it
                        # keeps ticking without another state or logging event.
                        remaining_text = ", ".join(remaining_collectors)
                        description = f"[green]{dut_id}[/green] - {remaining_text} remaining ({dut_progress.total_completed}/{dut_progress.total_collectors})"
                    else:
                        # All completed for this DUT
                        description = f"[green]{dut_id}[/green] - Complete! ({dut_progress.total_completed}/{dut_progress.total_collectors})"

                    self.progress.update(task, description=description)

        except Exception:
            # Don't let progress display errors break execution
            pass

    def stop(self):
        """
        Stop the progress display and clean up.

        The implementation uses current instance state to stop the progress
        display and clean up. It updates ``dut_tasks``, ``overall_task``, and
        ``progress`` on the instance as part of that state transition.
        """
        if self.progress:
            self.progress.stop()
            self.progress = None
            self.overall_task = None
            self.dut_tasks = {}
