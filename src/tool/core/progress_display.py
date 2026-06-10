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

from datetime import datetime

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)


class ProgressDisplay:
    """
    Displays progress bars using the progress state manager.

    Provides real-time visualization of collector execution progress across
    multiple DUTs using Rich progress bars.

    Attributes:
        console: Console for output.
        logger: Logger instance.
        progress: Rich Progress instance.
        overall_task: Overall progress task ID.
        dut_tasks (dict): Per-DUT progress task IDs.
        progress_state: Progress state manager.
    """

    def __init__(self, console, logger=None):
        """
        Initialize progress display.

        Args:
            console: Console instance.
            logger: Optional logger instance.
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

        Args:
            progress_state: Progress state manager instance.
        """
        self.progress_state = progress_state

    def _format_duration(self, seconds: float) -> str:
        """
        Format duration in seconds to H:MM:SS format.

        Args:
            seconds: Duration in seconds.

        Returns:
            Formatted duration string.
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

        Args:
            dut_ids (list): List of DUT IDs.
            total_collectors (int): Total number of collectors.
        """
        if not self.progress_state:
            return

        # Create progress bar
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
        )

        # Start the progress bar
        self.progress.start()

        # Create overall progress task
        total_work = total_collectors * len(dut_ids)
        self.overall_task = self.progress.add_task(
            f"[bold blue]Overall Progress ({total_collectors} collectors × {len(dut_ids)} DUTs)",
            total=total_work,
        )

        # Create DUT progress tasks
        for dut_id in dut_ids:
            task = self.progress.add_task(
                f"[green]{dut_id}[/green]",
                total=total_collectors,
                start=False,
            )
            self.dut_tasks[dut_id] = task

        # Start all DUT tasks
        for task in self.dut_tasks.values():
            self.progress.start_task(task)

    async def _logger(self, level: str, message: str, dut_id: str = None) -> None:
        """
        Log message using the configured logger or fallback to print.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR).
            message: Message to log.
            dut_id: Optional DUT ID for DUT-specific logging.
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
        """
        await self._logger("DEBUG", "ProgressDisplay.update() method called")
        await self._logger(
            "DEBUG",
            f"self.progress_state exists: {self.progress_state is not None}",
        )
        await self._logger(
            "DEBUG", f"self.progress exists: {self.progress is not None}"
        )

        if not self.progress_state or not self.progress:
            await self._logger(
                "DEBUG",
                "ProgressDisplay.update() - no progress_state or progress",
            )
            return

        await self._logger(
            "DEBUG",
            "ProgressDisplay.update() - both progress_state and progress exist",
        )
        await self._logger(
            "DEBUG",
            f"self.overall_task exists: {self.overall_task is not None}",
        )

        try:
            await self._logger("DEBUG", "Entering try block in update method")

            await self._logger("DEBUG", f"overall_task value: {self.overall_task}")
            await self._logger("DEBUG", f"overall_task type: {type(self.overall_task)}")
            await self._logger(
                "DEBUG", f"overall_task is None: {self.overall_task is None}"
            )

            # Update overall progress
            if self.overall_task is not None:
                await self._logger("DEBUG", "About to call get_overall_progress()")
                overall_progress = self.progress_state.get_overall_progress()
                await self._logger(
                    "DEBUG",
                    f"get_overall_progress() returned: {overall_progress}",
                )
                total_completed = (
                    overall_progress["completed"]
                    + overall_progress["failed"]
                    + overall_progress["skipped"]
                )

                # Debug logging
                await self._logger(
                    "DEBUG",
                    f"Overall progress - completed: {overall_progress['completed']}, failed: {overall_progress['failed']}, skipped: {overall_progress['skipped']}, total: {overall_progress['total_work']}",
                )
                await self._logger(
                    "DEBUG",
                    f"ProgressDisplay.update() called at {datetime.now()}",
                )
                await self._logger(
                    "DEBUG",
                    f"ProgressDisplay.progress_state object: {self.progress_state}",
                )
                await self._logger(
                    "DEBUG",
                    f"ProgressDisplay.progress_state type: {type(self.progress_state)}",
                )
                await self._logger(
                    "DEBUG",
                    f"ProgressDisplay.progress_state.overall_completed: {self.progress_state.overall_completed}",
                )
                await self._logger(
                    "DEBUG",
                    f"ProgressDisplay.progress_state.overall_failed: {self.progress_state.overall_failed}",
                )
                await self._logger(
                    "DEBUG",
                    f"ProgressDisplay.progress_state.overall_skipped: {self.progress_state.overall_skipped}",
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
                if overall_progress["skipped"] > 0:
                    description += f" - {overall_progress['skipped']} skipped"
                self.progress.update(self.overall_task, description=description)

            # Update DUT progress
            for dut_id, task in self.dut_tasks.items():
                dut_progress = self.progress_state.get_dut_progress(dut_id)
                if dut_progress:
                    # Debug logging
                    await self._logger(
                        "DEBUG",
                        f"DEBUG: DUT {dut_id} progress - total_completed: {dut_progress.total_completed}, total_collectors: {dut_progress.total_collectors}",
                    )

                    # Update progress count
                    self.progress.update(task, completed=dut_progress.total_completed)

                    # Update description with remaining collectors for this DUT
                    remaining_collectors = self.progress_state.get_remaining_collectors(
                        dut_id
                    )
                    remaining_count = (
                        dut_progress.total_collectors - dut_progress.total_completed
                    )

                    # Format per-DUT elapsed time
                    # Format per-DUT elapsed time
                    duration_str = self._format_duration(
                        dut_progress.duration
                        if hasattr(dut_progress, "duration")
                        else 0.0
                    )

                    if remaining_count > 0 and remaining_collectors:
                        # Show remaining collector names with per-DUT elapsed time
                        remaining_text = ", ".join(remaining_collectors)
                        description = f"[green]{dut_id}[/green] - {remaining_text} remaining ({dut_progress.total_completed}/{dut_progress.total_collectors}) {duration_str}"
                    else:
                        # All completed for this DUT
                        description = f"[green]{dut_id}[/green] - Complete! ({dut_progress.total_completed}/{dut_progress.total_collectors}) {duration_str}"

                    self.progress.update(task, description=description)

        except Exception as e:
            # Don't let progress display errors break execution
            await self._logger("ERROR", f"Progress display update error: {e}")
            pass

    def stop(self):
        """
        Stop the progress display and clean up.
        """
        if self.progress:
            self.progress.stop()
            self.progress = None
            self.overall_task = None
            self.dut_tasks = {}
