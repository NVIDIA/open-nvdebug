#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
Render sanitized best-effort progress for bounded terminal operations.

The renderer owns only presentation state. Callers retain lifecycle and result
ownership for the operation being displayed, and any console or Rich failure is
contained so it cannot change the operation's success, failure, or cancellation.
"""

from __future__ import annotations

import math
import threading
from typing import Any, Optional

from .sanitizer import neutralize_text_controls

_MAX_PROGRESS_DESCRIPTION_CHARS = 512
_MAX_PROGRESS_VALUE = (1 << 63) - 1


def _bounded_progress_value(value: object) -> Optional[int]:
    """
    Normalize one progress counter without invoking caller-defined coercion.

    Rich accepts floating-point counters, but progress producers in this tool
    report integral files, bytes, or stages. Exact built-in numeric types avoid
    executing hostile conversion hooks and keep unusually large provider values
    from destabilizing terminal rendering.

    Args:
        value: Candidate counter supplied by the progress producer.

    Returns:
        A non-negative bounded integer, or ``None`` when the value is not a
        finite supported counter.
    """

    if type(value) is int:  # noqa: E721 - subclasses are rejected
        normalized = value
    elif type(value) is float:  # noqa: E721 - subclasses are rejected
        if not math.isfinite(value):
            return None
        normalized = int(value)
    else:
        return None
    return min(_MAX_PROGRESS_VALUE, max(0, normalized))


class SanitizedOperationProgress:
    """
    Own one sanitized Rich task for an operator-visible operation.

    A live display is created only when the supplied sanitized console wraps an
    interactive Rich console. Non-terminal output remains line-oriented, while
    callers can use the same no-throw update interface in every environment.
    The instance may be entered as a context manager or started and stopped
    explicitly; repeated lifecycle calls are harmless.
    """

    def __init__(
        self,
        sanitized_console: Any,
        description: str,
        *,
        transient: bool = False,
    ) -> None:
        """
        Initialize an inactive operation progress display.

        No terminal output is created until :meth:`start` runs. The sanitized
        console remains caller-owned, and this instance owns only the Rich
        ``Progress`` object it creates.

        Args:
            sanitized_console: Host console whose sanitizer and Rich console
                are used for terminal presentation.
            description: Initial operator-visible operation description.
            transient: Whether Rich should remove the task after it stops.
        """

        self._sanitized_console = sanitized_console
        self._description = str(description)
        self._transient = bool(transient)
        self._lock = threading.RLock()
        self._progress: Any = None
        self._task_id: Any = None
        self._total: Optional[int] = None

    @property
    def enabled(self) -> bool:
        """
        Return whether an interactive Rich task is currently active.

        The value reflects successfully created presentation state rather than
        merely terminal capability, so adapters can suppress redundant
        heartbeat lines only after the live task actually starts.

        Returns:
            ``True`` while a Rich task owned by this instance is active.
        """

        with self._lock:
            return self._progress is not None and self._task_id is not None

    def _safe_description(self, description: object) -> str:
        """
        Sanitize and bound one progress description for markup-free rendering.

        Newlines are flattened so provider-controlled text cannot create extra
        terminal rows. Rich markup is disabled by the owning ``TextColumn``, so
        literal brackets remain literal instead of becoming presentation tags.

        Args:
            description: Candidate text supplied by the operation or provider.

        Returns:
            A bounded single-line description safe for the live task.
        """

        fallback = "Working"
        try:
            rendered = str(description or fallback)
            sanitizer = getattr(self._sanitized_console, "sanitizer", None)
            sanitize = getattr(sanitizer, "sanitize", None)
            if callable(sanitize):
                rendered = str(sanitize(rendered))
            rendered = neutralize_text_controls(rendered)
            rendered = " ".join(rendered.split())
        except Exception:
            rendered = fallback
        if not rendered:
            rendered = fallback
        return rendered[:_MAX_PROGRESS_DESCRIPTION_CHARS]

    def start(self) -> "SanitizedOperationProgress":
        """
        Start the live task when an interactive Rich console is available.

        Rich imports and presentation failures are contained. A failed or
        non-terminal start leaves the object as a safe no-op reporter and does
        not write fallback lines; callers remain responsible for their ordinary
        milestone output.

        Returns:
            This reporter after the idempotent start attempt.
        """

        with self._lock:
            if self._progress is not None:
                return self
            console = getattr(self._sanitized_console, "console", None)
            is_terminal = getattr(console, "is_terminal", None)
            if type(is_terminal) is not bool or not is_terminal:
                return self

            progress: Any = None
            try:
                from rich.progress import (
                    BarColumn,
                    Progress,
                    SpinnerColumn,
                    TaskProgressColumn,
                    TextColumn,
                    TimeElapsedColumn,
                )

                progress = Progress(
                    SpinnerColumn(style="cyan"),
                    TextColumn(
                        "{task.description}",
                        style="bold cyan",
                        markup=False,
                    ),
                    BarColumn(
                        bar_width=24,
                        complete_style="green",
                        finished_style="green",
                    ),
                    TaskProgressColumn(),
                    TimeElapsedColumn(),
                    console=console,
                    transient=self._transient,
                    redirect_stdout=False,
                    redirect_stderr=False,
                    refresh_per_second=8,
                    expand=False,
                )
                task_id = progress.add_task(
                    self._safe_description(self._description),
                    total=None,
                )
                progress.start()
                self._progress = progress
                self._task_id = task_id
            except Exception:
                if progress is not None:
                    try:
                        progress.stop()
                    except Exception:
                        pass
        return self

    def update(
        self,
        description: object,
        completed: object = None,
        total: object = None,
    ) -> None:
        """
        Update the live task without allowing presentation to affect work.

        A missing or invalid total selects Rich's indeterminate pulse. Valid
        determinate values are bounded and completion is clamped to the total.
        The description always passes through the host sanitizer before use.

        Args:
            description: Current operator-visible stage description.
            completed: Completed files, bytes, or stages for this update.
            total: Total files, bytes, or stages for this update.
        """

        with self._lock:
            progress = self._progress
            task_id = self._task_id
            if progress is None or task_id is None:
                return
            normalized_total = _bounded_progress_value(total)
            normalized_completed = _bounded_progress_value(completed)
            if normalized_total is not None:
                if normalized_total <= 0:
                    normalized_total = 1
                normalized_completed = min(
                    normalized_total,
                    normalized_completed or 0,
                )
            else:
                normalized_completed = 0
            try:
                progress.update(
                    task_id,
                    description=self._safe_description(description),
                    completed=normalized_completed,
                    total=normalized_total,
                )
                self._total = normalized_total
            except Exception:
                pass

    def complete(self, description: object) -> None:
        """
        Mark the live task complete with a sanitized final description.

        Indeterminate tasks become a one-unit completed task so even a very
        fast operation leaves a truthful completed bar when ``transient`` is
        disabled.

        Args:
            description: Final operator-visible completion description.
        """

        with self._lock:
            progress = self._progress
            task_id = self._task_id
            if progress is None or task_id is None:
                return
            total = self._total if self._total is not None else 1
            try:
                progress.update(
                    task_id,
                    description=self._safe_description(description),
                    completed=total,
                    total=total,
                    refresh=True,
                )
            except Exception:
                pass

    def stop(self) -> None:
        """
        Stop and detach the owned Rich task without raising display errors.

        The task is detached before ``Progress.stop`` runs so a repeated stop
        or a failed Rich shutdown cannot operate on stale presentation state.
        The caller-owned console is never closed.
        """

        with self._lock:
            progress = self._progress
            self._progress = None
            self._task_id = None
            self._total = None
        if progress is not None:
            try:
                progress.stop()
            except Exception:
                pass

    def __enter__(self) -> "SanitizedOperationProgress":
        """
        Start and return this progress reporter for a managed scope.

        Entering delegates to the idempotent start boundary, leaving the
        operation itself under caller ownership.

        Returns:
            This reporter after its best-effort live task has started.
        """

        return self.start()

    def __exit__(self, *_: Any) -> None:
        """
        Stop the owned live task when the managed scope exits.

        The incoming exception details are ignored so the context manager never
        suppresses or replaces an operation failure.

        Args:
            _: Context-manager exception details, intentionally ignored because
                presentation never changes exception propagation.
        """

        self.stop()
