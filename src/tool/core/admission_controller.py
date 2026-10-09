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
Provide work-conserving weighted admission and adaptive concurrency control.

The controller owns every background task it creates, changes only the global
collector-operation budget, and leaves endpoint-local serialization to the
execution engine.  Conservative and fixed modes use the same weighted limiter
without starting the adaptive sampling task, which keeps their scheduling
policy stable while producing comparable evidence.
"""

from __future__ import annotations

import asyncio
import copy
import errno
import inspect
import math
import os
import re
import resource
import tempfile
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Deque, Mapping, Sequence

from ..utils.json_utils import safe_json_dump

ADMISSION_EVIDENCE_SCHEMA_VERSION = "1.3"
_CONCURRENCY_MODES = frozenset({"conservative", "fixed", "adaptive"})
_SAFE_LABEL_PATTERN = re.compile(r"[^a-z0-9_-]+")
_REMOTE_HTTP_PRESSURE_STATUSES = {429: "http_429", 503: "http_503"}
_REMOTE_TRANSPORT_RESET_ERRNOS = frozenset(
    {errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE}
)
_MAX_CLASSIFICATION_EXCEPTION_DEPTH = 8
_ADAPTIVE_SETTING_FIELDS = frozenset(
    {
        "sample_interval_seconds",
        "healthy_windows_required",
        "increase_step",
        "decrease_ratio",
        "hard_decrease_ratio",
        "cooldown_seconds",
        "endpoint_cooldown_seconds",
        "cpu_utilization_threshold",
        "process_memory_utilization_threshold",
        "cgroup_throttling_ratio_threshold",
        "memory_headroom_threshold",
        "file_descriptor_utilization_threshold",
        "pid_utilization_threshold",
        "event_loop_lag_threshold_seconds",
        "remote_throttle_rate_threshold",
        "remote_throttle_minimum_events",
        "remote_throttle_minimum_endpoints",
        "maximum_consecutive_sampler_errors",
        "maximum_resident_bytes",
        "maximum_decision_events",
    }
)


async def _run_in_owned_thread(
    function: Callable[..., Any],
    *args: Any,
) -> Any:
    """
    Run one bounded blocking operation in an explicitly joined worker thread.

    The default asyncio executor is intentionally avoided here.  Collection
    shutdown must not depend on process-global executor lifecycle, and the
    evidence writer needs an owned cleanup path even when its caller is
    cancelled while an atomic file replacement is in progress.

    Args:
        function: Synchronous callable that performs bounded local work.
        args: Positional values forwarded unchanged to ``function``.

    Returns:
        The callable's return value.

    Raises:
        BaseException: Any exception raised by the callable, after the worker
            has terminated and been joined.
        asyncio.CancelledError: After the worker has terminated if the caller
            is cancelled while the operation is active.

    Side effects:
        Starts and joins one non-daemon thread owned by this invocation.
    """

    completed = threading.Event()
    result: list[Any] = []
    failure: list[BaseException] = []

    def _worker() -> None:
        """
        Capture the blocking callable's result and always signal completion.

        The worker communicates through invocation-owned containers so the
        event-loop task can join it before propagating success or failure.
        """

        try:
            result.append(function(*args))
        except BaseException as error:
            failure.append(error)
        finally:
            completed.set()

    worker = threading.Thread(
        target=_worker,
        name="nvdebug-scheduler-evidence-writer",
        daemon=False,
    )
    worker.start()
    cancelled: asyncio.CancelledError | None = None
    while not completed.is_set():
        try:
            await asyncio.sleep(0.01)
        except asyncio.CancelledError as error:
            cancelled = error
    worker.join()
    if cancelled is not None:
        raise cancelled
    if failure:
        raise failure[0]
    return result[0] if result else None


def _utc_now() -> str:
    """
    Return the current UTC timestamp in canonical ISO 8601 form.

    Scheduler artifacts use one timezone-qualified representation so partial
    and final snapshots remain directly comparable.

    Returns:
        A timezone-qualified UTC timestamp ending in ``Z``.
    """

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_label(value: Any, fallback: str = "unknown") -> str:
    """
    Normalize a service or signal label before recording metadata.

    Evidence accepts only short governed identifiers and never preserves
    arbitrary endpoint names or diagnostic text.

    Args:
        value: Candidate governed label.
        fallback: Value returned when normalization removes every character.

    Returns:
        A lower-case identifier bounded to 64 characters.
    """

    normalized = _SAFE_LABEL_PATTERN.sub(
        "_", str(value or "").strip().lower().replace(" ", "_")
    ).strip("_")
    return (normalized or fallback)[:64]


def _strict_int(
    value: Any,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    """
    Validate a strict bounded integer from runtime configuration.

    Booleans are deliberately rejected even though Python treats them as
    integers, keeping operator-facing concurrency settings unambiguous.

    Args:
        value: Candidate configuration value.
        field_name: Operator-facing field name used in an error.
        minimum: Inclusive lower bound.
        maximum: Inclusive upper bound.

    Returns:
        The validated integer.

    Raises:
        ValueError: If the candidate is a boolean, non-integer, or outside the
            declared bounds.
    """

    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(
            f"execution.{field_name} must be an integer from {minimum} through "
            f"{maximum}"
        )
    return value


def _finite_float(
    value: Any,
    *,
    field_name: str,
    minimum: float,
    maximum: float,
) -> float:
    """
    Validate a finite numeric adaptive-controller setting.

    Normalization happens only after excluding booleans, and non-finite
    values cannot reach controller arithmetic or evidence serialization.

    Args:
        value: Candidate configuration value.
        field_name: Operator-facing field name used in an error.
        minimum: Inclusive lower bound.
        maximum: Inclusive upper bound.

    Returns:
        The validated floating-point value.

    Raises:
        ValueError: If the candidate is boolean, nonnumeric, nonfinite, or
            outside the declared bounds.
    """

    if isinstance(value, bool):
        raise ValueError(f"execution.adaptive.{field_name} must be numeric")
    try:
        normalized = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"execution.adaptive.{field_name} must be numeric") from error
    if not math.isfinite(normalized) or not minimum <= normalized <= maximum:
        raise ValueError(
            f"execution.adaptive.{field_name} must be from {minimum} through {maximum}"
        )
    return normalized


@dataclass(frozen=True)
class AdmissionControllerSettings:
    """
    Hold the fully resolved policy for one collector-admission controller.

    The immutable object is the common boundary between configuration
    precedence, runtime control, and the recorded scheduling evidence.

    Attributes:
        mode: Conservative, fixed, or opt-in adaptive behavior.
        minimum_limit: Smallest weighted capacity the controller may install.
        initial_limit: Capacity installed before collector tasks start.
        maximum_limit: Hard capacity ceiling for the run.
        sample_interval_seconds: Delay between pressure windows.
        healthy_windows_required: Consecutive healthy windows before increase.
        increase_step: Maximum additive increase in one healthy decision.
        decrease_ratio: Multiplier used for sustained non-hard pressure.
        hard_decrease_ratio: Multiplier used for immediate safety pressure.
        cooldown_seconds: Delay after a decrease before any increase.
        endpoint_cooldown_seconds: Per-endpoint pause after remote throttling.
        cpu_utilization_threshold: Process CPU pressure threshold.
        process_memory_utilization_threshold: Process RSS pressure threshold.
        cgroup_throttling_ratio_threshold: Cgroup throttled-period threshold.
        memory_headroom_threshold: Minimum acceptable bounded memory headroom.
        file_descriptor_utilization_threshold: Descriptor pressure threshold.
        pid_utilization_threshold: Cgroup task pressure threshold.
        event_loop_lag_threshold_seconds: Event-loop scheduling-lag threshold.
        remote_throttle_rate_threshold: Remote pressure events per operation.
        remote_throttle_minimum_events: Minimum events before global decrease.
        remote_throttle_minimum_endpoints: Distinct pressured endpoints needed
            before a remote signal may reduce the global budget.
        maximum_consecutive_sampler_errors: Consecutive transient observation
            failures tolerated before sampling stops.
        maximum_resident_bytes: Optional explicit process RSS fallback bound.
        maximum_decision_events: Evidence history bound.
    """

    mode: str
    minimum_limit: int
    initial_limit: int
    maximum_limit: int
    sample_interval_seconds: float
    healthy_windows_required: int
    increase_step: int
    decrease_ratio: float
    hard_decrease_ratio: float
    cooldown_seconds: float
    endpoint_cooldown_seconds: float
    cpu_utilization_threshold: float
    process_memory_utilization_threshold: float
    cgroup_throttling_ratio_threshold: float
    memory_headroom_threshold: float
    file_descriptor_utilization_threshold: float
    pid_utilization_threshold: float
    event_loop_lag_threshold_seconds: float
    remote_throttle_rate_threshold: float
    remote_throttle_minimum_events: int
    remote_throttle_minimum_endpoints: int
    maximum_consecutive_sampler_errors: int
    maximum_resident_bytes: int | None
    maximum_decision_events: int

    @classmethod
    def from_execution_config(
        cls,
        execution_config: Mapping[str, Any] | None,
        *,
        derived_initial_limit: int,
    ) -> "AdmissionControllerSettings":
        """
        Resolve validated controller policy from runtime execution config.

        Conservative and fixed modes collapse to a single installed limit;
        adaptive mode retains explicit minimum and maximum safety bounds.

        Args:
            execution_config: Canonical execution mapping produced by config
                precedence resolution.
            derived_initial_limit: Cgroup-aware CPU-derived collector limit.

        Returns:
            An immutable controller policy with explicit min, initial, and max.

        Raises:
            ValueError: If a mode or adaptive bound is invalid, adaptive mode
                lacks an explicit hard maximum, or min/max values conflict.
        """

        config = dict(execution_config or {})
        mode = str(config.get("concurrency_mode", "conservative")).strip().lower()
        if mode not in _CONCURRENCY_MODES:
            raise ValueError(
                "execution.concurrency_mode must be conservative, adaptive, or fixed"
            )

        derived = _strict_int(
            int(derived_initial_limit),
            field_name="derived_initial_limit",
            minimum=1,
            maximum=1_000_000,
        )
        raw_maximum = config.get("maximum_collector_operations")
        if mode == "adaptive" and raw_maximum is None:
            raise ValueError(
                "execution.maximum_collector_operations is required in adaptive mode"
            )
        maximum = (
            _strict_int(
                raw_maximum,
                field_name="maximum_collector_operations",
                minimum=1,
                maximum=4096,
            )
            if raw_maximum is not None
            else derived
        )
        initial = (
            maximum
            if mode == "fixed" and raw_maximum is not None
            else min(derived, maximum)
        )
        raw_minimum = config.get("minimum_collector_operations", 1)
        minimum = _strict_int(
            raw_minimum,
            field_name="minimum_collector_operations",
            minimum=1,
            maximum=4096,
        )
        if minimum > initial:
            raise ValueError(
                "execution.minimum_collector_operations cannot exceed the initial limit"
            )

        raw_adaptive = config.get("adaptive", {}) or {}
        if not isinstance(raw_adaptive, Mapping):
            raise ValueError("execution.adaptive must be a mapping")
        adaptive = dict(raw_adaptive)
        unknown_adaptive = sorted(
            str(key) for key in set(adaptive) - _ADAPTIVE_SETTING_FIELDS
        )
        if unknown_adaptive:
            raise ValueError(
                f"execution.adaptive contains unknown field {unknown_adaptive[0]!r}"
            )

        return cls(
            mode=mode,
            minimum_limit=minimum if mode == "adaptive" else initial,
            initial_limit=initial,
            maximum_limit=maximum if mode == "adaptive" else initial,
            sample_interval_seconds=_finite_float(
                adaptive.get("sample_interval_seconds", 20.0),
                field_name="sample_interval_seconds",
                minimum=10.0,
                maximum=30.0,
            ),
            healthy_windows_required=_strict_int(
                adaptive.get("healthy_windows_required", 3),
                field_name="adaptive.healthy_windows_required",
                minimum=1,
                maximum=100,
            ),
            increase_step=_strict_int(
                adaptive.get("increase_step", 8),
                field_name="adaptive.increase_step",
                minimum=1,
                maximum=256,
            ),
            decrease_ratio=_finite_float(
                adaptive.get("decrease_ratio", 0.75),
                field_name="decrease_ratio",
                minimum=0.5,
                maximum=0.75,
            ),
            hard_decrease_ratio=_finite_float(
                adaptive.get("hard_decrease_ratio", 0.5),
                field_name="hard_decrease_ratio",
                minimum=0.5,
                maximum=0.75,
            ),
            cooldown_seconds=_finite_float(
                adaptive.get("cooldown_seconds", 60.0),
                field_name="cooldown_seconds",
                minimum=0.0,
                maximum=3600.0,
            ),
            endpoint_cooldown_seconds=_finite_float(
                adaptive.get("endpoint_cooldown_seconds", 30.0),
                field_name="endpoint_cooldown_seconds",
                minimum=0.0,
                maximum=3600.0,
            ),
            cpu_utilization_threshold=_finite_float(
                adaptive.get("cpu_utilization_threshold", 0.90),
                field_name="cpu_utilization_threshold",
                minimum=0.1,
                maximum=1.0,
            ),
            process_memory_utilization_threshold=_finite_float(
                adaptive.get("process_memory_utilization_threshold", 0.90),
                field_name="process_memory_utilization_threshold",
                minimum=0.1,
                maximum=1.0,
            ),
            cgroup_throttling_ratio_threshold=_finite_float(
                adaptive.get("cgroup_throttling_ratio_threshold", 0.10),
                field_name="cgroup_throttling_ratio_threshold",
                minimum=0.0,
                maximum=1.0,
            ),
            memory_headroom_threshold=_finite_float(
                adaptive.get("memory_headroom_threshold", 0.10),
                field_name="memory_headroom_threshold",
                minimum=0.0,
                maximum=1.0,
            ),
            file_descriptor_utilization_threshold=_finite_float(
                adaptive.get("file_descriptor_utilization_threshold", 0.80),
                field_name="file_descriptor_utilization_threshold",
                minimum=0.1,
                maximum=1.0,
            ),
            pid_utilization_threshold=_finite_float(
                adaptive.get("pid_utilization_threshold", 0.90),
                field_name="pid_utilization_threshold",
                minimum=0.1,
                maximum=1.0,
            ),
            event_loop_lag_threshold_seconds=_finite_float(
                adaptive.get("event_loop_lag_threshold_seconds", 0.25),
                field_name="event_loop_lag_threshold_seconds",
                minimum=0.001,
                maximum=60.0,
            ),
            remote_throttle_rate_threshold=_finite_float(
                adaptive.get("remote_throttle_rate_threshold", 0.10),
                field_name="remote_throttle_rate_threshold",
                minimum=0.0,
                maximum=1.0,
            ),
            remote_throttle_minimum_events=_strict_int(
                adaptive.get("remote_throttle_minimum_events", 2),
                field_name="adaptive.remote_throttle_minimum_events",
                minimum=1,
                maximum=10_000,
            ),
            remote_throttle_minimum_endpoints=_strict_int(
                adaptive.get("remote_throttle_minimum_endpoints", 2),
                field_name="adaptive.remote_throttle_minimum_endpoints",
                minimum=1,
                maximum=10_000,
            ),
            maximum_consecutive_sampler_errors=_strict_int(
                adaptive.get("maximum_consecutive_sampler_errors", 3),
                field_name="adaptive.maximum_consecutive_sampler_errors",
                minimum=1,
                maximum=100,
            ),
            maximum_resident_bytes=(
                None
                if adaptive.get("maximum_resident_bytes") is None
                else _strict_int(
                    adaptive["maximum_resident_bytes"],
                    field_name="adaptive.maximum_resident_bytes",
                    minimum=1,
                    maximum=(1 << 63) - 1,
                )
            ),
            maximum_decision_events=_strict_int(
                adaptive.get("maximum_decision_events", 10_000),
                field_name="adaptive.maximum_decision_events",
                minimum=1,
                maximum=10_000,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Return the bounded public policy recorded in scheduler evidence.

        Thresholds are grouped separately from control-loop mechanics to keep
        the persisted artifact stable and straightforward to inspect.

        Returns:
            A JSON-safe mapping containing every resolved controller setting.
        """

        return {
            "mode": self.mode,
            "minimum_limit": self.minimum_limit,
            "initial_limit": self.initial_limit,
            "maximum_limit": self.maximum_limit,
            "sample_interval_seconds": self.sample_interval_seconds,
            "healthy_windows_required": self.healthy_windows_required,
            "increase_step": self.increase_step,
            "decrease_ratio": self.decrease_ratio,
            "hard_decrease_ratio": self.hard_decrease_ratio,
            "cooldown_seconds": self.cooldown_seconds,
            "endpoint_cooldown_seconds": self.endpoint_cooldown_seconds,
            "maximum_consecutive_sampler_errors": (
                self.maximum_consecutive_sampler_errors
            ),
            "maximum_resident_bytes": self.maximum_resident_bytes,
            "thresholds": {
                "cpu_utilization": self.cpu_utilization_threshold,
                "process_memory_utilization": (
                    self.process_memory_utilization_threshold
                ),
                "cgroup_throttling_ratio": self.cgroup_throttling_ratio_threshold,
                "memory_headroom": self.memory_headroom_threshold,
                "file_descriptor_utilization": (
                    self.file_descriptor_utilization_threshold
                ),
                "pid_utilization": self.pid_utilization_threshold,
                "event_loop_lag_seconds": self.event_loop_lag_threshold_seconds,
                "remote_throttle_rate": self.remote_throttle_rate_threshold,
                "remote_throttle_minimum_events": (self.remote_throttle_minimum_events),
                "remote_throttle_minimum_endpoints": (
                    self.remote_throttle_minimum_endpoints
                ),
            },
            "maximum_decision_events": self.maximum_decision_events,
        }


@dataclass
class AdmissionLease:
    """
    Own one weighted permit until its asynchronous release completes.

    Idempotent lease release lets nested cleanup paths safely return capacity
    without corrupting limiter accounting.

    Attributes:
        limiter: Limiter that owns capacity accounting for this lease.
        weight: Weighted capacity consumed by the admitted operation.
        wait_seconds: Queue duration measured before admission.
        released: Whether capacity has already been returned.
    """

    limiter: "WeightedResizableLimiter"
    weight: int
    wait_seconds: float
    released: bool = False

    async def release(self) -> None:
        """
        Return the lease exactly once and wake eligible queued operations.

        Side effects:
            Decrements limiter accounting and notifies queued waiters.
        """

        if self.released:
            return
        self.released = True
        await self.limiter.release(self.weight)


@dataclass
class _WeightedAdmissionWaiter:
    """
    Retain one bounded weighted-admission request while it is queued.

    The waiter contains only local scheduling state.  It deliberately carries
    no DUT, endpoint, collector, or service identity, so limiter metrics and
    cancellation cleanup cannot expose collection targets.

    Attributes:
        weight: Positive weighted capacity requested by the operation.
        queued_at: Monotonic timestamp captured before queue insertion.
        lease: Lease assigned synchronously when capacity is reserved, or
            ``None`` while the request remains queued.
    """

    weight: int
    queued_at: float
    lease: AdmissionLease | None = None


class WeightedResizableLimiter:
    """
    Admit weighted operations opportunistically under a resizable capacity.

    The oldest queued operation that fits is reserved immediately whenever
    capacity changes.  This preserves FIFO order among equally eligible work
    while allowing a lighter operation to backfill capacity that an older,
    heavier request cannot yet use.  Collection plans are finite, which bounds
    backfill delay for a heavy request without deliberately idling usable
    capacity.  Cancellation removes its queue entry, and reducing capacity
    never cancels already-admitted work.  A single overweight head waiter may
    run only when the limiter is otherwise idle; scheduling-plan validation
    normally rejects that fail-safe case before execution begins.

    Event-driven integrals distinguish saturation, unavoidable weight
    fragmentation, and time when runnable work could have used idle capacity.
    They require no polling task and therefore describe every concurrency mode.
    """

    def __init__(
        self,
        capacity: int,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Initialize capacity accounting and the oldest-fit waiter queue.

        All mutable state belongs to the event loop that constructs the
        limiter; the condition serializes admission and resizing decisions.

        Args:
            capacity: Initial positive weighted operation capacity.
            monotonic: Clock used for queue waits and utilization integrals.

        Raises:
            ValueError: If capacity is not a strict positive integer.
        """

        if type(capacity) is not int or capacity <= 0:
            raise ValueError("weighted limiter capacity must be a positive integer")
        self._capacity = capacity
        self._monotonic = monotonic
        self._condition = asyncio.Condition()
        self._waiters: Deque[_WeightedAdmissionWaiter] = deque()
        self._active_weight = 0
        self._active_operations = 0
        self._peak_active_weight = 0
        self._peak_active_operations = 0
        self._peak_queued_operations = 0
        self._backfilled_operations = 0
        self._last_accounted_monotonic = float(self._monotonic())
        self._queued_wall_seconds = 0.0
        self._queued_capacity_weight_seconds = 0.0
        self._queued_active_weight_seconds = 0.0
        self._queued_unused_weight_seconds = 0.0
        self._saturated_while_queued_seconds = 0.0
        self._runnable_gap_weight_seconds = 0.0
        self._fragmentation_weight_seconds = 0.0

    @property
    def capacity(self) -> int:
        """
        Return the currently installed weighted capacity.

        Capacity may change during adaptive execution while admitted work is
        allowed to drain naturally.

        Returns:
            The positive current capacity.
        """

        return self._capacity

    @property
    def active_weight(self) -> int:
        """
        Return weighted capacity currently owned by active operations.

        This value can temporarily exceed a newly reduced capacity because
        resizing never cancels already-admitted collectors.

        Returns:
            The nonnegative admitted weight.
        """

        return self._active_weight

    @property
    def active_operations(self) -> int:
        """
        Return the number of currently admitted collector operations.

        Operation count is tracked independently from weighted consumption so
        evidence can report both forms of utilization.

        Returns:
            The nonnegative active operation count.
        """

        return self._active_operations

    @property
    def queued_operations(self) -> int:
        """
        Return the number of operations waiting for weighted capacity.

        Queue length reflects only tasks awaiting global oldest-fit admission
        and excludes endpoint cooldown waits.

        Returns:
            The current oldest-fit queue length.
        """

        return len(self._waiters)

    async def acquire(self, weight: int = 1) -> AdmissionLease:
        """
        Queue and acquire one opportunistically backfilled weighted permit.

        Admission is reserved inside the limiter condition as soon as the
        oldest request that fits can use available capacity.  A request may
        therefore bypass older requests only when those requests cannot fit.
        The returned lease still has to be released by the caller's cleanup.

        Args:
            weight: Strict positive amount of shared capacity requested.

        Returns:
            A lease that must be released in the caller's ``finally`` path.

        Raises:
            ValueError: If weight is not a strict positive integer.
            asyncio.CancelledError: If the caller is cancelled while queued.
        """

        if type(weight) is not int or weight <= 0:
            raise ValueError("weighted limiter weight must be a positive integer")
        queued_at = float(self._monotonic())
        waiter = _WeightedAdmissionWaiter(weight=weight, queued_at=queued_at)
        async with self._condition:
            self._account_state(queued_at)
            immediately_fits = self._active_weight + weight <= self._capacity
            idle_forward_progress = self._active_operations == 0
            if not self._waiters and (immediately_fits or idle_forward_progress):
                admitted_at = self._account_state()
                return self._assign_lease_locked(waiter, admitted_at)
            self._waiters.append(waiter)
            admitted = self._admit_waiters_locked()
            self._peak_queued_operations = max(
                self._peak_queued_operations, len(self._waiters)
            )
            if admitted:
                self._condition.notify_all()
            try:
                while waiter.lease is None:
                    await self._condition.wait()
                return waiter.lease
            except BaseException:
                self._account_state()
                if waiter.lease is None:
                    try:
                        self._waiters.remove(waiter)
                    except ValueError:
                        pass
                elif not waiter.lease.released:
                    self._release_accounting_locked(waiter.weight)
                    waiter.lease.released = True
                admitted = self._admit_waiters_locked()
                if admitted:
                    self._condition.notify_all()
                raise

    def _assign_lease_locked(
        self,
        waiter: _WeightedAdmissionWaiter,
        admitted_at: float,
        *,
        backfilled: bool = False,
    ) -> AdmissionLease:
        """
        Reserve capacity and assign one lease while owning the condition.

        Immediate acquisitions and batched queue draining share this mutation
        path so active/peak accounting cannot diverge.  The caller establishes
        that the request either fits or is the idle overweight fail-safe.

        Args:
            waiter: Bounded request receiving the new lease.
            admitted_at: Finite monotonic admission timestamp.
            backfilled: Whether this request bypassed an older non-fitting one.

        Returns:
            The assigned lease, also stored on ``waiter`` for a queued task.

        Side effects:
            Updates active, peak, and optional backfill counters.
        """

        if backfilled:
            self._backfilled_operations += 1
        self._active_weight += waiter.weight
        self._active_operations += 1
        self._peak_active_weight = max(self._peak_active_weight, self._active_weight)
        self._peak_active_operations = max(
            self._peak_active_operations, self._active_operations
        )
        lease = AdmissionLease(
            limiter=self,
            weight=waiter.weight,
            wait_seconds=max(0.0, admitted_at - waiter.queued_at),
        )
        waiter.lease = lease
        return lease

    def _oldest_admissible_waiter_index(self) -> int | None:
        """
        Select the oldest queued request that can use current capacity.

        The normally unreachable overweight-head fail-safe is selected only
        when no operation is active.  Otherwise the scan returns the first
        fitting request and thereby performs oldest-fit backfilling.

        Returns:
            The deque index to admit, or ``None`` when no request can run.
        """

        if not self._waiters:
            return None
        if self._active_operations == 0 and self._waiters[0].weight > self._capacity:
            return 0
        available = self._capacity - self._active_weight
        if available <= 0:
            return None
        for index, waiter in enumerate(self._waiters):
            if waiter.weight <= available:
                return index
        return None

    def _admit_waiters_locked(self) -> int:
        """
        Reserve every currently usable permit before releasing the condition.

        The caller must own ``self._condition``.  Reserving all fitting work in
        one critical section removes release-to-reacquire scheduler gaps and
        avoids one notify cycle per newly available weighted unit.

        Returns:
            The number of queued operations assigned a lease.

        Side effects:
            Removes admitted waiters, updates aggregate utilization metrics,
            and assigns their leases for delivery after the condition wakes.
        """

        admitted = 0
        while True:
            index = self._oldest_admissible_waiter_index()
            if index is None:
                return admitted
            admitted_at = self._account_state()
            waiter = self._waiters[index]
            del self._waiters[index]
            self._assign_lease_locked(
                waiter,
                admitted_at,
                backfilled=index > 0,
            )
            admitted += 1

    def _release_accounting_locked(self, weight: int) -> None:
        """
        Validate and return active weighted capacity inside the condition.

        Keeping validation and mutation separate from waiter notification lets
        release and cancellation reuse the same atomic batched-admission path.

        Args:
            weight: Exact positive weight held by the releasing lease.

        Raises:
            RuntimeError: If release would make active accounting negative.

        Side effects:
            Decrements active operation and weight counters without notifying
            waiters; the caller subsequently performs one batched admission.
        """

        if (
            type(weight) is not int
            or weight <= 0
            or self._active_operations <= 0
            or self._active_weight < weight
        ):
            raise RuntimeError("weighted limiter release accounting mismatch")
        self._active_weight -= weight
        self._active_operations -= 1

    def _account_state(self, now: float | None = None) -> float:
        """
        Integrate the current aggregate queue state up to one monotonic time.

        Queue-only integrals avoid counting setup and finalization time when no
        collector is globally blocked.  Idle capacity is classified as either
        runnable gap (some queued request fits) or unavoidable fragmentation
        (every queued request is heavier than the remaining capacity).

        Args:
            now: Optional already-captured monotonic timestamp.

        Returns:
            The finite nondecreasing timestamp used for accounting.

        Side effects:
            Advances bounded duration and weighted-capacity accumulators.
        """

        candidate = float(self._monotonic()) if now is None else float(now)
        if not math.isfinite(candidate):
            candidate = self._last_accounted_monotonic
        current = max(self._last_accounted_monotonic, candidate)
        elapsed = current - self._last_accounted_monotonic
        if elapsed > 0 and self._waiters:
            capacity = float(self._capacity)
            used = float(min(self._capacity, max(0, self._active_weight)))
            unused = max(0.0, capacity - used)
            self._queued_wall_seconds += elapsed
            self._queued_capacity_weight_seconds += capacity * elapsed
            self._queued_active_weight_seconds += used * elapsed
            self._queued_unused_weight_seconds += unused * elapsed
            if used >= capacity:
                self._saturated_while_queued_seconds += elapsed
            elif any(waiter.weight <= unused for waiter in self._waiters):
                self._runnable_gap_weight_seconds += unused * elapsed
            else:
                self._fragmentation_weight_seconds += unused * elapsed
        self._last_accounted_monotonic = current
        return current

    async def release(self, weight: int) -> None:
        """
        Return capacity previously acquired by an admission lease.

        Release validates aggregate accounting, then reserves leases for every
        oldest-fit request that can use the newly available capacity.

        Args:
            weight: Exact positive weight held by the releasing lease.

        Raises:
            RuntimeError: If release would make active accounting negative.
        """

        async with self._condition:
            self._account_state()
            self._release_accounting_locked(weight)
            if self._admit_waiters_locked():
                self._condition.notify_all()

    async def set_capacity(self, capacity: int) -> None:
        """
        Install a new positive capacity without disturbing active work.

        Reductions take effect for future admissions; existing leases keep
        their capacity until their normal cleanup completes.

        Args:
            capacity: New weighted operation capacity.

        Raises:
            ValueError: If capacity is not a strict positive integer.
        """

        if type(capacity) is not int or capacity <= 0:
            raise ValueError("weighted limiter capacity must be a positive integer")
        async with self._condition:
            self._account_state()
            self._capacity = capacity
            if self._admit_waiters_locked():
                self._condition.notify_all()

    def metrics(self) -> dict[str, int | float | None]:
        """
        Return bounded current, peak, and work-conservation accounting.

        The snapshot contains aggregate counts only and therefore cannot leak
        DUT or endpoint identity into scheduler evidence.  Utilization ratios
        cover only wall time with at least one globally queued operation.

        Returns:
            A mapping containing capacity, active, queued, backfill, peak, and
            event-driven utilization values.
        """

        self._account_state()
        queued_capacity = self._queued_capacity_weight_seconds
        queued_wall = self._queued_wall_seconds
        utilization = (
            self._queued_active_weight_seconds / queued_capacity
            if queued_capacity > 0
            else None
        )
        saturation = (
            self._saturated_while_queued_seconds / queued_wall
            if queued_wall > 0
            else None
        )
        return {
            "capacity": self._capacity,
            "active_weight": self._active_weight,
            "active_operations": self._active_operations,
            "queued_operations": len(self._waiters),
            "peak_active_weight": self._peak_active_weight,
            "peak_active_operations": self._peak_active_operations,
            "peak_queued_operations": self._peak_queued_operations,
            "backfilled_operations": self._backfilled_operations,
            "queued_wall_seconds": round(self._queued_wall_seconds, 6),
            "queued_capacity_weight_seconds": round(queued_capacity, 6),
            "queued_active_weight_seconds": round(
                self._queued_active_weight_seconds, 6
            ),
            "queued_unused_weight_seconds": round(
                self._queued_unused_weight_seconds, 6
            ),
            "saturated_while_queued_seconds": round(
                self._saturated_while_queued_seconds, 6
            ),
            "runnable_gap_weight_seconds": round(self._runnable_gap_weight_seconds, 6),
            "fragmentation_weight_seconds": round(
                self._fragmentation_weight_seconds, 6
            ),
            "utilization_while_queued_ratio": (
                round(utilization, 6) if utilization is not None else None
            ),
            "saturation_while_queued_ratio": (
                round(saturation, 6) if saturation is not None else None
            ),
        }


@dataclass(frozen=True)
class PressureSample:
    """
    Represent one sanitized local and remote adaptive pressure window.

    Every field is numeric or a governed signal label.  Missing measurements
    remain ``None`` and therefore cannot independently authorize an increase.

    Attributes:
        timestamp: UTC sampling timestamp.
        event_loop_lag_seconds: Delay beyond the scheduled sampling deadline.
        cpu_utilization: Process CPU use divided by effective CPU capacity.
        process_memory_utilization: Process RSS divided by the smallest known
            finite process/cgroup memory bound.
        cgroup_throttling_ratio: Fraction of elapsed periods throttled.
        memory_headroom_ratio: Smallest known limited-cgroup memory headroom.
        file_descriptor_utilization: Open descriptors divided by soft limit.
        pid_utilization: Smallest known task-limit utilization ratio.
        cgroup_oom_events: New OOM or OOM-kill events in the window.
        completed_operations: Collector operations completed in the window.
        remote_events: Governed remote-pressure event counts.
        transport_latency_p95_seconds: P95 completed operation duration.
        pressured_endpoints: Distinct endpoint keys with remote pressure.
        seen_endpoints: Distinct endpoint keys completing work in the window.
    """

    timestamp: str
    event_loop_lag_seconds: float
    cpu_utilization: float | None
    cgroup_throttling_ratio: float | None
    memory_headroom_ratio: float | None
    file_descriptor_utilization: float | None
    pid_utilization: float | None
    cgroup_oom_events: int
    completed_operations: int
    remote_events: Mapping[str, int]
    transport_latency_p95_seconds: float | None
    process_memory_utilization: float | None = None
    pressured_endpoints: int = 0
    seen_endpoints: int = 0

    def to_dict(self) -> dict[str, Any]:
        """
        Return the bounded representation embedded in decision evidence.

        Numeric normalization and sorted event labels make repeated local
        runs deterministic apart from expected timing measurements.

        Returns:
            A JSON-safe mapping containing every pressure measurement.
        """

        return {
            "timestamp": self.timestamp,
            "event_loop_lag_seconds": round(self.event_loop_lag_seconds, 6),
            "cpu_utilization": self.cpu_utilization,
            "process_memory_utilization": self.process_memory_utilization,
            "cgroup_throttling_ratio": self.cgroup_throttling_ratio,
            "memory_headroom_ratio": self.memory_headroom_ratio,
            "file_descriptor_utilization": self.file_descriptor_utilization,
            "pid_utilization": self.pid_utilization,
            "cgroup_oom_events": self.cgroup_oom_events,
            "completed_operations": self.completed_operations,
            "remote_events": dict(sorted(self.remote_events.items())),
            "transport_latency_p95_seconds": self.transport_latency_p95_seconds,
            "pressured_endpoints": self.pressured_endpoints,
            "seen_endpoints": self.seen_endpoints,
        }


class RemotePressureWindow:
    """
    Accumulate bounded transport outcomes between adaptive samples.

    The object is mutated only by tasks on the owning event loop.  Snapshotting
    resets the window atomically with respect to cooperative task scheduling
    because the method contains no await point.
    """

    def __init__(self) -> None:
        """
        Initialize empty operation, event, and latency counters.

        The counters are window-local and retain no collector result bodies or
        endpoint identifiers in emitted evidence.
        """

        self._completed_operations = 0
        self._events: Counter[str] = Counter()
        self._durations: list[float] = []
        self._pressured_endpoints: set[str] = set()
        self._seen_endpoints: set[str] = set()

    def record_operation(
        self,
        *,
        duration_seconds: float,
        remote_events: Sequence[str],
        endpoint_key: str = "unknown",
    ) -> None:
        """
        Record one terminal collector outcome in the current window.

        Durations and classified reason labels are sufficient for pressure
        decisions; raw errors and response content are intentionally omitted.

        Args:
            duration_seconds: Finite nonnegative active collector duration.
            remote_events: Governed event labels found in the result or error.
            endpoint_key: In-memory DUT/service identity used only for distinct
                endpoint counting; it is never copied into evidence.

        Side effects:
            Increments bounded counters and retains at most 10,000 durations.
        """

        self._completed_operations += 1
        if len(self._seen_endpoints) < 10_000:
            self._seen_endpoints.add(str(endpoint_key)[:512])
        if math.isfinite(duration_seconds) and duration_seconds >= 0:
            if len(self._durations) < 10_000:
                self._durations.append(duration_seconds)
        if remote_events:
            # One completed operation contributes at most one unit of global
            # remote pressure even when its result matches several patterns.
            self._events[_safe_label(remote_events[0])] += 1
            if len(self._pressured_endpoints) < 10_000:
                self._pressured_endpoints.add(str(endpoint_key)[:512])

    def snapshot_and_reset(
        self,
    ) -> tuple[int, dict[str, int], float | None, int, int]:
        """
        Return current counters and begin a fresh pressure window.

        Snapshot and reset execute without an await point, making the window
        transition atomic under cooperative event-loop scheduling.

        Returns:
            A tuple of completed operations, event counts, P95 duration,
            distinct pressured endpoints, and distinct seen endpoints.
        """

        operations = self._completed_operations
        events = dict(sorted(self._events.items()))
        durations = sorted(self._durations)
        latency_p95 = None
        if durations:
            index = max(0, math.ceil(0.95 * len(durations)) - 1)
            latency_p95 = round(durations[index], 6)
        pressured_endpoints = len(self._pressured_endpoints)
        seen_endpoints = len(self._seen_endpoints)
        self._completed_operations = 0
        self._events.clear()
        self._durations = []
        self._pressured_endpoints.clear()
        self._seen_endpoints.clear()
        return (
            operations,
            events,
            latency_p95,
            pressured_endpoints,
            seen_endpoints,
        )


class RuntimePressureSampler:
    """
    Convert resource-monitor snapshots into adaptive pressure measurements.

    The sampler never initiates a remote probe.  It reuses the local proc and
    cgroup readers owned by ``ResourceUsageMonitor`` and combines them with
    collector outcomes already observed by the execution engine.
    """

    def __init__(
        self,
        resource_monitor: Any,
        *,
        effective_cpus: float,
        remote_window: RemotePressureWindow,
        maximum_resident_bytes: int | None = None,
    ) -> None:
        """
        Initialize prior-sample state and resource providers.

        The first captured sample establishes counter baselines, so delta
        measurements remain unavailable until a subsequent window.

        Args:
            resource_monitor: Existing run-owned monitor exposing a scheduler
                snapshot method or current sample fallback.
            effective_cpus: Positive cgroup-aware CPU capacity.
            remote_window: Collector-outcome counters shared with execution.
            maximum_resident_bytes: Optional operator-authorized RSS bound used
                only when no finite OS or cgroup memory bound is visible.
        """

        self._resource_monitor = resource_monitor
        self._effective_cpus = max(float(effective_cpus), 0.001)
        self._remote_window = remote_window
        self._maximum_resident_bytes = maximum_resident_bytes
        self._previous: Mapping[str, Any] | None = None

    async def sample(self, event_loop_lag_seconds: float) -> PressureSample:
        """
        Capture one local snapshot and combine it with the remote window.

        Resource capture is local-only and unavailable measurements remain
        unknown instead of being interpreted as healthy.

        Args:
            event_loop_lag_seconds: Nonnegative delay beyond the scheduled
                sampling deadline.

        Returns:
            A sanitized pressure sample.  Unavailable local metrics are
            represented as ``None`` rather than guessed.
        """

        current: Mapping[str, Any] = {}
        monitor = self._resource_monitor
        capture = getattr(monitor, "capture_scheduler_sample", None)
        if callable(capture):
            value = capture()
            current = await value if inspect.isawaitable(value) else value
        elif monitor is not None:
            latest = getattr(monitor, "latest_sample", None)
            if callable(latest):
                current = latest()
        if not isinstance(current, Mapping):
            current = {}

        (
            operations,
            events,
            latency_p95,
            pressured_endpoints,
            seen_endpoints,
        ) = self._remote_window.snapshot_and_reset()
        cpu_utilization = self._cpu_utilization(current, self._previous)
        process_memory_utilization = self._process_memory_utilization(current)
        throttling_ratio = self._throttling_ratio(current, self._previous)
        memory_headroom, pid_utilization, oom_events = self._cgroup_pressure(
            current, self._previous
        )
        fd_utilization = self._fd_utilization(current)
        self._previous = current
        return PressureSample(
            timestamp=_utc_now(),
            event_loop_lag_seconds=max(0.0, float(event_loop_lag_seconds)),
            cpu_utilization=cpu_utilization,
            cgroup_throttling_ratio=throttling_ratio,
            memory_headroom_ratio=memory_headroom,
            file_descriptor_utilization=fd_utilization,
            pid_utilization=pid_utilization,
            cgroup_oom_events=oom_events,
            completed_operations=operations,
            remote_events=events,
            transport_latency_p95_seconds=latency_p95,
            process_memory_utilization=process_memory_utilization,
            pressured_endpoints=pressured_endpoints,
            seen_endpoints=seen_endpoints,
        )

    def _process_memory_utilization(
        self,
        current: Mapping[str, Any],
    ) -> float | None:
        """
        Normalize current process RSS by the smallest trustworthy bound.

        A finite ``RLIMIT_AS`` or cgroup memory limit is authoritative.  The
        configured maximum is consulted only when both operating-system
        sources are unavailable, so an optimistic operator value cannot hide
        a stricter live bound.

        Args:
            current: Current resource-monitor snapshot containing process and
                optional cgroup measurements.

        Returns:
            A nonnegative RSS utilization ratio, or ``None`` when RSS or every
            finite memory bound is unavailable.
        """

        process = current.get("process", {})
        rss_bytes = process.get("rss_bytes") if isinstance(process, Mapping) else None
        if type(rss_bytes) is not int or rss_bytes < 0:  # noqa: E721 - reject bool
            return None

        bounds: list[int] = []
        try:
            soft_limit, _ = resource.getrlimit(resource.RLIMIT_AS)
        except (OSError, ValueError):
            soft_limit = resource.RLIM_INFINITY
        if (
            type(soft_limit) is int  # noqa: E721 - reject unusual numeric wrappers
            and soft_limit > 0
            and soft_limit != resource.RLIM_INFINITY
        ):
            bounds.append(soft_limit)

        for scope in self._scope_map(current).values():
            memory = scope.get("memory", {})
            limit = memory.get("limit", {}) if isinstance(memory, Mapping) else {}
            value = limit.get("value") if isinstance(limit, Mapping) else None
            if type(value) is int and value > 0:  # noqa: E721 - reject bool
                bounds.append(value)

        if not bounds and self._maximum_resident_bytes is not None:
            bounds.append(self._maximum_resident_bytes)
        if not bounds:
            return None
        return round(max(0.0, rss_bytes / min(bounds)), 6)

    def _cpu_utilization(
        self,
        current: Mapping[str, Any],
        previous: Mapping[str, Any] | None,
    ) -> float | None:
        """
        Calculate process CPU utilization across two local samples.

        CPU-time deltas are normalized by elapsed monotonic time and the
        cgroup-aware effective CPU capacity selected for the run.

        Args:
            current: Current resource-monitor snapshot.
            previous: Prior snapshot, or ``None`` for the first window.

        Returns:
            CPU utilization from zero upward, or ``None`` without two valid
            counter snapshots.
        """

        if not previous:
            return None
        current_elapsed = current.get("elapsed_seconds")
        previous_elapsed = previous.get("elapsed_seconds")
        if not isinstance(current_elapsed, (int, float)) or not isinstance(
            previous_elapsed, (int, float)
        ):
            return None
        elapsed = float(current_elapsed) - float(previous_elapsed)
        if elapsed <= 0:
            return None
        current_process = current.get("process", {})
        previous_process = previous.get("process", {})
        if not isinstance(current_process, Mapping) or not isinstance(
            previous_process, Mapping
        ):
            return None
        names = (
            "user_cpu_seconds",
            "system_cpu_seconds",
            "completed_children_user_cpu_seconds",
            "completed_children_system_cpu_seconds",
        )
        total_delta = 0.0
        observed = False
        for name in names:
            first = previous_process.get(name)
            last = current_process.get(name)
            if isinstance(first, (int, float)) and isinstance(last, (int, float)):
                total_delta += max(0.0, float(last) - float(first))
                observed = True
        if not observed:
            return None
        return round(max(0.0, total_delta / elapsed / self._effective_cpus), 6)

    @staticmethod
    def _scope_map(sample: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
        """
        Index cgroup scopes from one resource-monitor sample.

        A bounded controller-and-path key pairs counters across consecutive
        snapshots without exposing those keys in public evidence.

        Args:
            sample: Resource-monitor snapshot containing optional cgroup scopes.

        Returns:
            A mapping from bounded controller/path identity to scope data.
        """

        result: dict[str, Mapping[str, Any]] = {}
        cgroup = sample.get("cgroup", {})
        scopes = cgroup.get("scopes", []) if isinstance(cgroup, Mapping) else []
        if not isinstance(scopes, Sequence):
            return result
        for scope in scopes:
            if not isinstance(scope, Mapping):
                continue
            key = f"{scope.get('controller')}:{scope.get('path')}"
            result[key[:512]] = scope
        return result

    @classmethod
    def _throttling_ratio(
        cls,
        current: Mapping[str, Any],
        previous: Mapping[str, Any] | None,
    ) -> float | None:
        """
        Calculate the largest cgroup throttled-period ratio in the window.

        Only comparable scope counters contribute, avoiding false pressure
        decisions when a cgroup hierarchy changes between samples.

        Args:
            current: Current resource-monitor snapshot.
            previous: Prior snapshot, or ``None`` for the first window.

        Returns:
            Largest observed ratio, or ``None`` without comparable counters.
        """

        if not previous:
            return None
        prior_scopes = cls._scope_map(previous)
        ratios: list[float] = []
        for key, scope in cls._scope_map(current).items():
            prior = prior_scopes.get(key)
            if not prior:
                continue
            current_stat = scope.get("cpu", {}).get("stat", {})
            prior_stat = prior.get("cpu", {}).get("stat", {})
            if not isinstance(current_stat, Mapping) or not isinstance(
                prior_stat, Mapping
            ):
                continue
            periods = current_stat.get("nr_periods")
            prior_periods = prior_stat.get("nr_periods")
            throttled = current_stat.get("nr_throttled")
            prior_throttled = prior_stat.get("nr_throttled")
            if not all(
                isinstance(value, int)
                for value in (
                    periods,
                    prior_periods,
                    throttled,
                    prior_throttled,
                )
            ):
                continue
            period_delta = periods - prior_periods
            if period_delta > 0:
                ratios.append(max(0.0, (throttled - prior_throttled) / period_delta))
        return round(max(ratios), 6) if ratios else None

    @classmethod
    def _cgroup_pressure(
        cls,
        current: Mapping[str, Any],
        previous: Mapping[str, Any] | None,
    ) -> tuple[float | None, float | None, int]:
        """
        Derive memory headroom, PID utilization, and new OOM events.

        The most constrained finite scope governs headroom and utilization,
        while OOM counters are reported only as nonnegative deltas.

        Args:
            current: Current resource-monitor snapshot.
            previous: Prior snapshot, or ``None`` for the first window.

        Returns:
            A tuple containing minimum memory headroom, maximum PID utilization,
            and nonnegative new OOM event count.
        """

        prior_scopes = cls._scope_map(previous or {})
        headrooms: list[float] = []
        pid_ratios: list[float] = []
        oom_events = 0
        for key, scope in cls._scope_map(current).items():
            memory = scope.get("memory", {})
            if isinstance(memory, Mapping):
                current_bytes = memory.get("current_bytes")
                limit = memory.get("limit", {})
                limit_value = limit.get("value") if isinstance(limit, Mapping) else None
                if (
                    isinstance(current_bytes, int)
                    and isinstance(limit_value, int)
                    and limit_value > 0
                ):
                    headrooms.append(
                        max(
                            0.0,
                            min(
                                1.0,
                                (limit_value - current_bytes) / limit_value,
                            ),
                        )
                    )
                events = memory.get("events", {})
                prior_memory = prior_scopes.get(key, {}).get("memory", {})
                prior_events = (
                    prior_memory.get("events", {})
                    if isinstance(prior_memory, Mapping)
                    else {}
                )
                if isinstance(events, Mapping) and isinstance(prior_events, Mapping):
                    for name in ("oom", "oom_kill"):
                        value = events.get(name)
                        prior_value = prior_events.get(name)
                        if isinstance(value, int) and isinstance(prior_value, int):
                            oom_events += max(0, value - prior_value)

            pids = scope.get("pids", {})
            if isinstance(pids, Mapping):
                current_pids = pids.get("current")
                limit = pids.get("limit", {})
                limit_value = limit.get("value") if isinstance(limit, Mapping) else None
                if (
                    isinstance(current_pids, int)
                    and isinstance(limit_value, int)
                    and limit_value > 0
                ):
                    pid_ratios.append(max(0.0, current_pids / limit_value))
        return (
            round(min(headrooms), 6) if headrooms else None,
            round(max(pid_ratios), 6) if pid_ratios else None,
            oom_events,
        )

    @staticmethod
    def _fd_utilization(current: Mapping[str, Any]) -> float | None:
        """
        Calculate process descriptor utilization against its soft limit.

        Infinite, invalid, or unavailable limits produce an unknown signal so
        they cannot independently authorize a concurrency increase.

        Args:
            current: Current resource-monitor snapshot.

        Returns:
            Utilization ratio, or ``None`` when either counter is unavailable.
        """

        process = current.get("process", {})
        open_fds = process.get("open_fds") if isinstance(process, Mapping) else None
        if not isinstance(open_fds, int):
            return None
        try:
            soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        except (OSError, ValueError):
            return None
        if soft_limit <= 0 or soft_limit == resource.RLIM_INFINITY:
            return None
        return round(max(0.0, open_fds / soft_limit), 6)


class SchedulerEvidenceRecorder:
    """
    Persist bounded explainability evidence for one scheduling run.

    Admission events are aggregated rather than emitted individually.  Limit
    decisions retain sanitized numeric samples in a bounded deque.  Atomic
    snapshots are written at start, on decisions, and at finalization so an
    interrupted run retains the last complete scheduler state.
    """

    def __init__(
        self,
        output_path: Path | str,
        *,
        settings: AdmissionControllerSettings,
        plan_summary: Mapping[str, Any],
    ) -> None:
        """
        Initialize bounded counters and immutable run context.

        The plan is deep-copied at construction so later workflow mutations
        cannot race with evidence serialization.

        Args:
            output_path: Metadata artifact path owned by the current run.
            settings: Fully resolved controller policy.
            plan_summary: Deterministic scheduling summary.
        """

        self.output_path = Path(output_path)
        self.settings = settings
        self.plan_summary = copy.deepcopy(dict(plan_summary))
        self.status = "not_started"
        self.started_at: str | None = None
        self.completed_at: str | None = None
        self.final_limit = settings.initial_limit
        self._decisions: Deque[dict[str, Any]] = deque(
            maxlen=settings.maximum_decision_events
        )
        self._decisions_total = 0
        self._admissions = 0
        self._releases = 0
        self._wait_seconds_total = 0.0
        self._wait_seconds_max = 0.0
        self._active_seconds_total = 0.0
        self._active_seconds_max = 0.0
        self._active_seconds_by_service: defaultdict[str, float] = defaultdict(float)
        self._completed_by_service: Counter[str] = Counter()
        self._active_by_service: Counter[str] = Counter()
        self._peak_by_service: Counter[str] = Counter()
        self._remote_events: Counter[str] = Counter()
        self._endpoint_cooldowns: Counter[str] = Counter()

    def record_admission(self, service: str, wait_seconds: float) -> None:
        """
        Aggregate one admitted operation without retaining endpoint identity.

        Only a governed service label and timing totals are retained, keeping
        evidence useful without revealing DUT-specific data.

        Args:
            service: Governed service lane label.
            wait_seconds: Nonnegative time spent waiting for global capacity.
        """

        safe_service = _safe_label(service)
        wait = max(0.0, float(wait_seconds))
        self._admissions += 1
        self._wait_seconds_total += wait
        self._wait_seconds_max = max(self._wait_seconds_max, wait)
        self._active_by_service[safe_service] += 1
        self._peak_by_service[safe_service] = max(
            self._peak_by_service[safe_service],
            self._active_by_service[safe_service],
        )

    def record_release(self, service: str, active_seconds: float = 0.0) -> None:
        """
        Record active time and decrement accounting after collector cleanup.

        Invalid duration inputs are conservatively normalized to zero while
        completion accounting and active-service cleanup still proceed.

        Args:
            service: Governed service lane label used during admission.
            active_seconds: Finite nonnegative time spent holding global
                capacity, including collector-owned cleanup.
        """

        safe_service = _safe_label(service)
        try:
            duration = float(active_seconds)
        except (TypeError, ValueError, OverflowError):
            duration = 0.0
        if not math.isfinite(duration) or duration < 0:
            duration = 0.0
        self._releases += 1
        self._active_seconds_total += duration
        self._active_seconds_max = max(self._active_seconds_max, duration)
        self._active_seconds_by_service[safe_service] += duration
        self._completed_by_service[safe_service] += 1
        if self._active_by_service[safe_service] > 0:
            self._active_by_service[safe_service] -= 1

    def record_remote_events(self, service: str, events: Sequence[str]) -> None:
        """
        Aggregate classified remote-pressure events by safe service and kind.

        Result bodies and arbitrary error strings never cross this evidence
        boundary; only classifier-owned reason codes are counted.

        Args:
            service: Governed service lane label.
            events: Governed event labels produced by bounded classification.
        """

        safe_service = _safe_label(service)
        for event in events:
            self._remote_events[f"{safe_service}:{_safe_label(event)}"] += 1

    def record_endpoint_cooldown(self, service: str, event: str) -> None:
        """
        Count an endpoint cooldown without recording the endpoint key.

        Aggregation by service and governed reason preserves operator insight
        while endpoint identities remain confined to the in-memory registry.

        Args:
            service: Governed service lane label.
            event: Governed remote-pressure reason.
        """

        self._endpoint_cooldowns[f"{_safe_label(service)}:{_safe_label(event)}"] += 1

    def record_decision(
        self,
        *,
        action: str,
        previous_limit: int,
        new_limit: int,
        reasons: Sequence[str],
        sample: PressureSample | None,
        monotonic_seconds: float,
        limiter: WeightedResizableLimiter | None = None,
    ) -> None:
        """
        Append one bounded concurrency decision to the retained history.

        Total and retained counts are tracked separately so truncation remains
        explicit when a long run reaches its configured evidence bound.

        Args:
            action: Governed increase, decrease, hold, start, or stop label.
            previous_limit: Capacity installed before the decision.
            new_limit: Capacity installed after the decision.
            reasons: Governed reason codes explaining the decision.
            sample: Pressure sample used for the decision, when applicable.
            monotonic_seconds: Nonnegative controller-relative timestamp.
            limiter: Optional live limiter used to attach aggregate progress
                and demand state without retaining endpoint identity.
        """

        self._decisions_total += 1
        self.final_limit = new_limit
        self._decisions.append(
            {
                "timestamp": _utc_now(),
                "elapsed_seconds": round(max(0.0, monotonic_seconds), 6),
                "action": _safe_label(action),
                "previous_limit": previous_limit,
                "new_limit": new_limit,
                "reasons": [_safe_label(reason) for reason in reasons[:32]],
                "signals": sample.to_dict() if sample is not None else None,
                "progress": {
                    "admissions": self._admissions,
                    "completed_operations": self._releases,
                    "limiter": (limiter.metrics() if limiter is not None else None),
                },
            }
        )

    def build_payload(self, limiter: WeightedResizableLimiter) -> dict[str, Any]:
        """
        Build the complete JSON-safe evidence payload.

        The detached aggregate snapshot contains bounded policy, decisions,
        timings, and pressure counts without per-endpoint records.

        Args:
            limiter: Limiter supplying current and peak admission accounting.

        Returns:
            A bounded mapping suitable for atomic serialization.
        """

        average_wait = (
            self._wait_seconds_total / self._admissions if self._admissions else 0.0
        )
        average_active = (
            self._active_seconds_total / self._releases if self._releases else 0.0
        )
        active_by_service = {
            service: {
                "completed_operations": self._completed_by_service[service],
                "active_seconds_total": round(total, 6),
                "active_seconds_average": round(
                    total / self._completed_by_service[service], 6
                ),
            }
            for service, total in sorted(self._active_seconds_by_service.items())
            if self._completed_by_service[service]
        }
        return {
            "schema_version": ADMISSION_EVIDENCE_SCHEMA_VERSION,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "settings": self.settings.to_dict(),
            "plan_summary": self.plan_summary,
            "decisions": list(self._decisions),
            "decision_accounting": {
                "total": self._decisions_total,
                "retained": len(self._decisions),
                "dropped": self._decisions_total - len(self._decisions),
            },
            "operation_metrics": {
                "admissions": self._admissions,
                "queue_wait_seconds_total": round(self._wait_seconds_total, 6),
                "queue_wait_seconds_average": round(average_wait, 6),
                "queue_wait_seconds_max": round(self._wait_seconds_max, 6),
                "completed_operations": self._releases,
                "active_seconds_total": round(self._active_seconds_total, 6),
                "active_seconds_average": round(average_active, 6),
                "active_seconds_max": round(self._active_seconds_max, 6),
                "active_time_by_service": active_by_service,
                "peak_active_operations_by_service": dict(
                    sorted(self._peak_by_service.items())
                ),
                "limiter": limiter.metrics(),
            },
            "remote_pressure_events": dict(sorted(self._remote_events.items())),
            "endpoint_cooldowns": dict(sorted(self._endpoint_cooldowns.items())),
            "final_limit": self.final_limit,
        }

    def write(self, limiter: WeightedResizableLimiter) -> None:
        """
        Atomically persist the current scheduler evidence snapshot.

        This synchronous convenience path first detaches live counters, then
        delegates to the same atomic serializer used by the controller.

        Args:
            limiter: Limiter supplying current and peak accounting.

        Raises:
            OSError: If the owned metadata directory or atomic replace cannot
                be written.
        """

        self.write_payload(self.build_payload(limiter))

    def write_payload(self, payload: Mapping[str, Any]) -> None:
        """
        Atomically persist a detached scheduler evidence payload.

        Building the payload on the event-loop thread prevents concurrent
        admission counters from changing while a worker serializes it.

        Args:
            payload: Complete JSON-safe evidence snapshot detached from live
                controller counters.

        Raises:
            OSError: If the owned metadata directory or atomic replace cannot
                be written.
        """

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.output_path.name}.",
            suffix=".tmp",
            dir=self.output_path.parent,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                safe_json_dump(payload, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, self.output_path)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise


class EndpointCooldownRegistry:
    """
    Pause only a throttled endpoint before its next collector operation.

    Endpoint keys remain in memory and are never written to scheduler evidence.
    Expired entries are removed opportunistically so storage remains bounded by
    the number of endpoints active in the current run.
    """

    def __init__(
        self,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """
        Initialize the deadline map and injectable timing functions.

        Injectable clocks make expiry behavior deterministic in unit tests and
        keep production waits cancellation-aware.

        Args:
            monotonic: Clock used for deadline comparisons.
            sleep: Cancellation-aware delay used while a cooldown remains.
        """

        self._monotonic = monotonic
        self._sleep = sleep
        self._deadlines: dict[tuple[str, str], float] = {}

    def impose(self, dut_id: str, service: str, duration_seconds: float) -> None:
        """
        Extend one endpoint's cooldown deadline.

        Repeated throttling can only move the deadline later, preventing a
        shorter subsequent event from prematurely reopening the endpoint.

        Args:
            dut_id: In-memory endpoint owner identity.
            service: In-memory service lane identity.
            duration_seconds: Nonnegative bounded cooldown duration.
        """

        if duration_seconds <= 0:
            return
        key = (str(dut_id), _safe_label(service))
        deadline = self._monotonic() + duration_seconds
        self._deadlines[key] = max(deadline, self._deadlines.get(key, 0.0))

    async def wait(self, dut_id: str, service: str) -> None:
        """
        Wait until one endpoint cooldown expires without holding global capacity.

        The wait occurs before admission so a throttled endpoint cannot consume
        weighted global capacity while it is intentionally paused.

        Args:
            dut_id: In-memory endpoint owner identity.
            service: In-memory service lane identity.

        Raises:
            asyncio.CancelledError: If collection is cancelled during cooldown.
        """

        key = (str(dut_id), _safe_label(service))
        while True:
            deadline = self._deadlines.get(key)
            if deadline is None:
                return
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                self._deadlines.pop(key, None)
                return
            await self._sleep(remaining)


class AdaptiveAdmissionController:
    """
    Observe one weighted limiter and apply AIMD only in adaptive mode.

    Every mode records bounded periodic pressure and progress snapshots so the
    report can explain utilization over time.  In adaptive mode, decreases
    occur on any hard safety signal or sustained remote/local pressure, while
    increases require several windows with at least two observable healthy
    signals.  Fixed and conservative modes never alter their installed limit.
    """

    def __init__(
        self,
        *,
        settings: AdmissionControllerSettings,
        limiter: WeightedResizableLimiter,
        sampler: RuntimePressureSampler,
        evidence: SchedulerEvidenceRecorder,
        log_callback: Callable[[str, str], Awaitable[None]] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        demand_observer: Callable[[], bool] | None = None,
    ) -> None:
        """
        Initialize controller state without starting background work.

        Task creation is deferred to :meth:`start` so workflow setup can fail
        cleanly before any adaptive background activity exists.

        Args:
            settings: Fully resolved adaptive policy.
            limiter: Run-owned weighted collector limiter.
            sampler: Local and remote pressure provider.
            evidence: Bounded scheduler artifact recorder.
            log_callback: Optional sanitized asynchronous logger.
            monotonic: Clock used for cooldown and elapsed evidence.
            demand_observer: Optional bounded callback reporting whether work
                is queued behind the installed global capacity. Production
                defaults to the run-owned limiter queue.
        """

        self.settings = settings
        self.limiter = limiter
        self.sampler = sampler
        self.evidence = evidence
        self._log_callback = log_callback
        self._monotonic = monotonic
        self._demand_observer = demand_observer
        self._started_monotonic: float | None = None
        self._cooldown_until = 0.0
        self._healthy_windows = 0
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """
        Persist initial evidence and start the owned observation sampler.

        Side effects:
            Creates at most one owned background task in every scheduler mode.
        """

        if self.evidence.status != "not_started":
            return
        self.evidence.status = "running"
        self.evidence.started_at = _utc_now()
        self._started_monotonic = self._monotonic()
        self.evidence.record_decision(
            action="start",
            previous_limit=self.limiter.capacity,
            new_limit=self.limiter.capacity,
            reasons=[f"mode_{self.settings.mode}"],
            sample=None,
            monotonic_seconds=0.0,
            limiter=self.limiter,
        )
        await self._persist_evidence()
        self._task = asyncio.create_task(
            self._run(), name="nvdebug-admission-controller"
        )

    async def stop(self, *, interrupted: bool = False) -> None:
        """
        Stop sampling, observe its exception, and finalize evidence.

        Finalization is idempotent and always observes the owned sampling task
        before recording the terminal artifact state.

        Args:
            interrupted: Whether cancellation or shutdown interrupted execution.

        Side effects:
            Wakes and awaits the owned task, then atomically writes final state.
        """

        self._stop_event.set()
        task = self._task
        if task is not None and task is not asyncio.current_task():
            await asyncio.gather(task, return_exceptions=True)
        if self.evidence.status in {"completed", "interrupted"}:
            return
        self.evidence.status = "interrupted" if interrupted else "completed"
        self.evidence.completed_at = _utc_now()
        elapsed = self._elapsed()
        self.evidence.record_decision(
            action="stop",
            previous_limit=self.limiter.capacity,
            new_limit=self.limiter.capacity,
            reasons=[self.evidence.status],
            sample=None,
            monotonic_seconds=elapsed,
            limiter=self.limiter,
        )
        await self._persist_evidence()

    async def _run(self) -> None:
        """
        Sample progress and pressure until stopped, containing failures.

        The loop uses an owned stop event rather than a fire-and-forget sleep so
        normal cleanup wakes immediately.  Adaptive mode evaluates each sample;
        other modes record an observation without changing capacity.  Sampling
        failures are recorded and retried up to the configured consecutive
        error bound without changing collector result semantics or the last
        installed limit. Each new deadline is anchored after the preceding
        cycle completes, so controller work is never misreported as loop lag.
        """

        loop = asyncio.get_running_loop()
        scheduled_at = loop.time() + self.settings.sample_interval_seconds
        consecutive_errors = 0
        while not self._stop_event.is_set():
            timeout = max(0.0, scheduled_at - loop.time())
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=timeout)
                break
            except asyncio.TimeoutError:
                pass
            actual = loop.time()
            try:
                sample = await self.sampler.sample(max(0.0, actual - scheduled_at))
                if self.settings.mode == "adaptive":
                    await self.evaluate_sample(sample)
                else:
                    await self._record_periodic_observation(sample)
                consecutive_errors = 0
            except asyncio.CancelledError:
                raise
            except Exception as error:
                consecutive_errors += 1
                self.evidence.record_decision(
                    action="hold",
                    previous_limit=self.limiter.capacity,
                    new_limit=self.limiter.capacity,
                    reasons=[f"sampler_error_{type(error).__name__}"],
                    sample=None,
                    monotonic_seconds=self._elapsed(),
                    limiter=self.limiter,
                )
                await self._persist_evidence()
                maximum_errors = self.settings.maximum_consecutive_sampler_errors
                if consecutive_errors >= maximum_errors:
                    await self._log(
                        "WARNING",
                        "Concurrency observation stopped after "
                        f"{consecutive_errors} consecutive sampling failures; "
                        "the last installed limit remains active",
                    )
                    break
                await self._log(
                    "WARNING",
                    "Concurrency pressure sampling failed "
                    f"({consecutive_errors}/{maximum_errors}); observation "
                    "will retry and the last installed limit remains active",
                )
            scheduled_at = loop.time() + self.settings.sample_interval_seconds

    async def _record_periodic_observation(self, sample: PressureSample) -> None:
        """
        Persist one progress point without changing fixed scheduler capacity.

        Conservative and fixed modes use the same evidence shape as adaptive
        decisions so the report can render one bounded timeline contract.

        Args:
            sample: Sanitized local and remote pressure window retained only as
                bounded aggregate evidence.

        Side effects:
            Appends and atomically persists a bounded ``hold`` decision with
            the current limiter progress snapshot.
        """

        current = self.limiter.capacity
        self.evidence.record_decision(
            action="hold",
            previous_limit=current,
            new_limit=current,
            reasons=["periodic_observation"],
            sample=sample,
            monotonic_seconds=self._elapsed(),
            limiter=self.limiter,
        )
        await self._persist_evidence()

    async def evaluate_sample(self, sample: PressureSample) -> int:
        """
        Apply one deterministic AIMD decision to the weighted limiter.

        Hard or sustained pressure decreases immediately, whereas an increase
        requires multiple healthy windows and at least two observed signals.

        Args:
            sample: Sanitized local and remote pressure window.

        Returns:
            The capacity installed after evaluation.
        """

        current = self.limiter.capacity
        hard_reasons, pressure_reasons, observed_healthy_signals = (
            self._classify_sample(sample)
        )
        now = self._monotonic()
        action = "hold"
        reasons: list[str]
        new_limit = current

        if hard_reasons or pressure_reasons:
            ratio = (
                self.settings.hard_decrease_ratio
                if hard_reasons
                else self.settings.decrease_ratio
            )
            new_limit = max(
                self.settings.minimum_limit,
                min(current - 1, math.floor(current * ratio)),
            )
            new_limit = min(current, new_limit)
            action = "decrease" if new_limit < current else "hold"
            reasons = hard_reasons + pressure_reasons
            self._healthy_windows = 0
            self._cooldown_until = max(
                self._cooldown_until, now + self.settings.cooldown_seconds
            )
        elif now < self._cooldown_until:
            self._healthy_windows = 0
            reasons = ["cooldown"]
        elif not self._has_queued_demand():
            self._healthy_windows = 0
            reasons = ["no_queued_demand"]
        elif (
            sample.memory_headroom_ratio is None
            and sample.process_memory_utilization is None
        ):
            self._healthy_windows = 0
            reasons = ["no_memory_visibility"]
        elif observed_healthy_signals < 2:
            self._healthy_windows = 0
            reasons = ["insufficient_healthy_signals"]
        else:
            self._healthy_windows += 1
            reasons = [f"healthy_window_{self._healthy_windows}"]
            if (
                self._healthy_windows >= self.settings.healthy_windows_required
                and current < self.settings.maximum_limit
            ):
                ten_percent = max(1, math.floor(current * 0.10))
                increase = min(ten_percent, self.settings.increase_step)
                new_limit = min(self.settings.maximum_limit, current + increase)
                action = "increase"
                reasons = ["consecutive_healthy_windows"]
                self._healthy_windows = 0

        if new_limit != current:
            await self.limiter.set_capacity(new_limit)
        self.evidence.record_decision(
            action=action,
            previous_limit=current,
            new_limit=new_limit,
            reasons=reasons,
            sample=sample,
            monotonic_seconds=self._elapsed(),
            limiter=self.limiter,
        )
        await self._persist_evidence()
        if new_limit != current:
            await self._log(
                "INFO" if new_limit > current else "WARNING",
                f"Adaptive collector-operation limit {current} -> {new_limit} "
                f"({', '.join(reasons)})",
            )
        return new_limit

    def _has_queued_demand(self) -> bool:
        """
        Return whether pending work can benefit from a larger capacity.

        Demand observation is deliberately aggregate and synchronous.  A
        callback failure is treated as no demand so an observability problem
        cannot authorize an optimistic concurrency increase.

        Returns:
            ``True`` when at least one operation is queued for global
            admission, otherwise ``False``.
        """

        try:
            if self._demand_observer is None:
                return self.limiter.queued_operations > 0
            return bool(self._demand_observer())
        except Exception:
            return False

    def _classify_sample(
        self, sample: PressureSample
    ) -> tuple[list[str], list[str], int]:
        """
        Classify hard, sustained, and healthy measurements in one sample.

        Missing signals contribute neither pressure nor health, preventing a
        sparse sample from authorizing an optimistic increase.

        Args:
            sample: Sanitized pressure measurements.

        Returns:
            A tuple of hard reason codes, pressure reason codes, and the count
            of independently observed healthy local/remote signals.
        """

        hard: list[str] = []
        pressure: list[str] = []
        healthy = 0
        settings = self.settings

        if sample.event_loop_lag_seconds >= settings.event_loop_lag_threshold_seconds:
            hard.append("event_loop_lag")
        else:
            healthy += 1
        if sample.cgroup_oom_events > 0:
            hard.append("cgroup_oom_event")

        measurements = (
            (
                sample.process_memory_utilization,
                settings.process_memory_utilization_threshold,
                "process_memory_pressure",
                "maximum",
            ),
            (
                sample.memory_headroom_ratio,
                settings.memory_headroom_threshold,
                "memory_headroom",
                "minimum",
            ),
            (
                sample.file_descriptor_utilization,
                settings.file_descriptor_utilization_threshold,
                "file_descriptor_pressure",
                "maximum",
            ),
            (
                sample.pid_utilization,
                settings.pid_utilization_threshold,
                "pid_pressure",
                "maximum",
            ),
            (
                sample.cgroup_throttling_ratio,
                settings.cgroup_throttling_ratio_threshold,
                "cgroup_throttling",
                "maximum",
            ),
        )
        for value, threshold, reason, direction in measurements:
            if value is None:
                continue
            breached = (
                value <= threshold if direction == "minimum" else value >= threshold
            )
            if breached:
                hard.append(reason)
            else:
                healthy += 1

        if sample.cpu_utilization is not None:
            if sample.cpu_utilization >= settings.cpu_utilization_threshold:
                pressure.append("cpu_utilization")
            else:
                healthy += 1

        remote_count = sum(
            max(0, int(value)) for value in sample.remote_events.values()
        )
        remote_rate = remote_count / max(1, sample.completed_operations)
        if (
            remote_count >= settings.remote_throttle_minimum_events
            and remote_rate >= settings.remote_throttle_rate_threshold
            and sample.pressured_endpoints >= settings.remote_throttle_minimum_endpoints
        ):
            pressure.append("remote_throttling")
        elif sample.completed_operations > 0:
            healthy += 1
        return hard, pressure, healthy

    def _elapsed(self) -> float:
        """
        Return nonnegative controller-relative monotonic time.

        A monotonic clock keeps evidence ordering stable across wall-clock
        adjustments during a long collection.

        Returns:
            Seconds since :meth:`start`, or zero before start.
        """

        if self._started_monotonic is None:
            return 0.0
        return max(0.0, self._monotonic() - self._started_monotonic)

    async def _persist_evidence(self) -> None:
        """
        Snapshot live counters before serializing them in an owned thread.

        Side effects:
            Atomically replaces the scheduler metadata artifact after the
            worker has finished and been joined.

        Raises:
            OSError: If the scheduler metadata snapshot cannot be persisted.
            asyncio.CancelledError: After the owned writer has terminated if
                the caller is cancelled during persistence.
        """

        payload = self.evidence.build_payload(self.limiter)
        await _run_in_owned_thread(self.evidence.write_payload, payload)

    async def _log(self, level: str, message: str) -> None:
        """
        Emit one sanitized controller message without breaking collection.

        Observability is best-effort: callback failures cannot change
        admission state or collector result semantics.

        Args:
            level: Standard runtime log level.
            message: Bounded message constructed only from governed reasons.
        """

        if self._log_callback is None:
            return
        try:
            await self._log_callback(level, message[:1024])
        except Exception:
            return


def classify_remote_pressure(value: Any) -> tuple[str, ...]:
    """
    Classify trusted transport signals from one result or exception.

    Device-controlled status, reason, and error text is deliberately ignored:
    it is collection evidence, not authority to change global concurrency.
    Only typed local transport failures and integer wire-status fields may
    influence admission.

    Args:
        value: Collector result mapping, nested result values, or raised error.

    Returns:
        Sorted unique remote-pressure reason codes.
    """

    reasons: set[str] = set()
    if isinstance(value, Mapping):
        for key in ("status_code", "http_status"):
            status = value.get(key)
            if type(status) is int and status in _REMOTE_HTTP_PRESSURE_STATUSES:
                reasons.add(_REMOTE_HTTP_PRESSURE_STATUSES[status])

    error = value if isinstance(value, BaseException) else None
    visited_errors: set[int] = set()
    depth = 0
    while error is not None and depth < _MAX_CLASSIFICATION_EXCEPTION_DEPTH:
        identity = id(error)
        if identity in visited_errors:
            break
        visited_errors.add(identity)
        depth += 1

        status = getattr(error, "status", None)
        if type(status) is int and status in _REMOTE_HTTP_PRESSURE_STATUSES:
            reasons.add(_REMOTE_HTTP_PRESSURE_STATUSES[status])
        if isinstance(error, TimeoutError) or (
            isinstance(error, OSError) and error.errno == errno.ETIMEDOUT
        ):
            reasons.add("transport_timeout")
        if isinstance(
            error,
            (BrokenPipeError, ConnectionAbortedError, ConnectionResetError),
        ) or (
            isinstance(error, OSError) and error.errno in _REMOTE_TRANSPORT_RESET_ERRNOS
        ):
            reasons.add("transport_reset")

        next_error = error.__cause__ or error.__context__
        error = next_error if isinstance(next_error, BaseException) else None
    return tuple(sorted(reasons))
