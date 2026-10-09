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
Low-overhead, in-process resource telemetry for collection runs.

The collector often runs in a Kubernetes pod where host CPU and memory values do
not describe the budget enforced on the process. This monitor records the exact
scheduler decision together with cgroup and process counters in the run
artifact, without requiring access to Kubernetes or Jenkins APIs.
"""

from __future__ import annotations

import asyncio
import copy
import json
import math
import os
import resource
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
)

from .json_utils import safe_json_dump, safe_json_dumps
from .managed_filesystem import run_managed_filesystem_operation

_DEFAULT_SAMPLE_INTERVAL_SECONDS = 30.0
_DEFAULT_MAX_SAMPLES = 720
_MAX_RECORDED_ERRORS = 100
_MAX_DUT_PROJECTIONS = 256
_MAX_RESOURCE_USAGE_ARTIFACT_BYTES = 4 * 1024 * 1024
_CGROUP_V1_UNLIMITED_MEMORY_MIN = 1 << 60

_INTERVAL_ENV = "NVDEBUG_RESOURCE_MONITOR_INTERVAL_SECONDS"
_MAX_SAMPLES_ENV = "NVDEBUG_RESOURCE_MONITOR_MAX_SAMPLES"
_SAFE_ENVIRONMENT_NAMES = (
    "NVDEBUG_CPU_COUNT",
    "NVDEBUG_CPU_OVERSUBSCRIBE",
    "NVDEBUG_MAX_CONCURRENT_DUTS",
    _INTERVAL_ENV,
    _MAX_SAMPLES_ENV,
)


def _utc_now() -> str:
    """
    Return the current UTC timestamp in ISO 8601 form.

    After applying local validation, the function forwards current instance
    state to ``replace`` and preserves its return and exception contract.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Returns:
        The canonical utc now text.
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _positive_float_env(name: str, default: float) -> float:
    """
    Read a positive number from an environment variable.

    The implementation uses ``name`` and ``default`` to read a positive number
    from an environment variable. Parsing or I/O must finish before the
    validated representation is made available to the caller.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.
        default: Fallback used when the requested value is absent or invalid.

    Returns:
        The numeric positive float environment value.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if math.isfinite(value) and value > 0 else default


def _positive_int_env(name: str, default: int) -> int:
    """
    Read a positive integer from an environment variable.

    The implementation uses ``name`` and ``default`` to read a positive integer
    from an environment variable. Parsing or I/O must finish before the
    validated representation is made available to the caller.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.
        default: Fallback used when the requested value is absent or invalid.

    Returns:
        The numeric positive int environment value.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _compact_cpu_list(cpus: Iterable[int]) -> str:
    """
    Format CPU IDs as Linux-style ranges (for example ``0-3,8``).

    The implementation uses ``cpus`` to format CPU IDs as Linux-style ranges
    (for example ``0-3,8``). The source value keeps its ownership while the
    normalized representation is returned separately.

    Args:
        cpus: Entries supplied as ``cpus`` without transferring container
            ownership.

    Returns:
        The canonical compact CPU list text.
    """
    ordered = sorted(set(cpus))
    if not ordered:
        return ""
    ranges: List[str] = []
    start = previous = ordered[0]
    for cpu in ordered[1:]:
        if cpu == previous + 1:
            previous = cpu
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = cpu
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


class ResourceUsageMonitor:
    """
    Persist periodic process and cgroup resource snapshots for one run.

    The type coordinates ``is_running``, ``start``, ``stop``, ``cancel``, and
    ``_run`` and retains the state those operations share between calls.
    Resource ownership remains inside the instance until the matching close,
    exit, or cleanup operation completes.
    """

    def __init__(
        self,
        log_dir: Path | str,
        scheduler: Optional[Mapping[str, Any]] = None,
        *,
        sample_interval_seconds: Optional[float] = None,
        max_samples: Optional[int] = None,
        proc_root: Path | str = "/proc",
        cgroup_root: Path | str = "/sys/fs/cgroup",
    ) -> None:
        """
        Initialize a ``ResourceUsageMonitor`` instance.

        Prevent an accidental environment override from turning telemetry into a
        workload of its own. Tests and callers can still choose any interval at
        or above one second.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            scheduler: Optional scheduler; ``None`` selects the function's
                default behavior.
            sample_interval_seconds: Maximum duration in seconds allowed for
                sample interval seconds.
            max_samples: Upper bound enforced for max samples; the consuming
                boundary rejects or truncates values that exceed it.
            proc_root: filesystem location used as the proc root for this
                operation.
            cgroup_root: filesystem location used as the cgroup root for this
                operation.
        """
        self.log_dir = Path(log_dir)
        self.output_path = self.log_dir / ".metadata" / "resource_usage.json"
        self.samples_path = self.log_dir / ".metadata" / "resource_usage_samples.jsonl"
        self.previous_samples_path = (
            self.log_dir / ".metadata" / "resource_usage_samples.previous.jsonl"
        )
        self.proc_root = Path(proc_root)
        self.cgroup_root = Path(cgroup_root)
        self.scheduler = dict(scheduler or {})

        if sample_interval_seconds is None:
            sample_interval_seconds = _positive_float_env(
                _INTERVAL_ENV, _DEFAULT_SAMPLE_INTERVAL_SECONDS
            )
        if max_samples is None:
            max_samples = _positive_int_env(_MAX_SAMPLES_ENV, _DEFAULT_MAX_SAMPLES)
        # Prevent an accidental environment override from turning telemetry
        # into a workload of its own.  Tests and callers can still choose any
        # interval at or above one second.
        self.sample_interval_seconds = max(1.0, float(sample_interval_seconds))
        self.max_samples = min(10_000, max(1, int(max_samples)))

        self.status = "not_started"
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        self._started_monotonic: Optional[float] = None
        self._baseline: Optional[Dict[str, Any]] = None
        self._latest: Optional[Dict[str, Any]] = None
        self._samples_total = 0
        self._samples_written = 0
        self._samples_dropped = 0
        self._samples_rotated_out = 0
        self._current_segment_samples = 0
        self._previous_segment_samples = 0
        self._history_rotations = 0
        self._peaks: Dict[str, Any] = {
            "process": {},
            "cgroup_scopes": {},
        }
        self._errors: List[Dict[str, str]] = []
        self._error_keys: set[Tuple[str, str]] = set()
        self._system: Dict[str, Any] = {}
        self._cgroup_version: Optional[int] = None
        self._cgroup_scopes: List[Tuple[str, Path]] = []

        self._stop_event = asyncio.Event()
        self._lifecycle_lock = asyncio.Lock()
        self._sample_lock = threading.Lock()
        self._component_lock = threading.Lock()
        self._request_capture_sampler: Optional[Callable[[], Mapping[str, Any]]] = None
        self._host_ssh_pool_sampler: Optional[Callable[[], Mapping[str, Any]]] = None
        self._task: Optional[asyncio.Task[None]] = None
        self._last_write_succeeded: Optional[bool] = None

    @property
    def is_running(self) -> bool:
        """
        Return whether ``the current value`` is running.

        Each access computes the value from ``status`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            Whether ``the current value`` is running.
        """
        return self.status == "running"

    def latest_sample(self) -> Dict[str, Any]:
        """
        Return a defensive copy of the most recent persisted sample.

        The adaptive scheduler can reuse this view without reading the metadata
        artifact or sharing mutable monitor state.  An empty mapping is
        returned before the first successful capture.

        Returns:
            A detached JSON-safe resource sample, or an empty mapping.
        """

        with self._sample_lock:
            return copy.deepcopy(self._latest or {})

    def set_request_capture_sampler(
        self, sampler: Callable[[], Mapping[str, Any]]
    ) -> None:
        """
        Attach the sole bounded request-capture telemetry provider.

        Registration does not call the provider. Periodic and final resource
        samples invoke it synchronously under its own runtime lock, producing
        only aggregate identity-free metrics. Re-registering replaces the
        provider so a reused monitor cannot retain an earlier run's runtime.

        Args:
            sampler: Zero-argument callable returning a JSON-safe bounded
                request-capture metrics mapping.

        Raises:
            TypeError: If ``sampler`` is not callable.

        Side effects:
            Replaces the request-capture component provider retained by this
            monitor.
        """

        if not callable(sampler):
            raise TypeError("Request-capture telemetry sampler must be callable")
        with self._component_lock:
            self._request_capture_sampler = sampler

    def set_host_ssh_pool_sampler(
        self, sampler: Callable[[], Mapping[str, Any]]
    ) -> None:
        """
        Attach the run-owned label-free Host SSH pool telemetry provider.

        Registration does not call the provider. Periodic and final resource
        samples invoke it synchronously under the pool's event-loop-owned
        counters. Re-registering replaces the provider so reused monitor state
        cannot retain an earlier manager.

        Args:
            sampler: Zero-argument callable returning the fixed-shape bounded
                Host SSH pool accounting mapping.

        Raises:
            TypeError: If ``sampler`` is not callable.

        Side effects:
            Replaces the Host SSH component provider retained by this monitor.
        """

        if not callable(sampler):
            raise TypeError("Host SSH pool telemetry sampler must be callable")
        with self._component_lock:
            self._host_ssh_pool_sampler = sampler

    def _capture_component_snapshots(self) -> Dict[str, Any]:
        """
        Return detached aggregate snapshots from registered run components.

        Component telemetry remains best effort like process and cgroup
        telemetry. Provider failures are recorded by bounded error code and do
        not change collection status or manufacture a successful component
        snapshot.

        Returns:
            A mapping containing each registered component snapshot whose
            provider succeeds, otherwise an empty mapping.

        Raises:
            BaseException: Preserves process-control exceptions raised by the
                registered provider while ordinary telemetry failures remain
                best effort.
        """

        with self._component_lock:
            samplers = (
                (
                    "request_capture",
                    "request_capture_component",
                    self._request_capture_sampler,
                ),
                (
                    "host_ssh_pool",
                    "host_ssh_pool_component",
                    self._host_ssh_pool_sampler,
                ),
            )
        components: Dict[str, Any] = {}
        for component_name, error_code, sampler in samplers:
            if sampler is None:
                continue
            try:
                snapshot = sampler()
                if not isinstance(snapshot, Mapping):
                    raise TypeError(f"{component_name} telemetry must be a mapping")
                components[component_name] = copy.deepcopy(dict(snapshot))
            except Exception as exc:
                self._record_error(error_code, exc)
        return components

    async def capture_scheduler_sample(self) -> Dict[str, Any]:
        """
        Capture an unpersisted local sample for adaptive scheduling.

        Procfs and cgroupfs reads run in a worker thread and share the monitor's
        sampling lock.  The sample does not change history, peaks, status, or
        artifact counters, so scheduler cadence cannot inflate observability
        output or trigger extra remote work.

        Returns:
            A fresh JSON-safe process and cgroup resource sample.
        """

        return await run_managed_filesystem_operation(
            self._capture_scheduler_sample_sync
        )

    def _capture_scheduler_sample_sync(self) -> Dict[str, Any]:
        """
        Capture one scheduler-only sample while holding monitor serialization.

        Reusing the monitor's synchronous collector under its lock prevents a
        concurrent periodic sample from racing shared proc and cgroup readers.

        Returns:
            A fresh local resource sample detached from monitor history.
        """

        with self._sample_lock:
            return self._capture_sample("scheduler")

    async def start(self) -> bool:
        """
        Write an immediate baseline and start periodic sampling.

        The implementation uses current instance state to write an immediate
        baseline and start periodic sampling. Success is reported only after the
        owning output boundary has completed its required write or publication
        step. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind. It updates
        ``_started_monotonic``, ``_system``, ``_task``, ``started_at``, and
        ``status`` on the instance as part of that state transition.

        Returns:
            Whether the immediate baseline and start periodic sampling operation
            succeeds.
        """
        async with self._lifecycle_lock:
            if self.status != "not_started":
                return self.output_path.exists()

            self.status = "running"
            self.started_at = _utc_now()
            self._started_monotonic = time.monotonic()
            self._system = self._capture_system_context()
            self._initialize_sample_history()
            initial_write_succeeded = self._capture_and_write("startup")
            self._task = asyncio.create_task(
                self._run(), name="nvdebug-resource-monitor"
            )
            self._task.add_done_callback(self._worker_done)
            return initial_write_succeeded

    async def stop(self) -> Optional[Dict[str, Any]]:
        """
        Wake the monitor, take a final sample, and atomically finalize it.

        A separately cancelled worker writes an interrupted final snapshot in
        its cancellation handler.

        Returns:
            A mapping containing stop, or ``None`` when the requested value is
            unavailable.
        """
        async with self._lifecycle_lock:
            if self.status == "not_started":
                return None
            if self.status != "running":
                # Teardown may attach final component providers after an
                # interruption cancelled the periodic worker. Refresh the
                # already-terminal atomic document without manufacturing a new
                # process/cgroup sample so final pool accounting is not lost.
                await run_managed_filesystem_operation(self._write_payload_with_result)
                return self._build_payload().get("summary")

            self._stop_event.set()
            task = self._task
            if task is not None and task is not asyncio.current_task():
                try:
                    await task
                except asyncio.CancelledError:
                    current = asyncio.current_task()
                    cancelling = (
                        current.cancelling()
                        if current is not None and hasattr(current, "cancelling")
                        else 0
                    )
                    if cancelling:
                        if self.status == "running":
                            self._complete("interrupted")
                        raise
                    # A separately cancelled worker writes an interrupted
                    # final snapshot in its cancellation handler.

            if self.status == "running":
                final_write_succeeded = self._complete("completed")
                if not final_write_succeeded:
                    final_write_succeeded = self._retry_final_payload_write("completed")
                if not final_write_succeeded:
                    self._freeze_after_failed_write()
            return self._build_payload().get("summary")

    async def publish_dut_projections(
        self, projection_paths: Mapping[str, Path | str]
    ) -> Tuple[Path, ...]:
        """
        Publish bounded per-DUT references to the finalized run telemetry.

        Process and cgroup counters describe the single nvdebug process, not
        independent DUT workloads. Each projection therefore retains the
        shared run summary and explicitly references the authoritative root
        artifact instead of manufacturing DUT-attributed samples or copying
        the potentially large JSONL history into every DUT directory.

        Args:
            projection_paths: Mapping from stable DUT identifiers to the exact
                ``resource_usage.json`` destination owned by that DUT.

        Returns:
            The projection paths written in deterministic DUT order.

        Raises:
            RuntimeError: If the root artifact is not terminal, is missing,
                exceeds its bound, or a projection cannot be written.
            ValueError: If a DUT identifier or destination is invalid, escapes
                the run directory, aliases the root artifact, or exceeds the
                bounded DUT count.

        Side effects:
            Atomically writes one small JSON projection under each selected
            DUT metadata directory using a managed filesystem worker.
        """

        if self.status == "running":
            raise RuntimeError(
                "Resource telemetry must be finalized before DUT projection"
            )
        if len(projection_paths) > _MAX_DUT_PROJECTIONS:
            raise ValueError(
                "Resource telemetry DUT projection count exceeds the supported bound"
            )

        run_root = self.log_dir.resolve()
        root_artifact = self.output_path.resolve()
        normalized: List[Tuple[str, Path]] = []
        seen_paths: set[Path] = set()
        for raw_dut_id, raw_path in sorted(
            projection_paths.items(), key=lambda item: str(item[0])
        ):
            dut_id = str(raw_dut_id).strip()
            if not dut_id:
                raise ValueError("Resource telemetry projection DUT ID is empty")
            target = Path(raw_path)
            if target.name != self.output_path.name:
                raise ValueError(
                    "Resource telemetry projection must be named resource_usage.json"
                )
            resolved_parent = target.parent.resolve()
            try:
                resolved_parent.relative_to(run_root)
            except ValueError as exc:
                raise ValueError(
                    "Resource telemetry projection escapes the run directory"
                ) from exc
            resolved_target = resolved_parent / target.name
            if resolved_target == root_artifact:
                raise ValueError(
                    "Resource telemetry projection cannot alias the root artifact"
                )
            if resolved_target in seen_paths:
                raise ValueError(
                    "Resource telemetry projection destinations must be unique"
                )
            seen_paths.add(resolved_target)
            normalized.append((dut_id, resolved_target))

        if not normalized:
            return ()
        return await run_managed_filesystem_operation(
            self._write_dut_projections,
            tuple(normalized),
        )

    def _write_dut_projections(
        self, targets: Tuple[Tuple[str, Path], ...]
    ) -> Tuple[Path, ...]:
        """
        Write exact shared-run projection documents for normalized targets.

        Every projection is derived from the finalized root document, which
        remains the authoritative telemetry record for the run. Publication is
        atomic per target, and any failed replacement aborts the operation
        instead of reporting partially written projections as complete.

        Args:
            targets: Deterministically ordered ``(dut_id, path)`` pairs whose
                paths were confined to the run directory by the caller.

        Returns:
            The exact paths successfully replaced atomically.

        Raises:
            RuntimeError: If the finalized root artifact is unavailable,
                malformed, oversized, non-terminal, or a target write fails.

        Side effects:
            Reads the authoritative root artifact and atomically replaces each
            target projection file.
        """

        try:
            artifact_size = self.output_path.stat().st_size
        except OSError as exc:
            raise RuntimeError(
                "Finalized resource telemetry root artifact is unavailable"
            ) from exc
        if artifact_size > _MAX_RESOURCE_USAGE_ARTIFACT_BYTES:
            raise RuntimeError(
                "Finalized resource telemetry root artifact exceeds its size bound"
            )
        try:
            root_payload = json.loads(self.output_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "Finalized resource telemetry root artifact is invalid"
            ) from exc
        if (
            not isinstance(root_payload, dict)
            or root_payload.get("status") == "running"
        ):
            raise RuntimeError(
                "Finalized resource telemetry root artifact is not terminal"
            )

        written: List[Path] = []
        for dut_id, target in targets:
            relative_root = Path(
                os.path.relpath(self.output_path, start=target.parent)
            ).as_posix()
            projection = self._build_dut_projection(
                root_payload,
                dut_id=dut_id,
                relative_root=relative_root,
            )
            temp_path = target.with_name(f".{target.name}.{os.getpid()}.tmp")
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with open(temp_path, "w", encoding="utf-8") as file_handle:
                    safe_json_dump(projection, file_handle, indent=2)
                    file_handle.write("\n")
                    file_handle.flush()
                    os.fsync(file_handle.fileno())
                os.replace(temp_path, target)
            except Exception as exc:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
                raise RuntimeError(
                    "Resource telemetry DUT projection could not be persisted"
                ) from exc
            written.append(target)
        return tuple(written)

    @staticmethod
    def _build_dut_projection(
        root_payload: Mapping[str, Any],
        *,
        dut_id: str,
        relative_root: str,
    ) -> Dict[str, Any]:
        """
        Build a truthful bounded view of shared run telemetry for one DUT.

        Shared samples cannot be attributed truthfully to a single DUT, so the
        projection references the root sample history rather than duplicating
        it. The returned document retains bounded run-level summaries while
        declaring its shared-run scope explicitly.

        Args:
            root_payload: Finalized root resource document whose bounded
                summary and endpoint samples are projected.
            dut_id: Stable DUT identifier bound to the projection location.
            relative_root: POSIX relative path back to the authoritative root
                resource artifact.

        Returns:
            A detached JSON-safe projection that contains no duplicated sample
            history and explicitly rejects per-DUT attribution.
        """

        projection: Dict[str, Any] = {
            key: copy.deepcopy(root_payload.get(key))
            for key in (
                "schema_version",
                "status",
                "started_at",
                "completed_at",
                "monitor",
                "scheduler",
                "components",
                "system",
                "baseline",
                "latest",
                "summary",
                "errors",
            )
        }
        root_history = root_payload.get("sample_history")
        root_samples_retained = (
            root_history.get("samples_retained", 0)
            if isinstance(root_history, Mapping)
            else 0
        )
        projection["sample_history"] = {
            "format": "root_reference",
            "segments": [],
            "samples_retained": 0,
            "root_artifact": relative_root,
            "root_samples_retained": root_samples_retained,
        }
        projection["projection"] = {
            "schema_version": 1,
            "scope": "shared_run",
            "dut_id": dut_id,
            "root_artifact": relative_root,
            "per_dut_attribution": False,
        }
        return projection

    async def cancel(self) -> None:
        """
        Stop a live worker after an unexpected lifecycle error.

        The implementation uses current instance state to stop a live worker
        after an unexpected lifecycle error. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        """
        task = self._task
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if self.status == "running":
            if not self._complete("interrupted"):
                self._freeze_after_failed_write()

    async def _run(self) -> None:
        """
        Run the configured operation.

        Proc/cgroup reads are small, but serialization and fsync are blocking
        syscalls. Keep them off the collector's asyncio event loop.
        """
        try:
            while not self._stop_event.is_set():
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=self.sample_interval_seconds,
                    )
                except asyncio.TimeoutError:
                    # Proc/cgroup reads are small, but serialization and fsync
                    # are blocking syscalls.  Keep them off the collector's
                    # asyncio event loop.
                    await run_managed_filesystem_operation(
                        self._capture_and_write, "periodic"
                    )
        except asyncio.CancelledError:
            # Signal handling cancels every event-loop task.  Synchronous final
            # capture here preserves a useful artifact before cancellation is
            # propagated; SIGKILL/OOM still has the last periodic snapshot.
            if self.status == "running":
                self._complete("interrupted")
            raise
        except Exception as exc:  # pragma: no cover - last-resort containment
            self._record_error("monitor_loop", exc)
            if self.status == "running":
                if not self._complete("monitor_failed"):
                    self._freeze_after_failed_write()

    def _worker_done(self, task: asyncio.Task[None]) -> None:
        """
        Cover cancellation that happens before the worker first executes.

        The implementation uses ``task`` to cover cancellation that happens
        before the worker first executes.

        Args:
            task: Optional task; ``None`` selects the function's default
                behavior.
        """
        if task.cancelled() and self.status == "running":
            if not self._complete("interrupted"):
                self._freeze_after_failed_write()

    def _complete(self, final_status: str) -> bool:
        """
        Mark the publication capability result as complete.

        Keep the monitor retryable while the caller retries only the payload
        write. The already-persisted running snapshot remains truthful until
        that retry succeeds.

        Args:
            final_status: Text supplied as final status in the format accepted
                by this function.

        Returns:
            Whether the mark the publication capability result as complete
            operation succeeds.
        """
        self.status = final_status
        self.completed_at = _utc_now()
        succeeded = self._capture_and_write("final")
        if not succeeded:
            # Keep the monitor retryable while the caller retries only the
            # payload write.  The already-persisted running snapshot remains
            # truthful until that retry succeeds.
            self.status = "running"
            self.completed_at = None
        return succeeded

    def _retry_final_payload_write(self, final_status: str) -> bool:
        """
        Retry a failed final payload write without taking another sample.

        The implementation uses ``final_status`` to retry a failed final payload
        write without taking another sample. It updates ``completed_at`` and
        ``status`` on the instance as part of that state transition.

        Args:
            final_status: Text supplied as final status in the format accepted
                by this function.

        Returns:
            Whether the retry a failed final payload write without taking
            another sample operation succeeds.
        """
        self.status = final_status
        self.completed_at = _utc_now()
        succeeded = self._write_payload_with_result()
        if not succeeded:
            self.status = "running"
            self.completed_at = None
        return succeeded

    def _freeze_after_failed_write(self) -> None:
        """
        Prevent any further writes once packaging is allowed to continue.

        The implementation uses current instance state to prevent any further
        writes once packaging is allowed to continue. It updates
        ``completed_at`` and ``status`` on the instance as part of that state
        transition.
        """
        self.status = "finalization_failed"
        self.completed_at = _utc_now()
        self._stop_event.set()

    def _capture_and_write(self, reason: str) -> bool:
        """
        Capture and write.

        After applying local validation, the function forwards ``reason`` to
        ``self._write_payload_with_result`` and preserves its return and
        exception contract. It updates ``_baseline``, ``_latest``, and
        ``_samples_total`` on the instance as part of that state transition.

        Args:
            reason: Text supplied as reason in the format accepted by this
                function.

        Returns:
            Whether the capture and write operation succeeds.
        """
        with self._sample_lock:
            try:
                sample = self._capture_sample(reason)
                if self._baseline is None:
                    self._baseline = sample
                self._latest = sample
                self._samples_total += 1
                self._append_sample_history(sample)
                self._update_peaks(sample)
            except Exception as exc:  # a monitor must never break collection
                self._record_error("sample", exc)
            return self._write_payload_with_result()

    def _write_payload_with_result(self) -> bool:
        """
        Write a payload whose own summary truthfully reports this attempt.

        The implementation uses current instance state to write a payload whose
        own summary truthfully reports this attempt. Success is reported only
        after the owning output boundary has completed its required write or
        publication step. It updates ``_last_write_succeeded`` on the instance
        as part of that state transition.

        Returns:
            Whether the payload whose own summary truthfully reports this
            attempt operation succeeds.
        """
        # The value serialized into the payload must describe the successful
        # write being attempted.  If the write fails, retain False in memory so
        # callers can warn and freeze the last valid atomic snapshot.
        self._last_write_succeeded = True
        self._last_write_succeeded = self._write_payload()
        return self._last_write_succeeded

    def _initialize_sample_history(self) -> None:
        """
        Initialize sample history.

        The implementation uses current instance state to initialize sample
        history. Filesystem effects remain confined to the caller-selected paths
        and the owning resource lifecycle.
        """
        try:
            self.samples_path.parent.mkdir(parents=True, exist_ok=True)
            self.samples_path.unlink(missing_ok=True)
            self.previous_samples_path.unlink(missing_ok=True)
        except OSError as exc:
            self._record_error("resource_sample_history_init", exc)

    def _append_sample_history(self, sample: Mapping[str, Any]) -> bool:
        """
        Append sample history.

        A same-directory replace atomically promotes the complete append-only
        current segment over the single previous segment. If rotation itself
        fails, append anyway so the final sample is never discarded merely to
        enforce the normal size bound.

        Args:
            sample: Mapping supplying fields for append sample history.

        Returns:
            Whether the append sample history operation succeeds.
        """
        try:
            encoded = safe_json_dumps(sample, separators=(",", ":"))
            if self._current_segment_samples >= self.max_samples:
                # A same-directory replace atomically promotes the complete
                # append-only current segment over the single previous segment.
                # If rotation itself fails, append anyway so the final sample is
                # never discarded merely to enforce the normal size bound.
                self._rotate_sample_history()
            with open(self.samples_path, "a", encoding="utf-8") as file_handle:
                file_handle.write(encoded)
                file_handle.write("\n")
                file_handle.flush()
            self._samples_written += 1
            self._current_segment_samples += 1
            return True
        except Exception as exc:
            self._samples_dropped += 1
            self._record_error("resource_sample_history_write", exc)
            return False

    def _rotate_sample_history(self) -> bool:
        """
        Atomically retain one full previous segment and start a new current one.

        The implementation uses current instance state to atomically retain one
        full previous segment and start a new current one. It updates
        ``_current_segment_samples``, ``_history_rotations``,
        ``_previous_segment_samples``, and ``_samples_rotated_out`` on the
        instance as part of that state transition. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Returns:
            Whether the atomically retain one full previous segment and start a
            new current one operation succeeds.
        """
        try:
            os.replace(self.samples_path, self.previous_samples_path)
        except OSError as exc:
            self._record_error("resource_sample_history_rotation", exc)
            return False

        self._samples_rotated_out += self._previous_segment_samples
        self._previous_segment_samples = self._current_segment_samples
        self._current_segment_samples = 0
        self._history_rotations += 1
        return True

    def _write_payload(self) -> bool:
        """
        Write payload.

        The implementation uses current instance state to write payload. Success
        is reported only after the owning output boundary has completed its
        required write or publication step.

        Returns:
            Whether the payload operation succeeds.
        """
        temp_path = self.output_path.with_name(
            f".{self.output_path.name}.{os.getpid()}.tmp"
        )
        try:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(temp_path, "w", encoding="utf-8") as file_handle:
                safe_json_dump(self._build_payload(), file_handle, indent=2)
                file_handle.write("\n")
                file_handle.flush()
                os.fsync(file_handle.fileno())
            os.replace(temp_path, self.output_path)
            return True
        except Exception as exc:
            self._record_error("resource_usage_write", exc)
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    def _build_payload(self) -> Dict[str, Any]:
        """
        Build payload.

        The implementation uses current instance state to build payload.

        Returns:
            A mapping containing the ``schema_version``, ``status``,
            ``started_at``, ``completed_at``, and ``monitor`` fields.
        """
        return {
            "schema_version": 1,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "monitor": {
                "sample_interval_seconds": self.sample_interval_seconds,
                "max_history_samples_per_segment": self.max_samples,
                "max_history_samples_retained": self.max_samples * 2,
                "scope": "collection_and_pre_packaging_cleanup",
                "process_io_includes_monitor_writes": True,
            },
            "scheduler": self.scheduler,
            "components": self._capture_component_snapshots(),
            "system": self._system,
            "baseline": self._baseline,
            "latest": self._latest,
            "sample_history": {
                "path": self.samples_path.name,
                "previous_path": self.previous_samples_path.name,
                "format": "json_lines",
                "rotation_strategy": "current_plus_one_previous_segment",
                "durability": "best_effort; main JSON is atomic and fsynced",
                "max_samples_per_segment": self.max_samples,
                "segments": [
                    {
                        "role": "previous",
                        "path": self.previous_samples_path.name,
                        "samples": self._previous_segment_samples,
                    },
                    {
                        "role": "current",
                        "path": self.samples_path.name,
                        "samples": self._current_segment_samples,
                    },
                ],
                "rotations": self._history_rotations,
                "samples_written_total": self._samples_written,
                "samples_retained": self._retained_history_samples(),
                "samples_rotated_out": self._samples_rotated_out,
                "samples_write_failures": self._samples_dropped,
            },
            "summary": self._build_summary(),
            "errors": list(self._errors),
        }

    def _build_summary(self) -> Dict[str, Any]:
        """
        Build summary.

        The implementation uses current instance state to build summary.

        Returns:
            A mapping containing the ``duration_seconds``, ``samples_total``,
            ``samples_retained``, ``samples_dropped``, and
            ``samples_rotated_out`` fields.
        """
        elapsed = 0.0
        if self._latest is not None:
            elapsed = float(self._latest.get("elapsed_seconds", 0.0))
        return {
            "duration_seconds": elapsed,
            "samples_total": self._samples_total,
            "samples_retained": self._retained_history_samples(),
            "samples_dropped": self._samples_rotated_out + self._samples_dropped,
            "samples_rotated_out": self._samples_rotated_out,
            "sample_history_write_failures": self._samples_dropped,
            "artifact_write_succeeded": self._last_write_succeeded,
            "peaks": self._peaks,
            "deltas": self._build_deltas(),
        }

    def _retained_history_samples(self) -> int:
        """
        Return the retained history samples.

        The implementation uses current instance state to produce the retained
        history samples.

        Returns:
            The numeric retained history samples value.
        """
        return self._previous_segment_samples + self._current_segment_samples

    def _capture_sample(self, reason: str) -> Dict[str, Any]:
        """
        Capture sample.

        The implementation uses ``reason`` to capture sample.

        Args:
            reason: Text supplied as reason in the format accepted by this
                function.

        Returns:
            The validated ``sample``.
        """
        started = self._started_monotonic or time.monotonic()
        sample: Dict[str, Any] = {
            "timestamp": _utc_now(),
            "elapsed_seconds": round(max(0.0, time.monotonic() - started), 3),
            "reason": reason,
            "process": self._capture_process(),
            "cgroup": {
                "version": self._cgroup_version,
                "scopes": [
                    self._capture_cgroup_scope(controller, path)
                    for controller, path in self._cgroup_scopes
                ],
            },
        }
        component_snapshots = self._capture_component_snapshots()
        if component_snapshots:
            sample["components"] = component_snapshots
        try:
            load_1m, load_5m, load_15m = os.getloadavg()
            sample["system_load"] = {
                "load_1m": load_1m,
                "load_5m": load_5m,
                "load_15m": load_15m,
            }
        except (AttributeError, OSError):
            pass
        return sample

    def _capture_system_context(self) -> Dict[str, Any]:
        """
        Capture system context.

        The implementation uses current instance state to capture system
        context.

        Returns:
            A mapping containing the ``pid``, ``host_cpu_count``, ``affinity``,
            ``environment``, and ``cgroup`` fields.
        """
        affinity: Dict[str, Any] = {}
        try:
            allowed = sorted(os.sched_getaffinity(0))
            affinity = {
                "cpu_count": len(allowed),
                "cpus_compact": _compact_cpu_list(allowed),
            }
        except (AttributeError, OSError):
            pass

        return {
            "pid": os.getpid(),
            "host_cpu_count": os.cpu_count(),
            "affinity": affinity,
            "environment": {
                name: os.environ[name]
                for name in _SAFE_ENVIRONMENT_NAMES
                if name in os.environ
            },
            "cgroup": self._inspect_cgroup(),
        }

    def _capture_process(self) -> Dict[str, Any]:
        """
        Capture process.

        The implementation uses current instance state to capture process.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Returns:
            The validated ``process``.
        """
        process: Dict[str, Any] = {"pid": os.getpid()}
        status_path = self.proc_root / "self" / "status"
        status = self._read_status(status_path)
        status_mapping = {
            "VmRSS": "rss_bytes",
            "VmHWM": "peak_rss_bytes",
            "VmSize": "virtual_memory_bytes",
        }
        for source, target in status_mapping.items():
            value = self._status_kib_value(status.get(source))
            if value is not None:
                process[target] = value
        for source, target in (
            ("Threads", "threads"),
            ("voluntary_ctxt_switches", "voluntary_context_switches"),
            ("nonvoluntary_ctxt_switches", "involuntary_context_switches"),
        ):
            value = self._first_int(status.get(source))
            if value is not None:
                process[target] = value
        if "Cpus_allowed_list" in status:
            process["allowed_cpu_list"] = status["Cpus_allowed_list"]

        io_values = self._read_key_value_ints(self.proc_root / "self" / "io")
        if io_values:
            process["io"] = io_values

        try:
            fd_directory = self.proc_root / "self" / "fd"
            live_fds = 0
            for entry in os.listdir(fd_directory):
                try:
                    # The descriptor used by listdir itself has disappeared by
                    # this point; lstat filters that transient procfs entry.
                    os.lstat(fd_directory / entry)
                    live_fds += 1
                except FileNotFoundError:
                    continue
            process["open_fds"] = live_fds
        except OSError:
            pass

        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            process.update(
                {
                    "user_cpu_seconds": usage.ru_utime,
                    "system_cpu_seconds": usage.ru_stime,
                    "minor_page_faults": usage.ru_minflt,
                    "major_page_faults": usage.ru_majflt,
                    "block_input_operations": usage.ru_inblock,
                    "block_output_operations": usage.ru_oublock,
                }
            )
            if "peak_rss_bytes" not in process and usage.ru_maxrss >= 0:
                # The supported runtime is Linux, where ru_maxrss is KiB.
                process["peak_rss_bytes"] = int(usage.ru_maxrss * 1024)
        except (ValueError, OSError):
            pass

        try:
            child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
            process.update(
                {
                    "completed_children_user_cpu_seconds": child_usage.ru_utime,
                    "completed_children_system_cpu_seconds": child_usage.ru_stime,
                }
            )
        except (ValueError, OSError):
            pass
        return process

    def _inspect_cgroup(self) -> Dict[str, Any]:
        """
        Inspect cgroup.

        The implementation uses current instance state to inspect cgroup. It
        updates ``_cgroup_version`` on the instance as part of that state
        transition.

        Returns:
            A mapping containing inspect cgroup.
        """
        memberships = self._read_cgroup_memberships()
        unified_path = memberships.get("")
        if unified_path is not None and (
            (self.cgroup_root / "cgroup.controllers").exists()
            or (self._cgroup_dir(self.cgroup_root, unified_path) / "cpu.max").exists()
        ):
            self._cgroup_version = 2
            return self._inspect_cgroup_v2(unified_path)

        if memberships:
            self._cgroup_version = 1
            return self._inspect_cgroup_v1(memberships)

        self._cgroup_version = None
        return {"version": None, "reason": "cgroup membership unavailable"}

    def _inspect_cgroup_v2(self, relative_path: Path) -> Dict[str, Any]:
        """
        Inspect cgroup v2.

        The implementation uses ``relative_path`` to inspect cgroup v2. It
        updates ``_cgroup_scopes`` on the instance as part of that state
        transition.

        Args:
            relative_path: filesystem location used as the relative path for
                this operation.

        Returns:
            A mapping containing the ``version``, ``relative_path``,
            ``cpu_quota_candidates``, ``effective_quota_cpus``, and
            ``memory_limit_candidates`` fields.
        """
        current = self._cgroup_dir(self.cgroup_root, relative_path)
        directories = self._ancestor_dirs(self.cgroup_root, relative_path)
        cpu_candidates = [
            self._inspect_cpu_max(directory / "cpu.max") for directory in directories
        ]
        memory_candidates = [
            self._inspect_limit(directory / "memory.max", "bytes")
            for directory in directories
        ]
        pids_candidates = [
            self._inspect_limit(directory / "pids.max", "tasks")
            for directory in directories
        ]

        scope_paths = [current]
        for directory, cpu, memory, pids in zip(
            directories, cpu_candidates, memory_candidates, pids_candidates
        ):
            if any(item.get("state") == "limited" for item in (cpu, memory, pids)):
                scope_paths.append(directory)
        self._cgroup_scopes = [
            ("unified", path) for path in self._dedupe_paths(scope_paths)
        ]

        cpuset = None
        for directory in directories:
            cpuset = self._read_optional_text(directory / "cpuset.cpus.effective")
            if cpuset:
                break

        limited_cpu_values = [
            candidate["cpus"]
            for candidate in cpu_candidates
            if candidate.get("state") == "limited"
        ]
        return {
            "version": 2,
            "relative_path": self._display_cgroup_path(current),
            "cpu_quota_candidates": cpu_candidates,
            "effective_quota_cpus": (
                min(limited_cpu_values) if limited_cpu_values else None
            ),
            "memory_limit_candidates": memory_candidates,
            "pids_limit_candidates": pids_candidates,
            "cpuset_cpus_effective": cpuset,
            "runtime_scopes": [
                self._display_cgroup_path(path) for _, path in self._cgroup_scopes
            ],
        }

    def _inspect_cgroup_v1(self, memberships: Dict[str, Path]) -> Dict[str, Any]:
        """
        Inspect cgroup v1.

        The implementation uses ``memberships`` to inspect cgroup v1. It updates
        ``_cgroup_scopes`` on the instance as part of that state transition.

        Args:
            memberships: filesystem location used as the memberships for this
                operation.

        Returns:
            A mapping containing the ``version`` and ``controllers`` fields.
        """
        controllers: Dict[str, Any] = {}
        self._cgroup_scopes = []
        cpu_includes_accounting = False

        cpu_relative = memberships.get("cpu")
        if cpu_relative is not None:
            for mount_name in ("cpu", "cpu,cpuacct"):
                root = self.cgroup_root / mount_name
                current = self._cgroup_dir(root, cpu_relative)
                if not current.exists():
                    continue
                directories = self._ancestor_dirs(root, cpu_relative)
                candidates = [self._inspect_v1_cpu_limit(path) for path in directories]
                scope_paths = [current] + [
                    path
                    for path, candidate in zip(directories, candidates)
                    if candidate.get("state") == "limited"
                ]
                self._cgroup_scopes.extend(
                    ("cpu", path) for path in self._dedupe_paths(scope_paths)
                )
                cpu_includes_accounting = mount_name == "cpu,cpuacct"
                controllers["cpu"] = {
                    "relative_path": self._display_path(current, root),
                    "quota_candidates": candidates,
                }
                break

        cpuacct_relative = memberships.get("cpuacct")
        if cpuacct_relative is not None and not cpu_includes_accounting:
            root = self.cgroup_root / "cpuacct"
            current = self._cgroup_dir(root, cpuacct_relative)
            if current.exists():
                self._cgroup_scopes.append(("cpuacct", current))
                controllers["cpuacct"] = {
                    "relative_path": self._display_path(current, root)
                }

        for controller, filename, unit in (
            ("memory", "memory.limit_in_bytes", "bytes"),
            ("pids", "pids.max", "tasks"),
        ):
            relative = memberships.get(controller)
            if relative is None:
                continue
            root = self.cgroup_root / controller
            current = self._cgroup_dir(root, relative)
            if not current.exists():
                continue
            directories = self._ancestor_dirs(root, relative)
            candidates = [
                self._inspect_limit(
                    path / filename,
                    unit,
                    negative_is_unlimited=True,
                    huge_value_is_unlimited=controller == "memory",
                )
                for path in directories
            ]
            scope_paths = [current] + [
                path
                for path, candidate in zip(directories, candidates)
                if candidate.get("state") == "limited"
            ]
            self._cgroup_scopes.extend(
                (controller, path) for path in self._dedupe_paths(scope_paths)
            )
            controllers[controller] = {
                "relative_path": self._display_path(current, root),
                "limit_candidates": candidates,
            }

        return {"version": 1, "controllers": controllers}

    def _capture_cgroup_scope(self, controller: str, path: Path) -> Dict[str, Any]:
        """
        Capture cgroup scope.

        The implementation uses ``controller`` and ``path`` to capture cgroup
        scope.

        Args:
            controller: Text supplied as controller in the format accepted by
                this function.
            path: filesystem location used as the path for this operation.

        Returns:
            The validated ``scope``.
        """
        scope: Dict[str, Any] = {
            "controller": controller,
            "path": self._scope_display_path(controller, path),
        }
        if self._cgroup_version == 2 or controller in {"cpu", "cpuacct"}:
            cpu: Dict[str, Any] = {}
            if self._cgroup_version == 2 or controller == "cpu":
                cpu["stat"] = self._read_key_value_ints(path / "cpu.stat")
            if self._cgroup_version == 1:
                cpu["usage_nanoseconds"] = self._read_optional_int(
                    path / "cpuacct.usage"
                )
                cpu["accounting_stat"] = self._read_key_value_ints(
                    path / "cpuacct.stat"
                )
            else:
                pressure = self._read_pressure(path / "cpu.pressure")
                if pressure:
                    cpu["pressure"] = pressure
            scope["cpu"] = cpu

        if self._cgroup_version == 2 or controller == "memory":
            if self._cgroup_version == 2:
                memory = {
                    "current_bytes": self._read_optional_int(path / "memory.current"),
                    "peak_bytes": self._read_optional_int(path / "memory.peak"),
                    "limit": self._read_limit_value(path / "memory.max"),
                    "events": self._read_key_value_ints(path / "memory.events"),
                    "events_local": self._read_key_value_ints(
                        path / "memory.events.local"
                    ),
                }
                pressure = self._read_pressure(path / "memory.pressure")
                if pressure:
                    memory["pressure"] = pressure
            else:
                memory = {
                    "current_bytes": self._read_optional_int(
                        path / "memory.usage_in_bytes"
                    ),
                    "peak_bytes": self._read_optional_int(
                        path / "memory.max_usage_in_bytes"
                    ),
                    "limit": self._read_limit_value(
                        path / "memory.limit_in_bytes",
                        negative_is_unlimited=True,
                        huge_value_is_unlimited=True,
                    ),
                    "fail_count": self._read_optional_int(path / "memory.failcnt"),
                    "oom_control": self._read_key_value_ints(
                        path / "memory.oom_control"
                    ),
                }
            scope["memory"] = memory

        if self._cgroup_version == 2 or controller == "pids":
            scope["pids"] = {
                "current": self._read_optional_int(path / "pids.current"),
                "limit": self._read_limit_value(path / "pids.max"),
                "events": self._read_key_value_ints(path / "pids.events"),
            }
        return scope

    def _inspect_cpu_max(self, path: Path) -> Dict[str, Any]:
        """
        Inspect CPU max.

        The implementation uses ``path`` to inspect CPU max.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            A mapping containing inspect CPU max.
        """
        result = {"path": self._display_cgroup_file(path)}
        raw, state = self._read_inspection_text(path)
        result.update({"raw": raw, "state": state})
        if raw is None:
            return result
        parts = raw.split()
        if len(parts) < 2:
            result["state"] = "invalid"
            return result
        if parts[0] == "max":
            result["state"] = "unlimited"
            return result
        try:
            quota, period = int(parts[0]), int(parts[1])
        except ValueError:
            result["state"] = "invalid"
            return result
        if quota <= 0 or period <= 0:
            result["state"] = "invalid"
            return result
        result.update(
            {
                "state": "limited",
                "quota_microseconds": quota,
                "period_microseconds": period,
                "cpus": quota / period,
            }
        )
        return result

    def _inspect_v1_cpu_limit(self, directory: Path) -> Dict[str, Any]:
        """
        Inspect v1 CPU limit.

        The implementation uses ``directory`` to inspect v1 CPU limit.

        Args:
            directory: filesystem location used as the directory for this
                operation.

        Returns:
            A mapping containing inspect v1 CPU limit.
        """
        quota_path = directory / "cpu.cfs_quota_us"
        period_path = directory / "cpu.cfs_period_us"
        quota_raw, quota_state = self._read_inspection_text(quota_path)
        period_raw, period_state = self._read_inspection_text(period_path)
        result: Dict[str, Any] = {
            "path": self._scope_display_path("cpu", directory),
            "quota_raw": quota_raw,
            "period_raw": period_raw,
            "state": (
                "unreadable"
                if "unreadable" in (quota_state, period_state)
                else "missing"
            ),
        }
        if quota_raw is None or period_raw is None:
            return result
        try:
            quota, period = int(quota_raw), int(period_raw)
        except ValueError:
            result["state"] = "invalid"
            return result
        if quota < 0:
            result["state"] = "unlimited"
        elif quota > 0 and period > 0:
            result.update(
                {
                    "state": "limited",
                    "quota_microseconds": quota,
                    "period_microseconds": period,
                    "cpus": quota / period,
                }
            )
        else:
            result["state"] = "invalid"
        return result

    def _inspect_limit(
        self,
        path: Path,
        unit: str,
        *,
        negative_is_unlimited: bool = False,
        huge_value_is_unlimited: bool = False,
    ) -> Dict[str, Any]:
        """
        Inspect limit.

        The implementation uses ``path``, ``unit``, ``negative_is_unlimited``,
        and ``huge_value_is_unlimited`` to inspect limit.

        Args:
            path: filesystem location used as the path for this operation.
            unit: Text supplied as unit in the format accepted by this function.
            negative_is_unlimited: Whether negative is unlimited is enabled or
                required for this operation.
            huge_value_is_unlimited: Whether huge value is unlimited is enabled
                or required for this operation.

        Returns:
            A mapping containing inspect limit.
        """
        result: Dict[str, Any] = {
            "path": self._display_cgroup_file(path),
            "unit": unit,
        }
        raw, state = self._read_inspection_text(path)
        result.update({"raw": raw, "state": state})
        if raw is None:
            return result
        if raw == "max":
            result["state"] = "unlimited"
            return result
        try:
            value = int(raw)
        except ValueError:
            result["state"] = "invalid"
            return result
        if (negative_is_unlimited and value < 0) or (
            huge_value_is_unlimited and value >= _CGROUP_V1_UNLIMITED_MEMORY_MIN
        ):
            result["state"] = "unlimited"
        elif value >= 0:
            result.update({"state": "limited", "value": value})
        else:
            result["state"] = "invalid"
        return result

    def _read_cgroup_memberships(self) -> Dict[str, Path]:
        """
        Read cgroup memberships.

        The implementation uses current instance state to read cgroup
        memberships. Parsing or I/O must finish before the validated
        representation is made available to the caller.

        Returns:
            A mapping containing cgroup memberships.
        """
        memberships: Dict[str, Path] = {}
        path = self.proc_root / "self" / "cgroup"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            self._record_error("proc_self_cgroup", exc)
            return memberships
        for line in lines:
            try:
                hierarchy, controllers, relative = line.split(":", 2)
            except ValueError:
                self._record_error("proc_self_cgroup", f"malformed line: {line!r}")
                continue
            relative_path = self._safe_relative_path(relative)
            if hierarchy == "0" and not controllers:
                memberships[""] = relative_path
            for controller in controllers.split(","):
                if controller:
                    memberships[controller] = relative_path
        return memberships

    def _read_status(self, path: Path) -> Dict[str, str]:
        """
        Read status.

        The implementation uses ``path`` to read status. Parsing or I/O must
        finish before the validated representation is made available to the
        caller.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            A mapping containing status.
        """
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            self._record_error("proc_self_status", exc)
            return {}
        result: Dict[str, str] = {}
        for line in lines:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
        return result

    def _read_key_value_ints(self, path: Path) -> Dict[str, int]:
        """
        Read key value ints.

        The implementation uses ``path`` to read key value ints. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            A mapping containing key value ints.
        """
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            self._record_error(self._display_file(path), exc)
            return {}
        result: Dict[str, int] = {}
        for line in lines:
            parts = line.replace(":", " ").split()
            if len(parts) < 2:
                continue
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                self._record_error(
                    self._display_file(path), f"non-integer counter: {line!r}"
                )
        return result

    def _read_pressure(self, path: Path) -> Dict[str, Dict[str, float | int]]:
        """
        Read pressure.

        The implementation uses ``path`` to read pressure. Parsing or I/O must
        finish before the validated representation is made available to the
        caller.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            A mapping containing pressure.
        """
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (FileNotFoundError, PermissionError):
            return {}
        except OSError as exc:
            self._record_error(self._display_file(path), exc)
            return {}
        result: Dict[str, Dict[str, float | int]] = {}
        for line in lines:
            parts = line.split()
            if not parts:
                continue
            values: Dict[str, float | int] = {}
            for part in parts[1:]:
                if "=" not in part:
                    continue
                key, raw = part.split("=", 1)
                try:
                    values[key] = int(raw) if key == "total" else float(raw)
                except ValueError:
                    continue
            result[parts[0]] = values
        return result

    def _read_optional_int(self, path: Path) -> Optional[int]:
        """
        Read optional int.

        After applying local validation, the function forwards ``path`` to
        ``int`` and preserves its return and exception contract. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The numeric optional int value, or ``None`` when the requested value
            is unavailable.
        """
        text = self._read_optional_text(path)
        if text is None:
            return None
        try:
            return int(text)
        except ValueError:
            self._record_error(self._display_file(path), f"invalid integer: {text!r}")
            return None

    def _read_limit_value(
        self,
        path: Path,
        *,
        negative_is_unlimited: bool = False,
        huge_value_is_unlimited: bool = False,
    ) -> Dict[str, Any]:
        """
        Read limit value.

        The implementation uses ``path``, ``negative_is_unlimited``, and
        ``huge_value_is_unlimited`` to read limit value. Parsing or I/O must
        finish before the validated representation is made available to the
        caller.

        Args:
            path: filesystem location used as the path for this operation.
            negative_is_unlimited: Whether negative is unlimited is enabled or
                required for this operation.
            huge_value_is_unlimited: Whether huge value is unlimited is enabled
                or required for this operation.

        Returns:
            A mapping containing the ``raw``, ``value``, ``unlimited``, and
            ``invalid`` fields.
        """
        text = self._read_optional_text(path)
        if text is None:
            return {"raw": None, "value": None}
        if text == "max":
            return {"raw": text, "value": None, "unlimited": True}
        try:
            value = int(text)
        except ValueError:
            return {"raw": text, "value": None, "invalid": True}
        if (negative_is_unlimited and value < 0) or (
            huge_value_is_unlimited and value >= _CGROUP_V1_UNLIMITED_MEMORY_MIN
        ):
            return {"raw": text, "value": None, "unlimited": True}
        return {"raw": text, "value": value, "unlimited": False}

    def _read_optional_text(self, path: Path) -> Optional[str]:
        """
        Read optional text.

        After applying local validation, the function forwards ``path`` to
        ``strip`` and preserves its return and exception contract. Parsing or
        I/O must finish before the validated representation is made available to
        the caller.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The canonical optional text, or ``None`` when the requested value is
            unavailable.
        """
        try:
            return path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return None
        except OSError as exc:
            self._record_error(self._display_file(path), exc)
            return None

    def _read_inspection_text(self, path: Path) -> Tuple[Optional[str], str]:
        """
        Read inspection text.

        The implementation uses ``path`` to read inspection text. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            A tuple containing ``status or message text`` and ``status text`` in
            that order.
        """
        try:
            return path.read_text(encoding="utf-8").strip(), "present"
        except FileNotFoundError:
            return None, "missing"
        except OSError as exc:
            self._record_error(self._display_file(path), exc)
            return None, "unreadable"

    def _update_peaks(self, sample: Dict[str, Any]) -> None:
        """
        Update peaks.

        The implementation uses ``sample`` to update peaks.

        Args:
            sample: Mapping supplying fields for update peaks.
        """
        process = sample.get("process", {})
        for key in ("rss_bytes", "peak_rss_bytes", "threads", "open_fds"):
            value = process.get(key)
            if isinstance(value, (int, float)):
                previous = self._peaks["process"].get(key)
                if previous is None or value > previous:
                    self._peaks["process"][key] = value

        for scope in sample.get("cgroup", {}).get("scopes", []):
            scope_id = self._scope_id(scope)
            peaks = self._peaks["cgroup_scopes"].setdefault(scope_id, {})
            memory = scope.get("memory", {})
            pids = scope.get("pids", {})
            for key, value in (
                ("memory_current_bytes", memory.get("current_bytes")),
                ("memory_peak_bytes", memory.get("peak_bytes")),
                ("pids_current", pids.get("current")),
            ):
                if isinstance(value, (int, float)):
                    if key not in peaks or value > peaks[key]:
                        peaks[key] = value

    def _build_deltas(self) -> Dict[str, Any]:
        """
        Build deltas.

        The implementation uses current instance state to build deltas.

        Returns:
            A mapping containing deltas.
        """
        if self._baseline is None or self._latest is None:
            return {}
        first_process = self._baseline.get("process", {})
        last_process = self._latest.get("process", {})
        process_delta = self._counter_delta(
            first_process,
            last_process,
            (
                "user_cpu_seconds",
                "system_cpu_seconds",
                "completed_children_user_cpu_seconds",
                "completed_children_system_cpu_seconds",
                "minor_page_faults",
                "major_page_faults",
                "block_input_operations",
                "block_output_operations",
                "voluntary_context_switches",
                "involuntary_context_switches",
            ),
        )
        io_delta = self._counter_delta(
            first_process.get("io", {}),
            last_process.get("io", {}),
            set(first_process.get("io", {})) | set(last_process.get("io", {})),
        )
        if io_delta:
            process_delta["io"] = io_delta

        first_scopes = {
            self._scope_id(scope): scope
            for scope in self._baseline.get("cgroup", {}).get("scopes", [])
        }
        last_scopes = {
            self._scope_id(scope): scope
            for scope in self._latest.get("cgroup", {}).get("scopes", [])
        }
        cgroup_deltas: Dict[str, Any] = {}
        for scope_id in first_scopes.keys() & last_scopes.keys():
            first = first_scopes[scope_id]
            last = last_scopes[scope_id]
            delta: Dict[str, Any] = {}
            first_cpu = first.get("cpu", {})
            last_cpu = last.get("cpu", {})
            cpu_stat_delta = self._counter_delta(
                first_cpu.get("stat", {}),
                last_cpu.get("stat", {}),
                set(first_cpu.get("stat", {})) | set(last_cpu.get("stat", {})),
            )
            if cpu_stat_delta:
                delta["cpu_stat"] = cpu_stat_delta
            for key in ("usage_nanoseconds",):
                scalar = self._counter_delta(first_cpu, last_cpu, (key,))
                if scalar:
                    delta.update(scalar)

            first_memory = first.get("memory", {})
            last_memory = last.get("memory", {})
            for source_key, target_key in (
                ("events", "memory_events"),
                ("events_local", "memory_events_local"),
            ):
                values = self._counter_delta(
                    first_memory.get(source_key, {}),
                    last_memory.get(source_key, {}),
                    set(first_memory.get(source_key, {}))
                    | set(last_memory.get(source_key, {})),
                )
                if values:
                    delta[target_key] = values
            fail_count = self._counter_delta(first_memory, last_memory, ("fail_count",))
            if fail_count:
                delta.update(fail_count)

            first_pids = first.get("pids", {})
            last_pids = last.get("pids", {})
            pids_events = self._counter_delta(
                first_pids.get("events", {}),
                last_pids.get("events", {}),
                set(first_pids.get("events", {})) | set(last_pids.get("events", {})),
            )
            if pids_events:
                delta["pids_events"] = pids_events
            if delta:
                cgroup_deltas[scope_id] = delta

        result: Dict[str, Any] = {"process": process_delta}
        if cgroup_deltas:
            result["cgroup_scopes"] = cgroup_deltas
        return result

    @staticmethod
    def _counter_delta(
        first: Mapping[str, Any],
        last: Mapping[str, Any],
        keys: Iterable[str],
    ) -> Dict[str, int | float]:
        """
        Return the counter delta.

        The implementation uses ``first``, ``last``, and ``keys`` to produce the
        counter delta.

        Args:
            first: Mapping supplying fields for counter delta.
            last: Mapping supplying fields for counter delta.
            keys: Entries supplied as ``keys`` without transferring container
                ownership.

        Returns:
            The validated ``delta``.
        """
        delta: Dict[str, int | float] = {}
        for key in keys:
            start = first.get(key)
            end = last.get(key)
            if (
                isinstance(start, (int, float))
                and not isinstance(start, bool)
                and isinstance(end, (int, float))
                and not isinstance(end, bool)
            ):
                delta[key] = max(0, end - start)
        return delta

    @staticmethod
    def _scope_id(scope: Mapping[str, Any]) -> str:
        """
        Return the scope identifier.

        The implementation uses ``scope`` to produce the scope identifier.

        Args:
            scope: Mapping supplying fields for scope identifier.

        Returns:
            The canonical scope identifier text.
        """
        controller = scope.get("controller", "unknown")
        path = scope.get("path", "/")
        return f"{controller}:{path}"

    def _record_error(self, source: str, error: object) -> None:
        """
        Record error.

        The implementation uses ``source`` and ``error`` to record error.

        Args:
            source: Text supplied as source in the format accepted by this
                function.
            error: Exception or failure detail associated with the operation.
        """
        message = str(error)
        key = (source, message)
        if key in self._error_keys:
            return
        self._error_keys.add(key)
        if len(self._errors) >= _MAX_RECORDED_ERRORS:
            return
        self._errors.append(
            {"timestamp": _utc_now(), "source": source, "error": message}
        )

    @staticmethod
    def _safe_relative_path(raw: str) -> Path:
        """
        Return the safe relative path.

        The implementation uses ``raw`` to produce the safe relative path.

        Args:
            raw: Text supplied as raw in the format accepted by this function.

        Returns:
            The validated safe relative path filesystem path.
        """
        path = Path(raw.lstrip("/"))
        if any(part in {".", ".."} for part in path.parts):
            return Path()
        return path

    @staticmethod
    def _cgroup_dir(root: Path, relative_path: Path) -> Path:
        """
        Return the cgroup dir.

        After applying local validation, the function forwards ``root`` and
        ``relative_path`` to ``root.joinpath`` and preserves its return and
        exception contract.

        Args:
            root: filesystem location used as the root for this operation.
            relative_path: filesystem location used as the relative path for
                this operation.

        Returns:
            The validated cgroup dir filesystem path.
        """
        return root.joinpath(*relative_path.parts)

    @staticmethod
    def _ancestor_dirs(root: Path, relative_path: Path) -> List[Path]:
        """
        Return the ancestor dirs.

        The implementation uses ``root`` and ``relative_path`` to produce the
        ancestor dirs.

        Args:
            root: filesystem location used as the root for this operation.
            relative_path: filesystem location used as the relative path for
                this operation.

        Returns:
            The ancestor dirs returned in operation-defined order.
        """
        current = ResourceUsageMonitor._cgroup_dir(root, relative_path)
        directories: List[Path] = []
        while True:
            directories.append(current)
            if current == root:
                break
            if root not in current.parents:
                return [root]
            current = current.parent
        return directories

    @staticmethod
    def _dedupe_paths(paths: Iterable[Path]) -> List[Path]:
        """
        Return the dedupe paths.

        The implementation uses ``paths`` to produce the dedupe paths.

        Args:
            paths: filesystem location used as the paths for this operation.

        Returns:
            The validated ``result``.
        """
        result: List[Path] = []
        seen: set[Path] = set()
        for path in paths:
            if path not in seen:
                seen.add(path)
                result.append(path)
        return result

    def _display_cgroup_path(self, path: Path) -> str:
        """
        Display cgroup path.

        After applying local validation, the function forwards ``path`` to
        ``self._display_path`` and preserves its return and exception contract.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The canonical display cgroup path.
        """
        return self._display_path(path, self.cgroup_root)

    def _display_cgroup_file(self, path: Path) -> str:
        """
        Display cgroup file.

        After applying local validation, the function forwards ``path`` to
        ``self._display_path`` and preserves its return and exception contract.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The canonical display cgroup file text.
        """
        return self._display_path(path, self.cgroup_root)

    def _scope_display_path(self, controller: str, path: Path) -> str:
        """
        Return the scope display path.

        The implementation uses ``controller`` and ``path`` to produce the scope
        display path.

        Args:
            controller: Text supplied as controller in the format accepted by
                this function.
            path: filesystem location used as the path for this operation.

        Returns:
            The canonical scope display path.
        """
        if self._cgroup_version == 2:
            return self._display_cgroup_path(path)
        roots = {
            "cpu": (
                self.cgroup_root / "cpu",
                self.cgroup_root / "cpu,cpuacct",
            ),
            "cpuacct": (self.cgroup_root / "cpuacct",),
            "memory": (self.cgroup_root / "memory",),
            "pids": (self.cgroup_root / "pids",),
        }
        for root in roots.get(controller, (self.cgroup_root,)):
            if path == root or root in path.parents:
                return self._display_path(path, root)
        return str(path)

    def _display_file(self, path: Path) -> str:
        """
        Display file.

        The implementation uses ``path`` to display file.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The canonical display file text.
        """
        for root in (self.proc_root, self.cgroup_root):
            if path == root or root in path.parents:
                return self._display_path(path, root)
        return str(path)

    @staticmethod
    def _display_path(path: Path, root: Path) -> str:
        """
        Display path.

        The implementation uses ``path`` and ``root`` to display path.

        Args:
            path: filesystem location used as the path for this operation.
            root: filesystem location used as the root for this operation.

        Returns:
            The canonical display path.
        """
        try:
            relative = path.relative_to(root)
        except ValueError:
            return str(path)
        value = relative.as_posix()
        return "/" if value == "." else f"/{value}"

    @staticmethod
    def _first_int(value: Optional[str]) -> Optional[int]:
        """
        Return the first int.

        After applying local validation, the function forwards ``value`` to
        ``int`` and preserves its return and exception contract.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The numeric first int value, or ``None`` when the requested value is
            unavailable.
        """
        if not value:
            return None
        try:
            return int(value.split()[0])
        except (ValueError, IndexError):
            return None

    @classmethod
    def _status_kib_value(cls, value: Optional[str]) -> Optional[int]:
        """
        Return the status kib value.

        The implementation uses ``value`` to produce the status kib value.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The numeric status kib value, or ``None`` when the requested value
            is unavailable.
        """
        parsed = cls._first_int(value)
        return parsed * 1024 if parsed is not None else None
