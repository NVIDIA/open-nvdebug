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
Execution Engine for NVDebug Tool.

Handles collector execution strategies with support for sequential and parallel
execution, priority-based scheduling, and progress tracking across multiple
DUTs.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
)

from rich.progress import (
    Progress,
)

from ..config import DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT
from ..services.base_service import BaseService
from ..utils.collector_resource_profile import profile_for_collector
from ..utils.cpu_resources import resolve_collector_operation_resources
from ..utils.enums import CollectorServiceMapping
from ..utils.redfish_diagnostic_concurrency import (
    diagnostic_concurrency_profile_for_collector,
    resolve_redfish_diagnostic_concurrency_cohort,
)
from ..utils.runtime_boundary_profile import runtime_boundary_value
from ..utils.transport_support import (
    collector_service_from_metadata,
    collector_transport_support_decision,
)
from .admission_controller import (
    AdaptiveAdmissionController,
    AdmissionControllerSettings,
    EndpointCooldownRegistry,
    RemotePressureWindow,
    RuntimePressureSampler,
    SchedulerEvidenceRecorder,
    WeightedResizableLimiter,
    classify_remote_pressure,
)
from .async_logger import _collector_context
from .collector_outcome import normalize_collector_result
from .finalization_receipt import (
    capture_owned_awaitable,
    drain_owned_tasks,
    select_authoritative_exception,
)
from .redfish_controller import collector_preflight_result

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _EndpointCohortWaiter:
    """
    Identify one ordered Redfish endpoint-admission request.

    Object identity distinguishes the exact queue entry even when multiple
    collectors request the same compatible token.

    Attributes:
        ticket: Monotonic process-local request order for fairness.
        token: Compatible cohort label or unique exclusive request token.
    """

    ticket: int
    token: str


class _EndpointCohortAdmission:
    """
    Admit compatible Redfish collectors while excluding every other cohort.

    Same-token requests may share the endpoint.  An earlier incompatible
    waiter stops later same-token arrivals from extending the active cohort
    indefinitely, while unique tokens retain ordinary exclusive behavior.
    """

    def __init__(self) -> None:
        """
        Initialize empty run-scoped endpoint admission state.

        Side Effects:
            Creates an asynchronous condition bound lazily to the running event
            loop and initializes deterministic waiter ordering.
        """

        self._condition = asyncio.Condition()
        self._active_token: Optional[str] = None
        self._active_count = 0
        self._next_ticket = 0
        self._waiters: List[_EndpointCohortWaiter] = []

    def _can_admit(self, waiter: _EndpointCohortWaiter) -> bool:
        """
        Return whether one queued request may enter without bypassing a peer.

        An idle endpoint admits only its oldest waiter. An active compatible
        cohort admits later peers only until an incompatible waiter is ahead.

        Args:
            waiter: Ordered request whose compatibility and queue position are
                evaluated.

        Returns:
            Whether the request may join or establish the active cohort.
        """

        if self._active_count == 0:
            return bool(self._waiters and self._waiters[0] is waiter)
        if self._active_token != waiter.token:
            return False
        for queued in self._waiters:
            if queued is waiter:
                return True
            if queued.token != waiter.token:
                return False
        return False

    @asynccontextmanager
    async def lease(self, cohort: Optional[str]) -> AsyncIterator[None]:
        """
        Acquire one compatible or exclusive endpoint lease.

        Exclusive requests receive an internal token that cannot collide with
        validated catalog cohort labels. Every exit path releases its active
        count and notifies queued owners.

        Args:
            cohort: Validated compatible cohort label, or ``None`` for an
                ordinary exclusive collector.

        Yields:
            Control after endpoint admission is held.

        Raises:
            asyncio.CancelledError: If the owner is cancelled while queued or
                while executing inside the lease.

        Side Effects:
            Mutates bounded waiter and active-owner state and wakes peers after
            admission, cancellation, or release.
        """

        async with self._condition:
            ticket = self._next_ticket
            self._next_ticket += 1
            token = cohort if cohort is not None else f"\0exclusive-{ticket}"
            waiter = _EndpointCohortWaiter(ticket=ticket, token=token)
            self._waiters.append(waiter)
            try:
                while not self._can_admit(waiter):
                    await self._condition.wait()
            except BaseException:
                if waiter in self._waiters:
                    self._waiters.remove(waiter)
                    self._condition.notify_all()
                raise

            self._waiters.remove(waiter)
            if self._active_count == 0:
                self._active_token = waiter.token
            self._active_count += 1
            self._condition.notify_all()

        try:
            yield
        finally:
            async with self._condition:
                self._active_count -= 1
                if self._active_count == 0:
                    self._active_token = None
                self._condition.notify_all()


async def _drain_execution_awaitables(
    awaitables: Sequence[Awaitable[Any]],
) -> tuple[Any | BaseException, ...]:
    """
    Own and drain a bounded execution-engine child set to terminal state.

    Ordinary child exceptions are returned in positional order so scheduler
    branches can emit per-DUT or per-service failures while allowing siblings
    to finish. Process-control exceptions cancel and drain every sibling before
    the deterministic authoritative control is re-raised.

    Args:
        awaitables: Finite child operations whose ownership transfers to this
            invocation.

    Returns:
        Positional child values, with ordinary ``Exception`` instances retained
        as data for branch-specific result construction.

    Raises:
        asyncio.CancelledError: After all owned children are drained when the
            owner or a child is cancelled.
        KeyboardInterrupt: After all owned children are drained when observed.
        SystemExit: After all owned children are drained when observed.

    Side effects:
        Creates one wrapper task per child and observes every terminal outcome.
    """

    owned_tasks = tuple(
        asyncio.create_task(capture_owned_awaitable(awaitable))
        for awaitable in awaitables
    )
    outcomes = await drain_owned_tasks(
        owned_tasks,
        cancel_on_error=lambda error: not isinstance(error, Exception),
    )
    controls = tuple(
        outcome.error
        for outcome in outcomes
        if outcome.error is not None
        and not isinstance(outcome.error, Exception)
        and not outcome.owner_cancelled
    )
    if controls:
        raise select_authoritative_exception(controls)
    return tuple(
        outcome.error if outcome.error is not None else outcome.value
        for outcome in outcomes
    )


@dataclass(frozen=True, slots=True, eq=False)
class _CollectorSkipDecision:
    """
    Typed pre-execution decision with legacy two-value unpacking.

    ``_should_skip_collector`` historically returned ``(should_skip, reason)``.
    Retaining that iteration contract keeps programmatic callers compatible,
    while ``skip_phase`` lets every scheduler produce truthful terminal result
    metadata without rediscovering the cause from free-form reason text.

    Attributes:
        should_skip: Whether skip applies to this record.
        reason: Canonical reason exposed to downstream status consumers.
        skip_phase: Canonical text used as skip phase.
    """

    should_skip: bool
    reason: str = ""
    skip_phase: Optional[str] = None

    def __iter__(self) -> Iterator[object]:
        """
        Iterate over the entries owned by the _CollectorSkipDecision.

        The implementation uses current instance state to iterate over the
        entries owned by the _CollectorSkipDecision.

        Yields:
            Each operation admitted by the operation, in deterministic iteration
            order.
        """
        yield self.should_skip
        yield self.reason

    def __eq__(self, other: object) -> bool:
        """
        Return whether another value represents the same state.

        The implementation uses ``other`` to determine whether another value
        represents the same state.

        Args:
            other: Other object whose ``reason``, ``should_skip``, and
                ``skip_phase`` state is read while performing another value
                represents the same state.

        Returns:
            Whether another value represents the same state.
        """
        if isinstance(other, _CollectorSkipDecision):
            return (
                self.should_skip,
                self.reason,
                self.skip_phase,
            ) == (
                other.should_skip,
                other.reason,
                other.skip_phase,
            )
        if isinstance(other, (tuple, list)):
            return (self.should_skip, self.reason) == tuple(other)
        return NotImplemented


class ExecutionEngine:
    """
    Manages collector execution strategies and progress tracking.

    Handles sequential and parallel collector execution across multiple DUTs
    with support for priority-based scheduling and service grouping.
    """

    def __init__(
        self,
        config_manager,
        dut_manager,
        logger,
        orchestrator=None,
        preflight_results=None,
        status_tracker=None,
    ):
        """
        Initialize an ``ExecutionEngine`` instance.

        The initializer records ``config_manager``, ``cpu_resource_resolution``,
        ``dut_manager``, ``logger``, and ``orchestrator`` for later operations
        and establishes the instance invariants before any public method runs.

        Args:
            config_manager: Config manager governing initialize an
                ``ExecutionEngine`` instance.
            dut_manager: DUT manager consumed while the function attempts to
                initialize an ``ExecutionEngine`` instance.
            logger: Sanitized logger used for operator-visible diagnostics.
            orchestrator: Optional orchestrator; ``None`` selects the function's
                default behavior.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.
            status_tracker: Optional status tracker; ``None`` selects the
                function's default behavior.
        """
        self.config_manager = config_manager
        self.dut_manager = dut_manager
        self.logger = logger
        self.orchestrator = orchestrator
        self.preflight_results = preflight_results or {}
        self.status_tracker = status_tracker
        self._host_service_admission_semaphores: Dict[
            tuple[str, str], asyncio.Semaphore
        ] = {}
        execution_config = self._get_execution_config_mapping()
        configured_oversubscription = execution_config.get(
            "initial_io_oversubscription"
        )
        if configured_oversubscription is None:
            self.cpu_resource_resolution = resolve_collector_operation_resources()
        else:
            self.cpu_resource_resolution = resolve_collector_operation_resources(
                configured_oversubscription
            )
        self.admission_settings = AdmissionControllerSettings.from_execution_config(
            execution_config,
            derived_initial_limit=(
                self.cpu_resource_resolution.collector_operation_limit
            ),
        )
        self._remote_pressure_window = RemotePressureWindow()
        self._endpoint_cooldowns = EndpointCooldownRegistry()
        self._redfish_endpoint_admissions: Dict[str, _EndpointCohortAdmission] = {}
        self.admission_controller: Optional[AdaptiveAdmissionController] = None
        self.scheduler_evidence: Optional[SchedulerEvidenceRecorder] = None
        self.configure_global_collector_operation_limit(
            self.admission_settings.initial_limit
        )

    def _get_execution_config_mapping(self) -> Dict[str, Any]:
        """
        Return canonical execution settings from dict or model config holders.

        Programmatic and older callers may supply only flat tool fields.  This
        boundary projects those accepted aliases without mutating the owning
        configuration object; production config loading already rejects
        contradictory spellings.

        Returns:
            A detached execution configuration mapping.
        """

        try:
            tool_config = self.config_manager.get_tool_config()
        except Exception:
            tool_config = {}
        if isinstance(tool_config, Mapping):
            execution = tool_config.get("execution_config") or tool_config.get(
                "execution"
            )
        else:
            execution = getattr(tool_config, "execution_config", None) or getattr(
                tool_config, "execution", None
            )
        if hasattr(execution, "model_dump"):
            dumped = execution.model_dump()
            resolved = dict(dumped) if isinstance(dumped, Mapping) else {}
        elif isinstance(execution, Mapping):
            resolved = dict(execution)
        else:
            resolved = {}

        for field_name, default in (
            ("concurrency_mode", "conservative"),
            ("initial_io_oversubscription", None),
            ("minimum_collector_operations", 1),
            ("maximum_collector_operations", None),
        ):
            if field_name in resolved:
                continue
            if isinstance(tool_config, Mapping):
                resolved[field_name] = tool_config.get(field_name, default)
            else:
                resolved[field_name] = getattr(tool_config, field_name, default)
        if not isinstance(resolved.get("concurrency_mode"), str):
            resolved["concurrency_mode"] = "conservative"
        initial_oversubscription = resolved.get("initial_io_oversubscription")
        if not isinstance(initial_oversubscription, (int, float)) or isinstance(
            initial_oversubscription, bool
        ):
            resolved["initial_io_oversubscription"] = None
        for field_name, fallback in (
            ("minimum_collector_operations", 1),
            ("maximum_collector_operations", None),
        ):
            value = resolved.get(field_name)
            if value is not None and type(value) is not int:
                resolved[field_name] = fallback
        if not isinstance(resolved.get("adaptive", {}), Mapping):
            resolved["adaptive"] = {}
        return resolved

    @property
    def global_collector_operation_limit(self) -> int:
        """
        Return the collector admission capacity currently installed.

        The property exposes the live limiter value rather than the initial
        configuration because adaptive decisions may resize it during a run.
        Fixed and adaptive modes interpret the units as governed weights;
        conservative mode retains one unit per collector.

        Returns:
            The positive limiter capacity, including adaptive changes.
        """

        return self._global_collector_operation_limiter.capacity

    def configure_global_collector_operation_limit(self, limit: int) -> None:
        """
        Install the shared limiter before collector tasks are started.

        The implementation uses ``limit`` to install the work-conserving
        weighted limiter before collector tasks are started.  Reconfiguration
        replaces only an idle pre-run limiter; adaptive changes use its
        asynchronous resize API.

        Args:
            limit: Numeric limit used while the operation performs bounded
                accounting.

        Raises:
            TypeError: If ``limit`` cannot be converted to an integer.
            ValueError: If ``limit`` has an invalid integer representation.
            RuntimeError: If collector operations still own the existing
                limiter when replacement is requested.
        """
        installed_limit = max(1, int(limit))
        existing = getattr(self, "_global_collector_operation_limiter", None)
        if existing is not None and existing.active_operations:
            raise RuntimeError(
                "cannot replace the global collector limiter while operations are active"
            )
        self._global_collector_operation_limiter = WeightedResizableLimiter(
            installed_limit
        )

    def configure_admission_controller(
        self,
        *,
        resource_monitor: Any,
        evidence_path: Path | str,
        plan_summary: Mapping[str, Any],
    ) -> None:
        """
        Bind pressure sampling and bounded evidence before collector tasks start.

        The resolved plan is checked against the hard admission ceiling before
        constructing run-owned sampler, evidence, and controller objects.

        Args:
            resource_monitor: Existing run-owned local resource monitor.
            evidence_path: Owned scheduler metadata artifact path.
            plan_summary: Deterministic post-preflight scheduling summary.

        Raises:
            RuntimeError: If a controller is replaced while already running.
            ValueError: If an explicit fixed/adaptive ceiling cannot admit a
                declared weighted operation.
        """

        controller = self.admission_controller
        if controller is not None and controller.evidence.status == "running":
            raise RuntimeError("admission controller is already running")
        maximum_weight = int(
            plan_summary.get("workload_profiles", {}).get("maximum_operation_weight", 1)
        )
        if (
            self.admission_settings.mode in {"fixed", "adaptive"}
            and maximum_weight > self.admission_settings.maximum_limit
        ):
            raise ValueError(
                "maximum_collector_operations cannot admit the plan's largest "
                f"resource weight ({maximum_weight})"
            )
        evidence = SchedulerEvidenceRecorder(
            evidence_path,
            settings=self.admission_settings,
            plan_summary=plan_summary,
        )
        sampler = RuntimePressureSampler(
            resource_monitor,
            effective_cpus=self.cpu_resource_resolution.effective_cpus,
            remote_window=self._remote_pressure_window,
            maximum_resident_bytes=self.admission_settings.maximum_resident_bytes,
        )
        self.scheduler_evidence = evidence
        self.admission_controller = AdaptiveAdmissionController(
            settings=self.admission_settings,
            limiter=self._global_collector_operation_limiter,
            sampler=sampler,
            evidence=evidence,
            log_callback=self._log_admission_controller,
        )

    async def start_admission_controller(self) -> None:
        """
        Start scheduler evidence and its bounded observation sampling task.

        Owned asynchronous work is awaited through the controller lifecycle.
        """

        if self.admission_controller is not None:
            await self.admission_controller.start()

    async def stop_admission_controller(self, *, interrupted: bool = False) -> None:
        """
        Stop scheduler observation and atomically finalize its evidence.

        Controller shutdown is delegated through its idempotent lifecycle so
        workflow cleanup can safely call this from success or failure paths.

        Args:
            interrupted: Whether cancellation or shutdown interrupted execution.
        """

        if self.admission_controller is not None:
            await self.admission_controller.stop(interrupted=interrupted)

    async def _log_admission_controller(self, level: str, message: str) -> None:
        """
        Route bounded controller messages through the sanitized runtime logger.

        Keeping adaptive messages on the existing logging path preserves the
        repository's sanitization and output ownership guarantees.

        Args:
            level: Standard runtime log level.
            message: Bounded message constructed from governed reason codes.
        """

        await self._log_runtime(level, message)

    def _redfish_diagnostic_concurrency_cohort(
        self,
        dut_id: str,
        collector_id: str,
        service: Optional[BaseService] = None,
    ) -> Optional[str]:
        """
        Resolve one catalog-authorized endpoint-sharing cohort.

        Missing policy, an inapplicable baseboard, or a shared-HMC route keeps
        the collector exclusive.  Explicit malformed catalog policy propagates
        from the common validation boundary instead of silently enabling work.

        Args:
            dut_id: Stable DUT identifier used to resolve the concrete
                baseboard and route.
            collector_id: Stable collector identifier used for catalog lookup.
            service: Optional service used to preserve shared-HMC exclusion.

        Returns:
            The validated compatible cohort, or ``None`` for exclusive
            endpoint admission.

        Raises:
            ValueError: If explicit catalog concurrency metadata is malformed.
        """

        definitions = self.config_manager.get_collector_definitions()
        if not isinstance(definitions, Mapping):
            return None
        collectors = definitions.get("collectors", definitions)
        if not isinstance(collectors, Mapping):
            return None
        definition = collectors.get(collector_id)
        if not isinstance(definition, Mapping):
            return None
        profile = diagnostic_concurrency_profile_for_collector(
            definition,
            collector_id=str(collector_id)[:128],
        )
        if profile is None:
            return None

        if service is not None:
            shared_hmc_key = None
            hmc_key_resolver = getattr(service, "_hmc_diagnostic_lock_key", None)
            if callable(hmc_key_resolver):
                shared_hmc_key = hmc_key_resolver(dut_id)
            if isinstance(shared_hmc_key, str) and shared_hmc_key:
                return None

        try:
            dut_config = self.dut_manager.get_dut_config(dut_id) or {}
        except (AttributeError, KeyError, TypeError, ValueError):
            dut_config = {}
        if isinstance(dut_config, Mapping):
            baseboard_name = dut_config.get("baseboard")
        else:
            baseboard_name = getattr(dut_config, "baseboard", None)

        baseboard_manager = None
        manager_getter = getattr(self.dut_manager, "_get_baseboard_manager", None)
        if callable(manager_getter):
            baseboard_manager = manager_getter()
        return resolve_redfish_diagnostic_concurrency_cohort(
            profile,
            baseboard_name=baseboard_name,
            baseboard_manager=baseboard_manager,
            context=f"collector {str(collector_id)[:128]}",
        )

    def _ordered_sequential_collector_batches(
        self,
        dut_id: str,
        collectors: Sequence[str],
    ) -> List[List[str]]:
        """
        Partition an ordered service lane into compatible collector batches.

        Every selected collector sharing the same explicit cohort is combined
        at that cohort's first position. This permits catalog-authorized dump
        types with non-adjacent IDs to overlap without allowing an unprofiled or
        differently profiled request into the batch. Unconfigured collectors
        remain singleton batches in their original relative order.

        Args:
            dut_id: Stable DUT identifier used for platform policy resolution.
            collectors: Ordered collectors from one sequential service lane.

        Returns:
            Non-empty batches containing each input entry exactly once. Cohort
            members may move ahead of intervening singleton collectors so the
            authorized cohort can execute as one wave.

        Raises:
            ValueError: If explicit catalog concurrency metadata is malformed.
        """

        resolved = [
            (
                collector_id,
                self._redfish_diagnostic_concurrency_cohort(dut_id, collector_id),
            )
            for collector_id in collectors
        ]
        batches: List[List[str]] = []
        emitted_cohorts: set[str] = set()
        for collector_id, cohort in resolved:
            if cohort is None:
                batches.append([collector_id])
                continue
            if cohort in emitted_cohorts:
                continue
            batches.append(
                [
                    candidate_id
                    for candidate_id, candidate_cohort in resolved
                    if candidate_cohort == cohort
                ]
            )
            emitted_cohorts.add(cohort)
        return batches

    async def _execute_collector_with_global_limit(
        self,
        service: BaseService,
        dut_id: str,
        collector_id: str,
        collection_level: str,
        start_status_tracking: bool = False,
        per_dut_semaphore: Optional[asyncio.Semaphore] = None,
        on_admitted: Optional[Callable[[], Awaitable[None]]] = None,
    ) -> Dict[str, Any]:
        """
        Execute one collector under endpoint-local and weighted global policy.

        Host collectors acquire a per-DUT service slot before an optional
        generic per-DUT slot and the weighted global lease. Its capacity is derived
        from the validated Host SSH pool capacity, so collectors do not create a
        large queue behind an intentionally narrow endpoint. Redfish collectors
        acquire per-DUT endpoint admission before waiting for cooldown or
        global capacity. Catalog-authorized collectors in the same compatible
        cohort may share that admission; different cohorts and ordinary
        collectors remain exclusive without consuming a permit while queued.

        Args:
            service: Service object whose ``execute_collector`` state is read
                while performing one real collector while holding the shared
                operation slot.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            start_status_tracking: Whether start status tracking is enabled or
                required for this operation.
            per_dut_semaphore: Optional generic per-DUT scheduler slot supplied
                by the parallel execution path. When present, this function
                acquires it after the Host service slot and before the shared
                global slot; callers must not acquire it separately.
            on_admitted: Optional asynchronous callback invoked exactly once
                after every required admission slot is held and immediately
                before status tracking and service execution. Callers use it to
                publish truthful execution-progress transitions.

        Returns:
            A mapping containing the collector result.

        Raises:
            asyncio.CancelledError: If the caller cancels while awaiting an
                admission slot or while the collector is executing.
        """
        service_label = self._admission_service_label(service)
        host_service_semaphore = self._get_host_service_admission_semaphore(
            service, dut_id
        )

        async def execute_after_per_dut_admission() -> Dict[str, Any]:
            """
            Start status tracking and execute after all local slots are held.

            The nested callable performs the last shared global admission only
            after any Host service and generic per-DUT slots are held. It does
            not create background work; cancellation propagates to the caller
            and asynchronous context managers release every acquired slot.

            Returns:
                A mapping containing the collector result.

            Raises:
                asyncio.CancelledError: If cancellation occurs while acquiring
                    the global slot or executing the collector.
            """

            # A shutdown can arrive while the parallel path waits for its
            # generic per-DUT slot. Keep the prior pre-execution check at the
            # centralized admission boundary without occupying global capacity.
            if (
                hasattr(self.orchestrator, "is_shutdown_requested")
                and self.orchestrator.is_shutdown_requested()
            ):
                return {
                    "status": "interrupted",
                    "reason": "Shutdown requested",
                    "execution_time": 0.0,
                    "execution_started": False,
                }

            async def execute_weighted() -> Dict[str, Any]:
                """
                Execute after endpoint and weighted admission are complete.

                This boundary starts collector-visible work only after every
                scheduler lease has been acquired.

                Returns:
                    A mapping containing the collector result.

                Raises:
                    asyncio.CancelledError: If collector execution is cancelled.
                """
                return await self._execute_admitted_collector(
                    service=service,
                    service_label=service_label,
                    dut_id=dut_id,
                    collector_id=collector_id,
                    collection_level=collection_level,
                    start_status_tracking=start_status_tracking,
                    on_admitted=on_admitted,
                )

            if service_label.startswith("redfish"):
                cohort = self._redfish_diagnostic_concurrency_cohort(
                    dut_id,
                    collector_id,
                    service,
                )
                endpoint_admission = self._redfish_endpoint_admissions.get(str(dut_id))
                if endpoint_admission is None:
                    endpoint_admission = _EndpointCohortAdmission()
                    self._redfish_endpoint_admissions[str(dut_id)] = endpoint_admission
                async with endpoint_admission.lease(cohort):
                    return await execute_weighted()
            return await execute_weighted()

        async def execute_after_host_admission() -> Dict[str, Any]:
            """
            Acquire optional generic per-DUT capacity after Host capacity.

            The parallel scheduler supplies its existing generic per-DUT
            semaphore here so a Host waiter cannot consume a generic slot.
            Non-parallel callers omit it and retain their previous global-only
            admission after any Host service slot.

            Returns:
                A mapping containing the collector result.

            Raises:
                asyncio.CancelledError: If cancellation occurs while acquiring
                    the generic per-DUT slot or executing the collector.
            """

            if per_dut_semaphore is not None:
                async with per_dut_semaphore:
                    return await execute_after_per_dut_admission()
            return await execute_after_per_dut_admission()

        if host_service_semaphore is not None:
            async with host_service_semaphore:
                return await execute_after_host_admission()

        return await execute_after_host_admission()

    def _get_host_service_admission_semaphore(
        self,
        service: BaseService,
        dut_id: str,
    ) -> Optional[asyncio.Semaphore]:
        """
        Return the shared per-DUT Host collector admission semaphore when needed.

        The Host SSH pool owns command-level safety. This scheduler-level gate
        prevents whole Host collectors from creating unbounded queue delay in
        front of a deliberately limited endpoint. The limit is the smaller of
        the existing per-DUT collector limit and the validated pool's session
        by usable-command capacity. Each session can admit no more concurrent
        commands than its channel and lifetime command limits allow. A
        semaphore is created lazily only for the real ``host`` service; static
        and preflight skips never call this method.

        Args:
            service: Service selected for the collector execution.
            dut_id: Stable DUT identifier used to isolate Host endpoints.

        Returns:
            The run-owned Host service semaphore, or ``None`` for non-Host
            services or incomplete lightweight test doubles.
        """

        if getattr(service, "service_name", None) != "host":
            return None

        pool_config = getattr(self.dut_manager, "host_ssh_pool_config", None)
        if isinstance(pool_config, Mapping):
            sessions = pool_config.get("max_sessions_per_endpoint")
            channels = pool_config.get("max_channels_per_session")
            commands = pool_config.get("max_commands_per_session")
        else:
            sessions = getattr(pool_config, "max_sessions_per_endpoint", None)
            channels = getattr(pool_config, "max_channels_per_session", None)
            commands = getattr(pool_config, "max_commands_per_session", None)

        # The production manager owns a validated SSHConnectionPoolConfig. Do
        # not invent a capacity for incomplete legacy test doubles or callers.
        if (
            isinstance(sessions, bool)
            or not isinstance(sessions, int)
            or sessions < 1
            or isinstance(channels, bool)
            or not isinstance(channels, int)
            or channels < 1
            or isinstance(commands, bool)
            or not isinstance(commands, int)
            or commands < 1
        ):
            return None

        limit = min(
            self._get_max_concurrent_collectors_per_dut(dut_id),
            sessions * min(channels, commands),
        )
        admission_key = (dut_id, "host")
        semaphore = self._host_service_admission_semaphores.get(admission_key)
        if semaphore is None:
            semaphore = asyncio.Semaphore(limit)
            self._host_service_admission_semaphores[admission_key] = semaphore
        return semaphore

    @staticmethod
    def _admission_service_label(service: BaseService) -> str:
        """
        Return a bounded in-memory service label for admission accounting.

        The normalized label is suitable for aggregate evidence and never
        includes endpoint identity or collector output.

        Args:
            service: Collector service owning the operation.

        Returns:
            A lower-case service label bounded to 64 characters.
        """

        raw = str(getattr(service, "service_name", "unknown") or "unknown")
        normalized = "_".join(raw.strip().lower().split())
        return normalized[:64] or "unknown"

    def _collector_resource_weight(self, collector_id: str) -> int:
        """
        Resolve one collector's governed effective resource weight.

        Conservative mode deliberately keeps legacy one-per-collector
        accounting. Fixed and adaptive opt-in modes pass runtime catalog data
        through the shared strict profile parser; collectors without an
        authored profile retain weight-one behavior.

        Args:
            collector_id: Stable catalog collector identifier.

        Returns:
            The positive effective weight, defaulting to one when no profile is
            declared.

        Raises:
            ValueError: If the runtime catalog contains an invalid profile.
        """

        if self.admission_settings.mode == "conservative":
            return 1
        get_definitions = getattr(
            self.config_manager, "get_collector_definitions", None
        )
        catalog = get_definitions() if callable(get_definitions) else {}
        definitions = (
            catalog.get("collectors", catalog) if isinstance(catalog, Mapping) else {}
        )
        definition = (
            definitions.get(collector_id, {})
            if isinstance(definitions, Mapping)
            else {}
        )
        if not isinstance(definition, Mapping):
            definition = {}
        return profile_for_collector(
            definition, collector_id=collector_id[:128]
        ).effective_weight

    async def _execute_admitted_collector(
        self,
        *,
        service: BaseService,
        service_label: str,
        dut_id: str,
        collector_id: str,
        collection_level: str,
        start_status_tracking: bool,
        on_admitted: Optional[Callable[[], Awaitable[None]]] = None,
    ) -> Dict[str, Any]:
        """
        Execute one collector while owning its cooldown and weighted lease.

        Status timing begins only after admission, and every terminal path
        classifies pressure and releases capacity in owned cleanup. A cancelled
        service records its terminal disposition before cancellation propagates;
        repeated caller cancellation cannot abandon that status publication.

        Args:
            service: Collector service owning the operation.
            service_label: Bounded lane label used only for scheduler metrics.
            dut_id: Stable DUT identity used only for in-memory endpoint policy.
            collector_id: Stable governed collector identifier.
            collection_level: Resolved collection level forwarded to service.
            start_status_tracking: Whether terminal tracking starts after
                admission rather than at the caller.
            on_admitted: Optional callback invoked after weighted admission and
                before status tracking or collector execution.

        Returns:
            The service's collector result mapping.

        Raises:
            BaseException: Preserves collector, status-tracker, cancellation,
                and cleanup failures after capacity is released.
        """

        weight = self._collector_resource_weight(collector_id)
        await self._endpoint_cooldowns.wait(dut_id, service_label)
        lease = await self._global_collector_operation_limiter.acquire(weight)
        evidence = self.scheduler_evidence
        if evidence is not None:
            evidence.record_admission(service_label, lease.wait_seconds)

        started = time.monotonic()
        service_started = False
        remote_events: tuple[str, ...] = ()
        try:
            if on_admitted is not None:
                await on_admitted()
            if start_status_tracking and self.status_tracker:
                await self._log_runtime(
                    "DEBUG",
                    f"Starting collector {dut_id}:{collector_id} after global admission",
                    dut_id=dut_id,
                )
                await self.status_tracker.start_collector(dut_id, collector_id)
            service_started = True
            result = await service.execute_collector(
                dut_id, collector_id, collection_level
            )
            remote_events = classify_remote_pressure(result)
            return result
        except BaseException as error:
            remote_events = classify_remote_pressure(error)
            if (
                isinstance(error, asyncio.CancelledError)
                and service_started
                and self.status_tracker
            ):
                completion = asyncio.create_task(
                    capture_owned_awaitable(
                        self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "cancelled",
                            reason="Collector execution was cancelled",
                            execution_time=max(0.0, time.monotonic() - started),
                        )
                    )
                )
                try:
                    (outcome,) = await drain_owned_tasks(
                        (completion,), cancel_on_wait_error=False
                    )
                except BaseException as completion_error:
                    raise select_authoritative_exception(
                        (error, completion_error)
                    ) from error
                if outcome.error is not None:
                    raise select_authoritative_exception(
                        (error, outcome.error)
                    ) from error
            raise
        finally:
            duration = max(0.0, time.monotonic() - started)
            self._remote_pressure_window.record_operation(
                duration_seconds=duration,
                remote_events=remote_events,
                endpoint_key=f"{dut_id}:{service_label}",
            )
            if evidence is not None:
                evidence.record_remote_events(service_label, remote_events)
            if remote_events and self.admission_settings.mode == "adaptive":
                cooldown = self.admission_settings.endpoint_cooldown_seconds
                self._endpoint_cooldowns.impose(dut_id, service_label, cooldown)
                if evidence is not None:
                    for event in remote_events:
                        evidence.record_endpoint_cooldown(service_label, event)
            try:
                await lease.release()
            finally:
                if evidence is not None:
                    evidence.record_release(service_label, duration)

    async def _log_runtime(
        self,
        level: str,
        message: str,
        component: str = "ExecutionEngine",
        dut_id: str = None,
    ) -> None:
        """
        Log runtime.

        The implementation uses ``level``, ``message``, ``component``, and
        ``dut_id`` to log runtime. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
            component: Text supplied as component in the format accepted by this
                function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if hasattr(self, "logger") and self.logger:
            # Use async logger if available
            if dut_id:
                await self.logger.write_to_dut_runtime_log(
                    dut_id, level, component, message
                )
            else:
                await self.logger.log_runtime(level, component, message)
        else:
            # Fallback to standard logger
            if level == "ERROR":
                logger.error(message)
            elif level == "WARNING":
                logger.warning(message)
            elif level == "DEBUG":
                logger.debug(message)
            else:
                logger.info(message)

    def set_preflight_results(self, preflight_results: Dict[str, Any]) -> None:
        """
        Set preflight results for collector execution decisions.

        The implementation uses ``preflight_results`` to set preflight results
        for collector execution decisions. It updates ``preflight_results`` on
        the instance as part of that state transition.

        Args:
            preflight_results: Mapping supplying fields for set preflight
                results for collector execution decisions.
        """
        self.preflight_results = preflight_results or {}

    def _normalize_skip_decision(
        self,
        decision: Any,
        *,
        default_skip_phase: str,
    ) -> _CollectorSkipDecision:
        """
        Coerce legacy/mocked decision pairs into the typed contract.

        The implementation uses ``decision`` and ``default_skip_phase`` to
        coerce legacy/mocked decision pairs into the typed contract.

        Args:
            decision: Decision consumed while the function attempts to coerce
                legacy/mocked decision pairs into the typed contract.
            default_skip_phase: Text supplied as default skip phase in the
                format accepted by this function.

        Returns:
            A ``_CollectorSkipDecision`` representing skip decision.
        """
        if isinstance(decision, _CollectorSkipDecision):
            return decision

        should_skip, reason = decision
        skip_phase = default_skip_phase if should_skip else None
        if (
            should_skip
            and default_skip_phase != "configuration"
            and self._is_baseboard_skip_reason(reason)
        ):
            skip_phase = "baseboard"
        return _CollectorSkipDecision(bool(should_skip), str(reason), skip_phase)

    @staticmethod
    def _authored_exclusion_type(
        decision: _CollectorSkipDecision,
    ) -> Optional[str]:
        """
        Return the authored exclusion class for one pre-execution decision.

        Configuration, baseboard, and capability decisions describe work that
        the authored plan intentionally excludes. Preflight and dependency
        decisions instead describe runtime work that could not start, so they
        remain visible as skipped collectors in the run-level reduction.

        Args:
            decision: Typed skip decision whose phase identifies why work did
                not enter collector execution.

        Returns:
            The canonical authored exclusion type, or ``None`` for a runtime
            skip.
        """
        if decision.skip_phase in {"configuration", "baseboard", "capability"}:
            return decision.skip_phase
        return None

    @staticmethod
    def _build_pre_execution_skip_result(
        decision: _CollectorSkipDecision,
    ) -> Dict[str, Any]:
        """
        Build one terminal leaf for work stopped before collector entry.

        The implementation uses ``decision`` to build one terminal leaf for work
        stopped before collector entry. If the function cannot build one
        terminal leaf for work stopped before collector entry, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            decision: Decision object whose ``reason``, ``should_skip``, and
                ``skip_phase`` state is read while performing one terminal leaf
                for work stopped before collector entry.

        Returns:
            A mapping containing the ``status``, ``reason``, ``execution_time``,
            ``execution_started``, and ``skip_phase`` fields.

        Raises:
            ValueError: If a skipped result lacks a typed pre-execution phase.
        """
        if not decision.should_skip or not decision.skip_phase:
            raise ValueError("A skipped result requires a typed pre-execution phase")
        return {
            "status": "skipped",
            "reason": decision.reason,
            "execution_time": 0.0,
            "execution_started": False,
            "skip_phase": decision.skip_phase,
        }

    def _get_max_concurrent_collectors_per_dut(
        self, dut_id: Optional[str] = None
    ) -> int:
        """
        Return the operator cap tightened by an optional baseboard budget.

        The implementation uses ``dut_id`` to produce the operator cap tightened
        by an optional baseboard budget.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``resolved_limit``.
        """
        try:
            tool_config = self.config_manager.get_tool_config()
        except Exception:
            tool_config = {}

        if isinstance(tool_config, dict):
            execution_config = tool_config.get("execution_config", {})
        else:
            execution_config = getattr(tool_config, "execution_config", {})

        if isinstance(execution_config, dict):
            raw_limit = execution_config.get(
                "max_concurrent_collectors_per_dut",
                DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT,
            )
        else:
            raw_limit = getattr(
                execution_config,
                "max_concurrent_collectors_per_dut",
                DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT,
            )

        try:
            resolved_limit = max(1, int(raw_limit))
        except (TypeError, ValueError, OverflowError):
            # Config loading rejects these values. Keep this defensive path
            # conservative for programmatic/mocked callers that bypass it.
            resolved_limit = 1

        if dut_id:
            try:
                dut_config = self.dut_manager.get_dut_config(dut_id) or {}
            except Exception:
                dut_config = {}
            resolved_limit = min(
                resolved_limit,
                runtime_boundary_value(dut_config, "collector_max_concurrent_per_dut"),
            )
        return resolved_limit

    # def set_progress_state(self, progress_state) -> None:
    #     """Set progress state manager for tracking execution progress"""
    #     self.progress_state = progress_state

    async def _get_service_for_collector(
        self, collector_id: str
    ) -> Optional[BaseService]:
        """
        Get the appropriate service for a collector.

        After applying local validation, the function forwards ``collector_id``
        to ``services.get`` and preserves its return and exception contract.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A ``BaseService`` representing service for collector, or ``None``
            when the requested value is unavailable.
        """
        service_name = self._get_service_name_for_collector(collector_id)
        services = self.config_manager.get_services()

        await self._log_runtime(
            "DEBUG",
            f"Looking for service '{service_name}' for collector {collector_id}, available services: {list(services.keys())}",
        )

        return services.get(service_name)

    def _get_collector_name(self, collector_id: str) -> str:
        """
        Get the collector name from collector definitions.

        The implementation uses ``collector_id`` to get the collector name from
        collector definitions.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical collector name.
        """
        try:
            # Get collector definitions from config manager
            collector_definitions = self.config_manager.get_collector_definitions()
            # The structure is {'collectors': {'R1': {...}, 'R2': {...}}}
            if (
                "collectors" in collector_definitions
                and collector_id in collector_definitions["collectors"]
            ):
                name = collector_definitions["collectors"][collector_id].get(
                    "name", collector_id
                )
                return name
            else:
                return collector_id
        except Exception:
            return collector_id

    def _get_collector_id_from_path(self, collector_path: str) -> str:
        """
        Extract collector ID from collector path.

        The implementation uses ``collector_path`` to extract collector ID from
        collector path.

        Args:
            collector_path: filesystem location used as the collector path for
                this operation.

        Returns:
            The canonical collector identifier from path.
        """
        try:
            # Handle different path formats
            if "/" in collector_path:
                # Path format: "path/to/collector"
                return collector_path.split("/")[-1]
            elif "." in collector_path:
                # Dot format: "path.to.collector"
                return collector_path.split(".")[-1]
            else:
                return collector_path
        except Exception:
            return collector_path

    def _get_tool_include_collectors(self, tool_config: Any = None) -> List[str]:
        """
        Retrieve the list of collectors explicitly included via tool configuration.

        The implementation uses ``tool_config`` to retrieve the list of
        collectors explicitly included via tool configuration.

        Args:
            tool_config: Optional Tool config governing retrieve the list of
                collectors explicitly included via tool configuration.

        Returns:
            The tool include collectors returned in operation-defined order.
        """
        if tool_config is None:
            try:
                tool_config = self.config_manager.get_tool_config()
            except Exception:
                tool_config = {}

        include_collectors: Any = []
        if isinstance(tool_config, dict):
            include_collectors = tool_config.get("include_collectors", []) or []
        else:
            include_collectors = getattr(tool_config, "include_collectors", []) or []

        if isinstance(include_collectors, str):
            return [
                cid.strip()
                for cid in include_collectors.split(",")
                if cid and cid.strip()
            ]

        if isinstance(include_collectors, (list, tuple, set)):
            return [str(cid).strip() for cid in include_collectors if str(cid).strip()]

        return []

    async def _get_local_mode_skip_decision(
        self, dut_id: str, dut: Any, service_name: str
    ) -> Optional[_CollectorSkipDecision]:
        """
        Return local mode skip decision.

        The implementation uses ``dut_id``, ``dut``, and ``service_name`` to
        produce local mode skip decision. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut: Stable DUT used to correlate configuration, logs, and results.
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.

        Returns:
            A ``_CollectorSkipDecision`` representing local mode skip decision,
            or ``None`` when the requested value is unavailable.
        """
        if not (dut and dut.config and dut.config.get("local", False)):
            return None

        await self._log_runtime(
            "DEBUG",
            f"Local mode detected for DUT {dut_id}, service {service_name}",
            dut_id=dut_id,
        )
        credentials = getattr(dut, "credentials", None)
        has_bmc_ip = bool(getattr(credentials, "bmc_ip", None))
        if has_bmc_ip:
            await self._log_runtime(
                "DEBUG",
                f"BMC IP available in local mode for DUT {dut_id}, service {service_name}",
                dut_id=dut_id,
            )
            return None

        await self._log_runtime(
            "DEBUG",
            f"No BMC IP in local mode for DUT {dut_id}, service {service_name}",
            dut_id=dut_id,
        )
        if service_name in ["redfish", "ssh"]:
            await self._log_runtime(
                "DEBUG",
                f"Skipping {service_name} collector in local mode (no BMC IP)",
                dut_id=dut_id,
            )
            return _CollectorSkipDecision(
                should_skip=True,
                reason=f"Collector not executed due to {service_name} preflight failure: No BMC IP configured (local mode)",
                skip_phase="preflight",
            )

        if service_name in ["ipmi", "host"]:
            await self._log_runtime(
                "DEBUG",
                f"Allowing {service_name} collector in local mode (no BMC IP)",
                dut_id=dut_id,
            )
            return _CollectorSkipDecision(False)

        return None

    async def _should_skip_collector(
        self, collector_id: str, dut_id: str
    ) -> _CollectorSkipDecision:
        """
        Check if collector should be skipped based on preflight and baseboard.

        The implementation uses ``collector_id`` and ``dut_id`` to check if
        collector should be skipped based on preflight and baseboard. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A ``_CollectorSkipDecision`` representing should skip collector.
        """
        transport_skip, transport_reason = (
            self._should_skip_collector_by_catalog_transport(collector_id, dut_id)
        )
        if transport_skip:
            return _CollectorSkipDecision(
                True, transport_reason, skip_phase="baseboard"
            )

        service_name = self._get_service_name_for_collector(collector_id)

        # Check baseboard applicability first
        if self.orchestrator and self.orchestrator.dut_manager:
            dut = self.orchestrator.dut_manager.get_dut(dut_id)
            if dut and dut.config:
                local_skip_decision = await self._get_local_mode_skip_decision(
                    dut_id, dut, service_name
                )
                baseboard_info = dut.config.get("baseboard") or dut.config.get(
                    "TargetBaseboard"
                )
                node_type = dut.config.get("NodeType") or dut.config.get("node_type")

                # If no baseboard is configured, this is a critical configuration error
                # The tool should not run without proper baseboard configuration
                if not baseboard_info or baseboard_info == "Unknown":
                    if local_skip_decision is not None:
                        return local_skip_decision

                    reason = f"CRITICAL ERROR: DUT {dut_id} has no baseboard configured ('{baseboard_info}'). Baseboard is required for collector compatibility. Please configure baseboard in DUT config."
                    await self._log_runtime(
                        "ERROR",
                        f"CRITICAL: DUT {dut_id} missing baseboard configuration - cannot determine collector compatibility",
                        dut_id=dut_id,
                    )
                    self.orchestrator.sanitized_console.print_failure(
                        f"DUT {dut_id} has no baseboard configuration, so collector "
                        "compatibility cannot be determined.",
                        title="Missing Baseboard Configuration",
                        suggestions=(
                            "Configure the baseboard for this DUT in the DUT config file.",
                            "Run platform detection before collector execution.",
                        ),
                    )
                    sys.exit(1)

                collector_def = self.orchestrator.config_manager.get_collector_info(
                    collector_id
                )

                try:
                    if collector_def and node_type:
                        is_applicable = (
                            self.orchestrator.is_collector_applicable_for_baseboard(
                                collector_def, baseboard_info, node_type=node_type
                            )
                        )
                    else:
                        is_applicable = (
                            collector_def
                            and self.orchestrator.is_collector_applicable_for_baseboard(
                                collector_def, baseboard_info
                            )
                        )
                except ValueError as e:
                    # Baseboard not found in spreadsheet - this is a critical configuration error
                    # Log the error and exit
                    error_msg = str(e)
                    await self._log_runtime(
                        "ERROR",
                        f"CRITICAL: {error_msg}",
                        dut_id=dut_id,
                    )
                    self.orchestrator.sanitized_console.print_failure(
                        error_msg,
                        title="Invalid Baseboard Configuration",
                        suggestions=(
                            "Configure a baseboard present in the selected Telemetry Catalog.",
                            "Run 'nvdebug list-baseboards' to inspect supported platforms.",
                        ),
                    )
                    sys.exit(1)

                if collector_def and not is_applicable:
                    # Check why it's not applicable
                    tags = collector_def.get("tags", {})
                    if isinstance(tags, dict):
                        include_tags = tags.get("include", [])
                        exclude_tags = tags.get("exclude", [])
                    else:
                        include_tags = []
                        exclude_tags = []

                    if exclude_tags:
                        reason = f"Collector not applicable for DUT {dut_id} baseboard '{baseboard_info}' (Tags: {exclude_tags})"
                    elif include_tags:
                        reason = f"Collector not applicable for DUT {dut_id} baseboard '{baseboard_info}' (BaseboardConstraint)"
                    else:
                        reason = f"Collector not applicable for DUT {dut_id} baseboard '{baseboard_info}' (BaseboardConstraint)"

                    # If this collector is explicitly included via --include-collectors,
                    # do not skip it here. Preserve the reason so the caller can emit a warning.
                    include_collectors = self._get_tool_include_collectors()
                    if include_collectors and collector_id in include_collectors:
                        return _CollectorSkipDecision(False, reason)

                    return _CollectorSkipDecision(True, reason, skip_phase="baseboard")

                if local_skip_decision is not None:
                    return local_skip_decision

        # Check preflight results
        if not self.preflight_results:
            return _CollectorSkipDecision(False)

        # Health check collectors don't require preflight checks
        if service_name == "health_check":
            return _CollectorSkipDecision(False)

        if service_name and dut_id in self.preflight_results:
            # Get DUT-specific preflight results
            dut_preflight = self.preflight_results[dut_id]
            if (
                "services" in dut_preflight
                and service_name in dut_preflight["services"]
            ):
                definitions = self.config_manager.get_collector_definitions()
                definitions = definitions.get("collectors", definitions)
                definition = definitions.get(collector_id, {})
                config = (
                    self.orchestrator.dut_manager.get_dut_config(dut_id)
                    if self.orchestrator and self.orchestrator.dut_manager
                    else {}
                )
                service_result = collector_preflight_result(
                    dut_preflight, service_name, definition, config
                )
                if service_result.get("status") == "fail":
                    # Get the actual preflight failure reason
                    failure_reason = service_result.get(
                        "message", "Unknown preflight failure"
                    )
                    reason = f"Collector not executed due to {service_name} preflight failure: {failure_reason}"
                    return _CollectorSkipDecision(True, reason, skip_phase="preflight")
            else:
                # Debug: Log what services are available
                available_services = (
                    list(dut_preflight.get("services", {}).keys())
                    if "services" in dut_preflight
                    else []
                )
                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} for DUT {dut_id}: service_name={service_name}, available_services={available_services}",
                    dut_id=dut_id,
                )

        return _CollectorSkipDecision(False)

    def _should_skip_collector_by_catalog_transport(
        self, collector_id: str, dut_id: str
    ) -> tuple[bool, str]:
        """
        Enforce explicit baseboard transport exclusions before execution.

        Transport declarations belong to a resolved baseboard catalog row. Let
        the normal applicability path reject a missing/unknown baseboard instead
        of allowing a support flag in an incomplete DUT config to turn that
        configuration error into a successful skip.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """

        collector = self.config_manager.get_collector_info(collector_id) or {}
        try:
            dut = self.dut_manager.get_dut(dut_id)
        except (KeyError, TypeError, ValueError, AttributeError):
            return False, ""

        dut_config = getattr(dut, "config", None)
        if not isinstance(dut_config, dict):
            return False, ""

        # Transport declarations belong to a resolved baseboard catalog row.
        # Let the normal applicability path reject a missing/unknown baseboard
        # instead of allowing a support flag in an incomplete DUT config to
        # turn that configuration error into a successful skip.
        baseboard = dut_config.get("baseboard") or dut_config.get("TargetBaseboard")
        if not isinstance(baseboard, str) or not baseboard.strip():
            return False, ""
        baseboard = baseboard.strip()
        if baseboard.lower() == "unknown":
            return False, ""

        supported, unsupported = collector_transport_support_decision(
            collector, dut_config
        )
        if supported or not unsupported:
            return False, ""

        declarations = ", ".join(
            f"{field_name}=false" for field_name in sorted(unsupported.values())
        )
        return (
            True,
            f"Collector {collector_id} is not applicable for baseboard "
            f"'{baseboard}': catalog transport support declares {declarations} "
            "(BaseboardConstraint)",
        )

    @staticmethod
    def _is_baseboard_skip_reason(reason: str) -> bool:
        """
        Return True when a skip reason came from baseboard applicability.

        The implementation uses ``reason`` to produce True when a skip reason
        came from baseboard applicability.

        Args:
            reason: Text supplied as reason in the format accepted by this
                function.

        Returns:
            Whether the true when a skip reason came from baseboard
            applicability operation succeeds.
        """
        reason_lower = (reason or "").lower()
        return (
            "not applicable for dut" in reason_lower and "baseboard" in reason_lower
        ) or "baseboardconstraint" in reason_lower

    @staticmethod
    def _custom_service_config_keys(collector: Dict[str, Any]) -> List[str]:
        """
        Return config keys consumed by custom-service execution hooks.

        The implementation uses ``collector`` to produce config keys consumed by
        custom-service execution hooks.

        Args:
            collector: Mapping supplying fields for config keys consumed by
                custom-service execution hooks.

        Returns:
            The validated ``keys``.
        """
        hooks = collector.get("stages", {}).get("execution", {}).get("hooks", [])
        keys: List[str] = []
        for hook in hooks if isinstance(hooks, list) else []:
            if (
                not isinstance(hook, dict)
                or hook.get("method") != "collect_custom_service_executor"
            ):
                continue
            params = hook.get("params", {})
            if not isinstance(params, dict):
                continue
            service_config = params.get("service_config", {})
            if not isinstance(service_config, dict):
                continue
            config_key = service_config.get("config_key", "CUSTOM_DUMP_SERVICES")
            if isinstance(config_key, str) and config_key and config_key not in keys:
                keys.append(config_key)
        return keys

    @staticmethod
    def _exclusive_uri_list_config_keys(
        collector: Dict[str, Any],
    ) -> List[str]:
        """
        Return URI-list keys when config is the sole execution data source.

        Static URIs, additional execution hooks, and dynamic discovery can all
        produce targets, so those collectors must reach the service layer.

        Args:
            collector: Mapping supplying fields for URI-list keys when config is
                the sole execution data source.

        Returns:
            The exclusive URI list config keys returned in operation-defined
            order.
        """
        hooks = collector.get("stages", {}).get("execution", {}).get("hooks", [])
        if not isinstance(hooks, list) or not hooks:
            return []

        keys: List[str] = []
        for hook in hooks:
            if (
                not isinstance(hook, dict)
                or hook.get("method") != "collect_redfish_unified"
            ):
                return []
            params = hook.get("params")
            if not isinstance(params, dict):
                return []

            config_key = params.get("uri_list_key")
            if not isinstance(config_key, str) or not config_key.strip():
                return []
            if params.get("collection_type") != "uri_list":
                return []
            if (
                params.get("dynamic_uri_discovery")
                or params.get("uri_list")
                or params.get("uri_patterns")
            ):
                return []

            normalized_key = config_key.strip()
            if normalized_key not in keys:
                keys.append(normalized_key)

        return keys

    @staticmethod
    def _effective_dut_tool_config_value(
        config_key: str,
        dut_config: Dict[str, Any],
        tool_config: Dict[str, Any],
    ) -> Any:
        """
        Resolve a DUT-over-tool value without discarding explicit empties.

        The implementation uses ``config_key``, ``dut_config``, and
        ``tool_config`` to resolve a DUT-over-tool value without discarding
        explicit empties.

        Args:
            config_key: Stable config key used for lookup and operator-facing
                diagnostics.
            dut_config: DUT config governing DUT-over-tool value without
                discarding explicit empties.
            tool_config: Tool config governing DUT-over-tool value without
                discarding explicit empties.

        Returns:
            The effective DUT tool config value selected by the operation.
        """
        if config_key in dut_config:
            return dut_config[config_key]
        return tool_config.get(config_key)

    @staticmethod
    def _uri_list_configs_are_provably_empty(
        config_keys: List[str],
        dut_config: Dict[str, Any],
        tool_config: Dict[str, Any],
    ) -> bool:
        """
        Return True only when every URI-list source is safely empty.

        Malformed non-list values are deliberately left for runtime validation
        instead of being hidden as a pre-execution applicability exclusion.

        Args:
            config_keys: Config keys governing true only when every URI-list
                source is safely empty.
            dut_config: DUT config governing true only when every URI-list
                source is safely empty.
            tool_config: Tool config governing true only when every URI-list
                source is safely empty.

        Returns:
            Whether the true only when every URI-list source is safely empty
            operation succeeds.
        """
        if not config_keys:
            return False

        for config_key in config_keys:
            value = ExecutionEngine._effective_dut_tool_config_value(
                config_key, dut_config, tool_config
            )
            if value is None:
                continue
            if not isinstance(value, list):
                return False
            if value:
                return False
        return True

    async def _should_skip_collector_by_capability(
        self, collector_id: str, dut_id: str
    ) -> tuple[bool, str]:
        """
        Gate a collector using canonical live Redfish capability data.

        Capability absence is distinct from an unavailable capability endpoint.
        The former skips a collector; the latter follows ``on_unavailable`` and
        defaults to allowing legacy platforms to retain their previous
        behaviour.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        collector = self.config_manager.get_collector_info(collector_id) or {}
        requirement = collector.get("redfish_capability")
        if not isinstance(requirement, dict) or not requirement:
            return False, ""

        # Mixed-scope collectors can contain an independent Manager diagnostic
        # hook alongside their System/Dump hook.  In that case the live map must
        # filter the rendered System payload, not suppress the whole collector.
        if str(requirement.get("scope", "collector")).strip().lower() == "payload":
            return False, ""

        source = requirement.get("source")
        parameter = requirement.get("parameter")
        if source != "system_dump_action_info" or parameter != "OEMDiagnosticDataType":
            await self._log_runtime(
                "WARNING",
                f"Collector {collector_id} has unsupported redfish_capability "
                f"source/parameter ({source!r}/{parameter!r}); allowing collector",
                dut_id=dut_id,
            )
            return False, ""

        values = requirement.get("any_of", [])
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not values:
            await self._log_runtime(
                "WARNING",
                f"Collector {collector_id} has no redfish_capability.any_of values; "
                "allowing collector",
                dut_id=dut_id,
            )
            return False, ""
        values = [value for value in values if isinstance(value, str) and value]
        if not values:
            return False, ""

        supports = (
            getattr(self.orchestrator, "supports_system_dump_value", None)
            if self.orchestrator
            else None
        )
        if not callable(supports):
            return False, ""

        decisions = [supports(dut_id, value) for value in values]
        if any(decision is True for decision in decisions):
            return False, ""

        if any(decision is None for decision in decisions):
            on_unavailable = (
                str(requirement.get("on_unavailable", "allow")).strip().lower()
            )
            if on_unavailable != "skip":
                await self._log_runtime(
                    "DEBUG",
                    f"Live capability data unavailable for collector {collector_id}; "
                    "preserving catalog applicability",
                    dut_id=dut_id,
                )
                return False, ""
            return (
                True,
                f"Collector {collector_id} skipped because System Dump ActionInfo "
                "capability data is unavailable",
            )

        return (
            True,
            f"Collector {collector_id} skipped because live System Dump ActionInfo "
            f"does not advertise any required {parameter} value: {values}",
        )

    async def apply_capability_filter_per_dut(
        self,
        filtered_collectors: Dict[str, List[str]],
        skipped_collectors: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        """
        Apply only live-capability gating to an existing execution plan.

        This supports callers that invoke
        ``WorkflowOrchestrator.execute_collectors`` directly with pre-filtered
        lists instead of using the CLI selection path. Input dictionaries and
        lists are copied rather than mutated.

        Args:
            filtered_collectors: Mapping supplying fields for apply only
                live-capability gating to an existing execution plan.
            skipped_collectors: Optional skipped collectors; ``None`` selects
                the function's default behavior.

        Returns:
            A mapping containing the ``filtered_collectors`` and
            ``skipped_collectors`` fields.
        """
        filtered_result: Dict[str, List[str]] = {
            dut_id: list(collector_ids)
            for dut_id, collector_ids in (filtered_collectors or {}).items()
        }
        skipped_result: Dict[str, List[Dict[str, Any]]] = {
            dut_id: list(entries)
            for dut_id, entries in (skipped_collectors or {}).items()
        }

        for dut_id, collector_ids in filtered_result.items():
            kept: List[str] = []
            dut_skipped = skipped_result.setdefault(dut_id, [])
            for collector_id in collector_ids:
                should_skip, reason = await self._should_skip_collector_by_capability(
                    collector_id, dut_id
                )
                if not should_skip:
                    kept.append(collector_id)
                    continue

                collector = self.config_manager.get_collector_info(collector_id) or {}
                dut_skipped.append(
                    {
                        "collector_id": collector_id,
                        "collector_name": collector.get("name", "Unknown"),
                        "group": collector.get("group", "Unknown"),
                        "reason": reason,
                        "skip_type": "capability",
                    }
                )
            filtered_result[dut_id] = kept

        return {
            "filtered_collectors": filtered_result,
            "skipped_collectors": skipped_result,
        }

    async def get_filtered_collectors_per_dut(
        self, collector_ids: List[str], dut_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Get filtered collectors for each DUT based on all filtering criteria.

        This method applies:

        1. Baseboard filtering (per-DUT).
        2. Live Redfish capability filtering (when authoritative).
        3. Skip flags (tool config + DUT config overrides).
        4. Include/exclude collectors (tool config + DUT config overrides).

        Args:
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.

        Returns:
            A mapping containing the ``filtered_collectors`` and
            ``skipped_collectors`` fields.
        """
        await self._log_runtime(
            "INFO",
            f"Starting per-DUT filtering for {len(dut_ids)} DUT(s) with {len(collector_ids)} input collectors",
        )
        await self._log_runtime(
            "DEBUG",
            f"Input collector IDs: {collector_ids}",
        )
        await self._log_runtime(
            "DEBUG",
            f"Input DUT IDs: {dut_ids}",
        )

        filtered_collectors_per_dut = {}
        skipped_collectors_per_dut = {}

        await self._log_runtime(
            "INFO",
            f"About to iterate over {len(dut_ids)} DUT(s): {dut_ids}",
        )
        await self._log_runtime(
            "INFO",
            f"About to check {len(collector_ids)} collector(s): {collector_ids}",
        )
        await self._log_runtime(
            "INFO",
            f"Type of dut_ids: {type(dut_ids)}, Type of collector_ids: {type(collector_ids)}",
        )
        await self._log_runtime(
            "INFO",
            f"Bool check - dut_ids: {bool(dut_ids)}, collector_ids: {bool(collector_ids)}",
        )

        iteration_count = 0
        for dut_id in dut_ids:
            iteration_count += 1
            await self._log_runtime(
                "DEBUG",
                f"FOR LOOP: Starting DUT iteration {iteration_count} for {dut_id}",
                dut_id=dut_id,
            )
            await self._log_runtime(
                "INFO",
                f"Processing DUT {dut_id} for filtering",
                dut_id=dut_id,
            )
            dut_filtered = []
            dut_skipped = []
            skipped_by_config = 0
            skipped_by_baseboard = 0
            skipped_by_capability = 0

            await self._log_runtime(
                "DEBUG",
                f"DUT {dut_id}: Starting collector loop with {len(collector_ids)} collectors: {collector_ids}",
                dut_id=dut_id,
            )
            collector_loop_count = 0
            for collector_id in collector_ids:
                collector_loop_count += 1
                await self._log_runtime(
                    "DEBUG",
                    f"COLLECTOR LOOP: Iteration {collector_loop_count} - checking collector {collector_id} for DUT {dut_id}",
                    dut_id=dut_id,
                )

                # An explicit catalog transport exclusion is a physical
                # applicability constraint.  Evaluate it before user include
                # overrides so neither -S nor --include-collectors can force an
                # unsupported protocol.
                transport_skip, transport_reason = (
                    self._should_skip_collector_by_catalog_transport(
                        collector_id, dut_id
                    )
                )
                if transport_skip:
                    collector_info = (
                        self.config_manager.get_collector_info(collector_id) or {}
                    )
                    await self._log_runtime(
                        "INFO",
                        f"Filtering out {collector_id} for DUT {dut_id}: "
                        f"{transport_reason}",
                        dut_id=dut_id,
                    )
                    skipped_by_baseboard += 1
                    dut_skipped.append(
                        {
                            "collector_id": collector_id,
                            "collector_name": collector_info.get("name", "Unknown"),
                            "group": collector_info.get("group", "Unknown"),
                            "reason": transport_reason,
                            "skip_type": "baseboard",
                        }
                    )
                    continue

                # Check baseboard applicability FIRST (hard requirement, cannot be overridden)
                (
                    should_skip_baseboard,
                    baseboard_reason,
                ) = await self._should_skip_collector(collector_id, dut_id)

                await self._log_runtime(
                    "DEBUG",
                    f"Baseboard check for {collector_id}: should_skip={should_skip_baseboard}, reason={baseboard_reason}",
                    dut_id=dut_id,
                )

                # If this collector was included via --include-collectors, allow it to run
                # even if baseboard compatibility would normally fail. We'll still record a warning.
                try:
                    tool_config = self.config_manager.get_tool_config()
                except Exception:
                    tool_config = {}
                include_collectors = self._get_tool_include_collectors(tool_config)
                explicitly_requested_list = []
                explicitly_requested_str = ""
                if isinstance(tool_config, dict):
                    explicitly_requested_str = tool_config.get("collector_id", "")
                else:
                    explicitly_requested_str = getattr(tool_config, "collector_id", "")
                if explicitly_requested_str:
                    explicitly_requested_list = [
                        cid.strip() for cid in explicitly_requested_str.split(",")
                    ]

                is_from_include = (
                    bool(include_collectors) and collector_id in include_collectors
                )
                is_from_s_flag = (
                    bool(explicitly_requested_list)
                    and collector_id in explicitly_requested_list
                )

                # Handle baseboard compatibility override for --include-collectors
                if should_skip_baseboard and is_from_include and not is_from_s_flag:
                    await self._log_runtime(
                        "WARNING",
                        f"{baseboard_reason} - forcing run due to --include-collectors",
                        dut_id=dut_id,
                    )
                    should_skip_baseboard = False
                    # No need for override_warning_logged flag as we've already logged it
                elif (
                    (not should_skip_baseboard)
                    and is_from_include
                    and (not is_from_s_flag)
                    and baseboard_reason
                ):
                    # Log warning for incompatible but included collectors
                    await self._log_runtime(
                        "WARNING",
                        f"{baseboard_reason} - forcing run due to --include-collectors",
                        dut_id=dut_id,
                    )

                # Skip baseboard-incompatible collectors unless explicitly allowed
                if should_skip_baseboard:
                    await self._log_runtime(
                        "DEBUG",
                        f"Filtering out {collector_id} for DUT {dut_id}: {baseboard_reason}",
                        dut_id=dut_id,
                    )
                    skipped_by_baseboard += 1

                    # Track skipped collector with reason
                    collector_info = self.config_manager.get_collector_info(
                        collector_id
                    )
                    collector_name = (
                        collector_info.get("name", "Unknown")
                        if collector_info
                        else "Unknown"
                    )
                    group = (
                        collector_info.get("group", "Unknown")
                        if collector_info
                        else "Unknown"
                    )
                    dut_skipped.append(
                        {
                            "collector_id": collector_id,
                            "collector_name": collector_name,
                            "group": group,
                            "reason": baseboard_reason,
                            "skip_type": "baseboard",
                        }
                    )
                    continue

                # Not skipping due to baseboard. If it was included and had an incompatibility reason,
                # this warning was already logged earlier, so we skip it here to avoid duplicates.

                # An explicit include may override the static baseboard allowlist,
                # but it must not force a payload the live firmware explicitly
                # rejects.  Unknown/legacy ActionInfo remains fail-open.
                (
                    should_skip_capability,
                    capability_reason,
                ) = await self._should_skip_collector_by_capability(
                    collector_id, dut_id
                )
                if should_skip_capability:
                    await self._log_runtime(
                        "INFO",
                        f"Filtering out {collector_id} for DUT {dut_id}: "
                        f"{capability_reason}",
                        dut_id=dut_id,
                    )
                    skipped_by_capability += 1
                    collector_info = self.config_manager.get_collector_info(
                        collector_id
                    )
                    dut_skipped.append(
                        {
                            "collector_id": collector_id,
                            "collector_name": (
                                collector_info.get("name", "Unknown")
                                if collector_info
                                else "Unknown"
                            ),
                            "group": (
                                collector_info.get("group", "Unknown")
                                if collector_info
                                else "Unknown"
                            ),
                            "reason": capability_reason,
                            "skip_type": "capability",
                        }
                    )
                    continue

                # Check if collector should be skipped by config (SKIP flags, skip_collectors list)
                (
                    should_skip_config,
                    skip_reason,
                ) = await self._should_skip_collector_by_config(collector_id, dut_id)

                if should_skip_config:
                    await self._log_runtime(
                        "DEBUG",
                        f"Filtering out {collector_id} for DUT {dut_id}: {skip_reason}",
                        dut_id=dut_id,
                    )
                    skipped_by_config += 1

                    # Track skipped collector with reason
                    collector_info = self.config_manager.get_collector_info(
                        collector_id
                    )
                    collector_name = (
                        collector_info.get("name", "Unknown")
                        if collector_info
                        else "Unknown"
                    )
                    group = (
                        collector_info.get("group", "Unknown")
                        if collector_info
                        else "Unknown"
                    )

                    skip_type = (
                        "config_applicability"
                        if "configuration is empty" in (skip_reason or "").lower()
                        else "config"
                    )
                    dut_skipped.append(
                        {
                            "collector_id": collector_id,
                            "collector_name": collector_name,
                            "group": group,
                            "reason": skip_reason,
                            "skip_type": skip_type,
                        }
                    )
                    continue

                # Collector passed all filters
                dut_filtered.append(collector_id)
                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} passed all filters for DUT {dut_id}",
                    dut_id=dut_id,
                )

            await self._log_runtime(
                "DEBUG",
                f"DUT {dut_id}: Collector loop complete. Filtered: {dut_filtered}, Skipped: {len(dut_skipped)}",
                dut_id=dut_id,
            )

            filtered_collectors_per_dut[dut_id] = dut_filtered
            skipped_collectors_per_dut[dut_id] = dut_skipped

            # Summarize skip reasons compactly
            if skipped_by_config > 0:
                skip_reasons = {}
                for s in dut_skipped:
                    if s.get("skip_type") == "config":
                        reason = s.get("reason", "unknown")
                        flag = (
                            reason.split("due to ")[-1].split("=")[0]
                            if "due to " in reason
                            else reason
                        )
                        skip_reasons.setdefault(flag, []).append(s["collector_id"])
                skip_summary = "; ".join(
                    f"{flag}: {','.join(ids)}" for flag, ids in skip_reasons.items()
                )
                await self._log_runtime(
                    "INFO",
                    f"DUT {dut_id} skipped {skipped_by_config} collectors by config ({skip_summary})",
                    dut_id=dut_id,
                )

            await self._log_runtime(
                "INFO",
                f"DUT {dut_id} filtering complete: {len(dut_filtered)} collectors will run, "
                f"{skipped_by_config} skipped by config, {skipped_by_baseboard} skipped by "
                f"baseboard, {skipped_by_capability} skipped by live capability, out of "
                f"{len(collector_ids)} input collectors",
                dut_id=dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                f"DUT {dut_id} final filtered collectors: {dut_filtered}",
                dut_id=dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                f"DUT {dut_id} skipped collectors: {len(dut_skipped)}",
                dut_id=dut_id,
            )

        await self._log_runtime(
            "DEBUG",
            f"DUT loop complete - processed {iteration_count} DUT(s)",
        )
        await self._log_runtime(
            "INFO",
            f"Per-DUT filtering complete for all {len(dut_ids)} DUT(s)",
        )

        return {
            "filtered_collectors": filtered_collectors_per_dut,
            "skipped_collectors": skipped_collectors_per_dut,
        }

    async def _should_skip_collector_by_config(
        self, collector_id: str, dut_id: str
    ) -> tuple[bool, str]:
        """
        Return whether ``collector_id`` should skip collector by configuration.

        The implementation uses ``collector_id`` and ``dut_id`` to determine
        whether ``collector_id`` should skip collector by configuration. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        try:
            await self._log_runtime(
                "DEBUG",
                f"Checking skip config for collector {collector_id} on DUT {dut_id}",
                dut_id=dut_id,
            )

            tool_config = self.config_manager.get_tool_config()
            await self._log_runtime(
                "DEBUG",
                f"Tool config keys: {list(tool_config.keys())}",
                dut_id=dut_id,
            )

            # Log skip flag values for debugging
            await self._log_runtime(
                "DEBUG",
                f"Skip flag values - tool_config: SKIP_BMC_SSH_LOGS={tool_config.get('SKIP_BMC_SSH_LOGS')}, SKIP_HOST_LOGS={tool_config.get('SKIP_HOST_LOGS')}, SKIP_REDFISH_OOB_LOGS={tool_config.get('SKIP_REDFISH_OOB_LOGS')}, SKIP_IPMI_LOGS={tool_config.get('SKIP_IPMI_LOGS')}",
                dut_id=dut_id,
            )

            # Get tool-level skip/include collector lists
            tool_skip_collectors = tool_config.get("skip_collectors", [])
            tool_include_collectors = self._get_tool_include_collectors(tool_config)

            await self._log_runtime(
                "DEBUG",
                f"Tool skip_collectors: {tool_skip_collectors}, tool include_collectors: {tool_include_collectors}",
                dut_id=dut_id,
            )

            # Get per-DUT skip/include collector lists
            dut_config = self.dut_manager.get_dut_config(dut_id)

            # Log skip flag values for debugging
            await self._log_runtime(
                "DEBUG",
                f"Skip flag values - dut_config: SKIP_BMC_SSH_LOGS={dut_config.get('SKIP_BMC_SSH_LOGS') if dut_config else 'None'}, SKIP_HOST_LOGS={dut_config.get('SKIP_HOST_LOGS') if dut_config else 'None'}, SKIP_REDFISH_OOB_LOGS={dut_config.get('SKIP_REDFISH_OOB_LOGS') if dut_config else 'None'}, SKIP_IPMI_LOGS={dut_config.get('SKIP_IPMI_LOGS') if dut_config else 'None'}",
                dut_id=dut_id,
            )

            collector_info = self.config_manager.get_collector_info(collector_id) or {}
            custom_config_keys = self._custom_service_config_keys(collector_info)
            if custom_config_keys and not any(
                bool(
                    self._effective_dut_tool_config_value(
                        key, dut_config or {}, tool_config
                    )
                )
                for key in custom_config_keys
            ):
                keys = ", ".join(custom_config_keys)
                return (
                    True,
                    f"Collector {collector_id} filtered out before execution: "
                    f"custom service configuration is empty ({keys})",
                )

            uri_list_config_keys = self._exclusive_uri_list_config_keys(collector_info)
            if self._uri_list_configs_are_provably_empty(
                uri_list_config_keys, dut_config or {}, tool_config
            ):
                keys = ", ".join(uri_list_config_keys)
                return (
                    True,
                    f"Collector {collector_id} filtered out before execution: "
                    f"URI list configuration is empty ({keys})",
                )

            dut_skip_collectors = (
                dut_config.get("skip_collectors", []) if dut_config else []
            )
            dut_include_collectors = (
                dut_config.get("include_collectors", []) if dut_config else []
            )

            resolved_selection = getattr(self, "resolved_collector_selection", {})
            resolution = (
                resolved_selection.get(str(dut_id))
                if isinstance(resolved_selection, dict)
                else None
            )
            if isinstance(resolution, dict):
                candidates = set(resolution.get("candidate_collectors", []))
                if collector_id not in candidates:
                    return (
                        True,
                        f"Collector {collector_id} excluded by resolved selection for DUT {dut_id}",
                    )
                skip_resolution = resolution.get("skip_collectors", {})
                resolved_skip = set(skip_resolution.get("values", []))
                resolved_skip_source = skip_resolution.get("source")
            else:
                resolved_skip = set()
                resolved_skip_source = None

            await self._log_runtime(
                "DEBUG",
                f"DUT {dut_id} skip_collectors: {dut_skip_collectors}, include_collectors: {dut_include_collectors}",
                dut_id=dut_id,
            )

            # A DUT-level skip winner retains its established precedence over
            # exact-ID selection. Includes are additive membership, not an
            # exclusive allowlist.
            if (
                isinstance(resolution, dict)
                and resolved_skip_source == "dut_config"
                and collector_id in resolved_skip
            ):
                return (
                    True,
                    f"Collector {collector_id} in DUT {dut_id} skip list",
                )
            if (
                resolution is None
                and dut_skip_collectors
                and collector_id in dut_skip_collectors
            ):
                return True, f"Collector {collector_id} in DUT {dut_id} skip list"

            # Fall back to tool-level configuration
            # Note: tool_include_collectors is treated as an "add to default" list, not a "replace all" list
            # So we don't filter out collectors that aren't in the include list
            # The include_collectors are handled at the CLI level by adding them to processed_cids

            # Exact -S selections bypass generic skip lists. Additive
            # --include-collectors selections remain subject to skip rules.
            tool_config = self.config_manager.get_tool_config()
            if isinstance(tool_config, dict):
                explicitly_requested_str = tool_config.get("collector_id", "")
            else:
                explicitly_requested_str = getattr(tool_config, "collector_id", "")

            # Accept the CLI's comma- and whitespace-separated ID spellings.
            explicitly_requested = []
            if explicitly_requested_str:
                explicitly_requested = explicitly_requested_str.replace(
                    ",", " "
                ).split()

            is_explicitly_requested = (
                explicitly_requested and collector_id in explicitly_requested
            )

            if is_explicitly_requested:
                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} was explicitly requested via -S",
                    dut_id=dut_id,
                )

                # Explicit selection has higher precedence than broad
                # service-group skip flags.
                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} was explicitly requested and will run (bypassing other skip flags)",
                    dut_id=dut_id,
                )
                return False, ""  # Don't skip the collector

            if isinstance(resolution, dict) and collector_id in resolved_skip:
                return (
                    True,
                    f"Collector {collector_id} in {resolved_skip_source} skip list",
                )

            # SKIP_PORT_FW is topology-specific: it excludes Redfish
            # collectors only when this DUT actually uses HMC port forwarding.
            collector_group = str(collector_info.get("group", "")).upper()
            if collector_group == "REDFISH":
                dut = self.dut_manager.get_dut(dut_id)
                tool_skip_port_fw = bool(tool_config.get("SKIP_PORT_FW", False))
                dut_skip_port_fw = bool(
                    dut_config.get("SKIP_PORT_FW", False) if dut_config else False
                )
                effective_skip_port_fw = (
                    dut_skip_port_fw
                    if dut and dut.has_explicit_config_key("SKIP_PORT_FW")
                    else tool_skip_port_fw
                )
                if (
                    effective_skip_port_fw
                    and dut is not None
                    and dut.uses_hmc_port_forwarding()
                ):
                    reason = (
                        f"Collector {collector_id} skipped because "
                        f"SKIP_PORT_FW=True and DUT {dut_id} uses "
                        "HostBmcTcpPortForwarding"
                    )
                    await self._log_runtime("DEBUG", reason, dut_id=dut_id)
                    return True, reason

            # Check tool-level skip list
            if (
                resolution is None
                and tool_skip_collectors
                and collector_id in tool_skip_collectors
            ):
                return True, f"Collector {collector_id} in tool skip list"

            # Check tool-level COLLECTOR_TO_SKIP list
            tool_collector_to_skip = tool_config.get("COLLECTOR_TO_SKIP", [])
            if (
                resolution is None
                and tool_collector_to_skip
                and collector_id in tool_collector_to_skip
            ):
                return (
                    True,
                    f"Collector {collector_id} in tool COLLECTOR_TO_SKIP list",
                )

            # Check new COLLECTOR_TO_SKIP list (per-DUT)
            if resolution is None and dut_config:
                collector_to_skip = dut_config.get("COLLECTOR_TO_SKIP", [])
                if collector_to_skip and collector_id in collector_to_skip:
                    return (
                        True,
                        f"Collector {collector_id} in DUT {dut_id} COLLECTOR_TO_SKIP list",
                    )

            # Check streaming_only filter
            streaming_only = tool_config.get("streaming_only", False)
            if streaming_only:
                collector_info_stream = self.config_manager.get_collector_info(
                    collector_id
                )
                is_streaming = collector_info_stream.get("streaming_candidate", False)
                if not is_streaming:
                    return (
                        True,
                        f"Collector {collector_id} skipped: not a streaming candidate (--streaming-only mode)",
                    )

            # Check legacy skip flags based on collector group
            if dut_config:
                collector_info = self.config_manager.get_collector_info(collector_id)
                collector_group = collector_info.get("group", "").upper()

                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} group: {collector_group}",
                    dut_id=dut_id,
                )

                # Map collector groups to skip flags
                skip_flag_mapping = {
                    "REDFISH": "SKIP_REDFISH_OOB_LOGS",
                    "SSH": "SKIP_BMC_SSH_LOGS",
                    "IPMI": "SKIP_IPMI_LOGS",
                    "HOST": "SKIP_HOST_LOGS",
                    "BMC_SSH": "SKIP_BMC_SSH_LOGS",
                }

                skip_flag = skip_flag_mapping.get(collector_group)
                if skip_flag:
                    await self._log_runtime(
                        "DEBUG",
                        f"Checking skip flag {skip_flag} for collector {collector_id} (group: {collector_group})",
                        dut_id=dut_id,
                    )

                    # Check both tool config and DUT config for skip flags
                    # DUT config takes precedence if it explicitly sets the flag
                    tool_skip = tool_config.get(skip_flag, False)
                    dut_skip = dut_config.get(skip_flag, False) if dut_config else False

                    await self._log_runtime(
                        "DEBUG",
                        f"Skip flag values: tool_skip={tool_skip}, dut_skip={dut_skip}",
                        dut_id=dut_id,
                    )

                    # Use DUT config value if it was explicitly set in the DUT config file,
                    # otherwise use tool config value
                    dut = self.dut_manager.get_dut(dut_id)
                    if dut and dut.has_explicit_config_key(skip_flag):
                        should_skip = dut_skip
                        await self._log_runtime(
                            "DEBUG",
                            f"DUT {dut_id} has explicit {skip_flag} setting in YAML, using DUT value: {dut_skip}",
                            dut_id=dut_id,
                        )
                    else:
                        should_skip = tool_skip
                        await self._log_runtime(
                            "DEBUG",
                            f"DUT {dut_id} does not have explicit {skip_flag} setting in YAML, using tool value: {tool_skip}",
                            dut_id=dut_id,
                        )

                    # Debug logging - show explicit config keys
                    await self._log_runtime(
                        "DEBUG",
                        f"DUT {dut_id} explicit config keys: {dut.explicit_config_keys}",
                        dut_id=dut_id,
                    )

                    # Debug logging
                    await self._log_runtime(
                        "DEBUG",
                        f"Skip check for {collector_id} (group: {collector_group}): tool_skip={tool_skip}, dut_skip={dut_skip}, should_skip={should_skip}",
                        dut_id=dut_id,
                    )

                    if should_skip:
                        skip_source = (
                            "DUT config"
                            if (dut_config and skip_flag in dut_config)
                            else "tool config"
                        )
                        await self._log_runtime(
                            "DEBUG",
                            f"Collector {collector_id} skipped due to {skip_flag}=True in {skip_source}",
                            dut_id=dut_id,
                        )
                        return (
                            True,
                            f"Collector {collector_id} skipped due to {skip_flag}=True in {skip_source}",
                        )
                    else:
                        await self._log_runtime(
                            "DEBUG",
                            f"Collector {collector_id} NOT skipped - {skip_flag}={should_skip}",
                            dut_id=dut_id,
                        )

        except Exception as e:
            await self._log_runtime(
                "WARNING",
                f"Error checking collector skip configuration for {collector_id} on {dut_id}: {e}",
                dut_id=dut_id,
            )

        return False, ""

    @staticmethod
    def _normalize_result(
        raw: Dict[str, Any],
        *,
        exception: Optional[BaseException] = None,
    ) -> Dict[str, Any]:
        """
        Normalize a service result through the canonical typed outcome boundary.

        After applying local validation, the function forwards ``raw`` and
        ``exception`` to ``to_legacy_result`` and preserves its return and
        exception contract. The source value keeps its ownership while the
        normalized representation is returned separately.

        Args:
            raw: Mapping supplying fields for service result through the
                canonical typed outcome boundary.
            exception: Exception associated with the operation's failure path.

        Returns:
            A mapping containing the values assembled by this operation.
        """
        return normalize_collector_result(
            raw,
            exception=exception,
        ).to_legacy_result()

    @staticmethod
    def _is_pre_execution_interruption(result: Mapping[str, Any]) -> bool:
        """
        Return whether shutdown stopped a collector before lifecycle entry.

        An interrupted result is pre-execution only when it explicitly records
        ``execution_started`` as ``False``. This prevents scheduler callers
        from completing status or progress records that were never started.

        Args:
            result: Normalized collector result inspected for shutdown
                lifecycle state.

        Returns:
            ``True`` when the result is an explicit pre-execution interruption.
        """
        return (
            result.get("status") == "interrupted"
            and result.get("execution_started") is False
        )

    @staticmethod
    def _status_tracker_completion_projection(
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Return only artifact/result fields explicitly owned by a result.

        Omitting a field and explicitly projecting an empty field have different
        meanings at the tracker boundary: omission preserves richer
        service-owned metadata, while an empty list clears stale provisional
        inventory.

        Args:
            result: Mapping supplying fields for only artifact/result fields
                explicitly owned by a result.

        Returns:
            A mapping containing status tracker completion projection.
        """
        fields = (
            "output_files",
            "diagnostic_files",
            "error_files",
            "all_files",
            "discovered_files",
            "context",
            "failure_category",
        )
        return {field: result[field] for field in fields if field in result}

    async def execute_sequential_collectors_with_progress(
        self,
        collectors: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
    ) -> Dict[str, Any]:
        """
        Execute collectors sequentially with per-DUT progress tracking.

        Create progress tasks for each DUT (only if progress is available).

        Args:
            collectors: Entries supplied as ``collectors`` without transferring
                container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            progress: Progress object whose ``add_task``, ``advance``,
                ``start_task``, and ``update`` state is read while performing
                collectors sequentially with per-DUT progress tracking.
            main_task: Main task consumed while the function attempts to execute
                collectors sequentially with per-DUT progress tracking.

        Returns:
            The validated ``results``.
        """
        # print(
        #     f"DEBUG: execute_sequential_collectors_with_progress called with {len(collectors)} collectors"
        # )
        await self._log_runtime(
            "DEBUG",
            f"execute_sequential_collectors_with_progress called with collectors: {collectors}, dut_ids: {dut_ids}",
        )
        await self._log_runtime(
            "DEBUG",
            f"status_tracker available: {self.status_tracker is not None}",
        )
        await self._log_runtime(
            "INFO",
            f"Starting sequential execution of {len(collectors)} collectors on {len(dut_ids)} DUTs",
        )
        await self._log_runtime("INFO", f"Collector IDs: {collectors}")
        await self._log_runtime("INFO", f"DUT IDs: {dut_ids}")
        results = {}

        # Create progress tasks for each DUT (only if progress is available)
        dut_tasks = {}
        if progress:
            for dut_id in dut_ids:
                task = progress.add_task(
                    f"[green]{dut_id}[/green]",
                    total=len(collectors),
                    start=False,
                )
                dut_tasks[dut_id] = task

            # Start all DUT tasks
            for task in dut_tasks.values():
                progress.start_task(task)

        for i, collector_id in enumerate(collectors):
            # Check for shutdown request
            if (
                hasattr(self.orchestrator, "is_shutdown_requested")
                and self.orchestrator.is_shutdown_requested()
            ):
                await self._log_runtime(
                    "WARN", "Shutdown requested, stopping collector execution"
                )
                break

            # Update main progress description with overall status
            progress.update(
                main_task,
                description=f"Overall Progress -- Sequential collectors (0/{len(collectors)} completed)",
            )

            # Execute collector on all DUTs
            collector_results = {}
            for dut_id in dut_ids:
                # Check for shutdown request
                if (
                    hasattr(self.orchestrator, "is_shutdown_requested")
                    and self.orchestrator.is_shutdown_requested()
                ):
                    await self._log_runtime(
                        "WARN",
                        f"Shutdown requested, stopping execution for DUT {dut_id}",
                    )
                    break
                # Check if collector should be skipped based on configuration (tool-level and per-DUT)
                config_skip = self._normalize_skip_decision(
                    await self._should_skip_collector_by_config(collector_id, dut_id),
                    default_skip_phase="configuration",
                )
                should_skip_config, skip_reason_config = config_skip

                if should_skip_config:
                    # Skip collector execution for this DUT due to configuration
                    collector_results[dut_id] = self._build_pre_execution_skip_result(
                        config_skip
                    )

                    # Update status tracking for skipped collector
                    if self.status_tracker:
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "skipped",
                            skip_reason_config,
                            0.0,
                            [],
                            exclusion_type=self._authored_exclusion_type(config_skip),
                        )

                    # Update per-DUT progress for skipped collector (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass

                    continue  # Skip to next DUT

                # Check if collector should be skipped for this specific DUT due to preflight failure
                skip_decision = self._normalize_skip_decision(
                    await self._should_skip_collector(collector_id, dut_id),
                    default_skip_phase="preflight",
                )
                should_skip, skip_reason = skip_decision

                if should_skip:
                    # Skip collector execution for this DUT
                    collector_results[dut_id] = self._build_pre_execution_skip_result(
                        skip_decision
                    )

                    # Update status tracking for skipped collector
                    if self.status_tracker:
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "skipped",
                            skip_reason,
                            0.0,
                            [],
                            exclusion_type=self._authored_exclusion_type(skip_decision),
                        )

                    # Update per-DUT progress for skipped collector (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass

                    continue  # Skip to next DUT

                try:
                    # Check for shutdown before the collector enters any
                    # execution lifecycle or admission slot.
                    if (
                        hasattr(self.orchestrator, "is_shutdown_requested")
                        and self.orchestrator.is_shutdown_requested()
                    ):
                        await self._log_runtime(
                            "WARN",
                            f"Shutdown requested, skipping collector {collector_id} on DUT {dut_id}",
                        )
                        collector_results[dut_id] = {
                            "status": "interrupted",
                            "reason": "Shutdown requested",
                            "execution_time": 0.0,
                            "execution_started": False,
                        }
                        continue

                    # Set async-safe context for this collector execution
                    _collector_context.set(collector_id)

                    service = await self._get_service_for_collector(collector_id)
                    if service:

                        async def publish_sequential_admission() -> None:
                            """
                            Publish sequential progress after all admission.

                            The shared execution helper invokes this callback
                            only after Host and global capacity are held. It
                            keeps the sequential progress lifecycle truthful
                            when this lane waits behind parallel Host work.
                            """

                            if progress and dut_id in dut_tasks:
                                try:
                                    progress.update(
                                        dut_tasks[dut_id],
                                        description=f"  - {dut_id}: Collector {i+1} out of {len(collectors)} in progress",
                                    )
                                except Exception:
                                    pass

                            await self._log_runtime(
                                "DEBUG",
                                f"About to call progress_state.start_collector for {collector_id} on {dut_id}",
                                dut_id=dut_id,
                            )
                            if hasattr(self, "progress_state") and self.progress_state:
                                await self._log_runtime(
                                    "DEBUG",
                                    "progress_state is available, calling start_collector",
                                    dut_id=dut_id,
                                )
                                try:
                                    await self._log_runtime(
                                        "DEBUG",
                                        f"Calling progress_state.start_collector({dut_id}, {collector_id}, {service.service_name}, 'sequential')",
                                        dut_id=dut_id,
                                    )
                                    await self.progress_state.start_collector(
                                        dut_id,
                                        collector_id,
                                        service.service_name,
                                        "sequential",
                                    )
                                except Exception as e:
                                    # Don't let progress tracking break execution
                                    await self._log_runtime(
                                        "DEBUG",
                                        f"Error calling progress_state.start_collector: {e}",
                                        dut_id=dut_id,
                                    )
                            else:
                                await self._log_runtime(
                                    "DEBUG",
                                    "progress_state not available or None",
                                    dut_id=dut_id,
                                )

                            await self._log_runtime(
                                "INFO",
                                f"Executing collector {collector_id} on DUT {dut_id} (sequential)",
                                dut_id=dut_id,
                            )

                        result = await self._execute_collector_with_global_limit(
                            service,
                            dut_id,
                            collector_id,
                            collection_level,
                            start_status_tracking=True,
                            on_admitted=publish_sequential_admission,
                        )
                        collector_results[dut_id] = self._normalize_result(result)

                        if self._is_pre_execution_interruption(
                            collector_results[dut_id]
                        ):
                            continue

                        # Update status tracking
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                collector_results[dut_id].get("status", "unknown"),
                                collector_results[dut_id].get("reason", ""),
                                collector_results[dut_id].get("execution_time", 0.0),
                                **self._status_tracker_completion_projection(
                                    collector_results[dut_id]
                                ),
                            )

                        # Update progress state (passive tracking - doesn't interfere with execution)
                        if hasattr(self, "progress_state") and self.progress_state:
                            try:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with collector_results: {collector_results[dut_id]}",
                                    dut_id=dut_id,
                                )
                                await self.progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    collector_results[dut_id].get("status", "unknown"),
                                    collector_results[dut_id].get("reason", ""),
                                    collector_results[dut_id].get(
                                        "execution_time", 0.0
                                    ),
                                )
                            except Exception as e:
                                # Don't let progress tracking break execution
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Error calling progress_state.complete_collector: {e}",
                                    dut_id=dut_id,
                                )
                                pass

                        await self._log_runtime(
                            "INFO",
                            f"Completed collector {collector_id} on DUT {dut_id} with status: {collector_results[dut_id].get('status', 'unknown')} (sequential)",
                            dut_id=dut_id,
                        )
                    else:
                        collector_results[dut_id] = self._normalize_result(
                            {
                                "status": "error",
                                "reason": f"No service found for collector {collector_id}",
                            }
                        )

                        # Update status tracking for error
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                collector_results[dut_id].get("reason", ""),
                                0.0,
                                [],
                                failure_category=collector_results[dut_id].get(
                                    "failure_category"
                                ),
                            )

                        # Update progress state for error (passive tracking - doesn't interfere with execution)
                        if hasattr(self, "progress_state") and self.progress_state:
                            try:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with collector_results: {collector_results[dut_id]}",
                                    dut_id=dut_id,
                                )
                                await self.progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    collector_results[dut_id].get("reason", ""),
                                    0.0,
                                )
                            except Exception as e:
                                # Don't let progress tracking break execution
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Error calling progress_state.complete_collector: {e}",
                                    dut_id=dut_id,
                                )
                                pass

                        await self._log_runtime(
                            "ERROR",
                            f"No service found for collector {collector_id} (sequential)",
                            dut_id=dut_id,
                        )
                except Exception as e:
                    collector_results[dut_id] = self._normalize_result(
                        {
                            "status": "error",
                            "reason": f"Execution failed: {str(e)}",
                        },
                        exception=e,
                    )

                    # Update status tracking for exception
                    if self.status_tracker:
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "error",
                            collector_results[dut_id].get("reason", ""),
                            0.0,
                            [],
                            failure_category=collector_results[dut_id].get(
                                "failure_category"
                            ),
                        )

                    # Update progress state for exception (passive tracking - doesn't interfere with execution)
                    if hasattr(self, "progress_state") and self.progress_state:
                        try:
                            await self.progress_state.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                collector_results[dut_id].get("reason", ""),
                                0.0,
                            )
                        except Exception:
                            # Don't let progress tracking break execution
                            pass

                    await self._log_runtime(
                        "ERROR",
                        f"Exception executing collector {collector_id} on DUT {dut_id}: {str(e)} (sequential)",
                        dut_id=dut_id,
                    )

                # Update per-DUT progress (only if progress is available)
                if progress and dut_id in dut_tasks:
                    try:
                        progress.advance(dut_tasks[dut_id], advance=1)
                        # Update status to completed after advancing
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {i + 1} out of {len(collectors)} completed",
                        )
                    except Exception:
                        pass

            results[collector_id] = collector_results

            # Update main progress (only if progress is available)
            if progress and main_task:
                progress.advance(main_task, advance=len(dut_ids))
                # Update progress description with completion count
                progress.update(
                    main_task,
                    description=f"Overall Progress -- Sequential collectors ({i + 1}/{len(collectors)} completed)",
                )

        return results

    async def execute_sequential_collectors_parallel_duts(
        self,
        collectors: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
    ) -> Dict[str, Any]:
        """
        Execute sequential collectors parallel duts.

        Create progress tasks for each DUT (only if progress is available).

        Args:
            collectors: Entries supplied as ``collectors`` without transferring
                container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            progress: Progress object whose ``add_task``, ``advance``,
                ``start_task``, and ``update`` state is read while performing
                sequential collectors parallel duts.
            main_task: Main task consumed while the function attempts to execute
                sequential collectors parallel duts.

        Returns:
            The validated ``results``.
        """
        await self._log_runtime(
            "INFO",
            f"Starting parallel DUT execution of {len(collectors)} sequential collectors on {len(dut_ids)} DUTs",
        )
        await self._log_runtime("INFO", f"Collector IDs: {collectors}")
        await self._log_runtime("INFO", f"DUT IDs: {dut_ids}")
        results = {}

        # Create progress tasks for each DUT (only if progress is available)
        dut_tasks = {}
        if progress:
            for dut_id in dut_ids:
                task = progress.add_task(
                    f"[green]{dut_id}[/green]",
                    total=len(collectors),
                    start=False,
                )
                dut_tasks[dut_id] = task

            # Start all DUT tasks
            for task in dut_tasks.values():
                progress.start_task(task)

        async def execute_sequential_collectors_for_dut(
            dut_id: str,
        ) -> Dict[str, Dict[str, Any]]:
            """
            Execute all sequential collectors for a single DUT.

            Check if collector should be skipped based on configuration
            (tool-level and per-DUT).

            Args:
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.

            Returns:
                The validated ``dut_results``.
            """
            # Set the DUT start time when collection actually begins
            if self.orchestrator and hasattr(
                self.orchestrator, "execution_summary_manager"
            ):
                self.orchestrator.execution_summary_manager.set_dut_start_time(
                    dut_id, datetime.now()
                )

            dut_results = {}

            for i, collector_id in enumerate(collectors):
                # Check if collector should be skipped based on configuration (tool-level and per-DUT)
                config_skip = self._normalize_skip_decision(
                    await self._should_skip_collector_by_config(collector_id, dut_id),
                    default_skip_phase="configuration",
                )
                should_skip_config, skip_reason_config = config_skip

                if should_skip_config:
                    # Skip collector execution for this DUT due to configuration
                    dut_results[collector_id] = self._build_pre_execution_skip_result(
                        config_skip
                    )

                    # Update per-DUT progress for skipped collector (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass

                    continue  # Skip to next collector

                # Check if collector should be skipped for this specific DUT due to preflight failure
                skip_decision = self._normalize_skip_decision(
                    await self._should_skip_collector(collector_id, dut_id),
                    default_skip_phase="preflight",
                )
                should_skip, skip_reason = skip_decision

                if should_skip:
                    # Skip collector execution for this DUT
                    dut_results[collector_id] = self._build_pre_execution_skip_result(
                        skip_decision
                    )

                    # Update per-DUT progress for skipped collector (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass

                    continue  # Skip to next collector

                try:
                    # Set async-safe context for this collector execution
                    _collector_context.set(collector_id)

                    service = await self._get_service_for_collector(collector_id)

                    if service:

                        async def publish_parallel_dut_sequential_admission() -> None:
                            """
                            Publish parallel-DUT sequential progress after admission.

                            The shared helper invokes this callback only after
                            Host and global capacity are held, preventing this
                            lane from appearing to run while queued behind a
                            parallel Host collector.
                            """

                            if progress and dut_id in dut_tasks:
                                try:
                                    progress.update(
                                        dut_tasks[dut_id],
                                        description=f"  - {dut_id}: Collector {i+1} out of {len(collectors)} in progress",
                                    )
                                except Exception:
                                    pass

                                if (
                                    hasattr(self, "progress_state")
                                    and self.progress_state
                                ):
                                    try:
                                        await self.progress_state.start_collector(
                                            dut_id,
                                            collector_id,
                                            service.service_name,
                                            "sequential_parallel_duts",
                                        )
                                    except Exception:
                                        # Don't let progress tracking break execution
                                        pass

                            await self._log_runtime(
                                "INFO",
                                f"Executing collector {collector_id} on DUT {dut_id} (sequential per DUT)",
                                dut_id=dut_id,
                            )

                        result = await self._execute_collector_with_global_limit(
                            service,
                            dut_id,
                            collector_id,
                            collection_level,
                            start_status_tracking=True,
                            on_admitted=publish_parallel_dut_sequential_admission,
                        )
                        dut_results[collector_id] = self._normalize_result(result)
                        if self._is_pre_execution_interruption(
                            dut_results[collector_id]
                        ):
                            continue
                        await self._log_runtime(
                            "INFO",
                            f"Completed collector {collector_id} on DUT {dut_id} with status: {dut_results[collector_id].get('status', 'unknown')} (sequential per DUT)",
                            dut_id=dut_id,
                        )
                    else:
                        dut_results[collector_id] = self._normalize_result(
                            {
                                "status": "error",
                                "reason": f"No service found for collector {collector_id}",
                            }
                        )
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                dut_results[collector_id].get("status", "unknown"),
                                dut_results[collector_id].get("reason", ""),
                                0.0,
                                [],
                                failure_category=dut_results[collector_id].get(
                                    "failure_category"
                                ),
                            )
                        await self._log_runtime(
                            "ERROR",
                            f"No service found for collector {collector_id} (sequential per DUT)",
                            dut_id=dut_id,
                        )
                except Exception as e:
                    dut_results[collector_id] = self._normalize_result(
                        {
                            "status": "error",
                            "reason": f"Execution failed: {str(e)}",
                        },
                        exception=e,
                    )
                    if self.status_tracker:
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            dut_results[collector_id].get("status", "unknown"),
                            dut_results[collector_id].get("reason", ""),
                            0.0,
                            [],
                            failure_category=dut_results[collector_id].get(
                                "failure_category"
                            ),
                        )
                    await self._log_runtime(
                        "ERROR",
                        f"Exception executing collector {collector_id} on DUT {dut_id}: {str(e)} (sequential per DUT)",
                        dut_id=dut_id,
                    )

                # Update per-DUT progress (only if progress is available)
                if progress and dut_id in dut_tasks:
                    try:
                        progress.advance(dut_tasks[dut_id], advance=1)
                        # Update status to completed after advancing
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {i + 1} out of {len(collectors)} completed",
                        )
                    except Exception:
                        pass

            return dut_results

        # Execute sequential collectors for all DUTs in parallel
        dut_tasks_list = [
            execute_sequential_collectors_for_dut(dut_id) for dut_id in dut_ids
        ]
        dut_results_list = await _drain_execution_awaitables(dut_tasks_list)

        # Reorganize results from per-DUT structure to per-collector structure
        for i, dut_id in enumerate(dut_ids):
            dut_results = dut_results_list[i]
            if isinstance(dut_results, Exception):
                await self._log_runtime(
                    "ERROR",
                    f"DUT execution failed for {dut_id}: {dut_results}",
                    dut_id=dut_id,
                )
                for collector_id in collectors:
                    results.setdefault(collector_id, {})[dut_id] = (
                        self._normalize_result(
                            {
                                "status": "error",
                                "reason": f"DUT execution failed: {dut_results}",
                            },
                            exception=dut_results,
                        )
                    )
                continue
            for collector_id, result in dut_results.items():
                if collector_id not in results:
                    results[collector_id] = {}
                results[collector_id][dut_id] = result

        # Update main progress to completion
        progress.advance(main_task, advance=len(collectors) * len(dut_ids))
        progress.update(
            main_task,
            description=f"Overall Progress -- Sequential collectors ({len(collectors)}/{len(collectors)} completed)",
        )

        return results

    async def execute_service_based_parallel_collectors(
        self,
        collectors: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
        progress_state=None,
    ) -> Dict[str, Any]:
        """
        Execute parallel collectors grouped by service with progress tracking.

        Pre-filter collectors for all DUTs with progress bar.

        Args:
            collectors: Entries supplied as ``collectors`` without transferring
                container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            progress: Progress object whose ``add_task``, ``advance``, and
                ``start_task`` state is read while performing parallel
                collectors grouped by service with progress tracking.
            main_task: Main task consumed while the function attempts to execute
                parallel collectors grouped by service with progress tracking.
            progress_state: Optional progress state; ``None`` selects the
                function's default behavior.

        Returns:
            The validated ``results``.

        Raises:
            BaseException: After owned children drain, if execution is cancelled
                or a process-control exception occurs. Ordinary child failures
                retain the compatibility scheduler's logged-error behavior.
        """
        await self._log_runtime(
            "INFO",
            f"Starting service-based parallel execution of {len(collectors)} collectors on {len(dut_ids)} DUTs",
        )
        await self._log_runtime("INFO", f"Collector IDs: {collectors}")
        await self._log_runtime("INFO", f"DUT IDs: {dut_ids}")
        configured_concurrency_limit = self._get_max_concurrent_collectors_per_dut()
        await self._log_runtime(
            "INFO",
            "Parallel collector concurrency limit: "
            f"up to {configured_concurrency_limit} per DUT before platform limits",
        )

        # Pre-filter collectors for all DUTs with progress bar
        await self._log_runtime(
            "DEBUG",
            f"Starting pre-filtering for {len(collectors)} collectors on {len(dut_ids)} DUTs",
        )
        filtered_collectors = await self._pre_filter_collectors_for_duts(
            collectors, dut_ids, progress, main_task
        )
        await self._log_runtime(
            "DEBUG",
            f"Pre-filtering completed, filtered_collectors keys: {list(filtered_collectors.keys())}",
        )

        results = {}

        # Create progress tasks for each DUT (only if progress is available)
        dut_tasks = {}
        if progress:
            for dut_id in dut_ids:
                task = progress.add_task(
                    f"[yellow]{dut_id}[/yellow]",
                    total=len(collectors),
                    start=False,
                )
                dut_tasks[dut_id] = task

            # Start all DUT tasks
            for task in dut_tasks.values():
                progress.start_task(task)

        # Group collectors by service
        service_groups = {}
        for collector_id in collectors:
            service = await self._get_service_for_collector(collector_id)
            if service:
                service_name = service.service_name
                if service_name not in service_groups:
                    service_groups[service_name] = []
                service_groups[service_name].append(collector_id)

        await self._log_runtime(
            "INFO",
            f"Grouped parallel collectors by service: {service_groups}",
        )

        async def execute_collectors_for_dut(
            dut_id: str,
        ) -> Dict[str, Dict[str, Any]]:
            """
            Execute all collectors for a single DUT in parallel.

            The implementation uses ``dut_id`` to execute all collectors for a
            single DUT in parallel. Terminal status is emitted only after all
            collectors for a single DUT in parallel and its owned cleanup have
            completed. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind.

            Args:
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.

            Returns:
                The validated ``dut_results``.
            Raises:
                BaseException: After all owned collectors drain, if a
                    process-control exception occurs.
            """
            dut_results = {}
            per_dut_concurrency_limit = self._get_max_concurrent_collectors_per_dut(
                dut_id
            )
            collector_semaphore = asyncio.Semaphore(per_dut_concurrency_limit)

            async def execute_single_collector_for_dut(
                collector_id: str,
            ) -> tuple:
                """
                Execute a single collector on a single DUT.

                The implementation uses ``collector_id`` to execute a single
                collector on a single DUT. Terminal status is emitted only after
                single collector on a single DUT and its owned cleanup have
                completed. Owned asynchronous work is awaited before return, so
                completion does not leave an unobserved task behind.

                Args:
                    collector_id: Stable collector identifier used to correlate
                        configuration, logs, and results.

                Returns:
                    A tuple containing ``collector identifier`` and ``execute
                    single collector for DUT value 2`` in that order.
                """
                # Check pre-filtering results
                skip_decision = self._normalize_skip_decision(
                    filtered_collectors[collector_id][dut_id],
                    default_skip_phase="preflight",
                )
                should_skip, skip_reason = skip_decision

                if should_skip:
                    if self._is_baseboard_skip_reason(skip_reason):
                        await self._log_runtime(
                            "DEBUG",
                            f"Pre-execution baseboard exclusion for {collector_id} on {dut_id}: {skip_reason}",
                            dut_id=dut_id,
                        )
                        return collector_id, None

                    # Update status tracking for skipped collector
                    if self.status_tracker:
                        await self._log_runtime(
                            "DEBUG",
                            f"Calling status_tracker.complete_collector for {collector_id} on {dut_id} with skip_reason: {skip_reason}",
                            dut_id=dut_id,
                        )
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "skipped",
                            skip_reason,
                            0.0,
                            exclusion_type=self._authored_exclusion_type(skip_decision),
                        )
                        await self._log_runtime(
                            "DEBUG",
                            f"status_tracker.complete_collector completed for {collector_id} on {dut_id}",
                            dut_id=dut_id,
                        )
                    else:
                        await self._log_runtime(
                            "DEBUG",
                            f"status_tracker is None, skipping status_tracker update for {collector_id} on {dut_id}",
                            dut_id=dut_id,
                        )

                    # Update progress state for skipped collector
                    if progress_state:
                        try:
                            await self._log_runtime(
                                "DEBUG",
                                f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with skip_reason: {skip_reason}",
                                dut_id=dut_id,
                            )
                            await progress_state.complete_collector(
                                dut_id,
                                collector_id,
                                "skipped",
                                skip_reason,
                                0.0,
                            )
                        except Exception as e:
                            await self._log_runtime(
                                "DEBUG",
                                f"Error calling progress_state.complete_collector: {e}",
                                dut_id=dut_id,
                            )
                            # Don't let progress tracking break execution
                            pass
                    # Skip collector execution for this DUT
                    return collector_id, self._build_pre_execution_skip_result(
                        skip_decision
                    )

                try:
                    # Set current collector context for logging
                    if self.orchestrator and hasattr(
                        self.orchestrator, "current_collector_id"
                    ):
                        self.orchestrator.current_collector_id = collector_id
                    if self.orchestrator and hasattr(
                        self.orchestrator, "current_execution_context"
                    ):
                        self.orchestrator.current_execution_context = {
                            "collector_id": collector_id,
                            "dut_id": dut_id,
                            "collection_level": collection_level,
                        }

                    # Set async-safe per-task context so all logging within this
                    # live parallel task uses the correct collector ID.
                    _collector_context.set(collector_id)

                    # Set per-collector context with original collector ID for cross-contamination prevention
                    if self.orchestrator and hasattr(
                        self.orchestrator, "set_collector_execution_context"
                    ):
                        context = {
                            "collector_id": collector_id,
                            "dut_id": dut_id,
                            "collection_level": collection_level,
                            "original_collector_id": collector_id,  # Store the original collector ID
                        }
                        await self.orchestrator.set_collector_execution_context(
                            dut_id, collector_id, context
                        )

                    # Check for shutdown before executing collector
                    if (
                        hasattr(self.orchestrator, "is_shutdown_requested")
                        and self.orchestrator.is_shutdown_requested()
                    ):
                        await self._log_runtime(
                            "WARN",
                            f"Shutdown requested, skipping collector {collector_id} on DUT {dut_id}",
                        )
                        return collector_id, {
                            "status": "interrupted",
                            "reason": "Shutdown requested",
                            "execution_time": 0.0,
                            "execution_started": False,
                        }

                    service = await self._get_service_for_collector(collector_id)
                    if service:
                        await self._log_runtime(
                            "DEBUG",
                            f"Waiting for collector admission for {collector_id} "
                            f"on {dut_id} (limit: {per_dut_concurrency_limit})",
                            dut_id=dut_id,
                        )

                        async def publish_parallel_admission() -> None:
                            """
                            Publish parallel progress only after all admission.

                            The shared execution helper invokes this callback
                            after Host, generic per-DUT, and global slots are
                            held. It keeps progress state and the operator
                            ``Executing`` event truthful for collectors waiting
                            behind a narrow Host endpoint.
                            """

                            # Only collectors that will actually execute reach
                            # this callback. Static and preflight skips return
                            # above without taking an admission slot.
                            if progress and dut_id in dut_tasks:
                                try:
                                    collector_index = collectors.index(collector_id) + 1
                                    progress.update(
                                        dut_tasks[dut_id],
                                        description=f"  - {dut_id}: Collector {collector_id} ({collector_index}/{len(collectors)}) in progress",
                                    )
                                except Exception:
                                    pass

                            if progress_state:
                                try:
                                    await self._log_runtime(
                                        "DEBUG",
                                        f"Calling progress_state.start_collector for {collector_id} on {dut_id}",
                                        dut_id=dut_id,
                                    )
                                    await progress_state.start_collector(
                                        dut_id,
                                        collector_id,
                                        service.service_name,
                                        "parallel",
                                    )
                                except Exception as e:
                                    await self._log_runtime(
                                        "DEBUG",
                                        f"Error calling progress_state.start_collector: {e}",
                                        dut_id=dut_id,
                                    )

                            await self._log_runtime(
                                "INFO",
                                f"Executing collector {collector_id} on DUT {dut_id} (parallel)",
                                dut_id=dut_id,
                            )

                        result = await self._execute_collector_with_global_limit(
                            service,
                            dut_id,
                            collector_id,
                            collection_level,
                            start_status_tracking=True,
                            per_dut_semaphore=collector_semaphore,
                            on_admitted=publish_parallel_admission,
                        )
                        collector_result = self._normalize_result(result)

                        if self._is_pre_execution_interruption(collector_result):
                            return collector_id, collector_result

                        # Update status tracking
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                collector_result.get("status", "unknown"),
                                collector_result.get("reason", ""),
                                collector_result.get("execution_time", 0.0),
                                **self._status_tracker_completion_projection(
                                    collector_result
                                ),
                            )

                        # Update progress state (passive tracking - doesn't interfere with execution)
                        if progress_state:
                            try:
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    collector_result.get("status", "unknown"),
                                    collector_result.get("reason", ""),
                                    collector_result.get("execution_time", 0.0),
                                )
                            except Exception:
                                # Don't let progress tracking break execution
                                pass

                        await self._log_runtime(
                            "INFO",
                            f"Completed collector {collector_id} on DUT {dut_id} with status: {collector_result.get('status', 'unknown')} (parallel)",
                            dut_id=dut_id,
                        )
                        return collector_id, collector_result
                    else:
                        collector_result = self._normalize_result(
                            {
                                "status": "error",
                                "reason": f"No service found for collector {collector_id}",
                            }
                        )

                        # Update status tracking for error
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                collector_result.get("reason", ""),
                                0.0,
                                [],
                                failure_category=collector_result.get(
                                    "failure_category"
                                ),
                            )

                        # Update progress state for error (passive tracking - doesn't interfere with execution)
                        if progress_state:
                            try:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with collector_result: {collector_result}",
                                    dut_id=dut_id,
                                )
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    collector_result.get("reason", ""),
                                    0.0,
                                )
                            except Exception as e:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Error calling progress_state.complete_collector: {e}",
                                    dut_id=dut_id,
                                )
                                # Don't let progress tracking break execution
                                pass

                        await self._log_runtime(
                            "ERROR",
                            f"No service found for collector {collector_id} (parallel)",
                            dut_id=dut_id,
                        )
                        return collector_id, collector_result
                except Exception as e:
                    collector_result = self._normalize_result(
                        {
                            "status": "error",
                            "reason": f"Execution failed: {str(e)}",
                        },
                        exception=e,
                    )

                    # Update status tracking for exception
                    if self.status_tracker:
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "error",
                            collector_result.get("reason", ""),
                            0.0,
                            [],
                            failure_category=collector_result.get("failure_category"),
                        )

                    # Update progress state for exception (passive tracking - doesn't interfere with execution)
                    if progress_state:
                        try:
                            await self._log_runtime(
                                "DEBUG",
                                f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with collector_result: {collector_result}",
                                dut_id=dut_id,
                            )
                            await progress_state.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                collector_result.get("reason", ""),
                                0.0,
                            )
                        except Exception:
                            await self._log_runtime(
                                "DEBUG",
                                f"Error calling progress_state.complete_collector: {e}",
                                dut_id=dut_id,
                            )
                            # Don't let progress tracking break execution
                            pass

                    await self._log_runtime(
                        "ERROR",
                        f"Exception executing collector {collector_id} on DUT {dut_id}: {str(e)} (parallel)",
                        dut_id=dut_id,
                    )
                    return collector_id, collector_result

            # Execute all collectors for this DUT in parallel
            collector_tasks = [
                execute_single_collector_for_dut(collector_id)
                for collector_id in collectors
            ]
            collector_results = await _drain_execution_awaitables(collector_tasks)

            # Process results for this DUT
            for result in collector_results:
                if isinstance(result, Exception):
                    await self._log_runtime(
                        "ERROR",
                        f"Collector execution failed for DUT {dut_id}: {result}",
                        dut_id=dut_id,
                    )
                    continue

                collector_id, collector_result = result
                if collector_result is None:
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass
                    continue

                dut_results[collector_id] = collector_result

                # Update per-DUT progress (only if progress is available)
                if progress and dut_id in dut_tasks:
                    try:
                        progress.advance(dut_tasks[dut_id], advance=1)
                        # Update status to completed after advancing
                        collector_index = collectors.index(collector_id) + 1
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {collector_id} ({collector_index}/{len(collectors)}) completed",
                        )
                    except Exception:
                        pass

            return dut_results

        # Execute all DUTs in parallel
        dut_task_coros = [execute_collectors_for_dut(dut_id) for dut_id in dut_ids]
        dut_results = await _drain_execution_awaitables(dut_task_coros)

        # Process results - reorganize by collector_id
        for i, dut_result in enumerate(dut_results):
            if isinstance(dut_result, Exception):
                dut_id = dut_ids[i]
                await self._log_runtime(
                    "ERROR", f"DUT execution failed for {dut_id}: {dut_result}"
                )
                continue

            dut_id = dut_ids[i]
            for collector_id, collector_result in dut_result.items():
                if collector_id not in results:
                    results[collector_id] = {}
                results[collector_id][dut_id] = collector_result

        # Update main progress - advance by number of DUTs for each collector
        if main_task:
            progress.advance(main_task, advance=len(dut_ids))

        return results

    async def execute_sequential_collectors_grouped_by_service(
        self,
        collectors: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
        progress_state=None,
    ) -> Dict[str, Any]:
        """
        Execute sequential collectors grouped by service.

        Create progress tasks for each DUT (only if progress is available).

        Args:
            collectors: Entries supplied as ``collectors`` without transferring
                container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            progress: Progress object whose ``add_task``, ``advance``,
                ``start_task``, and ``update`` state is read while performing
                sequential collectors grouped by service.
            main_task: Main task consumed while the function attempts to execute
                sequential collectors grouped by service.
            progress_state: Optional progress state; ``None`` selects the
                function's default behavior.

        Returns:
            The validated ``results``.
        """
        await self._log_runtime(
            "INFO",
            f"Starting service-grouped execution of {len(collectors)} sequential collectors on {len(dut_ids)} DUTs",
        )
        await self._log_runtime("INFO", f"Collector IDs: {collectors}")
        await self._log_runtime("INFO", f"DUT IDs: {dut_ids}")
        results = {}

        # Create progress tasks for each DUT (only if progress is available)
        dut_tasks = {}
        if progress:
            for dut_id in dut_ids:
                task = progress.add_task(
                    f"[green]{dut_id}[/green]",
                    total=len(collectors),
                    start=False,
                )
                dut_tasks[dut_id] = task

            # Start all DUT tasks
            for task in dut_tasks.values():
                progress.start_task(task)

        # Group collectors by service
        service_groups = {}
        for collector_id in collectors:
            service = await self._get_service_for_collector(collector_id)
            if service:
                service_name = service.service_name
                if service_name not in service_groups:
                    service_groups[service_name] = []
                service_groups[service_name].append(collector_id)

        await self._log_runtime(
            "INFO",
            f"Grouped sequential collectors by service: {service_groups}",
        )

        async def execute_sequential_collectors_for_dut_grouped_by_service(
            dut_id: str,
        ) -> Dict[str, Dict[str, Any]]:
            """
            Execute sequential collectors for DUT grouped by service.

            Check if collector should be skipped for this specific DUT due to
            preflight failure.

            Args:
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.

            Returns:
                The validated ``dut_results``.
            """
            dut_results = {}

            async def execute_service_sequential_collectors(
                service_name: str,
                service_collectors: List[str],
                *,
                admit_compatible_batches: bool = True,
            ) -> Dict[str, Dict[str, Any]]:
                """
                Execute sequential collectors for a single service sequentially.

                An ordered catalog-authorized batch may execute concurrently;
                recursive singleton invocations reuse the established skip,
                tracking, result, and error lifecycle without duplicating it.

                Args:
                    service_name: Stable service name used for lookup and
                        operator-facing diagnostics.
                    service_collectors: Entries supplied as
                        ``service_collectors`` without transferring container
                        ownership.
                    admit_compatible_batches: Whether catalog-authorized
                        cohorts may be expanded into singleton child
                        invocations.

                Returns:
                    The validated ``service_results``.
                """
                service_results = {}

                if admit_compatible_batches:
                    batches = self._ordered_sequential_collector_batches(
                        dut_id,
                        service_collectors,
                    )
                    if any(len(batch) > 1 for batch in batches):
                        for batch in batches:
                            if len(batch) > 1:
                                cohort = self._redfish_diagnostic_concurrency_cohort(
                                    dut_id,
                                    batch[0],
                                )
                                await self._log_runtime(
                                    "INFO",
                                    "Executing compatible Redfish diagnostic "
                                    f"cohort {cohort}: {', '.join(batch)}",
                                    dut_id=dut_id,
                                )
                            batch_outcomes = await _drain_execution_awaitables(
                                [
                                    execute_service_sequential_collectors(
                                        service_name,
                                        [collector_id],
                                        admit_compatible_batches=False,
                                    )
                                    for collector_id in batch
                                ]
                            )
                            for collector_id, outcome in zip(batch, batch_outcomes):
                                if isinstance(outcome, Exception):
                                    await self._log_runtime(
                                        "ERROR",
                                        "Compatible diagnostic collector execution "
                                        f"failed for {collector_id}: {outcome}",
                                        dut_id=dut_id,
                                    )
                                    service_results[collector_id] = (
                                        self._normalize_result(
                                            {
                                                "status": "error",
                                                "reason": (
                                                    "Execution failed: "
                                                    f"{str(outcome)}"
                                                ),
                                            },
                                            exception=outcome,
                                        )
                                    )
                                else:
                                    service_results.update(outcome)
                        return service_results

                for i, collector_id in enumerate(service_collectors):
                    # Check if collector should be skipped for this specific DUT due to preflight failure
                    skip_decision = self._normalize_skip_decision(
                        await self._should_skip_collector(collector_id, dut_id),
                        default_skip_phase="preflight",
                    )
                    should_skip, skip_reason = skip_decision

                    if should_skip:
                        if self._is_baseboard_skip_reason(skip_reason):
                            await self._log_runtime(
                                "DEBUG",
                                f"Pre-execution baseboard exclusion for {collector_id} on {dut_id}: {skip_reason}",
                                dut_id=dut_id,
                            )
                            if progress and dut_id in dut_tasks:
                                try:
                                    progress.advance(dut_tasks[dut_id], advance=1)
                                except Exception:
                                    pass
                            continue

                        # Skip collector execution for this DUT
                        service_results[collector_id] = (
                            self._build_pre_execution_skip_result(skip_decision)
                        )

                        # Runtime skips remain part of the execution plan and
                        # must reach the aggregate status tracker before it is
                        # finalized. Static baseboard exclusions return above
                        # and intentionally remain outside execution results.
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                "skipped",
                                skip_reason,
                                0.0,
                                [],
                                exclusion_type=self._authored_exclusion_type(
                                    skip_decision
                                ),
                            )

                        # Update progress state for skipped collector
                        if progress_state:
                            try:
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "skipped",
                                    skip_reason,
                                    0.0,
                                )
                            except Exception:
                                # Don't let progress tracking break execution
                                pass

                        # Update per-DUT progress for skipped collector (only if progress is available)
                        if progress and dut_id in dut_tasks:
                            try:
                                progress.advance(dut_tasks[dut_id], advance=1)
                            except Exception:
                                pass

                        continue  # Skip to next collector

                    try:
                        _collector_context.set(collector_id)

                        service = await self._get_service_for_collector(collector_id)
                        if service:

                            async def publish_grouped_sequential_admission() -> None:
                                """
                                Publish grouped sequential progress after admission.

                                The shared helper invokes this callback after
                                Host and global admission, so another service's
                                queued Host work cannot be marked running before
                                it has an executable service slot.
                                """

                                if progress and dut_id in dut_tasks:
                                    try:
                                        progress.update(
                                            dut_tasks[dut_id],
                                            description=f"  - {dut_id}: {service_name} collector {collector_id} ({i+1}/{len(service_collectors)}) in progress",
                                        )
                                    except Exception:
                                        pass

                                await self._log_runtime(
                                    "DEBUG",
                                    f"About to call progress_state.start_collector for {collector_id} on {dut_id}",
                                    dut_id=dut_id,
                                )
                                if progress_state:
                                    await self._log_runtime(
                                        "DEBUG",
                                        "progress_state is available, calling start_collector",
                                        dut_id=dut_id,
                                    )
                                    try:
                                        await progress_state.start_collector(
                                            dut_id,
                                            collector_id,
                                            service_name,
                                            "sequential_grouped_by_service",
                                        )
                                        await self._log_runtime(
                                            "DEBUG",
                                            "progress_state.start_collector called successfully",
                                            dut_id=dut_id,
                                        )
                                    except Exception as e:
                                        # Don't let progress tracking break execution
                                        await self._log_runtime(
                                            "DEBUG",
                                            f"Error calling progress_state.start_collector: {e}",
                                            dut_id=dut_id,
                                        )
                                else:
                                    await self._log_runtime(
                                        "DEBUG",
                                        "progress_state not available or None",
                                        dut_id=dut_id,
                                    )

                                await self._log_runtime(
                                    "INFO",
                                    f"Executing {service_name} collector {collector_id} on DUT {dut_id} (sequential within service)",
                                )

                            result = await self._execute_collector_with_global_limit(
                                service,
                                dut_id,
                                collector_id,
                                collection_level,
                                start_status_tracking=True,
                                on_admitted=publish_grouped_sequential_admission,
                            )
                            service_results[collector_id] = self._normalize_result(
                                result
                            )

                            if self._is_pre_execution_interruption(
                                service_results[collector_id]
                            ):
                                continue

                            # Update status tracking
                            if self.status_tracker:
                                await self.status_tracker.complete_collector(
                                    dut_id,
                                    collector_id,
                                    service_results[collector_id].get(
                                        "status", "unknown"
                                    ),
                                    service_results[collector_id].get("reason", ""),
                                    service_results[collector_id].get(
                                        "execution_time", 0.0
                                    ),
                                    **self._status_tracker_completion_projection(
                                        service_results[collector_id]
                                    ),
                                )

                            # Update progress state for successful completion
                            await self._log_runtime(
                                "DEBUG",
                                f"About to call progress_state.complete_collector for {collector_id} on {dut_id}",
                                dut_id=dut_id,
                            )
                            if progress_state:
                                await self._log_runtime(
                                    "DEBUG",
                                    "progress_state is available, calling complete_collector",
                                    dut_id=dut_id,
                                )
                                try:
                                    await progress_state.complete_collector(
                                        dut_id,
                                        collector_id,
                                        service_results[collector_id].get(
                                            "status", "unknown"
                                        ),
                                        service_results[collector_id].get("reason", ""),
                                        service_results[collector_id].get(
                                            "execution_time", 0.0
                                        ),
                                    )
                                    await self._log_runtime(
                                        "DEBUG",
                                        "progress_state.complete_collector called successfully",
                                        dut_id=dut_id,
                                    )
                                except Exception as e:
                                    # Don't let progress tracking break execution
                                    await self._log_runtime(
                                        "DEBUG",
                                        f"Error calling progress_state.complete_collector: {e}",
                                        dut_id=dut_id,
                                    )
                                    pass
                            else:
                                await self._log_runtime(
                                    "DEBUG",
                                    "progress_state not available or None",
                                    dut_id=dut_id,
                                )

                            await self._log_runtime(
                                "INFO",
                                f"Completed {service_name} collector {collector_id} on DUT {dut_id} with status: {service_results[collector_id].get('status', 'unknown')}",
                                dut_id=dut_id,
                            )
                        else:
                            service_results[collector_id] = self._normalize_result(
                                {
                                    "status": "error",
                                    "reason": f"No service found for collector {collector_id}",
                                }
                            )

                            # Update status tracking for error
                            if self.status_tracker:
                                await self.status_tracker.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    service_results[collector_id].get("reason", ""),
                                    0.0,
                                    [],
                                    failure_category=service_results[collector_id].get(
                                        "failure_category"
                                    ),
                                )

                            # Update progress state for service not found error
                            if progress_state:
                                try:
                                    await progress_state.complete_collector(
                                        dut_id,
                                        collector_id,
                                        "error",
                                        service_results[collector_id].get("reason", ""),
                                        0.0,
                                    )
                                except Exception:
                                    # Don't let progress tracking break execution
                                    pass

                            await self._log_runtime(
                                "ERROR",
                                f"No service found for collector {collector_id}",
                                dut_id=dut_id,
                            )
                    except Exception as e:
                        service_results[collector_id] = self._normalize_result(
                            {
                                "status": "error",
                                "reason": f"Execution failed: {str(e)}",
                            },
                            exception=e,
                        )

                        # Update status tracking for exception
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                service_results[collector_id].get("reason", ""),
                                0.0,
                                [],
                                failure_category=service_results[collector_id].get(
                                    "failure_category"
                                ),
                            )

                        # Update progress state for execution exception
                        if progress_state:
                            try:
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    f"Execution failed: {str(e)}",
                                    0.0,
                                )
                            except Exception:
                                # Don't let progress tracking break execution
                                pass

                        await self._log_runtime(
                            "ERROR",
                            f"Exception executing collector {collector_id} on DUT {dut_id}: {str(e)}",
                            dut_id=dut_id,
                        )

                    # Update per-DUT progress (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                            # Update status to completed after advancing
                            progress.update(
                                dut_tasks[dut_id],
                                description=f"  - {dut_id}: {service_name} collector {collector_id} ({i + 1}/{len(service_collectors)}) completed",
                            )
                        except Exception:
                            pass

                return service_results

            # Execute all services in parallel for this DUT.
            # Each service gets its own Task so _collector_context is isolated per-service.
            service_tasks = [
                asyncio.create_task(
                    execute_service_sequential_collectors(
                        service_name, service_collectors
                    )
                )
                for service_name, service_collectors in service_groups.items()
            ]
            service_results_list = await _drain_execution_awaitables(service_tasks)

            # Combine results from all services
            for (service_name, service_collectors), service_results in zip(
                service_groups.items(), service_results_list
            ):
                if isinstance(service_results, Exception):
                    await self._log_runtime(
                        "ERROR",
                        f"Service execution failed for {service_name}: "
                        f"{service_results}",
                        dut_id=dut_id,
                    )
                    for collector_id in service_collectors:
                        dut_results[collector_id] = self._normalize_result(
                            {
                                "status": "error",
                                "reason": (
                                    f"Service execution failed: {service_results}"
                                ),
                            },
                            exception=service_results,
                        )
                    continue
                dut_results.update(service_results)

            return dut_results

        # Execute sequential collectors for all DUTs in parallel
        dut_tasks_list = [
            asyncio.create_task(
                execute_sequential_collectors_for_dut_grouped_by_service(dut_id)
            )
            for dut_id in dut_ids
        ]
        dut_results_list = await _drain_execution_awaitables(dut_tasks_list)

        # Reorganize results from per-DUT structure to per-collector structure
        for i, dut_id in enumerate(dut_ids):
            dut_results = dut_results_list[i]
            if isinstance(dut_results, Exception):
                await self._log_runtime(
                    "ERROR",
                    f"DUT execution failed for {dut_id}: {dut_results}",
                    dut_id=dut_id,
                )
                for collector_id in collectors:
                    results.setdefault(collector_id, {})[dut_id] = (
                        self._normalize_result(
                            {
                                "status": "error",
                                "reason": f"DUT execution failed: {dut_results}",
                            },
                            exception=dut_results,
                        )
                    )
                continue
            for collector_id, result in dut_results.items():
                if collector_id not in results:
                    results[collector_id] = {}
                results[collector_id][dut_id] = result

        # Update main progress to completion (only if progress is available)
        if progress and main_task:
            progress.advance(main_task, advance=len(collectors) * len(dut_ids))
            progress.update(
                main_task,
                description=f"Overall Progress -- Service-grouped sequential collectors ({len(collectors)}/{len(collectors)} completed)",
            )

        return results

    async def _execute_service_groups_with_parallel_progress(
        self,
        service_groups: Dict[str, List[str]],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
        dut_tasks: Dict[str, Any],
        active_collectors: Dict[str, set],
        total_collectors: int,
    ) -> Dict[str, Any]:
        """
        Execute service groups with per-DUT progress tracking.

        The implementation uses ``service_groups``, ``dut_ids``,
        ``collection_level``, ``progress``, and ``main_task`` to execute service
        groups with per-DUT progress tracking. Terminal status is emitted only
        after service groups with per-DUT progress tracking and its owned
        cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            service_groups: Mapping supplying fields for service groups with
                per-DUT progress tracking.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            progress: Progress consumed while the function attempts to execute
                service groups with per-DUT progress tracking.
            main_task: Main task consumed while the function attempts to execute
                service groups with per-DUT progress tracking.
            dut_tasks: Mapping supplying fields for service groups with per-DUT
                progress tracking.
            active_collectors: Mapping supplying fields for service groups with
                per-DUT progress tracking.
            total_collectors: Numeric total collectors used while the operation
                performs bounded accounting.

        Returns:
            The validated ``all_results``.
        """
        all_results = {}

        # Execute each service group
        service_tasks_list = []
        for service_name, collectors in service_groups.items():
            service_task = self._execute_service_group(
                service_name,
                collectors,
                dut_ids,
                collection_level,
                progress,
                main_task,
                dut_tasks,  # Pass DUT tasks for per-DUT progress tracking
                active_collectors,  # Pass active collectors tracking
                total_collectors,  # Pass total collectors across all service groups
            )
            service_tasks_list.append(service_task)

        # Wait for all service groups to complete
        service_results = await _drain_execution_awaitables(service_tasks_list)

        # Combine results
        for service_name, results in zip(service_groups.keys(), service_results):
            if isinstance(results, Exception):
                await self._log_runtime(
                    "ERROR",
                    f"Service-group execution failed for {service_name}: {results}",
                )
                continue
            all_results.update(results)

        return all_results

    async def _pre_filter_collectors_for_duts(
        self,
        collectors: List[str],
        dut_ids: List[str],
        progress: Progress,
        main_task,
    ) -> Dict[
        str,
        Dict[str, tuple[bool, str] | _CollectorSkipDecision],
    ]:
        """
        Pre-filters collectors for each DUT to determine if they should be skipped.

        Returns a dictionary mapping collector ID and DUT ID to pair-compatible
        decisions. Skipped decisions retain their typed pre-execution phase.

        Args:
            collectors: Entries supplied as ``collectors`` without transferring
                container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            progress: Progress object whose ``update`` state is read while
                performing pre-filters collectors for each DUT to determine if
                they should be skipped.
            main_task: Main task consumed while the function attempts to
                pre-filters collectors for each DUT to determine if they should
                be skipped.

        Returns:
            The validated ``filtered_collectors_by_dut``.
        """
        await self._log_runtime(
            "INFO",
            f"Pre-filtering {len(collectors)} collectors across {len(dut_ids)} DUTs",
        )

        # Create a dictionary to hold pre-filtering results
        filtered_collectors_by_dut = {}
        for collector_id in collectors:
            filtered_collectors_by_dut[collector_id] = {}
            for dut_id in dut_ids:
                # Check if collector should be skipped based on configuration (tool-level and per-DUT)
                config_skip = self._normalize_skip_decision(
                    await self._should_skip_collector_by_config(collector_id, dut_id),
                    default_skip_phase="configuration",
                )
                should_skip_config, _ = config_skip

                if should_skip_config:
                    filtered_collectors_by_dut[collector_id][dut_id] = config_skip
                    continue

                # Check if collector should be skipped for this specific DUT due to preflight failure
                skip_decision = self._normalize_skip_decision(
                    await self._should_skip_collector(collector_id, dut_id),
                    default_skip_phase="preflight",
                )
                should_skip, _ = skip_decision

                if should_skip:
                    filtered_collectors_by_dut[collector_id][dut_id] = skip_decision
                    continue

                filtered_collectors_by_dut[collector_id][dut_id] = (False, "")

        # Update main progress with pre-filtering status (only if progress is available)
        if progress and main_task:
            progress.update(
                main_task,
                description=f"Overall Progress -- Pre-filtering collectors ({len(collectors)}/{len(collectors)} completed)",
            )

        return filtered_collectors_by_dut

    def _get_service_name_for_collector(self, collector_id: str) -> Optional[str]:
        """
        Get service name for a collector.

        Preserve legacy collectors that predate complete catalog metadata, but
        never let an ID prefix override an explicit group/action type.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical service name for collector text, or ``None`` when the
            requested value is unavailable.
        """
        # Check if collector_id is valid (non-empty)
        if not collector_id:
            return None

        collector_info = self.config_manager.get_collector_info(collector_id) or {}
        service_name = collector_service_from_metadata(collector_info)
        if service_name == "unknown":
            # Preserve legacy collectors that predate complete catalog metadata,
            # but never let an ID prefix override an explicit group/action type.
            service_name = CollectorServiceMapping.get_service_from_collector_id(
                collector_id
            )
        return None if service_name == "unknown" else service_name
