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
Workflow Orchestrator - Main orchestrator for the NVDebug Tool.

Coordinates all aspects of log collection including configuration management,
DUT initialization, preflight checks, collector execution, and reporting.
"""

import asyncio
import copy
import gc
import hmac
import inspect
import json
import logging
import os
import secrets
import signal
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import aiohttp
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from ..services.dynamic_discovery_service import DiscoveryConfig
from ..services.html_report_service import HTMLReportService
from ..utils.bundle_sanitizer import BundleSanitizationReport
from ..utils.catalog_snapshot import CatalogSnapshot, CatalogSnapshotFacts
from ..utils.console_output import create_sanitized_console
from ..utils.cpu_resources import (
    explicit_dut_concurrency_limit,
    resolve_dut_concurrency,
)
from ..utils.dependency_checker import DependencyChecker
from ..utils.enums import CollectorServiceMapping
from ..utils.filesystem_identity import directory_security_identity
from ..utils.json_utils import safe_json_dump
from ..utils.managed_filesystem import run_managed_filesystem_operation
from ..utils.operation_progress import SanitizedOperationProgress
from ..utils.report_app_assets import (
    ReportAppAssetError,
    validate_report_app_index,
)
from ..utils.request_response_capture import (
    _defer_capture_failure,
    _raise_capture_cleanup_outcome,
)
from ..utils.resource_monitor import ResourceUsageMonitor
from ..utils.runtime_boundary_profile import (
    resolve_run_finalization_boundaries,
)
from ..utils.timing_manager import TimingManager
from ..utils.zip_utils import validate_archive_artifact_digests
from .async_logger import DEFAULT_RUNTIME_LOG_FORMAT, AsyncSafeLogger
from .cleanup_manager import CleanupManager
from .collection_status_tracker import CollectionStatusTracker
from .config_manager import ConfigurationManager
from .delivery_evidence import write_terminal_outcome_override_evidence
from .dut_manager import DUTManager
from .execution_engine import ExecutionEngine
from .execution_summary import ExecutionSummaryManager
from .extension_lifecycle import ExtensionLifecycleManager
from .finalization_receipt import (
    MANDATORY_TEARDOWN_PHASES,
    FinalizationFailure,
    FinalizationReceipt,
    FinalizationReceiptError,
    attach_finalization_receipt,
    capture_owned_awaitable,
    drain_owned_tasks,
    empty_finalization_receipt,
    is_control_flow_exception,
    is_interruption_exception,
    iter_exception_leaves,
    sanitize_finalization_failure,
    sanitize_finalization_message,
    select_authoritative_exception,
)
from .progress_display import ProgressDisplay
from .progress_state_manager import ProgressStateManager
from .redfish_capability_manager import SystemDumpCapabilityManager
from .redfish_controller import collector_controllers, collector_preflight_result
from .reporting_engine import ReportingEngine
from .run_identity_builder import (
    PlanningPlanSnapshot,
    build_planning_run_identity,
    build_run_identity,
    capture_effective_config_cohort,
    capture_planning_plan_snapshot,
    tool_identity_facts,
)
from .run_result import (
    CollectionStatus,
    RunResult,
    RuntimeStatus,
    normalize_run_outcome_reason,
)
from .scheduling_plan import (
    build_scheduling_summary,
    format_scheduling_summary,
)

logger = logging.getLogger(__name__)

SPA_REPORT_ASSET_FAILURE = (
    "SPA report assets are unavailable or failed package validation. "
    "Replace the installed NVDebug package with a complete validated distribution."
)
SPA_REPORT_SOURCE_ASSET_FAILURE = (
    "SPA report assets do not match the current report application sources. "
    "Rebuild the report application before running a collection that requests "
    "SPA reports."
)
SPA_REPORT_DESTINATION_FAILURE = "SPA report destination index is unsafe."
SPA_REPORT_OUTPUT_FAILURE = (
    "SPA report generation did not produce a valid reports/index.html."
)
SPA_REPORT_GENERATION_FAILURE = "SPA report generation failed."
SPA_REPORT_GENERATION_SUCCESS = "SPA report generated at reports/index.html."


def spa_report_asset_failure_message(error: ReportAppAssetError) -> str:
    """
    Select a sanitized recovery message for source and packaged execution.

    The implementation uses ``error`` to select a sanitized recovery message for
    source and packaged execution.

    Args:
        error: Exception or failure detail associated with the operation.

    Returns:
        The canonical spa report asset failure message.
    """

    return (
        SPA_REPORT_SOURCE_ASSET_FAILURE
        if error.source_checkout
        else SPA_REPORT_ASSET_FAILURE
    )


def _dut_manager_catalog_inputs(
    config_manager: Any,
    tool_config: Dict[str, Any],
) -> tuple[Optional[Any], Optional[CatalogSnapshot]]:
    """
    Prefer exact runtime bytes while retaining legacy manager compatibility.

    The implementation uses ``config_manager`` and ``tool_config`` to prefer
    exact runtime bytes while retaining legacy manager compatibility.

    Args:
        config_manager: Config manager governing prefer exact runtime bytes
            while retaining legacy manager compatibility.
        tool_config: Tool config governing prefer exact runtime bytes while
            retaining legacy manager compatibility.

    Returns:
        A tuple containing ``returned value`` and ``optional[catalog snapshot]``
        in that order.
    """

    snapshot_getter = getattr(config_manager, "get_catalog_snapshot", None)
    snapshot = snapshot_getter() if callable(snapshot_getter) else None
    if isinstance(snapshot, CatalogSnapshot):
        return None, snapshot
    spreadsheet_path = tool_config.get("collector_definitions", {}).get(
        "spreadsheet_path"
    )
    return spreadsheet_path, None


async def _drain_workflow_tasks(
    tasks: List[asyncio.Task],
) -> tuple[Any | BaseException, ...]:
    """
    Drain child tasks while containing and selecting process controls.

    After applying local validation, the function forwards ``tasks`` to
    ``tuple`` and preserves its return and exception contract. Owned
    asynchronous work is awaited before return, so completion does not leave an
    unobserved task behind.

    Args:
        tasks: Entries supplied as ``tasks`` without transferring container
            ownership.

    Returns:
        The drain workflow tasks returned in operation-defined order.

    Raises:
        BaseException: If a delegated failure occurs while the function attempts
            to drain child tasks while containing and selecting process
            controls.
    """

    outcomes = await drain_owned_tasks(
        tasks,
        cancel_on_error=lambda error: not isinstance(error, Exception),
    )
    control_errors = [
        outcome.error
        for outcome in outcomes
        if outcome.error is not None
        and not outcome.owner_cancelled
        and not isinstance(outcome.error, Exception)
    ]
    if control_errors:
        raise select_authoritative_exception(control_errors)
    return tuple(
        outcome.error if outcome.error is not None else outcome.value
        for outcome in outcomes
    )


async def _await_workflow_child_with_timeout(
    awaitable: Any,
    *,
    timeout: float,
) -> Any:
    """
    Await one contained child without letting timeout orphan its task.

    The implementation uses ``awaitable`` and ``timeout`` to await one contained
    child without letting timeout orphan its task. Owned asynchronous work is
    awaited before return, so completion does not leave an unobserved task
    behind. If the function cannot await one contained child without letting
    timeout orphan its task, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        awaitable: Awaitable consumed while the function attempts to await one
            contained child without letting timeout orphan its task.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.

    Returns:
        The await workflow child with timeout value selected by the operation.

    Raises:
        BaseException: If a delegated failure occurs while the function attempts
            to await one contained child without letting timeout orphan its
            task.
    """

    child = asyncio.create_task(capture_owned_awaitable(awaitable))
    try:
        completed, _pending = await asyncio.wait((child,), timeout=timeout)
    except BaseException as primary:
        owner_cancelled = bool(not child.done() and child.cancel())
        errors = [primary]
        try:
            outcomes = await drain_owned_tasks((child,))
        except BaseException as cleanup_error:
            errors.append(cleanup_error)
            outcomes = ()
        for outcome in outcomes:
            if outcome.error is not None and not (
                owner_cancelled and isinstance(outcome.error, asyncio.CancelledError)
            ):
                errors.append(outcome.error)
        raise select_authoritative_exception(errors)

    if not completed:
        owner_cancelled = bool(not child.done() and child.cancel())
        outcomes = await drain_owned_tasks((child,))
        outcome = outcomes[0]
        if outcome.error is not None and not (
            owner_cancelled and isinstance(outcome.error, asyncio.CancelledError)
        ):
            raise outcome.error
        raise asyncio.TimeoutError

    outcome = child.result()
    if outcome.error is not None:
        raise outcome.error
    return outcome.value


def _path_identity(path_stat: os.stat_result) -> tuple[int, ...]:
    """
    Return the fields that must stay stable across SPA asset generation.

    The implementation uses ``path_stat`` to produce the fields that must stay
    stable across SPA asset generation.

    Args:
        path_stat: Path stat object whose ``st_ctime_ns``, ``st_dev``,
            ``st_ino``, ``st_mode``, and ``st_mtime_ns`` state is read while
            performing fields that must stay stable across SPA asset generation.

    Returns:
        A tuple containing ``st dev``, ``st ino``, ``st mode``, ``st size``,
        ``st mtime ns``, and ``st ctime ns`` in that order.
    """
    return (
        path_stat.st_dev,
        path_stat.st_ino,
        path_stat.st_mode,
        path_stat.st_size,
        path_stat.st_mtime_ns,
        path_stat.st_ctime_ns,
    )


_directory_identity = directory_security_identity


@dataclass(frozen=True)
class CollectorClassification:
    """
    Implement the collector classification boundary used by the NVDebug runtime.

    The immutable record keeps ``normal_sequential``, ``normal_parallel``, and
    ``tail`` together so consumers observe one collector classification state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        normal_sequential: Collection of normal sequential entries retained by
            this record.
        normal_parallel: Collection of normal parallel entries retained by this
            record.
        tail: Collection of tail entries retained by this record.
    """

    normal_sequential: List[str]
    normal_parallel: List[str]
    tail: List[str]


@dataclass(frozen=True)
class DutExecutionPlan:
    """
    Implement the DUT execution plan boundary used by the NVDebug runtime.

    The immutable record keeps ``dut_id``, ``normal_sequential``,
    ``normal_parallel``, and ``tail`` together so consumers observe one DUT
    execution plan state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        dut_id: Canonical text used as DUT identifier.
        normal_sequential: Collection of normal sequential entries retained by
            this record.
        normal_parallel: Collection of normal parallel entries retained by this
            record.
        tail: Collection of tail entries retained by this record.
    """

    dut_id: str
    normal_sequential: List[str]
    normal_parallel: List[str]
    tail: List[str]


class WorkflowOrchestrator:
    """
    Main orchestrator for the NVDebug Tool.

    Coordinates all aspects of log collection including configuration
    management, DUT initialization, preflight checks, collector execution, and
    reporting.
    """

    def __init__(
        self,
        tool_config=None,
        dut_configs=None,
        log_dir: str = None,
        tool_config_path: str = None,
        dut_config_path: str = None,
        debug_mode: bool = False,
        verbose_mode: bool = False,
        enable_status_tracking: bool = True,
        disable_live_display: bool = False,
        quiet_mode: bool = False,
        catalog_only_mode: Optional[bool] = None,
        sanitized_console=None,
        catalog_snapshot: Optional[CatalogSnapshot] = None,
    ) -> None:
        # Support both new object-based and legacy file-based initialization
        """
        Initialize a ``WorkflowOrchestrator`` instance.

        The initializer records ``_dut_configs_obj``,
        ``_execution_order_counters``, ``_execution_order_entries``,
        ``_run_identity_catalog_facts``, and ``_run_identity_planning_plan`` for
        later operations and establishes the instance invariants before any
        public method runs. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            tool_config: Optional Tool config governing initialize a
                ``WorkflowOrchestrator`` instance.
            dut_configs: Optional DUT configs governing initialize a
                ``WorkflowOrchestrator`` instance.
            log_dir: Optional filesystem location used as the log dir for this
                operation.
            tool_config_path: Optional filesystem location used as the tool
                config path for this operation.
            dut_config_path: Optional filesystem location used as the DUT config
                path for this operation.
            debug_mode: Whether debug mode is enabled or required for this
                operation.
            verbose_mode: Whether verbose mode is enabled or required for this
                operation.
            enable_status_tracking: Whether enable status tracking is enabled or
                required for this operation.
            disable_live_display: Whether disable live display is enabled or
                required for this operation.
            quiet_mode: Whether quiet mode is enabled or required for this
                operation.
            catalog_only_mode: Optional catalog only mode; ``None`` selects the
                function's default behavior.
            sanitized_console: Optional sanitized console; ``None`` selects the
                function's default behavior.
            catalog_snapshot: Optional catalog snapshot; ``None`` selects the
                function's default behavior.
        """
        if tool_config is not None:
            # New object-based initialization
            self._tool_config_obj = tool_config
            self._dut_configs_obj = dut_configs or []
            self.tool_config_path = None
            self.dut_config_path = None
            # Resolve both the canonical flat model and its accepted nested
            # mapping aliases at the orchestrator boundary.
            if isinstance(tool_config, dict):
                logging_section = tool_config.get("logging", {})
                if not isinstance(logging_section, dict):
                    logging_section = {}
                self.debug_mode = tool_config.get("debug", False)
                self.verbose_mode = tool_config.get("verbose", False)
                self.log_level = tool_config.get(
                    "log_level", logging_section.get("level", "INFO")
                )
                self.log_format = tool_config.get(
                    "log_format",
                    logging_section.get("format", DEFAULT_RUNTIME_LOG_FORMAT),
                )
            else:
                self.debug_mode = getattr(tool_config, "debug", False)
                self.verbose_mode = getattr(tool_config, "verbose", False)
                self.log_level = getattr(tool_config, "log_level", "INFO")
                self.log_format = getattr(
                    tool_config, "log_format", DEFAULT_RUNTIME_LOG_FORMAT
                )
        else:
            # Legacy file-based initialization
            self._tool_config_obj = None
            self._dut_configs_obj = None
            self.tool_config_path = tool_config_path
            self.dut_config_path = dut_config_path
            self.debug_mode = debug_mode
            self.verbose_mode = verbose_mode
            self.log_level = "INFO"
            self.log_format = DEFAULT_RUNTIME_LOG_FORMAT

        self.log_dir = Path(log_dir) if log_dir else Path("/tmp")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.resource_usage_monitor: Optional[ResourceUsageMonitor] = None

        # Store quiet mode flag
        self.quiet_mode = quiet_mode
        # Historically quiet mode also selected the lightweight catalog-only
        # initialization path. Keep that default for callers which only pass
        # quiet_mode, while allowing machine-readable commands such as
        # ``preflight --json`` to suppress console output and still initialize
        # their DUTs fully.
        self.catalog_only_mode = (
            quiet_mode if catalog_only_mode is None else catalog_only_mode
        )

        # Initialize logger first (sanitizer will be set later if available)
        self.logger = AsyncSafeLogger(
            str(self.log_dir),
            self,
            sanitizer=None,
            debug_mode=self.debug_mode,
            verbose_mode=self.verbose_mode,
            log_level=self.log_level,
            log_format=self.log_format,
        )

        # Current execution context tracking for logging
        self.current_collector_id = None
        self.current_execution_context = {}

        # Per-collector context tracking for cross-contamination prevention
        # This is a minimal addition that doesn't break existing functionality
        self.collector_execution_contexts: Dict[str, Dict[str, Any]] = {}

        # Initialize shutdown flag for graceful termination
        self._shutdown_requested = False
        self._signal_handler_called = False
        self._run_outcome: Dict[str, Any] = {
            "adapter_schema_version": "1.0",
            "status": "success",
            "reason": "",
            "affected_duts": [],
        }

        # Initialize signal handlers for cleanup on interruption
        self._setup_signal_handlers()

        # Initialize managers
        if self._tool_config_obj is not None:
            # Use object-based configuration
            self.config_manager = ConfigurationManager.from_objects(
                self._tool_config_obj,
                self._dut_configs_obj,
                sanitized_console=sanitized_console,
                quiet_mode=self.quiet_mode,
                catalog_snapshot=catalog_snapshot,
            )
        else:
            # Use file-based configuration (legacy)
            self.config_manager = ConfigurationManager(
                tool_config_path,
                dut_config_path,
                sanitized_console=sanitized_console,
                quiet_mode=self.quiet_mode,
            )

        # In non-quiet mode, pass the async logger to config manager
        if not self.quiet_mode:
            self.config_manager.logger = self.logger
            # Note: Collector categorization will be initialized in async_init()
        self.dut_manager: Optional[DUTManager] = None
        # Normal collection initialization may fail before a DUTManager can be
        # retained.  Preserve the root cause so callers do not discover that
        # failure later through an unrelated ``NoneType`` dereference.
        self.dut_manager_initialization_error: Optional[BaseException] = None
        self.dependency_checker = DependencyChecker()
        self.timing_manager = TimingManager(self.log_dir, debug_mode)
        self.execution_summary_manager = ExecutionSummaryManager(self.log_dir)
        self.finalization_receipt: Optional[FinalizationReceipt] = None
        self.run_result: Optional[RunResult] = None
        self._run_identity_required = (
            self.config_manager.has_prebound_catalog_snapshot()
        )
        self._run_identity_catalog_facts: Optional[CatalogSnapshotFacts] = None
        self._run_identity_tool_config: Any = None
        self._run_identity_tool_facts: Optional[Dict[str, str]] = None
        self._run_identity_planning_plan: Optional[PlanningPlanSnapshot] = None
        # Set logger reference for execution summary manager
        self.execution_summary_manager.logger = self.logger
        self._execution_order_counters: Dict[str, int] = {}
        self._execution_order_entries: Dict[str, List[Dict[str, str]]] = {}
        # Live Redfish capabilities are scoped to this orchestrator/run.  The
        # manager resolves DUTManager lazily because DUT initialization happens
        # later in the lifecycle.
        self.system_dump_capability_manager = SystemDumpCapabilityManager(self)
        self.extension_lifecycle_manager = ExtensionLifecycleManager(self)
        self.extension_results: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.runtime_capabilities: Dict[str, Dict[str, Any]] = {}

        # Sanitizer will be set by CLI handler if sanitization is enabled
        self.sanitizer = None

        # Console instances - use passed console or create new one
        self.console = sanitized_console.console if sanitized_console else Console()
        self.sanitized_console = (
            sanitized_console
            if sanitized_console
            else create_sanitized_console(self.sanitizer)
        )

        # Initialize collection status tracker (after console is created)
        self.enable_status_tracking = enable_status_tracking
        self.disable_live_display = disable_live_display
        try:
            self.status_tracker = (
                CollectionStatusTracker(
                    self.log_dir,
                    self.console,
                    self.logger,
                    self.timing_manager,
                )
                if enable_status_tracking
                else None
            )
        except Exception as e:
            # Log the error but don't fail the entire tool
            if self.logger:
                asyncio.create_task(
                    self.logger.log_runtime(
                        "WARN",
                        "WorkflowOrchestrator",
                        f"Failed to initialize status tracker: {e}. Status tracking will be disabled.",
                    )
                )
            self.status_tracker = None
            self.enable_status_tracking = False

    def get_finalization_runtime_boundaries(self) -> Dict[str, int]:
        """
        Resolve catalog finalization limits across every DUT in this run.

        Each initialized DUT contributes its baseboard-selected values. The
        shared resolver chooses limits that admit every participating platform.

        Returns:
            The complete run-wide finalization boundary mapping.
        """

        configs: List[Any] = []
        dut_manager = getattr(self, "dut_manager", None)
        if dut_manager is not None:
            try:
                dut_ids = dut_manager.get_all_dut_ids()
            except Exception:
                dut_ids = ()
            for dut_id in dut_ids:
                try:
                    configs.append(dut_manager.get_dut_config(dut_id))
                except Exception:
                    configs.append({})
        return resolve_run_finalization_boundaries(configs)

    def _get_collector_context_key(self, dut_id: str, collector_id: str) -> str:
        """
        Generate a unique key for collector context.

        The implementation uses ``dut_id`` and ``collector_id`` to generate a
        unique key for collector context.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical collector context key text.
        """
        return f"{dut_id}:{collector_id}"

    async def set_collector_execution_context(
        self, dut_id: str, collector_id: str, context: Dict[str, Any]
    ) -> None:
        """
        Set execution context for a specific collector.

        Also update the global context for backward compatibility.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            context: Runtime context carrying state shared across this
                operation.
        """
        context_key = self._get_collector_context_key(dut_id, collector_id)
        self.collector_execution_contexts[context_key] = context.copy()

        # Also update the global context for backward compatibility
        self.current_collector_id = collector_id
        self.current_execution_context = context.copy()

    async def get_collector_execution_context(
        self, dut_id: str, collector_id: str
    ) -> Dict[str, Any]:
        """
        Get execution context for a specific collector.

        After applying local validation, the function forwards ``dut_id`` and
        ``collector_id`` to ``self.collector_execution_contexts.get`` and
        preserves its return and exception contract. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A mapping containing collector execution context.
        """
        context_key = self._get_collector_context_key(dut_id, collector_id)
        return self.collector_execution_contexts.get(context_key, {})

    async def clear_collector_execution_context(
        self, dut_id: str, collector_id: str
    ) -> None:
        """
        Clear execution context for a specific collector.

        The implementation uses ``dut_id`` and ``collector_id`` to clear
        execution context for a specific collector. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        context_key = self._get_collector_context_key(dut_id, collector_id)
        if context_key in self.collector_execution_contexts:
            del self.collector_execution_contexts[context_key]

    def set_sanitizer(self, sanitizer) -> None:
        """
        Set the sanitizer for the orchestrator and its logger.

        Establish the sanitizer-backed cleanup owner before constructing
        engines. Engine policy/configuration can fail, but any artifacts already
        owned by this orchestrator must still receive final scanning.

        Args:
            sanitizer: Sanitizer applied before untrusted or sensitive text
                leaves its boundary.
        """
        self.sanitizer = sanitizer
        if self.logger:
            self.logger.sanitizer = sanitizer
        timing_manager = getattr(self, "timing_manager", None)
        if timing_manager:
            timing_manager.set_sanitizer(sanitizer)
        # Establish the sanitizer-backed cleanup owner before constructing
        # engines. Engine policy/configuration can fail, but any artifacts
        # already owned by this orchestrator must still receive final scanning.
        self.cleanup_manager = CleanupManager(self.logger)
        # Update the sanitized console to use the new sanitizer
        self.sanitized_console = create_sanitized_console(sanitizer)
        # if sanitizer:
        #     print(f"Sanitizer is enabled")
        # else:
        #     print(f"Sanitizer is disabled")

        # self.logger.log_runtime(
        #     "DEBUG",
        #     "WorkflowOrchestrator",
        #     f"Sanitizer set in orchestrator - enabled: {sanitizer.enabled if sanitizer else False}"
        # )

        # Initialize engines
        self.execution_engine = ExecutionEngine(
            self.config_manager,
            self.dut_manager,
            self.logger,
            orchestrator=self,
            status_tracker=self.status_tracker,
        )
        self.reporting_engine = ReportingEngine(
            self.config_manager, self.dut_manager, self.logger
        )

        if getattr(self, "resource_usage_monitor", None) is None:
            scheduler = self.execution_engine.cpu_resource_resolution.to_dict()
            scheduler["installed_collector_operation_limit"] = (
                self.execution_engine.global_collector_operation_limit
            )
            scheduler["concurrency_mode"] = (
                self.execution_engine.admission_settings.mode
            )
            scheduler["minimum_collector_operation_limit"] = (
                self.execution_engine.admission_settings.minimum_limit
            )
            scheduler["maximum_collector_operation_limit"] = (
                self.execution_engine.admission_settings.maximum_limit
            )
            self.resource_usage_monitor = ResourceUsageMonitor(
                self.log_dir, scheduler=scheduler
            )

        # Set orchestrator reference in reporting engine, logger, and execution engine
        self.reporting_engine.orchestrator = self
        if self.logger:
            self.logger.orchestrator = self
        self.execution_engine.orchestrator = self

    async def record_run_outcome(
        self,
        status: str,
        *,
        failure_type: Optional[str] = None,
        reason: str = "",
        evidence: Optional[str] = None,
        affected_duts: Optional[List[str]] = None,
    ) -> None:
        """
        Record one bounded run outcome before terminal finalization.

        The status tracker owns durable production state. The local projection
        is retained only for compatibility callers that intentionally disable
        status tracking; it follows the same flat typed contract and bounds all
        diagnostics after sanitization.

        Args:
            status: Text supplied as status in the format accepted by this
                function.
            failure_type: Optional failure type; ``None`` selects the function's
                default behavior.
            reason: Text supplied as reason in the format accepted by this
                function.
            evidence: Optional evidence; ``None`` selects the function's default
                behavior.
            affected_duts: Optional affected duts; ``None`` selects the
                function's default behavior.

        Raises:
            ValueError: If unsupported run outcome: ``status``; or
                ``normalized_status`` lacks failure_type.
            RuntimeError: If run-outcome recorder returned an unexpected value;
                or run-outcome tracker did not publish a projection.
        """

        normalized_status = str(status).strip().lower()
        if normalized_status not in {
            "success",
            "domain_failed",
            "runtime_failed",
            "interrupted",
        }:
            raise ValueError(f"unsupported run outcome: {status!r}")

        normalized_failure_type = str(failure_type or "").strip()
        if normalized_status in {"domain_failed", "runtime_failed"} and (
            not normalized_failure_type or len(normalized_failure_type) > 128
        ):
            raise ValueError(f"{normalized_status} requires failure_type")

        normalized_duts: List[str] = []
        for value in affected_duts or []:
            rendered = str(value)[:256]
            if not rendered or any(ord(character) < 32 for character in rendered):
                continue
            if rendered not in normalized_duts:
                normalized_duts.append(rendered)
            if len(normalized_duts) == 1024:
                break

        tracker = getattr(self, "status_tracker", None)
        setter = getattr(tracker, "set_run_outcome", None)
        if callable(setter):
            # Recursive legacy outcomes are intentionally not passed into the
            # typed tracker.  Collector counts retain any domain failure while
            # this hint records the later runtime/interruption classification.
            result = setter(
                normalized_status,
                failure_type=(
                    normalized_failure_type
                    if normalized_status in {"domain_failed", "runtime_failed"}
                    else None
                ),
                reason=reason,
                evidence=evidence,
                affected_duts=normalized_duts,
            )
            if inspect.isawaitable(result):
                await result
            elif result is not None:
                raise RuntimeError("Run-outcome recorder returned an unexpected value")
            tracker_outcome = getattr(tracker, "run_outcome", None)
            if not isinstance(tracker_outcome, dict):
                raise RuntimeError("Run-outcome tracker did not publish a projection")
            self._run_outcome = copy.deepcopy(tracker_outcome)
            return

        del evidence
        sanitizer = getattr(getattr(self, "sanitizer", None), "sanitize", None)
        if not callable(sanitizer):
            sanitizer = getattr(
                getattr(getattr(self, "logger", None), "sanitizer", None),
                "sanitize",
                None,
            )
        if callable(sanitizer):
            try:
                rendered_reason = str(sanitizer(str(reason or "")[:4096]))[:4096]
            except Exception:
                rendered_reason = "[message sanitization failed]"
        else:
            rendered_reason = sanitize_finalization_message(reason)
        if len(rendered_reason) <= 512:
            rendered_reason = normalize_run_outcome_reason(
                normalized_status,
                rendered_reason,
            )

        previous_outcome = self.get_run_outcome()
        underlying_outcome: Optional[Dict[str, Any]] = None
        if normalized_status in {"runtime_failed", "interrupted"}:
            if previous_outcome.get("status") == "domain_failed":
                underlying_outcome = previous_outcome
            elif isinstance(previous_outcome.get("underlying_outcome"), dict):
                underlying_outcome = copy.deepcopy(
                    previous_outcome["underlying_outcome"]
                )

        outcome: Dict[str, Any] = {
            "adapter_schema_version": "1.0",
            "status": normalized_status,
            "reason": rendered_reason,
            "affected_duts": normalized_duts,
        }
        if normalized_status in {"domain_failed", "runtime_failed"}:
            outcome["failure_type"] = normalized_failure_type
        if underlying_outcome is not None:
            outcome["underlying_outcome"] = copy.deepcopy(underlying_outcome)
        self._run_outcome = outcome

    def get_run_outcome(self) -> Dict[str, Any]:
        """
        Return a defensive projection of the current run outcome.

        The implementation uses current instance state to produce a defensive
        projection of the current run outcome.

        Returns:
            A mapping containing run outcome.
        """

        tracker = getattr(self, "status_tracker", None)
        tracker_outcome = getattr(tracker, "run_outcome", None)
        if isinstance(tracker_outcome, dict):
            return copy.deepcopy(tracker_outcome)
        fallback = getattr(self, "_run_outcome", None)
        if not isinstance(fallback, dict):
            fallback = {
                "adapter_schema_version": "1.0",
                "status": "success",
                "reason": "",
                "affected_duts": [],
            }
        return copy.deepcopy(fallback)

    async def start_resource_monitor(self) -> None:
        """
        Start best-effort resource telemetry after the async logger is ready.

        The implementation uses current instance state to start best-effort
        resource telemetry after the async logger is ready. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.
        """
        monitor = getattr(self, "resource_usage_monitor", None)
        if monitor is None:
            return
        try:
            artifact_created = await monitor.start()
        except Exception as exc:
            try:
                await monitor.cancel()
            except Exception:
                pass
            await self._log_resource_monitor_safely(
                "WARNING",
                f"Resource telemetry startup failed: {exc}",
            )
            return

        scheduler = monitor.scheduler
        await self._log_resource_monitor_safely(
            "INFO",
            "CPU resource budget: "
            f"effective_cpus={scheduler.get('effective_cpus')}, "
            f"K={scheduler.get('oversubscription_factor')}, "
            f"collector_operation_cap="
            f"{scheduler.get('installed_collector_operation_limit')}, "
            f"mode={scheduler.get('concurrency_mode')}, "
            f"min/max={scheduler.get('minimum_collector_operation_limit')}/"
            f"{scheduler.get('maximum_collector_operation_limit')}, "
            f"binding={scheduler.get('binding_sources', [])}",
        )
        level = "INFO" if artifact_created else "WARNING"
        await self._log_resource_monitor_safely(
            level,
            "Resource telemetry "
            f"{'started' if artifact_created else 'could not create its artifact'}: "
            f"{monitor.output_path} "
            f"(interval={monitor.sample_interval_seconds:g}s)",
        )

    async def stop_resource_monitor(self, dut_ids: Optional[List[str]] = None) -> None:
        """
        Finalize resource telemetry without allowing it to break cleanup.

        The implementation uses current instance state and ``dut_ids`` to
        finalize resource telemetry without allowing logging failures to break
        cleanup. For live execution, a successful root artifact is then
        projected into every DUT metadata directory before report or archive
        publication. Dry-run planning retains only the root telemetry and does
        not manufacture per-DUT execution projections. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Args:
            dut_ids: Optional finalized DUT roster. ``None`` resolves the
                current manager roster for direct lifecycle callers.

        Raises:
            RuntimeError: If a successful root artifact cannot publish its
                mandatory per-DUT projections.

        Side effects:
            Finalizes the root resource artifact and, for live execution,
            atomically writes one shared-run projection for every DUT in the
            selected roster.
        """
        monitor = getattr(self, "resource_usage_monitor", None)
        if monitor is None:
            return
        if isinstance(monitor, ResourceUsageMonitor):
            host_pool_sampler = getattr(
                getattr(self, "dut_manager", None),
                "get_host_ssh_pool_metrics",
                None,
            )
            if callable(host_pool_sampler):
                monitor.set_host_ssh_pool_sampler(host_pool_sampler)
        try:
            summary = await monitor.stop()
        except Exception as exc:
            try:
                await monitor.cancel()
            except Exception:
                pass
            await self._log_resource_monitor_safely(
                "WARNING",
                f"Resource telemetry finalization failed: {exc}",
            )
            return

        if summary is not None:
            process_peaks = summary.get("peaks", {}).get("process", {})
            succeeded = summary.get("artifact_write_succeeded") is True
            if succeeded:
                tool_config = self.config_manager.get_tool_config()
                dry_run = bool(
                    tool_config.get("dry_run", False)
                    if isinstance(tool_config, dict)
                    else getattr(tool_config, "dry_run", False)
                )
                resolved_dut_ids = [] if dry_run else dut_ids
                if resolved_dut_ids is None:
                    dut_manager = getattr(self, "dut_manager", None)
                    resolved_dut_ids = (
                        list(dut_manager.get_all_dut_ids())
                        if dut_manager is not None
                        else []
                    )
                logger_owner = getattr(self, "logger", None)
                get_metadata_dir = getattr(logger_owner, "get_dut_metadata_dir", None)
                if resolved_dut_ids and not callable(get_metadata_dir):
                    raise RuntimeError(
                        "Resource telemetry cannot resolve DUT metadata directories"
                    )
                projection_paths = {
                    dut_id: get_metadata_dir(dut_id) / monitor.output_path.name
                    for dut_id in resolved_dut_ids
                }
                publisher = getattr(monitor, "publish_dut_projections", None)
                if projection_paths and not callable(publisher):
                    raise RuntimeError(
                        "Resource telemetry monitor cannot publish DUT projections"
                    )
                if projection_paths:
                    publication = publisher(projection_paths)
                    if not inspect.isawaitable(publication):
                        raise RuntimeError(
                            "Resource telemetry DUT projection publisher is not asynchronous"
                        )
                    written_paths = await publication
                    if len(written_paths) != len(projection_paths):
                        raise RuntimeError(
                            "Resource telemetry did not publish every DUT projection"
                        )
                message = (
                    "Resource telemetry finalized: "
                    f"samples={summary.get('samples_total', 0)}, "
                    f"peak_rss_bytes={process_peaks.get('peak_rss_bytes')}, "
                    f"artifact={monitor.output_path}, "
                    f"dut_projections={len(projection_paths)}"
                )
            else:
                message = (
                    "Resource telemetry final snapshot could not be persisted; "
                    f"the last atomic snapshot remains at {monitor.output_path}"
                )
            await self._log_resource_monitor_safely(
                "INFO" if succeeded else "WARNING", message
            )

    async def _log_resource_monitor_safely(self, level: str, message: str) -> None:
        """
        Resource observability must never make collection logging fail.

        The implementation uses ``level`` and ``message`` to resource
        observability must never make collection logging fail. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        try:
            async_logger = getattr(self, "logger", None)
            if async_logger is not None:
                await async_logger.log_runtime(level, "ResourceUsageMonitor", message)
        except Exception:
            logger.debug("Failed to write resource telemetry log", exc_info=True)

    async def async_init(self) -> None:
        """
        Async initialization - called after sync __init__.

        Initializes config manager and sets orchestrator references.
        """
        # Initialize config manager async components (needed for both quiet and non-quiet modes)
        await self.config_manager.async_init()

        # Set orchestrator reference for all services after orchestrator is fully initialized
        await self.config_manager.set_orchestrator_reference(self)

    def _get_run_identity_tool_facts(self) -> Dict[str, str]:
        """
        Resolve one run-owned build fact set for every artifact projection.

        After applying local validation, the function forwards current instance
        state to ``dict`` and preserves its return and exception contract. It
        updates ``_run_identity_tool_facts`` on the instance as part of that
        state transition.

        Returns:
            A mapping containing run identity tool facts.
        """

        if getattr(self, "_run_identity_tool_facts", None) is None:
            self._run_identity_tool_facts = tool_identity_facts()
        return dict(self._run_identity_tool_facts)

    def capture_planning_plan_identity(self) -> None:
        """
        Bind the exact product-authored dry-run plan before teardown.

        The implementation uses current instance state to bind the exact
        product-authored dry-run plan before teardown. It updates
        ``_run_identity_planning_plan`` on the instance as part of that state
        transition. If the function cannot bind the exact product-authored
        dry-run plan before teardown, its exception reaches the caller instead
        of being converted into a successful result.

        Raises:
            RuntimeError: If authoritative planning artifact changed.
        """

        snapshot = capture_planning_plan_snapshot(self.log_dir)
        retained = getattr(self, "_run_identity_planning_plan", None)
        if retained is not None and retained != snapshot:
            raise RuntimeError("Authoritative planning artifact changed")
        self._run_identity_planning_plan = snapshot

    def finalize_run_provenance(self) -> None:
        """
        Capture immutable loader/build inputs before terminal sealing.

        The effective configuration and plan are intentionally not hashed here:
        their authoritative bytes do not exist until teardown and bundle
        sanitization complete.

        Raises:
            RuntimeError: If configuration manager has no catalog byte
                authority; authoritative catalog byte facts are unavailable;
                resolved invocation configuration is unavailable; or
                authoritative catalog facts changed during the run.
        """

        # Production owns the concrete transactional tracker.  Offline/test
        # compatibility doubles cannot publish a canonical RunResult and retain
        # their legacy no-op hook behavior.
        provenance_requested = bool(
            getattr(self, "_run_identity_required", False)
            or getattr(self, "_run_identity_catalog_facts", None) is not None
        )
        if (
            type(getattr(self, "status_tracker", None)) is not CollectionStatusTracker
            or not provenance_requested
            or (
                type(self.config_manager) is not ConfigurationManager
                and getattr(self, "_run_identity_catalog_facts", None) is None
            )
        ):
            return

        facts_getter = getattr(
            self.config_manager,
            "get_catalog_snapshot_facts",
            None,
        )
        if not callable(facts_getter):
            raise RuntimeError("Configuration manager has no catalog byte authority")
        catalog_facts = facts_getter()
        if type(catalog_facts) is not CatalogSnapshotFacts:
            raise RuntimeError("Authoritative catalog byte facts are unavailable")
        tool_config = getattr(self, "_tool_config_obj", None)
        if tool_config is None:
            tool_config = self.config_manager.get_tool_config()
        if tool_config is None:
            raise RuntimeError("Resolved invocation configuration is unavailable")
        if (
            getattr(self, "_run_identity_catalog_facts", None) is not None
            and self._run_identity_catalog_facts != catalog_facts
        ):
            raise RuntimeError("Authoritative catalog facts changed during the run")
        self._run_identity_catalog_facts = catalog_facts
        self._run_identity_tool_config = tool_config
        self._get_run_identity_tool_facts()

    # Configuration delegation methods
    @property
    def tool_config(self) -> Dict[str, Any]:
        """
        Expose tool configuration for backward compatibility with tests.

        Each access computes the value from ``config_manager`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            A mapping containing tool config.
        """
        return self.config_manager.get_tool_config()

    async def get_dut_specific_tool_config(self, dut_id: str) -> Dict[str, Any]:
        """
        Get tool configuration with DUT-specific overrides.

        After applying local validation, the function forwards ``dut_id`` to
        ``self.config_manager.get_dut_specific_tool_config`` and preserves its
        return and exception contract. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing DUT specific tool config.
        """
        return await self.config_manager.get_dut_specific_tool_config(dut_id)

    @property
    def collector_definitions(self) -> Dict[str, Any]:
        """
        Expose collector definitions for backward compatibility with tests.

        Each access computes the value from ``config_manager`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            A mapping containing collector definitions.
        """
        return self.config_manager.get_collector_definitions()

    @property
    def services(self) -> Dict[str, Any]:
        """
        Expose services map for backward compatibility with tests.

        Each access computes the value from ``config_manager`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            A mapping containing services.
        """
        return self.config_manager.get_services()

    def get_sequential_collectors(self) -> Set[str]:
        """
        Get sequential collector IDs.

        After applying local validation, the function forwards current instance
        state to ``self.config_manager.get_sequential_collectors`` and preserves
        its return and exception contract.

        Returns:
            The unique sequential collectors returned by the operation.
        """
        return self.config_manager.get_sequential_collectors()

    def get_parallel_collectors(self) -> Set[str]:
        """
        Get parallel collector IDs.

        After applying local validation, the function forwards current instance
        state to ``self.config_manager.get_parallel_collectors`` and preserves
        its return and exception contract.

        Returns:
            The unique parallel collectors returned by the operation.
        """
        return self.config_manager.get_parallel_collectors()

    def get_collector_info(self, collector_id: str) -> Dict[str, Any]:
        """
        Get collector information by ID.

        After applying local validation, the function forwards ``collector_id``
        to ``self.config_manager.get_collector_info`` and preserves its return
        and exception contract.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A mapping containing collector info.
        """
        return self.config_manager.get_collector_info(collector_id)

    def get_runtime_capabilities(
        self, dut_id: str, capability_type: Optional[str] = None
    ) -> Any:
        """
        Expose live per-DUT prerequisite capabilities to later collectors.

        The implementation uses ``dut_id`` and ``capability_type`` to expose
        live per-DUT prerequisite capabilities to later collectors.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            capability_type: Optional capability type; ``None`` selects the
                function's default behavior.

        Returns:
            The runtime capabilities value selected by the operation.
        """
        capabilities = getattr(self, "runtime_capabilities", {}).get(dut_id, {})
        if capability_type is None:
            return copy.deepcopy(capabilities)
        return copy.deepcopy(capabilities.get(capability_type, []))

    def get_collector_name(self, collector_id: str) -> str:
        """
        Get collector name by ID.

        The implementation uses ``collector_id`` to get collector name by ID.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical collector name.
        """
        collector_info = self.get_collector_info(collector_id)
        return (
            collector_info.get("name", collector_id) if collector_info else collector_id
        )

    def get_collectors_for_group(self, group: str) -> Dict[str, Any]:
        """
        Get all collectors for a specific group.

        After applying local validation, the function forwards ``group`` to
        ``self.config_manager.get_collectors_for_group`` and preserves its
        return and exception contract.

        Args:
            group: Text supplied as group in the format accepted by this
                function.

        Returns:
            A mapping containing collectors for group.
        """
        return self.config_manager.get_collectors_for_group(group)

    def get_all_collector_groups(self) -> List[str]:
        """
        Get all unique collector groups.

        After applying local validation, the function forwards current instance
        state to ``self.config_manager.get_all_collector_groups`` and preserves
        its return and exception contract.

        Returns:
            The all collector groups returned in operation-defined order.
        """
        return self.config_manager.get_all_collector_groups()

    async def log_collector_selection_table(self, collector_ids: List[str]) -> None:
        """
        Log a comprehensive table showing all available collectors and their status.

        This method shows all collectors from collector definitions along with
        clear reasons why collectors are or are not being collected.

        Args:
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"log_collector_selection_table called with {len(collector_ids)} collector IDs: {collector_ids}",
        )
        # Get all collector groups
        all_collector_groups = self.config_manager.get_all_collector_groups()

        # Create Rich table for console display
        table = Table(title="Collector Selection Summary")
        table.add_column("Group", style="cyan", no_wrap=True)
        table.add_column("ID", style="magenta", no_wrap=True)
        table.add_column("Collector Name", style="green")
        table.add_column("Level", style="blue", no_wrap=True)
        table.add_column("Status", style="yellow", no_wrap=True)
        table.add_column("Reason", style="white")

        # Write table header to DUT runtime logs
        if self.dut_manager:
            for dut_id in self.dut_manager.get_all_dut_ids():
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "CollectorSelection",
                    "Comprehensive Execution Summary:",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", "-" * 151
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "CollectorSelection",
                    f"{'Group':<12} {'ID':<8} {'Collector Name':<30} {'Level':<6} {'Status':<15} {'Reason':<80}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", "-" * 145
                )

        # Track statistics
        total_collectors = 0
        included_collectors = 0
        excluded_collectors = 0
        not_applicable_collectors = 0
        not_found_collectors = 0

        # Get baseboard information for applicability checks
        baseboard_info = None
        if self.dut_manager:
            dut_ids = self.dut_manager.get_all_dut_ids()
            if dut_ids:
                baseboards = set()
                for dut_id in dut_ids:
                    dut = self.dut_manager.get_dut(dut_id)
                    if dut and dut.config:
                        baseboard = dut.config.get("baseboard")
                        # Normalize None/empty baseboard to "Unknown" to keep logging/join safe
                        if not baseboard:
                            baseboard = "Unknown"
                        else:
                            baseboard = str(baseboard)
                        baseboards.add(baseboard)

                if len(baseboards) == 1:
                    # Single baseboard environment - use the baseboard for filtering
                    baseboard_info = list(baseboards)[0]
                elif len(baseboards) > 1:
                    # Multi-DUT environment with different baseboards
                    await self.logger.log_runtime(
                        "INFO",
                        "WorkflowOrchestrator",
                        f"Multi-DUT environment detected with baseboards: {', '.join(baseboards)}",
                    )
                    await self.logger.log_runtime(
                        "INFO",
                        "WorkflowOrchestrator",
                        "Each DUT will run only collectors applicable to its specific baseboard",
                    )
                    # For multi-DUT environments, we don't do global baseboard filtering
                    # Each DUT will determine its own applicable collectors during execution
                    baseboard_info = None

        # Get collection level
        collection_level = "L3"  # Default to L3 if not available
        if hasattr(self, "tool_config") and self.tool_config:
            if hasattr(self.tool_config, "collection_level"):
                collection_level = self.tool_config.collection_level
            elif isinstance(self.tool_config, dict):
                collection_level = self.tool_config.get("collection_level", "L3")

        # Log collection level to each DUT's runtime log
        if self.dut_manager:
            for dut_id in self.dut_manager.get_all_dut_ids():
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "CollectorSelection",
                    f"Collection level: {collection_level}",
                )

        # Iterate through all collector groups
        for group in all_collector_groups:
            # Map internal group key to display name using enum
            group_display_name = (
                CollectorServiceMapping.get_display_name_from_group_name(group)
            )

            # Get all collectors for this group
            group_collectors = self.config_manager.get_collectors_for_group(group)

            # Iterate through all collectors in this group
            for collector_id, collector_info in group_collectors.items():
                collector_name = collector_info.get("name", "unknown")

                # Determine status and reason
                status = "Not applicable"
                reason = "Not applicable for current platform/configuration"

                # Check if collector is in the requested list
                if collector_id in collector_ids:
                    # Check baseboard applicability
                    try:
                        is_applicable = self._is_collector_applicable(
                            collector_info, baseboard_info
                        )
                    except ValueError as e:
                        # Baseboard not found in spreadsheet - this is a critical configuration error
                        # Log the error and exit
                        error_msg = str(e)
                        await self.logger.log_runtime(
                            "ERROR",
                            "WorkflowOrchestrator",
                            f"CRITICAL: {error_msg}",
                        )
                        self.sanitized_console.print_failure(
                            error_msg,
                            title="Invalid Baseboard Configuration",
                            suggestions=(
                                "Configure a baseboard present in the selected Telemetry Catalog.",
                                "Run 'nvdebug list-baseboards' to inspect supported platforms.",
                            ),
                        )
                        sys.exit(1)

                    if is_applicable:
                        # Check collection level
                        collector_level = collector_info.get("collection_level", "L3")
                        if self._is_collector_level_applicable(
                            collector_level, collection_level
                        ):
                            status = "Included"
                            if baseboard_info:
                                reason = f"Collector is applicable for baseboard '{baseboard_info}'"
                            else:
                                reason = (
                                    "Collector is applicable for current configuration"
                                )
                            included_collectors += 1
                        else:
                            status = "Excluded"
                            reason = (
                                f"Not in current collection level ({collection_level})"
                            )
                            excluded_collectors += 1
                    else:
                        # Check why it's not applicable
                        tags = collector_info.get("tags", {})
                        if isinstance(tags, dict):
                            include_tags = tags.get("include", [])
                            exclude_tags = tags.get("exclude", [])
                        else:
                            include_tags = []
                            exclude_tags = []

                        if exclude_tags:
                            status = "Not applicable"
                            if baseboard_info:
                                reason = f"Not applicable for baseboard '{baseboard_info}' (Tags: {exclude_tags})"
                            else:
                                reason = f"Not applicable for current configuration (Tags: {exclude_tags})"
                        elif include_tags:
                            status = "Not applicable"
                            if baseboard_info:
                                reason = f"Not applicable for baseboard '{baseboard_info}' (BaseboardConstraint)"
                            else:
                                reason = "Not applicable for current configuration (BaseboardConstraint)"
                        else:
                            status = "Not applicable"
                            if baseboard_info:
                                reason = f"Not applicable for baseboard '{baseboard_info}' (BaseboardConstraint)"
                            else:
                                reason = "Not applicable for current configuration (BaseboardConstraint)"

                        not_applicable_collectors += 1
                else:
                    # Collector not requested
                    try:
                        is_applicable = self._is_collector_applicable(
                            collector_info, baseboard_info
                        )
                    except ValueError as e:
                        # Baseboard not found in spreadsheet - this is a critical configuration error
                        # Log the error and exit
                        error_msg = str(e)
                        await self.logger.log_runtime(
                            "ERROR",
                            "WorkflowOrchestrator",
                            f"CRITICAL: {error_msg}",
                        )
                        self.sanitized_console.print_failure(
                            error_msg,
                            title="Invalid Baseboard Configuration",
                            suggestions=(
                                "Configure a baseboard present in the selected Telemetry Catalog.",
                                "Run 'nvdebug list-baseboards' to inspect supported platforms.",
                            ),
                        )
                        sys.exit(1)

                    if is_applicable:
                        status = "Not selected"
                        reason = "Collector not included in current selection"
                        not_applicable_collectors += 1
                    else:
                        status = "Not applicable"
                        reason = f"Not applicable for baseboard '{baseboard_info}' (BaseboardConstraint)"
                        not_applicable_collectors += 1

                # Get collector level
                collector_level = collector_info.get("collection_level", "L1")

                # Truncate collector name to fit in columns
                truncated_collector_name = (
                    collector_name[:30] if len(collector_name) > 30 else collector_name
                )

                # For multi-DUT environments, generate reason per DUT
                if self.dut_manager and baseboard_info is None:
                    # Multi-DUT environment - generate reason for each DUT
                    for dut_id in self.dut_manager.get_all_dut_ids():
                        dut = self.dut_manager.get_dut(dut_id)
                        dut_baseboard = "Unknown"
                        if dut and dut.config:
                            dut_baseboard = dut.config.get("baseboard", "Unknown")

                        # Generate DUT-specific reason
                        dut_reason = self._generate_dut_specific_reason(
                            reason, status, dut_baseboard, collector_info
                        )
                        truncated_dut_reason = (
                            dut_reason[:80] if len(dut_reason) > 80 else dut_reason
                        )

                        table_row = (
                            f"{group_display_name:<12} {collector_id:<8} "
                            f"{truncated_collector_name:<30} {collector_level:<6} {status:<15} {truncated_dut_reason:<80}"
                        )

                        log_level = (
                            "INFO" if status in ("Included", "Excluded") else "DEBUG"
                        )
                        await self.logger.write_to_dut_runtime_log(
                            dut_id, log_level, "CollectorSelection", table_row
                        )
                else:
                    # Single DUT or no DUT manager - use global reason
                    truncated_reason = reason[:80] if len(reason) > 80 else reason
                    table_row = (
                        f"{group_display_name:<12} {collector_id:<8} "
                        f"{truncated_collector_name:<30} {collector_level:<6} {status:<15} {truncated_reason:<80}"
                    )

                    log_level = (
                        "INFO" if status in ("Included", "Excluded") else "DEBUG"
                    )
                    await self.logger.log_runtime(
                        log_level, "CollectorSelection", table_row
                    )

                    # Add row to Rich table
                    table.add_row(
                        group_display_name,
                        collector_id,
                        truncated_collector_name,
                        collector_level,
                        status,
                        truncated_reason,
                    )

                    if self.dut_manager:
                        for dut_id in self.dut_manager.get_all_dut_ids():
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                log_level,
                                "CollectorSelection",
                                table_row,
                            )

                total_collectors += 1

        # Write summary statistics
        summary_line = (
            f"Total collectors: {total_collectors} | Included: {included_collectors} | "
            f"Excluded: {excluded_collectors} | Not applicable: {not_applicable_collectors} | Not found: {not_found_collectors}"
        )

        # Log summary to DUT runtime logs
        if self.dut_manager:
            for dut_id in self.dut_manager.get_all_dut_ids():
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", "-" * 151
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", summary_line
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", "-" * 151
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "CollectorSelection",
                    f"Total collectors to execute: {included_collectors}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "INFO", "CollectorSelection", ""
                )

        # Display Rich table in console only if verbose mode is enabled
        if self.verbose_mode:
            console = Console()
            console.print(table)

    async def add_execution_summary_entry(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        log_paths: List[str],
        custom_reason: Optional[str] = None,
        failure_category: Optional[str] = None,
    ) -> None:
        """
        Add an entry to the execution summary.

        The implementation uses ``dut_id``, ``collector_id``, ``status``,
        ``log_paths``, and ``custom_reason`` to add an entry to the execution
        summary. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            status: Text supplied as status in the format accepted by this
                function.
            log_paths: Filesystem locations processed in caller-provided order.
            custom_reason: Optional custom reason; ``None`` selects the
                function's default behavior.
            failure_category: Optional failure category; ``None`` selects the
                function's default behavior.
        """
        collector_name = self.get_collector_name(collector_id)
        category_kwargs = (
            {"failure_category": failure_category}
            if failure_category is not None
            else {}
        )
        await self.execution_summary_manager.add_entry(
            dut_id,
            collector_name,
            status,
            log_paths,
            custom_reason,
            collector_id,
            **category_kwargs,
        )

    async def record_execution_order_entry(
        self, dut_id: str, collector_id: str
    ) -> None:
        """
        Record execution order entry.

        The implementation uses ``dut_id`` and ``collector_id`` to record
        execution order entry. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        if not dut_id:
            return
        if dut_id not in self._execution_order_counters:
            self._execution_order_counters[dut_id] = 0
        self._execution_order_counters[dut_id] += 1
        collector_info = self.get_collector_info(collector_id) or {}
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if dut_id not in self._execution_order_entries:
            self._execution_order_entries[dut_id] = []
        self._execution_order_entries[dut_id].append(
            {
                "order": str(self._execution_order_counters[dut_id]),
                "timestamp": timestamp,
                "id": str(collector_id),
                "name": str(collector_info.get("name", "Unknown")),
                "group": str(collector_info.get("group", "Unknown")),
            }
        )

    def _build_execution_order_table(self, dut_id: str) -> str:
        """
        Build execution order table.

        The implementation uses ``dut_id`` to build execution order table.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The canonical execution order table text.
        """
        rows = self._execution_order_entries.get(dut_id, [])
        if not rows:
            return ""
        header = "Order  | Timestamp           | ID    | Name                          | Group\n"
        separator = "------ | ------------------- | ----- | ----------------------------- | -----\n"
        lines = [header, separator]
        for row in rows:
            lines.append(
                f"{row['order'].ljust(5)} | "
                f"{row['timestamp']} | "
                f"{row['id'].ljust(5)} | "
                f"{row['name'].ljust(29)} | "
                f"{row['group']}\n"
            )
        return "".join(lines)

    def _append_execution_order_table_to_runtime_log(self) -> None:
        """
        Append execution order table to runtime log.

        The implementation uses current instance state to append execution order
        table to runtime log. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.
        """
        if not self.dut_manager:
            return
        for dut_id in self.dut_manager.get_all_dut_ids():
            table_text = self._build_execution_order_table(dut_id)
            if not table_text:
                continue
            runtime_log_path = self.log_dir / dut_id / "nvdebug_runtime_output.txt"
            runtime_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(runtime_log_path, "a", encoding="utf-8") as file_handle:
                file_handle.write("\n")
                file_handle.write(table_text)

    def _write_execution_order_metadata(self) -> None:
        """
        Write execution order metadata.

        The implementation uses current instance state to write execution order
        metadata. Success is reported only after the owning output boundary has
        completed its required write or publication step.
        """
        tool_config = getattr(self, "_tool_config_obj", None)
        dry_run = (
            tool_config.get("dry_run", False)
            if isinstance(tool_config, dict)
            else getattr(tool_config, "dry_run", False)
        )
        if dry_run:
            return
        if not self.dut_manager:
            return
        for dut_id in self.dut_manager.get_all_dut_ids():
            entries = self._execution_order_entries.get(dut_id, [])
            metadata_dir = None
            if self.logger:
                try:
                    metadata_dir = self.logger.get_dut_metadata_dir(dut_id)
                except Exception:
                    metadata_dir = None
            if not metadata_dir:
                metadata_dir = self.log_dir / dut_id / ".metadata"
            metadata_dir.mkdir(parents=True, exist_ok=True)

            payload = {
                "metadata": {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                },
                "payload": {
                    "execution_order": entries,
                },
            }
            output_path = metadata_dir / "execution_order.json"
            with open(output_path, "w", encoding="utf-8") as file_handle:
                safe_json_dump(payload, file_handle, indent=4)

    def _has_execution_order_entry(self, dut_id: str, collector_id: str) -> bool:
        """
        Return whether start-order evidence already contains a collector.

        After applying local validation, the function forwards ``dut_id`` and
        ``collector_id`` to ``any`` and preserves its return and exception
        contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            Whether start-order evidence already contains a collector.
        """

        return any(
            str(entry.get("id", "")).casefold() == str(collector_id).casefold()
            for entry in self._execution_order_entries.get(dut_id, [])
        )

    def _has_execution_summary_entry(self, dut_id: str, collector_id: str) -> bool:
        """
        Return whether a DUT summary already contains a collector row.

        After applying local validation, the function forwards ``dut_id`` and
        ``collector_id`` to ``any`` and preserves its return and exception
        contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            Whether a DUT summary already contains a collector row.
        """

        entries = self.execution_summary_manager.entries.get(dut_id, [])
        return any(
            str(entry.get("collector_id", "")).casefold()
            == str(collector_id).casefold()
            for entry in entries
            if isinstance(entry, dict)
        )

    async def _persist_interrupted_collector_evidence(
        self,
        *,
        project_unfinished: bool = False,
    ) -> None:
        """
        Project interrupted collectors onto every loose-bundle surface.

        Cleanup invokes this before the tracker freezes. Already-cancelled
        entries are refreshed idempotently; when the run itself is interrupted,
        pending and running entries are first transitioned through the tracker's
        ordinary completion API so in-memory counts and persisted evidence stay
        consistent.

        Args:
            project_unfinished: Whether project unfinished is enabled or
                required for this operation.

        Raises:
            RuntimeError: If interrupted collector inventory is malformed for
                ``dut_id``:``collector_id``; status tracker cannot transition
                interrupted collectors; interrupted collector transition
                returned an unexpected value; or status tracker did not
                transition interrupted collector ``dut_id``:``collector_id``; or
                another input invariant is violated.
        """

        tracker = getattr(self, "status_tracker", None)
        entries = getattr(tracker, "collector_statuses", None)
        if not isinstance(entries, dict):
            return

        selected_entries = []
        for entry in entries.values():
            status_value = str(
                getattr(getattr(entry, "status", None), "value", "")
            ).casefold()
            if status_value == "cancelled" or (
                project_unfinished and status_value in {"pending", "running"}
            ):
                selected_entries.append((entry, status_value))

        for entry, previous_status in selected_entries:
            dut_id = str(entry.dut_id)
            collector_id = str(entry.collector_id)
            reason = str(
                entry.reason or "Collector cancelled because collection was interrupted"
            )
            inventory = self.logger.reconcile_collector_file_inventory(
                dut_id,
                collector_id,
                list(getattr(entry, "all_files", None) or []),
                refresh=True,
            )
            if not isinstance(inventory, dict) or any(
                not isinstance(inventory.get(field), list)
                for field in (
                    "output_files",
                    "diagnostic_files",
                    "error_files",
                    "all_files",
                )
            ):
                raise RuntimeError(
                    "Interrupted collector inventory is malformed for "
                    f"{dut_id}:{collector_id}"
                )

            entry.output_files = list(inventory["output_files"])
            entry.diagnostic_files = list(inventory["diagnostic_files"])
            entry.error_files = list(inventory["error_files"])
            entry.all_files = list(inventory["all_files"])
            entry.discovered_files = self.logger._group_inventory_files(entry.all_files)
            existing_context = (
                dict(entry.context) if isinstance(entry.context, dict) else {}
            )
            existing_context.update(
                {
                    "status": "cancelled",
                    "successful_operations": existing_context.get(
                        "successful_operations", 0
                    ),
                    "total_operations": existing_context.get("total_operations", 0),
                    "error_messages": existing_context.get("error_messages", []),
                }
            )
            entry.context = existing_context
            execution_time = float(getattr(entry, "execution_time", 0.0) or 0.0)
            start_time = getattr(entry, "start_time", None)
            if previous_status == "running" and isinstance(start_time, datetime):
                completed_at = datetime.now(tz=start_time.tzinfo)
                execution_time = max(
                    execution_time,
                    (completed_at - start_time).total_seconds(),
                )

            if previous_status in {"pending", "running"}:
                complete_collector = getattr(tracker, "complete_collector", None)
                if not callable(complete_collector):
                    raise RuntimeError(
                        "Status tracker cannot transition interrupted collectors"
                    )
                completion = complete_collector(
                    dut_id,
                    collector_id,
                    "cancelled",
                    reason=reason,
                    execution_time=execution_time,
                    output_files=list(entry.output_files),
                    diagnostic_files=list(entry.diagnostic_files),
                    error_files=list(entry.error_files),
                    all_files=list(entry.all_files),
                    discovered_files=dict(entry.discovered_files),
                    context=dict(existing_context),
                    skip_status_update=True,
                )
                if inspect.isawaitable(completion):
                    await completion
                elif completion is not None:
                    raise RuntimeError(
                        "Interrupted collector transition returned an unexpected value"
                    )
                transitioned_status = str(
                    getattr(getattr(entry, "status", None), "value", "")
                ).casefold()
                if transitioned_status != "cancelled":
                    raise RuntimeError(
                        "Status tracker did not transition interrupted collector "
                        f"{dut_id}:{collector_id}"
                    )

            await self.logger.log_collector_result(
                dut_id,
                collector_id,
                "cancelled",
                reason,
                execution_time,
                list(entry.all_files),
                existing_context,
                entry.discovered_files,
            )
            await self.logger.write_collector_status_file(
                collector_id,
                dut_id,
                "cancelled",
                reason,
            )

            if getattr(
                entry, "start_time", None
            ) is not None and not self._has_execution_order_entry(dut_id, collector_id):
                await self.record_execution_order_entry(dut_id, collector_id)
            if not self._has_execution_summary_entry(dut_id, collector_id):
                await self.add_execution_summary_entry(
                    dut_id,
                    collector_id,
                    "cancelled",
                    list(entry.all_files),
                    reason,
                )

        if selected_entries:
            status_update = tracker._update_status()
            if inspect.isawaitable(status_update):
                await status_update
            elif status_update is not None:
                raise RuntimeError("Status update returned an unexpected value")
            timing_update = tracker._save_dut_timing_files()
            if inspect.isawaitable(timing_update):
                await timing_update
            elif timing_update is not None:
                raise RuntimeError("Timing update returned an unexpected value")

    async def initialize(self) -> None:
        """
        Initialize the orchestrator (setup DUTs, test connections).

        Initializes DUTs, tests connections, and sets up logging.
        """
        await self.logger.log_runtime(
            "INFO", "WorkflowOrchestrator", "Initializing orchestrator..."
        )
        catalog_only_mode = getattr(
            self, "catalog_only_mode", getattr(self, "quiet_mode", False)
        )

        # Create progress bar for initialization (only in non-quiet mode)
        try:
            if not self.quiet_mode:
                # Use the orchestrator's console
                progress_console = self.console

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=progress_console,
                    transient=True,
                ) as progress:
                    init_task = progress.add_task(
                        "Initializing orchestrator...", total=1
                    )
                    progress.update(
                        init_task,
                        description="Initializing orchestrator...",
                        advance=1,
                        completed=True,
                    )

            else:
                # In quiet mode, create a dummy progress object
                class DummyProgress:
                    """
                    Implement the dummy progress boundary used by the NVDebug runtime.

                    The type coordinates ``add_task`` and ``update`` and retains
                    the state those operations share between calls. Resource
                    ownership remains inside the instance until the matching
                    close, exit, or cleanup operation completes.
                    """

                    def add_task(self, *args, **kwargs):
                        """
                        Add task.

                        The implementation uses ``args`` and ``kwargs`` to add
                        task.

                        Args:
                            args: Additional positional values forwarded in
                                caller-provided order.
                            kwargs: Additional named values forwarded without
                                changing their keys.

                        Returns:
                            The sentinel task identifier used by the disabled
                            progress implementation.
                        """
                        return 0

                    def update(self, *args, **kwargs):
                        """
                        Update state retained by the current owner.

                        The implementation uses ``args`` and ``kwargs`` to
                        update state retained by the current owner.

                        Args:
                            args: Additional positional values forwarded in
                                caller-provided order.
                            kwargs: Additional named values forwarded without
                                changing their keys.
                        """
                        pass

                    def __enter__(self):
                        """
                        Enter the DummyProgress context.

                        Entering the scope acquires or validates its owned
                        resources and returns the value used until the matching
                        exit method completes cleanup.

                        Returns:
                            The validated ``self``.
                        """
                        return self

                    def __exit__(self, *args):
                        """
                        Exit the DummyProgress context.

                        Leaving the scope releases resources owned by the
                        context while preserving the exception-propagation
                        behavior declared by the context-manager protocol.

                        Args:
                            args: Additional positional values forwarded in
                                caller-provided order.
                        """
                        pass

                progress = DummyProgress()
                init_task = 0

            # Step 1: Initialize async components
            if not self.quiet_mode:
                progress.update(
                    init_task,
                    description="Initializing async components...",
                    advance=1,
                )
            await self.async_init()

            # Update console to use redirected stdout if available
            if hasattr(self.logger, "original_stdout") and self.logger.original_stdout:
                self.console = Console(file=self.logger.original_stdout)

            # Step 2: Check quiet mode
            if not self.quiet_mode:
                progress.update(
                    init_task,
                    description="Checking initialization mode...",
                    advance=1,
                )

            # Catalog-only commands initialize just enough state for filtering.
            if catalog_only_mode:
                if not self.quiet_mode:
                    progress.update(
                        init_task,
                        description="Catalog mode - initializing BaseboardManager...",
                        advance=1,
                    )

                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "Catalog mode - initializing BaseboardManager for collector filtering",
                )

                # Create a minimal DUT manager with only BaseboardManager for collector filtering
                try:
                    uri_config_manager = self.config_manager.get_uri_config_manager()
                    tool_config = self.config_manager.get_tool_config()
                    spreadsheet_path, catalog_snapshot = _dut_manager_catalog_inputs(
                        self.config_manager, tool_config
                    )
                    self.dut_manager = DUTManager(
                        self.config_manager.get_dut_config(),
                        str(self.log_dir),
                        uri_config_manager,
                        spreadsheet_path=spreadsheet_path,
                        catalog_snapshot=catalog_snapshot,
                        sanitized_console=self.sanitized_console,
                        tool_config=tool_config,
                        debug_mode=self.debug_mode,
                        redfish_session_config=tool_config.get(
                            "redfish_session_config", {}
                        ),
                        logger=self.logger,
                    )

                    # Initialize only the BaseboardManager, skip DUT connections
                    await self.dut_manager._initialize_baseboard_manager_only()

                except Exception as e:
                    await self.logger.log_runtime(
                        "WARNING",
                        "WorkflowOrchestrator",
                        f"BaseboardManager initialization failed in catalog mode: {e}",
                    )
                    self.dut_manager = None

                if not self.quiet_mode:
                    progress.update(
                        init_task,
                        description="Initialization complete",
                        completed=True,
                    )

                return

            # Step 3: Create DUT manager
            if not self.quiet_mode:
                progress.update(
                    init_task, description="Creating DUT manager...", advance=1
                )

            # Create DUT manager only if needed
            try:
                self.dut_manager_initialization_error = None
                uri_config_manager = self.config_manager.get_uri_config_manager()
                # Get spreadsheet configuration from config manager
                tool_config = self.config_manager.get_tool_config()
                spreadsheet_path, catalog_snapshot = _dut_manager_catalog_inputs(
                    self.config_manager, tool_config
                )
                self.dut_manager = DUTManager(
                    self.config_manager.get_dut_config(),
                    str(self.log_dir),
                    uri_config_manager,
                    spreadsheet_path=spreadsheet_path,
                    catalog_snapshot=catalog_snapshot,
                    sanitized_console=self.sanitized_console,
                    tool_config=tool_config,
                    debug_mode=self.debug_mode,
                    redfish_session_config=tool_config.get(
                        "redfish_session_config", {}
                    ),
                    logger=self.logger,
                )

                # Step 4: Initialize DUT manager (create DUTs and setup logging)
                if not self.quiet_mode:
                    progress.update(
                        init_task,
                        description="Initializing DUT manager...",
                        advance=1,
                    )
                await self.dut_manager.initialize()

                # Update execution and reporting engines with DUT manager
                self.execution_engine.dut_manager = self.dut_manager
                self.reporting_engine.dut_manager = self.dut_manager

                # Update dependency checker with DUT manager for remote command execution
                self.dependency_checker.set_dut_manager(self.dut_manager)

                # Update orchestrator reference in services after DUT manager is available
                self.config_manager.set_orchestrator(self)
            except Exception as e:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"DUT manager initialization failed: {e}",
                )
                self.dut_manager_initialization_error = e
                self.dut_manager = None
                # Catalog-only commands use the dedicated branch above. A
                # collection cannot continue without DUT state; preserving the
                # original exception avoids a later, misleading NoneType error.
                raise

            # Step 5: Setup DUTs and complete initialization
            if self.dut_manager:
                if not self.quiet_mode:
                    progress.update(
                        init_task, description="Setting up DUTs...", advance=1
                    )

                await self.logger.log_runtime(
                    "INFO", "WorkflowOrchestrator", "Setting up DUTs..."
                )

                # Start timing for DUT initialization
                if hasattr(self, "timing_manager") and self.timing_manager:
                    self.timing_manager.start_component("dut_initialization")

                await self.dut_manager.initialize_duts()

                # End timing for DUT initialization
                if hasattr(self, "timing_manager") and self.timing_manager:
                    self.timing_manager.end_component("dut_initialization")

                # Setup logging for each DUT
                for dut_id in self.dut_manager.get_all_dut_ids():
                    await self.logger.setup_dut_logging(dut_id)
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "WorkflowOrchestrator",
                        f"DUT {dut_id} initialized",
                    )

                    # Create config files and log signature for each DUT
                    try:
                        # Get DUT-specific configuration
                        dut_config = self.dut_manager.get_dut_config(dut_id)
                        tool_config = self.config_manager.get_tool_config()

                        # Create config files
                        await self.logger.create_config_files(
                            dut_id, tool_config, dut_config
                        )

                        # Create log signature with platform and baseboard info
                        platform = dut_config.get("platform", "unknown")
                        baseboard = dut_config.get("baseboard", "unknown")
                        await self.logger.create_log_signature(
                            dut_id, platform, baseboard
                        )

                        # Initialize all collector metadata upfront (like legacy code)
                        await self.logger.initialize_all_collector_metadata(dut_id)

                    except Exception as e:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "WorkflowOrchestrator",
                            f"Error creating config files: {e}",
                        )

                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "Orchestrator initialization completed",
                )

                # Skip dependency checking during initialization to avoid hangs with large numbers of DUTs
                # Dependency checking can be done later during preflight checks if needed
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Skipping dependency checking for {len(self.dut_manager.duts)} DUT(s) during initialization (will be done during preflight if needed)",
                )

                if not self.quiet_mode:
                    progress.update(
                        init_task,
                        description="Initialization complete",
                        completed=True,
                        advance=6,
                    )
            else:
                if not self.quiet_mode:
                    progress.update(
                        init_task,
                        description="Initialization complete (no DUT manager)",
                        completed=True,
                        advance=6,
                    )
        except ImportError:
            # Fallback to simple logging if Rich is not available
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Rich not available, using simple logging",
            )

            # Initialize async components
            await self.async_init()

            # Update console to use redirected stdout if available
            if hasattr(self.logger, "original_stdout") and self.logger.original_stdout:
                self.console = Console(file=self.logger.original_stdout)

            # Catalog-only commands initialize just enough state for filtering.
            if catalog_only_mode:
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "Catalog mode - initializing BaseboardManager for collector filtering",
                )

                # Create a minimal DUT manager with only BaseboardManager for collector filtering
                try:
                    uri_config_manager = self.config_manager.get_uri_config_manager()
                    tool_config = self.config_manager.get_tool_config()
                    spreadsheet_path, catalog_snapshot = _dut_manager_catalog_inputs(
                        self.config_manager, tool_config
                    )
                    self.dut_manager = DUTManager(
                        self.config_manager.get_dut_config(),
                        str(self.log_dir),
                        uri_config_manager,
                        spreadsheet_path=spreadsheet_path,
                        catalog_snapshot=catalog_snapshot,
                        sanitized_console=self.sanitized_console,
                        tool_config=tool_config,
                        debug_mode=self.debug_mode,
                        redfish_session_config=tool_config.get(
                            "redfish_session_config", {}
                        ),
                        logger=self.logger,
                    )

                    # Initialize only the BaseboardManager, skip DUT connections
                    await self.dut_manager._initialize_baseboard_manager_only()

                except Exception as e:
                    await self.logger.log_runtime(
                        "WARNING",
                        "WorkflowOrchestrator",
                        f"BaseboardManager initialization failed in catalog mode: {e}",
                    )
                    self.dut_manager = None

                return

            # Create DUT manager only if needed
            try:
                self.dut_manager_initialization_error = None
                uri_config_manager = self.config_manager.get_uri_config_manager()
                # Get spreadsheet configuration from config manager
                tool_config = self.config_manager.get_tool_config()
                spreadsheet_path, catalog_snapshot = _dut_manager_catalog_inputs(
                    self.config_manager, tool_config
                )
                self.dut_manager = DUTManager(
                    self.config_manager.get_dut_config(),
                    str(self.log_dir),
                    uri_config_manager,
                    spreadsheet_path=spreadsheet_path,
                    catalog_snapshot=catalog_snapshot,
                    sanitized_console=self.sanitized_console,
                    tool_config=tool_config,
                    debug_mode=self.debug_mode,
                    redfish_session_config=tool_config.get(
                        "redfish_session_config", {}
                    ),
                    logger=self.logger,
                )

                # Initialize DUT manager (create DUTs and setup logging)
                await self.dut_manager.initialize()

                # Update execution and reporting engines with DUT manager
                self.execution_engine.dut_manager = self.dut_manager
                self.reporting_engine.dut_manager = self.dut_manager

                # Update dependency checker with DUT manager for remote command execution
                self.dependency_checker.set_dut_manager(self.dut_manager)

                # Update orchestrator reference in services after DUT manager is available
                self.config_manager.set_orchestrator(self)
            except Exception as e:
                # For operations that don't need DUT manager (like listing collectors),
                # we can continue without it
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    f"DUT manager initialization failed: {e}",
                )
                self.dut_manager_initialization_error = e
                self.dut_manager = None

            if self.dut_manager:
                await self.logger.log_runtime(
                    "INFO", "WorkflowOrchestrator", "Setting up DUTs..."
                )

                # Start timing for DUT initialization
                if hasattr(self, "timing_manager") and self.timing_manager:
                    self.timing_manager.start_component("dut_initialization")

                await self.dut_manager.initialize_duts()

                # End timing for DUT initialization
                if hasattr(self, "timing_manager") and self.timing_manager:
                    self.timing_manager.end_component("dut_initialization")

                # Setup logging for each DUT
                for dut_id in self.dut_manager.get_all_dut_ids():
                    await self.logger.setup_dut_logging(dut_id)
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "WorkflowOrchestrator",
                        f"DUT {dut_id} initialized",
                    )

                    # Create config files and log signature for each DUT
                    try:
                        # Get DUT-specific configuration
                        dut_config = self.dut_manager.get_dut_config(dut_id)
                        tool_config = self.config_manager.get_tool_config()

                        # Create config files
                        await self.logger.create_config_files(
                            dut_id, tool_config, dut_config
                        )

                        # Create log signature with platform and baseboard info
                        platform = dut_config.get("platform", "unknown")
                        baseboard = dut_config.get("baseboard", "unknown")
                        await self.logger.create_log_signature(
                            dut_id, platform, baseboard
                        )

                        # Initialize all collector metadata upfront (like legacy code)
                        await self.logger.initialize_all_collector_metadata(dut_id)

                    except Exception as e:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "WorkflowOrchestrator",
                            f"Error creating config files: {e}",
                        )

                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "Orchestrator initialization completed",
                )

                # Skip dependency checking during initialization to avoid hangs with large numbers of DUTs
                # Dependency checking can be done later during preflight checks if needed
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Skipping dependency checking for {len(self.dut_manager.duts)} DUT(s) during initialization (will be done during preflight if needed)",
                )

    async def run_preflight_checks(
        self,
        collector_ids: Optional[List[str]] = None,
        show_progress: bool = True,
        collector_ids_per_dut: Optional[Dict[str, List[str]]] = None,
        service_candidates: Optional[List[str]] = None,
        preflight_label: str = "Preflight",
    ) -> Dict[str, Any]:
        """
        Run preflight checks on all DUTs with comprehensive logging.

        The implementation uses ``collector_ids``, ``show_progress``,
        ``collector_ids_per_dut``, ``service_candidates``, and
        ``preflight_label`` to run preflight checks on all DUTs with
        comprehensive logging. Terminal status is emitted only after preflight
        checks on all DUTs with comprehensive logging and its owned cleanup
        have completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            collector_ids: Optional collector identifiers; ``None`` selects the
                function's default behavior.
            show_progress: Whether show progress is enabled or required for this
                operation.
            collector_ids_per_dut: Optional collector identifiers per DUT;
                ``None`` selects the function's default behavior.
            service_candidates: Optional transport groups to probe instead of
                deriving them from collector identifiers. The DUT manager
                intersects these candidates with each DUT's configured
                endpoints.
            preflight_label: Operator-facing label which distinguishes the
                purpose of this preflight phase.

        Returns:
            A mapping containing run preflight checks.

        Raises:
            ValueError: If service candidates are combined with collector
                identifiers.
        """
        if not self.dut_manager:
            await self.logger.log_runtime(
                "ERROR", "WorkflowOrchestrator", "DUT manager not initialized"
            )
            return {"error": "DUT manager not initialized"}

        if service_candidates is not None and (
            collector_ids is not None or collector_ids_per_dut is not None
        ):
            raise ValueError(
                "service_candidates cannot be combined with collector identifiers"
            )

        # Start timing for preflight checks
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.start_component("preflight_checks")

        # Determine required collector groups from collector IDs. Explicit
        # service candidates bypass collector resolution and are filtered per
        # DUT by the manager below.
        required_collector_groups = (
            None
            if service_candidates is not None
            else self._get_collector_groups_from_ids(collector_ids)
        )
        required_collector_groups_per_dut = None
        if service_candidates is None and collector_ids_per_dut is not None:
            required_collector_groups_per_dut = {
                dut_id: (
                    self._get_collector_groups_from_ids(dut_collector_ids)
                    if dut_collector_ids
                    else []
                )
                for dut_id, dut_collector_ids in collector_ids_per_dut.items()
            }

        normalized_label = str(preflight_label).strip() or "Preflight"
        if service_candidates is None:
            scope_description = (
                f"collector groups: {required_collector_groups or 'all'}"
            )
        else:
            scope_description = f"candidate services: {service_candidates}"
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Starting {normalized_label.lower()} checks for {scope_description}",
        )

        collector_definitions = self.config_manager.get_collector_definitions()

        controller_options = {}
        if service_candidates is None:
            definitions = collector_definitions.get("collectors", collector_definitions)
            controllers_per_dut = {}
            for dut_id, dut in self.dut_manager.duts.items():
                selected = (
                    collector_ids_per_dut.get(dut_id, [])
                    if collector_ids_per_dut is not None
                    else collector_ids
                )
                if selected is None:
                    selected = definitions
                controllers = set()
                for collector_id in selected:
                    definition = definitions.get(collector_id, {})
                    if str(definition.get("group", "")).lower() == "redfish":
                        controllers.update(
                            collector_controllers(definition, dut.config)
                        )
                if "bmc" in controllers:
                    controllers_per_dut[dut_id] = controllers
            if controllers_per_dut:
                controller_options["redfish_controllers_per_dut"] = controllers_per_dut

        preflight_results = await self.dut_manager.run_preflight_checks(
            required_collector_groups,
            show_progress=show_progress,
            collector_definitions=collector_definitions,
            required_collector_groups_per_dut=required_collector_groups_per_dut,
            service_candidates=service_candidates,
            **controller_options,
        )

        # End timing for preflight checks
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.end_component("preflight_checks")

        # Log preflight results to metadata
        await self.reporting_engine.log_preflight_results(preflight_results)

        # Machine-readable commands must keep stdout reserved for their payload.
        if not getattr(self, "quiet_mode", False):
            await self.reporting_engine.log_preflight_results_table(
                preflight_results, preflight_label=normalized_label
            )

        # Log summary
        total_duts = len(preflight_results)
        passed_duts = sum(
            1 for r in preflight_results.values() if r.get("overall_status") == "pass"
        )
        failed_duts = sum(
            1 for r in preflight_results.values() if r.get("overall_status") == "fail"
        )

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Preflight checks completed: {passed_duts}/{total_duts} DUTs passed, {failed_duts} failed",
        )

        return preflight_results

    def _get_system_dump_capability_manager(
        self,
    ) -> SystemDumpCapabilityManager:
        """
        Return the run-scoped capability manager, including for legacy tests.

        The implementation uses current instance state to produce the run-scoped
        capability manager, including for legacy tests. It updates
        ``system_dump_capability_manager`` on the instance as part of that state
        transition.

        Returns:
            The validated ``manager``.
        """
        manager = getattr(self, "system_dump_capability_manager", None)
        if manager is None:
            manager = SystemDumpCapabilityManager(self)
            self.system_dump_capability_manager = manager
        return manager

    async def discover_system_dump_capabilities(
        self,
        dut_ids: Optional[List[str]] = None,
        preflight_results: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Populate live System Dump ActionInfo before collector filtering.

        The implementation uses ``dut_ids``, ``preflight_results``, and
        ``force`` to populate live System Dump ActionInfo before collector
        filtering. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_ids: Optional DUT identifiers; ``None`` selects the function's
                default behavior.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.
            force: Whether force is enabled or required for this operation.

        Returns:
            A mapping containing discover system dump capabilities.
        """
        if not self.dut_manager:
            return {}
        resolved_dut_ids = dut_ids or self.dut_manager.get_all_dut_ids()
        if not resolved_dut_ids:
            return {}
        return await self._get_system_dump_capability_manager().discover_many(
            resolved_dut_ids,
            preflight_results=preflight_results,
            force=force,
        )

    def collectors_require_system_dump_capabilities(
        self, collector_ids: List[str]
    ) -> bool:
        """
        Return whether selection/generation needs the live System Dump map.

        Device-derived diagnostic values (R35-R38 today) cannot declare a finite
        collector-level ``any_of`` list. They still need the cache so their
        fully rendered per-device payloads can be checked immediately before
        POST. Detect the execution shape as a future-proof fallback.

        Args:
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.

        Returns:
            Whether selection/generation needs the live System Dump map.
        """
        for collector_id in collector_ids:
            collector = self.config_manager.get_collector_info(collector_id) or {}
            requirement = collector.get("redfish_capability")
            if (
                isinstance(requirement, dict)
                and requirement.get("source") == "system_dump_action_info"
            ):
                return True

            # Device-derived diagnostic values (R35-R38 today) cannot declare a
            # finite collector-level ``any_of`` list.  They still need the cache so
            # their fully rendered per-device payloads can be checked immediately
            # before POST.  Detect the execution shape as a future-proof fallback.
            hooks = collector.get("stages", {}).get("execution", {}).get("hooks", [])
            for hook in hooks:
                if not isinstance(hook, dict):
                    continue
                method = hook.get("method")
                params = hook.get("params", {})
                if method in {
                    "collect_device_diagnostic_data",
                    "collect_system_dump_capabilities",
                }:
                    return True
                if (
                    method == "collect_diagnostic_data"
                    and isinstance(params, dict)
                    and params.get("entity_type") == "Systems"
                    and params.get("log_service") == "Dump"
                ):
                    return True
        return False

    def get_system_dump_capabilities(self, dut_id: str) -> Dict[str, Any]:
        """
        Return a defensive, serializable snapshot used by R46.

        After applying local validation, the function forwards ``dut_id`` to
        ``get`` and preserves its return and exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing system dump capabilities.
        """
        return self._get_system_dump_capability_manager().get(dut_id)

    def supports_system_dump_value(
        self, dut_id: str, value: str, system_id: Optional[str] = None
    ) -> Optional[bool]:
        """
        Return tri-state support for an exact OEMDiagnosticDataType value.

        After applying local validation, the function forwards ``dut_id``,
        ``value``, and ``system_id`` to ``supports`` and preserves its return
        and exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            value: Text supplied as value in the format accepted by this
                function.
            system_id: Stable system identifier used to correlate configuration,
                logs, and results.

        Returns:
            Whether the tri-state support for an exact OEMDiagnosticDataType
            value operation succeeds, or ``None`` when the decision is
            unavailable.
        """
        return self._get_system_dump_capability_manager().supports(
            dut_id, value, system_id=system_id
        )

    def filter_supported_system_dump_payloads(
        self,
        dut_id: str,
        payloads: List[Any],
        system_id: Optional[str] = None,
    ) -> List[Any]:
        """
        Filter known-unsupported payloads while preserving legacy unknowns.

        After applying local validation, the function forwards ``dut_id``,
        ``payloads``, and ``system_id`` to ``filter_payloads`` and preserves its
        return and exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            payloads: Entries supplied as ``payloads`` without transferring
                container ownership.
            system_id: Stable system identifier used to correlate configuration,
                logs, and results.

        Returns:
            The filter supported system dump payloads returned in
            operation-defined order.
        """
        return self._get_system_dump_capability_manager().filter_payloads(
            dut_id, payloads, system_id=system_id
        )

    async def run_dependency_checks(
        self,
        collector_ids: Optional[List[str]] = None,
        preflight_results: Optional[Dict[str, Any]] = None,
        filtered_collectors_per_dut: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, List[Dict[str, str]]]:
        """
        Run dependency checks for all collectors on all DUTs.

        The implementation uses ``collector_ids``, ``preflight_results``, and
        ``filtered_collectors_per_dut`` to run dependency checks for all
        collectors on all DUTs. Terminal status is emitted only after dependency
        checks for all collectors on all DUTs and its owned cleanup have
        completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            collector_ids: Optional collector identifiers; ``None`` selects the
                function's default behavior.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.
            filtered_collectors_per_dut: Optional filtered collectors per DUT;
                ``None`` selects the function's default behavior.

        Returns:
            A mapping containing run dependency checks.
        """
        if not self.dut_manager:
            await self.logger.log_runtime(
                "WARNING",
                "WorkflowOrchestrator",
                "DUT manager not initialized, skipping dependency checks",
            )
            return {}

        collector_definitions = self.config_manager.get_collector_definitions()
        if not collector_definitions:
            await self.logger.log_runtime(
                "WARNING",
                "WorkflowOrchestrator",
                "No collector definitions found, skipping dependency checks",
            )
            return {}

        collectors = collector_definitions.get("collectors", {})
        dut_ids = self.dut_manager.get_all_dut_ids()

        # Filter collectors if specific IDs provided
        if collector_ids:
            collectors = {
                cid: cinfo for cid, cinfo in collectors.items() if cid in collector_ids
            }

        # Build per-DUT filtered collector lists based on preflight results
        # Skip collectors whose service failed: S=ssh, I=ipmi, H=host, R=redfish
        dut_collectors_map = {}
        total_deps = 0

        for dut_id in dut_ids:
            if filtered_collectors_per_dut and dut_id in filtered_collectors_per_dut:
                dut_allowed = set(filtered_collectors_per_dut[dut_id])
                dut_collectors = {
                    cid: cinfo
                    for cid, cinfo in collectors.items()
                    if cid in dut_allowed
                }
            else:
                dut_collectors = collectors.copy()

            # Filter collectors for this specific DUT based on its preflight results
            if preflight_results:
                dut_preflight = preflight_results.get(dut_id, {})
                services = dut_preflight.get("services", {})
                prefixes_to_skip = set()

                # Check which services failed for THIS DUT and map to prefixes
                if services.get("ssh", {}).get("status") != "pass":
                    prefixes_to_skip.add("S")
                if services.get("ipmi", {}).get("status") != "pass":
                    prefixes_to_skip.add("I")
                if services.get("host", {}).get("status") != "pass":
                    prefixes_to_skip.add("H")
                # Filter out collectors with failed prefixes for THIS DUT
                if prefixes_to_skip:
                    dut_collectors = {
                        cid: cinfo
                        for cid, cinfo in dut_collectors.items()
                        if cid and cid[0].upper() not in prefixes_to_skip
                    }
                dut_config = self.dut_manager.get_dut_config(dut_id)
                dut_collectors = {
                    cid: cinfo
                    for cid, cinfo in dut_collectors.items()
                    if not cid.startswith("R")
                    or collector_preflight_result(
                        dut_preflight, "redfish", cinfo, dut_config
                    ).get("status")
                    == "pass"
                }

            # Store filtered collectors for this DUT
            dut_collectors_map[dut_id] = dut_collectors

            # Calculate per-DUT and total dependencies for progress bars
            dut_deps = 0
            for collector_info in dut_collectors.values():
                dependencies = collector_info.get("dependencies", {})
                required_deps = dependencies.get("required", [])
                dut_deps += len(required_deps)
            total_deps += dut_deps

        # Set up console for progress display
        if hasattr(self.logger, "original_stdout") and self.logger.original_stdout:
            console = Console(file=self.logger.original_stdout, force_terminal=True)
        else:
            console = Console(force_terminal=True)

        # Collect missing dependencies per DUT with progress bar
        dependency_results: Dict[str, List[Dict[str, str]]] = {}

        dep_progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10,
            transient=True,
            disable=getattr(self, "quiet_mode", False),
        )

        async def _check_deps_for_dut(
            dut_id: str,
            overall_task,
        ) -> tuple:
            """
            Check all dependencies for a single DUT.

            The implementation uses ``dut_id`` and ``overall_task`` to check all
            dependencies for a single DUT. Every required invariant is checked
            before a successful value is returned; invalid input follows the
            function's explicit exception path. Owned asynchronous work is
            awaited before return, so completion does not leave an unobserved
            task behind. Cleanup in the ``finally`` path runs for successful,
            failed, and cancelled execution.

            Args:
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.
                overall_task: Overall task consumed while the function attempts
                    to check all dependencies for a single DUT.

            Returns:
                A tuple containing ``DUT identifier`` and ``missing deps`` in
                that order.
            """
            missing_deps = []
            seen = set()
            dut = self.dut_manager.get_dut(dut_id)
            is_local_mode = False
            if dut and dut.config:
                is_local_mode = bool(dut.config.get("local", False))

            if dut_id not in dut_collectors_map:
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    f"DUT '{dut_id}' not found in dependency collectors map; "
                    f"skipping dependency checks for this DUT",
                )
            dut_collectors = dut_collectors_map.get(dut_id, {})

            for collector_id, collector_info in dut_collectors.items():
                dependencies = collector_info.get("dependencies", {})
                required_deps = dependencies.get("required", [])
                collector_name = collector_info.get("name", "unknown")

                if not required_deps:
                    continue

                for dep in required_deps:
                    if isinstance(dep, str):
                        dep_name = dep
                        dep_type = "command"
                    else:
                        dep_name = dep.get("name", "unknown")
                        dep_type = dep.get("type", "command")

                    # Determine check target
                    if is_local_mode or collector_id.startswith("I"):
                        target = "local"
                    elif collector_id.startswith("S"):
                        target = "BMC"
                    elif collector_id.startswith("H"):
                        target = "Host"
                    else:
                        target = "local"

                    try:
                        if dep_type == "command":
                            check_local = (
                                dep.get("check_local", False)
                                if isinstance(dep, dict)
                                else False
                            )
                            if isinstance(dep, dict) and (
                                "alternatives" in dep or "use_sudo" in dep
                            ):
                                result = await self.dependency_checker.check_command_requirement(
                                    dep,
                                    dut_id=dut_id,
                                    use_bmc=collector_id.startswith("S"),
                                    check_local=check_local
                                    or collector_id.startswith("I"),
                                )
                            elif (
                                check_local
                                or collector_id.startswith("I")
                                or is_local_mode
                            ):
                                result = self.dependency_checker.check_command(
                                    dep_name, check_local=True
                                )
                            elif (
                                dut_id
                                and self.dependency_checker.dut_manager
                                and not is_local_mode
                            ):
                                use_bmc = collector_id.startswith("S")
                                result = (
                                    await self.dependency_checker._check_command_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                            else:
                                result = self.dependency_checker.check_command(dep_name)
                        elif dep_type == "service":
                            if is_local_mode:
                                result = self.dependency_checker.check_service(dep_name)
                            elif dut_id and self.dependency_checker.dut_manager:
                                use_bmc = collector_id.startswith("S")
                                result = (
                                    await self.dependency_checker._check_service_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                            else:
                                result = self.dependency_checker.check_service(dep_name)
                        elif dep_type == "file":
                            if (
                                dut_id
                                and self.dependency_checker.dut_manager
                                and not is_local_mode
                            ):
                                use_bmc = collector_id.startswith("S")
                                result = (
                                    await self.dependency_checker._check_file_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                            else:
                                result = self.dependency_checker.check_file(dep_name)
                        elif dep_type == "platform_service":
                            dep_config = (
                                dep if isinstance(dep, dict) else {"name": dep_name}
                            )
                            result = (
                                await self.dependency_checker.check_platform_service(
                                    dep_config, "default", dut_id
                                )
                            )
                        else:
                            continue

                        if not result.available:
                            dedup_key = (dep_name, dep_type, collector_id)
                            if dedup_key not in seen:
                                seen.add(dedup_key)
                                missing_deps.append(
                                    {
                                        "dependency": dep_name,
                                        "type": dep_type,
                                        "collector_id": collector_id,
                                        "collector_name": collector_name,
                                        "target": target,
                                        "status": (
                                            "error"
                                            if getattr(result, "probe_failed", False)
                                            is True
                                            else "unavailable"
                                        ),
                                        "reason": result.error_message or "",
                                    }
                                )

                    except Exception as e:
                        await self.logger.log_runtime(
                            "DEBUG",
                            "WorkflowOrchestrator",
                            f"Error checking dependency {dep_name} on {dut_id}: {e}",
                        )
                        dedup_key = (dep_name, dep_type, collector_id)
                        if dedup_key not in seen:
                            seen.add(dedup_key)
                            missing_deps.append(
                                {
                                    "dependency": dep_name,
                                    "type": dep_type,
                                    "collector_id": collector_id,
                                    "collector_name": collector_name,
                                    "target": target,
                                    "status": "error",
                                    "reason": f"Dependency probe failed: {e}",
                                }
                            )

                    finally:
                        dep_progress.advance(overall_task)

            missing_deps.sort(
                key=lambda d: (d["target"], d["dependency"], d["collector_id"])
            )
            return dut_id, missing_deps

        with dep_progress:
            overall_task = dep_progress.add_task(
                f"[cyan]Dependency Checks ({len(dut_ids)} DUTs, {total_deps} dependencies)",
                total=total_deps,
            )

            all_coros = [
                _check_deps_for_dut(dut_id, overall_task) for dut_id in dut_ids
            ]
            all_results = await asyncio.gather(*all_coros, return_exceptions=True)
            for result in all_results:
                if isinstance(result, Exception):
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"Dependency check failed: {result}",
                    )
                else:
                    dut_id, missing = result
                    dependency_results[dut_id] = missing

        return dependency_results

    async def generate_html_reports(
        self,
        total_runtime: Optional[float] = None,
        collector_ids: Optional[List[str]] = None,
        finalization_receipt: Optional[FinalizationReceipt] = None,
        enforce_snapshot_consistency: bool = True,
    ) -> bool:
        # Start timing for HTML report generation
        """
        Generate HTML reports.

        Check if shutdown was requested - if so, skip HTML report generation.

        Args:
            total_runtime: Optional total runtime; ``None`` selects the
                function's default behavior.
            collector_ids: Optional collector identifiers; ``None`` selects the
                function's default behavior.
            finalization_receipt: Optional finalization receipt; ``None``
                selects the function's default behavior.
            enforce_snapshot_consistency: Whether enforce snapshot consistency
                is enabled or required for this operation.

        Returns:
            Whether the generate HTML reports operation succeeds.
        """
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.start_component("html_report_generation")
        """
        Generate HTML reports from collection results

        Args:
            total_runtime: Total runtime of the collection process

        Returns:
            bool: True if reports were generated successfully
        """
        try:
            # Check if shutdown was requested - if so, skip HTML report generation
            if self.is_shutdown_requested():
                await self.logger.log_runtime(
                    "WARN",
                    "WorkflowOrchestrator",
                    "Shutdown requested, skipping HTML report generation",
                )
                self.sanitized_console.print_warning("Skipping HTML report generation")
                return False

            # Check if HTML reports are enabled in configuration
            tool_config = self.config_manager.get_tool_config()
            generate_html = (
                tool_config.get("GENERATE_HTML_REPORTS", True)
                if isinstance(tool_config, dict)
                else getattr(tool_config, "GENERATE_HTML_REPORTS", True)
            )

            if not generate_html:
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "HTML report generation disabled in configuration",
                )
                return True

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Starting HTML report generation...",
            )
            self.sanitized_console.print_info("Starting HTML report generation...")

            # Initialize HTML report service
            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                "Creating HTML report service...",
            )
            html_service_kwargs: Dict[str, Any] = {}
            if not enforce_snapshot_consistency:
                html_service_kwargs["enforce_snapshot_consistency"] = False
            html_service = await HTMLReportService.create(
                self.log_dir,
                total_runtime,
                self.logger,
                self,
                collector_ids,
                finalization_receipt,
                **html_service_kwargs,
            )
            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                "HTML report service created successfully",
            )

            # Create progress bar for HTML report generation
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=self.console,
                transient=False,
            ) as progress:
                # Add main task for HTML report generation
                main_task = progress.add_task("Generating HTML reports...", total=100)

                # Generate reports with progress updates
                success = await html_service.generate_reports_with_progress(
                    progress, main_task
                )

            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                f"html_service.generate_reports() returned: {success}",
            )

            if success:
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"HTML reports generated successfully in {self.log_dir}/reports",
                )
                self.sanitized_console.print_success(
                    f"HTML reports generated in {self.log_dir}/reports"
                )
            else:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    "Failed to generate HTML reports",
                )
                self.sanitized_console.print_error("Failed to generate HTML reports")

            # End timing for HTML report generation
            if hasattr(self, "timing_manager") and self.timing_manager:
                self.timing_manager.end_component("html_report_generation")

            return success

        except (asyncio.CancelledError, KeyboardInterrupt, SystemExit):
            # Process control must reach the terminal owner so it can be
            # classified, receipt-bound, and mapped to the correct exit code.
            raise
        except Exception:
            pass

        failure_message = "HTML report generation failed."
        try:
            await self.logger.log_runtime(
                "ERROR",
                "WorkflowOrchestrator",
                failure_message,
            )
        except Exception:
            pass
        try:
            self.sanitized_console.print_error(failure_message)
        except Exception:
            pass
        return False

    async def _generate_spa_report(
        self,
        finalization_receipt: Optional[FinalizationReceipt] = None,
        enforce_snapshot_consistency: bool = True,
    ) -> bool:
        """
        Generate SPA report using ManifestService.

        The report root is caller-owned and must not redirect report generation
        (or its diagnostics) through a directory symlink.

        Args:
            finalization_receipt: Optional finalization receipt; ``None``
                selects the function's default behavior.
            enforce_snapshot_consistency: Whether enforce snapshot consistency
                is enabled or required for this operation.

        Returns:
            Whether the generate SPA report using ManifestService operation
            succeeds.
        """
        log_dir_stat: Optional[os.stat_result] = None
        progress = SanitizedOperationProgress(
            self.sanitized_console,
            "Generating SPA report",
        )
        try:
            from ..services.manifest_service import ManifestService

            # The report root is caller-owned and must not redirect report
            # generation (or its diagnostics) through a directory symlink.
            try:
                log_dir_stat = self.log_dir.lstat()
            except OSError:
                log_dir_stat = None
            if log_dir_stat is None or not stat.S_ISDIR(log_dir_stat.st_mode):
                self.sanitized_console.print_error(SPA_REPORT_DESTINATION_FAILURE)
                return False

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Starting SPA report generation...",
            )
            self.sanitized_console.print_info("Starting SPA report generation...")
            progress.start()
            progress.update("Validating SPA report assets", 0, 4)

            # A manifest alone is not a usable SPA report. Require the SPA entry
            # point without following a link outside the packaged asset tree.
            spa_dist_dir = Path(__file__).parent.parent / "report_app_dist"
            source_index = spa_dist_dir / "index.html"
            try:
                spa_dist_stat = spa_dist_dir.lstat()
                source_index_stat = source_index.lstat()
            except OSError:
                spa_dist_stat = None
                source_index_stat = None
            if (
                spa_dist_stat is None
                or not stat.S_ISDIR(spa_dist_stat.st_mode)
                or source_index_stat is None
                or not stat.S_ISREG(source_index_stat.st_mode)
            ):
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    SPA_REPORT_ASSET_FAILURE,
                )
                self.sanitized_console.print_warning(SPA_REPORT_ASSET_FAILURE)
                return False

            try:
                source_digest = validate_report_app_index(source_index)
            except ReportAppAssetError as error:
                failure_message = spa_report_asset_failure_message(error)
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    failure_message,
                )
                self.sanitized_console.print_warning(failure_message)
                return False

            progress.update("Preparing SPA report destination", 1, 4)

            report_dir = self.log_dir / "reports"
            expected_index = report_dir / "index.html"
            try:
                report_dir_stat = report_dir.lstat()
            except FileNotFoundError:
                report_dir_stat = None
            except OSError:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    SPA_REPORT_DESTINATION_FAILURE,
                )
                self.sanitized_console.print_error(SPA_REPORT_DESTINATION_FAILURE)
                return False
            if report_dir_stat is not None and not stat.S_ISDIR(
                report_dir_stat.st_mode
            ):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    SPA_REPORT_DESTINATION_FAILURE,
                )
                self.sanitized_console.print_error(SPA_REPORT_DESTINATION_FAILURE)
                return False

            try:
                destination_index_mode = expected_index.lstat().st_mode
            except FileNotFoundError:
                destination_index_mode = None
            except OSError:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    SPA_REPORT_DESTINATION_FAILURE,
                )
                self.sanitized_console.print_error(SPA_REPORT_DESTINATION_FAILURE)
                return False
            if destination_index_mode is not None and not stat.S_ISREG(
                destination_index_mode
            ):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    SPA_REPORT_DESTINATION_FAILURE,
                )
                self.sanitized_console.print_error(SPA_REPORT_DESTINATION_FAILURE)
                return False

            manifest_kwargs: Dict[str, Any] = {
                "finalization_receipt": finalization_receipt,
                "max_auxiliary_json_files": self.get_finalization_runtime_boundaries()[
                    "finalization_manifest_max_auxiliary_json_files"
                ],
            }
            if not enforce_snapshot_consistency:
                manifest_kwargs["enforce_snapshot_consistency"] = False
            service = ManifestService(
                self.log_dir,
                spa_dist_dir,
                **manifest_kwargs,
            )
            progress.update("Building SPA report", 2, 4)
            # ManifestService pins the report directory and revalidates its
            # descriptor immediately before committing. The surrounding
            # lstat snapshots are diagnostic drift evidence only; they do not
            # replace or weaken that write-time publication lock.
            result = await service.generate_report(report_dir)
            progress.update("Verifying SPA report", 3, 4)

            try:
                current_log_dir_stat = self.log_dir.lstat()
            except OSError:
                current_log_dir_stat = None
            if (
                current_log_dir_stat is None
                or not stat.S_ISDIR(current_log_dir_stat.st_mode)
                or _directory_identity(current_log_dir_stat)
                != _directory_identity(log_dir_stat)
            ):
                self.sanitized_console.print_error(SPA_REPORT_DESTINATION_FAILURE)
                return False

            # Reject attacker-controlled path-like/equality hooks before they
            # can run, then verify both roots and the source entry stayed put.
            if type(result) is not type(expected_index) or result != expected_index:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    SPA_REPORT_OUTPUT_FAILURE,
                )
                self.sanitized_console.print_error(SPA_REPORT_OUTPUT_FAILURE)
                return False

            try:
                current_spa_dist_stat = spa_dist_dir.lstat()
                current_source_index_stat = source_index.lstat()
            except OSError:
                current_spa_dist_stat = None
                current_source_index_stat = None
            if (
                current_spa_dist_stat is None
                or not stat.S_ISDIR(current_spa_dist_stat.st_mode)
                or _directory_identity(current_spa_dist_stat)
                != _directory_identity(spa_dist_stat)
                or current_source_index_stat is None
                or not stat.S_ISREG(current_source_index_stat.st_mode)
                or _path_identity(current_source_index_stat)
                != _path_identity(source_index_stat)
            ):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    SPA_REPORT_ASSET_FAILURE,
                )
                self.sanitized_console.print_error(SPA_REPORT_ASSET_FAILURE)
                return False

            try:
                current_source_digest = validate_report_app_index(source_index)
                generated_digest = validate_report_app_index(
                    expected_index,
                    trusted_source_digest=source_digest,
                )
            except ReportAppAssetError as error:
                failure_message = spa_report_asset_failure_message(error)
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    failure_message,
                )
                self.sanitized_console.print_error(failure_message)
                return False
            if not (
                hmac.compare_digest(source_digest, current_source_digest)
                and hmac.compare_digest(source_digest, generated_digest)
            ):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    SPA_REPORT_ASSET_FAILURE,
                )
                self.sanitized_console.print_error(SPA_REPORT_ASSET_FAILURE)
                return False

            try:
                generated_report_dir_stat = report_dir.lstat()
                generated_index_mode = expected_index.lstat().st_mode
            except OSError:
                generated_report_dir_stat = None
                generated_index_mode = None
            if (
                generated_report_dir_stat is None
                or not stat.S_ISDIR(generated_report_dir_stat.st_mode)
                or (
                    report_dir_stat is not None
                    and _directory_identity(generated_report_dir_stat)
                    != _directory_identity(report_dir_stat)
                )
                or generated_index_mode is None
                or not stat.S_ISREG(generated_index_mode)
            ):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    SPA_REPORT_OUTPUT_FAILURE,
                )
                self.sanitized_console.print_error(SPA_REPORT_OUTPUT_FAILURE)
                return False

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                SPA_REPORT_GENERATION_SUCCESS,
            )
            self.sanitized_console.print_success(SPA_REPORT_GENERATION_SUCCESS)
            progress.complete("SPA report generated")
            return True

        except Exception:
            try:
                current_log_dir_stat = self.log_dir.lstat()
            except OSError:
                current_log_dir_stat = None
            if (
                log_dir_stat is not None
                and current_log_dir_stat is not None
                and stat.S_ISDIR(current_log_dir_stat.st_mode)
                and _directory_identity(current_log_dir_stat)
                == _directory_identity(log_dir_stat)
            ):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    SPA_REPORT_GENERATION_FAILURE,
                )
            self.sanitized_console.print_error(SPA_REPORT_GENERATION_FAILURE)
            return False
        finally:
            progress.stop()

    async def _generate_openbmc_coredump_handoff(self) -> bool:
        """
        Create a metadata-only manual handoff before archive creation.

        Enrichment is deliberately fail-safe: it must not change collector
        status or prevent preservation of the original core artifacts.

        Returns:
            Whether the metadata-only manual handoff before archive creation
            operation succeeds.
        """
        discovery_error: Optional[Exception] = None
        try:
            from ..services.openbmc_coredump_manifest import (
                OpenBMCCoreDumpManifestService,
            )

            service = OpenBMCCoreDumpManifestService(self.log_dir)
            try:
                payload = await run_managed_filesystem_operation(service.generate)
            except Exception as exc:
                discovery_error = exc
                payload = service.unavailable_payload(f"{type(exc).__name__}: {exc}")
            output_path = await run_managed_filesystem_operation(
                service.write,
                None,
                payload,
            )
            summary = payload["summary"]
        except Exception as exc:
            try:
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    "Unable to generate OpenBMC core-dump handoff; collected "
                    f"artifacts remain unchanged: {exc}",
                )
            except Exception:
                logger.warning(
                    "Unable to generate or runtime-log the OpenBMC core-dump "
                    "handoff; collected artifacts remain unchanged",
                    exc_info=True,
                )
            return False

        try:
            if discovery_error is not None:
                await self.logger.log_runtime(
                    "WARNING",
                    "WorkflowOrchestrator",
                    "OpenBMC core-dump discovery was unavailable, so an "
                    f"explicit incomplete handoff was written at {output_path}; "
                    "collected artifacts remain unchanged: "
                    f"{type(discovery_error).__name__}: {discovery_error}",
                )
            else:
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "OpenBMC core-dump manual handoff generated at "
                    f"{output_path}: {summary['core_dump_count']} core dump(s), "
                    f"{summary['analyzer_ready_count']} analyzer-ready; "
                    "the handoff performed no analyzer upload",
                )
        except Exception:
            logger.warning(
                "OpenBMC core-dump handoff was generated, but its runtime "
                "status message could not be written",
                exc_info=True,
            )
        return discovery_error is None

    def _get_collector_groups_from_ids(
        self, collector_ids: Optional[List[str]] = None
    ) -> Optional[List[str]]:
        """
        Determine collector groups from collector IDs.

        The implementation uses ``collector_ids`` to determine collector groups
        from collector IDs.

        Args:
            collector_ids: Optional collector identifiers; ``None`` selects the
                function's default behavior.

        Returns:
            The collector groups from identifiers returned in operation-defined
            order, or ``None`` when the requested value is unavailable.
        """
        if not collector_ids:
            return None  # Check all services

        collector_groups = set()

        for collector_id in collector_ids:
            collector_info = self.config_manager.get_collector_info(collector_id)
            group = collector_info.get("group", "").lower()

            if group:
                collector_groups.add(group)

        return list(collector_groups) if collector_groups else None

    async def gather_platform_info(
        self,
        dut_ids: Optional[List[str]] = None,
        preflight_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, str]]:
        """
        Gather platform information from DUTs.

        The implementation uses ``dut_ids`` and ``preflight_results`` to gather
        platform information from DUTs. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_ids: Optional DUT identifiers; ``None`` selects the function's
                default behavior.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing gather platform info.
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            "gather_platform_info method called",
        )

        if not self.dut_manager:
            await self.logger.log_runtime(
                "ERROR", "WorkflowOrchestrator", "DUT manager not initialized"
            )
            return {}

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            "Starting platform information gathering...",
        )

        # Get all DUTs if none specified
        if not dut_ids:
            dut_ids = self.dut_manager.get_all_dut_ids()

        platform_results = {}

        # Show progress bar for platform information gathering
        total_duts = len(dut_ids)
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Gathering platform information for {total_duts} DUT(s) concurrently...",
        )

        # Create progress display using existing console
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )

        async def gather_platform_info_for_dut(dut_id: str, progress_task) -> tuple:
            """
            Gather platform info for a single DUT.

            The implementation uses ``dut_id`` and ``progress_task`` to gather
            platform info for a single DUT. Owned asynchronous work is awaited
            before return, so completion does not leave an unobserved task
            behind.

            Args:
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.
                progress_task: Progress task consumed while the function
                    attempts to gather platform info for a single DUT.

            Returns:
                A tuple containing ``DUT identifier`` and ``gather platform info
                for DUT value 2`` in that order.
            """
            try:
                # Check for shutdown request
                if self.is_shutdown_requested():
                    await self.logger.log_runtime(
                        "WARN",
                        "WorkflowOrchestrator",
                        f"Shutdown requested, skipping platform info gathering for DUT {dut_id}",
                    )
                    return dut_id, {}

                progress.update(
                    progress_task,
                    description=f"Gathering platform info for {dut_id}",
                )

                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Gathering platform info for DUT: {dut_id}",
                )

                # Get preflight results for this specific DUT
                dut_preflight_results = None
                if preflight_results and dut_id in preflight_results:
                    dut_preflight_results = preflight_results[dut_id].get(
                        "services", {}
                    )

                platform_info = await self.dut_manager.gather_platform_info(
                    dut_id, dut_preflight_results
                )

                # Log platform info to DUT runtime
                model = platform_info.get("model", "Unknown")
                partnumber = platform_info.get("partnumber", "Unknown")
                serialnumber = platform_info.get("serialnumber", "Unknown")

                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "PlatformDetection",
                    f"Identified system as Model: {model}, PartNo: {partnumber}, SerialNo: {serialnumber}",
                )

                # Store in metadata
                await self.logger.write_dut_metadata(
                    dut_id,
                    {
                        "PlatformModel": model,
                        "PartNumber": partnumber,
                        "SerialNumber": serialnumber,
                        "DUT_ID": dut_id,
                    },
                )

                return dut_id, platform_info

            except Exception as e:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Failed to gather platform info for DUT {dut_id}: {str(e)}",
                )
                return dut_id, {
                    "model": "Unknown",
                    "partnumber": "Unknown",
                    "serialnumber": "Unknown",
                }

        with progress:
            task = progress.add_task("Gathering platform information", total=total_duts)

            # Run platform info gathering concurrently for all DUTs
            all_tasks = [
                gather_platform_info_for_dut(dut_id, task) for dut_id in dut_ids
            ]
            all_results = await asyncio.gather(*all_tasks, return_exceptions=True)

            results = []
            for j, result in enumerate(all_results):
                if isinstance(result, Exception):
                    dut_id = dut_ids[j]
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"Failed to gather platform info for DUT {dut_id}: {str(result)}",
                    )
                    results.append(
                        (
                            dut_id,
                            {
                                "model": "Unknown",
                                "partnumber": "Unknown",
                                "serialnumber": "Unknown",
                            },
                        )
                    )
                else:
                    results.append(result)

                progress.update(task, advance=1)

            # Process results and update progress
            for i, result in enumerate(results):
                if isinstance(result, Exception):  # pragma: no cover
                    # Handle any exceptions that weren't caught
                    dut_id = dut_ids[i]
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"Unexpected error gathering platform info for DUT {dut_id}: {str(result)}",
                    )
                    platform_results[dut_id] = {
                        "model": "Unknown",
                        "partnumber": "Unknown",
                        "serialnumber": "Unknown",
                    }
                else:
                    dut_id, platform_info = result
                    platform_results[dut_id] = platform_info

                # Update progress
                progress.advance(task)

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Platform information gathering completed for {len(platform_results)} DUTs",
        )

        return platform_results

    async def _check_firmware_inventory_needed(
        self, collector_ids: List[str], dut_ids: List[str]
    ) -> bool:
        """
        Check if any filtered collectors require firmware inventory discovery.

        Analyzes collector definitions to see if they have
        use_firmware_inventory parameters and if any target DUT's baseboard
        requires firmware inventory.

        Args:
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.

        Returns:
            Whether the if any filtered collectors require firmware inventory
            discovery operation succeeds.
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"Checking if firmware inventory is needed for collectors: {collector_ids}",
        )

        for collector_id in collector_ids:
            collector_info = self.get_collector_info(collector_id)
            if not collector_info:
                continue

            # Check validation stage hooks for use_firmware_inventory parameter
            stages = collector_info.get("stages", {})
            validation_hooks = stages.get("validation", {}).get("hooks", [])

            for hook in validation_hooks:
                params = hook.get("params", {})
                use_firmware_inventory = params.get("use_firmware_inventory")

                if use_firmware_inventory:
                    # Check if any DUT's baseboard requires firmware inventory
                    for dut_id in dut_ids:
                        dut = self.dut_manager.get_dut(dut_id)
                        baseboard = dut.config.get("baseboard")

                        if baseboard:
                            # Check if this baseboard needs firmware inventory
                            if isinstance(use_firmware_inventory, dict):
                                needs_it = use_firmware_inventory.get(
                                    baseboard
                                ) or use_firmware_inventory.get("default", False)
                                if needs_it:
                                    await self.logger.log_runtime(
                                        "INFO",
                                        "WorkflowOrchestrator",
                                        f"Collector {collector_id} requires firmware inventory for baseboard {baseboard}",
                                    )
                                    return True
                            elif use_firmware_inventory is True:
                                # Simple boolean True means always needed
                                await self.logger.log_runtime(
                                    "INFO",
                                    "WorkflowOrchestrator",
                                    f"Collector {collector_id} requires firmware inventory (always enabled)",
                                )
                                return True

        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            "No collectors require firmware inventory discovery",
        )
        return False

    async def run_dynamic_discovery(
        self,
        dut_ids: Optional[List[str]] = None,
        preflight_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Run dynamic discovery for Redfish resources on DUTs.

        The implementation uses ``dut_ids`` and ``preflight_results`` to run
        dynamic discovery for Redfish resources on DUTs. Terminal status is
        emitted only after dynamic discovery for Redfish resources on DUTs and
        its owned cleanup have completed. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_ids: Optional DUT identifiers; ``None`` selects the function's
                default behavior.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing run dynamic discovery.
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            "run_dynamic_discovery method called",
        )

        if not self.dut_manager:
            await self.logger.log_runtime(
                "ERROR", "WorkflowOrchestrator", "DUT manager not initialized"
            )
            return {}

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            "Starting Redfish dynamic discovery...",
        )

        # Get all DUTs if none specified
        if not dut_ids:
            dut_ids = self.dut_manager.get_all_dut_ids()

        discovery_results = {}

        # Show progress bar for dynamic discovery
        total_duts = len(dut_ids)
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Running Redfish dynamic discovery for {total_duts} DUT(s) concurrently...",
        )

        # Create progress display using existing console
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )

        async def run_dynamic_discovery_for_dut(dut_id: str, progress_task) -> tuple:
            """
            Run dynamic discovery for a single DUT.

            The implementation uses ``dut_id`` and ``progress_task`` to run
            dynamic discovery for a single DUT. Terminal status is emitted only
            after dynamic discovery for a single DUT and its owned cleanup have
            completed. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind.

            Args:
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.
                progress_task: Progress task consumed while the function
                    attempts to run dynamic discovery for a single DUT.

            Returns:
                A tuple containing ``DUT identifier`` and ``run dynamic
                discovery for DUT value 2`` in that order.
            """
            try:
                # Check for shutdown request
                if self.is_shutdown_requested():
                    await self.logger.log_runtime(
                        "WARN",
                        "WorkflowOrchestrator",
                        f"Shutdown requested, skipping resource discovery for DUT {dut_id}",
                    )
                    return dut_id, {}

                progress.update(
                    progress_task,
                    description=f"Discovering resources for {dut_id}",
                )

                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Running dynamic discovery for DUT: {dut_id}",
                )

                # Get preflight results for this specific DUT
                dut_preflight_results = None
                if preflight_results and dut_id in preflight_results:
                    dut_preflight_results = preflight_results[dut_id].get(
                        "services", {}
                    )

                discovery_result = await self.dut_manager.run_dynamic_discovery(
                    dut_id, dut_preflight_results
                )

                if discovery_result.get("success"):
                    total_resources = discovery_result.get("metadata", {}).get(
                        "total_resources", 0
                    )
                    discovered_resources = discovery_result.get(
                        "discovered_resources", {}
                    )

                    # Categorize resources for better logging
                    collections = []
                    singleton_services = []

                    for (
                        resource_name,
                        resource_data,
                    ) in discovered_resources.items():
                        if resource_data.get("success", False):
                            members = resource_data.get("members", [])
                            if len(members) == 1 and members[0] == resource_name:
                                # This is likely a singleton service
                                singleton_services.append(resource_name)
                            else:
                                # This is a collection with multiple members
                                collections.append(f"{resource_name}({len(members)})")
                        else:
                            # Failed discovery
                            collections.append(f"{resource_name}(failed)")

                    # Log detailed summary
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "DynamicDiscovery",
                        f"Dynamic discovery completed - found {total_resources} total resources",
                    )

                    if collections:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "DynamicDiscovery",
                            f"Collections discovered: {', '.join(collections)}",
                        )

                    if singleton_services:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "DynamicDiscovery",
                            f"Singleton services discovered: {', '.join(singleton_services)} (metadata preserved)",
                        )

                    # Persist only the structured discovery summary. Raw Redfish
                    # member documents remain available in the discovery
                    # service's runtime result/detail cache. Arbitrary
                    # device-controlled mapping keys cannot safely cross into
                    # distributable structured metadata because they can
                    # collide with the fail-closed sanitizer policy.
                    await self.logger.write_dut_metadata(
                        dut_id,
                        {
                            "DynamicDiscovery": {
                                "success": True,
                                "total_resources": total_resources,
                                "discovered_resources": discovered_resources,
                                "timestamp": discovery_result.get("metadata", {}).get(
                                    "discovery_timestamp"
                                ),
                            }
                        },
                    )
                else:
                    error_msg = discovery_result.get("error", "Unknown error")
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "DynamicDiscovery",
                        f"Dynamic discovery failed: {error_msg}",
                    )

                    # Store failure in metadata
                    await self.logger.write_dut_metadata(
                        dut_id,
                        {
                            "DynamicDiscovery": {
                                "success": False,
                                "error": error_msg,
                                "timestamp": datetime.now().isoformat(),
                            }
                        },
                    )

                return dut_id, discovery_result

            except Exception as e:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Failed to run dynamic discovery for DUT {dut_id}: {str(e)}",
                )
                return dut_id, {"success": False, "error": str(e)}

        with progress:
            task = progress.add_task(
                "Running Redfish dynamic discovery", total=total_duts
            )

            # Run dynamic discovery concurrently for all DUTs
            all_tasks = [
                run_dynamic_discovery_for_dut(dut_id, task) for dut_id in dut_ids
            ]
            all_results = await asyncio.gather(*all_tasks, return_exceptions=True)

            for j, result in enumerate(all_results):
                if isinstance(result, Exception):
                    dut_id = dut_ids[j]
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"Failed to run dynamic discovery for DUT {dut_id}: {str(result)}",
                    )
                    discovery_results[dut_id] = {
                        "success": False,
                        "error": str(result),
                    }
                else:
                    dut_id, discovery_result = result
                    discovery_results[dut_id] = discovery_result

                progress.advance(task)

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            "Redfish dynamic discovery completed",
        )

        return discovery_results

    async def execute_collectors(
        self,
        filtered_collectors_per_dut: Dict[str, List[str]],
        skipped_collectors_per_dut: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        collection_level: str = "L1",
        original_collector_ids: Optional[List[str]] = None,
        preflight_results: Optional[Dict[str, Any]] = None,
        explicit_collector_pairs: Optional[Set[tuple[str, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Execute an upstream per-DUT plan through preflight and collection.

        Filtering and autodetection are owned by ``run_collection`` or an
        equivalent planning caller. This boundary refreshes live capabilities
        where needed and preserves the supplied selection instead of creating
        an implicit all-collector plan. An empty mapping remains an explicit
        empty selection.

        Args:
            filtered_collectors_per_dut: Already-selected collector identifiers
                for each DUT. A mapping is required; pass an empty mapping for
                an empty selection.
            skipped_collectors_per_dut: Optional skipped collectors per DUT;
                ``None`` selects the function's default behavior.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            original_collector_ids: Optional original collector identifiers;
                ``None`` selects the function's default behavior.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.
            explicit_collector_pairs: Optional DUT and collector identities
                selected by an explicit positive selector. These identities may
                require a compatibility summary row even when applicability
                filtering prevents execution.

        Returns:
            A mapping containing execute collectors.

        Raises:
            ValueError: If the caller supplies ``None`` instead of a per-DUT
                plan; no capability discovery or collector work is started.
        """
        if filtered_collectors_per_dut is None:
            raise ValueError("Collector execution requires a per-DUT plan")

        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.start_component("collector_execution")

        if not self.dut_manager:
            await self.logger.log_runtime(
                "ERROR", "WorkflowOrchestrator", "DUT manager not initialized"
            )
            return {"error": "DUT manager not initialized"}

        dut_ids = self.dut_manager.get_all_dut_ids()
        explicit_collector_pairs = {
            (str(dut_id), str(collector_id))
            for dut_id, collector_id in (explicit_collector_pairs or set())
        }

        # Lifecycle authorization and scheduler evidence are scoped to exactly
        # one collection invocation. Reusing an orchestrator must never carry
        # verified capabilities or prepared extension instances into a later
        # run.
        if not hasattr(self, "extension_lifecycle_manager"):
            self.extension_lifecycle_manager = ExtensionLifecycleManager(self)
        else:
            reset_run_state = getattr(
                self.extension_lifecycle_manager, "reset_run_state", None
            )
            if callable(reset_run_state):
                reset_run_state()
        self.extension_results = {}
        self.runtime_capabilities = {}
        self._extension_collector_scope: Dict[str, Dict[str, Any]] = {}
        self._extension_collector_results: Dict[str, Any] = {}
        lifecycle_extensions_enabled = (
            self.extension_lifecycle_manager.has_enabled_extensions(dut_ids)
        )

        # The CLI normally populates this before per-DUT filtering.  Repeat the
        # idempotent step here so API/test callers that enter the orchestrator
        # directly get the same live-capability behaviour.
        capability_candidate_ids = list(
            dict.fromkeys(
                cid
                for dut_collectors in filtered_collectors_per_dut.values()
                for cid in dut_collectors
            )
        )

        requires_system_dump_capabilities = (
            self.collectors_require_system_dump_capabilities(capability_candidate_ids)
        )
        has_declared_capability_requirements = any(
            isinstance(
                (self.config_manager.get_collector_info(collector_id) or {}).get(
                    "redfish_capability"
                ),
                dict,
            )
            for collector_id in capability_candidate_ids
        )
        if requires_system_dump_capabilities:
            await self.discover_system_dump_capabilities(
                dut_ids=dut_ids,
                preflight_results=preflight_results,
            )

        if requires_system_dump_capabilities or has_declared_capability_requirements:
            capability_filtering = (
                await self.execution_engine.apply_capability_filter_per_dut(
                    filtered_collectors_per_dut,
                    skipped_collectors_per_dut,
                )
            )
            filtered_collectors_per_dut = capability_filtering["filtered_collectors"]
            skipped_collectors_per_dut = capability_filtering["skipped_collectors"]

        if skipped_collectors_per_dut is None:
            skipped_collectors_per_dut = {did: [] for did in dut_ids}
        else:
            for dut_id in dut_ids:
                skipped_collectors_per_dut.setdefault(dut_id, [])

        # A collector can be surfaced by more than one filtering layer. Status
        # entries are keyed by DUT+collector, so normalize the exclusion input
        # to that same identity before updating both entries and category
        # counters. Preserve the first reason/type because it is the layer that
        # made the collector inapplicable first.
        for dut_id, dut_skipped in skipped_collectors_per_dut.items():
            deduplicated_skips = {}
            for skipped_info in dut_skipped:
                collector_id = skipped_info.get("collector_id")
                if collector_id and collector_id not in deduplicated_skips:
                    deduplicated_skips[collector_id] = skipped_info
            skipped_collectors_per_dut[dut_id] = list(deduplicated_skips.values())

        # Compute union sets
        all_filtered_collectors = list(
            dict.fromkeys(
                cid
                for dut_cids in filtered_collectors_per_dut.values()
                for cid in dut_cids
            )
        )
        all_skipped_collectors = list(
            dict.fromkeys(
                s["collector_id"]
                for dut_skipped in skipped_collectors_per_dut.values()
                for s in dut_skipped
            )
        )

        if original_collector_ids is None:
            original_collector_ids = list(
                dict.fromkeys(all_filtered_collectors + all_skipped_collectors)
            )

        self._extension_collector_scope = {
            dut_id: {
                "selected_collector_ids": list(original_collector_ids or []),
                "available_collector_ids": list(
                    filtered_collectors_per_dut.get(dut_id, [])
                ),
                "skipped_collectors": copy.deepcopy(
                    skipped_collectors_per_dut.get(dut_id, [])
                ),
            }
            for dut_id in dut_ids
        }

        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Starting execution: {len(all_filtered_collectors)} collectors across {len(dut_ids)} DUT(s)",
        )

        # Initialize status tracker
        if hasattr(self, "status_tracker") and self.status_tracker:
            await self.status_tracker.initialize_collection(
                dut_ids=dut_ids,
                collector_ids=list(original_collector_ids or []),
                config_manager=self.config_manager,
            )

        # Step 1: Preflight checks on filtered collectors
        if preflight_results is not None:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 1: Reusing preflight results gathered before autodetection",
            )
        elif all_filtered_collectors:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 1: Running preflight checks on filtered collectors...",
            )

            tool_config = self.config_manager.get_tool_config()
            skip_preflight = (
                tool_config.get("skip_preflight", False)
                if isinstance(tool_config, dict)
                else getattr(tool_config, "skip_preflight", False)
            )
            if not skip_preflight:
                preflight_results = await self.run_preflight_checks(
                    all_filtered_collectors,
                    collector_ids_per_dut=filtered_collectors_per_dut,
                )
            else:
                await self.logger.log_runtime(
                    "INFO", "WorkflowOrchestrator", "Skipping preflight checks"
                )
                preflight_results = None
        else:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 1: No collectors to execute - skipping preflight checks",
            )
            preflight_results = None

        # Step 2: Dependency checks (software prerequisites)
        if all_filtered_collectors:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 2: Running dependency checks on filtered collectors...",
            )
            dependency_results = await self.run_dependency_checks(
                all_filtered_collectors,
                preflight_results,
                filtered_collectors_per_dut=filtered_collectors_per_dut,
            )
            await self.reporting_engine.log_dependency_check_table(dependency_results)
        else:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 2: No collectors to execute - skipping dependency checks",
            )

        # Step 3: Platform info gathering and dynamic discovery. An explicitly
        # enabled lifecycle extension is runtime work even when no catalog
        # collector survived filtering.
        runtime_work_required = (
            bool(all_filtered_collectors) or lifecycle_extensions_enabled
        )
        if runtime_work_required:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 3: Gathering platform info and running dynamic discovery...",
            )

            # Step 3a: Analyze filtered collectors to determine discovery requirements
            firmware_inventory_needed = bool(all_filtered_collectors) and (
                await self._check_firmware_inventory_needed(
                    all_filtered_collectors, dut_ids
                )
            )

            # Configure discovery service based on collector requirements
            if firmware_inventory_needed:
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    "Firmware inventory discovery enabled (required by one or more collectors)",
                )
                discovery_service = self.dut_manager._get_discovery_service()
                config = DiscoveryConfig()
                config.discover_firmware_inventory = True
                discovery_service.set_config(config)

            platform_results = await self.gather_platform_info(
                dut_ids=dut_ids, preflight_results=preflight_results
            )

            discovery_results = await self.run_dynamic_discovery(
                dut_ids=dut_ids, preflight_results=preflight_results
            )
        else:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 3: No collectors to execute - skipping platform info gathering and discovery",
            )
            platform_results = {}
            discovery_results = {}

        # Step 3b: Every extension prepares before any extension executes.
        # Execute completes before the collector scheduler so catalog-declared
        # runtime capabilities cannot observe partially established state.
        if lifecycle_extensions_enabled:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                "Step 3b: Running enabled lifecycle extensions...",
            )
            await self.extension_lifecycle_manager.prepare(dut_ids, platform_results)
            self.extension_results = await self.extension_lifecycle_manager.execute()
            result_count = sum(
                len(per_dut) for per_dut in self.extension_results.values()
            )
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                f"Step 3b complete: {result_count} lifecycle result(s) recorded",
            )

        # Step 3: Mark skipped collectors in status tracker and create error logs
        if hasattr(self, "status_tracker") and self.status_tracker:
            total_skipped = sum(len(v) for v in skipped_collectors_per_dut.values())
            num_duts_with_skipped = len(skipped_collectors_per_dut)

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                f"Step 4: Processing {total_skipped} skipped collector entries across {num_duts_with_skipped} DUTs...",
            )

            async def _process_skipped_for_dut(
                dut_id: str,
                dut_skipped: list,
            ) -> None:
                """
                Process all skipped collector entries for a single DUT.

                Track pre-execution exclusion type for the footer summary.

                Args:
                    dut_id: Stable DUT identifier used to correlate
                        configuration, logs, and results.
                    dut_skipped: Entries supplied as ``dut_skipped`` without
                        transferring container ownership.
                """
                for skipped_info in dut_skipped:
                    collector_id = skipped_info["collector_id"]
                    reason = skipped_info["reason"]
                    skip_type = skipped_info.get("skip_type", "config")

                    await self.logger.log_runtime(
                        "DEBUG",
                        "WorkflowOrchestrator",
                        f"Marking collector {collector_id} as skipped for DUT {dut_id}: {reason}",
                    )
                    await self.status_tracker.complete_collector(
                        dut_id,
                        collector_id,
                        "skipped",
                        reason,
                        exclusion_type=skip_type,
                        skip_status_update=True,
                    )

                    # Track pre-execution exclusion type for the footer summary
                    if skip_type == "baseboard":
                        await self.status_tracker.increment_baseboard_excluded(
                            skip_status_update=True
                        )
                    elif skip_type == "capability":
                        await self.status_tracker.increment_capability_excluded(
                            skip_status_update=True
                        )
                    elif skip_type in {"config", "config_applicability"}:
                        await self.status_tracker.increment_config_excluded(
                            skip_status_update=True
                        )

                    # Implicit applicability filtering remains silent. An
                    # explicitly selected collector retains one truthful legacy
                    # summary row so automation can distinguish filtering from
                    # a missing or truncated summary.
                    applicability_filtered = skip_type in {
                        "baseboard",
                        "config_applicability",
                    }
                    explicitly_selected = (
                        str(dut_id),
                        str(collector_id),
                    ) in explicit_collector_pairs
                    if applicability_filtered and not explicitly_selected:
                        await self.logger.log_runtime(
                            "DEBUG",
                            "WorkflowOrchestrator",
                            f"Collector {collector_id} not applicable for DUT {dut_id} ({skip_type}) - silently excluded (no error log, no summary entry)",
                        )
                        continue

                    # A config/CLI skip or explicit applicability exclusion is
                    # not an execution error: record it in the summary without
                    # creating an error-log file or collector status envelope.
                    try:
                        await self.add_execution_summary_entry(
                            dut_id,
                            collector_id,
                            "skipped",
                            [],
                            reason,
                        )
                    except Exception as e:
                        await self.logger.log_runtime(
                            "WARNING",
                            "WorkflowOrchestrator",
                            f"Failed to add execution summary entry for skipped collector {collector_id}: {e}",
                        )

            all_coros = [
                _process_skipped_for_dut(dut_id, dut_skipped)
                for dut_id, dut_skipped in skipped_collectors_per_dut.items()
            ]
            await asyncio.gather(*all_coros, return_exceptions=True)

            # Single bulk status update after all skipped entries are marked
            await self.status_tracker._update_status()

            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                f"Step 4 complete: processed {total_skipped} skipped entries across {num_duts_with_skipped} DUTs",
            )

        explicit_config_skips = {
            dut_id: [
                skipped_info
                for skipped_info in dut_skipped
                if skipped_info.get("skip_type") == "config_applicability"
                and (
                    str(dut_id),
                    str(skipped_info.get("collector_id") or ""),
                )
                in explicit_collector_pairs
            ]
            for dut_id, dut_skipped in skipped_collectors_per_dut.items()
        }
        explicit_config_skips = {
            dut_id: dut_skipped
            for dut_id, dut_skipped in explicit_config_skips.items()
            if dut_skipped
        }
        if explicit_config_skips:
            await self.reporting_engine.display_config_applicability_skip_reasons(
                explicit_config_skips
            )

        # Step 5: Execute collectors using the filtered collectors per DUT
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            "Step 5: Executing filtered collectors...",
        )

        # Use the existing execution logic but with filtered collectors per DUT
        results = await self._execute_filtered_collectors(
            filtered_collectors_per_dut,
            skipped_collectors_per_dut,
            dut_ids,
            collection_level,
            preflight_results,
            original_collector_ids,
        )
        self._extension_collector_results = results

        # End timing for collector execution
        if hasattr(self, "timing_manager") and self.timing_manager:
            self.timing_manager.end_component("collector_execution")

        return results

    def _get_execution_scheduler_mode(self) -> str:
        """
        Return the collector scheduler mode, defaulting to per-DUT execution.

        The implementation uses current instance state to produce the collector
        scheduler mode, defaulting to per-DUT execution. If the function cannot
        produce the collector scheduler mode, defaulting to per-DUT execution,
        its exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            The validated ``mode``.

        Raises:
            ValueError: If invalid execution_scheduler value ``mode``; expected
                'per_dut' or 'legacy_global'.
        """
        tool_config = self.config_manager.get_tool_config()
        if isinstance(tool_config, dict):
            mode = tool_config.get(
                "execution_scheduler",
                tool_config.get("scheduler_mode", "per_dut"),
            )
        else:
            mode = getattr(
                tool_config,
                "execution_scheduler",
                getattr(tool_config, "scheduler_mode", "per_dut"),
            )

        mode = str(mode or "per_dut").strip().lower()
        if mode not in {"per_dut", "legacy_global"}:
            raise ValueError(
                "Invalid execution_scheduler value "
                f"{mode!r}; expected 'per_dut' or 'legacy_global'"
            )
        return mode

    def _get_unique_collectors(
        self, collectors_per_dut: Dict[str, List[str]]
    ) -> List[str]:
        """
        Return a stable unique collector list from per-DUT collector lists.

        The implementation uses ``collectors_per_dut`` to produce a stable
        unique collector list from per-DUT collector lists.

        Args:
            collectors_per_dut: Mapping supplying fields for stable unique
                collector list from per-DUT collector lists.

        Returns:
            The validated ``ordered``.
        """
        seen = set()
        ordered = []
        for collector_ids in collectors_per_dut.values():
            for collector_id in collector_ids:
                if collector_id not in seen:
                    seen.add(collector_id)
                    ordered.append(collector_id)
        return ordered

    def _classify_collectors_for_dut(
        self, collector_ids: List[str]
    ) -> CollectorClassification:
        """
        Return the classify collectors for DUT.

        After applying local validation, the function forwards ``collector_ids``
        to ``CollectorClassification`` and preserves its return and exception
        contract.

        Args:
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.

        Returns:
            A ``CollectorClassification`` representing classify collectors for
            DUT.
        """
        collector_positions = {cid: idx for idx, cid in enumerate(collector_ids)}
        tail_candidates = []
        normal_collectors = []

        for collector_id in collector_ids:
            collector_info = self.config_manager.get_collector_info(collector_id) or {}
            execution_phase = (
                str(collector_info.get("execution_phase", "")).strip().lower()
            )
            if execution_phase == "tail":
                tail_candidates.append((collector_id, collector_info))
            else:
                normal_collectors.append(collector_id)

        def _tail_sort_key(item):
            """
            Return the tail sort key.

            The implementation uses ``item`` to produce the tail sort key.

            Args:
                item: Item evaluated while performing tail sort key.

            Returns:
                A tuple containing ``tail sort key value 1`` and ``tail sort key
                value 2`` in that order.
            """
            collector_id, collector_info = item
            order_value = collector_info.get("execution_order")
            try:
                order = int(order_value)
            except (TypeError, ValueError):
                order = None
            if order is None:
                return (1, collector_positions.get(collector_id, 0))
            return (0, order)

        sequential_collectors = self.get_sequential_collectors()
        parallel_collectors = self.get_parallel_collectors()

        return CollectorClassification(
            normal_sequential=[
                cid for cid in normal_collectors if cid in sequential_collectors
            ],
            normal_parallel=[
                cid for cid in normal_collectors if cid in parallel_collectors
            ],
            tail=[cid for cid, _ in sorted(tail_candidates, key=_tail_sort_key)],
        )

    def _build_dut_execution_plan(
        self, dut_id: str, collector_ids: List[str]
    ) -> DutExecutionPlan:
        """
        Build DUT execution plan.

        After applying local validation, the function forwards ``dut_id`` and
        ``collector_ids`` to ``DutExecutionPlan`` and preserves its return and
        exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.

        Returns:
            A ``DutExecutionPlan`` representing DUT execution plan.
        """
        classification = self._classify_collectors_for_dut(collector_ids)
        return DutExecutionPlan(
            dut_id=dut_id,
            normal_sequential=classification.normal_sequential,
            normal_parallel=classification.normal_parallel,
            tail=classification.tail,
        )

    def _merge_collector_results(
        self, target: Dict[str, Any], source: Optional[Dict[str, Any]]
    ) -> None:
        """
        Merge collector-major execution results without dropping DUT entries.

        The implementation uses ``target`` and ``source`` to merge
        collector-major execution results without dropping DUT entries. The
        operation mutates ``target`` in place; ownership of those objects
        remains with the caller.

        Args:
            target: Mapping supplying fields for merge collector-major execution
                results without dropping DUT entries.
            source: Mapping supplying fields for merge collector-major execution
                results without dropping DUT entries.
        """
        if not source:
            return
        for collector_id, collector_result in source.items():
            if not isinstance(collector_result, dict):
                target[collector_id] = collector_result
                continue
            target.setdefault(collector_id, {})
            target[collector_id].update(collector_result)

    def _build_error_results(
        self, collector_ids: List[str], dut_id: str, error: BaseException
    ) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        Build error results.

        The implementation uses ``collector_ids``, ``dut_id``, and ``error`` to
        build error results.

        Args:
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            error: Exception or failure detail associated with the operation.

        Returns:
            A mapping containing error results.
        """
        return {
            collector_id: {
                dut_id: {
                    "status": "error",
                    "error": str(error),
                    "execution_time": 0.0,
                }
            }
            for collector_id in collector_ids
        }

    async def _execute_one_dut_plan(
        self, plan: DutExecutionPlan, collection_level: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        Execute one DUT's normal collectors, then that same DUT's tail collectors.

        The implementation uses ``plan`` and ``collection_level`` to execute one
        DUT's normal collectors, then that same DUT's tail collectors. Terminal
        status is emitted only after one DUT's normal collectors, then that same
        DUT's tail collectors and its owned cleanup have completed. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            plan: Plan object whose ``dut_id``, ``normal_parallel``,
                ``normal_sequential``, and ``tail`` state is read while
                performing one DUT's normal collectors, then that same DUT's
                tail collectors.
            collection_level: Text supplied as collection level in the format
                accepted by this function.

        Returns:
            The validated ``results``.
        """
        results = {"sequential_results": {}, "parallel_results": {}}
        normal_tasks = []

        if plan.normal_parallel:
            normal_tasks.append(
                (
                    "parallel_results",
                    plan.normal_parallel,
                    asyncio.create_task(
                        capture_owned_awaitable(
                            self._execute_parallel_collectors_unified(
                                plan.normal_parallel,
                                [plan.dut_id],
                                collection_level,
                                None,
                                self.progress_state,
                            )
                        )
                    ),
                )
            )

        if plan.normal_sequential:
            normal_tasks.append(
                (
                    "sequential_results",
                    plan.normal_sequential,
                    asyncio.create_task(
                        capture_owned_awaitable(
                            self._execute_sequential_collectors_unified(
                                plan.normal_sequential,
                                [plan.dut_id],
                                collection_level,
                                None,
                            )
                        )
                    ),
                )
            )

        if normal_tasks:
            normal_results = await _drain_workflow_tasks(
                [task for _, _, task in normal_tasks]
            )
            for (result_key, collector_ids, _), result in zip(
                normal_tasks, normal_results
            ):
                if isinstance(result, BaseException):
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"{result_key} failed for DUT {plan.dut_id}: {result}",
                    )
                    self._merge_collector_results(
                        results[result_key],
                        self._build_error_results(collector_ids, plan.dut_id, result),
                    )
                else:
                    self._merge_collector_results(results[result_key], result)

        if plan.tail:
            try:
                tail_results = await self._execute_sequential_collectors_unified(
                    plan.tail,
                    [plan.dut_id],
                    collection_level,
                    None,
                )
                self._merge_collector_results(
                    results["sequential_results"], tail_results
                )
            except Exception as exc:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Tail collector execution failed for DUT {plan.dut_id}: {exc}",
                )
                self._merge_collector_results(
                    results["sequential_results"],
                    self._build_error_results(plan.tail, plan.dut_id, exc),
                )

        return results

    def _estimate_peak_operations_per_dut(self, plans: List[DutExecutionPlan]) -> int:
        """
        Estimate the maximum simultaneously active operations for one DUT.

        A DUT's normal parallel and sequential lanes run concurrently.

        Args:
            plans: Entries supplied as ``plans`` without transferring container
                ownership.

        Returns:
            The validated ``peak``.
        """
        peak = 1
        for plan in plans:
            parallel_limit = 1
            try:
                parallel_limit = int(
                    self.execution_engine._get_max_concurrent_collectors_per_dut(
                        plan.dut_id
                    )
                )
            except (AttributeError, TypeError, ValueError, OverflowError):
                pass
            parallel_limit = max(1, parallel_limit)
            # A DUT's normal parallel and sequential lanes run concurrently.
            normal_width = min(len(plan.normal_parallel), parallel_limit)
            if plan.normal_sequential:
                normal_width += 1
            tail_width = 1 if plan.tail else 0
            peak = max(peak, normal_width, tail_width)
        return peak

    def _resolve_dut_concurrency_limit(
        self,
        plans: List[DutExecutionPlan],
        operations_per_dut: Optional[int] = None,
    ) -> int:
        """
        Resolve how many DUTs may collect concurrently.

        Admit every plan unless an explicit ``max_concurrent_duts`` override
        requests a whole-DUT cap. CPU-derived throttling is applied around
        collector operations in :class:`ExecutionEngine`. Returns at least 1 and
        never more than the number of plans.

        Args:
            plans: Entries supplied as ``plans`` without transferring container
                ownership.
            operations_per_dut: Optional operations per DUT; ``None`` selects
                the function's default behavior.

        Returns:
            The numeric DUT concurrency limit.
        """
        configured_max = self._get_configured_max_concurrent_duts()

        return resolve_dut_concurrency(
            num_duts=len(plans),
            operations_per_dut=(
                operations_per_dut
                if operations_per_dut is not None
                else self._estimate_peak_operations_per_dut(plans)
            ),
            configured_max=configured_max,
        )

    def _get_configured_max_concurrent_duts(self) -> Optional[object]:
        """
        Return the raw configured whole-DUT override, if present.

        The implementation uses current instance state to produce the raw
        configured whole-DUT override, if present.

        Returns:
            The validated ``raw``, or ``None`` when no value qualifies.
        """
        try:
            tool_config = self.config_manager.get_tool_config()
            execution_config = (
                tool_config.get("execution_config", {})
                if isinstance(tool_config, dict)
                else getattr(tool_config, "execution_config", {})
            )
            raw = (
                execution_config.get("max_concurrent_duts")
                if isinstance(execution_config, dict)
                else getattr(execution_config, "max_concurrent_duts", None)
            )
            if raw is None:
                raw = (
                    tool_config.get("max_concurrent_duts")
                    if isinstance(tool_config, dict)
                    else getattr(tool_config, "max_concurrent_duts", None)
                )
            return raw
        except (AttributeError, TypeError):
            return None

    def _configure_scheduling_admission(
        self,
        *,
        filtered_collectors_per_dut: Dict[str, List[str]],
        skipped_collectors_per_dut: Dict[str, List[Dict[str, Any]]],
        collection_level: str,
        preflight_results: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Build the post-preflight plan and bind its admission controller.

        Planning is shared by both scheduler implementations so their runtime
        policy and persisted evidence describe the same filtered workload.

        Args:
            filtered_collectors_per_dut: Runnable collector IDs by DUT.
            skipped_collectors_per_dut: Typed skip evidence by DUT.
            collection_level: Resolved collection level for the run.
            preflight_results: Existing transport outcomes and durations.

        Returns:
            The deterministic scheduling summary recorded for the run.

        Raises:
            ValueError: If governed profile data or resolved bounds conflict.

        Side effects:
            Installs a run-owned controller and evidence destination on the
            execution engine without starting background sampling.
        """

        raw_max_concurrent_duts = self._get_configured_max_concurrent_duts()
        try:
            planned_max_concurrent_duts = (
                int(raw_max_concurrent_duts)
                if raw_max_concurrent_duts is not None
                else None
            )
        except (TypeError, ValueError, OverflowError):
            planned_max_concurrent_duts = None
        admission_settings = self.execution_engine.admission_settings
        scheduling_summary = build_scheduling_summary(
            filtered_collectors_per_dut=filtered_collectors_per_dut,
            skipped_collectors_per_dut=skipped_collectors_per_dut,
            collector_definitions=self.config_manager.get_collector_definitions(),
            preflight_results=preflight_results,
            collection_level=collection_level,
            resource_inputs=self.execution_engine.cpu_resource_resolution.to_dict(),
            concurrency_mode=admission_settings.mode,
            initial_limit=admission_settings.initial_limit,
            minimum_limit=admission_settings.minimum_limit,
            maximum_limit=admission_settings.maximum_limit,
            max_concurrent_duts=planned_max_concurrent_duts,
            max_concurrent_collectors_per_dut=(
                self.execution_engine._get_max_concurrent_collectors_per_dut()
            ),
        )
        self.execution_engine.configure_admission_controller(
            resource_monitor=self.resource_usage_monitor,
            evidence_path=(self.log_dir / ".metadata" / "concurrency_scheduler.json"),
            plan_summary=scheduling_summary,
        )
        return scheduling_summary

    async def _execute_filtered_collectors_per_dut_scheduler(
        self,
        filtered_collectors_per_dut: Dict[str, List[str]],
        skipped_collectors_per_dut: Dict[str, List[Dict[str, Any]]],
        dut_ids: List[str],
        collection_level: str,
        preflight_results: Optional[Dict[str, Any]],
        original_collector_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute collector pipelines independently per DUT.

        The implementation uses ``filtered_collectors_per_dut``,
        ``skipped_collectors_per_dut``, ``dut_ids``, ``collection_level``, and
        ``preflight_results`` to execute collector pipelines independently per
        DUT. Terminal status is emitted only after collector pipelines
        independently per DUT and its owned cleanup have completed. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. It updates ``_extension_collector_results``
        on the instance as part of that state transition. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            filtered_collectors_per_dut: Mapping supplying fields for collector
                pipelines independently per DUT.
            skipped_collectors_per_dut: Mapping supplying fields for collector
                pipelines independently per DUT.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            preflight_results: Mapping supplying fields for collector pipelines
                independently per DUT.
            original_collector_ids: Optional original collector identifiers;
                ``None`` selects the function's default behavior.

        Returns:
            The validated ``results``.

        Raises:
            BaseException: Preserves setup, scheduling, cancellation, and
                cleanup failures after every owned task has been observed.
        """
        all_filtered_collectors = self._get_unique_collectors(
            filtered_collectors_per_dut
        )

        all_skipped_collectors = set()
        for dut_skipped in skipped_collectors_per_dut.values():
            for skipped_info in dut_skipped:
                all_skipped_collectors.add(skipped_info["collector_id"])

        plans = [
            self._build_dut_execution_plan(
                dut_id, filtered_collectors_per_dut.get(dut_id, [])
            )
            for dut_id in dut_ids
        ]
        total_sequential = sum(
            len(plan.normal_sequential) + len(plan.tail) for plan in plans
        )
        total_parallel = sum(len(plan.normal_parallel) for plan in plans)

        scheduling_summary = self._configure_scheduling_admission(
            filtered_collectors_per_dut=filtered_collectors_per_dut,
            skipped_collectors_per_dut=skipped_collectors_per_dut,
            preflight_results=preflight_results,
            collection_level=collection_level,
        )
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Scheduling plan: {format_scheduling_summary(scheduling_summary)}",
        )

        await self._log_to_all(
            "INFO",
            "WorkflowOrchestrator",
            f"Starting per-DUT execution of {len(all_filtered_collectors)} collectors: {', '.join(all_filtered_collectors)}",
            dut_ids,
        )

        results = {
            "sequential_results": {},
            "parallel_results": {},
            "skipped_results": skipped_collectors_per_dut,
            "summary": {
                "total_collectors": len(all_filtered_collectors),
                "skipped_collectors": len(all_skipped_collectors),
                "sequential_collectors": total_sequential,
                "parallel_collectors": total_parallel,
                "duts_processed": len(dut_ids),
            },
        }

        if preflight_results:
            self.execution_engine.set_preflight_results(preflight_results)

        await self._setup_progress_display(
            dut_ids,
            all_filtered_collectors,
            len(all_filtered_collectors),
            collectors_per_dut=filtered_collectors_per_dut,
        )

        # Admit every DUT plan by default. CPU protection is enforced by the
        # execution engine's shared weighted operation limiter, so one slow
        # DPU operation does not hold a whole-DUT slot and block unrelated work.
        # A plan-wide semaphore remains available as an explicit hard override.
        peak_operations_per_dut = self._estimate_peak_operations_per_dut(plans)
        dut_concurrency_limit = self._resolve_dut_concurrency_limit(
            plans, peak_operations_per_dut
        )
        explicit_plan_limit = explicit_dut_concurrency_limit(
            len(plans), self._get_configured_max_concurrent_duts()
        )
        if explicit_plan_limit is None:
            admission_message = (
                f"all {len(plans)} plans "
                "(no explicit max_concurrent_duts; whole-plan semaphore disabled)"
            )
        else:
            admission_message = (
                f"{dut_concurrency_limit}/{len(plans)} plans "
                "(explicit max_concurrent_duts override)"
            )
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"DUT plan admission: {admission_message}",
        )
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            "Global collector-operation capacity: "
            f"{self.execution_engine.global_collector_operation_limit} weighted units",
        )

        dut_semaphore = (
            asyncio.Semaphore(dut_concurrency_limit)
            if explicit_plan_limit is not None
            else None
        )

        async def _run_dut_plan(plan: DutExecutionPlan):
            """
            Run DUT plan.

            The implementation uses ``plan`` to run DUT plan. Terminal status is
            emitted only after DUT plan and its owned cleanup have completed.
            Owned asynchronous work is awaited before return, so completion does
            not leave an unobserved task behind.

            Args:
                plan: Plan consumed while the function attempts to run DUT plan.

            Returns:
                The terminal per-DUT result produced by the scheduled collector
                plan.
            """
            if dut_semaphore is None:
                return await self._execute_one_dut_plan(plan, collection_level)
            async with dut_semaphore:
                return await self._execute_one_dut_plan(plan, collection_level)

        execution_error: BaseException | None = None
        cleanup_errors: List[BaseException] = []
        try:
            await self.execution_engine.start_admission_controller()
            plan_tasks = [
                asyncio.create_task(capture_owned_awaitable(_run_dut_plan(plan)))
                for plan in plans
            ]
            plan_results = await _drain_workflow_tasks(
                plan_tasks,
            )

            for plan, plan_result in zip(plans, plan_results):
                if isinstance(plan_result, BaseException):
                    await self.logger.log_runtime(
                        "ERROR",
                        "WorkflowOrchestrator",
                        f"Per-DUT execution failed for DUT {plan.dut_id}: {plan_result}",
                    )
                    failed_collectors = (
                        plan.normal_parallel + plan.normal_sequential + plan.tail
                    )
                    self._merge_collector_results(
                        results["sequential_results"],
                        self._build_error_results(
                            failed_collectors, plan.dut_id, plan_result
                        ),
                    )
                    continue
                self._merge_collector_results(
                    results["parallel_results"],
                    plan_result.get("parallel_results", {}),
                )
                self._merge_collector_results(
                    results["sequential_results"],
                    plan_result.get("sequential_results", {}),
                )
            # Retain completed scheduler evidence before report generation.
            # Cleanup can then finalize lifecycle extensions correctly even if
            # a later reporting/summary step raises.
            self._extension_collector_results = results
        except BaseException as error:
            execution_error = error
        finally:
            current_task = asyncio.current_task()
            interrupted = self.is_shutdown_requested() or bool(
                current_task is not None
                and hasattr(current_task, "cancelling")
                and current_task.cancelling()
            )
            try:
                await self.execution_engine.stop_admission_controller(
                    interrupted=interrupted
                )
            except BaseException as error:
                cleanup_errors.append(error)
            try:
                await self._teardown_progress_display()
            except BaseException as error:
                cleanup_errors.append(error)

        if execution_error is not None:
            for cleanup_error in cleanup_errors:
                execution_error.add_note(
                    "Scheduler cleanup also failed: " f"{type(cleanup_error).__name__}"
                )
            raise execution_error.with_traceback(execution_error.__traceback__)
        if cleanup_errors:
            raise cleanup_errors[0]

        await self.reporting_engine.log_all_results(results, dut_ids)

        total_executed = len(results.get("sequential_results", {})) + len(
            results.get("parallel_results", {})
        )
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Collector execution completed: {total_executed} collector groups executed",
        )

        await self._ensure_all_collectors_in_summary(
            collector_ids=all_filtered_collectors,
            dut_ids=dut_ids,
            results=results,
            preflight_results=preflight_results,
            original_collector_ids=original_collector_ids,
            skipped_collectors_per_dut=skipped_collectors_per_dut,
        )

        await self.reporting_engine.log_collector_status_table(
            results, dut_ids, all_filtered_collectors
        )
        await self.reporting_engine.log_execution_results_table(
            results, dut_ids, all_filtered_collectors
        )
        await self.reporting_engine.display_console_collector_summary(
            results, dut_ids, all_filtered_collectors
        )

        await self._log_to_all(
            "INFO",
            "WorkflowOrchestrator",
            f"Completed execution of {len(all_filtered_collectors)} collectors",
            dut_ids,
        )

        self._write_execution_order_metadata()

        for dut_id in dut_ids:
            try:
                await self.logger.create_structured_log(dut_id)
            except Exception as e:
                await self.logger.log_runtime(
                    "WARN",
                    "WorkflowOrchestrator",
                    f"Failed to create structured log for DUT {dut_id}: {e}",
                )

        return results

    async def _execute_filtered_collectors(
        self,
        filtered_collectors_per_dut: Dict[str, List[str]],
        skipped_collectors_per_dut: Dict[str, List[Dict[str, Any]]],
        dut_ids: List[str],
        collection_level: str,
        preflight_results: Optional[Dict[str, Any]],
        original_collector_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Select a scheduler while preserving one admission lifecycle.

        Per-DUT scheduling owns its lifecycle internally; the compatibility
        scheduler is wrapped here with the same start and finalization rules.

        Args:
            filtered_collectors_per_dut: Runnable collector IDs by DUT.
            skipped_collectors_per_dut: Typed skip evidence by DUT.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collection_level: Resolved collection level for the run.
            preflight_results: Existing transport outcomes and durations.
            original_collector_ids: Optional original collector identifiers;
                ``None`` selects the function's default behavior.

        Returns:
            The scheduler's complete collector result mapping.

        Raises:
            BaseException: Preserves scheduler, cancellation, and controller
                cleanup failures after all owned lifecycle work is observed.
        """

        scheduler_mode = self._get_execution_scheduler_mode()
        if scheduler_mode == "per_dut":
            return await self._execute_filtered_collectors_per_dut_scheduler(
                filtered_collectors_per_dut,
                skipped_collectors_per_dut,
                dut_ids,
                collection_level,
                preflight_results,
                original_collector_ids,
            )

        scheduling_summary = self._configure_scheduling_admission(
            filtered_collectors_per_dut=filtered_collectors_per_dut,
            skipped_collectors_per_dut=skipped_collectors_per_dut,
            preflight_results=preflight_results,
            collection_level=collection_level,
        )
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Scheduling plan: {format_scheduling_summary(scheduling_summary)}",
        )

        lifecycle_entered = True
        execution_error: BaseException | None = None
        result: Dict[str, Any] | None = None
        cleanup_errors: List[BaseException] = []
        try:
            await self.execution_engine.start_admission_controller()
            result = await self._execute_filtered_collectors_legacy_global(
                filtered_collectors_per_dut,
                skipped_collectors_per_dut,
                dut_ids,
                collection_level,
                preflight_results,
                original_collector_ids,
            )
        except BaseException as error:
            execution_error = error
        finally:
            if lifecycle_entered:
                current_task = asyncio.current_task()
                interrupted = self.is_shutdown_requested() or bool(
                    current_task is not None
                    and hasattr(current_task, "cancelling")
                    and current_task.cancelling()
                )
                try:
                    await self.execution_engine.stop_admission_controller(
                        interrupted=interrupted
                    )
                except BaseException as error:
                    cleanup_errors.append(error)

        if execution_error is not None:
            for cleanup_error in cleanup_errors:
                execution_error.add_note(
                    "Admission cleanup also failed: " f"{type(cleanup_error).__name__}"
                )
            raise execution_error.with_traceback(execution_error.__traceback__)
        if cleanup_errors:
            raise cleanup_errors[0]
        if result is None:
            raise RuntimeError("legacy scheduler returned without a result")
        return result

    async def _execute_filtered_collectors_legacy_global(
        self,
        filtered_collectors_per_dut: Dict[str, List[str]],
        skipped_collectors_per_dut: Dict[str, List[Dict[str, Any]]],
        dut_ids: List[str],
        collection_level: str,
        preflight_results: Optional[Dict[str, Any]],
        original_collector_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the compatibility global-union scheduler implementation.

        Admission setup and teardown remain outside this compatibility body so
        both scheduler modes share one controller lifecycle contract.

        Args:
            filtered_collectors_per_dut: Runnable collector IDs by DUT.
            skipped_collectors_per_dut: Typed skip evidence by DUT.
            dut_ids: Entries supplied without transferring ownership.
            collection_level: Resolved collection level for the run.
            preflight_results: Existing transport outcomes and durations.
            original_collector_ids: Optional original collector request.

        Returns:
            The complete legacy scheduler result mapping.
        """

        # Get a stable union of all filtered collectors for execution.
        all_filtered_collectors = self._get_unique_collectors(
            filtered_collectors_per_dut
        )

        # Get union of all skipped collectors for tracking
        all_skipped_collectors = set()
        for dut_skipped in skipped_collectors_per_dut.values():
            for skipped_info in dut_skipped:
                all_skipped_collectors.add(skipped_info["collector_id"])
        all_skipped_collectors = list(all_skipped_collectors)

        await self._log_to_all(
            "INFO",
            "WorkflowOrchestrator",
            f"Starting execution of {len(all_filtered_collectors)} collectors: {', '.join(all_filtered_collectors)}",
            dut_ids,
        )

        # Separate sequential and parallel collectors
        # Ensure tail collectors run last based on collector definitions.
        collector_positions = {
            cid: idx for idx, cid in enumerate(all_filtered_collectors)
        }
        tail_candidates = []
        normal_collectors = []
        for collector_id in all_filtered_collectors:
            collector_info = self.config_manager.get_collector_info(collector_id) or {}
            execution_phase = (
                str(collector_info.get("execution_phase", "")).strip().lower()
            )
            if execution_phase == "tail":
                tail_candidates.append((collector_id, collector_info))
            else:
                normal_collectors.append(collector_id)

        def _tail_sort_key(item):
            """
            Return the tail sort key.

            The implementation uses ``item`` to produce the tail sort key.

            Args:
                item: Item evaluated while performing tail sort key.

            Returns:
                A tuple containing ``tail sort key value 1`` and ``tail sort key
                value 2`` in that order.
            """
            collector_id, collector_info = item
            order_value = collector_info.get("execution_order")
            try:
                order = int(order_value)
            except (TypeError, ValueError):
                order = None
            if order is None:
                return (1, collector_positions.get(collector_id, 0))
            return (0, order)

        tail_collectors_to_run = [
            collector_id
            for collector_id, _ in sorted(tail_candidates, key=_tail_sort_key)
        ]
        sequential_to_run = [
            cid for cid in normal_collectors if cid in self.get_sequential_collectors()
        ]
        parallel_to_run = [
            cid for cid in normal_collectors if cid in self.get_parallel_collectors()
        ]

        await self._log_to_all(
            "INFO",
            "WorkflowOrchestrator",
            f"Sequential collectors: {len(sequential_to_run) + len(tail_collectors_to_run)}, Parallel collectors: {len(parallel_to_run)}",
            dut_ids,
        )
        if tail_collectors_to_run:
            await self._log_to_all(
                "INFO",
                "WorkflowOrchestrator",
                f"Forced tail collectors (run last): {tail_collectors_to_run}",
                dut_ids,
            )

        # Execute collectors with progress bars
        results = {
            "sequential_results": {},
            "parallel_results": {},
            "skipped_results": skipped_collectors_per_dut,
            "summary": {
                "total_collectors": len(all_filtered_collectors),
                "skipped_collectors": len(all_skipped_collectors),
                "sequential_collectors": len(sequential_to_run)
                + len(tail_collectors_to_run),
                "parallel_collectors": len(parallel_to_run),
                "duts_processed": len(dut_ids),
            },
        }

        if preflight_results:
            self.execution_engine.set_preflight_results(preflight_results)

        total_collectors = (
            len(parallel_to_run) + len(sequential_to_run) + len(tail_collectors_to_run)
        )
        await self._setup_progress_display(
            dut_ids,
            all_filtered_collectors,
            total_collectors,
            collectors_per_dut=filtered_collectors_per_dut,
        )

        parallel_task = None
        sequential_task = None

        if parallel_to_run:
            parallel_task = asyncio.create_task(
                capture_owned_awaitable(
                    self._execute_parallel_collectors_unified(
                        parallel_to_run,
                        dut_ids,
                        collection_level,
                        None,
                        self.progress_state,
                    )
                )
            )

        if sequential_to_run:
            sequential_task = asyncio.create_task(
                capture_owned_awaitable(
                    self._execute_sequential_collectors_unified(
                        sequential_to_run,
                        dut_ids,
                        collection_level,
                        None,
                    )
                )
            )

        # Wait for both tasks to complete (normal collectors only).
        # Use return_exceptions=True so both groups finish even if one fails —
        # we want to collect whatever logs are available and run all post-execution work.
        if parallel_task and sequential_task:
            parallel_result, sequential_result = await _drain_workflow_tasks(
                [parallel_task, sequential_task]
            )

            if isinstance(parallel_result, BaseException):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Parallel collector execution failed: {parallel_result}",
                )
                results["parallel_results"] = {}
            else:
                results["parallel_results"] = parallel_result

            if isinstance(sequential_result, BaseException):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Sequential collector execution failed: {sequential_result}",
                )
                results["sequential_results"] = {}
            else:
                results["sequential_results"] = sequential_result

        elif parallel_task:
            (parallel_result,) = await _drain_workflow_tasks([parallel_task])
            if isinstance(parallel_result, Exception):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Parallel collector execution failed: {parallel_result}",
                )
                results["parallel_results"] = {}
            else:
                results["parallel_results"] = parallel_result
            results["sequential_results"] = {}

        elif sequential_task:
            (sequential_result,) = await _drain_workflow_tasks([sequential_task])
            if isinstance(sequential_result, Exception):
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Sequential collector execution failed: {sequential_result}",
                )
                results["sequential_results"] = {}
            else:
                results["sequential_results"] = sequential_result
            results["parallel_results"] = {}

        else:
            results["parallel_results"] = {}
            results["sequential_results"] = {}

        # Execute forced tail collectors last, in fixed order.
        if tail_collectors_to_run:
            await self.logger.log_runtime(
                "INFO",
                "WorkflowOrchestrator",
                f"Executing forced tail collectors last: {tail_collectors_to_run}",
            )
            try:
                tail_results = await self._execute_sequential_collectors_unified(
                    tail_collectors_to_run,
                    dut_ids,
                    collection_level,
                    None,
                )
                results["sequential_results"].update(tail_results)
            except Exception as exc:
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Tail collector execution failed: {exc}",
                )

        # Retain completed scheduler evidence before report generation.  This
        # is intentionally earlier than the return path so deferred lifecycle
        # finalization remains evidence-preserving on late reporting failures.
        self._extension_collector_results = results
        await self._teardown_progress_display()

        # Log all results to metadata
        await self.reporting_engine.log_all_results(results, dut_ids)

        # Log execution summary
        total_executed = len(results.get("sequential_results", {})) + len(
            results.get("parallel_results", {})
        )
        await self.logger.log_runtime(
            "INFO",
            "WorkflowOrchestrator",
            f"Collector execution completed: {total_executed} collector groups executed",
        )

        # Ensure requested collectors are represented in the execution summary
        await self._ensure_all_collectors_in_summary(
            collector_ids=all_filtered_collectors,
            dut_ids=dut_ids,
            results=results,
            preflight_results=preflight_results,
            original_collector_ids=original_collector_ids,
            skipped_collectors_per_dut=skipped_collectors_per_dut,
        )

        # Log collector status and execution results to DUT-specific logs (no console output)
        await self.reporting_engine.log_collector_status_table(
            results, dut_ids, all_filtered_collectors
        )
        await self.reporting_engine.log_execution_results_table(
            results, dut_ids, all_filtered_collectors
        )

        # Display summary on console with proper formatting
        # Only collectors that reached the execution stage are shown; pre-execution
        # skips (baseboard constraints, config options) are excluded entirely.
        await self.reporting_engine.display_console_collector_summary(
            results, dut_ids, all_filtered_collectors
        )

        await self._log_to_all(
            "INFO",
            "WorkflowOrchestrator",
            f"Completed execution of {len(all_filtered_collectors)} collectors",
            dut_ids,
        )

        # Write execution order metadata before structured log generation
        self._write_execution_order_metadata()

        # Create structured log files for each DUT
        for dut_id in dut_ids:
            try:
                await self.logger.create_structured_log(dut_id)
            except Exception as e:
                await self.logger.log_runtime(
                    "WARN",
                    "WorkflowOrchestrator",
                    f"Failed to create structured log for DUT {dut_id}: {e}",
                )

        return results

    async def _execute_parallel_collectors_unified(
        self,
        collector_ids: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        progress_state=None,
    ) -> Dict[str, Any]:
        """
        Execute parallel collectors with unified progress bar management.

        Create a main task for this group of parallel collectors.

        Args:
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            progress: Progress object whose ``add_task`` state is read while
                performing parallel collectors with unified progress bar
                management.
            progress_state: Optional progress state; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing execute parallel collectors unified.
        """
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"Executing unified parallel collectors: {len(collector_ids)} collectors for {len(dut_ids)} DUTs",
        )
        await self.logger.log_runtime(
            "DEBUG",
            "WorkflowOrchestrator",
            f"Unified parallel collector IDs: {collector_ids}",
        )
        try:
            # Create a main task for this group of parallel collectors
            main_task = None
            if progress:
                main_task = progress.add_task(
                    f"[cyan]Parallel ({len(collector_ids)} collectors × {len(dut_ids)} DUTs)",
                    total=len(collector_ids)
                    * len(dut_ids),  # Track collector-DUT combinations
                )

            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                "About to call execution_engine.execute_service_based_parallel_collectors",
            )
            return (
                await self.execution_engine.execute_service_based_parallel_collectors(
                    collector_ids,
                    dut_ids,
                    collection_level,
                    progress,
                    main_task,
                    progress_state,
                )
            )
        finally:
            # Don't stop progress here as it's shared with sequential collectors
            pass

    async def _execute_sequential_collectors_unified(
        self,
        collector_ids: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
    ) -> Dict[str, Any]:
        """
        Execute sequential collectors with unified progress bar management.

        Create a main task for this group of sequential collectors.

        Args:
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            progress: Progress object whose ``add_task`` state is read while
                performing sequential collectors with unified progress bar
                management.

        Returns:
            A mapping containing execute sequential collectors unified.
        """
        try:
            # Create a main task for this group of sequential collectors
            main_task = None
            if progress:
                main_task = progress.add_task(
                    f"[cyan]Sequential ({len(collector_ids)} collectors × {len(dut_ids)} DUTs)",
                    total=len(collector_ids)
                    * len(dut_ids),  # Track collector-DUT combinations
                )

            # Check execution strategy configuration
            tool_config = self.config_manager.get_tool_config()
            parallel_duts_enabled = (
                tool_config.get("parallel_dut_sequential_collectors", True)
                if isinstance(tool_config, dict)
                else getattr(tool_config, "parallel_dut_sequential_collectors", True)
            )
            service_grouping_enabled = (
                tool_config.get("service_grouped_sequential_collectors", True)
                if isinstance(tool_config, dict)
                else getattr(tool_config, "service_grouped_sequential_collectors", True)
            )

            await self.logger.log_runtime(
                "DEBUG",
                "WorkflowOrchestrator",
                f"Execution strategy decision - parallel_duts_enabled: {parallel_duts_enabled}, service_grouping_enabled: {service_grouping_enabled}, dut_count: {len(dut_ids)}",
            )

            if not parallel_duts_enabled or (
                len(dut_ids) <= 1 and not service_grouping_enabled
            ):
                # Use the original sequential execution method
                await self.logger.log_runtime(
                    "DEBUG",
                    "WorkflowOrchestrator",
                    "Using traditional sequential execution",
                )
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Using traditional sequential execution for collectors across {len(dut_ids)} DUTs",
                )
                return await self.execution_engine.execute_sequential_collectors_with_progress(
                    collector_ids,
                    dut_ids,
                    collection_level,
                    progress,
                    main_task,
                )
            elif service_grouping_enabled:
                # Use service-grouped parallel execution
                await self.logger.log_runtime(
                    "DEBUG",
                    "WorkflowOrchestrator",
                    "Using service-grouped parallel execution",
                )
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Using service-grouped parallel execution for sequential collectors across {len(dut_ids)} DUTs",
                )
                return await self.execution_engine.execute_sequential_collectors_grouped_by_service(
                    collector_ids,
                    dut_ids,
                    collection_level,
                    progress,
                    main_task,
                    self.progress_state,
                )
            else:
                # Use the parallel DUT execution method (without service grouping)
                await self.logger.log_runtime(
                    "DEBUG",
                    "WorkflowOrchestrator",
                    "Using parallel DUT execution",
                )
                await self.logger.log_runtime(
                    "INFO",
                    "WorkflowOrchestrator",
                    f"Using parallel DUT execution for sequential collectors across {len(dut_ids)} DUTs",
                )
                return await self.execution_engine.execute_sequential_collectors_parallel_duts(
                    collector_ids,
                    dut_ids,
                    collection_level,
                    progress,
                    main_task,
                )
        finally:
            # Don't stop progress here as it's shared with parallel collectors
            pass

    async def _ensure_all_collectors_in_summary(
        self,
        collector_ids: List[str],
        dut_ids: List[str],
        results: Dict[str, Any],
        preflight_results: Optional[Dict[str, Any]] = None,
        original_collector_ids: Optional[List[str]] = None,
        skipped_collectors_per_dut: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> None:
        """
        Ensure all collectors in summary.

        The implementation uses ``collector_ids``, ``dut_ids``, ``results``,
        ``preflight_results``, and ``original_collector_ids`` to ensure all
        collectors in summary. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

        Args:
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            results: Mapping supplying fields for ensure all collectors in
                summary.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.
            original_collector_ids: Optional original collector identifiers;
                ``None`` selects the function's default behavior.
            skipped_collectors_per_dut: Optional skipped collectors per DUT;
                ``None`` selects the function's default behavior.
        """
        # Track execution per DUT/collector pair. A collector running on one DUT
        # does not imply it ran on every DUT in a heterogeneous rack.
        executed_pairs = set()
        sequential_results = results.get("sequential_results", {})
        parallel_results = results.get("parallel_results", {})

        def _is_preflight_failure_skip(result: Any) -> bool:
            """
            Return True for execution-engine skips caused by preflight.

            The implementation uses ``result`` to produce True for
            execution-engine skips caused by preflight.

            Args:
                result: Result object whose ``get`` state is read while
                    performing true for execution-engine skips caused by
                    preflight.

            Returns:
                Whether the true for execution-engine skips caused by preflight
                operation succeeds.
            """
            if not isinstance(result, dict):
                return False
            if str(result.get("status", "")).strip().lower() != "skipped":
                return False
            reason = str(result.get("reason") or result.get("message") or "").lower()
            return (
                "collector not executed due to" in reason
                and "preflight failure" in reason
            )

        for collector_id, collector_results in sequential_results.items():
            if isinstance(collector_results, dict):
                for dut_id, result in collector_results.items():
                    if _is_preflight_failure_skip(result):
                        continue
                    executed_pairs.add((dut_id, collector_id))
        for collector_id, collector_results in parallel_results.items():
            if isinstance(collector_results, dict):
                for dut_id, result in collector_results.items():
                    if _is_preflight_failure_skip(result):
                        continue
                    executed_pairs.add((dut_id, collector_id))

        # Use original collector IDs if provided so requested collectors appear in summary
        if original_collector_ids:
            eligible_collectors = set(original_collector_ids)
            filtered_out_collectors = eligible_collectors - set(collector_ids)
        else:
            eligible_collectors = set(collector_ids)
            filtered_out_collectors = set()

        preexecution_filtered_pairs = {
            (dut_id, skipped_info.get("collector_id"))
            for dut_id, dut_skipped in (skipped_collectors_per_dut or {}).items()
            for skipped_info in dut_skipped
            if skipped_info.get("collector_id")
        }

        # Add entries for DUT/collector pairs that didn't run.
        for collector_id in eligible_collectors:
            for dut_id in dut_ids:
                if (dut_id, collector_id) in executed_pairs:
                    continue

                # Collectors filtered out before execution are represented in
                # collection-status accounting as FilteredOut. They should not
                # appear as runtime skipped rows in Execution_Summary_Report.txt
                # or in per-collector status.json files.
                if (
                    collector_id in filtered_out_collectors
                    or (dut_id, collector_id) in preexecution_filtered_pairs
                ):
                    await self.logger.log_runtime(
                        "DEBUG",
                        "WorkflowOrchestrator",
                        f"Skipping execution-summary row for pre-execution filtered collector {collector_id} on {dut_id}",
                    )
                    continue

                # Get specific preflight failure reason if available
                reason = "Collector not executed (likely due to preflight failure)"
                if preflight_results and dut_id in preflight_results:
                    # Get service name from collector ID prefix
                    service_name = (
                        CollectorServiceMapping.get_service_from_collector_id(
                            collector_id
                        )
                    )

                    if service_name and service_name != "unknown":
                        dut_preflight = preflight_results[dut_id]
                        if (
                            "services" in dut_preflight
                            and service_name in dut_preflight["services"]
                        ):
                            service_result = dut_preflight["services"][service_name]
                            if service_result.get("status") == "fail":
                                failure_reason = service_result.get(
                                    "message", "Unknown preflight failure"
                                )
                                reason = f"Collector not executed due to {service_name} preflight failure: {failure_reason}"

                # Add to execution summary with "skipped" status
                await self.add_execution_summary_entry(
                    dut_id,
                    collector_id,
                    "skipped",
                    [],
                    reason,
                )

                # Create status.json for skipped collectors
                try:
                    await self.logger.write_collector_status_file(
                        collector_id,
                        dut_id,
                        "skipped",
                        reason,
                    )
                except Exception as e:
                    await self.logger.log_runtime(
                        "WARN",
                        "WorkflowOrchestrator",
                        f"Failed to create status.json for skipped collector {collector_id} on {dut_id}: {e}",
                    )

                # Update collector metadata for skipped collectors
                try:
                    await self.logger._update_collector_status(
                        dut_id,
                        collector_id,
                        "skipped",
                        reason,
                        0.0,
                    )
                except Exception as e:
                    await self.logger.log_runtime(
                        "WARN",
                        "WorkflowOrchestrator",
                        f"Failed to update metadata for skipped collector {collector_id} on {dut_id}: {e}",
                    )

    async def _write_completion_timestamps(self) -> None:
        """
        Write 'Completed at' timestamps to all DUT runtime logs.

        This is called before finalizing the execution summary so that the
        summary can read the complete timestamps to calculate accurate execution
        times.
        """
        if not self.dut_manager:
            return

        from datetime import datetime

        for dut_id in self.dut_manager.get_all_dut_ids():
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                f"DUT:{dut_id}",
                "=" * 80,
                lifecycle=True,
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                f"DUT:{dut_id}",
                f"DUT Runtime Log - {dut_id} - Completed",
                lifecycle=True,
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                f"DUT:{dut_id}",
                f"Completed at: {datetime.now().isoformat()}",
                lifecycle=True,
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                f"DUT:{dut_id}",
                "=" * 80,
                lifecycle=True,
            )

    def _persist_bundle_sanitization_metadata(self, sanitization: Any) -> None:
        """
        Atomically align root and per-DUT sanitization lifecycle state.

        The implementation uses ``sanitization`` to atomically align root and
        per-DUT sanitization lifecycle state. Filesystem effects remain confined
        to the caller-selected paths and the owning resource lifecycle. If the
        function cannot atomically align root and per-DUT sanitization lifecycle
        state, its exception reaches the caller instead of being converted into
        a successful result. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            sanitization: Sanitization consumed while the function attempts to
                atomically align root and per-DUT sanitization lifecycle state.

        Raises:
            RuntimeError: If bundle sanitizer returned malformed error evidence;
                bundle sanitizer returned malformed ``source_field`` accounting;
                bundle metadata is not a regular file: ``metadata_path``; or
                bundle metadata escaped the collection root: ``metadata_path``;
                or another input invariant is violated.
        """

        raw_errors = getattr(sanitization, "errors", None)
        if not isinstance(raw_errors, (list, tuple)):
            raise RuntimeError("Bundle sanitizer returned malformed error evidence")

        counts: Dict[str, int] = {}
        for source_field, metadata_field in (
            ("scanned_files", "files_scanned"),
            ("sanitized_files", "files_rewritten"),
            ("scanned_archives", "nested_archives_scanned"),
        ):
            value = getattr(sanitization, source_field, None)
            if type(value) is not int or value < 0 or value > (1 << 31) - 1:
                raise RuntimeError(
                    f"Bundle sanitizer returned malformed {source_field} accounting"
                )
            counts[metadata_field] = value

        sanitizer = getattr(
            getattr(getattr(self, "logger", None), "sanitizer", None),
            "sanitize",
            None,
        )
        errors: List[str] = []
        remaining_error_characters = 2048
        for error in raw_errors[:8]:
            rendered = sanitize_finalization_message(
                error,
                sanitizer=sanitizer if callable(sanitizer) else None,
            )
            if remaining_error_characters <= 0:
                break
            rendered = rendered[:remaining_error_characters]
            errors.append(rendered)
            remaining_error_characters -= len(rendered)

        root = Path(self.log_dir).resolve(strict=True)
        root_metadata_path = root / ".metadata" / "metadata.json"
        metadata_paths = [root_metadata_path]
        metadata_paths.extend(sorted(root.glob("*/.metadata/metadata.json")))
        metadata_paths = list(dict.fromkeys(metadata_paths))

        documents: Dict[Path, Dict[str, Any]] = {}
        modes: Dict[Path, int] = {}
        for metadata_path in metadata_paths:
            try:
                path_stat = metadata_path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(path_stat.st_mode):
                raise RuntimeError(
                    f"Bundle metadata is not a regular file: {metadata_path}"
                )
            try:
                metadata_path.resolve(strict=True).relative_to(root)
            except (FileNotFoundError, ValueError) as error:
                raise RuntimeError(
                    f"Bundle metadata escaped the collection root: {metadata_path}"
                ) from error
            with metadata_path.open("r", encoding="utf-8") as stream:
                document = json.load(stream)
            if not isinstance(document, dict):
                raise RuntimeError(
                    f"Bundle metadata is not a JSON object: {metadata_path}"
                )
            metadata = document.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                raise RuntimeError(
                    f"Bundle metadata lifecycle is malformed: {metadata_path}"
                )
            documents[metadata_path] = document
            modes[metadata_path] = stat.S_IMODE(path_stat.st_mode)

        if not documents:
            return

        root_document = documents.get(root_metadata_path, {})
        root_metadata = root_document.get("metadata", {})
        current_state = (
            root_metadata.get("sanitization", "write_time_only")
            if isinstance(root_metadata, dict)
            else "write_time_only"
        )
        if current_state not in {
            "enabled",
            "write_time_only",
            "disabled_by_user",
            "failed_safe",
        }:
            raise RuntimeError(
                "Bundle metadata has malformed sanitization lifecycle state"
            )
        if current_state == "failed_safe" and not raw_errors:
            raise RuntimeError(
                "Bundle metadata cannot downgrade failed-safe sanitization state"
            )
        sanitization_state = "failed_safe" if raw_errors else current_state
        if raw_errors:
            detail_state = "failed_safe"
        elif current_state in {"disabled_by_user", "write_time_only"}:
            detail_state = current_state
        else:
            detail_state = "complete"
        sanitization_details = {
            "state": detail_state,
            **counts,
            "errors": errors,
        }

        staged_paths: Dict[Path, Path] = {}
        try:
            for metadata_path, document in documents.items():
                metadata = document["metadata"]
                metadata["sanitization"] = sanitization_state
                if metadata_path == root_metadata_path:
                    metadata["sanitization_details"] = sanitization_details
                else:
                    # Per-DUT metadata carries the shared state; detailed scan
                    # accounting is root-owned and must not retain stale data.
                    metadata.pop("sanitization_details", None)

                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=f".{metadata_path.name}.",
                    suffix=".tmp",
                    dir=metadata_path.parent,
                )
                temporary_path = Path(temporary_name)
                staged_paths[metadata_path] = temporary_path
                try:
                    os.fchmod(descriptor, modes[metadata_path])
                    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                        descriptor = -1
                        safe_json_dump(document, stream, indent=4)
                        stream.write("\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)

            for metadata_path, temporary_path in staged_paths.items():
                os.replace(temporary_path, metadata_path)
        finally:
            for temporary_path in staged_paths.values():
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass

    async def _close_request_capture_runtime(self) -> None:
        """
        Drain all capture owners and close the sole run-owned runtime.

        The implementation uses current instance state to drain all capture
        owners and close the sole run-owned runtime. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. It updates ``_request_response_capture_runtime`` on the instance
        as part of that state transition.
        """

        runtime = getattr(self, "_request_response_capture_runtime", None)
        if runtime is None:
            return
        services = getattr(getattr(self, "config_manager", None), "services", {})
        seen: set[int] = set()
        errors: List[BaseException] = []
        control_flow: Optional[BaseException] = None
        if isinstance(services, dict):
            for service in services.values():
                if id(service) in seen:
                    continue
                seen.add(id(service))
                closer = getattr(service, "close_request_capture_state", None)
                if callable(closer):
                    try:
                        await closer()
                    except BaseException as error:
                        control_flow = _defer_capture_failure(
                            control_flow, errors, error
                        )
        runtime_closed = False
        try:
            await runtime.close()
            runtime_closed = True
        except BaseException as error:
            control_flow = _defer_capture_failure(control_flow, errors, error)
            # RunOwnedRequestCaptureRuntime.close drains successful teardown
            # before propagating any deferred caller-side outcome.
            runtime_closed = bool(getattr(runtime, "_close_complete", False))
        if runtime_closed:
            self._request_response_capture_runtime = None
        _raise_capture_cleanup_outcome(
            control_flow,
            errors,
            "Request capture service and runtime teardown failed",
        )

    async def finalize_request_capture(self) -> None:
        """
        Bind mandatory teardown phase two to the run-owned capture owner.

        The implementation uses current instance state to bind mandatory
        teardown phase two to the run-owned capture owner. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.
        """

        await self._close_request_capture_runtime()

    def _finish_persistent_post_runtime(
        self,
        *,
        planning_successful: bool,
        runtime_clean: bool,
    ) -> None:
        """
        Freeze optional persistent-POST evidence inside finalization.

        This hook is intentionally invoked after transport/session teardown but
        before reports or archives consume a RunResult. A hook failure is
        therefore ordinary receipt-bound runtime evidence, never a late CLI
        override of an already-rendered success.

        Args:
            planning_successful: Whether planning successful is enabled or
                required for this operation.
            runtime_clean: Whether runtime clean is enabled or required for this
                operation.
        """

        config_manager = getattr(self, "config_manager", None)
        services = getattr(config_manager, "services", None)
        redfish_service = (
            services.get("redfish") if isinstance(services, dict) else None
        )
        finish = getattr(redfish_service, "finish_persistent_post_runtime", None)
        if callable(finish):
            finish(
                planning_successful=planning_successful,
                runtime_clean=runtime_clean,
            )

    async def cleanup(
        self,
        total_runtime: Optional[float] = None,
        collector_ids: Optional[List[str]] = None,
        *,
        active_exception: Optional[BaseException] = None,
        finalize_collection: bool = True,
    ) -> FinalizationReceipt:
        """
        Clean up resources and finalize logging.

        The implementation uses ``total_runtime``, ``collector_ids``,
        ``active_exception``, and ``finalize_collection`` to clean up resources
        and finalize logging. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind. It updates
        ``finalization_receipt``, ``run_result``, and ``zip_archive_path`` on
        the instance as part of that state transition. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        Remote I/O uses the configured transport policy and returns only after
        its response or failure has been observed.

        Args:
            total_runtime: Optional total runtime; ``None`` selects the
                function's default behavior.
            collector_ids: Optional collector identifiers; ``None`` selects the
                function's default behavior.
            active_exception: Optional active exception; ``None`` selects the
                function's default behavior.
            finalize_collection: Whether finalize collection is enabled or
                required for this operation.

        Returns:
            The validated ``finalization_receipt``.

        Raises:
            RuntimeError: If collection status tracker did not return a
                finalization receipt; collection status tracker did not durably
                finalize; collection status tracker cannot validate its
                snapshot; or collection status finalization receipt differs from
                the durable snapshot; or another input invariant is violated.
            BaseException: If a delegated failure occurs while the function
                attempts to clean up resources and finalize logging.
            FinalizationReceiptError: If the function cannot clean up resources
                and finalize logging safely.
        """
        # Never retain an artifact from an earlier cleanup attempt. A path is
        # assigned only after this run's complete teardown and publication
        # pipeline succeeds.
        self.zip_archive_path = None
        cleanup_errors: List[BaseException] = []
        receipt_failures: List[FinalizationFailure] = []
        completed_teardown_phases: List[str] = []
        interrupted = False
        primary_control_flow: Optional[BaseException] = None

        sanitizer = getattr(getattr(self, "sanitizer", None), "sanitize", None)

        def merged_failure_evidence(
            *groups: Any,
        ) -> tuple[FinalizationFailure, ...]:
            """
            Preserve first observation order and append exact evidence once.

            After applying local validation, the function forwards ``groups`` to
            ``tuple`` and preserves its return and exception contract.

            Args:
                groups: Additional positional values forwarded in
                    caller-provided order.

            Returns:
                The merged failure evidence returned in operation-defined order.
            """

            merged: List[FinalizationFailure] = []
            seen: Set[tuple[str, str, str]] = set()
            for group in groups:
                for failure in group:
                    identity = (
                        failure.phase,
                        failure.error_type,
                        failure.message,
                    )
                    if identity in seen:
                        continue
                    seen.add(identity)
                    merged.append(failure)
            return tuple(merged)

        def record_failure(
            phase: str,
            error: BaseException,
            *,
            fatal: bool = True,
        ) -> None:
            """
            Record failure.

            The implementation uses ``phase``, ``error``, and ``fatal`` to
            record failure.

            Args:
                phase: Text supplied as phase in the format accepted by this
                    function.
                error: Exception or failure detail associated with the
                    operation.
                fatal: Whether fatal is enabled or required for this operation.
            """
            nonlocal interrupted, primary_control_flow
            leaves = tuple(iter_exception_leaves(error))
            if is_control_flow_exception(error):
                interrupted = bool(interrupted or is_interruption_exception(error))
                if primary_control_flow is None:
                    primary_control_flow = select_authoritative_exception((error,))
                else:
                    primary_control_flow = select_authoritative_exception(
                        (primary_control_flow, error)
                    )
            receipt_holders = (error, *leaves)
            inherited_failures = merged_failure_evidence(
                *(
                    holder_receipt.failures
                    for holder in receipt_holders
                    if isinstance(
                        (holder_receipt := getattr(holder, "receipt", None)),
                        FinalizationReceipt,
                    )
                )
            )
            if inherited_failures:
                receipt_failures.extend(inherited_failures)
            if not inherited_failures or isinstance(error, BaseExceptionGroup):
                for leaf in leaves:
                    if isinstance(getattr(leaf, "receipt", None), FinalizationReceipt):
                        continue
                    receipt_failures.append(
                        sanitize_finalization_failure(
                            phase,
                            leaf,
                            sanitizer=(sanitizer if callable(sanitizer) else None),
                        )
                    )
            if fatal:
                cleanup_errors.append(error)

        if active_exception is not None:
            record_failure("runtime", active_exception)

        # Start timing for cleanup
        if hasattr(self, "timing_manager") and self.timing_manager:
            try:
                self.timing_manager.start_component("cleanup")
            except BaseException as error:
                record_failure("cleanup_timing_start", error)

        # Check if shutdown was requested
        try:
            interrupted = bool(interrupted or self.is_shutdown_requested())
        except BaseException as error:
            record_failure("shutdown_state", error)

        async def log_cleanup(level: str, message: str) -> None:
            """
            Log cleanup.

            Cleanup diagnostics are part of the same publication transaction.
            Losing them must retain a truthful failed RunResult and close every
            consumable-output path; the shared privacy sanitizer below still
            runs as a fail-closed backstop.

            Args:
                level: Text supplied as level in the format accepted by this
                    function.
                message: Operator-facing text carried by the reported event or
                    failure.
            """
            try:
                await self.logger.log_runtime(
                    level,
                    "WorkflowOrchestrator",
                    message,
                )
            except BaseException as error:
                # Cleanup diagnostics are part of the same publication
                # transaction. Losing them must retain a truthful failed
                # RunResult and close every consumable-output path; the shared
                # privacy sanitizer below still runs as a fail-closed backstop.
                record_failure("cleanup_logging", error)

        async def run_teardown_phase(
            phase: str,
            callback: Any,
            *,
            success_message: Optional[str] = None,
            failure_message: Optional[str] = None,
        ) -> bool:
            """
            Run one mandatory phase with exact, group-safe semantics.

            A phase completes only when its callback returns exactly ``None``.
            Every ``BaseException`` (including nested exception groups) is
            retained by ``record_failure`` and cannot prevent later teardown
            phases from running. Pre-feature optional hooks are represented by
            callbacks which return ``None`` when absent; an installed hook is
            never interpreted by truthiness.

            Args:
                phase: Text supplied as phase in the format accepted by this
                    function.
                callback: Callable invoked at the callback boundary.
                success_message: Optional success message; ``None`` selects the
                    function's default behavior.
                failure_message: Optional failure message; ``None`` selects the
                    function's default behavior.

            Returns:
                Whether the one mandatory phase with exact, group-safe semantics
                operation succeeds.

            Raises:
                ValueError: If unknown mandatory teardown phase: ``phase``.
                RuntimeError: If mandatory teardown phase repeated: ``phase``;
                    or mandatory teardown phase ``phase`` returned a value.
            """

            if phase not in MANDATORY_TEARDOWN_PHASES:
                raise ValueError(f"Unknown mandatory teardown phase: {phase}")
            if phase in completed_teardown_phases:
                raise RuntimeError(f"Mandatory teardown phase repeated: {phase}")
            try:
                result = callback()
                if inspect.isawaitable(result):
                    result = await result
                if result is not None:
                    raise RuntimeError(
                        f"Mandatory teardown phase {phase} returned a value"
                    )
            except BaseException as error:
                record_failure(phase, error)
                if failure_message:
                    await log_cleanup(
                        "WARNING",
                        f"{failure_message}: {type(error).__name__}",
                    )
                return False

            completed_teardown_phases.append(phase)
            if success_message:
                await log_cleanup("INFO", success_message)
            return True

        async def run_optional_teardown_hook(attribute: str) -> None:
            """
            Run optional teardown hook.

            The implementation uses ``attribute`` to run optional teardown hook.
            Terminal status is emitted only after optional teardown hook and its
            owned cleanup have completed. Owned asynchronous work is awaited
            before return, so completion does not leave an unobserved task
            behind. If the function cannot run optional teardown hook, its
            exception reaches the caller instead of being converted into a
            successful result.

            Args:
                attribute: Text supplied as attribute in the format accepted by
                    this function.

            Raises:
                TypeError: If teardown hook ``attribute`` is not callable.
                RuntimeError: If teardown hook ``attribute`` returned a value.
            """
            hook = getattr(self, attribute, None)
            if hook is None:
                return None
            if not callable(hook):
                raise TypeError(f"Teardown hook {attribute} is not callable")
            result = hook()
            if inspect.isawaitable(result):
                result = await result
            if result is not None:
                raise RuntimeError(f"Teardown hook {attribute} returned a value")
            return None

        await log_cleanup(
            "WARN" if interrupted else "INFO",
            (
                "Starting cleanup after interrupt..."
                if interrupted
                else "Starting cleanup..."
            ),
        )

        # Resolve publication mode once. A configuration failure is fail-closed:
        # required teardown continues, while metadata/report/archive publication
        # remains unauthorized.
        tool_config_for_cleanup: Any = {}
        dry_run = False
        try:
            tool_config_for_cleanup = self.config_manager.get_tool_config()
            dry_run = bool(
                tool_config_for_cleanup.get("dry_run", False)
                if isinstance(tool_config_for_cleanup, dict)
                else getattr(tool_config_for_cleanup, "dry_run", False)
            )
        except BaseException as error:
            record_failure("cleanup_configuration", error)

        catalog_only_mode = getattr(
            self, "catalog_only_mode", getattr(self, "quiet_mode", False)
        )
        collection_finalization_requested = bool(finalize_collection)
        terminal_snapshot_required = bool(
            collection_finalization_requested and not dry_run and not catalog_only_mode
        )
        planning_projection_required = bool(
            collection_finalization_requested and dry_run and not catalog_only_mode
        )

        dut_ids: List[str] = []
        try:
            if self.dut_manager:
                dut_ids = list(self.dut_manager.get_all_dut_ids())
        except BaseException as error:
            record_failure("dut_roster", error)

        status_receipt = empty_finalization_receipt(
            dut_roster=tuple(dut_ids),
            interrupted=interrupted,
        )
        self.finalization_receipt = status_receipt

        # Deferred extension cleanup must complete before final metadata,
        # reports, archives, and transport teardown.
        lifecycle_manager = getattr(self, "extension_lifecycle_manager", None)

        async def finalize_extension_lifecycle() -> None:
            """
            Finalize extension lifecycle.

            The implementation uses current instance state to finalize extension
            lifecycle. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind. If the function
            cannot finalize extension lifecycle, its exception reaches the
            caller instead of being converted into a successful result.

            Raises:
                RuntimeError: If extension lifecycle finalizer returned a value.
            """
            if lifecycle_manager is not None:
                result = lifecycle_manager.finalize()
                if inspect.isawaitable(result):
                    result = await result
                if result is not None:
                    raise RuntimeError("Extension lifecycle finalizer returned a value")

        await run_teardown_phase(
            "extension_lifecycle",
            finalize_extension_lifecycle,
            failure_message=(
                "Extension deferred cleanup or evidence publication failed"
            ),
        )

        # These hooks are no-op only while their feature owners are absent.
        # Request-capture integration binds ``finalize_request_capture`` to the
        # run-owned ``_close_request_capture_runtime`` so all capture children
        # drain before the snapshot.  Provenance integration must make an
        # unsealed required identity fail its phase rather than silently
        # returning success.
        await run_teardown_phase(
            "request_capture",
            lambda: run_optional_teardown_hook("finalize_request_capture"),
            failure_message="Request-capture finalization failed",
        )
        await run_teardown_phase(
            "run_provenance",
            lambda: run_optional_teardown_hook("finalize_run_provenance"),
            failure_message="Run-provenance finalization failed",
        )

        # A service coroutine can be cancelled before its ordinary ``finally``
        # path projects tracker state onto status.json and legacy summary
        # surfaces.  Reconcile those surfaces before the tracker freezes its
        # terminal snapshot. A child can cancel without a run-wide shutdown;
        # project its recorded cancellation without relabeling other work.
        try:
            await self._persist_interrupted_collector_evidence(
                project_unfinished=interrupted
            )
        except BaseException as error:
            record_failure("interrupted_collector_evidence", error)

        # Write "Completed at" timestamps to DUT runtime logs BEFORE finalizing execution summary
        # This ensures the execution summary can calculate correct DUT execution times from the logs
        if collection_finalization_requested:
            try:
                await self._write_completion_timestamps()
            except BaseException as error:
                record_failure("completion_timestamps", error)
                await log_cleanup(
                    "ERROR",
                    f"Failed to publish completion timestamps: {type(error).__name__}",
                )

        terminal_snapshot_ready = not terminal_snapshot_required
        status_tracker = getattr(self, "status_tracker", None)
        if (
            terminal_snapshot_required or planning_projection_required
        ) and status_tracker is None:
            record_failure(
                "status_snapshot",
                RuntimeError("Terminal status tracker is unavailable"),
            )
        elif terminal_snapshot_required:
            for attempt in range(2):
                try:
                    # The terminal owner always finalizes a real run, including
                    # an already-complete or empty plan. No status-count
                    # heuristic may bypass the durable commit.
                    if type(status_tracker) is CollectionStatusTracker:
                        candidate_receipt = await status_tracker.finalize(
                            interrupted=interrupted,
                            defer_close=True,
                        )
                    else:
                        # Test/offline compatibility doubles retain the original
                        # interface. Production always owns the concrete tracker.
                        candidate_receipt = await status_tracker.finalize(
                            interrupted=interrupted,
                        )
                    if not isinstance(candidate_receipt, FinalizationReceipt):
                        raise RuntimeError(
                            "Collection status tracker did not return a finalization receipt"
                        )
                    # Retain immutable evidence immediately. Validation below
                    # may itself fail or observe control flow.
                    status_receipt = candidate_receipt
                    self.finalization_receipt = status_receipt
                    if not bool(status_tracker.is_durably_finalized):
                        raise RuntimeError(
                            "Collection status tracker did not durably finalize"
                        )
                    validator = getattr(
                        status_tracker,
                        "validate_durable_snapshot",
                        None,
                    )
                    if not callable(validator):
                        raise RuntimeError(
                            "Collection status tracker cannot validate its snapshot"
                        )
                    committed_generation = (
                        validator(dut_ids, _allow_pending_run_result=True)
                        if type(status_tracker) is CollectionStatusTracker
                        else validator(dut_ids)
                    )
                    if (
                        not candidate_receipt.terminal_snapshot_committed
                        or candidate_receipt.committed_generation
                        != committed_generation
                        or candidate_receipt.dut_roster != tuple(dut_ids)
                    ):
                        raise RuntimeError(
                            "Collection status finalization receipt differs from "
                            "the durable snapshot"
                        )
                    terminal_snapshot_ready = True
                    break
                except BaseException as error:
                    error_receipt = getattr(error, "receipt", None)
                    if isinstance(error_receipt, FinalizationReceipt):
                        status_receipt = error_receipt
                        self.finalization_receipt = status_receipt
                    record_failure("status_snapshot", error, fatal=False)
                    if attempt == 0:
                        await log_cleanup(
                            "WARNING",
                            "Retrying durable status finalization after "
                            f"{type(error).__name__}",
                        )
                        continue
                    cleanup_errors.append(error)
                    await log_cleanup(
                        "ERROR",
                        "Failed to durably finalize collection status: "
                        f"{type(error).__name__}",
                    )

        publication_authorized = bool(
            collection_finalization_requested
            and terminal_snapshot_ready
            and not cleanup_errors
            and primary_control_flow is None
        )

        if publication_authorized and terminal_snapshot_required:
            try:
                bind_receipt = getattr(
                    self.execution_summary_manager,
                    "bind_finalization_receipt",
                    None,
                )
                if not callable(bind_receipt):
                    raise RuntimeError(
                        "Execution-summary consumer cannot bind finalization evidence"
                    )
                if type(self.execution_summary_manager) is ExecutionSummaryManager:
                    bind_receipt(
                        status_receipt,
                        _allow_pending_run_result=True,
                    )
                else:
                    bind_receipt(status_receipt)
            except BaseException as error:
                record_failure("execution_summary_receipt", error)
                publication_authorized = False

        try:
            # Runtime metadata may inspect the live target for platform
            # identity; dry-run retains the static metadata created during
            # initialization and skips the live refresh. Catalog-only commands
            # have no initialized DUTs and therefore publish no run metadata.
            if (
                publication_authorized
                and not cleanup_errors
                and self.dut_manager
                and not dry_run
                and not catalog_only_mode
            ):
                await self.reporting_engine.create_dut_metadata_files()
        except BaseException as error:
            record_failure("dut_metadata", error)

        for dut_id in (
            dut_ids
            if publication_authorized
            and not cleanup_errors
            and not dry_run
            and not catalog_only_mode
            else []
        ):
            try:
                await run_managed_filesystem_operation(
                    self.execution_summary_manager.ensure_zero_execution_summary, dut_id
                )
            except BaseException as error:
                record_failure("execution_summary_seed", error)
                break

        if publication_authorized and not cleanup_errors:
            try:
                await run_managed_filesystem_operation(
                    self.execution_summary_manager.finalize
                )
            except BaseException as error:
                record_failure("execution_summary", error)

        summary_paths: Dict[str, Any] = {}
        if publication_authorized and not cleanup_errors:
            try:
                summary_paths = self.execution_summary_manager.get_summary_file_paths()
            except BaseException as error:
                record_failure("execution_summary_paths", error)
            for dut_id, summary_path in summary_paths.items():
                await log_cleanup(
                    "INFO",
                    f"Execution summary finalized for {dut_id}: {summary_path}",
                )

        # Perform cleanup operations (this will finalize logger and add timing data)
        if (
            publication_authorized
            and not cleanup_errors
            and hasattr(self, "cleanup_manager")
            and self.cleanup_manager
        ):
            try:
                await self.cleanup_manager.cleanup(self.log_dir)
            except BaseException as error:
                record_failure("cleanup_manager", error)

        # Clean up DUT manager sessions to prevent "Unclosed client session" warnings.
        async def close_dut_manager_sessions() -> None:
            """
            Close DUT manager sessions.

            The implementation uses current instance state to close DUT manager
            sessions. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind. If the function
            cannot close DUT manager sessions, its exception reaches the caller
            instead of being converted into a successful result.

            Raises:
                RuntimeError: If DUT manager cleanup returned a value.
            """
            if self.dut_manager:
                result = self.dut_manager.cleanup()
                if inspect.isawaitable(result):
                    result = await result
                if result is not None:
                    raise RuntimeError("DUT manager cleanup returned a value")

        await run_teardown_phase(
            "dut_manager_sessions",
            close_dut_manager_sessions,
            success_message="DUT manager cleanup completed",
            failure_message="Error during DUT manager cleanup",
        )

        # Close every service even when another one raises process control.
        # Children are observed in configuration order and reported together;
        # ``record_failure`` recursively selects the authoritative control leaf.
        async def close_service_sessions() -> None:
            """
            Close service sessions.

            The implementation uses current instance state to close service
            sessions. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind. If the function
            cannot close service sessions, its exception reaches the caller
            instead of being converted into a successful result.

            Raises:
                TypeError: If ``service_name`` remote staging closer is not
                    callable; ``service_name`` Redfish session closer is not
                    callable; or ``service_name`` general session closer is not
                    callable.
                RuntimeError: If ``service_name`` remote staging closer returned
                    a value; ``service_name`` Redfish session closer returned a
                    value; or ``service_name`` general session closer returned a
                    value.
                Exception: If the function cannot close service sessions safely.
                BaseExceptionGroup: If service session teardown failed.
            """
            errors: List[BaseException] = []
            try:
                config_manager = getattr(self, "config_manager", None)
                cleanup_services = (
                    list(config_manager.services.items())
                    if config_manager is not None
                    else []
                )
            except BaseException as error:
                errors.append(error)
                cleanup_services = []

            for service_name, service in cleanup_services:
                try:
                    remote_staging_owner = inspect.getattr_static(
                        service, "close_owned_remote_staging", None
                    )
                    if remote_staging_owner is not None:
                        close_remote_staging = getattr(
                            service, "close_owned_remote_staging"
                        )
                        if not callable(close_remote_staging):
                            raise TypeError(
                                f"{service_name} remote staging closer is not callable"
                            )
                        result = close_remote_staging()
                        if inspect.isawaitable(result):
                            result = await result
                        if result is not None:
                            raise RuntimeError(
                                f"{service_name} remote staging closer returned a value"
                            )
                        await log_cleanup(
                            "INFO", f"Closed {service_name} remote staging"
                        )
                except BaseException as error:
                    errors.append(error)

                try:
                    close_redfish = getattr(service, "close_redfish_session", None)
                    if close_redfish is not None:
                        if not callable(close_redfish):
                            raise TypeError(
                                f"{service_name} Redfish session closer is not callable"
                            )
                        result = close_redfish()
                        if inspect.isawaitable(result):
                            result = await result
                        if result is not None:
                            raise RuntimeError(
                                f"{service_name} Redfish session closer returned a value"
                            )
                        await log_cleanup("INFO", f"Closed {service_name} session")
                except BaseException as error:
                    errors.append(error)

                try:
                    session = getattr(service, "session", None)
                    if session is not None:
                        close_session = getattr(session, "close", None)
                        if not callable(close_session):
                            raise TypeError(
                                f"{service_name} general session closer is not callable"
                            )
                        result = close_session()
                        if inspect.isawaitable(result):
                            result = await result
                        if result is not None:
                            raise RuntimeError(
                                f"{service_name} general session closer returned a value"
                            )
                        service.session = None
                        await log_cleanup(
                            "INFO", f"Closed {service_name} general session"
                        )
                except BaseException as error:
                    errors.append(error)

            if len(errors) == 1:
                raise errors[0]
            if errors:
                raise BaseExceptionGroup("Service session teardown failed", errors)

        await run_teardown_phase(
            "service_sessions",
            close_service_sessions,
            failure_message="Error during service session cleanup",
        )

        # Get tool config for skip flags
        # Use the tool_config passed to orchestrator if available, otherwise use config manager
        tool_config = tool_config_for_cleanup
        skip_html_reports = True
        skip_zip = True
        apply_sanitization = False
        generate_html = False
        report_format = "spa"
        try:
            cli_tool_config = getattr(self, "_tool_config_obj", None)
            if cli_tool_config is not None:
                skip_html_reports = bool(
                    cli_tool_config.get("skip_html_reports", False)
                    if isinstance(cli_tool_config, dict)
                    else getattr(cli_tool_config, "skip_html_reports", False)
                )
            else:
                skip_html_reports = bool(
                    tool_config.get("skip_html_reports", False)
                    if isinstance(tool_config, dict)
                    else getattr(tool_config, "skip_html_reports", False)
                )

            skip_zip = bool(
                tool_config.get("skip_zip", False)
                if isinstance(tool_config, dict)
                else getattr(tool_config, "skip_zip", False)
            )

            apply_sanitization = (
                bool(
                    cli_tool_config.get("apply_sanitization", False)
                    if isinstance(cli_tool_config, dict)
                    else getattr(cli_tool_config, "apply_sanitization", False)
                )
                if cli_tool_config is not None
                else bool(
                    tool_config.get("apply_sanitization", False)
                    if isinstance(tool_config, dict)
                    else getattr(tool_config, "apply_sanitization", False)
                )
            )

            if isinstance(tool_config, dict):
                output_config = tool_config.get("output", {})
                generate_html = bool(
                    output_config.get("generate_html", True)
                    if isinstance(output_config, dict)
                    else tool_config.get("GENERATE_HTML_REPORTS", True)
                )
                report_format = tool_config.get("report_format", "spa")
            else:
                generate_html = bool(
                    getattr(tool_config, "GENERATE_HTML_REPORTS", True)
                )
                report_format = getattr(tool_config, "report_format", "spa")
        except BaseException as error:
            record_failure("publication_configuration", error)

        generate_spa_after_logger = (
            not skip_html_reports and generate_html and report_format in ("spa", "both")
        )

        # Always create the metadata-only handoff so it is packaged even when
        # HTML report generation is disabled. This never uploads core content.
        if publication_authorized and not cleanup_errors:
            try:
                await self._generate_openbmc_coredump_handoff()
            except BaseException as error:
                record_failure("openbmc_coredump_handoff", error)

        # Append execution order table at the end of the DUT runtime log
        if publication_authorized and not cleanup_errors:
            try:
                self._append_execution_order_table_to_runtime_log()
                # Write execution order metadata json for each DUT
                self._write_execution_order_metadata()
            except BaseException as error:
                record_failure("execution_order", error)

        # Freeze resource telemetry before logger finalization, SPA manifest
        # generation, and archive creation so every packaged copy is stable.
        async def stop_resource_monitor_phase() -> None:
            """
            Stop resource monitor phase.

            The implementation uses current instance state to stop resource
            monitor phase. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind. If the function
            cannot stop resource monitor phase, its exception reaches the caller
            instead of being converted into a successful result.

            Raises:
                RuntimeError: If resource monitor finalizer returned a value.
            """
            result = self.stop_resource_monitor(dut_ids=dut_ids)
            if inspect.isawaitable(result):
                result = await result
            if result is not None:
                raise RuntimeError("Resource monitor finalizer returned a value")

        await run_teardown_phase(
            "resource_monitor",
            stop_resource_monitor_phase,
            failure_message="Resource monitor finalization failed",
        )

        # Finalize logger (this will close file handles and restore stdout/stderr)
        async def finalize_logger_phase() -> None:
            """
            Finalize logger phase.

            The implementation uses current instance state to finalize logger
            phase. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind. If the function
            cannot finalize logger phase, its exception reaches the caller
            instead of being converted into a successful result.

            Raises:
                RuntimeError: If required logger finalizer is unavailable; or
                    logger finalizer returned a value.
            """
            cleanup_manager = getattr(self, "cleanup_manager", None)
            if cleanup_manager is not None:
                finalizer = getattr(cleanup_manager, "finalize_logger", None)
            else:
                finalizer = getattr(getattr(self, "logger", None), "finalize", None)
            if not callable(finalizer):
                raise RuntimeError("Required logger finalizer is unavailable")
            result = finalizer()
            if inspect.isawaitable(result):
                result = await result
            if result is not None:
                raise RuntimeError("Logger finalizer returned a value")

        await run_teardown_phase(
            "logger",
            finalize_logger_phase,
            failure_message="Logger finalization failed",
        )

        # The session sweep is mandatory teardown, not post-publication
        # housekeeping. No sanitizer, manifest, or archive may run before it.
        async def sweep_aiohttp_sessions() -> None:
            """
            Sweep aiohttp sessions.

            The implementation uses current instance state to sweep aiohttp
            sessions. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind. If the function
            cannot sweep aiohttp sessions, its exception reaches the caller
            instead of being converted into a successful result.

            Raises:
                RuntimeError: If clientSession closer returned a value.
                Exception: If the function cannot sweep aiohttp sessions safely.
                BaseExceptionGroup: If aiohttp session sweep failed.
            """
            errors: List[BaseException] = []
            gc.collect()
            for obj in gc.get_objects():
                if isinstance(obj, aiohttp.ClientSession):
                    if not obj.closed:
                        await log_cleanup(
                            "WARNING",
                            f"Found unclosed ClientSession: {obj}, closing it",
                        )
                        try:
                            result = obj.close()
                            if inspect.isawaitable(result):
                                result = await result
                            if result is not None:
                                raise RuntimeError(
                                    "ClientSession closer returned a value"
                                )
                        except BaseException as error:
                            errors.append(error)

            await log_cleanup(
                "INFO",
                "Final aggressive cleanup completed",
            )
            if len(errors) == 1:
                raise errors[0]
            if errors:
                raise BaseExceptionGroup("aiohttp session sweep failed", errors)

        await run_teardown_phase(
            "aiohttp_session_sweep",
            sweep_aiohttp_sessions,
            failure_message="Error during final aggressive cleanup",
        )

        missing_teardown = tuple(
            phase
            for phase in MANDATORY_TEARDOWN_PHASES
            if phase not in completed_teardown_phases
        )
        if missing_teardown and not cleanup_errors and primary_control_flow is None:
            record_failure(
                "mandatory_teardown",
                RuntimeError(
                    "Mandatory teardown phases did not complete: "
                    + ", ".join(missing_teardown)
                ),
            )

        # Command-owned ephemeral credentials/configuration are part of the
        # same terminal transaction.  They must be removed before a success
        # RunResult or any report/archive can be published.
        pre_terminal_cleanup = getattr(self, "pre_terminal_cleanup", None)
        if callable(pre_terminal_cleanup):
            try:
                cleanup_result = pre_terminal_cleanup()
                if cleanup_result is not None:
                    raise RuntimeError(
                        "Pre-terminal cleanup returned an unexpected result"
                    )
            except BaseException as error:
                record_failure("cli_temporary_config_cleanup", error)

        # Managed publication rollback may deliberately leave a replacement
        # inode at the excluded lexical name because that inode is not owned by
        # this run. Fail the terminal delivery transaction before reports, ZIP
        # creation, or loose-directory publication can expose those bytes.
        if collection_finalization_requested:
            delivery_validator = getattr(
                type(self.logger),
                "validate_managed_publication_exclusions_for_delivery",
                None,
            )
            if callable(delivery_validator):
                try:
                    validation_result = delivery_validator(self.logger)
                    if inspect.isawaitable(validation_result):
                        validation_result = await validation_result
                    if validation_result is not None:
                        raise RuntimeError(
                            "Managed publication delivery validator returned a value"
                        )
                except BaseException as error:
                    record_failure("managed_publication_delivery", error)

        # A fully initialized non-collection command owns the tracker's pinned
        # output descriptor, but it has no run lifecycle to freeze or publish.
        # Release that ownership explicitly instead of declaring an empty run
        # solely to satisfy collection finalization.
        if (
            not collection_finalization_requested
            and type(status_tracker) is CollectionStatusTracker
        ):
            try:
                await status_tracker.aclose()
            except BaseException as error:
                record_failure("status_tracker_abort", error)

        # The optional persistent POST guard owns terminal evidence that can
        # fail validation. Close it while the loose status tree is still
        # available, before a RunResult, report, or archive is published. Its
        # inactive path is a strict no-op.
        preliminary_receipt = status_receipt.with_interruption(
            interrupted
        ).with_cleanup_evidence(
            completed_teardown_phases=tuple(completed_teardown_phases),
            failures=merged_failure_evidence(
                status_receipt.failures,
                receipt_failures,
            ),
        )
        if collection_finalization_requested:
            try:
                preliminary_result = (
                    RunResult.from_planning_receipt(preliminary_receipt)
                    if dry_run
                    else RunResult.from_finalization_receipt(preliminary_receipt)
                )
                runtime_clean = bool(
                    preliminary_result.runtime_status is RuntimeStatus.SUCCESS
                    and not cleanup_errors
                    and primary_control_flow is None
                    and not missing_teardown
                )
                self._finish_persistent_post_runtime(
                    planning_successful=bool(
                        terminal_snapshot_required
                        and runtime_clean
                        and preliminary_result.collection_status
                        is CollectionStatus.SUCCESS
                    ),
                    runtime_clean=runtime_clean,
                )
            except BaseException as error:
                record_failure("persistent_post_runtime", error)

        # Recheck after the final pre-publication hook. An externally installed
        # hook must not create a late occupant at a name whose managed owner
        # already failed durable adoption.
        if collection_finalization_requested:
            delivery_validator = getattr(
                type(self.logger),
                "validate_managed_publication_exclusions_for_delivery",
                None,
            )
            if callable(delivery_validator):
                try:
                    validation_result = delivery_validator(self.logger)
                    if inspect.isawaitable(validation_result):
                        validation_result = await validation_result
                    if validation_result is not None:
                        raise RuntimeError(
                            "Managed publication delivery validator returned a value"
                        )
                except BaseException as error:
                    record_failure("managed_publication_delivery", error)

        publication_authorized = bool(
            publication_authorized
            and not cleanup_errors
            and primary_control_flow is None
            and not missing_teardown
        )

        cleanup_manager = getattr(self, "cleanup_manager", None)
        required_identity_member_digests: tuple[tuple[str, int, str], ...] = ()
        required_planning_plan_snapshot: Optional[PlanningPlanSnapshot] = None
        if apply_sanitization and cleanup_manager is None:
            publication_authorized = False
            record_failure(
                "bundle_sanitization",
                RuntimeError(
                    "Post-collection sanitization was requested but the cleanup "
                    "manager is unavailable"
                ),
                fatal=False,
            )
            logger.warning(
                "Post-collection sanitization was requested but the cleanup "
                "manager is unavailable; the requested pass did not run"
            )
        elif apply_sanitization:
            # Once requested, the recursive privacy pass must finish before
            # reports or archives can publish the inspected tree. Failed
            # transactions retain their raw inputs and authenticated recovery
            # state locally; these must not enter a distributable archive.
            sanitization_report = None
            try:
                if (
                    terminal_snapshot_required
                    and terminal_snapshot_ready
                    and bool(status_receipt.snapshot_leaf_digests)
                ):
                    sanitization_report = (
                        await cleanup_manager.sanitize_distributable_bundle(
                            self.log_dir,
                            status_receipt=status_receipt,
                        )
                    )
                else:
                    sanitization_report = (
                        await cleanup_manager.sanitize_distributable_bundle(
                            self.log_dir
                        )
                    )
                sanitization_errors = getattr(sanitization_report, "errors", None)
                if not isinstance(sanitization_errors, (list, tuple)):
                    raise RuntimeError(
                        "Bundle sanitizer returned malformed failure accounting"
                    )
                if sanitization_errors:
                    publication_authorized = False
                    record_failure(
                        "bundle_sanitization_incomplete",
                        RuntimeError(
                            f"{len(sanitization_errors)} artifact(s) were not "
                            "fully inspected by post-collection sanitization"
                        ),
                        fatal=False,
                    )
                    logger.warning(
                        "Post-collection sanitization reported %d "
                        "artifact error(s); report and archive creation are blocked",
                        len(sanitization_errors),
                    )
            except Exception as error:
                publication_authorized = False
                record_failure("bundle_sanitization", error, fatal=False)
                sanitization_report = getattr(
                    cleanup_manager, "bundle_sanitization_report", None
                )
                if sanitization_report is None:
                    sanitization_report = BundleSanitizationReport(
                        errors=[
                            "post-collection sanitization aborted: "
                            f"{type(error).__name__}"
                        ]
                    )
                    cleanup_manager.bundle_sanitization_report = sanitization_report
                logger.warning(
                    "Post-collection sanitization could not complete (%s); "
                    "report and archive creation are blocked",
                    type(error).__name__,
                )
            if sanitization_report is not None:
                try:
                    self._persist_bundle_sanitization_metadata(sanitization_report)
                except Exception as error:
                    record_failure("bundle_sanitization_metadata", error, fatal=False)
                    publication_authorized = False

        # Snapshot consistency remains useful diagnostic evidence, but it is
        # not a release gate for reports or archives.
        snapshot_consistent = terminal_snapshot_ready
        if publication_authorized and terminal_snapshot_required:
            try:
                committed_generation = (
                    status_tracker.validate_durable_snapshot(
                        dut_ids,
                        _allow_pending_run_result=True,
                    )
                    if type(status_tracker) is CollectionStatusTracker
                    else status_tracker.validate_durable_snapshot(dut_ids)
                )
                if committed_generation != status_receipt.committed_generation:
                    raise RuntimeError(
                        "Final delivery gate differs from finalization evidence"
                    )
            except Exception as error:
                snapshot_consistent = False
                logger.warning(
                    "Snapshot inconsistency detected before report generation (%s); "
                    "continuing with report and archive creation",
                    type(error).__name__,
                )

        # Seal the identity only from the exact catalog captured at its loader,
        # the terminal resolved plan, and the public configuration bytes after
        # the privacy backstop has completed.  A missing input is a terminal
        # provenance failure and cannot leave reports or archives publishable.
        provenance_required = bool(
            collection_finalization_requested
            and not catalog_only_mode
            and type(status_tracker) is CollectionStatusTracker
            and (
                getattr(self, "_run_identity_required", False)
                or getattr(self, "_run_identity_catalog_facts", None) is not None
            )
        )
        if provenance_required:
            try:
                if not dry_run and not terminal_snapshot_ready:
                    raise RuntimeError("Terminal resolved plan is unavailable")
                if getattr(self, "_run_identity_catalog_facts", None) is None:
                    raise RuntimeError("Authoritative catalog facts were not captured")
                if getattr(self, "_run_identity_tool_config", None) is None:
                    raise RuntimeError("Resolved invocation facts were not captured")
                config_cohort = capture_effective_config_cohort(
                    self.log_dir,
                    status_receipt.dut_roster,
                )
                if dry_run:
                    initial_plan = getattr(
                        self,
                        "_run_identity_planning_plan",
                        None,
                    )
                    if type(initial_plan) is not PlanningPlanSnapshot:
                        raise RuntimeError(
                            "Authoritative planning artifact was not captured"
                        )
                    observed_plan = capture_planning_plan_snapshot(self.log_dir)
                    if observed_plan != initial_plan:
                        raise RuntimeError(
                            "Authoritative planning artifact changed before sealing"
                        )
                    run_identity = build_planning_run_identity(
                        tool_config=self._run_identity_tool_config,
                        catalog_facts=self._run_identity_catalog_facts,
                        receipt=status_receipt,
                        output_root=self.log_dir,
                        planning_plan=observed_plan,
                        tool_facts=self._get_run_identity_tool_facts(),
                        config_cohort=config_cohort,
                    )
                    required_planning_plan_snapshot = observed_plan
                else:
                    run_identity = build_run_identity(
                        tool_config=self._run_identity_tool_config,
                        catalog_facts=self._run_identity_catalog_facts,
                        receipt=status_receipt,
                        output_root=self.log_dir,
                        tool_facts=self._get_run_identity_tool_facts(),
                        config_cohort=config_cohort,
                    )
                status_receipt = status_receipt.with_run_identity(run_identity)
                required_identity_member_digests = config_cohort.member_digests
                self.finalization_receipt = status_receipt
            except BaseException as error:
                record_failure("run_provenance", error)
                publication_authorized = False

        # Commit the candidate/final invariant after all mandatory teardown and
        # sanitization but before any report or archive consumes the bundle.
        # Archive evidence is intentionally excluded from RunResult, so a clean
        # archive transaction cannot change these exact bytes.  A late failure
        # is reconciled against the retained loose tree below.
        run_result_candidate: Optional[RunResult] = None
        if (
            terminal_snapshot_required
            and not dry_run
            and terminal_snapshot_ready
            and type(status_tracker) is CollectionStatusTracker
        ):
            candidate_failures = merged_failure_evidence(
                status_receipt.failures,
                receipt_failures,
            )
            candidate_receipt = status_receipt.with_interruption(
                interrupted
            ).with_cleanup_evidence(
                completed_teardown_phases=tuple(completed_teardown_phases),
                failures=candidate_failures,
            )
            try:
                run_result_candidate = RunResult.from_finalization_receipt(
                    candidate_receipt
                )
                status_receipt = await status_tracker.commit_run_result(
                    run_result_candidate,
                    candidate_receipt,
                )
                status_tracker.project_run_result_metadata(run_result_candidate)
                self.run_result = run_result_candidate
                self.finalization_receipt = status_receipt
                # Close the internal pre-projection window before any report
                # consumer can observe the terminal snapshot.
                if type(self.execution_summary_manager) is ExecutionSummaryManager:
                    self.execution_summary_manager.bind_finalization_receipt(
                        status_receipt
                    )
            except BaseException as error:
                record_failure("run_result_projection", error)
                publication_authorized = False

        if (
            publication_authorized
            and not skip_html_reports
            and generate_html
            and report_format in ("legacy", "both")
        ):
            try:
                legacy_report_kwargs: Dict[str, Any] = {
                    "finalization_receipt": (
                        status_receipt if snapshot_consistent else None
                    )
                }
                if not snapshot_consistent:
                    legacy_report_kwargs["enforce_snapshot_consistency"] = False
                legacy_report_created = await self.generate_html_reports(
                    total_runtime,
                    collector_ids,
                    **legacy_report_kwargs,
                )
                if (
                    type(legacy_report_created)  # noqa: E721 - subclasses are rejected
                    is not bool  # noqa: E721 - subclasses are rejected
                    or not legacy_report_created  # noqa: E721 - subclasses are rejected
                ):  # noqa: E721 - subclasses are rejected
                    raise RuntimeError("Required legacy report generation failed")
            except BaseException as error:
                record_failure("legacy_report", error)
                # A report defect is terminal evidence, but it must not suppress
                # the independent SPA/archive stages.  The final receipt and
                # RunResult remain failed; a bound terminal override carries
                # that late truth when the archive has become immutable.

        # Build the SPA only after all mandatory teardown, sanitization, and
        # post-sanitization exact-byte validation.
        if publication_authorized and generate_spa_after_logger:
            try:
                spa_report_kwargs: Dict[str, Any] = {
                    "finalization_receipt": (
                        status_receipt if snapshot_consistent else None
                    )
                }
                if not snapshot_consistent:
                    spa_report_kwargs["enforce_snapshot_consistency"] = False
                spa_report_created = await self._generate_spa_report(
                    **spa_report_kwargs
                )
                if (
                    type(spa_report_created)  # noqa: E721 - subclasses are rejected
                    is not bool  # noqa: E721 - subclasses are rejected
                    or not spa_report_created  # noqa: E721 - subclasses are rejected
                ):  # noqa: E721 - subclasses are rejected
                    raise RuntimeError("Required SPA report generation failed")
            except BaseException as error:
                record_failure("spa_report", error)
                # Preserve the diagnostic while still attempting the archive.
                # Raw collector output remains valuable even without a report.

        # Retain the post-SPA snapshot check as diagnostic evidence only.
        if (
            publication_authorized
            and generate_spa_after_logger
            and terminal_snapshot_required
        ):
            try:
                committed_generation = status_tracker.validate_durable_snapshot(dut_ids)
                if committed_generation != status_receipt.committed_generation:
                    raise RuntimeError(
                        "Post-SPA status snapshot differs from finalization evidence"
                    )
            except Exception as error:
                snapshot_consistent = False
                logger.warning(
                    "Snapshot inconsistency detected after report generation (%s); "
                    "continuing with archive creation",
                    type(error).__name__,
                )

        zip_archive_path = None
        if publication_authorized and not skip_zip:
            try:
                archive_started = time.monotonic()
                # Keep the archive transaction and integrity verification, but
                # do not bind publication to snapshot leaf digests.
                archive_kwargs: Dict[str, Any] = {"expected_snapshot_leaf_digests": ()}
                if required_identity_member_digests:
                    archive_kwargs["required_member_digests"] = (
                        required_identity_member_digests
                    )
                zip_archive_path = await self.cleanup_manager.create_final_zip_archive(
                    self.log_dir,
                    **archive_kwargs,
                )
                if not zip_archive_path:
                    raise RuntimeError("Required archive creation failed")
                self.zip_archive_path = zip_archive_path
                archive_paths = (
                    tuple(zip_archive_path)
                    if isinstance(zip_archive_path, (list, tuple))
                    else (zip_archive_path,)
                )
                archive_evidence = validate_archive_artifact_digests(
                    getattr(
                        self.cleanup_manager,
                        "archive_artifact_digests",
                        (),
                    ),
                    archive_paths,
                )
                archive_duration_seconds = max(
                    0.0,
                    time.monotonic() - archive_started,
                )
                status_receipt = status_receipt.with_archive_evidence(
                    archive_evidence,
                    archive_duration_seconds=archive_duration_seconds,
                )
                # Retain completed archive evidence immediately so a process
                # control-flow event cannot fall back to an unbound path list.
                self.finalization_receipt = status_receipt
            except BaseException as error:
                verified_archive_paths = tuple(
                    Path(path)
                    for path in (getattr(error, "verified_archive_paths", ()) or ())
                )
                if verified_archive_paths:
                    try:
                        archive_evidence = validate_archive_artifact_digests(
                            getattr(
                                self.cleanup_manager,
                                "archive_artifact_digests",
                                (),
                            ),
                            verified_archive_paths,
                        )
                        self.zip_archive_path = (
                            list(verified_archive_paths)
                            if len(verified_archive_paths) > 1
                            else verified_archive_paths[0]
                        )
                        status_receipt = status_receipt.with_archive_evidence(
                            archive_evidence,
                            archive_duration_seconds=max(
                                0.0,
                                time.monotonic() - archive_started,
                            ),
                        )
                        self.finalization_receipt = status_receipt
                    except BaseException as evidence_error:
                        record_failure("archive_evidence", evidence_error)
                record_failure("archive", error)
                publication_authorized = False

        # Cleanup timing includes archive compression, splitting, verification,
        # and durability. A telemetry-recorder defect cannot invalidate exact
        # archive evidence after the loose tree has been removed; process
        # control-flow exceptions remain authoritative and are preserved.
        if hasattr(self, "timing_manager") and self.timing_manager:
            try:
                self.timing_manager.end_component("cleanup")
            except BaseException as error:
                if is_control_flow_exception(error):
                    record_failure("cleanup_timing_end", error)
                    publication_authorized = False
                else:
                    try:
                        logger.warning(
                            "Cleanup timing finalization failed after local output "
                            "was finalized (%s)",
                            type(error).__name__,
                        )
                    except BaseException:
                        # Telemetry is never authoritative after an archive has
                        # replaced the loose source tree.
                        pass

        # ZIP creation binds the exact sanitized config members through the
        # existing archive validator.  When the loose tree remains authoritative,
        # repeat the same identity checks after every in-process report phase and
        # before the final RunResult commit marker is published.
        if (
            status_receipt.run_identity is not None
            and not status_receipt.archive_artifact_digests
        ):
            try:
                observed_config = capture_effective_config_cohort(
                    self.log_dir,
                    status_receipt.dut_roster,
                )
                if not hmac.compare_digest(
                    observed_config.sha256,
                    status_receipt.run_identity.effective_config_sha256,
                ):
                    raise RuntimeError(
                        "Effective configuration changed after identity sealing"
                    )
                if dry_run:
                    if required_planning_plan_snapshot is None:
                        raise RuntimeError(
                            "Sealed planning artifact evidence is unavailable"
                        )
                    observed_plan = capture_planning_plan_snapshot(self.log_dir)
                    if observed_plan != required_planning_plan_snapshot:
                        raise RuntimeError(
                            "Planning artifact changed after identity sealing"
                        )
            except BaseException as error:
                record_failure("run_provenance_revalidation", error)
                publication_authorized = False

        status_receipt = status_receipt.with_interruption(interrupted)
        combined_failures = merged_failure_evidence(
            status_receipt.failures,
            receipt_failures,
        )
        finalization_receipt = status_receipt.with_cleanup_evidence(
            completed_teardown_phases=tuple(completed_teardown_phases),
            failures=combined_failures,
        )

        # Reconcile every fallible post-candidate phase. A clean ZIP adds only
        # delivery evidence and must reproduce the exact candidate RunResult.
        # Failures without a verified archive retain the loose tree and commit
        # a new failed result before that tree can be consumed. If a verified
        # archive already replaced the tree, a bound override marks the earlier
        # candidate result non-consumable.
        if (
            terminal_snapshot_required
            and type(status_tracker) is CollectionStatusTracker
        ):
            reconcile_failure_start = len(receipt_failures)
            loose_tree_retained = False
            try:
                final_result = RunResult.from_finalization_receipt(finalization_receipt)
                if finalization_receipt.archive_artifact_digests:
                    loose_tree_retained = False
                else:
                    try:
                        status_tracker._revalidate_output_root_path()
                    except (
                        FileNotFoundError,
                        NotADirectoryError,
                        OSError,
                        RuntimeError,
                    ):
                        loose_tree_retained = False
                    else:
                        loose_tree_retained = True
                candidate_changed = final_result != run_result_candidate
                if loose_tree_retained:
                    finalization_receipt = await status_tracker.commit_run_result(
                        final_result,
                        finalization_receipt,
                    )
                    status_tracker.project_run_result_metadata(final_result)
                    self.run_result = final_result

                    if candidate_changed and not skip_html_reports and generate_html:
                        report_retry_error: Optional[BaseException] = None
                        try:
                            report_retry_ok = True
                            if report_format in ("legacy", "both"):
                                report_retry_ok = bool(
                                    await self.generate_html_reports(
                                        total_runtime,
                                        collector_ids,
                                        finalization_receipt=finalization_receipt,
                                    )
                                )
                            if report_retry_ok and report_format in (
                                "spa",
                                "both",
                            ):
                                report_retry_ok = bool(
                                    await self._generate_spa_report(
                                        finalization_receipt=finalization_receipt
                                    )
                                )
                            if not report_retry_ok:
                                raise RuntimeError(
                                    "Failed to regenerate reports from final RunResult"
                                )
                        except BaseException as error:
                            report_retry_error = error

                        if report_retry_error is not None:
                            prior_failure_count = len(receipt_failures)
                            record_failure("report_reprojection", report_retry_error)
                            reprojection_failures = tuple(
                                receipt_failures[prior_failure_count:]
                            )
                            finalization_receipt = (
                                finalization_receipt.with_cleanup_evidence(
                                    completed_teardown_phases=tuple(
                                        completed_teardown_phases
                                    ),
                                    failures=merged_failure_evidence(
                                        finalization_receipt.failures,
                                        reprojection_failures,
                                    ),
                                )
                            )
                            final_result = RunResult.from_finalization_receipt(
                                finalization_receipt
                            )
                            finalization_receipt = (
                                await status_tracker.commit_run_result(
                                    final_result,
                                    finalization_receipt,
                                )
                            )
                            status_tracker.project_run_result_metadata(final_result)
                            self.run_result = final_result
                            reconcile_failure_start = len(receipt_failures)

                            root_descriptor = status_tracker._require_output_root_fd()
                            try:
                                report_metadata = os.stat(
                                    "reports",
                                    dir_fd=root_descriptor,
                                    follow_symlinks=False,
                                )
                            except FileNotFoundError:
                                report_metadata = None
                            if report_metadata is not None:
                                if not stat.S_ISDIR(report_metadata.st_mode):
                                    raise RuntimeError(
                                        "Failed report projection is not a directory"
                                    )
                                os.rename(
                                    "reports",
                                    f".reports-invalid-{secrets.token_hex(16)}",
                                    src_dir_fd=root_descriptor,
                                    dst_dir_fd=root_descriptor,
                                )
                                os.fsync(root_descriptor)
                    finalization_receipt = await status_tracker.commit_run_result(
                        final_result,
                        finalization_receipt,
                        close=True,
                    )
                else:
                    if candidate_changed:
                        raw_archives = getattr(self, "zip_archive_path", None)
                        archive_paths = (
                            list(raw_archives)
                            if isinstance(raw_archives, (list, tuple))
                            else [raw_archives] if raw_archives else []
                        )
                        if not archive_paths:
                            raise RuntimeError(
                                "Final RunResult changed after the loose tree disappeared"
                            )
                        write_terminal_outcome_override_evidence(
                            receipt=finalization_receipt,
                            run_result=final_result,
                            run_directory=Path(self.log_dir),
                            archive_paths=[Path(path) for path in archive_paths],
                        )
                    await status_tracker.aclose()
                    self.run_result = final_result
            except BaseException as error:
                record_failure("run_result_finalization", error)
                reconciliation_failures = tuple(
                    receipt_failures[reconcile_failure_start:]
                )
                finalization_receipt = finalization_receipt.with_cleanup_evidence(
                    completed_teardown_phases=tuple(completed_teardown_phases),
                    failures=merged_failure_evidence(
                        finalization_receipt.failures,
                        reconciliation_failures,
                    ),
                )
                try:
                    if loose_tree_retained and status_tracker._output_root_fd >= 0:
                        failed_result = RunResult.from_finalization_receipt(
                            finalization_receipt
                        )
                        finalization_receipt = await status_tracker.commit_run_result(
                            failed_result,
                            finalization_receipt,
                        )
                        status_tracker.project_run_result_metadata(failed_result)
                        await status_tracker.aclose()
                        self.run_result = failed_result
                    else:
                        await status_tracker.aclose()
                except BaseException:
                    try:
                        await status_tracker.aclose()
                    except BaseException:
                        pass

        if (
            collection_finalization_requested
            and dry_run
            and not catalog_only_mode
            and type(status_tracker) is CollectionStatusTracker
        ):
            reconcile_failure_start = len(receipt_failures)
            try:
                final_result = RunResult.from_planning_receipt(finalization_receipt)
                finalization_receipt = await status_tracker.commit_planning_run_result(
                    final_result,
                    finalization_receipt,
                )
                self.run_result = final_result
            except BaseException as error:
                record_failure("planning_run_result_finalization", error)
                reconciliation_failures = tuple(
                    receipt_failures[reconcile_failure_start:]
                )
                finalization_receipt = finalization_receipt.with_cleanup_evidence(
                    completed_teardown_phases=tuple(completed_teardown_phases),
                    failures=merged_failure_evidence(
                        finalization_receipt.failures,
                        reconciliation_failures,
                    ),
                )
                try:
                    failed_result = RunResult.from_planning_receipt(
                        finalization_receipt
                    )
                    finalization_receipt = (
                        await status_tracker.commit_planning_run_result(
                            failed_result,
                            finalization_receipt,
                        )
                    )
                    self.run_result = failed_result
                except BaseException:
                    pass
            # The root RunResult is already the durable terminal commit marker.
            # Descriptor release cannot safely become new outcome evidence after
            # publication: close(2) may release the FD and still report an error,
            # leaving no authority with which to replace the committed result.
            try:
                await status_tracker.aclose()
            except BaseException as error:
                try:
                    logger.warning(
                        "Planning publication descriptor cleanup reported %s "
                        "after the terminal result was committed",
                        type(error).__name__,
                    )
                except BaseException:
                    pass
        self.finalization_receipt = finalization_receipt

        if primary_control_flow is not None:
            raise attach_finalization_receipt(
                primary_control_flow,
                finalization_receipt,
            )

        if cleanup_errors:
            raise FinalizationReceiptError(finalization_receipt) from cleanup_errors[0]

        return finalization_receipt

    def _setup_signal_handlers(self) -> None:
        """
        Setup signal handlers for graceful cleanup on interruption.

        Registers handlers for SIGINT and SIGTERM to enable graceful shutdown.
        """

        def signal_handler(signum, frame):
            """
            Handle interruption signals.

            The implementation uses ``signum`` and ``frame`` to handle
            interruption signals. Terminal status is emitted only after
            interruption signals and its owned cleanup have completed. It
            updates ``_shutdown_requested`` and ``_signal_handler_called`` on
            the instance as part of that state transition. If the function
            cannot handle interruption signals, its exception reaches the caller
            instead of being converted into a successful result.

            Args:
                signum: Signum consumed while the function attempts to handle
                    interruption signals.
                frame: Frame consumed while the function attempts to handle
                    interruption signals.

            Raises:
                KeyboardInterrupt: If shutdown requested.
            """
            # Prevent multiple signal handler calls
            if self._signal_handler_called:
                print(f"\nReceived signal {signum} again, forcing immediate exit...")
                import os

                os._exit(128 + int(signum))

            self._signal_handler_called = True
            print(f"\nReceived signal {signum}, stopping execution...")
            self._shutdown_requested = True

            # Try to interrupt the current event loop
            try:
                loop = asyncio.get_running_loop()
                # Cancel all running tasks to force immediate interruption
                for task in asyncio.all_tasks(loop):
                    if not task.done():
                        task.cancel()
                        # Don't print task cancellation messages - too verbose
            except RuntimeError:
                # No event loop running
                pass

            # Also raise KeyboardInterrupt to be caught by the main function's handler
            # This provides a more immediate response
            raise KeyboardInterrupt("Shutdown requested")

        # Register signal handlers
        signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
        signal.signal(signal.SIGTERM, signal_handler)  # kill command

    async def _emergency_cleanup(self) -> None:
        """
        Emergency cleanup to close all ClientSessions when interrupted.

        Force garbage collection to find any unclosed sessions.
        """
        try:
            try:
                await self._close_request_capture_runtime()
            except BaseException:
                pass
            # Force garbage collection to find any unclosed sessions
            gc.collect()

            # Find any remaining ClientSession objects and close them
            closed_count = 0
            for obj in gc.get_objects():
                if isinstance(obj, aiohttp.ClientSession):
                    if not obj.closed:
                        try:
                            await obj.close()
                            closed_count += 1
                        except Exception:
                            # Silently handle errors during cleanup
                            pass

            if closed_count > 0:
                print(f"Cleaned up {closed_count} connection(s)")

        except Exception:
            # Silently handle errors during emergency cleanup
            pass

    def is_shutdown_requested(self) -> bool:
        """
        Check if shutdown has been requested via signal handler.

        The implementation uses current instance state to check if shutdown has
        been requested via signal handler. Every required invariant is checked
        before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Returns:
            Whether the if shutdown has been requested via signal handler
            operation succeeds.
        """
        return self._shutdown_requested

    def is_collector_applicable_for_baseboard(
        self,
        collector: Dict[str, Any],
        baseboard_info: Optional[str],
        node_type: Optional[str] = None,
    ) -> bool:
        """
        Check if a collector is applicable for a specific baseboard.

        This is a public method for use by other components.

        Args:
            collector: Mapping supplying fields for if a collector is applicable
                for a specific baseboard.
            baseboard_info: Text supplied as baseboard info in the format
                accepted by this function.
            node_type: Optional node type; ``None`` selects the function's
                default behavior.

        Returns:
            Whether the if a collector is applicable for a specific baseboard
            operation succeeds.

        Raises:
            ValueError: If baseboard is not defined in spreadsheet
                (configuration error).
        """
        try:
            if node_type:
                return self._is_collector_applicable(
                    collector, baseboard_info, node_type
                )
            return self._is_collector_applicable(collector, baseboard_info)
        except ValueError:
            # Re-raise ValueError as-is - it's a critical configuration error
            # that should stop execution. The error message is already formatted.
            raise

    def _generate_dut_specific_reason(
        self,
        original_reason: str,
        status: str,
        dut_baseboard: str,
        collector_info: Dict[str, Any],
    ) -> str:
        """
        Generate a DUT-specific reason message for multi-DUT environments.

        Check if it's due to tags or baseboard constraints.

        Args:
            original_reason: Text supplied as original reason in the format
                accepted by this function.
            status: Text supplied as status in the format accepted by this
                function.
            dut_baseboard: Text supplied as DUT baseboard in the format accepted
                by this function.
            collector_info: Mapping supplying fields for generate a DUT-specific
                reason message for multi-DUT environments.

        Returns:
            The canonical generate DUT specific reason text.
        """
        if status == "Included":
            return f"Collector is applicable for baseboard '{dut_baseboard}'"
        elif status == "Not applicable":
            # Check if it's due to tags or baseboard constraints
            tags = collector_info.get("tags", {})
            if isinstance(tags, dict):
                include_tags = tags.get("include", [])
                exclude_tags = tags.get("exclude", [])
            else:
                include_tags = []
                exclude_tags = []

            if exclude_tags:
                return f"Not applicable for baseboard '{dut_baseboard}' (Tags: {exclude_tags})"
            elif include_tags:
                return f"Not applicable for baseboard '{dut_baseboard}' (BaseboardConstraint)"
            else:
                return f"Not applicable for baseboard '{dut_baseboard}' (BaseboardConstraint)"
        else:
            # For other statuses, use the original reason
            return original_reason

    def _is_collector_applicable(
        self,
        collector: Dict[str, Any],
        baseboard_info: Optional[str],
        node_type: Optional[str] = None,
    ) -> bool:
        """
        Check if a collector is applicable for the current baseboard.

        Multi-DUT scenario - allow collector through global filter Per-DUT
        baseboard filtering will occur during execution.

        Args:
            collector: Mapping supplying fields for if a collector is applicable
                for the current baseboard.
            baseboard_info: Text supplied as baseboard info in the format
                accepted by this function.
            node_type: Optional node type; ``None`` selects the function's
                default behavior.

        Returns:
            Whether the if a collector is applicable for the current baseboard
            operation succeeds.

        Raises:
            ValueError: If the supplied input cannot be used to check if a
                collector is applicable for the current baseboard.
        """
        # Handle multi-DUT scenarios where baseboard_info is None
        # In these cases, baseboard filtering is deferred to per-DUT execution
        if baseboard_info is None:
            # Multi-DUT scenario - allow collector through global filter
            # Per-DUT baseboard filtering will occur during execution
            return True

        # Check for invalid baseboard values (empty string, "unknown", etc.)
        if not baseboard_info or baseboard_info.lower() == "unknown":
            # This is a critical configuration error - baseboard must be configured
            # The tool should not run without proper baseboard configuration
            self.sanitized_console.print_failure(
                "Baseboard is not configured or is unknown "
                f"('{baseboard_info}'), so collector compatibility cannot be determined.",
                title="Missing Baseboard Configuration",
                suggestions=(
                    "Configure the baseboard for this DUT in the DUT config file.",
                    "Use catalog-assisted platform detection before collector selection.",
                ),
            )
            sys.exit(1)

        baseboard_manager = None
        baseboard_type = None
        selected_group_names: list[str] = []
        if hasattr(self, "dut_manager") and self.dut_manager:
            baseboard_manager = self.dut_manager._get_baseboard_manager()
            if baseboard_manager:
                baseboard_type = baseboard_manager.get_baseboard_type(baseboard_info)
                if not isinstance(baseboard_type, str):
                    baseboard_type = None
                if baseboard_type is None:
                    raw_group_names = baseboard_manager.get_all_baseboard_types()
                    group_names = (
                        raw_group_names if isinstance(raw_group_names, list) else []
                    )
                    selected_group = next(
                        (
                            group_name
                            for group_name in group_names
                            if isinstance(group_name, str)
                            and group_name.casefold() == baseboard_info.casefold()
                        ),
                        None,
                    )
                    if selected_group is not None:
                        baseboard_type = selected_group
                        raw_equivalent_groups = (
                            baseboard_manager.get_equivalent_baseboard_groups(
                                selected_group
                            )
                        )
                        if isinstance(raw_equivalent_groups, list):
                            selected_group_names = [
                                group_name
                                for group_name in raw_equivalent_groups
                                if isinstance(group_name, str)
                            ]
        effective_baseboard_names = [baseboard_info]
        effective_baseboard_uppers = [
            member.upper() for member in effective_baseboard_names
        ]

        def _normalize_constraint_values(value):
            """
            Normalize constraint values.

            The implementation uses ``value`` to normalize constraint values.
            The source value keeps its ownership while the normalized
            representation is returned separately.

            Args:
                value: Value evaluated while performing constraint values.

            Returns:
                Normalized applicability values suitable for exact membership
                comparison.
            """
            normalized = []

            def _flatten(item):
                """
                Flatten nested values into deterministic processing order.

                The implementation uses ``item`` to flatten nested values into
                deterministic processing order.

                Args:
                    item: Item object whose ``items`` and ``strip`` state is
                        read while performing flatten nested values into
                        deterministic processing order.
                """
                if item is None:
                    return
                if isinstance(item, str):
                    trimmed = item.strip()
                    if trimmed:
                        normalized.append(trimmed)
                    return
                if isinstance(item, list):
                    for child in item:
                        _flatten(child)
                    return
                if isinstance(item, dict):
                    for key, flag in item.items():
                        include = True
                        if isinstance(flag, bool):
                            include = flag
                        elif isinstance(flag, str):
                            include = flag.strip().lower() not in (
                                "false",
                                "0",
                                "no",
                                "off",
                            )
                        elif isinstance(flag, (int, float)):
                            include = bool(flag)
                        if include:
                            normalized.append(str(key).strip())
                    return
                normalized.append(str(item).strip())

            _flatten(value)
            return [item for item in normalized if item]

        def _constraint_matches(spec: str) -> bool:
            """
            Return the constraint matches.

            The implementation uses ``spec`` to produce the constraint matches.

            Args:
                spec: Text supplied as spec in the format accepted by this
                    function.

            Returns:
                Whether the constraint matches operation succeeds.
            """
            spec_upper = spec.upper()
            if spec_upper in {"ALL", "*"}:
                return True
            if spec_upper in effective_baseboard_uppers:
                return True
            if baseboard_type and baseboard_type.upper() == spec_upper:
                return True
            if node_type and node_type.upper() == spec_upper:
                return True
            if spec_upper in {
                group_name.upper() for group_name in selected_group_names
            }:
                return True
            if baseboard_manager:
                group_members = baseboard_manager.get_baseboards_in_group(spec)
                group_members_upper = [member.upper() for member in group_members]
                if group_members and any(
                    effective in group_members_upper
                    for effective in effective_baseboard_uppers
                ):
                    return True
            return False

        exclude_baseboards = _normalize_constraint_values(
            collector.get("exclude_baseboards")
        )
        if any(_constraint_matches(spec) for spec in exclude_baseboards):
            return False

        # Check applicable_baseboards field (YAML-based method)
        applicable_baseboards = collector.get("applicable_baseboards", "all")

        # Handle empty/None applicable_baseboards (treat as "all")
        if applicable_baseboards is None or applicable_baseboards == "":
            applicable_baseboards = "all"

        applicable_specs = _normalize_constraint_values(applicable_baseboards)
        if any(spec.upper() in {"ALL", "*"} for spec in applicable_specs):
            # Applicable to all baseboards
            pass  # Continue to check tags if any
        elif isinstance(applicable_baseboards, list):
            # Use BaseboardManager for proper baseboard type matching
            if hasattr(self, "dut_manager") and self.dut_manager:
                if baseboard_manager:
                    # If baseboard_type is None, check if baseboard_info is a group name
                    # This handles cases where platform detection returns a group name like "NVL"
                    # instead of a specific baseboard name like "GB200 NVL"
                    if baseboard_type is None:
                        all_groups = baseboard_manager.get_all_baseboard_types()
                        if baseboard_info.upper() in [g.upper() for g in all_groups]:
                            # baseboard_info is a valid group name, use it as the type
                            baseboard_type = baseboard_info
                        else:
                            # Baseboard not found in spreadsheet and not a valid group name
                            # This is a configuration error - the spreadsheet needs to be updated
                            try:
                                available_baseboards = sorted(
                                    baseboard_manager.baseboards.keys()
                                )
                            except (AttributeError, TypeError):
                                available_baseboards = []

                            available_str = (
                                f"Available baseboards: {available_baseboards}"
                                if available_baseboards
                                else "No baseboards found in spreadsheet"
                            )

                            error_msg = (
                                f"Baseboard '{baseboard_info}' is not defined in the spreadsheet. "
                                f"This is a configuration error. Please ensure the spreadsheet includes "
                                f"the baseboard. {available_str}"
                            )
                            raise ValueError(error_msg)

                    # Check exact names, primary types, node types, and any
                    # overlapping semantic groups loaded from the workbook.
                    baseboard_found = any(
                        _constraint_matches(applicable_bb)
                        for applicable_bb in applicable_baseboards
                    )

                    if not baseboard_found:
                        return False
                else:
                    # Fallback to exact string matching if BaseboardManager not available
                    baseboard = baseboard_info.upper()
                    node = node_type.upper() if node_type else None
                    baseboard_found = False
                    for applicable_bb in applicable_baseboards:
                        applicable_upper = applicable_bb.upper()
                        if applicable_upper == baseboard or (
                            node and applicable_upper == node
                        ):
                            baseboard_found = True
                            break
                    if not baseboard_found:
                        return False
            else:
                # Fallback to exact string matching if DUT manager not available
                baseboard = baseboard_info.upper()
                node = node_type.upper() if node_type else None
                baseboard_found = False
                for applicable_bb in applicable_baseboards:
                    applicable_upper = applicable_bb.upper()
                    if applicable_upper == baseboard or (
                        node and applicable_upper == node
                    ):
                        baseboard_found = True
                        break
                if not baseboard_found:
                    return False
        elif isinstance(applicable_baseboards, str):
            # Single baseboard constraint
            if applicable_baseboards.upper() != "ALL":
                # Use BaseboardManager for proper baseboard type matching
                if hasattr(self, "dut_manager") and self.dut_manager:
                    if baseboard_manager:
                        # If baseboard_type is None, check if baseboard_info is a group name
                        # This handles cases where platform detection returns a group name like "NVL"
                        # instead of a specific baseboard name like "GB200 NVL"
                        if baseboard_type is None:
                            all_groups = baseboard_manager.get_all_baseboard_types()
                            if baseboard_info.upper() in [
                                g.upper() for g in all_groups
                            ]:
                                # baseboard_info is a valid group name, use it as the type
                                baseboard_type = baseboard_info
                            else:
                                # Baseboard not found in spreadsheet and not a valid group name
                                # This is a configuration error - the spreadsheet needs to be updated
                                try:
                                    available_baseboards = sorted(
                                        baseboard_manager.baseboards.keys()
                                    )
                                except (AttributeError, TypeError):
                                    available_baseboards = []

                                available_str = (
                                    f"Available baseboards: {available_baseboards}"
                                    if available_baseboards
                                    else "No baseboards found in spreadsheet"
                                )

                                error_msg = (
                                    f"Baseboard '{baseboard_info}' is not defined in the spreadsheet. "
                                    f"This is a configuration error. Please ensure the spreadsheet includes "
                                    f"the baseboard. {available_str}"
                                )
                                raise ValueError(error_msg)

                        # Check exact names, primary types, node types, and any
                        # overlapping semantic groups.
                        if _constraint_matches(applicable_baseboards):
                            return True
                        # If neither matches, it's not applicable
                        return False
                    else:
                        # Fallback to exact string matching
                        applicable_upper = applicable_baseboards.upper()
                        if applicable_upper != baseboard_info.upper() and (
                            not node_type or applicable_upper != node_type.upper()
                        ):
                            return False
                else:
                    # Fallback to exact string matching
                    applicable_upper = applicable_baseboards.upper()
                    if applicable_upper != baseboard_info.upper() and (
                        not node_type or applicable_upper != node_type.upper()
                    ):
                        return False

        # Also check legacy tags format for backward compatibility
        tags = collector.get("tags", {})
        if isinstance(tags, dict):
            include_tags = tags.get("include", [])
            exclude_tags = tags.get("exclude", [])
        else:
            include_tags = []
            exclude_tags = []

        context_for_tags = " ".join(
            part
            for part in [
                baseboard_info,
                baseboard_type,
                node_type,
                *selected_group_names,
            ]
            if part
        ).upper()

        # Check exclude tags first
        for exclude_tag in exclude_tags:
            if exclude_tag.upper() in context_for_tags:
                return False

        # Check include tags
        if include_tags:
            for include_tag in include_tags:
                if include_tag.upper() in context_for_tags:
                    return True
            return False  # No include tags matched

        return True  # Passed all checks

    def _is_collector_level_applicable(
        self, collector_level: str, current_level: str
    ) -> bool:
        """
        Check if a collector level is applicable for the current collection level.

        L0 collectors are special - they only run when explicitly specified via
        CLI (--collector-id or --include-collectors) and never run by default in
        any level.

        Args:
            collector_level: Text supplied as collector level in the format
                accepted by this function.
            current_level: Text supplied as current level in the format accepted
                by this function.

        Returns:
            Whether the if a collector level is applicable for the current
            collection level operation succeeds.
        """
        # L0 collectors never run by default - they must be explicitly specified
        # They are filtered at the CLI level when specific collector IDs are provided
        if collector_level == "L0":
            return False

        level_mapping = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}

        collector_level_num = level_mapping.get(collector_level, 3)
        current_level_num = level_mapping.get(current_level, 3)

        return collector_level_num <= current_level_num

    def get_all_collectors(
        self, collection_level: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get all collector definitions, optionally filtered by collection level.

        If no collection level specified, return all collectors (backward
        compatibility).

        Args:
            collection_level: Optional collection level; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing all collectors.
        """
        all_collectors = self.config_manager.get_all_collectors()

        # If no collection level specified, return all collectors (backward compatibility)
        if collection_level is None:
            return all_collectors

        # Filter by collection level
        filtered_collectors = {}
        for collector_id, collector_info in all_collectors.items():
            collector_level = collector_info.get("collection_level", "L1")
            if self._is_collector_level_applicable(collector_level, collection_level):
                filtered_collectors[collector_id] = collector_info

        return filtered_collectors

    async def _create_redfish_sessions_with_progress(
        self, dut_ids: List[str], progress, session_task
    ) -> None:
        """
        Create Redfish sessions with progress tracking and shutdown handling.

        The implementation uses ``dut_ids``, ``progress``, and ``session_task``
        to create Redfish sessions with progress tracking and shutdown handling.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind. The operation mutates ``progress`` in
        place; ownership of those objects remains with the caller.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            progress: Progress object whose ``advance`` and ``update`` state is
                read while performing redfish sessions with progress tracking
                and shutdown handling.
            session_task: Session task consumed while the function attempts to
                create Redfish sessions with progress tracking and shutdown
                handling.
        """

        async def create_session_for_dut(dut_id: str) -> tuple:
            """
            Create Redfish session for a single DUT.

            The implementation uses ``dut_id`` to create Redfish session for a
            single DUT. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind.

            Args:
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.

            Returns:
                A tuple containing ``DUT identifier`` and ``status text`` in
                that order.
            """
            try:
                dut = self.dut_manager.get_dut(dut_id)
                if dut.connection_state.redfish_connected:
                    # Add timeout to prevent hanging
                    await _await_workflow_child_with_timeout(
                        dut.create_redfish_session(),
                        timeout=30.0,  # 30 second timeout per DUT
                    )
                    return dut_id, "success"
                else:
                    return dut_id, "skipped"
            except asyncio.TimeoutError:
                await self.logger.log_runtime(
                    "WARN",
                    "WorkflowOrchestrator",
                    f"Timeout creating Redfish session for {dut_id} (30s)",
                )
                return dut_id, "timeout"
            except Exception as e:
                await self.logger.log_runtime(
                    "WARN",
                    "WorkflowOrchestrator",
                    f"Failed to create Redfish session for {dut_id}: {str(e)}",
                )
                return dut_id, "failed"

        # Check if shutdown was requested
        if hasattr(self, "_shutdown_requested") and self._shutdown_requested:
            await self.logger.log_runtime(
                "WARN",
                "WorkflowOrchestrator",
                "Shutdown requested, stopping Redfish session creation",
            )
            return

        # Process all DUTs concurrently
        all_tasks = [
            asyncio.create_task(capture_owned_awaitable(create_session_for_dut(dut_id)))
            for dut_id in dut_ids
        ]
        all_results = await _drain_workflow_tasks(all_tasks)

        for j, result in enumerate(all_results):
            if isinstance(result, Exception):
                dut_id = dut_ids[j]
                await self.logger.log_runtime(
                    "ERROR",
                    "WorkflowOrchestrator",
                    f"Unexpected error creating session for DUT {dut_id}: {str(result)}",
                )
                progress.update(session_task, description=f"Error {dut_id}")
            else:
                dut_id, status = result
                if status == "success":
                    progress.update(
                        session_task,
                        description=f"Created session for {dut_id}",
                    )
                elif status == "skipped":
                    progress.update(
                        session_task,
                        description=f"Skipped {dut_id} (no Redfish)",
                    )
                elif status == "timeout":
                    progress.update(session_task, description=f"Timeout {dut_id}")
                else:  # failed
                    progress.update(session_task, description=f"Failed {dut_id}")

            progress.advance(session_task)

    async def _setup_progress_display(
        self,
        dut_ids: List[str],
        all_filtered_collectors: list,
        total_collectors: int,
        *,
        collectors_per_dut: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """
        Initialize progress state manager and display for collector execution.

        The implementation uses ``dut_ids``, ``all_filtered_collectors``, and
        ``total_collectors`` to initialize progress state manager and display
        for collector execution. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. It
        updates ``progress_display``, ``progress_state``, and
        ``progress_update_task`` on the instance as part of that state
        transition.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            all_filtered_collectors: Entries supplied as
                ``all_filtered_collectors`` without transferring container
                ownership.
            total_collectors: Numeric total collectors used while the operation
                performs bounded accounting.
            collectors_per_dut: Actual scheduled collectors for each DUT, used
                only for progress accounting. ``None`` preserves uniform plans
                for callers that do not provide per-DUT scope.
        """
        try:
            progress_state = ProgressStateManager(
                dut_ids,
                all_filtered_collectors,
                self.logger,
                self.console,
                collectors_per_dut=collectors_per_dut,
            )
            self.progress_state = progress_state
            self.progress_display = ProgressDisplay(self.console, self.logger)
            self.progress_display.set_progress_state(progress_state)
            await progress_state.initialize()
        except ImportError:
            self.progress_state = None
            self.progress_display = None

        if total_collectors > 0:
            self.console.print(
                f"\n[bold blue]Executing {total_collectors} Collectors[/bold blue]"
            )
            if self.progress_display:
                self.progress_display.start(dut_ids, total_collectors)
                self.progress_update_task = asyncio.create_task(
                    self._update_progress_periodically()
                )

    async def _teardown_progress_display(self) -> None:
        """
        Stop progress display and cancel the background update task.

        The implementation uses current instance state to stop progress display
        and cancel the background update task. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.
        """
        if hasattr(self, "progress_display") and self.progress_display:
            await self.progress_display.update()
            self.progress_display.stop()

        if hasattr(self, "progress_update_task") and self.progress_update_task:
            self.progress_update_task.cancel()
            try:
                await self.progress_update_task
            except asyncio.CancelledError:
                pass

    async def _log_to_all(
        self,
        level: str,
        component: str,
        message: str,
        dut_ids: List[str],
    ) -> None:
        """
        Log a message to both the runtime log and every DUT's runtime log.

        The implementation uses ``level``, ``component``, ``message``, and
        ``dut_ids`` to log a message to both the runtime log and every DUT's
        runtime log. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            component: Text supplied as component in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
        """
        await self.logger.log_runtime(level, component, message)
        for dut_id in dut_ids:
            await self.logger.write_to_dut_runtime_log(
                dut_id, level, component, message
            )

    async def _update_progress_periodically(self):
        """
        Update progress display periodically.

        The implementation uses current instance state to update progress
        display periodically. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.
        """
        try:
            while True:
                # Check for shutdown request
                if self.is_shutdown_requested():
                    break

                if hasattr(self, "progress_display") and self.progress_display:
                    await self.progress_display.update()
                await asyncio.sleep(0.5)  # Update every 500ms
        except asyncio.CancelledError:
            # Task was cancelled, exit gracefully
            pass
        except Exception:
            # Don't let progress update errors break execution
            pass
