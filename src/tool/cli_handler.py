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
CLI Handler Module for nvdebugtool.

This module contains the CLI handlers for various commands:

- CLIListCollectors: Handles list-collectors command.
- CLIDefaultCollectors: Handles default-collectors command.
- CLIPreflight: Handles preflight command.
- BaseCLICommand: Base class for common CLI functionality.
"""

import builtins
import copy
import gc
import getpass
import inspect
import json
import math
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Set,
)

import aiohttp
import click
import yaml
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .config import (
    DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT,
    Config,
    DUTConfig,
    ExecutionSectionConfig,
    SSHConnectionPoolConfig,
    load_config,
    load_dut_config,
    load_yaml_strict,
    set_global_sanitization_enabled,
)
from .core.admission_controller import AdmissionControllerSettings
from .core.async_logger import AsyncSafeLogger
from .core.baseboard_manager import BaseboardManager
from .core.finalization_receipt import (
    FinalizationReceipt,
    attach_finalization_receipt,
    finalization_failures_allow_delivery,
    is_control_flow_exception,
    is_interruption_exception,
    sanitize_finalization_failure,
    select_authoritative_exception,
    validate_structural_finalization_receipt,
)
from .core.run_result import (
    EXPLICIT_SELECTION_EVIDENCE_PATH,
    CollectionStatus,
    DeliveryResult,
    RunMode,
    RunResult,
    RuntimeStatus,
)
from .core.scheduling_plan import build_scheduling_summary, format_scheduling_summary
from .core.workflow_orchestrator import (
    WorkflowOrchestrator,
    spa_report_asset_failure_message,
)
from .services.redfish_pagination import DEFAULT_MAX_PAGINATION_PAGES
from .utils.artifact_components import require_safe_artifact_component
from .utils.bounded_archive import (
    read_regular_file_bounded,
    resolve_archive_limits,
)
from .utils.catalog_snapshot import CatalogSnapshot
from .utils.console_output import create_sanitized_console
from .utils.constants import ASCII_HEADER
from .utils.cpu_resources import resolve_collector_operation_resources
from .utils.logging import create_timestamped_log_dir, ensure_secure_log_directory
from .utils.output_formatter import OutputFormatter
from .utils.post_collection_outcome import PostCollectionOutcomePublisher
from .utils.redfish_limits import RedfishRequestCaptureLimits
from .utils.redfish_tls import (
    INSECURE_REDFISH_TRANSPORT_WARNING_MESSAGE,
    RedfishTLSPolicy,
)
from .utils.report_app_assets import (
    ReportAppAssetError,
    validate_report_app_index,
)
from .utils.resources import find_config_directory
from .utils.sanitizer import (
    create_sanitizer_from_config,
    extract_sensitive_fields_from_environment,
    neutralize_terminal_text,
    neutralize_text_controls,
    normalize_sensitive_canary_values,
    patch_print_with_sanitizer,
    redact_config_file_references,
    sanitize_config_text,
)
from .utils.spreadsheet_utils import auto_detect_spreadsheet
from .utils.ssh_proxy_projection import project_tool_ssh_proxy_defaults
from .utils.ssh_security import (
    INSECURE_SSH_HOST_KEY_WARNING_MESSAGE,
    InsecureSSHHostKeyWarning,
)
from .utils.trusted_extensions import redact_optional_config_mapping
from .utils.validation import display_dut_config_error, run_comprehensive_validation

_MAX_RACK_ID_LENGTH = 128


def _run_receipt_text(console: object, value: object) -> str:
    """
    Return one sanitized terminal-neutral value for the run receipt.

    The value passes through the caller-owned console sanitizer before terminal
    controls are neutralized. This keeps the table on the same disclosure
    boundary as ordinary line-oriented CLI output.

    Args:
        console: Sanitized console supplying the configured disclosure policy.
        value: Canonical run-result value to render.

    Returns:
        Sanitized single-line text suitable for a Rich table cell.
    """

    raw_value = value if type(value) is str else str(value)
    sanitizer = getattr(console, "sanitizer", None)
    sanitize = getattr(sanitizer, "sanitize", None)
    safe_value = sanitize(raw_value) if callable(sanitize) else raw_value
    return neutralize_terminal_text(safe_value)


def _run_status_style(value: str) -> str:
    """
    Return the presentation style for one canonical terminal status.

    Unknown future statuses remain visible with neutral bold styling rather
    than being assigned a misleading success or failure color.

    Args:
        value: Canonical runtime or collection status value.

    Returns:
        Rich style text for the supplied status.
    """

    return {
        "success": "bold green",
        "partial": "bold yellow",
        "incomplete": "bold yellow",
        "interrupted": "bold magenta",
        "failed": "bold red",
    }.get(value, "bold")


def _render_run_receipt_table(console: object, run_result: RunResult) -> bool:
    """
    Render the canonical run outcome as a compact interactive table.

    Tables are limited to interactive terminals so redirected output preserves
    the stable line-oriented contract used by automation. Presentation errors
    are contained and reported through the false return value, allowing the
    caller to emit that same fallback contract.

    Args:
        console: Sanitized console that owns the Rich output boundary.
        run_result: Validated terminal result for the completed operation.

    Returns:
        Whether the interactive table was rendered successfully.
    """

    try:
        rich_console = getattr(console, "console", None)
        print_renderable = getattr(console, "print_renderable", None)
        if getattr(rich_console, "is_terminal", False) is not True or not callable(
            print_renderable
        ):
            return False

        runtime_status = _run_receipt_text(
            console,
            run_result.runtime_status.value,
        )
        collection_status = _run_receipt_text(
            console,
            run_result.collection_status.value,
        )
        status = Text()
        status.append("Runtime ", style="dim")
        status.append(
            runtime_status.replace("_", " ").title(),
            style=_run_status_style(runtime_status),
        )
        status.append("  •  Collection ", style="dim")
        status.append(
            collection_status.replace("_", " ").title(),
            style=_run_status_style(collection_status),
        )

        table = Table(
            title=Text("Run Receipt", style="bold cyan"),
            box=box.ROUNDED,
            show_header=False,
            padding=(0, 1),
        )
        table.add_column(style="bold cyan", no_wrap=True)
        table.add_column(overflow="fold")
        table.add_row("Status", status)

        identity = run_result.run_identity
        if identity is not None:
            table.add_row(
                "Tool",
                Text(
                    _run_receipt_text(
                        console,
                        f"{identity.tool_version}  •  Build {identity.build_hash}",
                    )
                ),
            )
            table.add_row(
                "Catalog",
                Text(
                    _run_receipt_text(
                        console,
                        f"{identity.catalog_version}  •  "
                        f"{identity.resolved_level} / {identity.resolved_profile}",
                    )
                ),
            )
            table.add_row(
                "Source",
                Text(_run_receipt_text(console, identity.source_revision)),
            )
            table.add_row(
                "Identity SHA-256",
                Text(_run_receipt_text(console, identity.identity_sha256)),
            )

        if run_result.mode is RunMode.COLLECTION:
            counts = dict(run_result.collector_counts)
            collector_summary = "  •  ".join(
                (
                    f"Total {counts['total_collectors']}",
                    f"Completed {counts['completed_collectors']}",
                    f"Degraded {counts['degraded_collectors']}",
                    f"Partial {counts['partial_collectors']}",
                    f"Failed {counts['failed_collectors']}",
                    f"Skipped {counts['skipped_collectors']}",
                    f"Cancelled {counts['cancelled_collectors']}",
                )
            )
            table.add_row(
                "Collectors",
                Text(_run_receipt_text(console, collector_summary)),
            )

        print_renderable(table)
        return True
    except Exception:
        # Terminal decoration is optional. Preserve the stable line-oriented
        # fallback for redirected output and presentation failures.
        return False


def _validate_requested_spa_report_assets(
    tool_config: "ToolConfig",
    *,
    dry_run_mode: bool,
) -> None:
    """
    Fail before DUT work when a requested SPA cannot be published safely.

    The implementation uses ``tool_config`` and ``dry_run_mode`` to fail before
    DUT work when a requested SPA cannot be published safely. If the function
    cannot fail before DUT work when a requested SPA cannot be published safely,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        tool_config: Tool config governing fail before DUT work when a requested
            SPA cannot be published safely.
        dry_run_mode: Whether dry run mode is enabled or required for this
            operation.

    Raises:
        RuntimeError: If the function cannot fail before DUT work when a
            requested SPA cannot be published safely.
    """

    if (
        dry_run_mode
        or tool_config.skip_html_reports
        or tool_config.report_format not in {"spa", "both"}
    ):
        return
    packaged_index = Path(__file__).parent / "report_app_dist" / "index.html"
    try:
        validate_report_app_index(packaged_index)
    except ReportAppAssetError as error:
        raise RuntimeError(spa_report_asset_failure_message(error)) from error


def _require_safe_rack_id(value: Any) -> str:
    """
    Validate one bounded rack component before extending an output root.

    The implementation uses ``value`` to validate one bounded rack component
    before extending an output root. Every required invariant is checked before
    a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        value: Value evaluated while performing one bounded rack component
            before extending an output root.

    Returns:
        The validated ``rack_id``.

    Raises:
        ValueError: If invalid rack ID: maximum length is
            ``_MAX_RACK_ID_LENGTH`` characters.
    """

    rack_id = require_safe_artifact_component(value, "rack ID")
    if len(rack_id) > _MAX_RACK_ID_LENGTH:
        raise ValueError(
            f"Invalid rack ID: maximum length is {_MAX_RACK_ID_LENGTH} characters"
        )
    return rack_id


def _is_universal_baseboard_spec(value: Any) -> bool:
    """
    Return whether a scalar or flat collection contains ``all``/``*``.

    The implementation uses ``value`` to determine whether a scalar or flat
    collection contains ``all``/``*``.

    Args:
        value: Value evaluated while performing scalar or flat collection
            contains ``all``/``*``.

    Returns:
        Whether a scalar or flat collection contains ``all``/``*``.
    """
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, (list, tuple, set)):
        return False
    return any(
        isinstance(item, str) and item.strip().lower() in {"all", "*"}
        for item in values
    )


def _resolved_baseboard_value(*values: Any) -> Optional[str]:
    """
    Return the first non-empty normalized baseboard value.

    Configuration provenance controls which value reaches this runtime
    boundary, but presence alone does not make an empty or whitespace-only
    value usable. Keeping that distinction here gives startup reporting and
    auto-detection candidate selection one shared definition of resolution.

    Args:
        values: Candidate modern or legacy baseboard values in precedence order.

    Returns:
        The first stripped non-empty baseboard value, or ``None`` when every
        candidate remains unresolved.
    """

    for value in values:
        if isinstance(value, str):
            normalized = value.strip()
            if normalized:
                return normalized
    return None


def _format_container_summary(records: Any) -> str:
    """
    Summarize container breadth by depth without inventing a linear chain.

    The implementation uses ``records`` to summarize container breadth by depth
    without inventing a linear chain.

    Args:
        records: Entries supplied as ``records`` and processed in
            caller-provided order.

    Returns:
        The canonical container summary text.
    """

    if not isinstance(records, (list, tuple)):
        return ""

    by_depth: Dict[int, Counter[str]] = defaultdict(Counter)
    exceptional_statuses: Counter[str] = Counter()
    total = 0
    for record in records:
        if not isinstance(record, Mapping):
            continue
        total += 1
        raw_depth = record.get("depth", 0)
        try:
            depth = int(raw_depth) if not isinstance(raw_depth, bool) else 0
        except (TypeError, ValueError, OverflowError):
            depth = 0
        depth = max(depth, 0)
        container_type = str(record.get("type") or "unknown").strip().casefold()
        by_depth[depth][container_type or "unknown"] += 1

        status = str(record.get("status") or "unknown").strip().casefold()
        if status != "expanded":
            exceptional_statuses[status or "unknown"] += 1

    if not total:
        return ""

    segments = [f"{total} total"]
    for depth in sorted(by_depth):
        types = ", ".join(
            name if count == 1 else f"{name} x{count}"
            for name, count in sorted(by_depth[depth].items())
        )
        segments.append(f"depth {depth}: {types}")
    if exceptional_statuses:
        statuses = ", ".join(
            f"{name} x{count}" for name, count in sorted(exceptional_statuses.items())
        )
        segments.append(f"non-expanded: {statuses}")
    return "; ".join(segments)


_DOMAIN_RESULT_MAX_DEPTH = 64
_DOMAIN_RESULT_MAX_CONTAINERS = 65536
_DOMAIN_RESULT_IGNORED_BRANCHES = {
    "context",
    "exclusions",
    "filtered_collectors",
    "skipped_collectors",
}


def collection_result_has_domain_failure(result: Any) -> bool:
    """
    Return whether a finalized result contains a domain failure or partial.

    Result producers use both flat collector records and nested scheduler
    envelopes. Collector context and exclusion evidence are intentionally
    ignored: canonical status fields classify the collector, while context may
    contain optional-operation failures or large copied configuration graphs.
    Malformed cyclic or unreasonably deep result graphs fail closed instead of
    allowing a successful terminal outcome or exhausting the process stack.

    Args:
        result: Result evaluated while performing finalized result contains a
            domain failure or partial.

    Returns:
        Whether a finalized result contains a domain failure or partial.
    """

    active_containers: Set[int] = set()
    visited_containers = 0

    def _visit(value: Any, depth: int) -> bool:
        """
        Visit the current syntax or data node.

        The implementation uses ``value`` and ``depth`` to visit the current
        syntax or data node. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            value: Value object whose ``get`` and ``items`` state is read while
                performing visit the current syntax or data node.
            depth: Numeric depth used while the operation performs bounded
                accounting.

        Returns:
            Whether the visit the current syntax or data node operation
            succeeds.
        """
        nonlocal visited_containers
        if depth > _DOMAIN_RESULT_MAX_DEPTH:
            return True

        if isinstance(value, (list, tuple)):
            visited_containers += 1
            if visited_containers > _DOMAIN_RESULT_MAX_CONTAINERS:
                return True
            identity = id(value)
            if identity in active_containers:
                return True
            active_containers.add(identity)
            try:
                return any(_visit(item, depth + 1) for item in value)
            finally:
                active_containers.remove(identity)

        if not isinstance(value, dict):
            return False
        visited_containers += 1
        if visited_containers > _DOMAIN_RESULT_MAX_CONTAINERS:
            return True
        if value.get("dry_run") is True:
            return False
        if value.get("domain_failure") is True:
            return True

        status = str(value.get("status", "")).strip().lower()
        if value.get("error"):
            return True
        # Legacy collector records use ``success=False`` for canonical skips.
        # The typed terminal status owns that distinction; only an accompanying
        # error or explicit domain marker may promote a skip to failure.
        if value.get("success") is False and status not in {"skipped", "not_ran"}:
            return True
        if status in {
            "degraded",
            "error",
            "failed",
            "failure",
            "partial",
            "timeout",
            "timed_out",
        }:
            return True
        overall_status = str(value.get("overall_status", "")).strip().lower()
        if overall_status in {
            "error",
            "degraded",
            "fail",
            "failed",
            "failure",
            "partial",
            "timeout",
        }:
            return True

        identity = id(value)
        if identity in active_containers:
            return True
        active_containers.add(identity)
        try:
            return any(
                _visit(item, depth + 1)
                for key, item in value.items()
                if key not in _DOMAIN_RESULT_IGNORED_BRANCHES
            )
        finally:
            active_containers.remove(identity)

    return _visit(result, 0)


def collection_result_domain_failure_duts(
    result: Any,
    dut_ids: List[str],
) -> List[str]:
    """
    Return ordered DUTs whose executed result contains a domain failure.

    Scheduler results normally group terminal leaves by collector and then DUT.
    Preserve that typed boundary so one partial DUT does not make every DUT look
    affected in the canonical ``RunResult``. A malformed/global failure that
    cannot be attributed safely still fails closed to the complete known roster.

    Args:
        result: Result object whose ``get`` state is read while performing
            ordered DUTs whose executed result contains a domain failure.
        dut_ids: Entries supplied as ``dut_ids`` without transferring container
            ownership.

    Returns:
        The collection result domain failure duts returned in operation-defined
        order.
    """

    known_duts = list(dict.fromkeys(str(dut_id) for dut_id in dut_ids))
    if not known_duts or not collection_result_has_domain_failure(result):
        return []
    if not isinstance(result, dict):
        return known_duts

    affected: Set[str] = set()
    attributed_terminal_leaf = False
    for result_group in ("sequential_results", "parallel_results"):
        collector_results = result.get(result_group, {})
        if not isinstance(collector_results, dict):
            continue
        for collector_result in collector_results.values():
            if not isinstance(collector_result, dict):
                continue
            if "status" in collector_result:
                attributed_terminal_leaf = True
                if collection_result_has_domain_failure(collector_result):
                    return known_duts
                continue
            for dut_id in known_duts:
                if dut_id not in collector_result:
                    continue
                attributed_terminal_leaf = True
                if collection_result_has_domain_failure(collector_result[dut_id]):
                    affected.add(dut_id)

    if affected:
        return [dut_id for dut_id in known_duts if dut_id in affected]
    if attributed_terminal_leaf:
        # A top-level failure marker alongside clean attributed leaves is global.
        return known_duts
    return known_duts


class FinalizationHeartbeat:
    """
    Emit elapsed finalization progress independently of the asyncio loop.

    Final report generation, sanitization, and archive verification can spend
    substantial time in synchronous filesystem or compression code. A daemon
    thread keeps the terminal visibly alive even while that code blocks the
    collection's event-loop thread.
    """

    _STOP_JOIN_TIMEOUT_SECONDS = 1.0

    def __init__(
        self,
        console: Any,
        *,
        label: str = "Finalizing output bundle",
        interval_seconds: float = 5.0,
    ) -> None:
        """
        Initialize a ``FinalizationHeartbeat`` instance.

        The initializer records ``_label``, ``_label_lock``,
        ``_lifecycle_lock``, ``_stop_event``, and ``_thread`` for later
        operations and establishes the instance invariants before any public
        method runs. If the function cannot initialize a
        ``FinalizationHeartbeat`` instance, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            console: Console consumed while the function attempts to initialize
                a ``FinalizationHeartbeat`` instance.
            label: Text supplied as label in the format accepted by this
                function.
            interval_seconds: Maximum duration in seconds allowed for interval
                seconds.

        Raises:
            ValueError: If the finalization heartbeat interval is not finite and
                positive.
        """
        interval_seconds = float(interval_seconds)
        if not math.isfinite(interval_seconds) or interval_seconds <= 0:
            raise ValueError(
                "finalization heartbeat interval must be finite and positive"
            )
        self.console = console
        self.interval_seconds = interval_seconds
        self._label = label
        self._label_lock = threading.Lock()
        self._lifecycle_lock = threading.Lock()
        self._stop_event: Optional[threading.Event] = None
        self._thread: Optional[threading.Thread] = None

    def set_label(self, label: str) -> None:
        """
        Change the stage shown by subsequent heartbeat ticks.

        The implementation uses ``label`` to change the stage shown by
        subsequent heartbeat ticks. It updates ``_label`` on the instance as
        part of that state transition.

        Args:
            label: Text supplied as label in the format accepted by this
                function.
        """

        with self._label_lock:
            self._label = label

    def _run(
        self,
        stop_event: threading.Event,
        started_at: float,
    ) -> None:
        """
        Run the configured operation.

        Console reporting must never make cleanup fail or stop.

        Args:
            stop_event: Stop event object whose ``is_set`` and ``wait`` state is
                read while performing configured.
            started_at: Numeric started at used while the operation performs
                bounded accounting.
        """
        while not stop_event.wait(self.interval_seconds):
            with self._label_lock:
                label = self._label
            elapsed = time.monotonic() - started_at
            try:
                self.console.print_info(f"{label}... elapsed {elapsed:.1f}s")
            except Exception:
                # Console reporting must never make cleanup fail or stop.
                pass

    def start(self) -> "FinalizationHeartbeat":
        """
        Start heartbeat ticks; repeated calls are harmless.

        The implementation uses current instance state to start heartbeat ticks;
        repeated calls are harmless. It updates ``_stop_event`` and ``_thread``
        on the instance as part of that state transition.

        Returns:
            A ``FinalizationHeartbeat`` representing start.
        """

        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                return self

            stop_event = threading.Event()
            started_at = time.monotonic()
            thread = threading.Thread(
                target=self._run,
                args=(stop_event, started_at),
                name="nvdebug-finalization-heartbeat",
                daemon=True,
            )
            self._stop_event = stop_event
            self._thread = thread
            try:
                thread.start()
            except Exception:
                stop_event.set()
                self._stop_event = None
                self._thread = None
                raise
        return self

    def stop(self) -> None:
        """
        Stop ticks without allowing a blocked console sink to hang cleanup.

        Detach this generation before waiting. A concurrent restart gets a fresh
        event, so it cannot reactivate a timed-out daemon thread.
        """

        with self._lifecycle_lock:
            thread = self._thread
            stop_event = self._stop_event
            if stop_event is not None:
                stop_event.set()
            if thread is None:
                return

            # Detach this generation before waiting. A concurrent restart gets a
            # fresh event, so it cannot reactivate a timed-out daemon thread.
            self._thread = None
            self._stop_event = None

        if thread is not threading.current_thread():
            thread.join(timeout=self._STOP_JOIN_TIMEOUT_SECONDS)

    def __enter__(self) -> "FinalizationHeartbeat":
        """
        Enter the FinalizationHeartbeat context.

        Entering the scope acquires or validates its owned resources and returns
        the value used until the matching exit method completes cleanup.

        Returns:
            A ``FinalizationHeartbeat`` representing enter.
        """
        return self.start()

    def __exit__(self, *_: Any) -> None:
        """
        Exit the FinalizationHeartbeat context.

        Leaving the scope releases resources owned by the context while
        preserving the exception-propagation behavior declared by the
        context-manager protocol.

        Args:
            _: Additional positional values forwarded in caller-provided order.
        """
        self.stop()


@dataclass
class ToolConfig:
    """
    Global tool configuration that applies to all DUTs.

    This dataclass contains all tool-level settings that control execution,
    output, logging, and collection behavior across all Device Under Test (DUT)
    instances.

    Attributes:
        concurrency_mode: Conservative, fixed, or adaptive global admission.
        initial_io_oversubscription: Optional configured CPU multiplier.
        minimum_collector_operations: Adaptive weighted-capacity floor.
        maximum_collector_operations: Optional hard weighted-capacity ceiling.
        adaptive_concurrency: Bounded AIMD pressure and lifecycle settings.
        max_concurrent_duts: Maximum concurrent duts admitted by this record.
        max_concurrent_collectors_per_dut: Maximum concurrent collectors per DUT
            admitted by this record.
        timeout: Numeric timeout retained by this record.
        retry_count: Number of retry entries represented by the record.
        output_directory: Canonical text used as output directory.
        caller_output_was_explicit: Whether caller output was explicit applies
            to this record.
        skip_zip: Whether skip ZIP applies to this record.
        skip_zip_split: Whether skip ZIP split applies to this record.
        zip_split_threshold: Numeric ZIP split threshold retained by this
            record.
        log_level: Canonical text used as log level.
        log_format: Canonical text used as log format.
        baseboard: Canonical text used as baseboard.
        environment_baseboard: Canonical text used as environment baseboard.
        collection_level: Canonical text used as collection level.
        dry_run: Whether dry run applies to this record.
        debug: Whether debug applies to this record.
        verbose: Whether verbose applies to this record.
        skip_preflight: Whether skip preflight applies to this record.
        skip_sanitization: Whether skip sanitization applies to this record.
        apply_sanitization: Whether apply sanitization applies to this record.
        skip_html_reports: Whether skip HTML reports applies to this record.
        report_format: Canonical text used as report format.
        collector_id: Canonical text used as collector identifier.
        collector_group: Collection of collector group entries retained by this
            record.
        skip_collectors: Collection of skip collectors entries retained by this
            record.
        include_collectors: Collection of include collectors entries retained by
            this record.
        streaming_only: Whether streaming only applies to this record.
        stream_begin: Stream begin retained as part of the record's public
            state.
        stream_end: Stream end retained as part of the record's public state.
        stream_destination: Canonical text used as stream destination.
        append: Whether append applies to this record.
        rack_id: Canonical text used as rack identifier.
        spreadsheet: Canonical text used as spreadsheet.
        enable_status_tracking: Whether status tracking applies to this record.
        disable_live_display: Whether disable live display applies to this
            record.
        execution_scheduler: Canonical text used as execution scheduler.
        parallel_dut_sequential_collectors: Whether parallel DUT sequential
            collectors applies to this record.
        service_grouped_sequential_collectors: Whether service grouped
            sequential collectors applies to this record.
        task_id_prefix: Canonical text used as task identifier prefix.
        tool_temp_dir: Canonical text used as tool temp dir.
        EXTRA_LOG_COLLECTION: Whether extra log collection applies to this
            record.
        sysinfo_snapshot_mode: Snapshot profile inherited by DUTs; fast disables
            firmware dumps and full enables them with the longer catalog timeout.
        i2c_config: Mapping that retains the i2c config fields for this record.
        SKIP_PORT_FW: Whether skip port firmware applies to this record.
        SKIP_BMC_SSH_LOGS: Whether skip BMC SSH logs applies to this record.
        SKIP_HOST_LOGS: Whether skip host logs applies to this record.
        SKIP_IPMI_LOGS: Whether skip IPMI logs applies to this record.
        SKIP_REDFISH_OOB_LOGS: Whether skip Redfish oob logs applies to this
            record.
        COLLECTOR_TO_SKIP: Collection of collector to skip entries retained by
            this record.
        SYSTEM_ID_TO_SKIP: Collection of system identifier to skip entries
            retained by this record.
        CHASSIS_ID_TO_SKIP: Collection of chassis identifier to skip entries
            retained by this record.
        MANAGER_ID_TO_SKIP: Collection of manager identifier to skip entries
            retained by this record.
        EXPAND_QUERY_CHASSIS_LEVEL: Numeric expand query chassis level retained
            by this record.
        EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL: Numeric expand query firmware
            inventory level retained by this record.
        EXPAND_QUERY_MANAGER_LEVEL: Numeric expand query manager level retained
            by this record.
        EXPAND_QUERY_SYSTEM_LEVEL: Numeric expand query system level retained by
            this record.
        explicit_tool_config_keys: Whether explicit tool config keys applies to
            this record.
        explicit_cli_config_keys: Whether explicit CLI config keys applies to
            this record.
        EXPAND_FALLBACK_MODE: Canonical text used as expand fallback mode.
        NVOS_TECH_DUMP_TIMEOUT: Numeric nvos tech dump timeout retained by this
            record.
        REDFISH_DUMP_TIMEOUT: Numeric Redfish dump timeout retained by this
            record.
        REDFISH_DEVICE_DUMP_SLEEP_DURATION: Numeric Redfish device dump sleep
            duration retained by this record.
        COLLECTOR_EXTENSION_CONFIG: Mapping that retains the collector extension
            config fields for this record.
        BMC_TEMP_DIR: Canonical text used as BMC temp dir.
        FW_INVENTORY_TABLE_PROPERTIES: Collection of firmware inventory table
            properties entries retained by this record.
        ADDITIONAL_OOB_URI_COLLECTION: Collection of additional oob URI
            collection entries retained by this record.
        NVLINK_OOB_URI: Collection of nvlink oob URI entries retained by this
            record.
        CUSTOM_DUMP_SERVICES: Mapping that retains the custom dump services
            fields for this record.
        REDFISH_R31_PAYLOAD: Mapping that retains the Redfish r31 payload fields
            for this record.
        POST_CODES_URI: Collection of post codes URI entries retained by this
            record.
        preflight_config: Mapping that retains the preflight config fields for
            this record.
        redfish_session_config: Mapping that retains the Redfish session config
            fields for this record.
        ssh_host_key_policy: Canonical text used as SSH host key policy.
        ssh_known_hosts_file: Canonical text used as SSH known hosts file.
        ssh_connection_pool: Mapping that retains the SSH connection pool fields
            for this record.
        redfish_request_capture: Mapping that retains the Redfish request
            capture fields for this record.
        uri_overrides: Mapping that retains the URI overrides fields for this
            record.
        max_pagination_pages: Maximum pagination pages admitted by this record.
        max_duplicate_url_retries: Maximum duplicate URL retries admitted by
            this record.
    """

    # Execution Configuration
    # None selects resource-aware auto sizing. A positive value is an
    # intentional hard cap.
    concurrency_mode: str = "conservative"
    initial_io_oversubscription: Optional[float] = None
    minimum_collector_operations: int = 1
    maximum_collector_operations: Optional[int] = None
    adaptive_concurrency: Dict[str, Any] = field(default_factory=dict)
    max_concurrent_duts: Optional[int] = None
    max_concurrent_collectors_per_dut: int = DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT
    timeout: int = 300
    retry_count: int = 1

    # Output Configuration
    output_directory: str = "/tmp/nvdebug"
    # Preserve the invocation source boundary without retaining a second path.
    # The resolved path remains ``output_directory``/``stream_destination``;
    # this bit records whether Click supplied that output namespace explicitly.
    caller_output_was_explicit: bool = False
    skip_zip: bool = False
    skip_zip_split: bool = False
    zip_split_threshold: float = 200.0

    # Logging Configuration
    log_level: str = "INFO"
    log_format: str = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"

    # Collection Configuration
    baseboard: Optional[str] = None
    environment_baseboard: Optional[str] = None
    collection_level: str = "L1"
    dry_run: bool = False
    debug: bool = False
    verbose: bool = False

    # Preflight and Sanitization
    skip_preflight: bool = False
    skip_sanitization: bool = False
    apply_sanitization: bool = False
    skip_html_reports: bool = False
    report_format: str = "spa"  # "legacy", "spa", or "both"

    # Collector Configuration
    collector_id: Optional[str] = None
    collector_group: Optional[List[str]] = None

    # Collector Skip Configuration
    skip_collectors: Optional[List[str]] = None
    include_collectors: Optional[List[str]] = None

    # Streaming Configuration
    streaming_only: bool = False
    stream_begin: Any = "24"
    stream_end: Any = "0"
    stream_destination: Optional[str] = None
    append: bool = False
    rack_id: Optional[str] = None

    # Configuration files
    spreadsheet: Optional[str] = None

    # Status Tracking Configuration
    enable_status_tracking: bool = True
    disable_live_display: bool = False

    # Parallelization Configuration
    execution_scheduler: str = "per_dut"
    parallel_dut_sequential_collectors: bool = True
    service_grouped_sequential_collectors: bool = True

    # Global Directory and Prefix Configuration
    task_id_prefix: str = ""  # Empty by default, only used if user specifies
    tool_temp_dir: str = "/tmp"

    # Global feature flags / passthroughs
    # H11: Enable nvidia-bug-report extra mode globally when true
    EXTRA_LOG_COLLECTION: Optional[bool] = None
    sysinfo_snapshot_mode: Literal["fast", "full"] = "fast"

    # I2C Configuration - Global overrides for baseboard i2c_config defaults
    i2c_config: Optional[Dict[str, Any]] = None

    # Skip Flags - Global tool-level settings
    SKIP_PORT_FW: bool = False
    SKIP_BMC_SSH_LOGS: bool = True
    SKIP_HOST_LOGS: bool = False
    SKIP_IPMI_LOGS: bool = False
    SKIP_REDFISH_OOB_LOGS: bool = False

    # New Skip Fields - Global tool-level settings
    COLLECTOR_TO_SKIP: Optional[List[str]] = None
    SYSTEM_ID_TO_SKIP: Optional[List[str]] = None
    CHASSIS_ID_TO_SKIP: Optional[List[str]] = None
    MANAGER_ID_TO_SKIP: Optional[List[str]] = None

    # Expand Query Fields - Global tool-level settings
    EXPAND_QUERY_CHASSIS_LEVEL: int = 1
    EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL: int = 1
    EXPAND_QUERY_MANAGER_LEVEL: int = 1
    EXPAND_QUERY_SYSTEM_LEVEL: int = 1
    explicit_tool_config_keys: Dict[str, bool] = field(default_factory=dict)
    explicit_cli_config_keys: Dict[str, bool] = field(default_factory=dict)
    # Behavior when BMC does not support $expand. See DUTConfig.EXPAND_FALLBACK_MODE.
    # Per-DUT EXPAND_FALLBACK_MODE in dut_config.yaml takes precedence over this.
    EXPAND_FALLBACK_MODE: str = "auto"

    # Timeout Fields - Global tool-level settings
    NVOS_TECH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DUMP_TIMEOUT: Optional[int] = None
    REDFISH_DEVICE_DUMP_SLEEP_DURATION: Optional[int] = None

    # Namespaced configuration consumed only by trusted catalog extensions.
    COLLECTOR_EXTENSION_CONFIG: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Directory Fields - Global tool-level settings
    BMC_TEMP_DIR: str = "/tmp"

    # Firmware Inventory Configuration - Global tool-level settings
    FW_INVENTORY_TABLE_PROPERTIES: List[str] = field(default_factory=list)

    # Additional OOB URI Collection Configuration - Global tool-level settings
    ADDITIONAL_OOB_URI_COLLECTION: List[str] = field(default_factory=list)

    # NVLink OOB URI Collection Configuration - Global tool-level settings
    NVLINK_OOB_URI: List[str] = field(default_factory=list)

    # Custom Dump Services Configuration - Global tool-level settings
    CUSTOM_DUMP_SERVICES: List[Dict[str, Any]] = field(default_factory=list)

    # R31 FDR diagnostic payload override. None preserves the catalog default.
    REDFISH_R31_PAYLOAD: Optional[Dict[str, Any]] = None

    # Post Codes URI Configuration - Global tool-level settings
    POST_CODES_URI: List[str] = field(default_factory=list)

    # Preflight credential validation configuration
    preflight_config: Optional[Dict[str, Any]] = None

    # Redfish session configuration (connection pool settings)
    redfish_session_config: Optional[Dict[str, Any]] = None

    # SSH server-authentication policy
    ssh_host_key_policy: str = "insecure"
    ssh_known_hosts_file: Optional[str] = None

    # Reusable Host SSH endpoint connection limits
    ssh_connection_pool: Optional[Dict[str, Any]] = None

    # Validated limits for the active run-owned request-capture boundary.
    redfish_request_capture: Dict[str, int] = field(
        default_factory=lambda: RedfishRequestCaptureLimits().as_dict()
    )

    # URI and Redfish pagination guardrails
    uri_overrides: Optional[Dict[str, Any]] = None
    # Reaching the finite default is reported as a partial collection.
    max_pagination_pages: int = DEFAULT_MAX_PAGINATION_PAGES
    max_duplicate_url_retries: int = 3

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized ToolConfig state.

        Config declares i2c_config with an empty-map schema default. Preserve
        the distinction between that omitted default and an explicit empty
        mapping, which intentionally clears lower-precedence I2C values.

        Raises:
            ValueError: If invalid report_format value ``report_format``;
                expected 'legacy', 'spa', or 'both'; or invalid
                execution_scheduler value ``execution_scheduler``; expected
                'per_dut' or 'legacy_global'; or the final adaptive admission
                policy lacks a maximum or has conflicting minimum/maximum
                bounds.
        """
        execution_values = {
            "concurrency_mode": self.concurrency_mode,
            "initial_io_oversubscription": self.initial_io_oversubscription,
            "minimum_collector_operations": self.minimum_collector_operations,
            "maximum_collector_operations": self.maximum_collector_operations,
            "adaptive": self.adaptive_concurrency,
            "max_concurrent_collectors_per_dut": (
                self.max_concurrent_collectors_per_dut
            ),
            "timeout": self.timeout,
            "retry_count": self.retry_count,
        }
        # ``None`` means the optional whole-DUT bound was omitted.  The strict
        # YAML boundary still rejects an explicitly written null value.
        if self.max_concurrent_duts is not None:
            execution_values["max_concurrent_duts"] = self.max_concurrent_duts
        execution_section = ExecutionSectionConfig.model_validate(execution_values)
        self.concurrency_mode = execution_section.concurrency_mode
        self.initial_io_oversubscription = execution_section.initial_io_oversubscription
        self.minimum_collector_operations = (
            execution_section.minimum_collector_operations
        )
        self.maximum_collector_operations = (
            execution_section.maximum_collector_operations
        )
        self.adaptive_concurrency = execution_section.adaptive.model_dump()
        if (
            self.concurrency_mode == "adaptive"
            and self.maximum_collector_operations is None
        ):
            raise ValueError(
                "execution.maximum_collector_operations is required in adaptive mode"
            )
        if (
            self.maximum_collector_operations is not None
            and self.minimum_collector_operations > self.maximum_collector_operations
        ):
            raise ValueError(
                "execution.minimum_collector_operations cannot exceed "
                "maximum_collector_operations"
            )

        self.redfish_request_capture = RedfishRequestCaptureLimits.model_validate(
            self.redfish_request_capture
        ).as_dict()
        ssh_connection_pool = (
            {} if self.ssh_connection_pool is None else self.ssh_connection_pool
        )
        self.ssh_connection_pool = SSHConnectionPoolConfig.model_validate(
            ssh_connection_pool
        ).model_dump()

        # Config declares i2c_config with an empty-map schema default. Preserve
        # the distinction between that omitted default and an explicit empty
        # mapping, which intentionally clears lower-precedence I2C values.
        if self.explicit_tool_config_keys.get("i2c_config") is False:
            self.i2c_config = None
            self.explicit_tool_config_keys.pop("i2c_config")

        self.report_format = str(self.report_format or "spa").strip().lower()
        if self.report_format not in {"legacy", "spa", "both"}:
            raise ValueError(
                "Invalid report_format value "
                f"{self.report_format!r}; expected 'legacy', 'spa', or 'both'"
            )

        self.execution_scheduler = (
            str(self.execution_scheduler or "per_dut").strip().lower()
        )
        if self.execution_scheduler not in {"per_dut", "legacy_global"}:
            raise ValueError(
                "Invalid execution_scheduler value "
                f"{self.execution_scheduler!r}; expected 'per_dut' or 'legacy_global'"
            )

        if self.debug:
            self.log_level = "DEBUG"


def _result_node_is_explicitly_nonexecuted(result: Any) -> bool:
    """
    Return whether every terminal leaf stopped before collector execution.

    A generic skipped or not-applicable result can be produced by a collector
    that did run. Typed ``execution_started`` and ``skip_phase`` fields are
    therefore authoritative. The reason fallback is retained only for legacy
    result producers, and unknown shapes remain fail-open.

    Args:
        result: Result object whose ``get`` and ``values`` state is read while
            performing every terminal leaf stopped before collector execution.

    Returns:
        Whether every terminal leaf stopped before collector execution.
    """

    if not isinstance(result, dict):
        return False
    if "status" in result:
        status = str(result.get("status", "")).strip().lower()
        execution_started = result.get("execution_started")
        skip_phase = str(result.get("skip_phase", "")).strip().lower()
        if execution_started is False:
            return status == "skipped" and skip_phase in {
                "preflight",
                "selection",
                "configuration",
                "applicability",
                "pre_execution",
            }
        if execution_started is True:
            return False
        if "execution_started" in result or "skip_phase" in result:
            return False
        reason = str(result.get("reason") or result.get("message") or "").lower()
        return bool(
            status == "skipped"
            and "collector not executed due to" in reason
            and "preflight failure" in reason
        )
    if not result:
        return False
    return all(
        _result_node_is_explicitly_nonexecuted(value) for value in result.values()
    )


def _executed_collector_pairs(result: Any) -> Set[tuple[Optional[str], str]]:
    """
    Return DUT/collector pairs whose result reached collector execution.

    The implementation uses ``result`` to produce DUT/collector pairs whose
    result reached collector execution.

    Args:
        result: Result object whose ``get`` state is read while performing
            DUT/collector pairs whose result reached collector execution.

    Returns:
        The unique executed collector pairs returned by the operation, or
        ``None`` when the requested value is unavailable.
    """

    if not isinstance(result, dict):
        return set()

    executed: Set[tuple[Optional[str], str]] = set()
    for result_group in ("sequential_results", "parallel_results"):
        collector_results = result.get(result_group, {})
        if not isinstance(collector_results, dict):
            continue
        for collector_id, collector_result in collector_results.items():
            if isinstance(collector_result, dict) and "status" in collector_result:
                if not _result_node_is_explicitly_nonexecuted(collector_result):
                    executed.add((None, str(collector_id)))
                continue
            if not isinstance(collector_result, dict):
                executed.add((None, str(collector_id)))
                continue
            for dut_id, dut_result in collector_result.items():
                if not _result_node_is_explicitly_nonexecuted(dut_result):
                    executed.add((str(dut_id), str(collector_id)))
    return executed


def _executed_collector_ids(result: Any) -> Set[str]:
    """
    Return collector IDs with at least one result that reached execution.

    The implementation uses ``result`` to produce collector IDs with at least
    one result that reached execution.

    Args:
        result: Result evaluated while performing collector IDs with at least
            one result that reached execution.

    Returns:
        The unique executed collector identifiers returned by the operation.
    """

    return {collector_id for _, collector_id in _executed_collector_pairs(result)}


def _preflight_blocked_collector_pairs(result: Any) -> Set[tuple[str, str]]:
    """
    Return typed DUT/collector pairs blocked by required preflight.

    The implementation uses ``result`` to produce typed DUT/collector pairs
    blocked by required preflight.

    Args:
        result: Result object whose ``get`` state is read while performing typed
            DUT/collector pairs blocked by required preflight.

    Returns:
        The unique preflight blocked collector pairs returned by the operation.
    """

    blocked: Set[tuple[str, str]] = set()
    if not isinstance(result, dict):
        return blocked
    for result_group in ("sequential_results", "parallel_results"):
        collector_results = result.get(result_group, {})
        if not isinstance(collector_results, dict):
            continue
        for collector_id, collector_result in collector_results.items():
            if not isinstance(collector_result, dict):
                continue
            leaves = (
                [(None, collector_result)]
                if "status" in collector_result
                else list(collector_result.items())
            )
            for dut_id, leaf in leaves:
                if dut_id is None or not isinstance(leaf, dict):
                    continue
                status = str(leaf.get("status", "")).strip().lower()
                typed = (
                    leaf.get("execution_started") is False
                    and str(leaf.get("skip_phase", "")).strip().lower() == "preflight"
                )
                reason = str(leaf.get("reason") or leaf.get("message") or "").lower()
                legacy = (
                    "execution_started" not in leaf
                    and "skip_phase" not in leaf
                    and "collector not executed due to" in reason
                    and "preflight failure" in reason
                )
                if status == "skipped" and (typed or legacy):
                    blocked.add((str(dut_id), str(collector_id)))
    return blocked


_SELECTION_EVIDENCE_MAX_RECORDS = 2048
_SELECTION_EVIDENCE_MAX_DUTS = 256
_SELECTION_EVIDENCE_MAX_TOKEN_CHARS = 256
_SELECTION_EVIDENCE_MAX_REASON_CHARS = 512
_SELECTION_EVIDENCE_MAX_SERIALIZED_BYTES = 4 * 1024 * 1024


def _bounded_terminal_result_evidence(
    result: Any,
    *,
    maximum_records: int = _SELECTION_EVIDENCE_MAX_RECORDS,
    maximum_reason_characters: int = _SELECTION_EVIDENCE_MAX_REASON_CHARS,
    priority_pairs: Optional[Set[tuple[str, str]]] = None,
) -> List[Dict[str, Any]]:
    """
    Project result leaves to a bounded, identity-preserving evidence list.

    The traversal keeps only terminal collector leaves, preserves their DUT and
    collector identity, and caps both record count and reason length. Priority
    pairs are emitted first without allowing duplicate evidence.

    Args:
        result: Result object whose ``get`` state is read while performing
            project result leaves to a bounded, identity-preserving evidence
            list.
        maximum_records: Upper bound enforced for records; the consuming
            boundary rejects or truncates values that exceed it.
        maximum_reason_characters: Upper bound enforced for reason characters;
            the consuming boundary rejects or truncates values that exceed it.
        priority_pairs: Optional priority pairs; ``None`` selects the function's
            default behavior.

    Returns:
        The bounded terminal result evidence returned in operation-defined
        order.
    """

    if not isinstance(result, dict):
        return []
    records: List[Dict[str, Any]] = []
    prioritized = priority_pairs or set()
    passes = (True, False) if prioritized else (False,)
    for priority_pass in passes:
        for result_group in ("sequential_results", "parallel_results"):
            collector_results = result.get(result_group, {})
            if not isinstance(collector_results, dict):
                continue
            for collector_id, collector_result in collector_results.items():
                if isinstance(collector_result, dict) and "status" in collector_result:
                    leaves = [(None, collector_result)]
                elif isinstance(collector_result, dict):
                    leaves = list(collector_result.items())
                else:
                    continue
                for dut_id, leaf in leaves:
                    is_priority = bool(
                        dut_id is not None
                        and (str(dut_id), str(collector_id)) in prioritized
                    )
                    if is_priority != priority_pass:
                        continue
                    if len(records) >= maximum_records:
                        return records
                    if not isinstance(leaf, dict) or "status" not in leaf:
                        continue
                    records.append(
                        {
                            "result_group": str(result_group)[:64],
                            "collector_id": str(collector_id)[
                                :_SELECTION_EVIDENCE_MAX_TOKEN_CHARS
                            ],
                            "dut_id": (
                                str(dut_id)[:_SELECTION_EVIDENCE_MAX_TOKEN_CHARS]
                                if dut_id is not None
                                else None
                            ),
                            "status": str(leaf.get("status", ""))[:64],
                            "reason": str(
                                leaf.get("reason") or leaf.get("message") or ""
                            )[:maximum_reason_characters],
                            "execution_started": leaf.get("execution_started"),
                            "skip_phase": str(leaf.get("skip_phase", ""))[:64],
                        }
                    )
    return records


def _normalized_collector_values(value: Any) -> List[str]:
    """
    Normalize selector input to stable, unique collector tokens.

    The implementation uses ``value`` to normalize selector input to stable,
    unique collector tokens. The source value keeps its ownership while the
    normalized representation is returned separately.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.

    Returns:
        The validated ``normalized``.
    """

    raw_values: List[Any]
    if value is None:
        raw_values = []
    elif isinstance(value, str):
        raw_values = re.split(r"[,\s]+", value)
    elif isinstance(value, (list, tuple, set, frozenset)):
        raw_values = []
        for item in value:
            if isinstance(item, str):
                raw_values.extend(re.split(r"[,\s]+", item))
            else:
                raw_values.append(item)
    else:
        raw_values = [value]

    normalized: List[str] = []
    seen: Set[str] = set()
    for item in raw_values:
        token = str(item).strip()
        if token and token not in seen:
            seen.add(token)
            normalized.append(token)
    return normalized


def _tool_config_value(tool_config: Any, key: str, default: Any = None) -> Any:
    """
    Read one tool-configuration entry from a mapping or a settings object.

    The CLI carries the tool configuration as a ``ToolConfig`` dataclass on the
    collect path and as a plain mapping on the preflight path. Both spellings
    reach the shared console-disclosure helpers, so read through whichever one
    the caller holds instead of duplicating the branch at every call site.

    Args:
        tool_config: Mapping or settings object holding the resolved tool
            configuration for this run.
        key: Configuration entry name to read.
        default: Value returned when the entry is absent from either spelling.

    Returns:
        The configured entry, or ``default`` when it is not present.
    """

    if isinstance(tool_config, Mapping):
        return tool_config.get(key, default)
    return getattr(tool_config, key, default)


def _resolve_console_redfish_tls_policy(
    dut_config: DUTConfig,
    tool_config: Any,
) -> RedfishTLSPolicy:
    """
    Resolve the Redfish TLS policy the console must disclose for one DUT.

    The console disclosure and the runtime must never disagree about the
    posture a run will use, so this delegates to the same resolver the DUT
    runtime calls rather than re-deriving precedence. Tool-level provenance is
    read from ``explicit_tool_config_keys`` when the caller holds a settings
    object; the preflight mapping has no provenance map, and there the presence
    of a ``redfish_session_config`` entry is itself the explicit signal because
    the tool-config builder writes that key only for a source-present holder.

    Args:
        dut_config: Validated DUT model whose ``model_fields_set`` supplies the
            per-DUT provenance used by the resolver.
        tool_config: Mapping or settings object holding the resolved tool
            configuration, including any Redfish session holder.

    Returns:
        A ``RedfishTLSPolicy`` identical to the one the runtime resolves for
        this DUT.

    Raises:
        ValueError: If a configured legacy verification value is malformed; the
            console fails closed exactly as the runtime does.
    """

    from .core.dut_manager import _resolve_dut_redfish_tls_policy

    session_config = _tool_config_value(tool_config, "redfish_session_config")
    session_values = (
        session_config.model_dump()
        if hasattr(session_config, "model_dump")
        else session_config
    )
    provenance = getattr(tool_config, "explicit_tool_config_keys", None)
    if isinstance(provenance, Mapping):
        explicit_tool_keys = {key for key, value in provenance.items() if value}
        session_default_is_explicit = "redfish_session_config" in explicit_tool_keys
    else:
        explicit_tool_keys = set()
        session_default_is_explicit = session_values is not None

    dut_explicit_keys = {
        key: True for key in getattr(dut_config, "model_fields_set", set())
    }
    combined_explicit_keys = {key: True for key in explicit_tool_keys}
    combined_explicit_keys.update(dut_explicit_keys)

    return _resolve_dut_redfish_tls_policy(
        dut_config.model_dump(),
        combined_explicit_keys,
        RedfishTLSPolicy.from_session_config(session_values),
        session_default_is_explicit=session_default_is_explicit,
        session_override_keys=dut_explicit_keys,
    )


def _insecure_redfish_transport_is_reachable(
    dut_configs: Iterable[DUTConfig],
    tool_config: Any,
) -> bool:
    """
    Report whether any configured Redfish route runs without verification.

    A route counts only when the endpoint is actually configured, so an unused
    controller cannot trigger a warning about a posture the run never applies.

    Args:
        dut_configs: Validated DUT models scheduled for this run.
        tool_config: Mapping or settings object holding the resolved tool
            configuration used as the lower-precedence trust source.

    Returns:
        ``True`` when at least one configured BMC or HMC Redfish route resolves
        to an unverified policy.

    Raises:
        ValueError: If a configured legacy verification value is malformed.
    """

    for dut_config in dut_configs:
        policy = _resolve_console_redfish_tls_policy(dut_config, tool_config)
        insecure_bmc = bool(dut_config.bmc_ip) and not policy.is_verified(
            use_https=dut_config.bmc_use_https
        )
        insecure_hmc = bool(dut_config.hmc_ip) and not policy.is_verified(
            use_https=dut_config.hmc_use_https
        )
        if insecure_bmc or insecure_hmc:
            return True
    return False


def _has_positive_collector_selector(tool_config: Any) -> bool:
    """
    Return whether resolved configuration has a positive selector.

    After applying local validation, the function forwards ``tool_config`` to
    ``any`` and preserves its return and exception contract.

    Args:
        tool_config: Tool config governing resolved configuration has a positive
            selector.

    Returns:
        Whether resolved configuration has a positive selector.
    """

    return any(
        _normalized_collector_values(getattr(tool_config, field_name, None))
        for field_name in ("collector_id", "collector_group", "include_collectors")
    )


@dataclass
class CLIConfig:
    """
    Configuration object for CLI arguments to avoid long parameter lists.

    This dataclass encapsulates all CLI-provided arguments for DUT
    configuration, making it easier to pass configuration data without long
    parameter lists.

    Attributes:
        baseboard: Canonical text used as baseboard.
        local: Whether local applies to this record.
        collector_id: Canonical text used as collector identifier.
        collector_group: Collection of collector group entries retained by this
            record.
        collection_level: Canonical text used as collection level.
        dry_run: Whether dry run applies to this record.
        debug: Whether debug applies to this record.
        verbose: Whether verbose applies to this record.
        bmc_ip: Canonical text used as BMC IP.
        bmc_user: Canonical text used as BMC user.
        bmc_pass: Canonical text used as BMC pass.
        bmc_ssh_user: Canonical text used as BMC SSH user.
        bmc_ssh_pass: Canonical text used as BMC SSH pass.
        bmc_ssh_port: Numeric BMC SSH port retained by this record.
        bmc_ssh_key_path: Validated filesystem location associated with BMC SSH
            key path.
        bmc_ssh_passwordless: Whether BMC SSH passwordless applies to this
            record.
        bmc_ssh_max_retries: Number of BMC SSH max retries represented by this
            record.
        bmc_rf_user: Canonical text used as BMC Redfish user.
        bmc_rf_pass: Canonical text used as BMC Redfish pass.
        bmc_rf_port: Numeric BMC Redfish port retained by this record.
        host_ip: Canonical text used as host IP.
        host_user: Canonical text used as host user.
        host_pass: Canonical text used as host pass.
        host_ssh_port: Numeric host SSH port retained by this record.
        host_ssh_key_path: Validated filesystem location associated with host
            SSH key path.
        host_ssh_passwordless: Whether host SSH passwordless applies to this
            record.
        host_ssh_max_retries: Number of host SSH max retries represented by this
            record.
        hmc_ip: Canonical text used as HMC IP.
        hmc_user: Canonical text used as HMC user.
        hmc_pass: Canonical text used as HMC pass.
        hmc_ssh_user: Canonical text used as HMC SSH user.
        hmc_ssh_pass: Canonical text used as HMC SSH pass.
        hmc_ssh_port: Numeric HMC SSH port retained by this record.
        hmc_ssh_key_path: Validated filesystem location associated with HMC SSH
            key path.
        hmc_ssh_passwordless: Whether HMC SSH passwordless applies to this
            record.
        hmc_ssh_max_retries: Number of HMC SSH max retries represented by this
            record.
        hmc_http_port: Numeric HMC HTTP port retained by this record.
        hmc_https_port: Numeric HMC HTTPS port retained by this record.
        hmc_use_https: Whether HMC use HTTPS applies to this record.
        use_port_forwarding: Whether use port forwarding applies to this record.
        tunnel_tcp_port: Numeric tunnel TCP port retained by this record.
        setup_port_forwarding: Whether setup port forwarding applies to this
            record.
        force_port_fw: Whether force port firmware applies to this record.
        hmc_access_method: Canonical text used as HMC access method.
        ssh_proxy_host: Canonical text used as SSH proxy host.
        ssh_proxy_port: Numeric SSH proxy port retained by this record.
        ssh_proxy_user: Canonical text used as SSH proxy user.
        ssh_proxy_pass: Canonical text used as SSH proxy pass.
        ssh_proxy_key: Canonical text used as SSH proxy key.
        ssh_proxy_passwordless: Whether SSH proxy passwordless applies to this
            record.
        ssh_proxy_max_retries: Number of SSH proxy max retries represented by
            this record.
        skip_zip: Whether skip ZIP applies to this record.
        skip_zip_split: Whether skip ZIP split applies to this record.
        zip_split_threshold: Numeric ZIP split threshold retained by this
            record.
        non_interactive: Whether non interactive applies to this record.
        skip_preflight: Whether skip preflight applies to this record.
        skip_sanitization: Whether skip sanitization applies to this record.
        apply_sanitization: Whether apply sanitization applies to this record.
        skip_html_reports: Whether skip HTML reports applies to this record.
        report_format: Canonical text used as report format.
    """

    # Required arguments (can be provided via CLI or config files)
    baseboard: str

    # Local Configuration
    local: bool = False

    # Collector Configuration
    collector_id: Optional[str] = None
    collector_group: Optional[List[str]] = None
    collection_level: str = "L1"
    dry_run: bool = False

    # Logging Configuration
    debug: bool = False
    verbose: bool = False

    # BMC Configuration
    bmc_ip: Optional[str] = None
    bmc_user: Optional[str] = None
    bmc_pass: Optional[str] = None
    bmc_ssh_user: Optional[str] = None
    bmc_ssh_pass: Optional[str] = None
    bmc_ssh_port: Optional[int] = None
    bmc_ssh_key_path: Optional[str] = None
    bmc_ssh_passwordless: bool = False
    bmc_ssh_max_retries: Optional[int] = 3
    bmc_rf_user: Optional[str] = None
    bmc_rf_pass: Optional[str] = None
    bmc_rf_port: Optional[int] = None

    # Host Configuration
    host_ip: Optional[str] = None
    host_user: Optional[str] = None
    host_pass: Optional[str] = None
    host_ssh_port: Optional[int] = None
    host_ssh_key_path: Optional[str] = None
    host_ssh_passwordless: bool = False
    host_ssh_max_retries: Optional[int] = 3

    # HMC Configuration
    hmc_ip: Optional[str] = None
    hmc_user: Optional[str] = None
    hmc_pass: Optional[str] = None
    hmc_ssh_user: Optional[str] = None
    hmc_ssh_pass: Optional[str] = None
    hmc_ssh_port: Optional[int] = None
    hmc_ssh_key_path: Optional[str] = None
    hmc_ssh_passwordless: bool = False
    hmc_ssh_max_retries: Optional[int] = 3
    hmc_http_port: Optional[int] = None
    hmc_https_port: Optional[int] = None
    hmc_use_https: bool = False
    use_port_forwarding: bool = False
    tunnel_tcp_port: Optional[int] = None
    setup_port_forwarding: Optional[bool] = None
    force_port_fw: Optional[bool] = None
    hmc_access_method: Optional[str] = None

    # SSH Proxy Configuration
    ssh_proxy_host: Optional[str] = None
    ssh_proxy_port: Optional[int] = 22
    ssh_proxy_user: Optional[str] = None
    ssh_proxy_pass: Optional[str] = None
    ssh_proxy_key: Optional[str] = None
    ssh_proxy_passwordless: bool = False
    ssh_proxy_max_retries: Optional[int] = 3

    # Archive Configuration
    skip_zip: bool = False
    skip_zip_split: bool = False
    zip_split_threshold: float = 200.0

    # Common Configuration
    non_interactive: bool = False
    skip_preflight: bool = False
    skip_sanitization: bool = False
    apply_sanitization: bool = False
    skip_html_reports: bool = False
    report_format: str = "spa"  # "legacy", "spa", or "both"


class CLICollector(PostCollectionOutcomePublisher):
    """
    Handles the collect command logic.

    This class orchestrates the log collection process, managing DUT
    configurations, validation, and execution of the collection workflow.
    """

    _FAILED_SAFE_DIAGNOSTIC_LIMIT = 2048
    _FAILED_SAFE_ERROR_LIMIT = 8

    def __init__(
        self,
        tool_config: ToolConfig,
        dut_configs: List["DUTConfig"],
        source_tool_config: Optional[Path] = None,
        source_dut_config: Optional[Path] = None,
        enable_status_tracking: bool = True,
        disable_live_display: bool = False,
        skip_validation: bool = False,
        extra_sensitive_strings: Optional[List[str]] = None,
        pre_terminal_cleanup: Optional[Callable[[], None]] = None,
        catalog_snapshot: Optional[CatalogSnapshot] = None,
    ):
        """
        Initialize the CLI collector.

        Track original config file paths (CLI-provided or auto-detected) so we
        can archive them into the run-level log directory.

        Args:
            tool_config: Tool config governing initialize the CLI collector.
            dut_configs: DUT configs governing initialize the CLI collector.
            source_tool_config: Optional filesystem location used as the source
                for this operation.
            source_dut_config: Optional filesystem location used as the source
                for this operation.
            enable_status_tracking: Whether enable status tracking is enabled or
                required for this operation.
            disable_live_display: Whether disable live display is enabled or
                required for this operation.
            skip_validation: Whether skip validation is enabled or required for
                this operation.
            extra_sensitive_strings: Optional extra sensitive strings; ``None``
                selects the function's default behavior.
            pre_terminal_cleanup: Optional pre terminal cleanup; ``None``
                selects the function's default behavior.
            catalog_snapshot: Optional catalog snapshot; ``None`` selects the
                function's default behavior.
        """
        self.tool_config = tool_config
        self.dut_configs = dut_configs
        # Track original config file paths (CLI-provided or auto-detected) so we can
        # archive them into the run-level log directory.
        self.source_tool_config = source_tool_config
        self.source_dut_config = source_dut_config
        self.extra_sensitive_strings = list(
            dict.fromkeys(
                str(value) for value in (extra_sensitive_strings or []) if value
            )
        )
        self.pre_terminal_cleanup = pre_terminal_cleanup
        self.catalog_snapshot = catalog_snapshot
        self.enable_status_tracking = enable_status_tracking
        self.disable_live_display = disable_live_display
        self.skip_validation = skip_validation
        self.orchestrator = None
        self.sanitized_console = None  # Will be set when sanitizer is available
        self.sanitizer = None
        self.finalization_receipt: Optional[FinalizationReceipt] = None
        self.run_result: Optional[RunResult] = None
        self.delivery_result: Optional[DeliveryResult] = None
        self.delivery_result_path: Optional[Path] = None
        self._ssh_host_key_warning_presented = False
        self._redfish_tls_warning_presented = False

        # Start overall runtime timing from tool initialization
        self.tool_start_time = time.time()

        # Start timing for tool initialization
        self.init_start_time = time.time()

    def _sensitive_strings_for_sanitizer(self) -> List[str]:
        """
        Return exact credential canaries without logging their values.

        After applying local validation, the function forwards current instance
        state to ``normalize_sensitive_canary_values`` and preserves its return
        and exception contract.

        Returns:
            The sensitive strings for sanitizer returned in operation-defined
            order.
        """

        values = list(self.extra_sensitive_strings)
        values.extend(extract_sensitive_fields_from_environment())
        return normalize_sensitive_canary_values(values)

    def _username_strings_for_sanitizer(self) -> List[str]:
        """
        Return the invoking operating-system username as an identity canary.

        Identity canaries are redacted only when they appear as complete
        lexical identities. This protects user-specific paths and messages
        without rewriting longer collector, firmware, or kernel identifiers.

        Returns:
            The normalized invoking username, or an empty list when unavailable
            or unsafe as a sanitizer canary.
        """

        current_username = getpass.getuser()
        return normalize_sensitive_canary_values(
            [current_username] if current_username else []
        )

    def _failed_safe_sanitization_failure(self) -> Optional[RuntimeError]:
        """
        Return a bounded terminal failure for an incomplete safe scan.

        After applying local validation, the function forwards current instance
        state to ``RuntimeError`` and preserves its return and exception
        contract.

        Returns:
            A ``RuntimeError`` describing failed safe sanitization failure, or
            ``None`` when the requested value is unavailable.
        """

        tool_config = getattr(self, "tool_config", None)
        if getattr(tool_config, "skip_sanitization", False) or not getattr(
            tool_config, "apply_sanitization", False
        ):
            return None

        orchestrator = getattr(self, "orchestrator", None)
        cleanup_manager = getattr(orchestrator, "cleanup_manager", None)
        report = getattr(cleanup_manager, "bundle_sanitization_report", None)
        if report is None:
            errors = [
                "post-collection sanitization did not produce a completion report"
            ]
        else:
            errors = getattr(report, "errors", None)
        if not isinstance(errors, (list, tuple)):
            errors = ["post-collection sanitization produced malformed evidence"]
        if not errors:
            return None

        rendered_errors = []
        for error in errors[: self._FAILED_SAFE_ERROR_LIMIT]:
            try:
                rendered_errors.append(str(error))
            except Exception:
                rendered_errors.append("[unrenderable sanitization error]")
        detail = "; ".join(rendered_errors)

        sanitizer = (
            getattr(self, "sanitizer", None)
            or getattr(orchestrator, "sanitizer", None)
            or getattr(getattr(orchestrator, "logger", None), "sanitizer", None)
        )
        if sanitizer is not None:
            try:
                detail = str(sanitizer.sanitize(detail))
            except Exception:
                detail = "[sanitization diagnostic unavailable]"

        detail = re.sub(r"[\x00-\x1f\x7f]+", " ", detail).strip()
        omitted = len(errors) - len(rendered_errors)
        omitted_suffix = (
            f"; {omitted} additional error(s) omitted" if omitted > 0 else ""
        )
        prefix = (
            "Bundle sanitization state=failed_safe; "
            f"{len(errors)} artifact(s) could not be safely inspected: "
        )
        detail_limit = max(
            0,
            self._FAILED_SAFE_DIAGNOSTIC_LIMIT - len(prefix) - len(omitted_suffix),
        )
        reason = f"{prefix}{detail[:detail_limit]}{omitted_suffix}"
        return RuntimeError(reason[: self._FAILED_SAFE_DIAGNOSTIC_LIMIT])

    async def _finalize_collection_run(
        self,
        *,
        start_time: Optional[float],
        processed_cids: List[str],
        results: Any,
        active_exception: Optional[BaseException],
        heartbeat: Any,
    ) -> Optional[BaseException]:
        """
        Publish an optional post-collection sanitization diagnostic.

        The implementation uses ``start_time``, ``processed_cids``, ``results``,
        ``active_exception``, and ``heartbeat`` to publish an optional
        post-collection sanitization diagnostic. Success is reported only after
        the owning output boundary has completed its required write or
        publication step. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            start_time: Numeric start time used while the operation performs
                bounded accounting.
            processed_cids: Entries supplied as ``processed_cids`` without
                transferring container ownership.
            results: Results consumed while the function attempts to publish an
                optional post-collection sanitization diagnostic.
            active_exception: Active exception consumed while the function
                attempts to publish an optional post-collection sanitization
                diagnostic.
            heartbeat: Heartbeat consumed while the function attempts to publish
                an optional post-collection sanitization diagnostic.

        Returns:
            A ``BaseException`` describing finalize collection run, or ``None``
            when the requested value is unavailable.
        """

        del start_time, processed_cids, results, active_exception, heartbeat
        cleanup_failure = self._failed_safe_sanitization_failure()
        if cleanup_failure is not None:
            self.sanitized_console.print_warning(
                "Post-collection sanitization was incomplete; reports and archives "
                "were still generated. Treat the bundle as not fully sanitized."
            )

        return None

    def _retain_finalization_receipt(
        self,
        error: Optional[BaseException] = None,
    ) -> Optional[FinalizationReceipt]:
        """
        Retain cleanup evidence before any later CLI fallback can fail.

        The implementation uses ``error`` to retain cleanup evidence before any
        later CLI fallback can fail. It updates ``finalization_receipt`` on the
        instance as part of that state transition.

        Args:
            error: Exception or failure detail associated with the operation.

        Returns:
            A ``FinalizationReceipt`` representing retain finalization receipt,
            or ``None`` when the requested value is unavailable.
        """

        error_receipt = getattr(error, "receipt", None)
        if isinstance(error_receipt, FinalizationReceipt):
            self.finalization_receipt = error_receipt
            return error_receipt
        current_receipt = getattr(self, "finalization_receipt", None)
        if error is None and isinstance(current_receipt, FinalizationReceipt):
            return current_receipt
        orchestrator_receipt = getattr(
            getattr(self, "orchestrator", None),
            "finalization_receipt",
            None,
        )
        if isinstance(orchestrator_receipt, FinalizationReceipt):
            self.finalization_receipt = orchestrator_receipt
            return orchestrator_receipt
        return current_receipt

    def _attach_retained_receipt(
        self,
        primary_error: Optional[BaseException],
    ) -> None:
        """
        Attach immutable cleanup evidence to the process-visible primary.

        The implementation uses ``primary_error`` to attach immutable cleanup
        evidence to the process-visible primary.

        Args:
            primary_error: Primary error consumed while the function attempts to
                attach immutable cleanup evidence to the process-visible
                primary.
        """

        receipt = self._retain_finalization_receipt()
        if primary_error is not None and isinstance(receipt, FinalizationReceipt):
            attach_finalization_receipt(primary_error, receipt)

    def create_cli_dut_config(self, config: "CLIConfig") -> Path:
        """
        Create a temporary DUT config file from CLI arguments.

        The implementation uses ``config`` to create a temporary DUT config file
        from CLI arguments.

        Args:
            config: Config governing temporary DUT config file from CLI
                arguments.

        Returns:
            The validated ``dut_config``.
        """

        dut_config_data = {
            "duts": {
                "cli-dut": {
                    "hostname": config.host_ip or "localhost",
                    "host_username": config.host_user,
                    "host_password": config.host_pass,
                    "ipmi_hostname": config.bmc_ip,
                    "ipmi_username": config.bmc_user,
                    "ipmi_password": config.bmc_pass,
                    "redfish_username": config.bmc_rf_user,
                    "redfish_password": config.bmc_rf_pass,
                    "ssh_username": config.bmc_ssh_user,
                    "ssh_password": config.bmc_ssh_pass,
                    "baseboard": config.baseboard,
                    "collection_level": config.collection_level,
                    # BMC SSH Configuration
                    "bmc_ssh_port": config.bmc_ssh_port,
                    "bmc_ssh_key_path": config.bmc_ssh_key_path,
                    "bmc_ssh_passwordless": config.bmc_ssh_passwordless,
                    "bmc_ssh_max_retries": config.bmc_ssh_max_retries,
                    "bmc_rf_port": config.bmc_rf_port,
                    # Host SSH Configuration
                    "host_ssh_port": config.host_ssh_port,
                    "host_ssh_key_path": config.host_ssh_key_path,
                    "host_ssh_passwordless": config.host_ssh_passwordless,
                    "host_ssh_max_retries": config.host_ssh_max_retries,
                    # HMC Configuration
                    "hmc_ip": config.hmc_ip,
                    "hmc_username": config.hmc_user,
                    "hmc_password": config.hmc_pass,
                    "hmc_ssh_username": config.hmc_ssh_user,
                    "hmc_ssh_password": config.hmc_ssh_pass,
                    "hmc_ssh_port": config.hmc_ssh_port,
                    "hmc_ssh_key_path": config.hmc_ssh_key_path,
                    "hmc_ssh_passwordless": config.hmc_ssh_passwordless,
                    "hmc_ssh_max_retries": config.hmc_ssh_max_retries,
                    "hmc_http_port": config.hmc_http_port,
                    "hmc_https_port": config.hmc_https_port,
                    "hmc_use_https": config.hmc_use_https,
                    "use_port_forwarding": config.use_port_forwarding,
                    "tunnel_tcp_port": config.tunnel_tcp_port,
                    "setup_port_forwarding": (
                        config.setup_port_forwarding
                        if config.setup_port_forwarding is not None
                        else False
                    ),
                    "force_port_fw": (
                        config.force_port_fw
                        if config.force_port_fw is not None
                        else False
                    ),
                    "rf_hmc_access_method": config.hmc_access_method,
                    # SSH Proxy Configuration
                    "ssh_proxy_host": config.ssh_proxy_host,
                    "ssh_proxy_port": config.ssh_proxy_port,
                    "ssh_proxy_username": config.ssh_proxy_user,
                    "ssh_proxy_password": config.ssh_proxy_pass,
                    "ssh_proxy_key_path": config.ssh_proxy_key,
                    "ssh_proxy_passwordless": config.ssh_proxy_passwordless,
                    "ssh_proxy_max_retries": config.ssh_proxy_max_retries,
                    # Execution mode
                    "execution_mode": "local" if config.local else "remote",
                }
            }
        }

        # Create temporary DUT config file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as tmp_file:
            # Note: Temporary files don't need sanitization as they're cleaned up
            yaml.dump(dut_config_data, tmp_file)
            dut_config = Path(tmp_file.name)
        os.chmod(tmp_file.name, 0o600)

        sanitized_console = create_sanitized_console()
        sanitized_console.print_warning(
            "Created temporary DUT config from CLI arguments"
        )
        return dut_config

    def create_tool_config_from_object(self, tool_config: ToolConfig) -> Path:
        """
        Create a temporary tool config file from a ToolConfig object.

        The implementation uses ``tool_config`` to create a temporary tool
        config file from a ToolConfig object.

        Args:
            tool_config: Tool config governing temporary tool config file from a
                ToolConfig object.

        Returns:
            The validated ``tool_config``.
        """

        execution_config = {
            "concurrency_mode": tool_config.concurrency_mode,
            "initial_io_oversubscription": tool_config.initial_io_oversubscription,
            "minimum_collector_operations": tool_config.minimum_collector_operations,
            "maximum_collector_operations": tool_config.maximum_collector_operations,
            "adaptive": dict(tool_config.adaptive_concurrency),
            "max_concurrent_collectors_per_dut": tool_config.max_concurrent_collectors_per_dut,
            "timeout": tool_config.timeout,
            "retry_count": tool_config.retry_count,
        }
        if tool_config.max_concurrent_duts is not None:
            execution_config["max_concurrent_duts"] = tool_config.max_concurrent_duts

        tool_config_data = {
            "execution_config": execution_config,
            "collector_definitions": self._get_collector_definitions_config(),
            "logging": {
                "level": tool_config.log_level,
                "format": tool_config.log_format,
            },
            "output": {
                "directory": tool_config.output_directory,
                "skipzip": tool_config.skip_zip,
                "skipzipsplit": tool_config.skip_zip_split,
                "create_zip": not tool_config.skip_zip,
                "create_split_zip": not tool_config.skip_zip_split,
                "zip_split_threshold": tool_config.zip_split_threshold,
                "generate_html": not tool_config.skip_html_reports,
            },
            # New structured format fields
            "sanitization": {
                "enabled": not tool_config.skip_sanitization,
                "apply_post_collection": tool_config.apply_sanitization,
            },
            "apply_sanitization": tool_config.apply_sanitization,
            # Collection level
            "collection_level": tool_config.collection_level,
            "sysinfo_snapshot_mode": tool_config.sysinfo_snapshot_mode,
            # Add critical parallelization settings
            "PARALLEL_DUT_SEQUENTIAL_COLLECTORS": tool_config.parallel_dut_sequential_collectors,
            "SERVICE_GROUPED_SEQUENTIAL_COLLECTORS": tool_config.service_grouped_sequential_collectors,
            # Add skip flags for orchestrator
            "skip_html_reports": tool_config.skip_html_reports,
            "report_format": tool_config.report_format,
            "skip_zip": tool_config.skip_zip,
            "skip_zip_split": tool_config.skip_zip_split,
            "zip_split_threshold": tool_config.zip_split_threshold,
            # Streaming configuration
            "streaming_only": tool_config.streaming_only,
            "stream_begin": tool_config.stream_begin,
            "stream_end": tool_config.stream_end,
            "stream_destination": tool_config.stream_destination,
            "append": tool_config.append,
            "rack_id": tool_config.rack_id,
        }

        # Create temporary tool config file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as tmp_file:
            # Note: Temporary files don't need sanitization as they're cleaned up
            yaml.dump(tool_config_data, tmp_file)
            tool_config = Path(tmp_file.name)
        os.chmod(tmp_file.name, 0o600)

        # Note: This is a static method, so we create a temporary sanitized console
        sanitized_console = create_sanitized_console()
        sanitized_console.print_warning(
            "Created temporary tool config from CLI arguments"
        )
        return tool_config

    def validate_cli_mode(self, baseboard: Optional[str], cli_args: List[Any]) -> bool:
        """
        Validate CLI mode requirements.

        Note: This is a static method, so we create a temporary sanitized
        console.

        Args:
            baseboard: Text supplied as baseboard in the format accepted by this
                function.
            cli_args: Entries supplied as ``cli_args`` without transferring
                container ownership.

        Returns:
            Whether the CLI mode requirements operation succeeds.
        """
        if not baseboard:
            # Note: This is a static method, so we create a temporary sanitized console
            sanitized_console = create_sanitized_console()
            sanitized_console.print_error(
                "Error: --baseboard is required when using CLI arguments"
            )
            return False
        return True

    def _sanitize_config_dict(
        self,
        config_dict: Dict[str, Any],
        *,
        _inside_extension_config: bool = False,
        _apply_trusted_hook: bool = True,
    ) -> Dict[str, Any]:
        """
        Recursively sanitize all string values in a configuration dictionary.

        The implementation uses ``config_dict``, ``_inside_extension_config``,
        and ``_apply_trusted_hook`` to recursively sanitize all string values in
        a configuration dictionary.

        Args:
            config_dict: Config dict governing recursively sanitize all string
                values in a configuration dictionary.
            _inside_extension_config: Whether inside extension config is enabled
                or required for this operation.
            _apply_trusted_hook: Whether apply trusted hook is enabled or
                required for this operation.

        Returns:
            The validated ``sanitized``.
        """
        if _apply_trusted_hook:
            config_dict = redact_optional_config_mapping(config_dict, "XXXX")
        sanitized = {}
        for key, value in config_dict.items():
            normalized_key = str(key).casefold()
            inside_extension_config = (
                _inside_extension_config
                or normalized_key == "collector_extension_config"
            )
            if _inside_extension_config and (
                normalized_key in {"path", "file", "source"}
                or normalized_key.endswith(("_path", "_file", "_source"))
            ):
                sanitized[key] = "XXXX"
                continue
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_config_dict(
                    value,
                    _inside_extension_config=inside_extension_config,
                    _apply_trusted_hook=False,
                )
            elif isinstance(value, list):
                sanitized[key] = [
                    (
                        self._sanitize_config_dict(
                            item,
                            _inside_extension_config=inside_extension_config,
                            _apply_trusted_hook=False,
                        )
                        if isinstance(item, dict)
                        else (
                            self.sanitizer.sanitize(str(item))
                            if isinstance(item, str)
                            and getattr(self, "sanitizer", None)
                            else item
                        )
                    )
                    for item in value
                ]
            elif isinstance(value, str):
                sanitizer = getattr(self, "sanitizer", None)
                sanitized[key] = sanitizer.sanitize(value) if sanitizer else value
            else:
                sanitized[key] = value
        return sanitized

    @staticmethod
    def create_cli_config_from_args(**kwargs) -> "CLIConfig":
        """
        Create a CLIConfig object from keyword arguments.

        After applying local validation, the function forwards ``kwargs`` to
        ``CLIConfig`` and preserves its return and exception contract.

        Args:
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A ``CLIConfig`` representing CLI config from args.
        """
        return CLIConfig(**kwargs)

    def _find_config_directory(self) -> Path:
        """
        Find the config directory using the shared utility function.

        After applying local validation, the function forwards current instance
        state to ``find_config_directory`` and preserves its return and
        exception contract.

        Returns:
            The validated config directory filesystem path.
        """
        return find_config_directory()

    def _get_collector_definitions_config(self) -> Dict[str, str]:
        """
        Get collector definitions configuration based on spreadsheet path.

        The implementation uses current instance state to get collector
        definitions configuration based on spreadsheet path.

        Returns:
            A mapping containing the ``spreadsheet_path`` fields.
        """
        if not self.tool_config.spreadsheet:
            # Auto-detect spreadsheet using existing logic
            try:
                from .utils.spreadsheet_utils import auto_detect_spreadsheet

                detected_spreadsheet = auto_detect_spreadsheet(
                    None, suppress_print=True
                )
                if detected_spreadsheet:
                    return {"spreadsheet_path": str(detected_spreadsheet)}
            except Exception:
                pass
            # No fallback - let the system handle missing spreadsheet
            return {}

        spreadsheet_path = Path(self.tool_config.spreadsheet)
        if not spreadsheet_path.exists():
            # Try auto-detection if provided path doesn't exist
            try:
                from .utils.spreadsheet_utils import auto_detect_spreadsheet

                detected_spreadsheet = auto_detect_spreadsheet(
                    None, suppress_print=True
                )
                if detected_spreadsheet:
                    return {"spreadsheet_path": str(detected_spreadsheet)}
            except Exception:
                pass
            # No fallback - let the system handle missing spreadsheet
            return {}

        # Detect file type based on extension
        if spreadsheet_path.suffix.lower() in [".xlsx", ".xls"]:
            return {"spreadsheet_path": str(spreadsheet_path)}
        else:
            # Try auto-detection for unsupported file types
            try:
                from .utils.spreadsheet_utils import auto_detect_spreadsheet

                detected_spreadsheet = auto_detect_spreadsheet(
                    None, suppress_print=True
                )
                if detected_spreadsheet:
                    return {"spreadsheet_path": str(detected_spreadsheet)}
            except Exception:
                pass
            # No fallback - let the system handle missing spreadsheet
            return {}

    def validate_config_mode(self, dut_config: Optional[Path]) -> bool:
        """
        Validate config mode requirements.

        Note: This is a static method, so we create a temporary sanitized
        console.

        Args:
            dut_config: filesystem location used as the DUT config for this
                operation.

        Returns:
            Whether the config mode requirements operation succeeds.
        """
        if not dut_config:
            # Note: This is a static method, so we create a temporary sanitized console
            sanitized_console = create_sanitized_console()
            sanitized_console.print_error(
                "Error: --dut-config is required when not using CLI arguments"
            )
            return False

        if not dut_config.exists():
            # Note: This is a static method, so we create a temporary sanitized console
            sanitized_console = create_sanitized_console()
            sanitized_console.print_error(
                f"Error: DUT config file '{dut_config}' does not exist"
            )
            return False

        return True

    def _missing_requested_archive_failure(self) -> Optional[RuntimeError]:
        """
        Return an error when required archive finalization produced nothing.

        After applying local validation, the function forwards current instance
        state to ``RuntimeError`` and preserves its return and exception
        contract.

        Returns:
            A ``RuntimeError`` describing missing requested archive failure, or
            ``None`` when the requested value is unavailable.
        """

        tool_config = getattr(self, "tool_config", None)
        orchestrator = getattr(self, "orchestrator", None)
        if tool_config is None or orchestrator is None:
            return None
        if getattr(tool_config, "dry_run", False) or getattr(
            tool_config, "skip_zip", False
        ):
            return None
        if getattr(orchestrator, "zip_archive_path", None):
            return None
        return RuntimeError(
            "Requested archive creation or verification failed; "
            "no finalized archive was published"
        )

    async def run_collection(self) -> RunResult:
        """
        Run collection and return the one canonical terminal result.

        The implementation uses current instance state to run collection and
        return the one canonical terminal result. Terminal status is emitted
        only after collection and return the one canonical terminal result and
        its owned cleanup have completed. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        It updates ``_redfish_tls_warning_presented`` and
        ``_ssh_host_key_warning_presented`` on the instance as part of that
        state transition. If the function cannot run collection and return the
        one canonical terminal result, its exception reaches the caller instead
        of being converted into a successful result. Cleanup in the ``finally``
        path runs for successful, failed, and cancelled execution.

        Returns:
            A ``RunResult`` representing run collection.

        Raises:
            RuntimeError: If collection lifecycle did not retain an exact
                canonical RunResult.
        """

        original_print = builtins.print
        self._ssh_host_key_warning_presented = False
        self._redfish_tls_warning_presented = False
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=InsecureSSHHostKeyWarning)
                await self._run_collection_impl()
                if type(self.run_result) is not RunResult:
                    raise RuntimeError(
                        "Collection lifecycle did not retain an exact canonical RunResult"
                    )
                return self.run_result
        finally:
            builtins.print = original_print

    def _display_ssh_host_key_policy_warning(self, *, dry_run_mode: bool) -> None:
        """
        Present the insecure SSH policy warning once at the CLI boundary.

        The implementation uses ``dry_run_mode`` to present the insecure SSH
        policy warning once at the CLI boundary. It updates
        ``_ssh_host_key_warning_presented`` on the instance as part of that
        state transition.

        Args:
            dry_run_mode: Whether dry run mode is enabled or required for this
                operation.
        """

        # Dry-run is a security review surface: it must show the posture that
        # the corresponding live run would use.
        _ = dry_run_mode
        if self._ssh_host_key_warning_presented:
            return

        def uses_remote_ssh(dut_config: DUTConfig) -> bool:
            """
            Return the uses remote SSH.

            The implementation uses ``dut_config`` to produce the uses remote
            SSH.

            Args:
                dut_config: DUT config governing uses remote SSH.

            Returns:
                Whether the uses remote SSH operation succeeds.
            """
            return bool(dut_config.bmc_ip or dut_config.hmc_ip) or (
                not dut_config.local and bool(dut_config.host_ip)
            )

        def effective_policy(dut_config: DUTConfig) -> str:
            """
            Return the effective policy.

            The implementation uses ``dut_config`` to produce the effective
            policy.

            Args:
                dut_config: DUT config governing effective policy.

            Returns:
                The canonical effective policy text.
            """
            if "ssh_host_key_policy" in getattr(dut_config, "model_fields_set", set()):
                return str(dut_config.ssh_host_key_policy).strip().lower()
            return (
                str(
                    getattr(self.tool_config, "ssh_host_key_policy", None) or "insecure"
                )
                .strip()
                .lower()
            )

        has_insecure_remote_dut = any(
            uses_remote_ssh(dut_config) and effective_policy(dut_config) == "insecure"
            for dut_config in self.dut_configs
        )
        if not has_insecure_remote_dut:
            return

        self.sanitized_console.print_warning(INSECURE_SSH_HOST_KEY_WARNING_MESSAGE)
        self._ssh_host_key_warning_presented = True

    def _display_redfish_tls_policy_warning(self, *, dry_run_mode: bool) -> None:
        """
        Present the effective insecure Redfish posture once on the console.

        The implementation uses ``dry_run_mode`` to present the effective
        insecure Redfish posture once on the console. It updates
        ``_redfish_tls_warning_presented`` on the instance as part of that state
        transition.

        Args:
            dry_run_mode: Whether dry run mode is enabled or required for this
                operation.
        """

        # A dry-run still resolves transport policy and must disclose an
        # explicit insecure opt-out before an operator performs a live run.
        _ = dry_run_mode
        if self._redfish_tls_warning_presented:
            return

        # Resolve through the runtime resolver rather than a second copy of the
        # precedence rules: a console disclosure that disagrees with the policy
        # the run applies is worse than no disclosure at all.
        try:
            reachable = _insecure_redfish_transport_is_reachable(
                self.dut_configs, self.tool_config
            )
        except ValueError as error:
            # Disclosure is advisory. The runtime resolver rejects the same
            # malformed value at connect time for the affected DUT; this call
            # must not abort the run before that per-DUT failure is recorded.
            self.sanitized_console.print_warning(
                f"Could not resolve the Redfish TLS posture for disclosure: {error}"
            )
            return

        if not reachable:
            return

        self.sanitized_console.print_warning(INSECURE_REDFISH_TRANSPORT_WARNING_MESSAGE)
        self._redfish_tls_warning_presented = True

    async def _run_collection_impl(self) -> Dict[str, Any]:
        """
        Run the collection workflow using the WorkflowOrchestrator.

        This method orchestrates the entire log collection process including
        validation, initialization, collection execution, and cleanup.

        Returns:
            A mapping containing run collection impl.

        Raises:
            RuntimeError: If dry-run plan identity capture is unavailable; the
                function cannot run the collection workflow using the
                WorkflowOrchestrator safely; overall-runtime finalizer returned
                a value; or fallback resource monitor cleanup returned a value.
            TypeError: If collection lifecycle returned a noncanonical
                FinalizationReceipt; or collection lifecycle returned a
                noncanonical RunResult.
            BaseException: If a delegated failure occurs while the function
                attempts to run the collection workflow using the
                WorkflowOrchestrator.
        """
        # Use the tool start time for overall runtime tracking
        start_time = self.tool_start_time

        extra_strings = self._sensitive_strings_for_sanitizer()
        username_strings = self._username_strings_for_sanitizer()

        processed_cids = []
        dry_run_mode = bool(getattr(self.tool_config, "dry_run", False))
        results: Any = None

        try:
            _validate_requested_spa_report_assets(
                self.tool_config,
                dry_run_mode=dry_run_mode,
            )
            if not dry_run_mode:
                # Create tool config file from ToolConfig object.
                config_file = self.create_tool_config_from_object(self.tool_config)

            environment_baseboard = getattr(
                self.tool_config, "environment_baseboard", None
            )
            if dry_run_mode and environment_baseboard:
                # In planning mode the environment value is the final fallback;
                # live platform discovery is deliberately unreachable.
                for dut_config in self.dut_configs:
                    if (
                        "baseboard"
                        not in getattr(dut_config, "model_fields_set", set())
                        and not dut_config.baseboard
                    ):
                        dut_config.baseboard = environment_baseboard

            output_root = (
                self.tool_config.stream_destination
                if self.tool_config.streaming_only
                and self.tool_config.stream_destination
                else self.tool_config.output_directory
            )
            output_base = os.fspath(output_root)
            timestamped_output_namespace = bool(
                not self.tool_config.streaming_only and not self.tool_config.append
            )
            shared_read_output_namespace = not self.tool_config.skip_sanitization
            # Collection destinations may traverse safe or sticky components
            # owned by another UID in every output mode. Descriptor pinning and
            # non-sticky shared-write rejection remain mandatory.
            allow_external_output_owners = True
            if self.tool_config.rack_id is not None:
                rack_id = _require_safe_rack_id(self.tool_config.rack_id)
                output_base = os.path.join(output_base, rack_id)

            if self.tool_config.append or self.tool_config.rack_id is not None:
                output_base = ensure_secure_log_directory(
                    output_base,
                    shared_read=shared_read_output_namespace,
                    repair_existing_permissions=timestamped_output_namespace,
                    allow_sticky_run_parent=timestamped_output_namespace,
                    allow_external_path_owners=allow_external_output_owners,
                )

            if self.tool_config.append:
                log_dir = Path(output_base)
            else:
                timestamped_log_dir = create_timestamped_log_dir(
                    output_base,
                    shared_read=shared_read_output_namespace,
                    repair_existing_permissions=timestamped_output_namespace,
                    allow_external_path_owners=allow_external_output_owners,
                )
                log_dir = Path(timestamped_log_dir)
            sanitization_enabled = not self.tool_config.skip_sanitization
            set_global_sanitization_enabled(sanitization_enabled)

            dut_config_data = {dut.name: dut.__dict__ for dut in self.dut_configs}
            self.sanitizer = create_sanitizer_from_config(
                dut_config_data,
                enabled=sanitization_enabled,
                extra_strings=extra_strings,
                username_strings=username_strings,
            )
            patch_print_with_sanitizer(self.sanitizer)
            self.sanitized_console = create_sanitized_console(self.sanitizer)

            if sanitization_enabled:
                self.sanitized_console.print_warning("Log sanitization enabled")
            else:
                self.sanitized_console.print_warning(
                    "UNSAFE_TO_SHARE: log sanitization was explicitly disabled"
                )

            self._display_ssh_host_key_policy_warning(dry_run_mode=dry_run_mode)
            self._display_redfish_tls_policy_warning(dry_run_mode=dry_run_mode)

            if self.tool_config.append:
                self.sanitized_console.print_success(
                    f"Using append-mode log directory: {log_dir}"
                )
            else:
                self.sanitized_console.print_success(
                    f"Created timestamped log directory: {log_dir}"
                )

            # Archive config files into the run directory (sanitized, best-effort)
            self._archive_config_files(log_dir)

            # Print ASCII header to console
            self.sanitized_console.print_info(ASCII_HEADER)

            # Create orchestrator with ToolConfig object
            self.orchestrator = WorkflowOrchestrator(
                tool_config=self.tool_config,
                dut_configs=self.dut_configs,
                log_dir=str(log_dir),
                enable_status_tracking=self.enable_status_tracking,
                disable_live_display=self.disable_live_display,
                catalog_snapshot=self.catalog_snapshot,
            )
            self.orchestrator.pre_terminal_cleanup = self.pre_terminal_cleanup

            # Set sanitizer in orchestrator (always pass sanitizer, it handles enabled/disabled internally)
            self.orchestrator.set_sanitizer(self.sanitizer)

            # End timing for configuration loading
            if (
                hasattr(self.orchestrator, "timing_manager")
                and self.orchestrator.timing_manager
            ):
                self.orchestrator.timing_manager.end_component("configuration_loading")

            # Start timing for overall runtime (from tool start)
            if (
                hasattr(self.orchestrator, "timing_manager")
                and self.orchestrator.timing_manager
            ):
                self.orchestrator.timing_manager.start_component("overall_runtime")

            # Start logging system first
            await self.orchestrator.logger.start()

            # Capture the scheduler inputs and an immediate resource baseline
            # before initialization or collector work starts.
            start_resource_monitor = getattr(
                self.orchestrator, "start_resource_monitor", None
            )
            if callable(start_resource_monitor):
                await start_resource_monitor()

            # Log startup information
            await self.orchestrator.logger.log_runtime(
                "INFO", "CLICollector", "Starting NVDebug Tool collection"
            )
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"DUT configs: {[dut.name for dut in self.dut_configs]}",
            )
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Output directory: {self.tool_config.output_directory}",
            )
            await self.orchestrator.logger.log_runtime(
                "INFO", "CLICollector", f"Log directory: {log_dir}"
            )
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Collection level: {self.tool_config.collection_level}",
            )

            # Initialize orchestrator
            await self.orchestrator.initialize()
            if self.orchestrator.dut_manager is None:
                initialization_error = getattr(
                    self.orchestrator,
                    "dut_manager_initialization_error",
                    None,
                )
                if initialization_error is None:
                    raise RuntimeError(
                        "DUT manager initialization completed without a manager"
                    )
                raise RuntimeError(
                    f"DUT manager initialization failed: {initialization_error}"
                ) from initialization_error

            # End timing for tool initialization
            if (
                hasattr(self.orchestrator, "timing_manager")
                and self.orchestrator.timing_manager
            ):
                self.orchestrator.timing_manager.end_component("tool_initialization")

            # Handle baseboard detection
            # Check if all DUTs have baseboard configured
            duts_without_baseboard = []
            duts_with_cli_baseboard = []

            for dut in self.dut_configs:
                if _resolved_baseboard_value(dut.baseboard) is not None:
                    # This DUT has a baseboard specified (either via CLI or config file)
                    duts_with_cli_baseboard.append(dut.name)

                    # Ensure the baseboard is set in the orchestrator
                    if self.orchestrator.dut_manager.duts.get(dut.name):
                        self.orchestrator.dut_manager.duts[dut.name].config[
                            "baseboard"
                        ] = dut.baseboard
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            f"Set baseboard '{dut.baseboard}' for DUT {dut.name}",
                        )
                else:
                    # No baseboard specified - auto-detection will handle it
                    duts_without_baseboard.append(dut.name)

            # If we have DUTs with baseboards, use them directly
            if duts_with_cli_baseboard:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"DUTs with baseboard configured: {duts_with_cli_baseboard}",
                )
                self.sanitized_console.print_success(
                    f"\n\nUsing configured baseboard for DUT(s): {', '.join(duts_with_cli_baseboard)}"
                )

            if duts_without_baseboard:
                detection_message = (
                    "baseboard will remain unresolved in the transport-free plan"
                    if dry_run_mode
                    else "will attempt auto-detection after preflight checks"
                )
                await self.orchestrator.logger.log_runtime(
                    "WARN",
                    "CLICollector",
                    f"DUTs without baseboard configured: {duts_without_baseboard} - {detection_message}",
                )
                self.sanitized_console.print_warning(
                    f"\n\nDUTs without baseboard configured: {', '.join(duts_without_baseboard)}"
                )
                self.sanitized_console.print_info(detection_message.capitalize())

            dut_ids = self.orchestrator.dut_manager.get_all_dut_ids()

            await self.orchestrator.logger.log_runtime(
                "INFO", "CLICollector", f"Found {len(dut_ids)} DUT(s): {dut_ids}"
            )

            autodetection_preflight_results = None
            if getattr(self.tool_config, "dry_run", False):
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    "Skipping preflight checks in dry-run mode",
                )
            elif getattr(self.tool_config, "skip_preflight", False):
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    "Skipping preflight checks before autodetection",
                )
            elif duts_without_baseboard:
                # Collector applicability cannot be resolved until the
                # baseboard is known. Probe only the transports consumed by
                # auto-detection; execution owns the exact post-filter
                # collector preflight later in the workflow.
                autodetection_preflight_results = (
                    await self.orchestrator.run_preflight_checks(
                        show_progress=True,
                        service_candidates=["redfish", "host"],
                        preflight_label="Auto-detection Connectivity",
                    )
                )
                if (
                    autodetection_preflight_results
                    and "error" in autodetection_preflight_results
                ):
                    _preflight_err = autodetection_preflight_results.get(
                        "error", "Preflight checks failed"
                    )
                    _preflight_err_str = (
                        _preflight_err
                        if isinstance(_preflight_err, str)
                        else str(_preflight_err)
                    )
                    await self.orchestrator.logger.log_runtime(
                        "ERROR",
                        "CLICollector",
                        f"Preflight checks failed: {_preflight_err_str}",
                    )
                    self.sanitized_console.print_error(
                        f"Preflight checks failed: {_preflight_err_str}"
                    )
                    return {
                        "success": False,
                        "error": _preflight_err_str,
                        "preflight_results": autodetection_preflight_results,
                    }
            else:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    "Deferring preflight checks until collector selection and applicability filtering",
                )

            if dry_run_mode:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    "Skipping platform/baseboard autodetection in dry-run mode",
                )
            else:
                await self._run_autodetection(dut_ids, autodetection_preflight_results)

            processed_cids, requested_cids = await self._resolve_collector_selection()
            # Keep selection resolution robust for subclasses and test harnesses
            # that override the legacy selector hook while returning its public
            # two-list contract. The production hook records these richer
            # inputs itself before applying additive includes.
            if not hasattr(self, "_base_selected_collectors"):
                self._base_selected_collectors = list(dict.fromkeys(processed_cids))
            if not hasattr(self, "_global_explicit_selector_ids"):
                self._global_explicit_selector_ids = list(dict.fromkeys(requested_cids))
            resolved_selection = self._resolve_per_dut_collector_selection(dut_ids)
            processed_cids, requested_cids = self._apply_resolved_selection_union(
                resolved_selection
            )
            self.orchestrator.execution_engine.resolved_collector_selection = (
                resolved_selection
            )

            # Query each discovered System's Dump ActionInfo before per-DUT
            # applicability filtering, but only when the selected collectors use
            # that capability map (or R46 must record it).  Dry-run remains free
            # of this additional live probe.
            capability_required = (
                self.orchestrator.collectors_require_system_dump_capabilities(
                    processed_cids
                )
            )
            if (
                not getattr(self.tool_config, "dry_run", False)
                and capability_required is True
            ):
                await self.orchestrator.discover_system_dump_capabilities(
                    dut_ids=dut_ids,
                    preflight_results=autodetection_preflight_results,
                )

            await self.orchestrator.logger.log_runtime(
                "INFO", "CLICollector", f"Input processed_cids: {processed_cids}"
            )

            if dry_run_mode and duts_without_baseboard:
                # Applicability filtering needs a baseboard. Preserve the
                # selector/level result without contacting a target to infer it.
                filtered_collectors_per_dut = {
                    dut_id: list(processed_cids) for dut_id in dut_ids
                }
                skipped_collectors_per_dut = {dut_id: {} for dut_id in dut_ids}
                all_filtered_collectors = list(processed_cids)
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    "Dry-run applicability is conservative because baseboard is unresolved",
                )
            else:
                (
                    all_filtered_collectors,
                    filtered_collectors_per_dut,
                    skipped_collectors_per_dut,
                ) = await self._filter_and_display_collectors(processed_cids, dut_ids)

            # Step 3: Choose between dry run or actual execution
            if self.tool_config.dry_run:
                shared_tool_config = (
                    self.orchestrator.config_manager.get_tool_config() or {}
                )
                for dut_id in dut_ids:
                    dut = self.orchestrator.dut_manager.get_dut(dut_id)
                    static_config = dut.config if dut is not None else {}
                    projected_tool_config = self._project_dry_run_catalog_timeout(
                        shared_tool_config,
                        filtered_collectors_per_dut.get(dut_id, []),
                    )
                    await self.orchestrator.logger.create_config_files(
                        dut_id,
                        projected_tool_config,
                        static_config,
                    )
                    await self.orchestrator.logger.write_dut_metadata(
                        dut_id,
                        {
                            "PlatformModel": static_config.get("baseboard", "Unknown"),
                            "PartNumber": "Unknown",
                            "SerialNumber": "Unknown",
                            "Baseboard": static_config.get("baseboard", "Unknown"),
                            "DUT_ID": dut_id,
                            "run_mode": "dry_run",
                            "transport_calls": 0,
                        },
                    )

                self._write_collection_plan(
                    log_dir=log_dir,
                    dut_ids=dut_ids,
                    requested_collectors=requested_cids or processed_cids,
                    filtered_collectors_per_dut=filtered_collectors_per_dut,
                    skipped_collectors_per_dut=skipped_collectors_per_dut,
                )
                capture_planning_identity = getattr(
                    self.orchestrator,
                    "capture_planning_plan_identity",
                    None,
                )
                if not callable(capture_planning_identity):
                    raise RuntimeError("Dry-run plan identity capture is unavailable")
                capture_planning_identity()

                await self.orchestrator.logger.log_runtime(
                    "INFO", "CLICollector", "DRY RUN MODE - simulation complete"
                )
                self.sanitized_console.print_warning(
                    "DRY RUN MODE - No actual execution"
                )
                return {
                    "dry_run": True,
                    "filtered_collectors_per_dut": filtered_collectors_per_dut,
                    "all_filtered_collectors": all_filtered_collectors,
                    "total_collectors": len(all_filtered_collectors),
                }
            else:
                is_multi_dut = len(dut_ids) > 1

                if is_multi_dut:
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        f"Multi-DUT operation detected ({len(dut_ids)} DUTs). Skipping baseboard detection.",
                    )
                    self.sanitized_console.print_info(
                        f"Multi-DUT operation detected ({len(dut_ids)} DUTs). Skipping baseboard detection."
                    )
                    self.sanitized_console.print_info(
                        "Please ensure baseboard is properly configured in config files."
                    )

                    # Validate that baseboard is set in config files for all DUTs
                    missing_configs = []
                    for dut_id in dut_ids:
                        dut_config = self.orchestrator.dut_manager.duts[dut_id].config
                        if not dut_config.get("baseboard"):
                            missing_configs.append(f"{dut_id}: missing baseboard")

                    if missing_configs:
                        await self.orchestrator.logger.log_runtime(
                            "WARNING",
                            "CLICollector",
                            f"Multi-DUT baseboard gaps (auto-detection may have partially failed): {', '.join(missing_configs)}",
                        )
                        self.sanitized_console.print_warning(
                            f"Warning: Some DUTs are missing baseboard after auto-detection: {', '.join(missing_configs)}"
                        )
                        self.sanitized_console.print_warning(
                            "Collection will proceed but collectors may be limited for DUTs without baseboard."
                        )
                    else:
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            "✓ Baseboard configuration verified in config files.",
                        )
                        self.sanitized_console.print_success(
                            "✓ Baseboard configuration verified in config files."
                        )
                else:
                    # Single DUT operation - auto-detection will be handled by the orchestrator
                    # during its execution flow (after preflight checks)
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        "Single DUT operation - auto-detection will be handled during execution flow",
                    )
                    self.sanitized_console.print_info(
                        "Single DUT operation - auto-detection will be handled during execution flow"
                    )

                # Platform info gathering and dynamic discovery are now handled in the new execution flow

                # Show what collectors were requested (before baseboard filtering)
                if processed_cids:
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        f"Requested collectors: {processed_cids}",
                    )
                    # Log comprehensive collector selection table
                    await self.orchestrator.log_collector_selection_table(
                        processed_cids
                    )

                # Execute collectors
                await self.orchestrator.logger.log_runtime(
                    "INFO", "CLICollector", "Executing collectors..."
                )
                self.sanitized_console.print_info("\nExecuting collectors...\n")

                from asyncio import CancelledError

                # Bind the exact plan before entering the fallible execution
                # seam.  The production executor repeats this same idempotent
                # bind, while an injected/early control-flow failure still has
                # enough durable status evidence to derive a canonical result.
                # Bind the complete scheduling union. ``requested_cids`` is
                # evidence for positive selector intent, while additive
                # includes must not erase the default collectors from durable
                # accounting.
                original_collector_ids = processed_cids
                status_tracker = getattr(self.orchestrator, "status_tracker", None)
                if status_tracker is not None:
                    await status_tracker.initialize_collection(
                        dut_ids=dut_ids,
                        collector_ids=list(original_collector_ids),
                        config_manager=self.orchestrator.config_manager,
                    )
                explicit_pairs = self._selection_explicit_pairs(resolved_selection)

                try:
                    results = await self.orchestrator.execute_collectors(
                        filtered_collectors_per_dut=filtered_collectors_per_dut,
                        skipped_collectors_per_dut=skipped_collectors_per_dut,
                        collection_level=self.tool_config.collection_level,
                        original_collector_ids=original_collector_ids,
                        explicit_collector_pairs=explicit_pairs,
                        # Execution owns the exact per-DUT preflight after
                        # collector applicability has been resolved. Broad
                        # autodetection results must not bypass that check.
                        preflight_results=None,
                    )
                except CancelledError as error:
                    if self.orchestrator.is_shutdown_requested():
                        raise

                    reason = "Collection task was cancelled without a shutdown request"
                    status_tracker = getattr(self.orchestrator, "status_tracker", None)
                    if status_tracker is not None:
                        await status_tracker.set_run_outcome(
                            "runtime_failed",
                            failure_type="runtime_exception",
                            reason=reason,
                            affected_duts=dut_ids,
                        )
                    raise RuntimeError(reason) from error

                executed_pairs = _executed_collector_pairs(results)
                executed_unscoped_ids = {
                    collector_id
                    for result_dut, collector_id in executed_pairs
                    if result_dut is None
                }
                executed_scoped_pairs = {
                    (str(result_dut), collector_id)
                    for result_dut, collector_id in executed_pairs
                    if result_dut is not None
                }
                executed_explicit_pairs = {
                    pair
                    for pair in explicit_pairs
                    if pair in executed_scoped_pairs or pair[1] in executed_unscoped_ids
                }
                preflight_blocked_pairs = (
                    _preflight_blocked_collector_pairs(results) & explicit_pairs
                )
                if preflight_blocked_pairs:
                    selection_failure_type = "explicit_selection_preflight_failure"
                    affected_pairs = preflight_blocked_pairs
                    selection_reason = (
                        "Explicit collector selection failed required preflight "
                        f"for {len(affected_pairs)} DUT/collector pair(s)"
                    )
                elif explicit_pairs and not executed_explicit_pairs:
                    selection_failure_type = "explicit_selection_no_execution"
                    affected_pairs = explicit_pairs
                    selection_reason = (
                        "Explicit collector selection produced no collector "
                        f"execution for {len(affected_pairs)} DUT/collector pair(s)"
                    )
                else:
                    selection_failure_type = None
                    affected_pairs = set()
                    selection_reason = ""

                if selection_failure_type is not None:
                    selection_failure = self._write_selection_failure_evidence(
                        log_dir=log_dir,
                        requested_collectors=requested_cids or processed_cids,
                        filtered_collectors_per_dut=filtered_collectors_per_dut,
                        skipped_collectors_per_dut=skipped_collectors_per_dut,
                        results=results,
                        reason=selection_reason,
                        failure_type=selection_failure_type,
                        resolved_selection=resolved_selection,
                        affected_pairs=affected_pairs,
                    )
                    results["domain_failure"] = True
                    results["failure_type"] = selection_failure_type
                    results["reason"] = selection_failure["reason"]
                    results["selection_failure"] = selection_failure
                    self.sanitized_console.print_error(selection_failure["reason"])

                # Get the actual executed collectors from results
                executed_collectors = set()
                sequential_results = results.get("sequential_results", {})
                parallel_results = results.get("parallel_results", {})
                for collector_id in sequential_results:
                    executed_collectors.add(collector_id)
                for collector_id in parallel_results:
                    executed_collectors.add(collector_id)

                # Check if shutdown was requested during execution
                if self.orchestrator.is_shutdown_requested():
                    await self.orchestrator.logger.log_runtime(
                        "WARN",
                        "CLICollector",
                        "Collection was interrupted by user. Continuing with post-collection flows...",
                    )
                    self.sanitized_console.print_warning(
                        "Collection interrupted. Finishing up..."
                    )
                else:
                    # Log the collectors that were executed (after baseboard filtering)
                    if executed_collectors:
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            f"Executed collectors: {sorted(list(executed_collectors))}",
                        )
                        self.sanitized_console.print_info(
                            f"Executed collectors: {', '.join(sorted(executed_collectors))}"
                        )
                    else:
                        await self.orchestrator.logger.log_runtime(
                            "WARN",
                            "CLICollector",
                            "No collectors were executed (all were filtered out)",
                        )
                        self.sanitized_console.print_warning(
                            "No collectors were executed (all were filtered out)"
                        )

                    # Collector execution has ended; final outcome is established
                    # only after teardown, sanitization, reports, and archive work.
                    await self.orchestrator.logger.log_runtime(
                        "INFO", "CLICollector", "Collector execution phase completed"
                    )

                return results

        except Exception as e:
            error_msg = f"Collection failed: {str(e)}"
            if self.orchestrator and self.orchestrator.logger:
                await self.orchestrator.logger.log_runtime(
                    "ERROR", "CLICollector", error_msg
                )

            # Safely handle console output - create one if not available
            if self.sanitized_console is None:
                self.sanitized_console = create_sanitized_console()

            self.sanitized_console.print_error(f"{error_msg}")
            if self.tool_config.debug:
                self.sanitized_console.print_error("Exception details:")
                # Note: console.print_exception() is a Rich method, we'll keep it for now
                Console().print_exception()
            raise
        finally:
            # Ensure cleanup happens
            if self.orchestrator:
                active_exception = sys.exc_info()[1]
                cleanup_failed = False
                cleanup_error: Optional[BaseException] = None
                emergency_cleanup_error: Optional[BaseException] = None
                outcome_projection_error: Optional[BaseException] = None
                boundary_errors: List[BaseException] = []
                if active_exception is not None:
                    boundary_errors.append(active_exception)
                try:
                    if (
                        active_exception is None
                        and not dry_run_mode
                        and results is not None
                        and collection_result_has_domain_failure(results)
                    ):
                        status_tracker = getattr(
                            self.orchestrator, "status_tracker", None
                        )
                        setter = getattr(status_tracker, "set_run_outcome", None)
                        if callable(setter):
                            try:
                                selection_failure = results.get("selection_failure")
                                if isinstance(selection_failure, dict):
                                    failure_type = str(
                                        selection_failure.get("failure_type") or ""
                                    )
                                    failure_reason = str(
                                        selection_failure.get("reason") or ""
                                    )
                                    selection = selection_failure.get("selection")
                                    affected_pairs = (
                                        selection.get("affected_pairs", [])
                                        if isinstance(selection, dict)
                                        else []
                                    )
                                    affected_duts = list(
                                        dict.fromkeys(
                                            str(pair.get("dut_id"))
                                            for pair in affected_pairs
                                            if isinstance(pair, dict)
                                            and pair.get("dut_id")
                                        )
                                    )
                                else:
                                    failure_type = "collector_result_failure"
                                    failure_reason = (
                                        "Collector execution produced one or more "
                                        "failed or partial results"
                                    )
                                    affected_duts = (
                                        collection_result_domain_failure_duts(
                                            results,
                                            dut_ids,
                                        )
                                    )
                                await setter(
                                    "domain_failed",
                                    failure_type=failure_type,
                                    reason=failure_reason,
                                    evidence=(
                                        EXPLICIT_SELECTION_EVIDENCE_PATH
                                        if isinstance(selection_failure, dict)
                                        else None
                                    ),
                                    affected_duts=affected_duts,
                                )
                            except BaseException as error:
                                outcome_projection_error = error
                                boundary_errors.append(error)

                    # Calculate total runtime for HTML reports
                    total_runtime = time.time() - start_time if start_time else None

                    # Presentation cannot prevent mandatory cleanup. Preserve a
                    # process-control failure as data, continue to the durable
                    # boundary, then select it recursively with cleanup errors.
                    try:
                        if total_runtime is not None:
                            human_readable_time = OutputFormatter.format_time(
                                total_runtime
                            )
                            if total_runtime >= 60:
                                execution_time_msg = f"\nTotal execution time: {human_readable_time} ({total_runtime:.2f} seconds)"
                            else:
                                execution_time_msg = (
                                    f"\nTotal execution time: {human_readable_time}"
                                )
                            self.sanitized_console.print_success(execution_time_msg)
                            if self.orchestrator and self.orchestrator.logger:
                                await self.orchestrator.logger.log_runtime(
                                    "INFO", "CLICollector", execution_time_msg
                                )
                    except BaseException as error:
                        boundary_errors.append(error)

                    # End timing for overall runtime
                    try:
                        timing_manager = getattr(
                            self.orchestrator, "timing_manager", None
                        )
                        if timing_manager is not None:
                            timing_result = timing_manager.end_component(
                                "overall_runtime"
                            )
                            if timing_result is not None:
                                raise RuntimeError(
                                    "Overall-runtime finalizer returned a value"
                                )
                    except BaseException as error:
                        boundary_errors.append(error)

                    # Keep report/archive work visible even when synchronous
                    # filesystem code stalls the event loop. Presentation
                    # failures must never bypass mandatory teardown.
                    heartbeat = None
                    try:
                        heartbeat = FinalizationHeartbeat(self.sanitized_console)
                        heartbeat.start()
                    except BaseException as error:
                        boundary_errors.append(error)

                    cleanup_input = (
                        select_authoritative_exception(boundary_errors)
                        if boundary_errors
                        else None
                    )

                    try:
                        self.finalization_receipt = await self.orchestrator.cleanup(
                            total_runtime,
                            processed_cids,
                            active_exception=cleanup_input,
                        )
                    finally:
                        if heartbeat is not None:
                            try:
                                heartbeat.stop()
                            except BaseException as error:
                                boundary_errors.append(error)
                    if type(self.finalization_receipt) is not FinalizationReceipt:
                        raise TypeError(
                            "Collection lifecycle returned a noncanonical "
                            "FinalizationReceipt"
                        )
                    candidate_result = getattr(self.orchestrator, "run_result", None)
                    if type(candidate_result) is RunResult:
                        self.run_result = candidate_result
                    elif candidate_result is not None:
                        raise TypeError(
                            "Collection lifecycle returned a noncanonical RunResult"
                        )
                    elif dry_run_mode:
                        self.run_result = RunResult.from_planning_receipt(
                            self.finalization_receipt
                        )
                    else:
                        self.run_result = RunResult.from_finalization_receipt(
                            self.finalization_receipt
                        )
                except BaseException as error:
                    cleanup_failed = True
                    cleanup_error = error
                    boundary_errors.append(error)
                    self._retain_finalization_receipt(error)
                    retained_result = getattr(self.orchestrator, "run_result", None)
                    if type(retained_result) is RunResult:
                        self.run_result = retained_result
                    elif retained_result is not None:
                        retained_type_error = TypeError(
                            "Collection lifecycle retained a noncanonical RunResult"
                        )
                        cleanup_error = retained_type_error
                        boundary_errors.append(retained_type_error)
                    # Safely handle console output - create one if not available
                    if self.sanitized_console is None:
                        self.sanitized_console = create_sanitized_console()
                    try:
                        self.sanitized_console.print_warning(
                            f"Warning: Cleanup error: {error}"
                        )
                    except BaseException as presentation_error:
                        boundary_errors.append(presentation_error)

                canonical_result_committed = False
                if (
                    type(self.run_result) is RunResult
                    and type(self.finalization_receipt) is FinalizationReceipt
                    and self.finalization_receipt.mandatory_teardown_complete
                ):
                    try:
                        validate_structural_finalization_receipt(
                            self.finalization_receipt
                        )
                        projector = (
                            RunResult.from_planning_receipt
                            if self.run_result.mode is RunMode.PLANNING
                            else RunResult.from_finalization_receipt
                        )
                        canonical_result_committed = (
                            projector(self.finalization_receipt) == self.run_result
                        )
                    except BaseException as error:
                        canonical_result_committed = False
                        boundary_errors.append(error)

                # These fallbacks are exclusively for cleanup paths that did
                # not produce a receipt-bound canonical result.  A committed
                # receipt already proves resource-monitor shutdown and the
                # mandatory aiohttp sweep, so rerunning either after terminal
                # publication could only manufacture a contradictory failure.
                if not canonical_result_committed:
                    try:
                        stop_resource_monitor = getattr(
                            self.orchestrator, "stop_resource_monitor", None
                        )
                        if callable(stop_resource_monitor):
                            stop_result = stop_resource_monitor()
                            if inspect.isawaitable(stop_result):
                                stop_result = await stop_result
                            if stop_result is not None:
                                raise RuntimeError(
                                    "Fallback resource monitor cleanup returned a value"
                                )
                    except BaseException as error:
                        cleanup_failed = True
                        boundary_errors.append(error)
                        if cleanup_error is None:
                            cleanup_error = error
                        if self.sanitized_console is None:
                            self.sanitized_console = create_sanitized_console()
                        try:
                            self.sanitized_console.print_warning(
                                f"Warning: Resource telemetry cleanup error: {error}"
                            )
                        except BaseException as presentation_error:
                            boundary_errors.append(presentation_error)

                    try:
                        await self._emergency_cleanup()
                    except BaseException as error:
                        cleanup_failed = True
                        emergency_cleanup_error = error
                        boundary_errors.append(error)
                        if cleanup_error is None:
                            cleanup_error = error
                        if self.sanitized_console is None:
                            self.sanitized_console = create_sanitized_console()
                        try:
                            self.sanitized_console.print_warning(
                                f"Warning: Emergency cleanup error: {error}"
                            )
                        except BaseException as presentation_error:
                            boundary_errors.append(presentation_error)

                if (
                    emergency_cleanup_error is not None
                    and self.finalization_receipt is not None
                    and not canonical_result_committed
                ):
                    emergency_failure = sanitize_finalization_failure(
                        "cli_emergency_cleanup",
                        emergency_cleanup_error,
                    )
                    failures = tuple(
                        dict.fromkeys(
                            (*self.finalization_receipt.failures, emergency_failure)
                        )
                    )
                    self.finalization_receipt = (
                        self.finalization_receipt.with_cleanup_evidence(
                            completed_teardown_phases=(
                                self.finalization_receipt.completed_teardown_phases
                            ),
                            failures=failures,
                        ).with_interruption(
                            is_interruption_exception(emergency_cleanup_error)
                        )
                    )

                archive_failure = self._missing_requested_archive_failure()
                if archive_failure is not None:
                    boundary_errors.append(archive_failure)
                    try:
                        self.sanitized_console.print_error(
                            f"Finalization failed: {archive_failure}"
                        )
                    except BaseException as presentation_error:
                        boundary_errors.append(presentation_error)
                    if cleanup_error is None:
                        cleanup_error = archive_failure

                selected_error = (
                    select_authoritative_exception(boundary_errors)
                    if boundary_errors
                    else None
                )
                self._attach_retained_receipt(selected_error)
                safe_post_collection_failure = bool(
                    active_exception is None
                    and canonical_result_committed
                    and type(self.finalization_receipt) is FinalizationReceipt
                    and bool(self.finalization_receipt.failures)
                    and finalization_failures_allow_delivery(self.finalization_receipt)
                )
                if (
                    selected_error is not None
                    and selected_error is not active_exception
                    and not safe_post_collection_failure
                ):
                    raise selected_error
                if active_exception is None and self.run_result is not None:
                    self._display_final_output(
                        log_dir,
                        run_result=self.run_result,
                    )

    def _project_dry_run_catalog_timeout(
        self,
        tool_config: Mapping[str, Any],
        selected_collectors: Iterable[str],
    ) -> Dict[str, Any]:
        """
        Return a per-DUT dry-run config with an unambiguous catalog timeout.

        A single-collector plan has one catalog-owned timeout, so its public
        ``config.json`` can project that value into the legacy
        ``execution_config.timeout`` observer without ambiguity. Multiple- or
        zero-collector plans retain the resolved tool configuration because one
        scalar field cannot truthfully represent several collector timeouts.
        The input mapping and all of its nested values remain unmodified.

        Args:
            tool_config: Shared resolved tool configuration used as the source
                for a private per-DUT projection.
            selected_collectors: Collector identifiers selected for one DUT
                after applicability filtering.

        Returns:
            A deep-copied tool configuration whose legacy timeout observer is
            replaced by the selected collector's positive catalog timeout when
            the selection contains exactly one collector.
        """

        projected = copy.deepcopy(dict(tool_config))
        selection = tuple(dict.fromkeys(selected_collectors))
        if len(selection) != 1:
            return projected

        collector_info = self.orchestrator.config_manager.get_collector_info(
            selection[0]
        )
        raw_timeout = (
            collector_info.get("timeout")
            if isinstance(collector_info, Mapping)
            else None
        )
        if (
            isinstance(raw_timeout, bool)
            or not isinstance(raw_timeout, (int, float))
            or not math.isfinite(raw_timeout)
            or raw_timeout <= 0
        ):
            return projected

        raw_execution_config = projected.get("execution_config")
        execution_config = (
            dict(raw_execution_config)
            if isinstance(raw_execution_config, Mapping)
            else {}
        )
        execution_config["timeout"] = int(raw_timeout)
        projected["execution_config"] = execution_config
        return projected

    def _write_collection_plan(
        self,
        *,
        log_dir: Path,
        dut_ids: List[str],
        requested_collectors: List[str],
        filtered_collectors_per_dut: Dict[str, Any],
        skipped_collectors_per_dut: Dict[str, Any],
    ) -> None:
        """
        Atomically publish the transport-free dry-run planning artifact.

        The implementation uses ``log_dir``, ``dut_ids``,
        ``requested_collectors``, ``filtered_collectors_per_dut``, and
        ``skipped_collectors_per_dut`` to atomically publish the transport-free
        dry-run planning artifact. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot atomically publish the transport-free dry-run planning artifact,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            requested_collectors: Entries supplied as ``requested_collectors``
                without transferring container ownership.
            filtered_collectors_per_dut: Mapping supplying fields for atomically
                publish the transport-free dry-run planning artifact.
            skipped_collectors_per_dut: Mapping supplying fields for atomically
                publish the transport-free dry-run planning artifact.

        Raises:
            TypeError: If the dry-run skipped collector evidence is not an
                object; or the dry-run skipped collector evidence is not a
                mapping or list.
            ValueError: If dry-run skipped collector evidence is malformed.
        """
        plan_duts = []
        for dut_id in dut_ids:
            dut = self.orchestrator.dut_manager.get_dut(dut_id)
            dut_config = dut.config if dut is not None else {}
            raw_skipped = skipped_collectors_per_dut.get(dut_id, {}) or {}
            if isinstance(raw_skipped, dict):
                planning_skips = dict(raw_skipped)
            elif isinstance(raw_skipped, list):
                planning_skips = {}
                for entry in raw_skipped:
                    if not isinstance(entry, dict):
                        raise TypeError(
                            "Dry-run skipped collector evidence must be an object"
                        )
                    collector_id = entry.get("collector_id")
                    reason = entry.get("reason", "")
                    if (
                        type(collector_id) is not str
                        or not collector_id
                        or type(reason) is not str
                        or collector_id in planning_skips
                    ):
                        raise ValueError(
                            "Dry-run skipped collector evidence is malformed"
                        )
                    planning_skips[collector_id] = reason
            else:
                raise TypeError(
                    "Dry-run skipped collector evidence must be a mapping or list"
                )
            plan_duts.append(
                {
                    "id": dut_id,
                    "baseboard": dut_config.get("baseboard"),
                    "selected_collectors": list(
                        filtered_collectors_per_dut.get(dut_id, []) or []
                    ),
                    "skipped_collectors": planning_skips,
                }
            )

        plan = {
            "schema_version": "1.0",
            "mode": "dry_run",
            "transport_calls": 0,
            "collection_level": self.tool_config.collection_level,
            "requested_collectors": list(requested_collectors or []),
            "duts": plan_duts,
        }
        configured_oversubscription = self.tool_config.initial_io_oversubscription
        if configured_oversubscription is None:
            fallback_resolution = resolve_collector_operation_resources()
        else:
            fallback_resolution = resolve_collector_operation_resources(
                configured_oversubscription
            )
        fallback_settings = AdmissionControllerSettings.from_execution_config(
            {
                "concurrency_mode": self.tool_config.concurrency_mode,
                "initial_io_oversubscription": configured_oversubscription,
                "minimum_collector_operations": (
                    self.tool_config.minimum_collector_operations
                ),
                "maximum_collector_operations": (
                    self.tool_config.maximum_collector_operations
                ),
                "adaptive": self.tool_config.adaptive_concurrency,
            },
            derived_initial_limit=fallback_resolution.collector_operation_limit,
        )
        execution_engine = getattr(self.orchestrator, "execution_engine", None)
        candidate_settings = getattr(execution_engine, "admission_settings", None)
        admission_settings = (
            candidate_settings
            if (
                isinstance(getattr(candidate_settings, "mode", None), str)
                and type(getattr(candidate_settings, "initial_limit", None)) is int
                and type(getattr(candidate_settings, "minimum_limit", None)) is int
                and type(getattr(candidate_settings, "maximum_limit", None)) is int
            )
            else fallback_settings
        )
        candidate_resolution = getattr(
            execution_engine, "cpu_resource_resolution", None
        )
        try:
            resource_inputs = candidate_resolution.to_dict()
        except (AttributeError, TypeError, ValueError):
            resource_inputs = fallback_resolution.to_dict()
        if (
            not isinstance(resource_inputs, Mapping)
            or type(resource_inputs.get("collector_operation_limit")) is not int
        ):
            resource_inputs = fallback_resolution.to_dict()

        scheduling_summary = build_scheduling_summary(
            filtered_collectors_per_dut=filtered_collectors_per_dut,
            skipped_collectors_per_dut=skipped_collectors_per_dut,
            collector_definitions=(
                self.orchestrator.config_manager.get_collector_definitions()
            ),
            preflight_results=None,
            collection_level=self.tool_config.collection_level,
            resource_inputs=resource_inputs,
            concurrency_mode=admission_settings.mode,
            initial_limit=admission_settings.initial_limit,
            minimum_limit=admission_settings.minimum_limit,
            maximum_limit=admission_settings.maximum_limit,
            max_concurrent_duts=self.tool_config.max_concurrent_duts,
            max_concurrent_collectors_per_dut=(
                self.tool_config.max_concurrent_collectors_per_dut
            ),
        )
        if self.sanitizer:
            plan = self._sanitize_config_dict(plan)
            scheduling_summary = self._sanitize_config_dict(scheduling_summary)
            # DUT directory names and finalization receipts already expose the
            # canonical roster. Keep the same identity in the authoritative
            # planning leaf even when a username-shaped substring is redacted
            # from ordinary descriptive values.
            for index, dut_id in enumerate(dut_ids):
                plan["duts"][index]["id"] = dut_id

        metadata_dir = Path(log_dir) / ".metadata"
        metadata_dir.mkdir(parents=True, exist_ok=True)
        destination = metadata_dir / "collection_plan.json"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".collection_plan.",
            suffix=".tmp",
            dir=metadata_dir,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(plan, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, destination)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise

        scheduling_destination = metadata_dir / "scheduling_plan.json"
        scheduling_descriptor, scheduling_temporary_name = tempfile.mkstemp(
            prefix=".scheduling_plan.",
            suffix=".tmp",
            dir=metadata_dir,
        )
        try:
            with os.fdopen(scheduling_descriptor, "w", encoding="utf-8") as stream:
                json.dump(scheduling_summary, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(scheduling_temporary_name, scheduling_destination)
        except BaseException:
            try:
                os.unlink(scheduling_temporary_name)
            except OSError:
                pass
            raise

        console = getattr(self, "sanitized_console", None)
        if console is not None and callable(getattr(console, "print_info", None)):
            console.print_info(
                "Scheduling summary: "
                f"{format_scheduling_summary(scheduling_summary)}"
            )

    @staticmethod
    def _model_field_was_explicit(model: Any, field_name: str) -> bool:
        """
        Return whether a configuration model received a field from source.

        The implementation uses ``model`` and ``field_name`` to determine
        whether a configuration model received a field from source.

        Args:
            model: Model consumed while the function attempts to determine
                whether a configuration model received a field from source.
            field_name: Field label included in validation failures for the
                selected input.

        Returns:
            Whether a configuration model received a field from source.
        """

        fields_set = getattr(model, "model_fields_set", None)
        if fields_set is None:
            fields_set = getattr(model, "__fields_set__", None)
        if fields_set is not None:
            return field_name in fields_set
        return isinstance(model, dict) and field_name in model

    def _resolve_per_dut_collector_selection(
        self, dut_ids: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Resolve the established CLI > DUT > tool selector precedence.

        The implementation uses ``dut_ids`` to resolve the established CLI > DUT
        > tool selector precedence. It updates ``_resolved_collector_selection``
        on the instance as part of that state transition.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.

        Returns:
            The validated ``resolved``.
        """

        cli_keys = getattr(self.tool_config, "explicit_cli_config_keys", {}) or {}
        tool_keys = getattr(self.tool_config, "explicit_tool_config_keys", {}) or {}
        cli_include_explicit = bool(cli_keys.get("include_collectors"))
        cli_skip_explicit = bool(cli_keys.get("skip_collectors"))
        tool_include = _normalized_collector_values(
            getattr(self.tool_config, "include_collectors", None)
        )
        tool_include_explicit = bool(tool_keys.get("include_collectors"))

        modern_tool_skip = _normalized_collector_values(
            getattr(self.tool_config, "skip_collectors", None)
        )
        legacy_tool_skip = _normalized_collector_values(
            getattr(self.tool_config, "COLLECTOR_TO_SKIP", None)
        )
        if tool_keys.get("skip_collectors"):
            tool_skip = modern_tool_skip
            tool_skip_explicit = True
        elif tool_keys.get("COLLECTOR_TO_SKIP"):
            tool_skip = legacy_tool_skip
            tool_skip_explicit = True
        else:
            tool_skip = modern_tool_skip or legacy_tool_skip
            tool_skip_explicit = bool(tool_skip)

        raw_ids = _normalized_collector_values(
            getattr(self.tool_config, "collector_id", None)
        )
        raw_groups = _normalized_collector_values(
            getattr(self.tool_config, "collector_group", None)
        )
        global_explicit_ids = list(
            dict.fromkeys(getattr(self, "_global_explicit_selector_ids", []))
        )
        base_selected = list(dict.fromkeys(self._base_selected_collectors))
        dut_models = {
            str(getattr(dut, "name", "")): dut
            for dut in self.dut_configs
            if getattr(dut, "name", None)
        }

        resolved: Dict[str, Dict[str, Any]] = {}
        for dut_id in dut_ids:
            dut = dut_models.get(str(dut_id))
            dut_include_explicit = bool(
                dut is not None
                and self._model_field_was_explicit(dut, "include_collectors")
            )
            dut_include = _normalized_collector_values(
                getattr(dut, "include_collectors", None) if dut is not None else None
            )
            dut_modern_skip_explicit = bool(
                dut is not None
                and self._model_field_was_explicit(dut, "skip_collectors")
            )
            dut_legacy_skip_explicit = bool(
                dut is not None
                and self._model_field_was_explicit(dut, "COLLECTOR_TO_SKIP")
            )
            modern_dut_skip = _normalized_collector_values(
                getattr(dut, "skip_collectors", None) if dut is not None else None
            )
            legacy_dut_skip = _normalized_collector_values(
                getattr(dut, "COLLECTOR_TO_SKIP", None) if dut is not None else None
            )
            if dut_modern_skip_explicit:
                dut_skip = modern_dut_skip
                dut_skip_explicit = True
            elif dut_legacy_skip_explicit:
                dut_skip = legacy_dut_skip
                dut_skip_explicit = True
            else:
                dut_skip = modern_dut_skip or legacy_dut_skip
                dut_skip_explicit = bool(dut_skip)

            if cli_include_explicit:
                include_source, effective_include, include_explicit = (
                    "explicit_cli",
                    tool_include,
                    True,
                )
            elif dut_include_explicit:
                include_source, effective_include, include_explicit = (
                    "dut_config",
                    dut_include,
                    True,
                )
            elif tool_include_explicit or tool_include:
                include_source, effective_include, include_explicit = (
                    "tool_config",
                    tool_include,
                    True,
                )
            else:
                include_source, effective_include, include_explicit = (
                    "code_default",
                    [],
                    False,
                )

            if cli_skip_explicit:
                skip_source, effective_skip, skip_explicit = (
                    "explicit_cli",
                    modern_tool_skip,
                    True,
                )
            elif dut_skip_explicit:
                skip_source, effective_skip, skip_explicit = (
                    "dut_config",
                    dut_skip,
                    True,
                )
            elif tool_skip_explicit or tool_skip:
                skip_source, effective_skip, skip_explicit = (
                    "tool_config",
                    tool_skip,
                    True,
                )
            else:
                skip_source, effective_skip, skip_explicit = (
                    "code_default",
                    [],
                    False,
                )

            explicit_collectors = list(
                dict.fromkeys(global_explicit_ids + effective_include)
            )
            resolved[str(dut_id)] = {
                "include_collectors": {
                    "source": include_source,
                    "values": effective_include,
                    "explicit": include_explicit,
                },
                "skip_collectors": {
                    "source": skip_source,
                    "values": effective_skip,
                    "explicit": skip_explicit,
                },
                "global_selectors": {
                    "collector_ids": raw_ids,
                    "collector_groups": raw_groups,
                    "source": (
                        "explicit_cli" if raw_ids or raw_groups else "code_default"
                    ),
                },
                "candidate_collectors": list(
                    dict.fromkeys(base_selected + effective_include)
                ),
                "explicit_collectors": explicit_collectors,
                "positive_selector": bool(explicit_collectors),
            }
        self._resolved_collector_selection = resolved
        return resolved

    def _apply_resolved_selection_union(
        self, resolved_selection: Dict[str, Dict[str, Any]]
    ) -> tuple[List[str], List[str]]:
        """
        Build one scheduling union without leaking a shadowed include.

        The implementation uses ``resolved_selection`` to build one scheduling
        union without leaking a shadowed include.

        Args:
            resolved_selection: Mapping supplying fields for one scheduling
                union without leaking a shadowed include.

        Returns:
            A tuple containing ``processed`` and ``requested`` in that order.
        """

        base = list(dict.fromkeys(self._base_selected_collectors))
        global_explicit = list(
            dict.fromkeys(getattr(self, "_global_explicit_selector_ids", []))
        )
        includes = list(
            dict.fromkeys(
                collector_id
                for resolution in resolved_selection.values()
                for collector_id in resolution["include_collectors"]["values"]
            )
        )
        combined = list(dict.fromkeys(base + includes))
        catalog_order = list(
            dict.fromkeys(getattr(self, "_default_selection_catalog_order", []))
        )
        if catalog_order:
            selected = set(combined)
            processed = [
                collector_id
                for collector_id in catalog_order
                if collector_id in selected
            ] + [
                collector_id
                for collector_id in combined
                if collector_id not in catalog_order
            ]
        else:
            processed = combined
        requested = list(dict.fromkeys(global_explicit + includes))
        return processed, requested

    @staticmethod
    def _selection_explicit_pairs(
        resolved_selection: Dict[str, Dict[str, Any]],
    ) -> Set[tuple[str, str]]:
        """
        Return the selection explicit pairs.

        The implementation uses ``resolved_selection`` to produce the selection
        explicit pairs.

        Args:
            resolved_selection: Mapping supplying fields for selection explicit
                pairs.

        Returns:
            The unique selection explicit pairs returned by the operation.
        """
        return {
            (str(dut_id), str(collector_id))
            for dut_id, resolution in resolved_selection.items()
            for collector_id in resolution.get("explicit_collectors", [])
            if str(collector_id).strip()
        }

    def _write_selection_failure_evidence(
        self,
        *,
        log_dir: Path,
        requested_collectors: List[str],
        filtered_collectors_per_dut: Dict[str, Any],
        skipped_collectors_per_dut: Dict[str, Any],
        results: Dict[str, Any],
        reason: str,
        failure_type: str,
        resolved_selection: Dict[str, Dict[str, Any]],
        affected_pairs: Set[tuple[str, str]],
    ) -> Dict[str, Any]:
        """
        Atomically publish bounded, owner-private selection evidence.

        The implementation uses ``log_dir``, ``requested_collectors``,
        ``filtered_collectors_per_dut``, ``skipped_collectors_per_dut``, and
        ``results`` to atomically publish bounded, owner-private selection
        evidence. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle. If the function cannot
        atomically publish bounded, owner-private selection evidence, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            requested_collectors: Entries supplied as ``requested_collectors``
                without transferring container ownership.
            filtered_collectors_per_dut: Mapping supplying fields for atomically
                publish bounded, owner-private selection evidence.
            skipped_collectors_per_dut: Mapping supplying fields for atomically
                publish bounded, owner-private selection evidence.
            results: Mapping supplying fields for atomically publish bounded,
                owner-private selection evidence.
            reason: Text supplied as reason in the format accepted by this
                function.
            failure_type: Text supplied as failure type in the format accepted
                by this function.
            resolved_selection: Mapping supplying fields for atomically publish
                bounded, owner-private selection evidence.
            affected_pairs: Entries supplied as ``affected_pairs`` without
                transferring container ownership.

        Returns:
            The validated ``payload``.

        Raises:
            RuntimeError: If selection failure evidence exceeded its byte
                budget after record-budget truncation.
        """

        remaining_records = _SELECTION_EVIDENCE_MAX_RECORDS
        truncated = False

        def token(
            value: Any, maximum: int = _SELECTION_EVIDENCE_MAX_TOKEN_CHARS
        ) -> str:
            """
            Convert a value to a bounded evidence token.

            The implementation uses ``value`` and ``maximum`` to convert a value
            to a bounded evidence token. The source value keeps its ownership
            while the normalized representation is returned separately.

            Args:
                value: Value evaluated while performing value to a bounded
                    evidence token.
                maximum: Numeric maximum used while the operation performs
                    bounded accounting.

            Returns:
                The canonical token text.
            """
            nonlocal truncated
            text = str(value or "")
            truncated = truncated or len(text) > maximum
            return text[:maximum]

        def prose(value: Any) -> str:
            """
            Sanitize and bound a value for diagnostic prose.

            The implementation uses ``value`` to sanitize and bound a value for
            diagnostic prose.

            Args:
                value: Value evaluated while performing sanitize and bound a
                    value for diagnostic prose.

            Returns:
                The canonical prose text.
            """
            nonlocal truncated
            text = str(value or "")
            sanitizer = getattr(self, "sanitizer", None)
            if sanitizer is not None:
                text = str(sanitizer.sanitize(text))
            truncated = truncated or len(text) > _SELECTION_EVIDENCE_MAX_REASON_CHARS
            return text[:_SELECTION_EVIDENCE_MAX_REASON_CHARS]

        def take_values(
            values: Any,
            *,
            reserve: int = 0,
            maximum: int = 256,
        ) -> List[str]:
            """
            Consume normalized tokens from the shared evidence record budget.

            Mandatory evidence callers use ``reserve`` to leave space for
            affected-pair identity and matching typed terminal proof. Optional
            context is truncated instead of turning a truthful domain failure
            into a runtime failure.

            Args:
                values: Values normalized into stable collector tokens.
                reserve: Records which later mandatory evidence must retain.
                maximum: Maximum values emitted by this individual field.

            Returns:
                The tokens admitted by both the field and shared record limits.

            Side Effects:
                Decrements ``remaining_records`` and marks the payload truncated
                when input cannot be represented completely.
            """
            nonlocal remaining_records, truncated
            normalized = _normalized_collector_values(values)
            projected: List[str] = []
            for value in normalized:
                if len(projected) >= maximum or remaining_records <= reserve:
                    truncated = True
                    break
                projected.append(token(value))
                remaining_records -= 1
            return projected

        raw_ids = take_values(
            getattr(self.tool_config, "collector_id", None),
            reserve=4,
            maximum=128,
        )
        collector_groups = take_values(
            getattr(self.tool_config, "collector_group", None),
            reserve=4,
            maximum=128,
        )
        include_collectors = take_values(
            getattr(self.tool_config, "include_collectors", None),
            reserve=4,
            maximum=128,
        )
        bounded_requested = take_values(
            requested_collectors,
            reserve=4,
            maximum=256,
        )

        bounded_pairs: List[Dict[str, str]] = []
        for dut_id, collector_id in sorted(affected_pairs):
            if len(bounded_pairs) >= 256 or remaining_records <= 2:
                truncated = True
                break
            bounded_pairs.append(
                {"dut_id": token(dut_id), "collector_id": token(collector_id)}
            )
            remaining_records -= 1
        bounded_pair_set = {
            (pair["dut_id"], pair["collector_id"]) for pair in bounded_pairs
        }

        affected_ids_by_dut: Dict[str, List[str]] = {}
        for pair in bounded_pairs:
            affected_ids_by_dut.setdefault(pair["dut_id"], []).append(
                pair["collector_id"]
            )

        mandatory_resolution_records = len(affected_ids_by_dut) + len(bounded_pairs)
        terminal_budget = max(
            remaining_records - mandatory_resolution_records - 1,
            0,
        )
        minimum_priority_records = (
            len(bounded_pairs)
            if failure_type == "explicit_selection_preflight_failure"
            else 0
        )
        terminal_limit = min(
            max(terminal_budget // 3, minimum_priority_records),
            terminal_budget,
            512,
        )
        terminal_probe = _bounded_terminal_result_evidence(
            results,
            maximum_records=terminal_limit + 1,
            priority_pairs=bounded_pair_set,
        )
        if len(terminal_probe) > terminal_limit:
            truncated = True
        terminal_results = terminal_probe[:terminal_limit]
        for record in terminal_results:
            record["reason"] = prose(record.get("reason", ""))
        remaining_records -= len(terminal_results)

        bounded_resolution: Dict[str, Dict[str, Any]] = {}
        affected_dut_ids = set(affected_ids_by_dut)
        ordered_resolutions = sorted(
            resolved_selection.items(),
            key=lambda item: (str(item[0]) not in affected_dut_ids, str(item[0])),
        )
        for dut_index, (dut_id, resolution) in enumerate(ordered_resolutions):
            if dut_index >= _SELECTION_EVIDENCE_MAX_DUTS or remaining_records <= 1:
                truncated = True
                break
            remaining_records -= 1
            include = resolution.get("include_collectors", {})
            skip = resolution.get("skip_collectors", {})
            selectors = resolution.get("global_selectors", {})
            affected_for_dut = affected_ids_by_dut.get(str(dut_id), [])
            affected_for_dut_set = set(affected_for_dut)
            prioritized_explicit = list(
                dict.fromkeys(
                    affected_for_dut
                    + [
                        value
                        for value in _normalized_collector_values(
                            resolution.get("explicit_collectors", [])
                        )
                        if value not in affected_for_dut_set
                    ]
                )
            )
            later_mandatory = sum(
                1 + len(values)
                for later_dut, values in affected_ids_by_dut.items()
                if later_dut != str(dut_id) and later_dut not in bounded_resolution
            )
            bounded_explicit = take_values(
                prioritized_explicit,
                reserve=later_mandatory,
                maximum=512,
            )
            bounded_global_ids = take_values(
                selectors.get("collector_ids", []),
                reserve=later_mandatory,
            )
            bounded_global_groups = take_values(
                selectors.get("collector_groups", []),
                reserve=later_mandatory,
            )
            bounded_include = take_values(
                include.get("values", []),
                reserve=later_mandatory,
            )
            bounded_skip = take_values(
                skip.get("values", []),
                reserve=later_mandatory,
            )
            bounded_resolution[token(dut_id)] = {
                "include_collectors": {
                    "source": token(include.get("source", ""), 64),
                    "values": bounded_include,
                    "explicit": bool(include.get("explicit", False)),
                },
                "skip_collectors": {
                    "source": token(skip.get("source", ""), 64),
                    "values": bounded_skip,
                    "explicit": bool(skip.get("explicit", False)),
                },
                "global_selectors": {
                    "collector_ids": bounded_global_ids,
                    "collector_groups": bounded_global_groups,
                    "source": token(selectors.get("source", ""), 64),
                },
                "explicit_collectors": bounded_explicit,
                "positive_selector": bool(resolution.get("positive_selector")),
            }

        bounded_applicable: Dict[str, List[str]] = {}
        for dut_index, (dut_id, values) in enumerate(
            sorted(filtered_collectors_per_dut.items())
        ):
            if dut_index >= _SELECTION_EVIDENCE_MAX_DUTS or remaining_records <= 1:
                truncated = True
                break
            remaining_records -= 1
            bounded_applicable[token(dut_id)] = take_values(
                values,
                reserve=1,
                maximum=512,
            )

        bounded_skipped: Dict[str, List[Dict[str, Any]]] = {}
        for dut_index, (dut_id, values) in enumerate(
            sorted(skipped_collectors_per_dut.items())
        ):
            if dut_index >= _SELECTION_EVIDENCE_MAX_DUTS or remaining_records <= 0:
                truncated = True
                break
            remaining_records -= 1
            items = values if isinstance(values, list) else []
            projected_items: List[Dict[str, Any]] = []
            for item in items:
                if len(projected_items) >= 512 or remaining_records <= 0:
                    truncated = True
                    break
                if not isinstance(item, dict):
                    continue
                projected_items.append(
                    {
                        "collector_id": token(item.get("collector_id", "")),
                        "collector_name": prose(item.get("collector_name", "")),
                        "group": token(item.get("group", ""), 64),
                        "reason": prose(item.get("reason", "")),
                        "skip_type": token(item.get("skip_type", ""), 64),
                    }
                )
                remaining_records -= 1
            bounded_skipped[token(dut_id)] = projected_items

        payload: Dict[str, Any] = {
            "schema_version": "1.0",
            "status": "domain_failure",
            "failure_type": token(failure_type, 128),
            "reason": prose(reason),
            "selection": {
                "collector_id": ",".join(raw_ids) or None,
                "collector_groups": collector_groups,
                "include_collectors": include_collectors,
                "requested_collectors": bounded_requested,
                "resolved_per_dut": bounded_resolution,
                "affected_pairs": bounded_pairs,
            },
            "applicable_collectors_per_dut": bounded_applicable,
            "skipped_collectors_per_dut": bounded_skipped,
            "terminal_results": terminal_results,
        }

        payload["evidence_limits"] = {
            "maximum_records": _SELECTION_EVIDENCE_MAX_RECORDS,
            "maximum_duts": _SELECTION_EVIDENCE_MAX_DUTS,
            "maximum_token_characters": _SELECTION_EVIDENCE_MAX_TOKEN_CHARS,
            "maximum_reason_characters": _SELECTION_EVIDENCE_MAX_REASON_CHARS,
            "maximum_serialized_bytes": _SELECTION_EVIDENCE_MAX_SERIALIZED_BYTES,
            "records_emitted": _SELECTION_EVIDENCE_MAX_RECORDS - remaining_records,
            "truncated": truncated,
        }
        serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if len(serialized.encode("utf-8")) > _SELECTION_EVIDENCE_MAX_SERIALIZED_BYTES:
            raise RuntimeError("selection failure evidence exceeded its byte budget")

        metadata_dir = Path(log_dir) / ".metadata"
        metadata_dir.mkdir(parents=True, exist_ok=True)
        destination = Path(log_dir) / EXPLICIT_SELECTION_EVIDENCE_PATH
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".selection_failure.", suffix=".tmp", dir=metadata_dir
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary_name, destination)
            os.unlink(temporary_name)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise
        return payload

    async def _resolve_collector_selection(self) -> tuple:
        """
        Resolve collector selection.

        Determine global baseboard info for pre-filtering.

        Returns:
            A tuple containing ``processed cids`` and ``requested cids`` in that
            order.
        """
        processed_cids = []
        group_cids = []
        group_requested_cids = []
        specific_cids = []
        requested_cids = []
        default_catalog_order = []
        self._default_selection_catalog_order = []
        current_level = self.tool_config.collection_level
        await self.orchestrator.logger.log_runtime(
            "DEBUG",
            "CLICollector",
            f"Collection level from tool config: {current_level}",
        )

        include_collectors = self.tool_config.include_collectors or []

        # Determine global baseboard info for pre-filtering
        baseboard_info = None
        if self.orchestrator.dut_manager:
            dut_ids = self.orchestrator.dut_manager.get_all_dut_ids()
            if dut_ids:
                baseboards = set()
                for dut_id in dut_ids:
                    dut = self.orchestrator.dut_manager.get_dut(dut_id)
                    if dut and dut.config:
                        bb = dut.config.get("baseboard")
                        if bb and str(bb).strip():
                            baseboards.add(str(bb))

                if len(baseboards) == 1:
                    baseboard_info = list(baseboards)[0]
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        f"Single baseboard detected: {baseboard_info}",
                    )
                elif len(baseboards) > 1:
                    baseboard_list = sorted(baseboards)
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        f"Multiple baseboards detected ({', '.join(baseboard_list)}). Per-DUT filtering will apply.",
                    )
                    self.sanitized_console.print_info(
                        f"\n\nMultiple baseboards detected ({', '.join(baseboard_list)}). Each DUT will filter collectors based on its own baseboard during execution."
                    )
                    baseboard_info = None

        # Process collector groups
        if self.tool_config.collector_group:
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Processing collector groups: {self.tool_config.collector_group} for level {current_level}",
            )
            self.sanitized_console.print_info(
                f"Processing collector groups: {', '.join(self.tool_config.collector_group)} for level {current_level}"
            )

            for group in self.tool_config.collector_group:
                group_collectors = (
                    self.orchestrator.config_manager.get_collectors_for_group(group)
                )
                if not group_collectors:
                    await self.orchestrator.logger.log_runtime(
                        "WARN",
                        "CLICollector",
                        f"No collectors found for group '{group}'",
                    )
                    self.sanitized_console.print_warning(
                        f"No collectors found for group '{group}'"
                    )
                    continue

                level_filtered = []
                baseboard_filtered = []
                disabled_out = 0
                for cid, cinfo in group_collectors.items():
                    if not cinfo.get("enabled", True):
                        disabled_out += 1
                        await self.orchestrator.logger.log_runtime(
                            "DEBUG",
                            "CLICollector",
                            f"Collector {cid} in group '{group}' is disabled by catalog - excluding from default group selection",
                        )
                        continue
                    clevel = cinfo.get("collection_level", "L1")
                    if not self.orchestrator._is_collector_level_applicable(
                        clevel, current_level
                    ):
                        continue
                    level_filtered.append(cid)
                    if (
                        baseboard_info is None
                        or self.orchestrator.is_collector_applicable_for_baseboard(
                            cinfo, baseboard_info
                        )
                    ):
                        baseboard_filtered.append(cid)
                    else:
                        await self.orchestrator.logger.log_runtime(
                            "WARN",
                            "CLICollector",
                            f"Collector {cid} in group '{group}' not applicable for baseboard {baseboard_info} - skipping",
                        )

                group_requested_cids.extend(level_filtered)
                group_cids.extend(baseboard_filtered)

                level_out = len(group_collectors) - disabled_out - len(level_filtered)
                bb_out = len(level_filtered) - len(baseboard_filtered)
                bb_label = (
                    f" and baseboard {baseboard_info}"
                    if baseboard_info
                    else " (per-DUT baseboard filtering during execution)"
                )
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"Found {len(baseboard_filtered)} collectors in group '{group}' for level {current_level}{bb_label}: {baseboard_filtered}",
                )
                self.sanitized_console.print_info(
                    f"Found {len(baseboard_filtered)} collectors in group '{group}' for level {current_level}{bb_label}: {', '.join(baseboard_filtered)}"
                )
                if level_out > 0:
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        f"Filtered out {level_out} collectors from group '{group}' that don't match level {current_level}",
                    )
                    self.sanitized_console.print_info(
                        f"Filtered out {level_out} collectors from group '{group}' that don't match level {current_level}"
                    )
                if disabled_out > 0:
                    msg = (
                        f"Excluded {disabled_out} disabled collector(s) from "
                        f"default group '{group}' selection"
                    )
                    await self.orchestrator.logger.log_runtime(
                        "INFO", "CLICollector", msg
                    )
                    self.sanitized_console.print_info(msg)
                if bb_out > 0:
                    msg = (
                        f"Filtered out {bb_out} collectors from group '{group}' that don't match baseboard {baseboard_info}"
                        if baseboard_info
                        else f"Note: {bb_out} collectors from group '{group}' may be filtered out during execution based on individual DUT baseboards"
                    )
                    await self.orchestrator.logger.log_runtime(
                        "INFO", "CLICollector", msg
                    )
                    self.sanitized_console.print_info(msg)

        # Process specific collector IDs
        cids = self.tool_config.collector_id
        if cids:
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Processing specific collector IDs: {cids}",
            )
            self.sanitized_console.print_info(
                f"\n\nProcessing specific collector IDs: {cids}"
            )
            specific_cids = [
                c.strip() for item in cids.split() for c in item.split(",") if c.strip()
            ]

        # Combine group and specific collectors
        if specific_cids and group_cids:
            processed_cids = group_cids.copy()
            for cid in specific_cids:
                if cid in processed_cids:
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        f"Specific collector ID '{cid}' is already included by group selection",
                    )
                    self.sanitized_console.print_info(
                        f"Specific collector ID '{cid}' is already included by group selection"
                    )
                processed_cids.append(cid)
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Combined group and specific collectors: {processed_cids}",
            )
            self.sanitized_console.print_info(
                f"Combined group and specific collectors: {', '.join(processed_cids)}"
            )
        elif specific_cids:
            processed_cids = specific_cids
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Using specific collector IDs: {specific_cids}",
            )
            self.sanitized_console.print_info(
                f"Using specific collector IDs: {', '.join(specific_cids)}"
            )
        elif group_cids:
            processed_cids = group_cids
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Using collectors from groups for level {current_level}: {group_cids}",
            )
            self.sanitized_console.print_info(
                f"Using collectors from groups for level {current_level}: {', '.join(group_cids)}"
            )
        else:
            if self.tool_config.collector_group:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    "No applicable collectors found for the requested group(s). No collectors will be executed.",
                )
                self.sanitized_console.print_warning(
                    "No applicable collectors found for the requested group(s). No collectors will be executed."
                )
                processed_cids = []
            else:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"No specific collectors or groups specified - will run all applicable collectors for level {current_level}",
                )
                self.sanitized_console.print_info(
                    f"\nNo specific collectors or groups specified - will run all applicable collectors for level {current_level}\n"
                )
                all_collectors = self.orchestrator.get_all_collectors(current_level)
                default_catalog_order = list(all_collectors)
                self._default_selection_catalog_order = list(default_catalog_order)
                processed_cids = [
                    cid
                    for cid, collector_info in all_collectors.items()
                    if collector_info.get("enabled", True)
                ]
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    f"Using all {len(processed_cids)} collectors for level {current_level}",
                )

        # Build requested_cids for summary reporting (pre-filter)
        self._base_selected_collectors = list(dict.fromkeys(processed_cids))
        self._global_explicit_selector_ids = list(
            dict.fromkeys(group_requested_cids + specific_cids)
        )
        requested_cids = group_requested_cids + specific_cids + include_collectors
        if requested_cids:
            seen = set()
            requested_cids = [
                c for c in requested_cids if c and not (c in seen or seen.add(c))
            ]

        # Apply --include-collectors additively
        if include_collectors:
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Adding collectors from --include-collectors: {include_collectors}",
            )
            added_count = 0
            for cid in include_collectors:
                if cid not in processed_cids:
                    collector_info = (
                        self.orchestrator.config_manager.get_collector_info(cid)
                    )
                    if collector_info:
                        processed_cids.append(cid)
                        added_count += 1
                        await self.orchestrator.logger.log_runtime(
                            "INFO",
                            "CLICollector",
                            f"Added collector {cid} from --include-collectors",
                        )
            if added_count > 0:
                self.sanitized_console.print_info(
                    f"Added {added_count} additional collector(s) from --include-collectors"
                )
            else:
                await self.orchestrator.logger.log_runtime(
                    "INFO",
                    "CLICollector",
                    "All collectors from --include-collectors were already in the selection",
                )

            # The default selection is a filtered view of catalog order. Insert
            # explicitly included (for example, disabled-by-default) collectors
            # back into that stable order instead of appending them at the end.
            if default_catalog_order:
                selected = set(processed_cids)
                processed_cids = [
                    cid for cid in default_catalog_order if cid in selected
                ] + [cid for cid in processed_cids if cid not in default_catalog_order]

            # Baseboard compatibility warnings for include_collectors
            all_baseboards = set()
            if self.orchestrator.dut_manager:
                for did in self.orchestrator.dut_manager.get_all_dut_ids():
                    bb = self.orchestrator.dut_manager.duts[did].config.get(
                        "baseboard", "Unknown"
                    )
                    all_baseboards.add(bb)

            for cid in include_collectors:
                cinfo = self.orchestrator.config_manager.get_collector_info(cid)
                if not cinfo:
                    self.sanitized_console.print_warning(
                        f"Warning: Collector {cid} in --include-collectors not found in collector catalog"
                    )
                    continue
                supported = cinfo.get("applicable_baseboards", [])
                if not supported:
                    continue
                if _is_universal_baseboard_spec(supported):
                    continue
                if isinstance(supported, str):
                    supported = [supported]
                unsupported = all_baseboards - set(supported)
                if unsupported:
                    supported_str = ", ".join(supported)
                    unsupported_str = ", ".join(sorted(unsupported))
                    self.sanitized_console.print_warning(
                        f"Warning: Collector {cid} in --include-collectors is not supported on baseboard(s) '{unsupported_str}'; forcing run due to --include-collectors. Supported baseboards: {supported_str}"
                    )

        # Deduplicate while preserving order
        if processed_cids:
            seen = set()
            processed_cids = [
                c for c in processed_cids if not (c in seen or seen.add(c))
            ]
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Final processed CIDs: {processed_cids}",
            )

        return processed_cids, requested_cids

    async def _run_autodetection(
        self, dut_ids: list, preflight_results: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Run platform/baseboard auto-detection for DUTs that lack baseboard info.

        The implementation uses ``dut_ids`` and ``preflight_results`` to run
        platform/baseboard auto-detection for DUTs that lack baseboard info.
        Terminal status is emitted only after platform/baseboard auto-detection
        for DUTs that lack baseboard info and its owned cleanup have completed.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.
        """
        duts_needing = []
        for dut_id in dut_ids:
            dut = self.orchestrator.dut_manager.get_dut(dut_id)
            configured = _resolved_baseboard_value(
                dut.config.get("baseboard"),
                dut.config.get("TargetBaseboard"),
            )

            if configured is None:
                duts_needing.append(dut_id)

        if not duts_needing:
            return

        await self.orchestrator.logger.log_runtime(
            "INFO",
            "CLICollector",
            f"DUTs needing autodetection: {duts_needing} - running autodetection before filtering",
        )

        for dut_id in duts_needing:
            await self.orchestrator.logger.log_runtime(
                "INFO",
                "CLICollector",
                f"Running autodetection for DUT: {dut_id}",
            )
            dut = self.orchestrator.dut_manager.get_dut(dut_id)
            non_interactive = dut.config.get("non_interactive", False)
            t0 = time.time()
            self.orchestrator.sanitized_console.console.print(
                Text.assemble(
                    (
                        "Auto-detecting platform and baseboard for "
                        f"{neutralize_text_controls(dut_id)}...",
                        "bold blue",
                    )
                )
            )

            (
                success,
                detected_info,
            ) = await self.orchestrator.dut_manager.detect_platform_and_baseboard(
                dut_id,
                preflight_results.get(dut_id, {}) if preflight_results else {},
                non_interactive,
            )

            elapsed = time.time() - t0
            self.orchestrator.sanitized_console.console.print(
                f"[green]Auto-detection completed in {elapsed:.1f}s![/green]"
            )

            configuration_resolved = False
            if success:
                bb = detected_info.get("baseboard")
                plat = detected_info.get("platform")
                ntype = detected_info.get("node_type")

                if not bb or not plat:
                    await self.orchestrator.logger.log_runtime(
                        "WARNING",
                        "CLICollector",
                        f"Autodetection returned success but with invalid values for DUT {dut_id}: Baseboard={bb}, Platform={plat}",
                    )
                    success = False
                else:
                    await self.orchestrator.logger.log_runtime(
                        "INFO",
                        "CLICollector",
                        f"Autodetection successful for DUT {dut_id}: Baseboard={bb}, Platform={plat}, NodeType={ntype}",
                    )
                    dut.config["baseboard"] = bb
                    dut.config["TargetBaseboard"] = bb
                    dut.config["platform"] = plat
                    if ntype:
                        dut.config["node_type"] = ntype
                        dut.config["NodeType"] = ntype
                    await self.orchestrator.dut_manager.apply_baseboard_defaults(
                        dut_id, bb
                    )
                    await self.orchestrator.logger.create_log_signature(
                        dut_id, plat, bb
                    )
                    configuration_resolved = True

            if not success:
                fallback = getattr(self.tool_config, "environment_baseboard", None)
                fallback_applied = bool(
                    fallback
                    and await self.orchestrator.dut_manager.apply_baseboard_defaults(
                        dut_id, fallback
                    )
                )
                if fallback_applied:
                    dut.config["baseboard"] = fallback
                    dut.config["TargetBaseboard"] = fallback
                    await self.orchestrator.logger.log_runtime(
                        "WARNING",
                        "CLICollector",
                        f"Autodetection failed for DUT {dut_id}; using BASEBOARD environment fallback '{fallback}'",
                    )
                    configuration_resolved = True
                else:
                    await self.orchestrator.logger.log_runtime(
                        "WARNING",
                        "CLICollector",
                        f"Autodetection failed for DUT {dut_id} - will continue with unknown baseboard",
                    )

            if configuration_resolved:
                # This is the authoritative post-resolution configuration
                # boundary consumed by run identity.  Refresh exactly once,
                # after detection/fallback and baseboard defaults have made all
                # DUT mutations, and fail the run if the resolved bytes cannot
                # be published.
                tool_config = self.orchestrator.config_manager.get_tool_config()
                await self.orchestrator.logger.create_config_files(
                    dut_id,
                    tool_config,
                    dut.config,
                )

    async def _filter_and_display_collectors(
        self, processed_cids: list, dut_ids: list
    ) -> tuple:
        """
        Filter collectors per DUT, display a summary table, and return results.

        Returns (all_filtered_collectors, filtered_collectors_per_dut,
        skipped_collectors_per_dut).

        Args:
            processed_cids: Entries supplied as ``processed_cids`` without
                transferring container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.

        Returns:
            A tuple containing ``all filtered collectors``, ``filtered
            collectors per DUT``, and ``skipped collectors per DUT`` in that
            order.
        """
        await self.orchestrator.logger.log_runtime(
            "INFO",
            "CLICollector",
            "Applying all filtering (level, baseboard, skip flags, include/exclude)...",
        )

        filtering_results = (
            await self.orchestrator.execution_engine.get_filtered_collectors_per_dut(
                processed_cids, dut_ids
            )
        )
        filtered_collectors_per_dut = filtering_results["filtered_collectors"]
        skipped_collectors_per_dut = filtering_results["skipped_collectors"]

        all_filtered = set()
        for dut_collectors in filtered_collectors_per_dut.values():
            all_filtered.update(dut_collectors)
        all_filtered_collectors = list(all_filtered)

        await self.orchestrator.logger.log_runtime(
            "INFO",
            "CLICollector",
            f"Final filtering complete. {len(all_filtered_collectors)} collectors will run.",
        )

        def _nsort(text):
            """
            Return the nsort.

            The implementation uses ``text`` to produce the nsort.

            Args:
                text: Text consumed while the function attempts to produce the
                    nsort.

            Returns:
                Natural-sort key segments, with digit runs converted to
                integers.
            """
            return [
                int(c) if c.isdigit() else c.lower() for c in re.split(r"(\d+)", text)
            ]

        table = Table(title="Filtered Collectors by DUT")
        table.add_column("DUT Name", style="cyan", no_wrap=True)
        table.add_column("Baseboard", style="magenta", no_wrap=True)
        table.add_column("Filtered Collectors", style="green", overflow="fold")
        table.add_column("Count", style="yellow", justify="right")

        for dut_id in sorted(filtered_collectors_per_dut.keys()):
            dut_collectors = filtered_collectors_per_dut[dut_id]
            sorted_collectors = sorted(dut_collectors, key=_nsort)

            dut_cfg = self.orchestrator.dut_manager.duts[dut_id].config
            baseboard = dut_cfg.get("baseboard", "Unknown")

            groups: Dict[str, list] = {}
            for cid in sorted_collectors:
                cinfo = self.orchestrator.config_manager.get_collector_info(cid)
                g = cinfo.get("group", "Unknown") if cinfo else "Unknown"
                groups.setdefault(g, []).append(cid)

            lines = [
                f"{neutralize_terminal_text(g)}: "
                + ", ".join(
                    neutralize_terminal_text(cid) for cid in sorted(ids, key=_nsort)
                )
                for g, ids in sorted(groups.items())
            ]
            table.add_row(
                neutralize_terminal_text(dut_id),
                neutralize_terminal_text(baseboard),
                "\n".join(lines),
                str(len(dut_collectors)),
            )

        self.sanitized_console.console.print(table)

        total_duts = len(filtered_collectors_per_dut)
        avg = (
            sum(len(c) for c in filtered_collectors_per_dut.values()) / total_duts
            if total_duts
            else 0
        )
        self.sanitized_console.print_info(
            f"\nSummary: {total_duts} DUT(s), {len(all_filtered_collectors)} unique collectors, {avg:.1f} avg collectors per DUT\n"
        )

        return (
            all_filtered_collectors,
            filtered_collectors_per_dut,
            skipped_collectors_per_dut,
        )

    def _display_final_output(
        self,
        log_dir: Path,
        run_result: Optional[RunResult] = None,
        interrupted: bool = False,
        domain_failure: bool = False,
        total_runtime: Optional[float] = None,
    ) -> None:
        """
        Display the terminal duration, outcome, and artifact location.

        The implementation uses ``log_dir``, ``run_result``, ``interrupted``,
        ``domain_failure``, and ``total_runtime`` to display the terminal
        duration, outcome, and artifact location. If the function cannot display
        the terminal duration, outcome, and artifact location, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            run_result: Optional run result; ``None`` selects the function's
                default behavior.
            interrupted: Whether interrupted is enabled or required for this
                operation.
            domain_failure: Whether domain failure is enabled or required for
                this operation.
            total_runtime: Optional total runtime; ``None`` selects the
                function's default behavior.

        Raises:
            TypeError: If terminal display lacks an exact RunResult.
        """
        final_console = create_sanitized_console()
        if total_runtime is not None:
            human_readable_time = OutputFormatter.format_time(total_runtime)
            if total_runtime >= 60:
                execution_time_msg = (
                    f"\nTotal execution time: {human_readable_time} "
                    f"({total_runtime:.2f} seconds)"
                )
            else:
                execution_time_msg = f"\nTotal execution time: {human_readable_time}"
            final_console.print_info(execution_time_msg)

        terminal_success = False
        planning_result = False
        if run_result is not None:
            if type(run_result) is not RunResult:
                raise TypeError("Terminal display requires an exact RunResult")
            interrupted = run_result.runtime_status is RuntimeStatus.INTERRUPTED
            domain_failure = run_result.collection_status in {
                CollectionStatus.PARTIAL,
                CollectionStatus.FAILED,
            }
            receipt_rendered = _render_run_receipt_table(final_console, run_result)
            if not receipt_rendered:
                final_console.print_info(
                    "Runtime status: "
                    f"{run_result.runtime_status.value}; collection status: "
                    f"{run_result.collection_status.value}"
                )
                if run_result.run_identity is not None:
                    identity = run_result.run_identity
                    final_console.print_info(
                        "Run identity: "
                        f"tool={identity.tool_version}; "
                        f"build={identity.build_hash}; "
                        f"source={identity.source_revision}; "
                        f"catalog={identity.catalog_version}; "
                        f"level={identity.resolved_level}; "
                        f"profile={identity.resolved_profile}; "
                        f"sha256={identity.identity_sha256}"
                    )
                if run_result.mode is RunMode.COLLECTION:
                    counts = dict(run_result.collector_counts)
                    final_console.print_info(
                        "Collectors: "
                        f"total={counts['total_collectors']}, "
                        f"completed={counts['completed_collectors']}, "
                        f"partial={counts['partial_collectors']}, "
                        f"failed={counts['failed_collectors']}, "
                        f"skipped={counts['skipped_collectors']}, "
                        f"cancelled={counts['cancelled_collectors']}"
                    )
            if interrupted:
                final_console.print_warning("Collection interrupted before completion.")
            elif run_result.runtime_status is RuntimeStatus.FAILED:
                final_console.print_error(
                    "Collection runtime or mandatory finalization failed."
                )
            elif run_result.mode is RunMode.PLANNING:
                planning_result = True
                final_console.print_info(
                    "Planning completed; no collection was executed."
                )
            elif domain_failure:
                final_console.print_warning(
                    "Collection completed with domain failures or partial results."
                )
            elif run_result.collection_status is CollectionStatus.INCOMPLETE:
                final_console.print_warning(
                    "Collection did not reach a complete terminal outcome."
                )
            elif (
                run_result.runtime_status is RuntimeStatus.SUCCESS
                and run_result.collection_status is CollectionStatus.SUCCESS
            ):
                terminal_success = True
                final_console.print_success("Collection completed successfully!")
        elif interrupted:
            final_console.print_warning("Collection interrupted before completion.")
        elif domain_failure:
            final_console.print_warning(
                "Collection completed with domain failures or partial results."
            )
        else:
            terminal_success = True
            final_console.print_success("Collection completed successfully!")
        artifact_printer = (
            final_console.print_success
            if terminal_success
            else final_console.print_info
        )

        zip_path = getattr(self.orchestrator, "zip_archive_path", None)
        if not zip_path:
            if planning_result:
                final_console.print_info(f"\nPlanning output saved to: {log_dir}")
            elif not terminal_success:
                final_console.print_info(f"\nLocal output saved to: {log_dir}")
            else:
                final_console.print_success(f"\nLogs saved to: {log_dir}")
            return

        if isinstance(zip_path, list):
            first_part = os.path.basename(zip_path[0])
            chunked_match = re.search(r"(\.part\d+)$", first_part)
            standard_split = re.search(r"\.z\d+$", first_part) is not None

            if chunked_match:
                artifact_printer("Split archive parts created:")
            else:
                artifact_printer("Split archive output created:")
            for fp in zip_path:
                artifact_printer(f"  {fp}")

            if chunked_match:
                archive_name = first_part[: -len(chunked_match.group(1))]
                final_console.print_info("\nTo recombine the archive on Linux:")
                final_console.print_info(f"  cat {archive_name}.part* > {archive_name}")
                final_console.print_info("\nThen extract the reconstructed ZIP:")
                final_console.print_info(f"  unzip {archive_name}")
            elif standard_split:
                base_name = re.sub(r"\.z\d+$", "", first_part)
                final_console.print_info(
                    "\nLegacy multipart ZIP detected. Keep all parts in the same directory and open:"
                )
                final_console.print_info(f"  7z x {base_name}.zip")
            else:
                artifact_printer(f"\nLogs saved to: {zip_path[-1]}")
        else:
            artifact_printer(f"\nLogs saved to: {zip_path}")

    def _archive_config_files(self, log_dir: Path) -> None:
        """
        Archive mode-consistent copies of config files into the run directory.

        Normal runs apply full configuration sanitization. An explicit
        ``skip_sanitization`` request preserves ordinary configuration values
        while retaining unconditional trusted extension file-reference
        redaction. Success is reported only after the owning output boundary
        has completed its required write or publication step.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
        """

        tool_config = getattr(self, "tool_config", None)
        if isinstance(tool_config, dict):
            sanitization_disabled = tool_config.get("skip_sanitization", False) is True
        else:
            sanitization_disabled = (
                getattr(tool_config, "skip_sanitization", False) is True
            )

        def _copy(src_path: Optional[Path], dest_name: str, label: str) -> None:
            """
            Archive a bounded configuration copy through private atomic staging.

            Configuration stays ``0600`` regardless of the live-output umask.
            The sanitized or explicitly unsanitized copy is complete before it
            replaces the destination, so a failed write preserves the old copy.

            Args:
                src_path: filesystem location used as the src path for this
                    operation.
                dest_name: Stable dest name used for lookup and operator-facing
                    diagnostics.
                label: Text supplied as label in the format accepted by this
                    function.

            Raises:
                Exception: If reading, sanitizing, or publishing the copy fails.
            """
            try:
                if not src_path:
                    self.sanitized_console.print_warning(
                        f"Skipping {label} copy: no source path available"
                    )
                    return
                src = Path(src_path)
                if not src.exists() or not src.is_file():
                    self.sanitized_console.print_warning(
                        f"Skipping {label} copy: source file not found: {src}"
                    )
                    return
                dest = log_dir / dest_name
                raw_text = read_regular_file_bounded(
                    src,
                    maximum_bytes=resolve_archive_limits().max_metadata_member_bytes,
                ).decode("utf-8", errors="replace")
                if sanitization_disabled:
                    archived_text = redact_config_file_references(
                        raw_text, replacement="XXXX"
                    )
                else:
                    archived_text = sanitize_config_text(raw_text, replacement="XXXX")
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=".config-copy-", suffix=".tmp", dir=log_dir
                )
                try:
                    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                        stream.write(archived_text)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary_name, dest)
                finally:
                    try:
                        os.unlink(temporary_name)
                    except FileNotFoundError:
                        pass
            except Exception as e:
                try:
                    self.sanitized_console.print_warning(
                        f"Failed to copy {label} into run directory: {e}"
                    )
                except Exception:
                    pass
                raise

        def _resolve_config_file_to_use(config_path: str) -> Optional[Path]:
            """
            Resolve config file to use.

            The implementation uses ``config_path`` to resolve config file to
            use.

            Args:
                config_path: filesystem location used as the config path for
                    this operation.

            Returns:
                The validated config file to use filesystem path, or ``None``
                when the requested value is unavailable.
            """
            if not config_path:
                return None
            candidate = Path(config_path)
            if candidate.exists():
                return candidate
            if self.source_dut_config:
                relative_candidate = Path(self.source_dut_config).parent / candidate
                if relative_candidate.exists():
                    return relative_candidate
            return candidate

        _copy(self.source_dut_config, "dut_config.yaml", "DUT config")
        _copy(self.source_tool_config, "tool_config.yaml", "tool config")

        for dut in self.dut_configs:
            config_to_use = getattr(dut, "ConfigFileToUse", None)
            if not config_to_use:
                continue
            resolved_path = _resolve_config_file_to_use(config_to_use)
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", dut.name or "") or "dut"
            _copy(
                resolved_path,
                f"tool_config_{safe_name}.yaml",
                f"tool config for {dut.name}",
            )

    async def _handle_emergency_cleanup_failure(
        self,
        error: Exception,
        *,
        active_exception: Optional[BaseException],
    ) -> None:
        """
        Publish and propagate a new emergency-finalization failure.

        Publication is best effort; retain the emergency failure as the
        process-visible cause.

        Args:
            error: Exception or failure detail associated with the operation.
            active_exception: Active exception consumed while the function
                attempts to publish and propagate a new emergency-finalization
                failure.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to publish and propagate a new emergency-finalization
                failure.
        """

        if active_exception is not None:
            return

        publisher = getattr(self, "publish_post_collection_outcome", None)
        if callable(publisher):
            try:
                await publisher(
                    status="runtime_failed",
                    failure_type="finalization_failure",
                    reason=f"Emergency cleanup failed: {error}",
                )
            except Exception:
                # Publication is best effort; retain the emergency failure as
                # the process-visible cause.
                pass
        raise error

    async def _emergency_cleanup(self) -> None:
        """
        Emergency cleanup to close all ClientSessions when interrupted.

        This method performs garbage collection and forcefully closes any
        remaining open aiohttp ClientSession objects to prevent resource leaks.
        """
        console = self.sanitized_console
        del self
        diagnostics = await CLICollector._collect_emergency_cleanup_diagnostics()
        if console is None:
            return
        for diagnostic in diagnostics:
            try:
                console.print_warning(diagnostic)
            except Exception:
                pass

    @staticmethod
    async def _collect_emergency_cleanup_diagnostics() -> List[str]:
        """
        Close open sessions and return only value-free result diagnostics.

        The implementation uses current instance state to close open sessions
        and return only value-free result diagnostics. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Returns:
            The validated ``diagnostics``.
        """
        diagnostics: List[str] = []
        closed_count = 0
        try:
            gc.collect()
            for obj in gc.get_objects():
                if isinstance(obj, aiohttp.ClientSession):
                    if not obj.closed:
                        try:
                            await obj.close()
                        except Exception:
                            diagnostics.append(
                                "Emergency cleanup could not close an open "
                                "ClientSession."
                            )
                            continue

                        closed_count += 1
                        diagnostics.append(
                            "Emergency cleanup closed an open ClientSession."
                        )

            if closed_count > 0:
                diagnostics.append(
                    f"Emergency cleanup completed: closed {closed_count} ClientSession(s)"
                )

        except Exception:
            diagnostics.append(
                "Emergency cleanup could not inspect open ClientSessions."
            )
        return diagnostics


class BaseCLICommand:
    """
    Base class for CLI commands with common functionality.

    This class provides shared utilities for all CLI command implementations,
    including configuration management and output handling.
    """

    def __init__(self):
        """
        Initialize the base CLI command.

        The initializer records ``orchestrator`` and ``sanitized_console`` for
        later operations and establishes the instance invariants before any
        public method runs.
        """
        self.sanitized_console = create_sanitized_console()
        self.orchestrator: Optional[WorkflowOrchestrator] = None

    def _print_command_error(
        self,
        message: str,
        *,
        json_output: bool,
        title: str = "Command Error",
        suggestions: Sequence[str] = (),
    ) -> None:
        """
        Emit command diagnostics without writing into JSON stdout.

        The implementation uses ``message`` and ``json_output`` to emit command
        diagnostics without writing into JSON stdout.

        Args:
            message: Operator-facing text carried by the reported event or
                failure.
            json_output: Whether JSON output is enabled or required for this
                operation.
            title: Stable failure category displayed in the human-mode panel.
            suggestions: Ordered recovery actions displayed in human mode.
        """

        if not json_output:
            recovery = tuple(suggestions) or (
                "Correct the reported input or configuration and retry.",
                "Run the command with --help to inspect valid inputs.",
            )
            self.sanitized_console.print_failure(
                message,
                title=title,
                suggestions=recovery,
            )
            return

        try:
            rendered = self.sanitized_console.sanitizer.sanitize(str(message))
            rendered = neutralize_terminal_text(str(rendered))
        except Exception:
            rendered = "Command failed."
        print(rendered, file=sys.stderr)

    def _find_config_directory(self) -> Path:
        """
        Find the config directory using the shared utility function.

        After applying local validation, the function forwards current instance
        state to ``find_config_directory`` and preserves its return and
        exception contract.

        Returns:
            The validated config directory filesystem path.
        """
        return find_config_directory()

    def _create_tool_config_object(
        self,
        spreadsheet: Optional[Path],
        quiet_mode: bool = False,
        config_file: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Create tool config as object instead of YAML file.

        Will attempt to load from tool_config.yaml if it exists, otherwise uses
        defaults.

        Args:
            spreadsheet: filesystem location used as the spreadsheet for this
                operation.
            quiet_mode: Whether quiet mode is enabled or required for this
                operation.
            config_file: Optional filesystem location used as the config file
                for this operation.

        Returns:
            The validated ``tool_config``.

        Raises:
            FileNotFoundError: If tool configuration file not found:
                ``tool_config_path``.
            ValueError: If unknown ``label`` in tool configuration:
                ``rendered``.
        """
        # Resolve through the same strict model used by the collection command.
        # Standalone commands must not silently discard malformed or unknown
        # settings and then run with defaults.
        if config_file is not None:
            tool_config_path = config_file
            if not tool_config_path.exists():
                raise FileNotFoundError(
                    f"Tool configuration file not found: {tool_config_path}"
                )
        else:
            config_dir = self._find_config_directory()
            tool_config_path = config_dir / "tool_config.yaml"

        resolved_tool_config = (
            load_config(tool_config_path) if tool_config_path.exists() else None
        )
        if resolved_tool_config is not None:
            unknown_keys = sorted(
                str(key)
                for key in (getattr(resolved_tool_config, "model_extra", None) or {})
            )
            if unknown_keys:
                label = "key" if len(unknown_keys) == 1 else "keys"
                rendered = ", ".join(repr(key) for key in unknown_keys)
                raise ValueError(f"Unknown {label} in tool configuration: {rendered}")

        # Auto-detect spreadsheet path and add to tool config
        spreadsheet_path = None
        try:
            from .utils.spreadsheet_utils import auto_detect_spreadsheet

            detected_spreadsheet = auto_detect_spreadsheet(None, suppress_print=True)
            if detected_spreadsheet:
                spreadsheet_path = str(detected_spreadsheet)
        except Exception:
            pass

        # Start with default config
        tool_config = {
            "execution_config": {
                "concurrency_mode": "conservative",
                "initial_io_oversubscription": None,
                "minimum_collector_operations": 1,
                "maximum_collector_operations": None,
                "adaptive": {},
                "max_concurrent_duts": None,
                "max_concurrent_collectors_per_dut": (
                    DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT
                ),
                "retry_count": 1,
            },
            "collector_definitions": (
                {"spreadsheet_path": spreadsheet_path} if spreadsheet_path else {}
            ),
            "logging": {
                "level": "INFO",
                "format": "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            },
            # Preflight credential validation configuration (defaults)
            "preflight_config": {
                "validate_credentials_in_preflight": True,  # Default: validate credentials
            },
            # Add critical parallelization settings
            "PARALLEL_DUT_SEQUENTIAL_COLLECTORS": True,
            "SERVICE_GROUPED_SEQUENTIAL_COLLECTORS": True,
            # Global directory and prefix fields
            "TASK_ID_PREFIX": "",  # Empty by default, only used if user specifies
            "TOOL_TEMP_DIR": getattr(
                getattr(self, "tool_config", None), "tool_temp_dir", "/tmp"
            ),
        }

        # Project only source-present model fields onto the standalone runtime
        # dictionary so aliases and validation remain identical to collect().
        if resolved_tool_config is not None:
            source_fields = set(getattr(resolved_tool_config, "_yaml_fields", set()))

            execution_values: Dict[str, Any] = {}
            for holder_name in ("execution_config", "execution"):
                if holder_name not in source_fields:
                    continue
                holder = getattr(resolved_tool_config, holder_name, None)
                if holder is not None:
                    execution_values.update(holder.model_dump(exclude_unset=True))
            for field_name in (
                "concurrency_mode",
                "initial_io_oversubscription",
                "minimum_collector_operations",
                "maximum_collector_operations",
                "max_concurrent_duts",
                "max_concurrent_collectors_per_dut",
                "timeout",
                "retry_count",
            ):
                if field_name in source_fields:
                    execution_values[field_name] = getattr(
                        resolved_tool_config, field_name
                    )
            tool_config["execution_config"].update(execution_values)

            if "logging" in source_fields:
                logging_values = resolved_tool_config.logging.model_dump(
                    exclude_unset=True
                )
                tool_config["logging"].update(
                    {
                        key: value
                        for key, value in logging_values.items()
                        if key in {"level", "format"} and value is not None
                    }
                )
            if "log_level" in source_fields:
                tool_config["logging"]["level"] = resolved_tool_config.log_level
            if "log_format" in source_fields:
                tool_config["logging"]["format"] = resolved_tool_config.log_format

            preflight_values = resolved_tool_config.preflight_config.model_dump(
                exclude_unset=True
            )
            tool_config["preflight_config"].update(preflight_values)

            if source_fields.intersection(
                {"redfish_session_config", "redfish_sessions"}
            ):
                tool_config["redfish_session_config"] = (
                    resolved_tool_config.redfish_session_config.model_dump(
                        exclude_unset=True
                    )
                )
            for field_name in (
                "uri_overrides",
                "i2c_config",
                "sysinfo_snapshot_mode",
            ):
                if field_name in source_fields:
                    tool_config[field_name] = getattr(resolved_tool_config, field_name)
            for field_name in ("ssh_host_key_policy", "ssh_known_hosts_file"):
                if field_name in source_fields:
                    tool_config[field_name] = getattr(resolved_tool_config, field_name)

        # Add spreadsheet configuration if provided
        if spreadsheet:
            tool_config["collector_definitions"]["spreadsheet_path"] = str(spreadsheet)

        # Quiet mode flags - disable unnecessary operations
        if quiet_mode:
            tool_config["skip_preflight"] = True
            tool_config["skip_html_reports"] = True
            tool_config["skip_zip"] = True
            tool_config["skip_zip_split"] = True

        return tool_config

    def _create_minimal_dut_config(
        self, baseboard: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create minimal DUT config for commands that don't need full DUT validation.

        The implementation uses ``baseboard`` to create minimal DUT config for
        commands that don't need full DUT validation.

        Args:
            baseboard: Optional baseboard; ``None`` selects the function's
                default behavior.

        Returns:
            A mapping containing the ``DUT_Defaults`` and ``duts`` fields.
        """
        return {
            "DUT_Defaults": {},
            "duts": {
                "temp-dut": {
                    "hostname": "localhost",
                    "baseboard": baseboard if baseboard else "generic",
                }
            },
        }

    async def _initialize_orchestrator(
        self,
        tool_config: Dict[str, Any],
        dut_config: Dict[str, Any],
        quiet_mode: bool = False,
    ) -> WorkflowOrchestrator:
        """
        Initialize the workflow orchestrator with common configuration.

        The implementation uses ``tool_config``, ``dut_config``, and
        ``quiet_mode`` to initialize the workflow orchestrator with common
        configuration. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. It updates
        ``orchestrator`` on the instance as part of that state transition.

        Args:
            tool_config: Tool config governing initialize the workflow
                orchestrator with common configuration.
            dut_config: DUT config governing initialize the workflow
                orchestrator with common configuration.
            quiet_mode: Whether quiet mode is enabled or required for this
                operation.

        Returns:
            The validated ``orchestrator``.
        """

        # For quiet mode operations, use a temporary directory that will be cleaned up
        if quiet_mode:
            # Create a temporary directory for logging
            temp_dir = tempfile.mkdtemp(prefix="nvdebug_quiet_")
            log_dir = temp_dir

            # Store the temporary directory path in tool config for global access
            tool_config["temp_log_dir"] = temp_dir
        else:
            # For non-quiet mode (like collect command), use the default log directory
            log_dir = None

        orchestrator = WorkflowOrchestrator(
            tool_config=tool_config,
            dut_configs=dut_config,
            quiet_mode=quiet_mode,
            catalog_only_mode=quiet_mode,
            sanitized_console=self.sanitized_console,
            log_dir=log_dir,
        )

        # Store the orchestrator before async initialization so the shared
        # error handler can clean up partially initialized state.
        self.orchestrator = orchestrator
        orchestrator.set_sanitizer(getattr(self, "sanitizer", None))
        await orchestrator.initialize()
        return orchestrator

    async def _cleanup_orchestrator(self):
        """
        Clean up the orchestrator if it exists.

        Performs cleanup of the workflow orchestrator and any temporary
        directories created during execution.
        """
        orchestrator = self.orchestrator
        if not orchestrator:
            return

        # Clear the reference before awaiting cleanup. This makes cleanup
        # idempotent when the command-level error handler runs after a cleanup
        # failure and prevents a second traceback from the same orchestrator.
        self.orchestrator = None

        temp_log_dir = None
        if hasattr(orchestrator, "config_manager"):
            try:
                tool_config = orchestrator.config_manager.get_tool_config()
                temp_log_dir = tool_config.get("temp_log_dir")
            except Exception:
                # The orchestrator may only be partially initialized. Its
                # original tool config still contains the temporary path.
                tool_config = getattr(orchestrator, "_tool_config_obj", None)
                if isinstance(tool_config, dict):
                    temp_log_dir = tool_config.get("temp_log_dir")

        try:
            await orchestrator.cleanup()
        finally:
            if temp_log_dir:
                try:
                    if os.path.exists(temp_log_dir):
                        shutil.rmtree(temp_log_dir)
                except Exception as e:
                    # Use stderr so machine-readable stdout remains valid.
                    print(
                        f"Failed to cleanup temp dir {temp_log_dir}: {e}",
                        file=sys.stderr,
                    )

    def _handle_output(
        self,
        data: Any,
        json_output: bool = False,
        output_file: Optional[str] = None,
        output_type: str = "collectors",
    ) -> None:
        """
        Handle output formatting using OutputFormatter.

        The implementation uses ``data``, ``json_output``, ``output_file``, and
        ``output_type`` to handle output formatting using OutputFormatter.
        Terminal status is emitted only after output formatting using
        OutputFormatter and its owned cleanup have completed.

        Args:
            data: Data consumed while the function attempts to handle output
                formatting using OutputFormatter.
            json_output: Whether JSON output is enabled or required for this
                operation.
            output_file: Optional filesystem location used as the output file
                for this operation.
            output_type: Text supplied as output type in the format accepted by
                this function.
        """
        output_formatter = OutputFormatter(self.sanitized_console)

        if output_type == "collectors":
            filtered_collectors, sequential_collectors = data
            if filtered_collectors:
                output_formatter.output_collectors(
                    filtered_collectors,
                    sequential_collectors,
                    json_output=json_output,
                    output_file=output_file,
                )
            else:
                if json_output:
                    output_formatter.output_collectors(
                        [],
                        sequential_collectors,
                        json_output=True,
                        output_file=output_file,
                    )
                else:
                    if output_file:
                        output_formatter.output_collectors(
                            [],
                            sequential_collectors,
                            json_output=False,
                            output_file=output_file,
                        )
                    else:
                        self.sanitized_console.print_warning(
                            "No collectors found matching the criteria"
                        )
        elif output_type == "preflight":
            output_formatter.output_preflight_results(
                data, json_output=json_output, output_file=output_file
            )
        elif output_type == "baseboards":
            if json_output:
                if output_file:
                    output_formatter._output_baseboards_json_to_file(
                        data, Path(output_file)
                    )
                else:
                    output_formatter._output_baseboards_json_to_stdout(data)
            else:
                if output_file:
                    output_formatter._output_baseboards_table_to_file(
                        data, Path(output_file)
                    )
                else:
                    output_formatter._output_baseboards_table_to_stdout(data)

    async def _run_with_error_handling(
        self,
        operation_func: Callable[..., Any],
        *args: Any,
        error_json_output: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Run an operation with common error handling.

        After applying local validation, the function forwards
        ``operation_func``, ``args``, and ``kwargs`` to ``operation_func`` and
        preserves its return and exception contract. Terminal status is emitted
        only after operation with common error handling and its owned cleanup
        have completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            operation_func: Operation func consumed while the function attempts
                to run an operation with common error handling.
            args: Additional positional values forwarded in caller-provided
                order.
            error_json_output: Whether terminal diagnostics must preserve
                machine-readable stdout.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The awaited operation result, or ``None`` after a handled command
            failure.

        Raises:
            click.UsageError: If local validation rejects command input. The
                error is re-raised after owned orchestrator cleanup so the CLI
                command can render its contextual usage diagnostic.
            SystemExit: Exits with code 1 on error.
        """
        try:
            return await operation_func(*args, **kwargs)
        except click.UsageError:
            await self._cleanup_orchestrator()
            raise
        except Exception as e:
            self._print_command_error(
                f"Error: {e}",
                json_output=error_json_output,
            )
            await self._cleanup_orchestrator()
            sys.exit(1)


class CLIListCollectors(BaseCLICommand):
    """
    Handles the list-collectors command logic.

    This class implements the list-collectors CLI command which displays
    available log collectors, optionally filtered by baseboard or group.
    """

    def __init__(self):
        """
        Initialize the list-collectors command handler.

        The initializer establishes the instance invariants required by later
        operations before the object becomes visible to callers.
        """
        super().__init__()

    async def run(
        self,
        baseboard: Optional[str],
        group: Optional[str],
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
    ) -> None:
        """
        Run the list collectors command using the WorkflowOrchestrator.

        The implementation uses ``baseboard``, ``group``, ``spreadsheet``,
        ``json_output``, and ``output_file`` to run the list collectors command
        using the WorkflowOrchestrator. Terminal status is emitted only after
        list collectors command using the WorkflowOrchestrator and its owned
        cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            baseboard: Text supplied as baseboard in the format accepted by this
                function.
            group: Text supplied as group in the format accepted by this
                function.
            spreadsheet: filesystem location used as the spreadsheet for this
                operation.
            json_output: Whether JSON output is enabled or required for this
                operation.
            output_file: Optional filesystem location used as the output file
                for this operation.
        """
        await self._run_collector_command(
            baseboard=baseboard,
            group=group,
            spreadsheet=spreadsheet,
            json_output=json_output,
            output_file=output_file,
            filter_default_only=False,
        )

    async def _run_collector_command(
        self,
        baseboard: Optional[str],
        group: Optional[str],
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
        filter_default_only: bool = False,
    ) -> None:
        """
        Shared method for running collector listing commands.

        After applying local validation, the function forwards ``baseboard``,
        ``group``, ``spreadsheet``, ``json_output``, and ``output_file`` to
        ``self._run_with_error_handling`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            baseboard: Text supplied as baseboard in the format accepted by this
                function.
            group: Text supplied as group in the format accepted by this
                function.
            spreadsheet: filesystem location used as the spreadsheet for this
                operation.
            json_output: Whether JSON output is enabled or required for this
                operation.
            output_file: Optional filesystem location used as the output file
                for this operation.
            filter_default_only: Whether filter default only is enabled or
                required for this operation.

        Returns:
            The delegated operation's completion result when it returns one.
        """
        return await self._run_with_error_handling(
            self._execute_collector_command,
            baseboard,
            group,
            spreadsheet,
            json_output,
            output_file,
            filter_default_only,
            error_json_output=json_output,
        )

    async def _execute_collector_command(
        self,
        baseboard: Optional[str],
        group: Optional[str],
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
        filter_default_only: bool = False,
    ) -> None:
        """
        Execute the collector command logic.

        Create minimal DUT config for quiet mode (needed for BaseboardManager
        initialization).

        Args:
            baseboard: Text supplied as baseboard in the format accepted by this
                function.
            group: Text supplied as group in the format accepted by this
                function.
            spreadsheet: filesystem location used as the spreadsheet for this
                operation.
            json_output: Whether JSON output is enabled or required for this
                operation.
            output_file: Optional filesystem location used as the output file
                for this operation.
            filter_default_only: Whether filter default only is enabled or
                required for this operation.

        Raises:
            click.BadParameter: If one or more requested collector groups do
                not exist in the active catalog.
        """
        # Create tool config as object instead of YAML file
        tool_config_obj = self._create_tool_config_object(spreadsheet, quiet_mode=True)
        # Create minimal DUT config for quiet mode (needed for BaseboardManager initialization)
        dut_config = self._create_minimal_dut_config(baseboard)

        # Create orchestrator in quiet mode for listing collectors
        orchestrator = await self._initialize_orchestrator(
            tool_config_obj, dut_config, quiet_mode=True
        )

        # Normalize and validate group filters (case-insensitive, comma-separated)
        normalized_groups: Optional[List[str]] = None
        if group:
            group_items = [item.strip() for item in group.split(",")]
            normalized_groups = [
                "health_check" if item.lower() == "healthcheck" else item.lower()
                for item in group_items
                if item
            ]
            if normalized_groups:
                available_groups = (
                    orchestrator.config_manager.get_all_collector_groups()
                )
                available_groups_normalized = {
                    item.lower() for item in available_groups
                }
                invalid_groups = sorted(
                    set(normalized_groups) - available_groups_normalized
                )
                if invalid_groups:
                    valid_groups = ", ".join(sorted(available_groups_normalized))
                    invalid_list = ", ".join(invalid_groups)
                    raise click.BadParameter(
                        "Invalid collector group(s): "
                        f"{invalid_list}. Valid groups: {valid_groups}",
                        param_hint="--group",
                    )
            else:
                normalized_groups = None

        # Get all collectors
        all_collectors = orchestrator.get_all_collectors()

        sequential_collectors = orchestrator.get_sequential_collectors()
        orchestrator.get_parallel_collectors()

        # Apply filters
        filtered_collectors = []
        for collector_id in all_collectors:
            collector_info = orchestrator.get_collector_info(collector_id)

            # Baseboard filter
            if baseboard and not orchestrator._is_collector_applicable(
                collector_info, baseboard
            ):
                continue

            # Group filter
            if normalized_groups:
                collector_group = collector_info.get("group", "")
                if (
                    not collector_group
                    or collector_group.lower() not in normalized_groups
                ):
                    continue

            # Default collectors filter (only for default-collectors command)
            if filter_default_only:
                if collector_info.get("collection_level", "L1") != "L1" or not (
                    collector_info.get("enabled", True)
                ):
                    continue

            display_info = dict(collector_info)
            effective_baseboards = self._resolve_effective_supported_baseboards(
                collector_info, orchestrator
            )
            if effective_baseboards is not None:
                display_info["applicable_baseboards"] = effective_baseboards
            filtered_collectors.append((collector_id, display_info))

        # Use shared output handling
        self._handle_output(
            (filtered_collectors, sequential_collectors),
            json_output=json_output,
            output_file=output_file,
            output_type="collectors",
        )

        # Cleanup
        await self._cleanup_orchestrator()

    def _resolve_effective_supported_baseboards(
        self,
        collector_info: Mapping[str, Any],
        orchestrator: WorkflowOrchestrator,
    ) -> Optional[List[str]]:
        """
        Resolve a collector's effective support to concrete catalog baseboards.

        The runtime applicability predicate owns include-group expansion,
        explicit exclusions, legacy tag constraints, and case normalization.
        Evaluating every concrete baseboard through that same predicate keeps
        the unfiltered display consistent with ``--baseboard`` filtering.

        Args:
            collector_info: Collector definition loaded from the runtime
                spreadsheet.
            orchestrator: Initialized listing orchestrator that owns the
                runtime baseboard manager and applicability predicate.

        Returns:
            Sorted concrete baseboard names supported by the collector, or
            ``None`` when the orchestrator does not expose a baseboard manager
            and the caller must retain the raw catalog expression.

        Raises:
            ValueError: If a catalog baseboard cannot be evaluated by the
                runtime applicability predicate.
        """
        dut_manager = getattr(orchestrator, "dut_manager", None)
        get_baseboard_manager = getattr(dut_manager, "_get_baseboard_manager", None)
        if not callable(get_baseboard_manager):
            return None
        baseboard_manager = get_baseboard_manager()
        if baseboard_manager is None:
            return None

        baseboard_names = baseboard_manager.get_all_baseboard_names()
        if not isinstance(baseboard_names, list):
            return None
        return [
            baseboard_name
            for baseboard_name in sorted(baseboard_names)
            if orchestrator._is_collector_applicable(
                dict(collector_info), baseboard_name
            )
        ]

    def _format_supported_baseboards(
        self, applicable_baseboards, orchestrator=None
    ) -> str:
        """
        Format supported baseboards.

        The implementation uses ``applicable_baseboards`` and ``orchestrator``
        to format supported baseboards. The source value keeps its ownership
        while the normalized representation is returned separately.

        Args:
            applicable_baseboards: Entries supplied as ``applicable_baseboards``
                and processed in caller-provided order.
            orchestrator: Optional orchestrator; ``None`` selects the function's
                default behavior.

        Returns:
            The canonical supported baseboards text.
        """
        if _is_universal_baseboard_spec(applicable_baseboards):
            return "All"
        elif not applicable_baseboards:
            return "None"

        # Load baseboard groups mapping
        baseboard_groups = self._get_baseboard_groups(orchestrator)

        expanded_baseboards = set()

        if isinstance(applicable_baseboards, list):
            for item in applicable_baseboards:
                if item in baseboard_groups:
                    # Expand group to specific baseboards
                    expanded_baseboards.update(baseboard_groups[item])
                else:
                    # It's already a specific baseboard
                    expanded_baseboards.add(item)
        elif isinstance(applicable_baseboards, str):
            if applicable_baseboards in baseboard_groups:
                # Expand group to specific baseboards
                expanded_baseboards.update(baseboard_groups[applicable_baseboards])
            else:
                # It's already a specific baseboard
                expanded_baseboards.add(applicable_baseboards)

        # Sort for consistent display
        return (
            ", ".join(sorted(expanded_baseboards)) if expanded_baseboards else "Unknown"
        )

    def _get_baseboard_groups(self, orchestrator=None) -> dict:
        """
        Get baseboard groups mapping from spreadsheet.

        Try to get baseboard groups from the orchestrator's baseboard manager.

        Args:
            orchestrator: Optional orchestrator; ``None`` selects the function's
                default behavior.

        Returns:
            A mapping containing baseboard groups.
        """
        try:
            # Try to get baseboard groups from the orchestrator's baseboard manager
            if orchestrator and hasattr(orchestrator, "config_manager"):
                baseboard_manager = orchestrator.config_manager.get_baseboard_manager()
                if baseboard_manager:
                    return baseboard_manager.get_baseboard_groups()
        except Exception:
            pass

        # Return empty dict if no baseboard manager available
        return {}


class CLIDefaultCollectors(BaseCLICommand):
    """
    Handles the default-collectors command logic.

    This class implements the default-collectors CLI command which shows
    collectors that are enabled by default for a given baseboard.
    """

    def __init__(self):
        """
        Initialize the default-collectors command handler.

        The initializer establishes the instance invariants required by later
        operations before the object becomes visible to callers.
        """
        super().__init__()

    async def run(
        self,
        baseboard: str,
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
    ) -> None:
        """
        Run the default collectors command using the shared collector logic.

        The implementation uses ``baseboard``, ``spreadsheet``, ``json_output``,
        and ``output_file`` to run the default collectors command using the
        shared collector logic. Terminal status is emitted only after default
        collectors command using the shared collector logic and its owned
        cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            baseboard: Text supplied as baseboard in the format accepted by this
                function.
            spreadsheet: filesystem location used as the spreadsheet for this
                operation.
            json_output: Whether JSON output is enabled or required for this
                operation.
            output_file: Optional filesystem location used as the output file
                for this operation.
        """
        # Create a CLIListCollectors instance to use the shared method
        list_collectors_handler = CLIListCollectors()
        await list_collectors_handler._run_collector_command(
            baseboard=baseboard,
            group=None,  # No group filter for default collectors
            spreadsheet=spreadsheet,
            json_output=json_output,
            output_file=output_file,
            filter_default_only=True,  # Enable default collectors filtering
        )


class CLIListBaseboards(BaseCLICommand):
    """
    Handles the list-baseboards command logic.

    This class implements the list-baseboards CLI command which displays all
    available baseboard platforms from the collector definitions.
    """

    def __init__(self):
        """
        Initialize the list-baseboards command handler.

        The initializer establishes the instance invariants required by later
        operations before the object becomes visible to callers.
        """
        super().__init__()

    async def run(
        self,
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
    ) -> None:
        """
        Run the list baseboards command using the BaseboardManager.

        After applying local validation, the function forwards ``spreadsheet``,
        ``json_output``, and ``output_file`` to
        ``self._run_with_error_handling`` and preserves its return and exception
        contract. Terminal status is emitted only after list baseboards command
        using the BaseboardManager and its owned cleanup have completed. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            spreadsheet: filesystem location used as the spreadsheet for this
                operation.
            json_output: Whether JSON output is enabled or required for this
                operation.
            output_file: Optional filesystem location used as the output file
                for this operation.

        Returns:
            The delegated operation's completion result when it returns one.
        """
        return await self._run_with_error_handling(
            self._execute_list_baseboards,
            spreadsheet,
            json_output,
            output_file,
            error_json_output=json_output,
        )

    async def _execute_list_baseboards(
        self,
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
    ) -> None:
        """
        Execute the list baseboards command logic.

        Debug: Check if spreadsheet path is set correctly.

        Args:
            spreadsheet: filesystem location used as the spreadsheet for this
                operation.
            json_output: Whether JSON output is enabled or required for this
                operation.
            output_file: Optional filesystem location used as the output file
                for this operation.

        Raises:
            SystemExit: If the selected Telemetry Catalog is unavailable.
        """
        # Create tool config as object instead of YAML file
        tool_config_obj = self._create_tool_config_object(spreadsheet, quiet_mode=True)

        # Debug: Check if spreadsheet path is set correctly
        spreadsheet_path = tool_config_obj.get("collector_definitions", {}).get(
            "spreadsheet_path"
        )
        if not spreadsheet_path or not Path(spreadsheet_path).exists():
            self._print_command_error(
                "The selected Telemetry Catalog spreadsheet is unavailable.",
                json_output=json_output,
                title="Telemetry Catalog Required",
                suggestions=(
                    "Provide a readable spreadsheet with --spreadsheet.",
                    "Install one supported Telemetry Catalog in the config directory.",
                ),
            )
            raise SystemExit(1)

        # Create BaseboardManager directly

        # Create a temporary directory that will be cleaned up automatically
        with tempfile.TemporaryDirectory(prefix="nvdebug_quiet_") as temp_dir:
            # Store the temporary directory path in tool config for global access
            tool_config_obj["temp_log_dir"] = temp_dir

            # Create a temporary logger for the baseboard manager
            temp_logger = AsyncSafeLogger(temp_dir)

            async with BaseboardManager(
                spreadsheet_path=spreadsheet_path,
                logger=temp_logger,
            ) as baseboard_manager:
                # Get all baseboards from the manager
                baseboards = baseboard_manager.get_all_baseboard_names()

                if not baseboards:
                    if json_output:
                        # Output empty JSON
                        self._handle_output(
                            {"baseboards": [], "total_baseboards": 0},
                            json_output=True,
                            output_file=output_file,
                            output_type="baseboards",
                        )
                    else:
                        if output_file:
                            # Write empty result to file
                            self._handle_output(
                                {"baseboards": [], "total_baseboards": 0},
                                json_output=False,
                                output_file=output_file,
                                output_type="baseboards",
                            )
                        else:
                            self.sanitized_console.print_warning("No baseboards found")
                    return

                # Prepare baseboard data with descriptions
                baseboard_data = []
                for baseboard in sorted(baseboards):
                    # Node role and family group are independent catalog fields.
                    baseboard_type = baseboard_manager.get_baseboard_node_type(
                        baseboard
                    )
                    baseboard_group = baseboard_manager.get_baseboard_group(baseboard)

                    description = f"Type: {baseboard_type or 'Unknown'}"
                    if baseboard_group:
                        description += f", Group: {baseboard_group}"

                    baseboard_data.append(
                        {
                            "name": baseboard,
                            "type": baseboard_type or "",
                            "group": baseboard_group or "",
                            "description": description,
                        }
                    )

                # Use shared output handling
                self._handle_output(
                    {
                        "baseboards": baseboard_data,
                        "total_baseboards": len(baseboard_data),
                    },
                    json_output=json_output,
                    output_file=output_file,
                    output_type="baseboards",
                )


_PREFLIGHT_SECRET_BINDINGS = {
    "bmc_pass": ("bmc_ip", "BMC_IP", "BMC_PASSWORD"),
    "bmc_ssh_pass": ("bmc_ip", "BMC_IP", "BMC_SSH_PASSWORD"),
    "bmc_rf_pass": ("bmc_ip", "BMC_IP", "RF_Pass"),
    "host_pass": ("host_ip", "HOST_IP", "HOST_PASSWORD"),
    "hmc_pass": ("hmc_ip", "HMC_IP", "HMC_PASSWORD"),
    "hmc_ssh_pass": ("hmc_ip", "HMC_IP", "HMC_SSH_PASSWORD"),
    "ssh_proxy_pass": (
        "ssh_proxy_host",
        "SSH_PROXY_HOST",
        "SSH_PROXY_PASSWORD",
    ),
}
_PREFLIGHT_MULTI_DUT_SHARED_SECRETS = frozenset({"host_pass", "ssh_proxy_pass"})


def _bind_preflight_config_overlays(
    dut_configs: List[DUTConfig],
    *,
    bmc_pass: Optional[str] = None,
    bmc_ssh_pass: Optional[str] = None,
    bmc_rf_pass: Optional[str] = None,
    host_pass: Optional[str] = None,
    hmc_pass: Optional[str] = None,
    hmc_ssh_pass: Optional[str] = None,
    ssh_proxy_host: Optional[str] = None,
    ssh_proxy_port: Optional[int] = None,
    ssh_proxy_user: Optional[str] = None,
    ssh_proxy_pass: Optional[str] = None,
    ssh_proxy_key_path: Optional[str] = None,
    ssh_proxy_passwordless: bool = False,
    ssh_proxy_max_retries: Optional[int] = None,
    bmc_rf_verify_ssl: Optional[bool] = None,
    ssh_host_key_policy: Optional[str] = None,
    ssh_known_hosts_file: Optional[str] = None,
) -> List[DUTConfig]:
    """
    Return DUT models with safe preflight-only overlays applied.

    A single environment password may be intentionally shared by host or proxy
    endpoints in a multi-DUT file. Other endpoint passwords remain single-DUT to
    avoid silently spreading one credential across unrelated management
    controllers. No source YAML is changed, and a no-op preserves the caller's
    exact list and model identities.

    Args:
        dut_configs: DUT configs governing DUT models with safe preflight-only
            overlays applied.
        bmc_pass: Optional BMC pass; ``None`` selects the function's default
            behavior.
        bmc_ssh_pass: Optional BMC SSH pass; ``None`` selects the function's
            default behavior.
        bmc_rf_pass: Optional BMC Redfish pass; ``None`` selects the function's
            default behavior.
        host_pass: Optional host pass; ``None`` selects the function's default
            behavior.
        hmc_pass: Optional HMC pass; ``None`` selects the function's default
            behavior.
        hmc_ssh_pass: Optional HMC SSH pass; ``None`` selects the function's
            default behavior.
        ssh_proxy_host: Optional SSH proxy host; ``None`` selects the function's
            default behavior.
        ssh_proxy_port: Optional SSH proxy port; ``None`` selects the function's
            default behavior.
        ssh_proxy_user: Optional SSH proxy user; ``None`` selects the function's
            default behavior.
        ssh_proxy_pass: Optional SSH proxy pass; ``None`` selects the function's
            default behavior.
        ssh_proxy_key_path: Optional filesystem location used as the SSH proxy
            key path for this operation.
        ssh_proxy_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        ssh_proxy_max_retries: Optional SSH proxy max retries; ``None`` selects
            the function's default behavior.
        bmc_rf_verify_ssl: Optional legacy Redfish certificate-verification
            override applied only during preflight configuration resolution.
        ssh_host_key_policy: Optional SSH server-authentication policy applied
            consistently to every preflight route.
        ssh_known_hosts_file: Optional known-hosts trust source used when strict
            SSH host-key verification is selected.

    Returns:
        The bind preflight config overlays returned in operation-defined order.

    Raises:
        ValueError: If the supplied input cannot be used to produce DUT models
            with safe preflight-only overlays applied.
    """

    proxy_overrides: Dict[str, Any] = {}
    for field_name, legacy_name, value in (
        ("ssh_proxy_host", "SSH_PROXY_HOST", ssh_proxy_host),
        ("ssh_proxy_port", "SSH_PROXY_PORT", ssh_proxy_port),
        ("ssh_proxy_user", "SSH_PROXY_USERNAME", ssh_proxy_user),
        ("ssh_proxy_key_path", "SSH_PROXY_KEY_PATH", ssh_proxy_key_path),
        (
            "ssh_proxy_max_retries",
            "SSH_PROXY_MAX_RETRIES",
            ssh_proxy_max_retries,
        ),
    ):
        if value is not None:
            proxy_overrides[field_name] = value
            proxy_overrides[legacy_name] = value
    if ssh_proxy_passwordless:
        proxy_overrides["ssh_proxy_passwordless"] = True
        proxy_overrides["SSH_PROXY_PASSWORDLESS"] = True

    trust_overrides: Dict[str, Any] = {}
    if bmc_rf_verify_ssl is not None:
        trust_overrides.update(
            {
                "bmc_rf_verify_ssl": bmc_rf_verify_ssl,
                "bmc_rf_tls_mode": ("system_ca" if bmc_rf_verify_ssl else "insecure"),
            }
        )
    if ssh_host_key_policy is not None:
        trust_overrides["ssh_host_key_policy"] = ssh_host_key_policy
    if ssh_known_hosts_file is not None:
        trust_overrides["ssh_known_hosts_file"] = ssh_known_hosts_file

    supplied_secrets = {
        field_name: value
        for field_name, value in (
            ("bmc_pass", bmc_pass),
            ("bmc_ssh_pass", bmc_ssh_pass),
            ("bmc_rf_pass", bmc_rf_pass),
            ("host_pass", host_pass),
            ("hmc_pass", hmc_pass),
            ("hmc_ssh_pass", hmc_ssh_pass),
            ("ssh_proxy_pass", ssh_proxy_pass),
        )
        if value is not None
    }
    if not proxy_overrides and not trust_overrides and not supplied_secrets:
        return dut_configs

    resolved = [
        (
            dut.model_copy(update={**proxy_overrides, **trust_overrides})
            if proxy_overrides or trust_overrides
            else dut
        )
        for dut in dut_configs
    ]
    if len(resolved) > 1:
        ambiguous = sorted(set(supplied_secrets) - _PREFLIGHT_MULTI_DUT_SHARED_SECRETS)
        if ambiguous:
            raise ValueError(
                "Preflight management-controller secrets cannot be shared across "
                "multiple DUTs: " + ", ".join(ambiguous)
            )

    matched = {field_name: 0 for field_name in supplied_secrets}
    bound: List[DUTConfig] = []
    for dut in resolved:
        updates: Dict[str, Any] = {}
        for field_name, secret in supplied_secrets.items():
            endpoint_field, legacy_endpoint_field, legacy_secret_field = (
                _PREFLIGHT_SECRET_BINDINGS[field_name]
            )
            if not (
                getattr(dut, endpoint_field, None)
                or getattr(dut, legacy_endpoint_field, None)
            ):
                continue
            updates[field_name] = secret
            updates[legacy_secret_field] = secret
            matched[field_name] += 1
        bound.append(dut.model_copy(update=updates) if updates else dut)

    unmatched = sorted(
        field_name for field_name, match_count in matched.items() if not match_count
    )
    if unmatched:
        raise ValueError(
            "Supplied preflight secrets do not match a configured endpoint: "
            + ", ".join(unmatched)
        )
    return bound


class CLIPreflight(BaseCLICommand):
    """
    Handles the preflight command logic.

    This class implements the preflight CLI command which performs connectivity
    and configuration checks without collecting logs.
    """

    def __init__(self):
        """
        Initialize the preflight command handler.

        The initializer records ``_ssh_host_key_warning_presented`` for later
        operations and establishes the instance invariants before any public
        method runs.
        """
        super().__init__()
        self._ssh_host_key_warning_presented = False
        self._redfish_tls_warning_presented = False

    def _display_redfish_tls_policy_warning(
        self,
        dut_configs: List[DUTConfig],
        tool_config: Any,
        *,
        json_output: bool,
    ) -> None:
        """
        Disclose an unverified preflight Redfish posture once on the console.

        Preflight resolves the same transport trust the collection run will
        use, so it must make the same explicit insecure opt-out visible. The
        check is advisory only: it never changes the resolved policy, never
        alters a per-check verdict, and a malformed configured value that the
        shared resolver rejects is reported instead of aborting the command.

        Args:
            dut_configs: Validated DUT models scheduled for this preflight run.
            tool_config: Mapping or settings object holding the resolved tool
                configuration used as the lower-precedence trust source.
            json_output: Whether machine-readable output is selected; console
                disclosure is suppressed so the JSON document stays parseable.

        Side Effects:
            Writes one warning to the sanitized console and latches
            ``_redfish_tls_warning_presented`` so repeated calls stay quiet.
        """

        if json_output or self._redfish_tls_warning_presented:
            return

        try:
            reachable = _insecure_redfish_transport_is_reachable(
                dut_configs, tool_config
            )
        except ValueError as error:
            # Disclosure must never mask a malformed trust selection, and it
            # must never abort preflight before the per-DUT checks report.
            self.sanitized_console.print_warning(
                f"Could not resolve the Redfish TLS posture for disclosure: {error}"
            )
            return

        if not reachable:
            return

        self.sanitized_console.print_warning(INSECURE_REDFISH_TRANSPORT_WARNING_MESSAGE)
        self._redfish_tls_warning_presented = True

    def _display_ssh_host_key_policy_warning(
        self,
        dut_configs: List[DUTConfig],
        *,
        json_output: bool,
    ) -> None:
        """
        Present the insecure SSH policy warning once at the CLI boundary.

        The implementation uses ``dut_configs`` and ``json_output`` to present
        the insecure SSH policy warning once at the CLI boundary. It updates
        ``_ssh_host_key_warning_presented`` on the instance as part of that
        state transition.

        Args:
            dut_configs: DUT configs governing present the insecure SSH policy
                warning once at the CLI boundary.
            json_output: Whether JSON output is enabled or required for this
                operation.
        """

        if self._ssh_host_key_warning_presented:
            return

        has_insecure_remote_dut = any(
            not dut_config.local
            and str(dut_config.ssh_host_key_policy or "insecure").strip().lower()
            == "insecure"
            for dut_config in dut_configs
        )
        if not has_insecure_remote_dut:
            return

        if json_output:
            print(INSECURE_SSH_HOST_KEY_WARNING_MESSAGE, file=sys.stderr)
        else:
            self.sanitized_console.print_warning(INSECURE_SSH_HOST_KEY_WARNING_MESSAGE)
        self._ssh_host_key_warning_presented = True

    async def _cleanup_owned_orchestrator(
        self,
        active_exception: Optional[BaseException] = None,
    ) -> Optional[FinalizationReceipt]:
        """
        Consume and tear down preflight's orchestrator exactly once.

        The implementation uses ``active_exception`` to consume and tear down
        preflight's orchestrator exactly once. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. It updates ``orchestrator`` on the instance as part of that
        state transition.

        Args:
            active_exception: Optional active exception; ``None`` selects the
                function's default behavior.

        Returns:
            The validated ``receipt``, or ``None`` when no value qualifies.

        Raises:
            RuntimeError: If standalone preflight cleanup returned no
                finalization receipt.
            BaseException: If a delegated failure occurs while the function
                attempts to consume and tear down preflight's orchestrator
                exactly once.
        """

        orchestrator = self.orchestrator
        if orchestrator is None:
            return None
        self.orchestrator = None

        cleanup_kwargs: Dict[str, Any] = {"finalize_collection": False}
        if active_exception is not None:
            cleanup_kwargs["active_exception"] = active_exception
        receipt = await orchestrator.cleanup(**cleanup_kwargs)
        if type(receipt) is not FinalizationReceipt:
            raise RuntimeError(
                "Standalone preflight cleanup returned no finalization receipt"
            )
        try:
            validate_structural_finalization_receipt(receipt)
        except Exception as error:
            raise attach_finalization_receipt(error, receipt)
        if not receipt.mandatory_teardown_complete or receipt.failures:
            raise attach_finalization_receipt(
                RuntimeError(
                    "Standalone preflight cleanup did not complete every teardown phase"
                ),
                receipt,
            )
        return receipt

    async def _run_with_owned_cleanup(
        self,
        operation_func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Run preflight under one BaseException-safe ownership boundary.

        The implementation uses ``operation_func``, ``args``, and ``kwargs`` to
        run preflight under one BaseException-safe ownership boundary. Terminal
        status is emitted only after preflight under one BaseException-safe
        ownership boundary and its owned cleanup have completed. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            operation_func: Operation func consumed while the function attempts
                to run preflight under one BaseException-safe ownership
                boundary.
            args: Additional positional values forwarded in caller-provided
                order.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The validated ``result``.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to run preflight under one BaseException-safe ownership
                boundary.
            RuntimeError: If standalone preflight completed without an owned
                cleanup receipt.
        """

        result: Any = None
        primary_error: Optional[BaseException] = None
        try:
            result = await operation_func(*args, **kwargs)
        except BaseException as error:
            primary_error = error

        cleanup_error: Optional[BaseException] = None
        cleanup_receipt: Optional[FinalizationReceipt] = None
        try:
            candidate_receipt = await self._cleanup_owned_orchestrator(primary_error)
            if type(candidate_receipt) is FinalizationReceipt:
                cleanup_receipt = candidate_receipt
        except BaseException as error:
            cleanup_error = error
            candidate_receipt = getattr(error, "receipt", None)
            if type(candidate_receipt) is FinalizationReceipt:
                cleanup_receipt = candidate_receipt

        if primary_error is not None:
            if cleanup_receipt is not None:
                attach_finalization_receipt(primary_error, cleanup_receipt)
            observed_errors = [primary_error]
            if cleanup_error is not None and cleanup_error is not primary_error:
                observed_errors.append(cleanup_error)
            raise select_authoritative_exception(observed_errors)

        if cleanup_error is not None:
            raise cleanup_error
        if cleanup_receipt is None:
            raise RuntimeError(
                "Standalone preflight completed without an owned cleanup receipt"
            )
        return result

    async def _run_with_preflight_error_handling(
        self,
        operation_func: Callable[..., Any],
        *args: Any,
        error_json_output: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Convert ordinary preflight failures to exit 1 without losing evidence.

        After applying local validation, the function forwards
        ``operation_func``, ``args``, and ``kwargs`` to ``operation_func`` and
        preserves its return and exception contract. The source value keeps its
        ownership while the normalized representation is returned separately.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            operation_func: Operation func consumed while the function attempts
                to convert ordinary preflight failures to exit 1 without losing
                evidence.
            args: Additional positional values forwarded in caller-provided
                order.
            error_json_output: Whether terminal diagnostics must preserve
                machine-readable stdout.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The run with preflight error handling value selected by the
            operation.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to convert ordinary preflight failures to exit 1
                without losing evidence.
        """

        try:
            return await operation_func(*args, **kwargs)
        except Exception as error:
            self._print_command_error(
                f"Preflight failed: {error}",
                json_output=error_json_output,
                title="Preflight Failed",
                suggestions=(
                    "Correct the reported target or runtime configuration and retry.",
                    "Run preflight with --verbose to capture additional diagnostics.",
                ),
            )
            exit_error = SystemExit(1)
            receipt = getattr(error, "receipt", None)
            if type(receipt) is FinalizationReceipt:
                attach_finalization_receipt(exit_error, receipt)
            raise exit_error from error

    async def _get_preflight_collectors_per_dut(
        self,
        orchestrator: WorkflowOrchestrator,
        collector_ids: List[str],
        dut_ids: List[str],
    ) -> Dict[str, List[str]]:
        """
        Build a dependency-check plan without requiring a known baseboard.

        Preflight also serves targets whose platform has not been detected yet.
        For those DUTs, use the conservative full catalog and let preflight
        service results remove unavailable transports. DUTs with a configured
        baseboard retain normal applicability filtering.

        Args:
            orchestrator: Text supplied as orchestrator in the format accepted
                by this function.
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.

        Returns:
            The validated ``filtered_collectors_per_dut``.
        """
        unresolved_dut_ids: List[str] = []
        resolved_dut_ids: List[str] = []

        for dut_id in dut_ids:
            dut = orchestrator.dut_manager.get_dut(dut_id)
            dut_config = getattr(dut, "config", None)
            baseboard = (
                dut_config.get("baseboard") or dut_config.get("TargetBaseboard")
                if isinstance(dut_config, dict)
                else None
            )
            if isinstance(baseboard, str) and baseboard.strip().lower() != "unknown":
                resolved_dut_ids.append(dut_id)
            else:
                unresolved_dut_ids.append(dut_id)

        filtered_collectors_per_dut = {
            dut_id: list(collector_ids) for dut_id in unresolved_dut_ids
        }
        if resolved_dut_ids:
            filtering_results = (
                await orchestrator.execution_engine.get_filtered_collectors_per_dut(
                    collector_ids, resolved_dut_ids
                )
            )
            filtered_collectors_per_dut.update(filtering_results["filtered_collectors"])

        return filtered_collectors_per_dut

    async def run(
        self,
        config_file: Optional[Path],
        dut_config: Optional[Path],
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
        local: bool = False,
        # BMC Configuration
        bmc_ip: Optional[str] = None,
        bmc_user: Optional[str] = None,
        bmc_pass: Optional[str] = None,
        bmc_ssh_user: Optional[str] = None,
        bmc_ssh_pass: Optional[str] = None,
        bmc_ssh_port: Optional[int] = None,
        bmc_ssh_key_path: Optional[str] = None,
        bmc_ssh_passwordless: bool = False,
        bmc_ssh_max_retries: Optional[int] = None,
        bmc_rf_user: Optional[str] = None,
        bmc_rf_pass: Optional[str] = None,
        bmc_rf_port: Optional[int] = None,
        # Host Configuration
        host_ip: Optional[str] = None,
        host_user: Optional[str] = None,
        host_pass: Optional[str] = None,
        host_ssh_port: Optional[int] = None,
        host_ssh_key_path: Optional[str] = None,
        host_ssh_passwordless: bool = False,
        host_ssh_max_retries: Optional[int] = None,
        # HMC Configuration
        hmc_ip: Optional[str] = None,
        hmc_user: Optional[str] = None,
        hmc_pass: Optional[str] = None,
        hmc_ssh_user: Optional[str] = None,
        hmc_ssh_pass: Optional[str] = None,
        hmc_ssh_port: Optional[int] = None,
        hmc_ssh_key_path: Optional[str] = None,
        hmc_ssh_passwordless: bool = False,
        hmc_ssh_max_retries: Optional[int] = None,
        hmc_http_port: Optional[int] = None,
        hmc_https_port: Optional[int] = None,
        hmc_use_https: bool = False,
        # SSH Proxy Configuration
        ssh_proxy_host: Optional[str] = None,
        ssh_proxy_port: Optional[int] = None,
        ssh_proxy_user: Optional[str] = None,
        ssh_proxy_pass: Optional[str] = None,
        ssh_proxy_key_path: Optional[str] = None,
        ssh_proxy_passwordless: bool = False,
        ssh_proxy_max_retries: Optional[int] = None,
        bmc_rf_verify_ssl: Optional[bool] = None,
        ssh_host_key_policy: Optional[str] = None,
        ssh_known_hosts_file: Optional[str] = None,
        resolved_dut_configs: Optional[List[DUTConfig]] = None,
        resolved_tool_config: Any = None,
        explicit_cli_params: Optional[Set[str]] = None,
    ) -> None:
        """
        Run the preflight command using the WorkflowOrchestrator.

        The implementation uses ``config_file``, ``dut_config``,
        ``spreadsheet``, ``json_output``, and ``output_file`` to run the
        preflight command using the WorkflowOrchestrator. Terminal status is
        emitted only after preflight command using the WorkflowOrchestrator and
        its owned cleanup have completed. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        It updates ``_ssh_host_key_warning_presented`` on the instance as part
        of that state transition.

        Args:
            config_file: filesystem location used as the config file for this
                operation.
            dut_config: filesystem location used as the DUT config for this
                operation.
            spreadsheet: filesystem location used as the spreadsheet for this
                operation.
            json_output: Whether JSON output is enabled or required for this
                operation.
            output_file: Optional filesystem location used as the output file
                for this operation.
            local: Whether local is enabled or required for this operation.
            bmc_ip: Optional BMC IP; ``None`` selects the function's default
                behavior.
            bmc_user: Optional BMC user; ``None`` selects the function's default
                behavior.
            bmc_pass: Optional BMC pass; ``None`` selects the function's default
                behavior.
            bmc_ssh_user: Optional BMC SSH user; ``None`` selects the function's
                default behavior.
            bmc_ssh_pass: Optional BMC SSH pass; ``None`` selects the function's
                default behavior.
            bmc_ssh_port: Optional BMC SSH port; ``None`` selects the function's
                default behavior.
            bmc_ssh_key_path: Optional filesystem location used as the BMC SSH
                key path for this operation.
            bmc_ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            bmc_ssh_max_retries: Optional BMC SSH max retries; ``None`` selects
                the function's default behavior.
            bmc_rf_user: Optional BMC Redfish user; ``None`` selects the
                function's default behavior.
            bmc_rf_pass: Optional BMC Redfish pass; ``None`` selects the
                function's default behavior.
            bmc_rf_port: Optional BMC Redfish port; ``None`` selects the
                function's default behavior.
            host_ip: Optional host IP; ``None`` selects the function's default
                behavior.
            host_user: Optional host user; ``None`` selects the function's
                default behavior.
            host_pass: Optional host pass; ``None`` selects the function's
                default behavior.
            host_ssh_port: Optional host SSH port; ``None`` selects the
                function's default behavior.
            host_ssh_key_path: Optional filesystem location used as the host SSH
                key path for this operation.
            host_ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            host_ssh_max_retries: Optional host SSH max retries; ``None``
                selects the function's default behavior.
            hmc_ip: Optional HMC IP; ``None`` selects the function's default
                behavior.
            hmc_user: Optional HMC user; ``None`` selects the function's default
                behavior.
            hmc_pass: Optional HMC pass; ``None`` selects the function's default
                behavior.
            hmc_ssh_user: Optional HMC SSH user; ``None`` selects the function's
                default behavior.
            hmc_ssh_pass: Optional HMC SSH pass; ``None`` selects the function's
                default behavior.
            hmc_ssh_port: Optional HMC SSH port; ``None`` selects the function's
                default behavior.
            hmc_ssh_key_path: Optional filesystem location used as the HMC SSH
                key path for this operation.
            hmc_ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            hmc_ssh_max_retries: Optional HMC SSH max retries; ``None`` selects
                the function's default behavior.
            hmc_http_port: Optional HMC HTTP port; ``None`` selects the
                function's default behavior.
            hmc_https_port: Optional HMC HTTPS port; ``None`` selects the
                function's default behavior.
            hmc_use_https: Whether HMC use HTTPS is enabled or required for this
                operation.
            ssh_proxy_host: Optional SSH proxy host; ``None`` selects the
                function's default behavior.
            ssh_proxy_port: Optional SSH proxy port; ``None`` selects the
                function's default behavior.
            ssh_proxy_user: Optional SSH proxy user; ``None`` selects the
                function's default behavior.
            ssh_proxy_pass: Optional SSH proxy pass; ``None`` selects the
                function's default behavior.
            ssh_proxy_key_path: Optional filesystem location used as the SSH
                proxy key path for this operation.
            ssh_proxy_passwordless: Sensitive value supplied through the
                approved input boundary and never logged.
            ssh_proxy_max_retries: Optional SSH proxy max retries; ``None``
                selects the function's default behavior.
            bmc_rf_verify_ssl: Optional legacy Redfish certificate-verification
                override forwarded to the resolved DUT configuration.
            ssh_host_key_policy: Optional SSH server-authentication policy
                applied consistently to every preflight route.
            ssh_known_hosts_file: Optional known-hosts trust source used when
                strict SSH host-key verification is selected.
            resolved_dut_configs: Optional Resolved DUT configs governing
                preflight command using the WorkflowOrchestrator.
            resolved_tool_config: Optional validated tool configuration already
                resolved by the command layer, forwarded so preflight resolves
                the same tool-wide transport the collection run would use.
            explicit_cli_params: Optional names of CLI parameters the operator
                supplied explicitly, used to keep CLI overrides above the
                tool-wide values projected from ``resolved_tool_config``.

        Returns:
            The validated ``operation``, or ``None`` when no value qualifies.
        """
        self._ssh_host_key_warning_presented = False
        operation = self._run_with_preflight_error_handling(
            self._run_with_owned_cleanup,
            self._execute_preflight,
            config_file,
            dut_config,
            spreadsheet,
            json_output,
            output_file,
            local,
            # BMC Configuration
            bmc_ip,
            bmc_user,
            bmc_pass,
            bmc_ssh_user,
            bmc_ssh_pass,
            bmc_ssh_port,
            bmc_ssh_key_path,
            bmc_ssh_passwordless,
            bmc_ssh_max_retries,
            bmc_rf_user,
            bmc_rf_pass,
            bmc_rf_port,
            # Host Configuration
            host_ip,
            host_user,
            host_pass,
            host_ssh_port,
            host_ssh_key_path,
            host_ssh_passwordless,
            host_ssh_max_retries,
            # HMC Configuration
            hmc_ip,
            hmc_user,
            hmc_pass,
            hmc_ssh_user,
            hmc_ssh_pass,
            hmc_ssh_port,
            hmc_ssh_key_path,
            hmc_ssh_passwordless,
            hmc_ssh_max_retries,
            hmc_http_port,
            hmc_https_port,
            hmc_use_https,
            # SSH Proxy Configuration
            ssh_proxy_host,
            ssh_proxy_port,
            ssh_proxy_user,
            ssh_proxy_pass,
            ssh_proxy_key_path,
            ssh_proxy_passwordless,
            ssh_proxy_max_retries,
            bmc_rf_verify_ssl=bmc_rf_verify_ssl,
            ssh_host_key_policy=ssh_host_key_policy,
            ssh_known_hosts_file=ssh_known_hosts_file,
            resolved_dut_configs=resolved_dut_configs,
            resolved_tool_config=resolved_tool_config,
            explicit_cli_params=explicit_cli_params,
            error_json_output=json_output,
        )
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=InsecureSSHHostKeyWarning)
            return await operation

    async def _execute_preflight(
        self,
        config_file: Optional[Path],
        dut_config: Optional[Path],
        spreadsheet: Optional[Path],
        json_output: bool = False,
        output_file: Optional[str] = None,
        local: bool = False,
        # BMC Configuration
        bmc_ip: Optional[str] = None,
        bmc_user: Optional[str] = None,
        bmc_pass: Optional[str] = None,
        bmc_ssh_user: Optional[str] = None,
        bmc_ssh_pass: Optional[str] = None,
        bmc_ssh_port: Optional[int] = None,
        bmc_ssh_key_path: Optional[str] = None,
        bmc_ssh_passwordless: bool = False,
        bmc_ssh_max_retries: Optional[int] = None,
        bmc_rf_user: Optional[str] = None,
        bmc_rf_pass: Optional[str] = None,
        bmc_rf_port: Optional[int] = None,
        # Host Configuration
        host_ip: Optional[str] = None,
        host_user: Optional[str] = None,
        host_pass: Optional[str] = None,
        host_ssh_port: Optional[int] = None,
        host_ssh_key_path: Optional[str] = None,
        host_ssh_passwordless: bool = False,
        host_ssh_max_retries: Optional[int] = None,
        # HMC Configuration
        hmc_ip: Optional[str] = None,
        hmc_user: Optional[str] = None,
        hmc_pass: Optional[str] = None,
        hmc_ssh_user: Optional[str] = None,
        hmc_ssh_pass: Optional[str] = None,
        hmc_ssh_port: Optional[int] = None,
        hmc_ssh_key_path: Optional[str] = None,
        hmc_ssh_passwordless: bool = False,
        hmc_ssh_max_retries: Optional[int] = None,
        hmc_http_port: Optional[int] = None,
        hmc_https_port: Optional[int] = None,
        hmc_use_https: bool = False,
        # SSH Proxy Configuration
        ssh_proxy_host: Optional[str] = None,
        ssh_proxy_port: Optional[int] = None,
        ssh_proxy_user: Optional[str] = None,
        ssh_proxy_pass: Optional[str] = None,
        ssh_proxy_key_path: Optional[str] = None,
        ssh_proxy_passwordless: bool = False,
        ssh_proxy_max_retries: Optional[int] = None,
        bmc_rf_verify_ssl: Optional[bool] = None,
        ssh_host_key_policy: Optional[str] = None,
        ssh_known_hosts_file: Optional[str] = None,
        resolved_dut_configs: Optional[List[DUTConfig]] = None,
        resolved_tool_config: Any = None,
        explicit_cli_params: Optional[Set[str]] = None,
    ) -> None:
        """
        Execute the preflight command logic.

        Performs connectivity checks and validates configuration without
        actually collecting any logs.

        Args:
            config_file: filesystem location used as the config file for this
                operation.
            dut_config: filesystem location used as the DUT config for this
                operation.
            spreadsheet: filesystem location used as the spreadsheet for this
                operation.
            json_output: Whether JSON output is enabled or required for this
                operation.
            output_file: Optional filesystem location used as the output file
                for this operation.
            local: Whether local is enabled or required for this operation.
            bmc_ip: Optional BMC IP; ``None`` selects the function's default
                behavior.
            bmc_user: Optional BMC user; ``None`` selects the function's default
                behavior.
            bmc_pass: Optional BMC pass; ``None`` selects the function's default
                behavior.
            bmc_ssh_user: Optional BMC SSH user; ``None`` selects the function's
                default behavior.
            bmc_ssh_pass: Optional BMC SSH pass; ``None`` selects the function's
                default behavior.
            bmc_ssh_port: Optional BMC SSH port; ``None`` selects the function's
                default behavior.
            bmc_ssh_key_path: Optional filesystem location used as the BMC SSH
                key path for this operation.
            bmc_ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            bmc_ssh_max_retries: Optional BMC SSH max retries; ``None`` selects
                the function's default behavior.
            bmc_rf_user: Optional BMC Redfish user; ``None`` selects the
                function's default behavior.
            bmc_rf_pass: Optional BMC Redfish pass; ``None`` selects the
                function's default behavior.
            bmc_rf_port: Optional BMC Redfish port; ``None`` selects the
                function's default behavior.
            host_ip: Optional host IP; ``None`` selects the function's default
                behavior.
            host_user: Optional host user; ``None`` selects the function's
                default behavior.
            host_pass: Optional host pass; ``None`` selects the function's
                default behavior.
            host_ssh_port: Optional host SSH port; ``None`` selects the
                function's default behavior.
            host_ssh_key_path: Optional filesystem location used as the host SSH
                key path for this operation.
            host_ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            host_ssh_max_retries: Optional host SSH max retries; ``None``
                selects the function's default behavior.
            hmc_ip: Optional HMC IP; ``None`` selects the function's default
                behavior.
            hmc_user: Optional HMC user; ``None`` selects the function's default
                behavior.
            hmc_pass: Optional HMC pass; ``None`` selects the function's default
                behavior.
            hmc_ssh_user: Optional HMC SSH user; ``None`` selects the function's
                default behavior.
            hmc_ssh_pass: Optional HMC SSH pass; ``None`` selects the function's
                default behavior.
            hmc_ssh_port: Optional HMC SSH port; ``None`` selects the function's
                default behavior.
            hmc_ssh_key_path: Optional filesystem location used as the HMC SSH
                key path for this operation.
            hmc_ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            hmc_ssh_max_retries: Optional HMC SSH max retries; ``None`` selects
                the function's default behavior.
            hmc_http_port: Optional HMC HTTP port; ``None`` selects the
                function's default behavior.
            hmc_https_port: Optional HMC HTTPS port; ``None`` selects the
                function's default behavior.
            hmc_use_https: Whether HMC use HTTPS is enabled or required for this
                operation.
            ssh_proxy_host: Optional SSH proxy host; ``None`` selects the
                function's default behavior.
            ssh_proxy_port: Optional SSH proxy port; ``None`` selects the
                function's default behavior.
            ssh_proxy_user: Optional SSH proxy user; ``None`` selects the
                function's default behavior.
            ssh_proxy_pass: Optional SSH proxy pass; ``None`` selects the
                function's default behavior.
            ssh_proxy_key_path: Optional filesystem location used as the SSH
                proxy key path for this operation.
            ssh_proxy_passwordless: Sensitive value supplied through the
                approved input boundary and never logged.
            ssh_proxy_max_retries: Optional SSH proxy max retries; ``None``
                selects the function's default behavior.
            bmc_rf_verify_ssl: Optional legacy Redfish certificate-verification
                override applied while constructing preflight DUT models.
            ssh_host_key_policy: Optional SSH server-authentication policy
                applied consistently to every preflight route.
            ssh_known_hosts_file: Optional known-hosts trust source used when
                strict SSH host-key verification is selected.
            resolved_dut_configs: Optional Resolved DUT configs governing
                preflight command logic.
            resolved_tool_config: Optional validated tool configuration already
                resolved by the command layer, used to project the tool-wide
                SSH proxy below the CLI overlay.
            explicit_cli_params: Optional names of CLI parameters the operator
                supplied explicitly, used to keep CLI overrides above the
                tool-wide values projected from ``resolved_tool_config``.

        Raises:
            SystemExit: If the function cannot execute the preflight command
                logic safely.
            RuntimeError: If the function cannot execute the preflight command
                logic safely.
        """
        # Determine if we're in CLI mode or config file mode
        # Only trigger CLI mode if actual values are provided (not None or default values)
        # A password by itself is an overlay for a selected config, not a new
        # CLI-mode target. This distinction prevents env-bound secrets from
        # discarding --dut-config/NVDEBUG_DUT_CONFIG.
        cli_mode = local or any([bmc_ip, host_ip, hmc_ip])
        config_mode = resolved_dut_configs is not None or not cli_mode

        if cli_mode and dut_config and resolved_dut_configs is None:
            # Use stderr for warnings to avoid corrupting JSON output

            print(
                "Warning: Both CLI credentials and DUT config file are provided.",
                file=sys.stderr,
            )
            print(
                "CLI credentials will be used, ignoring the DUT config file.",
                file=sys.stderr,
            )

        if resolved_dut_configs is not None:
            dut_configs = resolved_dut_configs
            warning_dut_configs = dut_configs
        elif cli_mode:
            # Create DUT config from CLI arguments

            # Create DUTConfig object first
            proxy_cli_values = {
                key: value
                for key, value in (
                    ("SSH_PROXY_HOST", ssh_proxy_host),
                    ("SSH_PROXY_PORT", ssh_proxy_port),
                    ("SSH_PROXY_USERNAME", ssh_proxy_user),
                    ("SSH_PROXY_PASSWORD", ssh_proxy_pass),
                    ("SSH_PROXY_KEY_PATH", ssh_proxy_key_path),
                    ("SSH_PROXY_MAX_RETRIES", ssh_proxy_max_retries),
                )
                if value is not None
            }
            if ssh_proxy_passwordless:
                proxy_cli_values["SSH_PROXY_PASSWORDLESS"] = True
            # Only a supplied CLI trust flag may be baked into the synthetic
            # DUT. Manufacturing a value here would put it in
            # ``model_fields_set`` and let the CLI-target DUT outrank the
            # tool-wide selection it never chose to replace.
            trust_cli_values: Dict[str, Any] = {}
            if bmc_rf_verify_ssl is not None:
                trust_cli_values["bmc_rf_verify_ssl"] = bmc_rf_verify_ssl
                trust_cli_values["bmc_rf_tls_mode"] = (
                    "system_ca" if bmc_rf_verify_ssl else "insecure"
                )
            if ssh_host_key_policy is not None:
                trust_cli_values["ssh_host_key_policy"] = ssh_host_key_policy
            if ssh_known_hosts_file is not None:
                trust_cli_values["ssh_known_hosts_file"] = ssh_known_hosts_file
            dut_config_obj = DUTConfig(
                name="dut-1",
                baseboard=None,  # Allow auto-detection
                local=local,  # Set local mode
                # BMC Configuration - use uppercase field names
                BMC_IP=bmc_ip,
                BMC_USERNAME=bmc_user,
                BMC_PASSWORD=bmc_pass,
                BMC_SSH_USERNAME=bmc_ssh_user,
                BMC_SSH_PASSWORD=bmc_ssh_pass,
                BMC_SSH_PORT=bmc_ssh_port,
                BMC_SSH_KEY_PATH=bmc_ssh_key_path,
                BMC_SSH_PASSWORDLESS=bmc_ssh_passwordless,
                BMC_SSH_MAX_RETRIES=bmc_ssh_max_retries,
                RF_User=bmc_rf_user,
                RF_Pass=bmc_rf_pass,
                BMC_RF_PORT=bmc_rf_port,
                # Host Configuration - use uppercase field names
                HOST_IP=host_ip,
                HOST_USERNAME=host_user,
                HOST_PASSWORD=host_pass,
                HOST_SSH_PORT=host_ssh_port,
                HOST_SSH_KEY_PATH=host_ssh_key_path,
                HOST_SSH_PASSWORDLESS=host_ssh_passwordless,
                HOST_SSH_MAX_RETRIES=host_ssh_max_retries,
                # HMC Configuration - use uppercase field names
                HMC_IP=hmc_ip,
                HMC_USERNAME=hmc_user,
                HMC_PASSWORD=hmc_pass,
                HMC_SSH_USERNAME=hmc_ssh_user,
                HMC_SSH_PASSWORD=hmc_ssh_pass,
                HMC_SSH_PORT=hmc_ssh_port,
                HMC_SSH_KEY_PATH=hmc_ssh_key_path,
                HMC_SSH_PASSWORDLESS=hmc_ssh_passwordless,
                HMC_SSH_MAX_RETRIES=hmc_ssh_max_retries,
                HMC_HTTP_PORT=hmc_http_port,
                HMC_HTTPS_PORT=hmc_https_port,
                HMC_USE_HTTPS=hmc_use_https,
                # SSH Proxy Configuration
                **trust_cli_values,
                **proxy_cli_values,
            )

            # Convert to dictionary format expected by DUTManager. Carry the
            # model's own source-presence metadata so the runtime merge can
            # still tell an operator-supplied override from a materialized
            # DUTConfig default; a plain dump would make every field look
            # explicit and clobber the tool-wide configuration.
            dut_configs = {
                "DUT_Defaults": {},
                "dut-1": {
                    **dut_config_obj.model_dump(),
                    "__explicit_fields": sorted(dut_config_obj.model_fields_set),
                },
            }
            warning_dut_configs = [dut_config_obj]
        else:
            # Load DUT configs from file
            if not dut_config:
                # Try auto-detection like the collect command does
                from .utils.resources import find_all_config_files

                if not json_output:
                    self.sanitized_console.print_info(
                        "No DUT config file provided - attempting auto-detection..."
                    )

                # Auto-detect configuration files in the same directory as the executable
                auto_dut_config, auto_config, auto_tool_config = find_all_config_files()

                if auto_dut_config:
                    dut_config = auto_dut_config
                    if not json_output:
                        self.sanitized_console.print_info(
                            f"Auto-detected DUT config file: {dut_config}"
                        )
                else:
                    self._print_command_error(
                        "Auto-detection did not find dut_config.yaml in executable directory. "
                        "Please provide one of the following:\n"
                        "  • --dut-config <file> - Use a DUT configuration file\n"
                        "  • --local - Run in local mode (no remote access needed)\n"
                        "  • BMC credentials - Provide --bmc-ip and --bmc-user, "
                        "then set NVDEBUG_BMC_PASSWORD or use a protected config file\n"
                        "  • Host credentials - Provide --host-ip and --host-user, "
                        "then set NVDEBUG_HOST_PASSWORD or use a protected config file",
                        json_output=json_output,
                    )
                    raise SystemExit(2)

            # Load DUT configs (same as collect command)
            try:
                dut_configs = load_dut_config(dut_config, quiet_mode=json_output)
                warning_dut_configs = dut_configs
                if not json_output:
                    self.sanitized_console.print_success(
                        f"Loaded DUT config from: {dut_config}"
                    )
            except Exception as e:
                if json_output:
                    self._print_command_error(
                        f"Error loading DUT config file: {e}",
                        json_output=True,
                    )
                else:
                    # For regular output, use pretty formatted error
                    display_dut_config_error(str(e))
                raise SystemExit(2) from e

        if isinstance(dut_configs, list) and not dut_configs:
            self._print_command_error(
                "Selected DUT configuration defines no DUTs.",
                json_output=json_output,
            )
            raise SystemExit(2)

        if config_mode and isinstance(dut_configs, list) and resolved_tool_config:
            # Preflight must describe the transport the collection run will
            # actually use. Reuse collect's projection helper so the tool-wide
            # ssh_proxy holder lands below the CLI overlay applied next, rather
            # than duplicating precedence logic that could drift apart.
            project_tool_ssh_proxy_defaults(
                resolved_tool_config,
                dut_configs,
                explicit_cli_params or set(),
                cli_mode=False,
            )

        if config_mode:
            try:
                dut_configs = _bind_preflight_config_overlays(
                    dut_configs,
                    bmc_pass=bmc_pass,
                    bmc_ssh_pass=bmc_ssh_pass,
                    bmc_rf_pass=bmc_rf_pass,
                    host_pass=host_pass,
                    hmc_pass=hmc_pass,
                    hmc_ssh_pass=hmc_ssh_pass,
                    ssh_proxy_host=ssh_proxy_host,
                    ssh_proxy_port=ssh_proxy_port,
                    ssh_proxy_user=ssh_proxy_user,
                    ssh_proxy_pass=ssh_proxy_pass,
                    ssh_proxy_key_path=ssh_proxy_key_path,
                    ssh_proxy_passwordless=ssh_proxy_passwordless,
                    ssh_proxy_max_retries=ssh_proxy_max_retries,
                    bmc_rf_verify_ssl=bmc_rf_verify_ssl,
                    ssh_host_key_policy=ssh_host_key_policy,
                    ssh_known_hosts_file=ssh_known_hosts_file,
                )
                warning_dut_configs = dut_configs
            except ValueError as error:
                self._print_command_error(
                    str(error),
                    json_output=json_output,
                    title="Conflicting DUT Options",
                )
                raise SystemExit(2) from error

        sanitizer_config = (
            {dut.name: dut.model_dump() for dut in dut_configs}
            if isinstance(dut_configs, list)
            else dut_configs
        )
        supplied_secret_values = normalize_sensitive_canary_values(
            [
                bmc_pass,
                bmc_ssh_pass,
                bmc_rf_pass,
                host_pass,
                hmc_pass,
                hmc_ssh_pass,
                ssh_proxy_pass,
            ]
        )
        self.sanitizer = create_sanitizer_from_config(
            sanitizer_config,
            enabled=True,
            extra_strings=supplied_secret_values,
        )
        self.sanitized_console = create_sanitized_console(self.sanitizer)

        self._display_ssh_host_key_policy_warning(
            warning_dut_configs,
            json_output=json_output,
        )

        # Create tool config specifically for preflight (no spreadsheet needed)
        # Create tool config specifically for preflight (use same logic as collect command)
        # Auto-detect spreadsheet if not provided
        if spreadsheet:
            spreadsheet = Path(spreadsheet)
        else:
            # Try to auto-detect spreadsheet like the collect command does
            spreadsheet = self._auto_detect_spreadsheet()

        # Use the same configuration logic as the collect command
        # For JSON output, use quiet mode to suppress initialization messages
        # For non-JSON output, use full mode to get DUT manager
        tool_config_obj = self._create_tool_config_object(
            spreadsheet=spreadsheet,
            quiet_mode=json_output,
            config_file=config_file,
        )

        # The SSH half of the transport posture is disclosed above. Disclose the
        # Redfish half here, once the tool configuration that supplies the
        # lower-precedence TLS policy has been resolved.
        self._display_redfish_tls_policy_warning(
            warning_dut_configs if isinstance(warning_dut_configs, list) else [],
            tool_config_obj,
            json_output=json_output,
        )

        # Preflight command should skip HTML reports and zip generation
        tool_config_obj["skip_html_reports"] = True
        tool_config_obj["skip_zip"] = True
        tool_config_obj["skip_zip_split"] = True

        # Create log directory
        log_dir = Path("logs/preflight")
        log_dir.mkdir(parents=True, exist_ok=True)

        # Create orchestrator using the newer pattern
        try:
            orchestrator = WorkflowOrchestrator(
                tool_config=tool_config_obj,
                dut_configs=dut_configs,
                log_dir=str(log_dir),
                sanitized_console=self.sanitized_console,
                quiet_mode=json_output,  # Use quiet mode for JSON output to suppress messages
                catalog_only_mode=False,
            )
            self.orchestrator = orchestrator

            # Set sanitizer in orchestrator (required for engine initialization)
            orchestrator.set_sanitizer(self.sanitizer)

        except Exception:
            raise

        # Initialize orchestrator
        try:
            await orchestrator.initialize()

        except Exception:
            raise

        # Run preflight checks (suppress progress bar for JSON output)
        show_progress = not json_output
        results = await orchestrator.run_preflight_checks(show_progress=show_progress)

        # A top-level error is an infrastructure/runtime failure, not a
        # per-DUT preflight result.  Stop before dependency checks while still
        # releasing the initialized orchestrator.
        if isinstance(results, dict) and "error" in results:
            error_message = str(results["error"])
            raise RuntimeError(error_message)

        # Compute per-DUT filtered collectors so dependency checks are scoped
        # to each DUT's applicable collectors (baseboard/skip/include/exclude).
        all_collectors = orchestrator.get_all_collectors()
        all_collector_ids = list(all_collectors.keys())
        dut_ids = orchestrator.dut_manager.get_all_dut_ids()
        filtered_collectors_per_dut = await self._get_preflight_collectors_per_dut(
            orchestrator, all_collector_ids, dut_ids
        )
        filtered_collector_ids = list(
            {cid for cids in filtered_collectors_per_dut.values() for cid in cids}
        )

        # Run dependency checks scoped per-DUT with preflight service filtering
        dependency_results = await orchestrator.run_dependency_checks(
            collector_ids=filtered_collector_ids,
            preflight_results=results,
            filtered_collectors_per_dut=filtered_collectors_per_dut,
        )
        if not json_output:
            await orchestrator.reporting_engine.log_dependency_check_table(
                dependency_results
            )

        # Handle output - only use CLI output handling for JSON output or file output
        # The orchestrator already displays the table results to console for non-JSON output
        if json_output or output_file:
            # Use shared output handling for JSON output or file output
            if results and len(results) > 0:
                self._handle_output(
                    results,
                    json_output=json_output,
                    output_file=output_file,
                    output_type="preflight",
                )
            else:
                if json_output:
                    # Output empty JSON
                    self._handle_output(
                        {},
                        json_output=True,
                        output_file=output_file,
                        output_type="preflight",
                    )
                else:
                    # Write empty result to file
                    self._handle_output(
                        {},
                        json_output=False,
                        output_file=output_file,
                        output_type="preflight",
                    )
        else:
            # For non-JSON console output, the orchestrator already displayed the results
            # Only show a message if there are no results
            if not results or len(results) == 0:
                self.sanitized_console.print_warning("No preflight results to display")

        # Emit every structured or human-readable result before setting the
        # process outcome. A failed required transport must not look successful
        # to automation merely because the check completed without an exception.
        required_transport_names = {"ipmi", "redfish", "ssh"}
        preflight_failed = False
        for dut_result in results.values():
            if not isinstance(dut_result, dict):
                continue
            if dut_result.get("overall_status") == "fail":
                preflight_failed = True
                break
            services = dut_result.get("services", {})
            if isinstance(services, dict) and any(
                service_name in required_transport_names
                and isinstance(service_result, dict)
                and service_result.get("status") == "fail"
                for service_name, service_result in services.items()
            ):
                preflight_failed = True
                break

        if preflight_failed:
            raise SystemExit(1)

    def _auto_detect_spreadsheet(self) -> Optional[Path]:
        """
        Auto-detect the latest Telemetry Catalog spreadsheet in config directory.

        After applying local validation, the function forwards current instance
        state to ``auto_detect_spreadsheet`` and preserves its return and
        exception contract.

        Returns:
            The validated auto detect spreadsheet filesystem path, or ``None``
            when the requested value is unavailable.
        """
        return auto_detect_spreadsheet(None, suppress_print=True)
