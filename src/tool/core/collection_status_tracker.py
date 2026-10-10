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
Collection Status Tracker.

This module provides real-time tracking of collector execution status across
multiple DUTs with in-memory state management and persistent file storage for
status information.
"""

import asyncio
import copy
import errno
import hashlib
import json
import math
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, NoReturn, Optional, Set, Tuple

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from ..utils.artifact_paths import (
    normalize_artifact_file_list,
    normalize_timing_artifact_paths,
    run_tree_dut_component,
)
from ..utils.collector_attempt_policy import (
    project_additive_attempts,
    project_attempt_policy,
)
from ..utils.filesystem_identity import directory_security_identity
from ..utils.managed_filesystem import run_managed_filesystem_operation
from ..utils.run_limits import (
    MAX_COLLECTOR_ID_BYTES,
    MAX_COLLECTORS_PER_RUN,
    MAX_DUT_ID_BYTES,
    MAX_DUTS,
    MAX_SNAPSHOT_CANDIDATE_ENTRIES,
    MAX_SNAPSHOT_ROOT_ENTRIES,
    MAX_TRACKED_COLLECTOR_RECORDS,
    is_printable_identity,
    snapshot_directory_scan_budget_seconds,
)
from ..utils.status_snapshot import (
    MAX_DUT_STATUS_BYTES,
    MAX_ROOT_STATUS_BYTES,
    MAX_SUMMARY_BYTES,
    MAX_TIMING_BYTES,
    validate_terminal_snapshot_tree,
)
from .collector_outcome import (
    extract_collector_outcome_details,
    is_valid_not_applicable_skip,
    normalize_collector_failure_category,
    sanitize_terminal_collector_reason,
)
from .finalization_receipt import (
    CapturedAwaitableOutcome,
    FinalizationFailure,
    FinalizationOutcomeHint,
    FinalizationReceipt,
    FinalizationReceiptCancelledError,
    FinalizationReceiptError,
    FrozenCollectorStatus,
    SnapshotLeafDigest,
    attach_finalization_receipt,
    capture_owned_awaitable,
    drain_owned_tasks,
    is_control_flow_exception,
    is_interruption_exception,
    sanitize_finalization_failure,
    sanitize_finalization_message,
    select_authoritative_exception,
    validate_structural_finalization_receipt,
)
from .run_result import (
    EXPLICIT_SELECTION_EVIDENCE_PATH,
    EXPLICIT_SELECTION_FAILURE_TYPES,
    CollectionStatus,
    RunMode,
    RunResult,
    normalize_run_outcome_reason,
    project_legacy_run_outcome,
)

# Collector events are frequent and may arrive concurrently for every DUT.  In a
# rack-sized run, rewriting the run-wide JSON/text files and every DUT's files on
# each event creates quadratic write amplification.  Keep per-DUT status current,
# but only refresh the aggregate view periodically.  Both values can be tuned for
# unusually slow/fast storage without changing the collection configuration.
AGGREGATE_STATUS_SNAPSHOT_INTERVAL_SECONDS = 30.0
INCREMENTAL_STATUS_MIN_ENTRIES = 256
AGGREGATE_STATUS_SNAPSHOT_INTERVAL_ENV = "NVDEBUG_STATUS_SNAPSHOT_INTERVAL_SECONDS"
INCREMENTAL_STATUS_MIN_ENTRIES_ENV = "NVDEBUG_STATUS_INCREMENTAL_MIN_ENTRIES"
# Preserve the local performance target and the minimum I/O budget. Large NFS
# runs receive additional time for each validated DUT's status, summary, timing,
# and RunResult leaves, including durable publication and rollback metadata.
SNAPSHOT_PUBLICATION_DEADLINE_SECONDS = 180.0
SNAPSHOT_PUBLICATION_SECONDS_PER_DUT = 30.0
MAX_ROOT_METADATA_BYTES = 16 * 1024 * 1024

# ``None`` is an explicit final category correction. A separate sentinel lets
# detail-only duplicate completions omit the field without erasing the category
# already recorded by the service/result authority boundary.
_FAILURE_CATEGORY_UNSET = object()

# Persist only bounded counts from collector context. Raw context can contain
# recursive service objects and target URIs, neither of which belongs in the
# portable collection-status contract.
_SCOPE_CONTEXT_FIELDS = (
    "filtered_systems",
    "entities_processed",
    "collections_processed",
    "successful_collections",
    "partial_collections",
    "failed_collections",
)

_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


def _open_relative_directory(
    root_descriptor: int,
    components: Tuple[str, ...],
    *,
    create: bool,
) -> int:
    """
    Open a directory chain without resolving any symbolic-link component.

    The implementation uses ``root_descriptor``, ``components``, and ``create``
    to open a directory chain without resolving any symbolic-link component. If
    the function cannot open a directory chain without resolving any
    symbolic-link component, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        root_descriptor: Numeric root descriptor used while the operation
            performs bounded accounting.
        components: Entries supplied as ``components`` without transferring
            container ownership.
        create: Whether create is enabled or required for this operation.

    Returns:
        The validated ``descriptor``.

    Raises:
        RuntimeError: If invalid status publication directory component.
    """

    descriptor = os.dup(root_descriptor)
    try:
        for component in components:
            if not component or component in {".", ".."} or "/" in component:
                raise RuntimeError("Invalid status publication directory component")
            try:
                child_descriptor = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, mode=0o755, dir_fd=descriptor)
                child_descriptor = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
            os.close(descriptor)
            descriptor = child_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class CollectorStatus(Enum):
    """
    Enumeration of collector status states.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    DEGRADED = "degraded"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    NOT_RAN = "not_ran"


class _TrackerLifecycle(Enum):
    """
    One-way setup states for the in-memory collection plan.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    NEW = "new"
    DECLARED = "declared"
    BOUND = "bound"
    FROZEN = "frozen"
    FINALIZED = "finalized"
    PLANNING_FINALIZED = "planning_finalized"


class _SnapshotCommitPhase(Enum):
    """
    Explicit root-marker commit state for one tracker instance.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    IDLE = "idle"
    RENDERING = "rendering"
    ROOT_RENAMED = "root_renamed"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True)
class _PublicationResult:
    """
    Outcome after the root-marker commit point has been resolved.

    The immutable record keeps ``generation``, ``terminal``,
    ``post_commit_control_flow``, and ``candidate_cleanup_error`` together so
    consumers observe one publication state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        generation: Canonical text used as generation.
        terminal: Whether terminal applies to this record.
        post_commit_control_flow: Post commit control flow retained as part of
            the record's public state.
        candidate_cleanup_error: Candidate cleanup error retained as part of the
            record's public state.
    """

    generation: str
    terminal: bool
    post_commit_control_flow: Optional[BaseException] = None
    candidate_cleanup_error: Optional[BaseException] = None


@dataclass(frozen=True)
class _CollectorIdentity:
    """
    Exact identity used for all in-memory collector mutations.

    The immutable record keeps ``dut_id`` and ``collector_id`` together so
    consumers observe one collector identity state. Consumers receive the fields
    as one unit instead of assembling partial state.

    Attributes:
        dut_id: Canonical text used as DUT identifier.
        collector_id: Canonical text used as collector identifier.
    """

    dut_id: str
    collector_id: str

    @property
    def legacy_key(self) -> str:
        """
        Return the historical key retained at serialization boundaries.

        Each access computes the value from ``collector_id`` and ``dut_id`` on
        the current instance; the derived view is not stored as independent
        state.

        Returns:
            The canonical legacy key text.
        """

        return f"{self.dut_id}:{self.collector_id}"


@dataclass
class CollectorStatusEntry:
    """
    Data class for collector status entry.

    The coherent record keeps ``dut_id``, ``collector_id``, ``collector_name``,
    ``group``, and ``level`` together so consumers observe one collector status
    entry state. Construction validates cross-field invariants before the
    instance is exposed.

    Attributes:
        dut_id: Canonical text used as DUT identifier.
        collector_id: Canonical text used as collector identifier.
        collector_name: Canonical text used as collector name.
        group: Canonical text used as group.
        level: Canonical text used as level.
        status: Canonical status exposed to downstream status consumers.
        start_time: Start time retained as part of the record's public state.
        end_time: End time retained as part of the record's public state.
        execution_time: Numeric execution time retained by this record.
        timeout: Numeric timeout retained by this record.
        reason: Canonical reason exposed to downstream status consumers.
        exclusion_type: Canonical text used as exclusion type.
        output_files: Collection of output files entries retained by this
            record.
        diagnostic_files: Collection of diagnostic files entries retained by
            this record.
        error_files: Collection of error files entries retained by this record.
        all_files: Collection of all files entries retained by this record.
        discovered_files: Mapping that retains the discovered files fields for
            this record.
        context: Mapping that retains the context fields for this record.
        failure_category: Canonical text used as failure category.
    """

    dut_id: str
    collector_id: str
    collector_name: str
    group: str
    level: str
    status: CollectorStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    execution_time: float = 0.0
    timeout: Optional[int] = None
    reason: str = ""
    # Explicit classification for work removed from the execution plan before
    # it started (for example ``baseboard``, ``capability``, or ``config``).
    # A missing start_time is not sufficient: preflight failures also skip
    # before start_collector(), but remain runtime outcomes in the report.
    exclusion_type: Optional[str] = None
    output_files: List[str] = None
    diagnostic_files: List[str] = None
    error_files: List[str] = None
    all_files: List[str] = None
    discovered_files: Dict[str, List[str]] = None
    context: Dict[str, Any] = None
    failure_category: Optional[str] = None

    def __post_init__(self):
        """
        Initialize default values for optional fields after dataclass creation.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers.
        """
        if self.output_files is None:
            self.output_files = []
        if self.diagnostic_files is None:
            self.diagnostic_files = []
        if self.error_files is None:
            self.error_files = []
        if self.all_files is None:
            self.all_files = []
        if self.discovered_files is None:
            self.discovered_files = {}
        if self.context is None:
            self.context = {}

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert collector status entry to dictionary for JSON serialization.

        Manually create dict to avoid recursion issues with complex context
        objects.

        Returns:
            The validated ``data``.
        """
        is_excluded = bool(self.exclusion_type)
        # Manually create dict to avoid recursion issues with complex context objects
        data = {
            "dut_id": self.dut_id,
            "collector_id": self.collector_id,
            "collector_name": self.collector_name,
            "group": self.group,
            "level": self.level,
            "status": self.status.value,
            "start_time": (
                self.start_time.isoformat()
                if self.start_time and not is_excluded
                else None
            ),
            "end_time": (
                self.end_time.isoformat() if self.end_time and not is_excluded else None
            ),
            "execution_time": 0.0 if is_excluded else self.execution_time,
            "timeout": self.timeout,
            "reason": self.reason,
            "failure_category": self.failure_category,
            "exclusion_type": self.exclusion_type,
            "output_files": (
                self.output_files[:] if self.output_files else []
            ),  # shallow copy
            "diagnostic_files": (
                self.diagnostic_files[:] if self.diagnostic_files else []
            ),
            "error_files": self.error_files[:] if self.error_files else [],
            "all_files": self.all_files[:] if self.all_files else [],
            "discovered_files": (
                dict(self.discovered_files) if self.discovered_files else {}
            ),  # shallow copy
            # Exclude context to prevent recursion - it can contain complex objects
            # "context": self.context,  # Skip this to avoid recursion
        }
        attempt_policy = self.context.get("attempt_policy")
        if attempt_policy is not None:
            data["attempt_policy"] = project_attempt_policy(attempt_policy)
        additive_attempts = self.context.get("additive_attempts")
        if additive_attempts is not None:
            projected_additive_attempts = project_additive_attempts(additive_attempts)
            if projected_additive_attempts:
                data["additive_attempts"] = projected_additive_attempts
        outcome_details = extract_collector_outcome_details(self.context)
        if (
            self.status
            in {
                CollectorStatus.DEGRADED,
                CollectorStatus.PARTIAL,
                CollectorStatus.ERROR,
            }
            and outcome_details is not None
        ):
            data["outcome_details"] = outcome_details
            if data["failure_category"] is None:
                data["failure_category"] = outcome_details["category"]
        return data


class CollectionStatusTracker:
    """
    Tracks collection status across multiple DUTs with async-safe operations.

    Manages real-time status tracking, file storage, and statistics aggregation
    for collector execution across multiple DUTs.
    """

    def __init__(
        self,
        output_dir: Path,
        console: Optional[Console] = None,
        logger=None,
        timing_manager=None,
    ):
        """
        Initialize a ``CollectionStatusTracker`` instance.

        The initializer records ``_aggregate_snapshot_interval_seconds``,
        ``_bound_plan_signature``, ``_candidate_backed_up_leaves``,
        ``_candidate_directory_removed``, and ``_candidate_fd`` for later
        operations and establishes the instance invariants before any public
        method runs. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle. If the function cannot
        initialize a ``CollectionStatusTracker`` instance, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            output_dir: filesystem location used as the output dir for this
                operation.
            console: Optional console; ``None`` selects the function's default
                behavior.
            logger: Sanitized logger used for operator-visible diagnostics.
            timing_manager: Optional timing manager; ``None`` selects the
                function's default behavior.

        Raises:
            ValueError: If collection output must not be the filesystem root.
        """
        self.output_dir = Path(output_dir).absolute()
        self.logger = logger
        self.timing_manager = timing_manager
        if self.output_dir == Path(os.sep):
            raise ValueError("Collection output must not be the filesystem root")
        self._output_root_fd = os.open(self.output_dir, _DIRECTORY_OPEN_FLAGS)
        self._output_root_identity = self._directory_identity(self._output_root_fd)
        self._publication_parent_identities: Dict[Path, Tuple[int, int]] = {}
        self._candidate_name: Optional[str] = None
        self._candidate_fd: Optional[int] = None
        self._candidate_directory_removed = False
        self._candidate_leaves: Set[Path] = set()
        self._candidate_leaf_digests: Dict[Path, SnapshotLeafDigest] = {}
        self._candidate_moved_leaves: Set[Path] = set()
        self._candidate_backed_up_leaves: Set[Path] = set()
        self._candidate_publication_committed = False
        self._candidate_prior_snapshot: Optional[
            Tuple[Optional[str], bool, _SnapshotCommitPhase]
        ] = None
        self._snapshot_generation: Optional[str] = None
        self._snapshot_terminal = False
        self._snapshot_commit_phase = _SnapshotCommitPhase.IDLE
        self._snapshot_leaf_digests: Tuple[SnapshotLeafDigest, ...] = ()
        self._render_snapshot_generation: Optional[str] = None
        self._render_snapshot_terminal = False
        self._publication_deadline: Optional[float] = None
        self._terminal_commit_diagnostics: List[str] = []
        self._outcome_intent = FinalizationOutcomeHint()
        self.run_outcome: Dict[str, Any] = self._outcome_intent.to_legacy_run_outcome()
        self.run_result: Optional[RunResult] = None

        # Ensure we have a valid Rich Console
        if console is not None and hasattr(console, "print"):
            self.console = console
        else:
            # Create a new console if the provided one is invalid
            try:
                self.console = Console()
            except Exception:
                # Fallback to a minimal console if Rich is not available
                self.console = None

        # Global status files (in root .metadata directory)
        self.metadata_dir = self.output_dir / ".metadata"
        self.global_status_file = self.metadata_dir / "collection_status.json"
        self.global_summary_file = self.metadata_dir / "collection_status_summary.txt"
        self.global_run_result_file = self.metadata_dir / "run_result.json"
        self.global_metadata_file = self.metadata_dir / "metadata.json"
        self._register_publication_parent(self.global_status_file)
        self._register_publication_parent(self.global_run_result_file)

        # DUT-specific status files (will be created per DUT)
        self.dut_status_files: Dict[str, Path] = {}  # dut_id -> status file path
        self.dut_summary_files: Dict[str, Path] = {}  # dut_id -> summary file path
        self.dut_run_result_files: Dict[str, Path] = {}

        # In-memory state
        # ``collector_statuses`` preserves the historical string-keyed view used
        # by status JSON and a small number of integrations.  Lifecycle
        # mutations never consult that composed key: the typed map below is the
        # authoritative in-memory identity index.
        self.collector_statuses: Dict[str, CollectorStatusEntry] = {}
        self._collector_statuses_by_identity: Dict[
            _CollectorIdentity, CollectorStatusEntry
        ] = {}
        self.dut_collectors: Dict[str, Set[str]] = {}  # DUT -> set of collector IDs
        self.collector_groups: Dict[str, Set[str]] = {}  # group -> set of collector IDs

        # Statistics
        self.stats = {
            "total_collectors": 0,
            "pending_collectors": 0,
            "running_collectors": 0,
            "completed_collectors": 0,
            "degraded_collectors": 0,
            "partial_collectors": 0,
            "failed_collectors": 0,
            "skipped_collectors": 0,
            "cancelled_collectors": 0,
            "baseboard_excluded": 0,
            "capability_excluded": 0,
            "config_excluded": 0,
        }

        # File lock for async-safe operations
        self._file_lock = asyncio.Lock()
        # Serialize publications. Rack progress has one owned, coalescing writer;
        # terminal publication joins it before changing the snapshot generation.
        self._status_update_lock = asyncio.Lock()
        self._deferred_progress_enabled = False
        self._pending_progress_duts: Set[str] = set()
        self._progress_full_snapshot_pending = False
        self._progress_task: Optional[asyncio.Task[CapturedAwaitableOutcome]] = None
        # Keep lifecycle mutations and their snapshots atomic with finalization.
        # Once finalization begins, late collector callbacks are ignored so they
        # cannot rewrite the terminal report state.
        self._lifecycle_lock = asyncio.Lock()
        self._finalized = False
        self._lifecycle_state = _TrackerLifecycle.NEW
        self._declared_dut_ids: Optional[Tuple[str, ...]] = None
        self._bound_plan_signature: Optional[Tuple[Any, ...]] = None
        self._finalization_interrupted = False
        self._finalization_receipt: Optional[FinalizationReceipt] = None
        self._finalization_diagnostic_failures: List[FinalizationFailure] = []
        self._nonfatal_finalization_diagnostics: List[FinalizationFailure] = []

        try:
            configured_interval = float(
                os.getenv(
                    AGGREGATE_STATUS_SNAPSHOT_INTERVAL_ENV,
                    str(AGGREGATE_STATUS_SNAPSHOT_INTERVAL_SECONDS),
                )
            )
        except (TypeError, ValueError):
            configured_interval = AGGREGATE_STATUS_SNAPSHOT_INTERVAL_SECONDS
        if not math.isfinite(configured_interval):
            configured_interval = AGGREGATE_STATUS_SNAPSHOT_INTERVAL_SECONDS
        self._aggregate_snapshot_interval_seconds = max(configured_interval, 0.0)

        try:
            configured_min_entries = int(
                os.getenv(
                    INCREMENTAL_STATUS_MIN_ENTRIES_ENV,
                    str(INCREMENTAL_STATUS_MIN_ENTRIES),
                )
            )
        except (TypeError, ValueError):
            configured_min_entries = INCREMENTAL_STATUS_MIN_ENTRIES
        self._incremental_status_min_entries = max(configured_min_entries, 1)
        self._last_aggregate_snapshot_at: Optional[float] = None

        # Live display
        self._live_display: Optional[Live] = None
        self._display_enabled = False

    def _sanitize_run_outcome_reason(self, value: Any) -> str:
        """
        Return one bounded, printable diagnostic without rewriting IDs.

        After applying local validation, the function forwards ``value`` to
        ``sanitize_finalization_message`` and preserves its return and exception
        contract.

        Args:
            value: Value evaluated while performing one bounded, printable
                diagnostic without rewriting IDs.

        Returns:
            The canonical run outcome reason text.
        """

        sanitizer = getattr(self.logger, "sanitizer", None)
        sanitize = getattr(sanitizer, "sanitize", None)
        return sanitize_finalization_message(
            value,
            sanitizer=sanitize if callable(sanitize) else None,
        )

    @staticmethod
    def _canonicalize_affected_duts(values: Any) -> List[str]:
        """
        Preserve bounded DUT identities while removing duplicates.

        The implementation uses ``values`` to preserve bounded DUT identities
        while removing duplicates.

        Args:
            values: Entries supplied as ``values`` and processed in
                caller-provided order.

        Returns:
            The affected duts returned in operation-defined order.
        """

        if not isinstance(values, (list, tuple, set)):
            return []
        normalized: List[str] = []
        for value in values:
            text = str(value)[:256]
            if not text or any(ord(character) < 32 for character in text):
                continue
            if text not in normalized:
                normalized.append(text)
            if len(normalized) == 1024:
                break
        return normalized

    def _relative_publication_path(self, destination: Path) -> Path:
        """
        Return a lexical path below the pinned collection root.

        The implementation uses ``destination`` to produce a lexical path below
        the pinned collection root. If the function cannot produce a lexical
        path below the pinned collection root, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            destination: filesystem location used as the destination for this
                operation.

        Returns:
            The validated ``relative``.

        Raises:
            RuntimeError: If status publication escaped the collection root; or
                invalid status publication path.
        """

        try:
            relative = Path(destination).absolute().relative_to(self.output_dir)
        except ValueError as error:
            raise RuntimeError(
                "Status publication escaped the collection root"
            ) from error
        if not relative.parts or any(
            part in {"", ".", ".."} for part in relative.parts
        ):
            raise RuntimeError("Invalid status publication path")
        return relative

    @staticmethod
    def _directory_identity(descriptor: int) -> Tuple[int, int, int, int, int]:
        """
        Return the directory identity.

        The implementation uses ``descriptor`` to produce the directory
        identity.

        Args:
            descriptor: Numeric descriptor used while the operation performs
                bounded accounting.

        Returns:
            Device, inode, full mode, owner UID, and owner GID.
        """
        metadata = os.fstat(descriptor)
        return directory_security_identity(metadata)

    def _require_output_root_fd(self) -> int:
        """
        Require output root fd.

        The implementation uses current instance state to require output root
        fd. Every required invariant is checked before a successful value is
        returned; invalid input follows the function's explicit exception path.

        Returns:
            The numeric require output root fd value.

        Raises:
            RuntimeError: If status publication root is closed.
        """
        if self._output_root_fd < 0:
            raise RuntimeError("Status publication root is closed")
        return self._output_root_fd

    def _revalidate_output_root_path(self) -> None:
        """
        Ensure the configured pathname still names the pinned root inode.

        The implementation uses current instance state to ensure the configured
        pathname still names the pinned root inode. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot ensure the configured pathname still names the
        pinned root inode, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Raises:
            RuntimeError: If collection output root pathname changed.
        """

        try:
            visible_descriptor = os.open(
                self.output_dir,
                _DIRECTORY_OPEN_FLAGS,
            )
        except (FileNotFoundError, NotADirectoryError, OSError) as error:
            raise RuntimeError("Collection output root pathname changed") from error
        try:
            if (
                self._directory_identity(visible_descriptor)
                != self._output_root_identity
            ):
                raise RuntimeError("Collection output root pathname changed")
        finally:
            os.close(visible_descriptor)

    def close(self) -> None:
        """
        Release every owned descriptor after publication or explicit abort.

        The implementation uses current instance state to release every owned
        descriptor after publication or explicit abort. It updates
        ``_candidate_fd`` and ``_output_root_fd`` on the instance as part of
        that state transition. If the function cannot release every owned
        descriptor after publication or explicit abort, its exception reaches
        the caller instead of being converted into a successful result.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to release every owned descriptor after publication or
                explicit abort.
        """

        progress_task = getattr(self, "_progress_task", None)
        if progress_task is not None and not progress_task.done():
            raise RuntimeError("Live status publication is pending; await aclose()")
        close_errors: List[BaseException] = []
        if progress_task is not None:
            try:
                outcome = progress_task.result()
                if outcome.error is not None:
                    close_errors.append(outcome.error)
            except BaseException as error:
                close_errors.append(error)
            self._progress_task = None
        candidate_descriptor = getattr(self, "_candidate_fd", None)
        if candidate_descriptor is not None:
            try:
                self._close_descriptor(candidate_descriptor)
            except BaseException as error:
                if self._descriptor_is_definitively_closed(candidate_descriptor):
                    self._candidate_fd = None
                close_errors.append(error)
            else:
                self._candidate_fd = None

        descriptor = getattr(self, "_output_root_fd", -1)
        if descriptor >= 0:
            try:
                self._close_descriptor(descriptor)
            except BaseException as error:
                if self._descriptor_is_definitively_closed(descriptor):
                    self._output_root_fd = -1
                close_errors.append(error)
            else:
                self._output_root_fd = -1

        if close_errors:
            primary_error = close_errors[0]
            for additional_error in close_errors[1:]:
                try:
                    primary_error.add_note(
                        "additional descriptor close failed: "
                        f"{type(additional_error).__name__}"
                    )
                except BaseException:
                    pass
            raise primary_error

    @staticmethod
    def _descriptor_is_definitively_closed(descriptor: int) -> bool:
        """
        Return true only when the kernel reports that the FD is invalid.

        The implementation uses ``descriptor`` to produce true only when the
        kernel reports that the FD is invalid.

        Args:
            descriptor: Numeric descriptor used while the operation performs
                bounded accounting.

        Returns:
            Whether the true only when the kernel reports that the FD is invalid
            operation succeeds.
        """

        try:
            os.fstat(descriptor)
        except OSError as error:
            return error.errno == errno.EBADF
        except BaseException:
            return False
        return False

    @staticmethod
    def _close_descriptor(descriptor: int) -> None:
        """
        Retry an ambiguously interrupted close while preserving its class.

        The implementation uses ``descriptor`` to retry an ambiguously
        interrupted close while preserving its class. If the function cannot
        retry an ambiguously interrupted close while preserving its class, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            descriptor: Numeric descriptor used while the operation performs
                bounded accounting.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to retry an ambiguously interrupted close while
                preserving its class.
        """

        try:
            os.close(descriptor)
        except BaseException as primary_error:
            try:
                os.fstat(descriptor)
            except OSError:
                raise primary_error
            try:
                os.close(descriptor)
            except BaseException as retry_error:
                try:
                    primary_error.add_note(
                        f"descriptor close retry failed: {type(retry_error).__name__}"
                    )
                except BaseException:
                    pass
            raise primary_error

    def __del__(self) -> None:
        """
        Release remaining resources owned by the CollectionStatusTracker.

        The implementation uses current instance state to release remaining
        resources owned by the CollectionStatusTracker.
        """
        try:
            self.close()
        except Exception:
            pass

    def _register_publication_parent(self, destination: Path) -> None:
        """
        Create and pin the identity of one public leaf's parent directory.

        The implementation uses ``destination`` to create and pin the identity
        of one public leaf's parent directory. If the function cannot create and
        pin the identity of one public leaf's parent directory, its exception
        reaches the caller instead of being converted into a successful result.
        Cleanup in the ``finally`` path runs for successful, failed, and
        cancelled execution.

        Args:
            destination: filesystem location used as the destination for this
                operation.

        Raises:
            RuntimeError: If status publication parent identity changed.
        """

        relative = self._relative_publication_path(destination)
        parent = Path(*relative.parts[:-1])
        descriptor = self._open_public_directory(parent, create=True)
        try:
            identity = self._directory_identity(descriptor)
        finally:
            os.close(descriptor)
        existing = self._publication_parent_identities.get(parent)
        if existing is not None and existing != identity:
            raise RuntimeError("Status publication parent identity changed")
        self._publication_parent_identities[parent] = identity

    def _open_public_directory(self, relative: Path, *, create: bool) -> int:
        """
        Open a public directory while revalidating every pinned ancestor.

        The implementation uses ``relative`` and ``create`` to open a public
        directory while revalidating every pinned ancestor. If the function
        cannot open a public directory while revalidating every pinned ancestor,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            relative: filesystem location used as the relative for this
                operation.
            create: Whether create is enabled or required for this operation.

        Returns:
            The validated ``descriptor``.

        Raises:
            RuntimeError: If invalid status publication directory component; or
                status publication parent identity changed.
        """

        self._revalidate_output_root_path()
        descriptor = os.dup(self._require_output_root_fd())
        traversed: List[str] = []
        try:
            for component in relative.parts:
                if not component or component in {".", ".."} or "/" in component:
                    raise RuntimeError("Invalid status publication directory component")
                try:
                    child_descriptor = os.open(
                        component,
                        _DIRECTORY_OPEN_FLAGS,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(component, mode=0o755, dir_fd=descriptor)
                    os.fsync(descriptor)
                    child_descriptor = os.open(
                        component,
                        _DIRECTORY_OPEN_FLAGS,
                        dir_fd=descriptor,
                    )
                traversed.append(component)
                expected = self._publication_parent_identities.get(Path(*traversed))
                if (
                    expected is not None
                    and self._directory_identity(child_descriptor) != expected
                ):
                    os.close(child_descriptor)
                    raise RuntimeError("Status publication parent identity changed")
                os.close(descriptor)
                descriptor = child_descriptor
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _open_publication_parent(self, relative: Path) -> int:
        """
        Open and identity-check a previously registered public parent.

        The implementation uses ``relative`` to open and identity-check a
        previously registered public parent. If the function cannot open and
        identity-check a previously registered public parent, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            relative: filesystem location used as the relative for this
                operation.

        Returns:
            The validated ``descriptor``.

        Raises:
            RuntimeError: If status publication parent was not registered; or
                status publication parent identity changed.
        """

        parent = Path(*relative.parts[:-1])
        expected = self._publication_parent_identities.get(parent)
        if expected is None:
            raise RuntimeError("Status publication parent was not registered")
        descriptor = self._open_public_directory(parent, create=False)
        if self._directory_identity(descriptor) != expected:
            os.close(descriptor)
            raise RuntimeError("Status publication parent identity changed")
        return descriptor

    @staticmethod
    def _serialized_snapshot(document: Any) -> str:
        """
        Return the serialized snapshot.

        The implementation uses ``document`` to produce the serialized snapshot.

        Args:
            document: Document consumed while the function attempts to produce
                the serialized snapshot.

        Returns:
            The canonical serialized snapshot text.
        """
        return document if isinstance(document, str) else json.dumps(document, indent=2)

    @staticmethod
    def _snapshot_io_budget_seconds(dut_count: int) -> float:
        """
        Size publication and candidate cleanup time for a validated DUT roster.

        Each DUT contributes up to four durable leaves and their directory,
        replacement, and rollback operations. Reserve thirty seconds per DUT
        plus one root share, with the existing three-minute minimum for small
        runs. A maximum roster has a finite 15,030-second budget per transaction
        or cleanup attempt. Scanned entries cannot enlarge or reset the budget.

        Args:
            dut_count: Number of DUTs in the immutable, validated run roster.

        Returns:
            Wall-clock seconds available to one publication or cleanup attempt.

        Raises:
            ValueError: If the count is outside the supported integer topology.
        """

        if type(dut_count) is not int or not 0 <= dut_count <= MAX_DUTS:
            raise ValueError("Snapshot DUT count is outside the supported topology")
        return max(
            SNAPSHOT_PUBLICATION_DEADLINE_SECONDS,
            (dut_count + 1) * SNAPSHOT_PUBLICATION_SECONDS_PER_DUT,
        )

    def _check_publication_deadline(self, phase: str) -> None:
        """
        Fail a snapshot attempt before it can run without a time bound.

        The implementation uses ``phase`` to fail a snapshot attempt before it
        can run without a time bound. If the function cannot fail a snapshot
        attempt before it can run without a time bound, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            phase: Text supplied as phase in the format accepted by this
                function.

        Raises:
            TimeoutError: If collection status snapshot exceeded its publication
                deadline during ``phase``.
        """

        deadline = self._publication_deadline
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError(
                "Collection status snapshot exceeded its publication deadline "
                f"during {phase}"
            )

    @staticmethod
    def _snapshot_leaf_limit(relative: Path) -> int:
        """
        Return the reader-compatible maximum for one authoritative leaf.

        The implementation uses ``relative`` to produce the reader-compatible
        maximum for one authoritative leaf. If the function cannot produce the
        reader-compatible maximum for one authoritative leaf, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            relative: filesystem location used as the relative for this
                operation.

        Returns:
            The numeric snapshot leaf limit.

        Raises:
            RuntimeError: If unsupported status snapshot leaf: ``relative``.
        """

        if relative.name == "timing.json":
            return MAX_TIMING_BYTES
        if relative.name == "collection_status_summary.txt":
            return MAX_SUMMARY_BYTES
        if relative.name == "collection_status.json":
            return (
                MAX_ROOT_STATUS_BYTES
                if relative.parts == (".metadata", "collection_status.json")
                else MAX_DUT_STATUS_BYTES
            )
        if relative.name == "run_result.json":
            return 256 * 1024
        if (
            relative.name == "metadata.json"
            and len(relative.parts) >= 2
            and relative.parts[-2] == ".metadata"
        ):
            return MAX_ROOT_METADATA_BYTES
        raise RuntimeError(f"Unsupported status snapshot leaf: {relative}")

    def _read_public_json_document(
        self,
        relative: Path,
        *,
        maximum_bytes: int,
    ) -> Dict[str, Any]:
        """
        Read one bounded regular JSON consumer through the pinned root.

        The implementation uses ``relative`` and ``maximum_bytes`` to read one
        bounded regular JSON consumer through the pinned root. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            relative: filesystem location used as the relative for this
                operation.
            maximum_bytes: Upper bound enforced for bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A mapping containing public JSON document.
        """

        return self._read_public_json_snapshot(
            relative,
            maximum_bytes=maximum_bytes,
        )[1]

    def _read_public_json_snapshot(
        self,
        relative: Path,
        *,
        maximum_bytes: int,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Return exact text and parsed JSON from one stable public leaf.

        The implementation uses ``relative`` and ``maximum_bytes`` to produce
        exact text and parsed JSON from one stable public leaf. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle. If the function cannot produce exact text and parsed
        JSON from one stable public leaf, its exception reaches the caller
        instead of being converted into a successful result. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            relative: filesystem location used as the relative for this
                operation.
            maximum_bytes: Upper bound enforced for bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A tuple containing ``serialized`` and ``document`` in that order.

        Raises:
            RuntimeError: If runResult metadata consumer is not a regular file;
                runResult metadata consumer path changed; runResult metadata
                consumer exceeds its read bound; or runResult metadata consumer
                changed while read; or another input invariant is violated.
        """

        parent_descriptor = self._open_publication_parent(relative)
        descriptor = -1
        try:
            descriptor = os.open(
                relative.name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            before = os.fstat(descriptor)
            path_before = os.stat(
                relative.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError("RunResult metadata consumer is not a regular file")
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if any(
                getattr(before, field) != getattr(path_before, field)
                for field in stable_fields
            ):
                raise RuntimeError("RunResult metadata consumer path changed")
            if before.st_size < 0 or before.st_size > maximum_bytes:
                raise RuntimeError("RunResult metadata consumer exceeds its read bound")
            chunks: List[bytes] = []
            observed = 0
            while True:
                chunk = os.read(
                    descriptor, min(64 * 1024, maximum_bytes + 1 - observed)
                )
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
                if observed > maximum_bytes:
                    raise RuntimeError(
                        "RunResult metadata consumer exceeds its read bound"
                    )
            after = os.fstat(descriptor)
            path_after = os.stat(
                relative.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if observed != before.st_size or any(
                getattr(before, field) != getattr(after, field)
                or getattr(before, field) != getattr(path_after, field)
                for field in stable_fields
            ):
                raise RuntimeError("RunResult metadata consumer changed while read")
            serialized = b"".join(chunks).decode("utf-8")
            document = json.loads(serialized)
            if type(document) is not dict:  # noqa: E721 - subclasses are rejected
                raise RuntimeError("RunResult metadata consumer is not an object")
            return serialized, document
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeError("RunResult metadata consumer is invalid JSON") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_descriptor)

    def _unlink_public_leaf_if_present(self, relative: Path) -> None:
        """
        Durably remove one regular public leaf through its pinned parent.

        The implementation uses ``relative`` to durably remove one regular
        public leaf through its pinned parent. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot durably remove one regular public leaf through
        its pinned parent, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            relative: filesystem location used as the relative for this
                operation.

        Raises:
            RuntimeError: If planning rollback leaf is not a regular file; or
                planning rollback leaf remains visible.
        """

        parent_descriptor = self._open_publication_parent(relative)
        try:
            try:
                metadata = os.stat(
                    relative.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError("Planning rollback leaf is not a regular file")
            os.unlink(relative.name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
            try:
                os.stat(
                    relative.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            raise RuntimeError("Planning rollback leaf remains visible")
        finally:
            os.close(parent_descriptor)

    def project_run_result_metadata(self, result: RunResult) -> None:
        """
        Durably reproject root legacy metadata from exact canonical truth.

        The implementation uses ``result`` to durably reproject root legacy
        metadata from exact canonical truth. If the function cannot durably
        reproject root legacy metadata from exact canonical truth, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            result: Result object whose ``collection_status``,
                ``collector_counts``, ``run_identity``, ``runtime_status``, and
                ``value`` state is read while performing durably reproject root
                legacy metadata from exact canonical truth.

        Raises:
            RuntimeError: If metadata projection lacks the committed RunResult;
                metadata projection lacks a terminal snapshot; root metadata
                lacks lifecycle and summary objects; or root metadata projection
                was not durable.
        """

        if type(result) is not RunResult or result != self.run_result:
            raise RuntimeError("Metadata projection requires the committed RunResult")
        if not self.is_durably_finalized:
            raise RuntimeError("Metadata projection requires a terminal snapshot")

        relative = self._relative_publication_path(self.global_metadata_file)
        document = self._read_public_json_document(
            relative,
            maximum_bytes=MAX_ROOT_METADATA_BYTES,
        )
        lifecycle = document.get("metadata")
        summary = document.get("summary")
        if (
            type(lifecycle) is not dict  # noqa: E721 - subclasses are rejected
            or type(summary) is not dict  # noqa: E721 - subclasses are rejected
        ):  # noqa: E721 - subclasses are rejected
            raise RuntimeError("Root metadata lacks lifecycle and summary objects")

        outcome = project_legacy_run_outcome(
            result,
            domain_hint=self.run_outcome,
        )
        lifecycle["run_outcome"] = outcome
        if result.run_identity is not None:
            identity = result.run_identity
            lifecycle.update(
                {
                    "run_identity": identity.to_dict(),
                    "tool_version": identity.tool_version,
                    "collection_level": identity.resolved_level,
                    "collection_profile": identity.resolved_profile,
                }
            )
        else:
            for field in (
                "run_identity",
                "collection_profile",
            ):
                lifecycle.pop(field, None)
        explicit_selection_failure = bool(
            outcome.get("status") == "domain_failed"
            and outcome.get("failure_type") in EXPLICIT_SELECTION_FAILURE_TYPES
            and outcome.get("evidence") == EXPLICIT_SELECTION_EVIDENCE_PATH
        )
        collector_counts = dict(result.collector_counts)
        if result.runtime_status.value == "failed" or explicit_selection_failure:
            overall_status = "Failed"
        elif result.runtime_status.value == "interrupted":
            overall_status = "Interrupted"
        elif collector_counts.get("failed_collectors", 0) > 0:
            overall_status = "Failed"
        else:
            overall_status = {
                "success": "Passed",
                "partial": "Partial",
                "failed": "Failed",
                "interrupted": "Interrupted",
                "incomplete": "Incomplete",
            }[result.collection_status.value]
        summary["overall_status"] = overall_status

        domain_fields = (
            "domain_failure",
            "domain_failure_type",
            "domain_failure_reason",
            "domain_failure_evidence",
        )
        if outcome["status"] == "domain_failed":
            summary.update(
                {
                    "domain_failure": True,
                    "domain_failure_type": outcome["failure_type"],
                    "domain_failure_reason": outcome["reason"],
                }
            )
            evidence = outcome.get("evidence")
            if evidence:
                summary["domain_failure_evidence"] = evidence
            else:
                summary.pop("domain_failure_evidence", None)
        else:
            for field in domain_fields:
                summary.pop(field, None)

        self._atomic_write_at(
            self._require_output_root_fd(),
            relative,
            document,
            durable=True,
            public=True,
        )
        if (
            self._read_public_json_document(
                relative,
                maximum_bytes=MAX_ROOT_METADATA_BYTES,
            )
            != document
        ):
            raise RuntimeError("Root metadata projection was not durable")

    def _atomic_write_at(
        self,
        root_descriptor: int,
        relative: Path,
        document: Any,
        *,
        durable: bool,
        public: bool,
        terminal_commit: bool = False,
    ) -> bytes:
        """
        Replace one leaf relative to a pinned directory hierarchy.

        The implementation uses ``root_descriptor``, ``relative``, ``document``,
        ``durable``, and ``public`` to replace one leaf relative to a pinned
        directory hierarchy. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot replace one leaf relative to a pinned directory hierarchy, its
        exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Args:
            root_descriptor: Numeric root descriptor used while the operation
                performs bounded accounting.
            relative: filesystem location used as the relative for this
                operation.
            document: Document consumed while the function attempts to replace
                one leaf relative to a pinned directory hierarchy.
            durable: Whether durable is enabled or required for this operation.
            public: Whether public is enabled or required for this operation.
            terminal_commit: Whether terminal commit is enabled or required for
                this operation.

        Returns:
            The validated ``encoded``.

        Raises:
            ValueError: If the a terminal commit marker is not public and
                durable.
            RuntimeError: If the function cannot replace one leaf relative to a
                pinned directory hierarchy safely; status publication leaf is
                not replaceable; or could not allocate status publication leaf.
        """

        if terminal_commit and (not durable or not public):
            raise ValueError("A terminal commit marker must be public and durable")

        self._check_publication_deadline(f"serializing {relative.as_posix()}")
        serialized = self._serialized_snapshot(document)
        encoded = serialized.encode("utf-8")
        encoded_size = len(encoded)
        byte_limit = self._snapshot_leaf_limit(relative)
        if encoded_size > byte_limit:
            raise RuntimeError(
                f"Status snapshot leaf {relative.as_posix()} exceeds its "
                f"{byte_limit}-byte write bound"
            )

        parent_descriptor = (
            self._open_publication_parent(relative)
            if public
            else _open_relative_directory(
                root_descriptor,
                tuple(relative.parts[:-1]),
                create=True,
            )
        )
        destination_name = relative.name
        temporary_name: Optional[str] = None
        descriptor = -1
        replacement_committed = False

        def remember_post_commit_diagnostic(
            phase: str,
            error: BaseException,
        ) -> None:
            """
            Remember post commit diagnostic.

            The implementation uses ``phase`` and ``error`` to remember post
            commit diagnostic. If the function cannot remember post commit
            diagnostic, its exception reaches the caller instead of being
            converted into a successful result.

            Args:
                phase: Text supplied as phase in the format accepted by this
                    function.
                error: Exception or failure detail associated with the
                    operation.

            Raises:
                BaseException: If a delegated failure occurs while the function
                    attempts to remember post commit diagnostic.
            """
            if not terminal_commit or not replacement_committed:
                raise error
            try:
                if len(self._terminal_commit_diagnostics) < 8:
                    self._terminal_commit_diagnostics.append(
                        f"{phase}:{type(error).__name__}"
                    )
            except BaseException:
                pass

        try:
            try:
                destination_metadata = os.stat(
                    destination_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                destination_mode = 0o644
            else:
                if stat.S_ISLNK(destination_metadata.st_mode):
                    destination_mode = 0o644
                elif stat.S_ISREG(destination_metadata.st_mode):
                    destination_mode = (
                        stat.S_IMODE(destination_metadata.st_mode) & 0o666
                    )
                else:
                    raise RuntimeError("Status publication leaf is not replaceable")

            for _ in range(64):
                temporary_name = f".{destination_name}.{secrets.token_hex(12)}.tmp"
                try:
                    descriptor = os.open(
                        temporary_name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        destination_mode,
                        dir_fd=parent_descriptor,
                    )
                    break
                except FileExistsError:
                    continue
            else:
                raise RuntimeError("Could not allocate status publication leaf")

            os.fchmod(descriptor, destination_mode)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(serialized)
                stream.flush()
                if durable:
                    os.fsync(stream.fileno())
            os.replace(
                temporary_name,
                destination_name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            replacement_committed = True
            temporary_name = None
            if durable:
                try:
                    os.fsync(parent_descriptor)
                except BaseException as error:
                    remember_post_commit_diagnostic("parent_fsync", error)
            if public:
                try:
                    confirmation_descriptor = self._open_publication_parent(relative)
                    os.close(confirmation_descriptor)
                except BaseException as error:
                    remember_post_commit_diagnostic("parent_confirmation", error)
            return encoded
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    remember_post_commit_diagnostic("temporary_close", error)
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
                except FileNotFoundError:
                    pass
            try:
                os.close(parent_descriptor)
            except BaseException as error:
                remember_post_commit_diagnostic("parent_close", error)

    def _atomic_write_json_document(
        self,
        path: Path,
        document: Any,
        *,
        durable: bool = False,
    ) -> None:
        """
        Replace one public or candidate leaf through pinned dirfds.

        The implementation uses ``path``, ``document``, and ``durable`` to
        replace one public or candidate leaf through pinned dirfds.

        Args:
            path: filesystem location used as the path for this operation.
            document: Document consumed while the function attempts to replace
                one public or candidate leaf through pinned dirfds.
            durable: Whether durable is enabled or required for this operation.
        """

        relative = self._relative_publication_path(path)
        if self._candidate_fd is None:
            self._atomic_write_at(
                self._output_root_fd,
                relative,
                document,
                durable=durable,
                public=True,
            )
            return
        encoded = self._atomic_write_at(
            self._candidate_fd,
            relative,
            document,
            durable=durable,
            public=False,
        )
        self._candidate_leaves.add(relative)
        self._candidate_leaf_digests[relative] = (
            relative.as_posix(),
            len(encoded),
            hashlib.sha256(encoded).hexdigest(),
        )

    def _write_snapshot_leaf(
        self,
        destination: Path,
        document: Any,
        *,
        durable: bool = False,
    ) -> None:
        """
        Compatibility wrapper for the hardened relative writer.

        The implementation uses ``destination``, ``document``, and ``durable``
        to compatibility wrapper for the hardened relative writer.

        Args:
            destination: filesystem location used as the destination for this
                operation.
            document: Document consumed while the function attempts to
                compatibility wrapper for the hardened relative writer.
            durable: Whether durable is enabled or required for this operation.
        """

        self._atomic_write_json_document(
            destination,
            document,
            durable=durable,
        )

    async def _write_snapshot_leaf_async(
        self,
        destination: Path,
        document: Any,
        *,
        durable: bool = False,
    ) -> None:
        """
        Persist one status leaf without blocking collector or progress tasks.

        Callers retain the existing file/status locks until the bounded worker
        finishes. Cancellation joins that worker before transaction rollback or
        descriptor cleanup can touch its candidate. The synchronous writer
        remains the single implementation of validation and atomic replacement.

        Args:
            destination: Leaf path beneath the pinned collection output root.
            document: Snapshot data prepared while holding the caller's lock.
            durable: Whether this leaf belongs to a durable snapshot transaction.

        Raises:
            BaseException: The writer's failure, or cancellation after its worker
                has stopped and the operation's effects can be reconciled.

        Side Effects:
            Writes one leaf using the shared bounded filesystem worker pool.
        """

        await run_managed_filesystem_operation(
            partial(self._write_snapshot_leaf, destination, document, durable=durable)
        )

    @property
    def is_durably_finalized(self) -> bool:
        """
        Return whether the root commit marker names a terminal generation.

        Each access computes the value from ``_snapshot_commit_phase``,
        ``_snapshot_generation``, and ``_snapshot_terminal`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            Whether the root commit marker names a terminal generation.
        """

        return bool(
            self._snapshot_commit_phase is _SnapshotCommitPhase.COMMITTED
            and self._snapshot_generation
            and self._snapshot_terminal
        )

    @property
    def has_pending_candidate(self) -> bool:
        """
        Return whether candidate cleanup still has explicit ownership.

        Each access computes the value from ``_candidate_fd`` and
        ``_candidate_name`` on the current instance; the derived view is not
        stored as independent state.

        Returns:
            Whether candidate cleanup still has explicit ownership.
        """

        return bool(self._candidate_name is not None or self._candidate_fd is not None)

    def assert_no_candidate_roots(self) -> None:
        """
        Reject owned or orphaned candidates before report/archive publication.

        The implementation uses current instance state to reject owned or
        orphaned candidates before report/archive publication. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle. Cleanup in the ``finally`` path runs for successful, failed,
        and cancelled execution.

        Raises:
            RuntimeError: If collection status candidate cleanup is incomplete;
                collection output root pathname changed; collection output root
                enumeration exceeded its bound; or collection output contains an
                unowned status candidate.
        """

        if self.has_pending_candidate:
            raise RuntimeError("Collection status candidate cleanup is incomplete")
        if self._output_root_fd >= 0:
            descriptor = os.dup(self._output_root_fd)
        else:
            try:
                descriptor = os.open(self.output_dir, _DIRECTORY_OPEN_FLAGS)
            except OSError as error:
                raise RuntimeError("Collection output root pathname changed") from error
            if self._directory_identity(descriptor) != self._output_root_identity:
                os.close(descriptor)
                raise RuntimeError("Collection output root pathname changed")
        deadline = time.monotonic() + snapshot_directory_scan_budget_seconds(
            len(self._declared_dut_ids or ())
        )
        try:
            with os.scandir(descriptor) as entries:
                for entry_count, entry in enumerate(entries, start=1):
                    if (
                        entry_count > MAX_SNAPSHOT_ROOT_ENTRIES
                        or time.monotonic() > deadline
                    ):
                        raise RuntimeError(
                            "Collection output root enumeration exceeded its bound"
                        )
                    if entry.name.startswith(".collection-status-candidate-"):
                        raise RuntimeError(
                            "Collection output contains an unowned status candidate"
                        )
            if time.monotonic() > deadline:
                raise RuntimeError(
                    "Collection output root enumeration exceeded its bound"
                )
        finally:
            os.close(descriptor)

    def validate_durable_snapshot(
        self,
        dut_ids: List[str],
        *,
        _allow_pending_run_result: bool = False,
    ) -> str:
        """
        Re-read every committed leaf before authorizing downstream output.

        After applying local validation, the function forwards ``dut_ids`` and
        ``_allow_pending_run_result`` to ``validate_terminal_snapshot_tree`` and
        preserves its return and exception contract.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            _allow_pending_run_result: Whether allow pending run result is
                enabled or required for this operation.

        Returns:
            The canonical durable snapshot text.

        Raises:
            RuntimeError: If collection status snapshot is not durably
                finalized; or final status validation DUT roster differs from
                the bound run.
        """

        if not self.is_durably_finalized:
            raise RuntimeError("Collection status snapshot is not durably finalized")
        roster = tuple(dut_ids)
        if roster != self._declared_dut_ids:
            raise RuntimeError(
                "Final status validation DUT roster differs from the bound run"
            )
        self.assert_no_candidate_roots()
        return validate_terminal_snapshot_tree(
            self.output_dir,
            roster,
            expected_generation=self._snapshot_generation,
            expected_leaf_digests=self._snapshot_leaf_digests,
            allow_pending_run_result=_allow_pending_run_result,
        )

    def _snapshot_marker(self) -> Tuple[str, bool]:
        """
        Return the snapshot marker.

        The implementation uses current instance state to produce the snapshot
        marker. If the function cannot produce the snapshot marker, its
        exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            A tuple containing ``generation`` and ``terminal`` in that order.

        Raises:
            RuntimeError: If status snapshot generation is unavailable.
        """
        generation = self._render_snapshot_generation or self._snapshot_generation
        terminal = (
            self._render_snapshot_terminal
            if self._render_snapshot_generation is not None
            else self._snapshot_terminal
        )
        if generation is None:
            raise RuntimeError("Status snapshot generation is unavailable")
        return generation, terminal

    def _create_candidate_root(self) -> None:
        """
        Create candidate root.

        The implementation uses current instance state to create candidate root.
        It updates ``_candidate_backed_up_leaves``,
        ``_candidate_directory_removed``, ``_candidate_fd``,
        ``_candidate_leaf_digests``, and ``_candidate_leaves`` on the instance
        as part of that state transition. Filesystem effects remain confined to
        the caller-selected paths and the owning resource lifecycle. If the
        function cannot create candidate root, its exception reaches the caller
        instead of being converted into a successful result.

        Raises:
            RuntimeError: If a status publication candidate is already active;
                or could not allocate status publication candidate.
        """
        if self.has_pending_candidate:
            self.cleanup_pending_candidate()
        if self.has_pending_candidate:
            raise RuntimeError("A status publication candidate is already active")
        self._revalidate_output_root_path()
        output_root_descriptor = self._require_output_root_fd()
        for _ in range(64):
            name = f".collection-status-candidate-{secrets.token_hex(12)}"
            try:
                os.mkdir(name, mode=0o700, dir_fd=output_root_descriptor)
            except FileExistsError:
                continue
            self._candidate_name = name
            self._candidate_directory_removed = False
            self._candidate_leaves = set()
            self._candidate_leaf_digests = {}
            self._candidate_moved_leaves = set()
            self._candidate_backed_up_leaves = set()
            self._candidate_publication_committed = False
            self._candidate_prior_snapshot = None
            try:
                self._candidate_fd = os.open(
                    name,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=output_root_descriptor,
                )
                return
            except BaseException:
                try:
                    self._discard_candidate_root()
                except BaseException as cleanup_error:
                    self._record_finalization_diagnostic(
                        "candidate_cleanup",
                        cleanup_error,
                    )
                raise
        raise RuntimeError("Could not allocate status publication candidate")

    @staticmethod
    def _clear_directory(
        descriptor: int,
        *,
        _remaining: Optional[List[int]] = None,
        _deadline: Optional[float] = None,
    ) -> None:
        """
        Remove one owned candidate tree with shared count and I/O time bounds.

        Cleanup includes network metadata calls, unlinks, and directory removals,
        so its caller supplies the roster-sized publication I/O budget. Direct
        callers without a roster retain the minimum publication budget. The
        shorter root-enumeration budget cannot cover an entire recursive cleanup
        on NFS. Recursive calls share both budgets; neither resets per directory.
        Pinned descriptors and no-follow opens confine deletion to the candidate.

        Args:
            descriptor: Pinned candidate directory descriptor owned by the caller.
            _remaining: Shared remaining entry count, initialized at the root.
            _deadline: Shared absolute monotonic deadline, initialized at the root.

        Raises:
            RuntimeError: If the candidate exceeds its entry limit or cleanup
                deadline. The caller retains ownership for a later cleanup retry.
            OSError: If enumeration or a no-follow filesystem operation fails.

        Side Effects:
            Removes candidate descendants and closes every opened child descriptor.
        """

        remaining = (
            _remaining if _remaining is not None else [MAX_SNAPSHOT_CANDIDATE_ENTRIES]
        )
        deadline = (
            _deadline
            if _deadline is not None
            else time.monotonic() + SNAPSHOT_PUBLICATION_DEADLINE_SECONDS
        )

        def check_deadline() -> None:
            """
            Enforce the shared deadline before and after filesystem work.

            The last unlink or directory removal can consume the remaining time
            even when enumeration has finished. Checking on both sides prevents
            that case from being reported as cleanup within the time budget.

            Raises:
                RuntimeError: If cleanup has exhausted its finite I/O budget.
            """

            if time.monotonic() > deadline:
                raise RuntimeError("Status candidate cleanup exceeded its deadline")

        pending_entries: List[Tuple[str, bool]] = []
        check_deadline()
        with os.scandir(descriptor) as entries:
            for entry in entries:
                remaining[0] -= 1
                if remaining[0] < 0:
                    raise RuntimeError(
                        "Status candidate enumeration exceeded its entry limit "
                        f"({MAX_SNAPSHOT_CANDIDATE_ENTRIES})"
                    )
                check_deadline()
                pending_entries.append(
                    (entry.name, entry.is_dir(follow_symlinks=False))
                )
        for entry_name, is_directory in pending_entries:
            check_deadline()
            if is_directory:
                child = os.open(entry_name, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
                try:
                    CollectionStatusTracker._clear_directory(
                        child,
                        _remaining=remaining,
                        _deadline=deadline,
                    )
                finally:
                    CollectionStatusTracker._close_descriptor(child)
                os.rmdir(entry_name, dir_fd=descriptor)
            else:
                os.unlink(entry_name, dir_fd=descriptor)
        check_deadline()

    def _discard_candidate_root(self) -> None:
        """
        Discard candidate root.

        The implementation uses current instance state to discard candidate
        root. It updates ``_candidate_backed_up_leaves``,
        ``_candidate_directory_removed``, ``_candidate_fd``,
        ``_candidate_leaf_digests``, and ``_candidate_leaves`` on the instance
        as part of that state transition. Filesystem effects remain confined to
        the caller-selected paths and the owning resource lifecycle. If the
        function cannot discard candidate root, its exception reaches the caller
        instead of being converted into a successful result.

        Raises:
            RuntimeError: If status candidate ownership has no directory name;
                the uncommitted status publication is not rolled back before
                cleanup; or status candidate directory identity changed.
            BaseException: If a delegated failure occurs while the function
                attempts to discard candidate root.
        """
        name = self._candidate_name
        descriptor = self._candidate_fd
        observed_remove_error: Optional[BaseException] = None
        if name is None and descriptor is None:
            return
        if name is None:
            raise RuntimeError("Status candidate ownership has no directory name")
        if (
            self._candidate_moved_leaves or self._candidate_backed_up_leaves
        ) and not self._candidate_publication_committed:
            raise RuntimeError(
                "Uncommitted status publication must be rolled back before cleanup"
            )
        if descriptor is None and not self._candidate_directory_removed:
            descriptor = os.open(
                name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=self._require_output_root_fd(),
            )
            self._candidate_fd = descriptor

        if not self._candidate_directory_removed:
            assert descriptor is not None
            identity = self._directory_identity(descriptor)
            self._clear_directory(
                descriptor,
                _deadline=time.monotonic()
                + self._snapshot_io_budget_seconds(len(self._declared_dut_ids or ())),
            )
            os.fsync(descriptor)
            visible = os.stat(
                name,
                dir_fd=self._require_output_root_fd(),
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(visible.st_mode)
                or directory_security_identity(visible) != identity
            ):
                raise RuntimeError("Status candidate directory identity changed")
            try:
                os.rmdir(name, dir_fd=self._require_output_root_fd())
            except BaseException as remove_error:
                try:
                    os.stat(
                        name,
                        dir_fd=self._require_output_root_fd(),
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    self._candidate_directory_removed = True
                    observed_remove_error = remove_error
                else:
                    raise
            else:
                self._candidate_directory_removed = True

        os.fsync(self._require_output_root_fd())
        if descriptor is not None:
            try:
                self._close_descriptor(descriptor)
            except BaseException:
                if self._descriptor_is_definitively_closed(descriptor):
                    self._candidate_fd = None
                else:
                    self._candidate_fd = descriptor
                raise
            else:
                self._candidate_fd = None
        self._candidate_name = None
        self._candidate_directory_removed = False
        self._candidate_leaves = set()
        self._candidate_leaf_digests = {}
        self._candidate_moved_leaves = set()
        self._candidate_backed_up_leaves = set()
        self._candidate_publication_committed = False
        self._candidate_prior_snapshot = None
        if observed_remove_error is not None:
            raise observed_remove_error

    def cleanup_pending_candidate(self) -> None:
        """
        Idempotently finish cleanup retained from an earlier attempt.

        The implementation uses current instance state to idempotently finish
        cleanup retained from an earlier attempt.
        """

        if self.has_pending_candidate and not self._candidate_publication_committed:
            self._rollback_candidate_publication()
            if self._candidate_prior_snapshot is not None:
                (
                    self._snapshot_generation,
                    self._snapshot_terminal,
                    self._snapshot_commit_phase,
                ) = self._candidate_prior_snapshot
        self._discard_candidate_root()
        self.assert_no_candidate_roots()

    def _read_public_root_bytes(self, *, missing_ok: bool) -> Optional[bytes]:
        """
        Read the current root marker through its registered parent dirfd.

        The implementation uses ``missing_ok`` to read the current root marker
        through its registered parent dirfd. Parsing or I/O must finish before
        the validated representation is made available to the caller. If the
        function cannot read the current root marker through its registered
        parent dirfd, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            missing_ok: Whether missing ok is enabled or required for this
                operation.

        Returns:
            The validated ``data``, or ``None`` when no value qualifies.

        Raises:
            RuntimeError: If public status root is not a bounded regular file;
                public status root exceeds its read bound; or public status root
                changed while reading.
        """

        relative = self._relative_publication_path(self.global_status_file)
        parent_descriptor = self._open_publication_parent(relative)
        descriptor: Optional[int] = None
        try:
            try:
                descriptor = os.open(
                    relative.name,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_descriptor,
                )
            except FileNotFoundError:
                if missing_ok:
                    return None
                raise
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size > MAX_ROOT_STATUS_BYTES
            ):
                raise RuntimeError("Public status root is not a bounded regular file")
            chunks: List[bytes] = []
            remaining = MAX_ROOT_STATUS_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > MAX_ROOT_STATUS_BYTES:
                raise RuntimeError("Public status root exceeds its read bound")
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise RuntimeError("Public status root changed while reading")
            return data
        finally:
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                os.close(parent_descriptor)

    @staticmethod
    def _root_bytes_match_generation(
        data: bytes,
        generation: str,
        terminal: bool,
    ) -> bool:
        """
        Return the root bytes match generation.

        The implementation uses ``data``, ``generation``, and ``terminal`` to
        produce the root bytes match generation.

        Args:
            data: Bounded byte sequence supplied as data.
            generation: Text supplied as generation in the format accepted by
                this function.
            terminal: Whether terminal is enabled or required for this
                operation.

        Returns:
            Whether the root bytes match generation operation succeeds.
        """
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return False
        metadata = document.get("metadata") if isinstance(document, dict) else None
        return bool(
            isinstance(metadata, dict)
            and metadata.get("snapshot_generation") == generation
            and metadata.get("terminal_finalized") is terminal
        )

    def _validate_published_generation(
        self,
        generation: str,
        terminal: bool,
        expected_leaf_digests: Tuple[SnapshotLeafDigest, ...],
    ) -> None:
        """
        Adopt only the exact root generation named by this attempt.

        The implementation uses ``generation``, ``terminal``, and
        ``expected_leaf_digests`` to adopt only the exact root generation named
        by this attempt. If the function cannot adopt only the exact root
        generation named by this attempt, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            generation: Text supplied as generation in the format accepted by
                this function.
            terminal: Whether terminal is enabled or required for this
                operation.
            expected_leaf_digests: Entries supplied as ``expected_leaf_digests``
                without transferring container ownership.

        Raises:
            RuntimeError: If published status root differs from the attempted
                generation.
        """

        self._revalidate_output_root_path()
        if terminal:
            validate_terminal_snapshot_tree(
                self.output_dir,
                self._declared_dut_ids or (),
                expected_generation=generation,
                expected_leaf_digests=expected_leaf_digests,
                allow_candidate_directories=True,
                allow_pending_run_result=True,
            )
            return
        current = self._read_public_root_bytes(missing_ok=False)
        assert current is not None
        if not self._root_bytes_match_generation(current, generation, terminal):
            raise RuntimeError(
                "Published status root differs from the attempted generation"
            )

    def _candidate_digest_evidence(self) -> Tuple[SnapshotLeafDigest, ...]:
        """
        Return deterministic exact-byte evidence rendered for this candidate.

        After applying local validation, the function forwards current instance
        state to ``tuple`` and preserves its return and exception contract.

        Returns:
            The candidate digest evidence returned in operation-defined order.
        """

        return tuple(
            self._candidate_leaf_digests[path]
            for path in sorted(
                self._candidate_leaf_digests,
                key=lambda value: value.as_posix(),
            )
        )

    def _record_adopted_snapshot_time(self) -> None:
        """
        Record non-authoritative publication telemetry after state adoption.

        The implementation uses current instance state to record
        non-authoritative publication telemetry after state adoption. It updates
        ``_last_aggregate_snapshot_at`` on the instance as part of that state
        transition.
        """

        self._last_aggregate_snapshot_at = time.monotonic()

    def _restore_prior_root_marker(self, prior_root: Optional[bytes]) -> None:
        """
        Durably restore the marker that preceded an ambiguous root rename.

        The implementation uses ``prior_root`` to durably restore the marker
        that preceded an ambiguous root rename. It updates
        ``_publication_deadline`` and ``_snapshot_commit_phase`` on the instance
        as part of that state transition. Filesystem effects remain confined to
        the caller-selected paths and the owning resource lifecycle. If the
        function cannot durably restore the marker that preceded an ambiguous
        root rename, its exception reaches the caller instead of being converted
        into a successful result. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            prior_root: filesystem location used as the prior root for this
                operation.

        Raises:
            RuntimeError: If prior status root restoration was not durable.
        """

        saved_deadline = self._publication_deadline
        self._publication_deadline = None
        try:
            relative = self._relative_publication_path(self.global_status_file)
            if prior_root is None:
                parent_descriptor = self._open_publication_parent(relative)
                try:
                    try:
                        os.unlink(relative.name, dir_fd=parent_descriptor)
                    except FileNotFoundError:
                        pass
                    os.fsync(parent_descriptor)
                finally:
                    os.close(parent_descriptor)
            else:
                self._atomic_write_at(
                    self._require_output_root_fd(),
                    relative,
                    prior_root.decode("utf-8"),
                    durable=True,
                    public=True,
                )
                confirmation = self._read_public_root_bytes(missing_ok=False)
                if confirmation != prior_root:
                    raise RuntimeError("Prior status root restoration was not durable")
            self._snapshot_commit_phase = _SnapshotCommitPhase.ROLLED_BACK
        finally:
            self._publication_deadline = saved_deadline

    def _resolve_post_root_failure(
        self,
        error: BaseException,
        *,
        generation: str,
        terminal: bool,
        prior_generation: Optional[str],
        prior_terminal: bool,
        prior_phase: _SnapshotCommitPhase,
        candidate_leaf_digests: Tuple[SnapshotLeafDigest, ...],
    ) -> Tuple[bool, Optional[BaseException]]:
        """
        Adopt an exact committed root or durably restore its predecessor.

        A one-shot validation fault may have hidden a valid commit; make one
        final exact adoption attempt before declaring the publication
        irrecoverably ambiguous.

        Args:
            error: Exception or failure detail associated with the operation.
            generation: Text supplied as generation in the format accepted by
                this function.
            terminal: Whether terminal is enabled or required for this
                operation.
            prior_generation: Text supplied as prior generation in the format
                accepted by this function.
            prior_terminal: Whether prior terminal is enabled or required for
                this operation.
            prior_phase: Prior phase consumed while the function attempts to
                adopt an exact committed root or durably restore its
                predecessor.
            candidate_leaf_digests: Entries supplied as
                ``candidate_leaf_digests`` without transferring container
                ownership.

        Returns:
            A tuple containing ``success flag`` and ``observed control flow`` in
            that order.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to adopt an exact committed root or durably restore its
                predecessor.
        """

        observed_control_flow = error if is_control_flow_exception(error) else None
        try:
            self._validate_published_generation(
                generation,
                terminal,
                candidate_leaf_digests,
            )
        except BaseException as validation_error:
            if observed_control_flow is None and is_control_flow_exception(
                validation_error
            ):
                observed_control_flow = validation_error
            try:
                self._rollback_candidate_publication()
            except BaseException as restore_error:
                if observed_control_flow is None and is_control_flow_exception(
                    restore_error
                ):
                    observed_control_flow = restore_error
                # A one-shot validation fault may have hidden a valid commit;
                # make one final exact adoption attempt before declaring the
                # publication irrecoverably ambiguous.
                try:
                    self._validate_published_generation(
                        generation,
                        terminal,
                        candidate_leaf_digests,
                    )
                except BaseException as final_validation_error:
                    if observed_control_flow is None and is_control_flow_exception(
                        final_validation_error
                    ):
                        observed_control_flow = final_validation_error
                    ambiguity = RuntimeError(
                        "Status root commit could be neither adopted nor restored"
                    )
                    ambiguity.add_note(
                        f"validation={type(validation_error).__name__}; "
                        f"restore={type(restore_error).__name__}; "
                        f"final_validation={type(final_validation_error).__name__}"
                    )
                    if observed_control_flow is not None:
                        try:
                            observed_control_flow.add_note(str(ambiguity))
                        except BaseException:
                            pass
                        raise observed_control_flow from ambiguity
                    raise ambiguity from error
                else:
                    self._snapshot_generation = generation
                    self._snapshot_terminal = terminal
                    self._snapshot_leaf_digests = candidate_leaf_digests
                    self._snapshot_commit_phase = _SnapshotCommitPhase.COMMITTED
                    self._candidate_publication_committed = True
                    return True, observed_control_flow
            else:
                self._snapshot_generation = prior_generation
                self._snapshot_terminal = prior_terminal
                self._snapshot_commit_phase = prior_phase
                return False, observed_control_flow
        else:
            self._snapshot_generation = generation
            self._snapshot_terminal = terminal
            self._snapshot_leaf_digests = candidate_leaf_digests
            self._snapshot_commit_phase = _SnapshotCommitPhase.COMMITTED
            self._candidate_publication_committed = True
            if not is_control_flow_exception(error):
                self._record_finalization_diagnostic(
                    "status_commit_confirmation",
                    error,
                )
            return True, observed_control_flow

    @staticmethod
    def _publication_leaf_identity(
        metadata: os.stat_result,
    ) -> Tuple[int, ...]:
        """
        Return the immutable identity used to resolve rename ambiguity.

        The implementation uses ``metadata`` to produce the immutable identity
        used to resolve rename ambiguity.

        Args:
            metadata: Metadata object whose ``st_dev``, ``st_ino``, ``st_mode``,
                and ``st_size`` state is read while performing immutable
                identity used to resolve rename ambiguity.

        Returns:
            A tuple containing ``st dev``, ``st ino``, ``st mode``, and ``st
            size`` in that order.
        """

        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
        )

    def _backup_public_leaf(self, relative: Path, public_parent: int) -> int:
        """
        Retain a durable hard-link rollback image before replacing a leaf.

        The implementation uses ``relative`` and ``public_parent`` to retain a
        durable hard-link rollback image before replacing a leaf. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle. If the function cannot retain a durable hard-link
        rollback image before replacing a leaf, its exception reaches the caller
        instead of being converted into a successful result. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            relative: filesystem location used as the relative for this
                operation.
            public_parent: Numeric public parent used while the operation
                performs bounded accounting.

        Returns:
            The numeric backup public leaf value.

        Raises:
            RuntimeError: If status publication leaf is not replaceable; or
                status publication candidate is unavailable.
        """

        try:
            destination_metadata = os.stat(
                relative.name,
                dir_fd=public_parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return 0o644
        if stat.S_ISLNK(destination_metadata.st_mode):
            destination_mode = 0o644
        elif stat.S_ISREG(destination_metadata.st_mode):
            destination_mode = stat.S_IMODE(destination_metadata.st_mode) & 0o666
        else:
            raise RuntimeError("Status publication leaf is not replaceable")

        candidate_descriptor = self._candidate_fd
        if candidate_descriptor is None:
            raise RuntimeError("Status publication candidate is unavailable")
        backup_parent = _open_relative_directory(
            candidate_descriptor,
            (".rollback", *relative.parts[:-1]),
            create=True,
        )
        try:
            try:
                os.link(
                    relative.name,
                    relative.name,
                    src_dir_fd=public_parent,
                    dst_dir_fd=backup_parent,
                    follow_symlinks=False,
                )
            except BaseException:
                try:
                    backup_metadata = os.stat(
                        relative.name,
                        dir_fd=backup_parent,
                        follow_symlinks=False,
                    )
                    current_metadata = os.stat(
                        relative.name,
                        dir_fd=public_parent,
                        follow_symlinks=False,
                    )
                except BaseException:
                    raise
                if self._publication_leaf_identity(
                    backup_metadata
                ) != self._publication_leaf_identity(current_metadata):
                    raise
                self._candidate_backed_up_leaves.add(relative)
                raise
            self._candidate_backed_up_leaves.add(relative)
            os.fsync(backup_parent)
        finally:
            os.close(backup_parent)
        return destination_mode

    def _rollback_candidate_publication(self) -> None:
        """
        Restore every predecessor leaf, retaining backups until fsync succeeds.

        The implementation uses current instance state to restore every
        predecessor leaf, retaining backups until fsync succeeds. It updates
        ``_candidate_fd`` and ``_publication_deadline`` on the instance as part
        of that state transition. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot restore every predecessor leaf, retaining backups until fsync
        succeeds, its exception reaches the caller instead of being converted
        into a successful result. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Raises:
            RuntimeError: If status rollback candidate ownership was lost; could
                not allocate status rollback leaf; status rollback leaf identity
                changed; or new status leaf remained after rollback.
        """

        touched = self._candidate_moved_leaves | self._candidate_backed_up_leaves
        if not touched:
            return
        candidate_descriptor = self._candidate_fd
        if candidate_descriptor is None:
            name = self._candidate_name
            if name is None:
                raise RuntimeError("Status rollback candidate ownership was lost")
            candidate_descriptor = os.open(
                name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=self._require_output_root_fd(),
            )
            self._candidate_fd = candidate_descriptor

        root_relative = self._relative_publication_path(self.global_status_file)
        ordered = sorted(
            (relative for relative in touched if relative != root_relative),
            key=lambda path: path.as_posix(),
        )
        if root_relative in touched:
            ordered.append(root_relative)

        saved_deadline = self._publication_deadline
        self._publication_deadline = None
        try:
            for relative in ordered:
                public_parent = self._open_publication_parent(relative)
                temporary_name: Optional[str] = None
                backup_parent: Optional[int] = None
                try:
                    if relative in self._candidate_backed_up_leaves:
                        backup_parent = _open_relative_directory(
                            candidate_descriptor,
                            (".rollback", *relative.parts[:-1]),
                            create=False,
                        )
                        backup_metadata = os.stat(
                            relative.name,
                            dir_fd=backup_parent,
                            follow_symlinks=False,
                        )
                        for _ in range(64):
                            temporary_name = (
                                f".{relative.name}.rollback-{secrets.token_hex(12)}.tmp"
                            )
                            try:
                                os.link(
                                    relative.name,
                                    temporary_name,
                                    src_dir_fd=backup_parent,
                                    dst_dir_fd=public_parent,
                                    follow_symlinks=False,
                                )
                                break
                            except FileExistsError:
                                continue
                        else:
                            raise RuntimeError(
                                "Could not allocate status rollback leaf"
                            )
                        os.replace(
                            temporary_name,
                            relative.name,
                            src_dir_fd=public_parent,
                            dst_dir_fd=public_parent,
                        )
                        temporary_name = None
                        os.fsync(public_parent)
                        restored_metadata = os.stat(
                            relative.name,
                            dir_fd=public_parent,
                            follow_symlinks=False,
                        )
                        if self._publication_leaf_identity(
                            restored_metadata
                        ) != self._publication_leaf_identity(backup_metadata):
                            raise RuntimeError("Status rollback leaf identity changed")
                        self._candidate_backed_up_leaves.discard(relative)
                        self._candidate_moved_leaves.discard(relative)
                    elif relative in self._candidate_moved_leaves:
                        try:
                            os.unlink(relative.name, dir_fd=public_parent)
                        except FileNotFoundError:
                            pass
                        os.fsync(public_parent)
                        try:
                            os.stat(
                                relative.name,
                                dir_fd=public_parent,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError:
                            pass
                        else:
                            raise RuntimeError(
                                "New status leaf remained after rollback"
                            )
                        self._candidate_moved_leaves.discard(relative)
                finally:
                    if temporary_name is not None:
                        try:
                            os.unlink(temporary_name, dir_fd=public_parent)
                        except FileNotFoundError:
                            pass
                    if backup_parent is not None:
                        os.close(backup_parent)
                    os.close(public_parent)
            os.fsync(self._require_output_root_fd())
        finally:
            self._publication_deadline = saved_deadline

    def _publish_candidate_root(self) -> None:
        """
        Replace candidate leaves and publish root status as the commit marker.

        Apply each destination's access mode through a pinned regular-file
        descriptor. Descriptor chmod is already required by the candidate
        writer and avoids the optional no-follow pathname chmod capability.
        Publish the root marker last and retain rollback ownership until every
        replacement is durable. Record rename identity after the mode change
        so an exception following a completed rename can be reconciled.
        Release all acquired handles even if one close fails, preserving the
        authoritative publication or control-flow exception for the caller.

        Raises:
            RuntimeError: If status publication candidate is unavailable; status
                candidate is missing its root commit marker; or status candidate
                leaf is not a regular file or changes before it is opened.
            OSError: If a file cannot be opened, permission-adjusted, replaced,
                synchronized, or closed.

        Side Effects:
            Replaces output metadata leaves, updates the snapshot commit phase,
            and closes all descriptors on success, failure, or cancellation.
        """

        candidate_descriptor = self._candidate_fd
        if candidate_descriptor is None:
            raise RuntimeError("Status publication candidate is unavailable")
        root_relative = self._relative_publication_path(self.global_status_file)
        if root_relative not in self._candidate_leaves:
            raise RuntimeError("Status candidate is missing its root commit marker")
        ordered = sorted(
            (path for path in self._candidate_leaves if path != root_relative),
            key=lambda path: path.as_posix(),
        )
        ordered.append(root_relative)

        for relative in ordered:
            self._check_publication_deadline(f"publishing {relative.as_posix()}")
            candidate_parent = _open_relative_directory(
                candidate_descriptor,
                tuple(relative.parts[:-1]),
                create=False,
            )
            public_parent = -1
            candidate_leaf = -1
            publication_errors: List[BaseException] = []
            try:
                public_parent = self._open_publication_parent(relative)
                candidate_metadata = os.stat(
                    relative.name,
                    dir_fd=candidate_parent,
                    follow_symlinks=False,
                )
                if not stat.S_ISREG(candidate_metadata.st_mode):
                    raise RuntimeError("Status candidate leaf is not a regular file")
                destination_mode = self._backup_public_leaf(relative, public_parent)
                candidate_leaf = os.open(
                    relative.name,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=candidate_parent,
                )
                opened_metadata = os.fstat(candidate_leaf)
                if self._publication_leaf_identity(
                    opened_metadata
                ) != self._publication_leaf_identity(candidate_metadata):
                    raise RuntimeError("Status candidate leaf changed before opening")
                os.fchmod(candidate_leaf, destination_mode)
                candidate_identity = self._publication_leaf_identity(
                    os.fstat(candidate_leaf)
                )
                try:
                    os.replace(
                        relative.name,
                        relative.name,
                        src_dir_fd=candidate_parent,
                        dst_dir_fd=public_parent,
                    )
                except BaseException:
                    try:
                        published_metadata = os.stat(
                            relative.name,
                            dir_fd=public_parent,
                            follow_symlinks=False,
                        )
                    except BaseException:
                        raise
                    if (
                        self._publication_leaf_identity(published_metadata)
                        == candidate_identity
                    ):
                        self._candidate_moved_leaves.add(relative)
                        if relative == root_relative:
                            self._snapshot_commit_phase = (
                                _SnapshotCommitPhase.ROOT_RENAMED
                            )
                    raise
                else:
                    self._candidate_moved_leaves.add(relative)
                    if relative == root_relative:
                        # os.replace() is the externally visible commit point.
                        self._snapshot_commit_phase = _SnapshotCommitPhase.ROOT_RENAMED
                os.fsync(public_parent)
                confirmation_descriptor = self._open_publication_parent(relative)
                self._close_descriptor(confirmation_descriptor)
            except BaseException as error:
                publication_errors.append(error)
            finally:
                for descriptor in (candidate_leaf, candidate_parent, public_parent):
                    if descriptor >= 0:
                        try:
                            self._close_descriptor(descriptor)
                        except BaseException as error:
                            publication_errors.append(error)
                if publication_errors:
                    raise select_authoritative_exception(publication_errors)
        self._revalidate_output_root_path()

    async def _publish_candidate_snapshot(
        self,
        *,
        include_summaries: bool,
        include_timing: bool,
        terminal: bool,
        new_generation: bool,
    ) -> _PublicationResult:
        """
        Render a complete generation before publishing its root marker.

        Filesystem phases run on the owned bounded pool so slow output storage
        cannot block collector scheduling or progress callbacks. Every worker is
        joined before cancellation enters rollback or candidate cleanup.

        The implementation uses ``include_summaries``, ``include_timing``,
        ``terminal``, and ``new_generation`` to render a complete generation
        before publishing its root marker. The source value keeps its ownership
        while the normalized representation is returned separately. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. It updates ``_candidate_prior_snapshot``,
        ``_candidate_publication_committed``, ``_publication_deadline``,
        ``_render_snapshot_generation``, and ``_render_snapshot_terminal`` on
        the instance as part of that state transition. If the function cannot
        render a complete generation before publishing its root marker, its
        exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Args:
            include_summaries: Whether include summaries is enabled or required
                for this operation.
            include_timing: Whether include timing is enabled or required for
                this operation.
            terminal: Whether terminal is enabled or required for this
                operation.
            new_generation: Whether new generation is enabled or required for
                this operation.

        Returns:
            A ``_PublicationResult`` representing publish candidate snapshot.

        Raises:
            RuntimeError: If failed to render global status candidate; failed to
                render per-DUT status candidates; failed to render global
                summary candidate; or failed to render per-DUT summary
                candidates; or another input invariant is violated.
            BaseException: If a delegated failure occurs while the function
                attempts to render a complete generation before publishing its
                root marker.
        """

        await self.flush_progress(raise_on_error=False)
        if self.has_pending_candidate:
            await run_managed_filesystem_operation(self.cleanup_pending_candidate)
        generation = (
            secrets.token_hex(16)
            if new_generation or self._snapshot_generation is None
            else self._snapshot_generation
        )
        prior_generation = self._snapshot_generation
        prior_terminal = self._snapshot_terminal
        prior_leaf_digests = self._snapshot_leaf_digests
        prior_phase = self._snapshot_commit_phase
        candidate_leaf_digests: Tuple[SnapshotLeafDigest, ...] = ()
        committed = False
        post_commit_control_flow: Optional[BaseException] = None
        candidate_cleanup_error: Optional[BaseException] = None
        self._publication_deadline = (
            time.monotonic()
            + self._snapshot_io_budget_seconds(len(self._declared_dut_ids or ()))
        )
        self._snapshot_commit_phase = _SnapshotCommitPhase.RENDERING
        try:
            await run_managed_filesystem_operation(self._create_candidate_root)
            self._candidate_prior_snapshot = (
                prior_generation,
                prior_terminal,
                prior_phase,
            )
            self._render_snapshot_generation = generation
            self._render_snapshot_terminal = terminal
            async with self._status_update_lock:
                if not await self._save_global_status_file(durable=True):
                    raise RuntimeError("Failed to render global status candidate")
                if not await self._save_dut_status_files(durable=True):
                    raise RuntimeError("Failed to render per-DUT status candidates")
                if include_summaries:
                    if not await self._save_global_summary_file(durable=True):
                        raise RuntimeError("Failed to render global summary candidate")
                    if not await self._save_dut_summary_files(durable=True):
                        raise RuntimeError(
                            "Failed to render per-DUT summary candidates"
                        )
                    if not await self._save_run_result_files(durable=True):
                        raise RuntimeError("Failed to render canonical RunResult files")
                if include_timing and not await self._save_dut_timing_files(
                    durable=True
                ):
                    raise RuntimeError("Failed to render per-DUT timing candidates")

            # Freeze all receipt evidence before the externally visible root
            # rename. Allocation/sort failures remain precommit and therefore
            # cannot attach stale evidence to a newly committed generation.
            candidate_leaf_digests = self._candidate_digest_evidence()

            try:
                await run_managed_filesystem_operation(self._publish_candidate_root)
            except BaseException as error:
                if self._snapshot_commit_phase is not _SnapshotCommitPhase.ROOT_RENAMED:
                    raise
                committed, resolution_control_flow = (
                    await run_managed_filesystem_operation(
                        partial(
                            self._resolve_post_root_failure,
                            error,
                            generation=generation,
                            terminal=terminal,
                            prior_generation=prior_generation,
                            prior_terminal=prior_terminal,
                            prior_phase=prior_phase,
                            candidate_leaf_digests=candidate_leaf_digests,
                        )
                    )
                )
                if not committed:
                    if resolution_control_flow is not None:
                        raise resolution_control_flow
                    raise
                post_commit_control_flow = resolution_control_flow
            else:
                # Returning from root publication proves the commit point was
                # crossed. Mark that fact before fallible in-memory bookkeeping
                # so the exception path can deterministically adopt the exact
                # frozen state instead of attempting rollback.
                committed = True
                self._snapshot_generation = generation
                self._snapshot_terminal = terminal
                self._snapshot_leaf_digests = candidate_leaf_digests
                self._snapshot_commit_phase = _SnapshotCommitPhase.COMMITTED
                self._candidate_publication_committed = True
            self._record_adopted_snapshot_time()
        except BaseException as primary_error:
            if committed:
                # Complete an exact adoption even if a control-flow signal or
                # bookkeeping defect arrived between individual assignments.
                self._snapshot_generation = generation
                self._snapshot_terminal = terminal
                self._snapshot_leaf_digests = candidate_leaf_digests
                self._snapshot_commit_phase = _SnapshotCommitPhase.COMMITTED
                self._candidate_publication_committed = True
                post_commit_errors: list[BaseException] = [primary_error]
                if post_commit_control_flow is not None:
                    post_commit_errors.insert(0, post_commit_control_flow)
                try:
                    await run_managed_filesystem_operation(self._discard_candidate_root)
                except BaseException as cleanup_error:
                    post_commit_errors.append(cleanup_error)
                authoritative = select_authoritative_exception(post_commit_errors)
                if is_control_flow_exception(authoritative):
                    post_commit_control_flow = authoritative
                    candidate_cleanup_error = next(
                        (
                            error
                            for error in post_commit_errors
                            if not is_control_flow_exception(error)
                        ),
                        None,
                    )
                else:
                    post_commit_control_flow = None
                    candidate_cleanup_error = authoritative
                return _PublicationResult(
                    generation=generation,
                    terminal=terminal,
                    post_commit_control_flow=post_commit_control_flow,
                    candidate_cleanup_error=candidate_cleanup_error,
                )
            try:
                await run_managed_filesystem_operation(
                    self._rollback_candidate_publication
                )
                self._snapshot_generation = prior_generation
                self._snapshot_terminal = prior_terminal
                self._snapshot_leaf_digests = prior_leaf_digests
                self._snapshot_commit_phase = prior_phase
                await run_managed_filesystem_operation(self._discard_candidate_root)
            except BaseException as cleanup_error:
                self._record_finalization_diagnostic(
                    "candidate_cleanup",
                    cleanup_error,
                )
                try:
                    primary_error.add_note(
                        "Status candidate cleanup remains pending after publication failure"
                    )
                except BaseException:
                    pass
            raise
        else:
            post_commit_errors = (
                [post_commit_control_flow]
                if post_commit_control_flow is not None
                else []
            )
            try:
                await run_managed_filesystem_operation(self._discard_candidate_root)
            except BaseException as cleanup_error:
                post_commit_errors.append(cleanup_error)
            if post_commit_errors:
                authoritative = select_authoritative_exception(post_commit_errors)
                if is_control_flow_exception(authoritative):
                    post_commit_control_flow = authoritative
                    candidate_cleanup_error = next(
                        (
                            error
                            for error in post_commit_errors
                            if not is_control_flow_exception(error)
                        ),
                        None,
                    )
                else:
                    post_commit_control_flow = None
                    candidate_cleanup_error = authoritative
                    self._record_finalization_diagnostic(
                        "candidate_cleanup",
                        authoritative,
                    )
            return _PublicationResult(
                generation=generation,
                terminal=terminal,
                post_commit_control_flow=post_commit_control_flow,
                candidate_cleanup_error=candidate_cleanup_error,
            )
        finally:
            self._render_snapshot_generation = None
            self._render_snapshot_terminal = False
            self._publication_deadline = None
            if committed and terminal:
                # The complete terminal generation supersedes restored dirty
                # live leaves. Cleanup must not retry them over terminal state.
                self._pending_progress_duts.clear()
                self._progress_full_snapshot_pending = False
            if not committed and not self.has_pending_candidate:
                self._snapshot_generation = prior_generation
                self._snapshot_terminal = prior_terminal
                self._snapshot_leaf_digests = prior_leaf_digests
                self._snapshot_commit_phase = prior_phase

    @staticmethod
    def _raise_post_commit_control_flow(result: _PublicationResult) -> None:
        """
        Preserve control-flow classification after an adopted publication.

        The implementation uses ``result`` to preserve control-flow
        classification after an adopted publication. If the function cannot
        preserve control-flow classification after an adopted publication, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            result: Result object whose ``post_commit_control_flow`` state is
                read while performing preserve control-flow classification after
                an adopted publication.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to preserve control-flow classification after an
                adopted publication.
        """

        if result.post_commit_control_flow is not None:
            raise result.post_commit_control_flow

    async def set_run_outcome(
        self,
        status: str,
        *,
        failure_type: Optional[str] = None,
        reason: str = "",
        evidence: Optional[str] = None,
        affected_duts: Optional[List[str]] = None,
        underlying_outcome: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Bound and durably republish one run-level terminal outcome.

        The implementation uses ``status``, ``failure_type``, ``reason``,
        ``evidence``, and ``affected_duts`` to bound and durably republish one
        run-level terminal outcome. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. It
        updates ``_outcome_intent`` and ``run_outcome`` on the instance as part
        of that state transition. If the function cannot bound and durably
        republish one run-level terminal outcome, its exception reaches the
        caller instead of being converted into a successful result.

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
            underlying_outcome: Optional underlying outcome; ``None`` selects
                the function's default behavior.

        Raises:
            ValueError: If unsupported run outcome: ``status``;
                ``normalized_status`` lacks failure_type; recursive underlying
                outcomes are unsupported; use the typed intent; or evidence path
                is supported only for domain failures; or another input
                invariant is violated.
            RuntimeError: If run outcome can only change before terminal
                finalization.
            BaseException: If a delegated failure occurs while the function
                attempts to bound and durably republish one run-level terminal
                outcome.
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

        if underlying_outcome is not None:
            raise ValueError(
                "Recursive underlying outcomes are unsupported; use the typed intent"
            )

        normalized_evidence = ""
        if evidence is not None:
            if normalized_status != "domain_failed" or type(evidence) is not str:
                raise ValueError("evidence path is supported only for domain failures")
            candidate = PurePosixPath(evidence)
            if (
                not evidence
                or len(evidence.encode("utf-8")) > 512
                or candidate.is_absolute()
                or candidate.as_posix() != evidence
                or any(part in {"", ".", ".."} for part in candidate.parts)
                or not is_printable_identity(evidence, maximum_bytes=512)
            ):
                raise ValueError("evidence path must be a bounded safe relative path")
            normalized_evidence = evidence
        if normalized_failure_type in EXPLICIT_SELECTION_FAILURE_TYPES and (
            normalized_evidence != EXPLICIT_SELECTION_EVIDENCE_PATH
        ):
            raise ValueError(
                "explicit selection failure requires its canonical evidence path"
            )
        intent = FinalizationOutcomeHint(
            status=normalized_status,
            failure_type=(
                normalized_failure_type
                if normalized_status in {"domain_failed", "runtime_failed"}
                else ""
            ),
            reason=normalize_run_outcome_reason(
                normalized_status,
                self._sanitize_run_outcome_reason(reason),
            ),
            affected_duts=tuple(self._canonicalize_affected_duts(affected_duts)),
        )
        outcome = intent.to_legacy_run_outcome()
        if normalized_evidence:
            outcome["evidence"] = normalized_evidence

        async with self._lifecycle_lock:
            if self._lifecycle_state is not _TrackerLifecycle.BOUND:
                raise RuntimeError(
                    "Run outcome can only change before terminal finalization"
                )
            previous_intent = self._outcome_intent
            previous_outcome = self.run_outcome
            self._outcome_intent = intent
            self.run_outcome = outcome
            try:
                publication_result = await self._publish_candidate_snapshot(
                    include_summaries=False,
                    include_timing=False,
                    terminal=False,
                    new_generation=False,
                )
            except BaseException:
                self._outcome_intent = previous_intent
                self.run_outcome = previous_outcome
                raise
            self._raise_post_commit_control_flow(publication_result)
            if publication_result.candidate_cleanup_error is not None:
                raise publication_result.candidate_cleanup_error

    @staticmethod
    def _validate_dut_roster(dut_ids: Any) -> Tuple[str, ...]:
        """
        Return an exact, ordered DUT roster safe for direct output paths.

        The implementation uses ``dut_ids`` to produce an exact, ordered DUT
        roster safe for direct output paths. If the function cannot produce an
        exact, ordered DUT roster safe for direct output paths, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            dut_ids: DUT identifiers consumed while the function attempts to
                produce an exact, ordered DUT roster safe for direct output
                paths.

        Returns:
            The validated ``roster``.

        Raises:
            ValueError: If the dut roster is not a list or tuple; DUT roster
                exceeds the supported maximum of ``MAX_DUTS``; the dut identity
                is not a bounded printable path component; or the dut identity
                is not one direct path component; or another input invariant is
                violated.
        """

        if not isinstance(dut_ids, (list, tuple)):
            raise ValueError("DUT roster must be a list or tuple")

        roster = tuple(dut_ids)
        if len(roster) > MAX_DUTS:
            raise ValueError(f"DUT roster exceeds the supported maximum of {MAX_DUTS}")
        seen: Set[str] = set()
        for dut_id in roster:
            if (
                not is_printable_identity(dut_id, maximum_bytes=MAX_DUT_ID_BYTES)
                or "\x00" in dut_id
                or "\\" in dut_id
            ):
                raise ValueError(
                    "DUT identity must be a bounded printable path component"
                )
            component = Path(dut_id)
            if (
                component.is_absolute()
                or len(component.parts) != 1
                or component.as_posix() != dut_id
                or component.name in {".", "..", ".metadata"}
            ):
                raise ValueError("DUT identity must be one direct path component")
            if dut_id in seen:
                raise ValueError(f"Duplicate DUT identity: {dut_id}")
            seen.add(dut_id)
        return roster

    @staticmethod
    def _validate_collector_roster(collector_ids: Any) -> Tuple[str, ...]:
        """
        Return an exact, ordered collector roster without duplicate IDs.

        The implementation uses ``collector_ids`` to produce an exact, ordered
        collector roster without duplicate IDs. If the function cannot produce
        an exact, ordered collector roster without duplicate IDs, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            collector_ids: Collector identifiers consumed while the function
                attempts to produce an exact, ordered collector roster without
                duplicate IDs.

        Returns:
            The validated ``roster``.

        Raises:
            ValueError: If the collector roster is not a list or tuple;
                collector roster exceeds the supported maximum of
                ``MAX_COLLECTORS_PER_RUN``; the collector identities are not
                bounded printable strings; or collector roster contains
                duplicate identities.
        """

        if not isinstance(collector_ids, (list, tuple)):
            raise ValueError("Collector roster must be a list or tuple")

        roster = tuple(collector_ids)
        if len(roster) > MAX_COLLECTORS_PER_RUN:
            raise ValueError(
                "Collector roster exceeds the supported maximum of "
                f"{MAX_COLLECTORS_PER_RUN}"
            )
        if any(
            not is_printable_identity(
                collector_id,
                maximum_bytes=MAX_COLLECTOR_ID_BYTES,
            )
            for collector_id in roster
        ):
            raise ValueError("Collector identities must be bounded printable strings")
        if len(roster) != len(set(roster)):
            raise ValueError("Collector roster contains duplicate identities")
        return roster

    def _declare_run_unlocked(
        self, dut_ids: Tuple[str, ...], *, defer_filesystem: bool = False
    ) -> bool:
        """
        Declare the immutable ordered DUT roster while holding the lock.

        Register the outer DUT directory first so opening its metadata directory
        also revalidates the DUT identity.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            defer_filesystem: Defer per-DUT directory registration to the owned
                live writer so rack startup does not wait for every NFS inode.

        Returns:
            Whether the declare the immutable ordered DUT roster while holding
            the lock operation succeeds.

        Raises:
            RuntimeError: If cannot declare a run after finalization; run was
                already declared with a different DUT roster; or tracker is not
                open for run declaration.
            ValueError: If the dut output paths are not stable directories:
                ``dut_id``.
        """

        if self._finalized:
            raise RuntimeError("Cannot declare a run after finalization")
        if self._declared_dut_ids is not None:
            if dut_ids == self._declared_dut_ids:
                return False
            raise RuntimeError("Run was already declared with a different DUT roster")
        if self._lifecycle_state is not _TrackerLifecycle.NEW:
            raise RuntimeError("Tracker is not open for run declaration")

        status_files: Dict[str, Path] = {}
        summary_files: Dict[str, Path] = {}
        run_result_files: Dict[str, Path] = {}
        dut_collectors: Dict[str, Set[str]] = {}
        for dut_id in dut_ids:
            dut_dir = self.output_dir / run_tree_dut_component(dut_id)
            dut_metadata_dir = dut_dir / ".metadata"
            status_file = dut_metadata_dir / "collection_status.json"
            summary_file = dut_dir / "collection_status_summary.txt"
            run_result_file = dut_metadata_dir / "run_result.json"
            try:
                # Register the outer DUT directory first so opening its metadata
                # directory also revalidates the DUT identity.
                if not defer_filesystem:
                    self._register_publication_parent(summary_file)
                    self._register_publication_parent(status_file)
            except (NotADirectoryError, OSError, RuntimeError) as error:
                raise ValueError(
                    f"DUT output paths must be stable directories: {dut_id}"
                ) from error
            status_files[dut_id] = status_file
            summary_files[dut_id] = summary_file
            run_result_files[dut_id] = run_result_file
            dut_collectors[dut_id] = set()

        self.dut_status_files = status_files
        self.dut_summary_files = summary_files
        self.dut_run_result_files = run_result_files
        self.dut_collectors = dut_collectors
        self._declared_dut_ids = dut_ids
        self._lifecycle_state = _TrackerLifecycle.DECLARED
        return True

    async def declare_run(self, dut_ids: List[str]) -> None:
        """
        Declare the exact ordered DUT roster once.

        The implementation uses ``dut_ids`` to declare the exact ordered DUT
        roster once. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
        """

        async with self._lifecycle_lock:
            roster = self._validate_dut_roster(dut_ids)
            await run_managed_filesystem_operation(self._declare_run_unlocked, roster)

    def _build_plan(
        self,
        dut_ids: Tuple[str, ...],
        collector_ids: Tuple[str, ...],
        config_manager: Any,
    ) -> Tuple[
        Dict[_CollectorIdentity, CollectorStatusEntry],
        Dict[str, CollectorStatusEntry],
        Dict[str, Set[str]],
        Dict[str, Set[str]],
        Dict[str, int],
        Tuple[Any, ...],
    ]:
        """
        Build an immutable plan candidate without changing tracker state.

        The implementation uses ``dut_ids``, ``collector_ids``, and
        ``config_manager`` to build an immutable plan candidate without changing
        tracker state. If the function cannot build an immutable plan candidate
        without changing tracker state, its exception reaches the caller instead
        of being converted into a successful result.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
            config_manager: Config manager governing immutable plan candidate
                without changing tracker state.

        Returns:
            A tuple containing ``statuses by identity``, ``legacy statuses``,
            ``DUT collectors``, ``collector groups``, ``stats``, and
            ``signature`` in that order.

        Raises:
            ValueError: If DUT and collector identities collide at the legacy
                status serialization boundary.
        """

        # Resolve tool config once, but retain per-DUT config because effective
        # timeout overrides can differ across an otherwise identical plan.
        tool_config: Dict[str, Any] = {}
        all_dut_configs: Dict[str, Any] = {}
        try:
            tool_config = config_manager.get_tool_config() or {}
        except Exception:
            tool_config = {}
        try:
            all_dut_configs = config_manager.get_dut_config() or {}
        except Exception:
            all_dut_configs = {}

        from ..utils.timeout_config import get_collector_timeout

        statuses_by_identity: Dict[_CollectorIdentity, CollectorStatusEntry] = {}
        legacy_statuses: Dict[str, CollectorStatusEntry] = {}
        dut_collectors: Dict[str, Set[str]] = {dut_id: set() for dut_id in dut_ids}
        collector_groups: Dict[str, Set[str]] = {}
        stats = {key: 0 for key in self.stats}
        stats["total_collectors"] = len(dut_ids) * len(collector_ids)
        stats["pending_collectors"] = stats["total_collectors"]

        for dut_id in dut_ids:
            per_dut_config = all_dut_configs.get(dut_id, {}) or {}
            for collector_id in collector_ids:
                collector_info = config_manager.get_collector_info(collector_id)
                collector_name = collector_info.get("name", "Unknown")
                group = collector_info.get("group", "Unknown")
                level = collector_info.get("collection_level", "L1")
                raw_timeout = collector_info.get("timeout")
                default_for_resolver = (
                    int(raw_timeout)
                    if isinstance(raw_timeout, (int, float)) and raw_timeout > 0
                    else 300
                )
                try:
                    timeout = get_collector_timeout(
                        collector_id,
                        collector_info,
                        per_dut_config,
                        default_for_resolver,
                        tool_config,
                    )
                except Exception:
                    # Timeout reporting must not make plan binding fail. Fall
                    # back to a deterministic integer (or None), preserving 0.
                    if raw_timeout is None:
                        timeout = None
                    else:
                        try:
                            timeout = int(raw_timeout)
                        except (TypeError, ValueError):
                            timeout = None

                identity = _CollectorIdentity(dut_id, collector_id)
                entry = CollectorStatusEntry(
                    dut_id=dut_id,
                    collector_id=collector_id,
                    collector_name=collector_name,
                    group=group,
                    level=level,
                    status=CollectorStatus.PENDING,
                    timeout=timeout,
                )
                if identity.legacy_key in legacy_statuses:
                    raise ValueError(
                        "DUT and collector identities collide at the legacy "
                        "status serialization boundary"
                    )
                statuses_by_identity[identity] = entry
                legacy_statuses[identity.legacy_key] = entry
                dut_collectors[dut_id].add(collector_id)
                collector_groups.setdefault(group, set()).add(identity.legacy_key)

        signature = (
            dut_ids,
            collector_ids,
            tuple(
                (
                    identity.dut_id,
                    identity.collector_id,
                    json.dumps(
                        (
                            entry.collector_name,
                            entry.group,
                            entry.level,
                            entry.timeout,
                        ),
                        sort_keys=True,
                        default=repr,
                    ),
                )
                for identity, entry in statuses_by_identity.items()
            ),
        )
        return (
            statuses_by_identity,
            legacy_statuses,
            dut_collectors,
            collector_groups,
            stats,
            signature,
        )

    async def bind_plan(
        self,
        dut_ids: List[str],
        collector_ids: List[str],
        config_manager: Any,
    ) -> None:
        """
        Bind the tracker once to one exact ordered DUT/collector plan.

        Validate identities and materialize the in-memory plan before callbacks
        may start. Rack-sized plans queue their initial live snapshot on one
        owned writer instead of waiting for every NFS directory and status file.
        ``flush_progress``, finalization, and ``aclose`` join that writer and
        surface its failures. Small single-DUT plans retain immediate publication.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
            config_manager: Config manager governing bind the tracker once to
                one exact ordered DUT/collector plan.

        Raises:
            RuntimeError: If cannot bind a plan after finalization; or tracker
                is already bound to a different plan.
            ValueError: If DUT/collector plan exceeds the supported maximum of
                ``MAX_TRACKED_COLLECTOR_RECORDS`` tracked records.
            BaseException: If a delegated failure occurs while the function
                attempts to bind the tracker once to one exact ordered
                DUT/collector plan.
        """

        async with self._lifecycle_lock:
            if self._finalized:
                raise RuntimeError("Cannot bind a plan after finalization")

            roster = self._validate_dut_roster(dut_ids)
            collectors = self._validate_collector_roster(collector_ids)
            tracked_records = len(roster) * len(collectors)
            if tracked_records > MAX_TRACKED_COLLECTOR_RECORDS:
                raise ValueError(
                    "DUT/collector plan exceeds the supported maximum of "
                    f"{MAX_TRACKED_COLLECTOR_RECORDS} tracked records"
                )
            deferred_progress = (
                len(roster) > 1 or tracked_records >= INCREMENTAL_STATUS_MIN_ENTRIES
            )
            if deferred_progress:
                self._declare_run_unlocked(roster, defer_filesystem=True)
            else:
                await run_managed_filesystem_operation(
                    self._declare_run_unlocked, roster
                )
            (
                statuses_by_identity,
                legacy_statuses,
                dut_collectors,
                collector_groups,
                stats,
                signature,
            ) = self._build_plan(roster, collectors, config_manager)

            if self._lifecycle_state is _TrackerLifecycle.BOUND:
                if signature == self._bound_plan_signature:
                    return
                raise RuntimeError("Tracker is already bound to a different plan")

            previous_state = (
                self._collector_statuses_by_identity,
                self.collector_statuses,
                self.dut_collectors,
                self.collector_groups,
                self.stats,
                self._last_aggregate_snapshot_at,
            )
            self._collector_statuses_by_identity = statuses_by_identity
            self.collector_statuses = legacy_statuses
            self.dut_collectors = dut_collectors
            self.collector_groups = collector_groups
            self.stats = stats
            self._last_aggregate_snapshot_at = None
            publication_result = None
            try:
                if deferred_progress:
                    self._deferred_progress_enabled = True
                    self._snapshot_generation = secrets.token_hex(16)
                    self._queue_progress_update()
                else:
                    publication_result = await self._publish_candidate_snapshot(
                        include_summaries=True,
                        include_timing=False,
                        terminal=False,
                        new_generation=True,
                    )
            except BaseException:
                (
                    self._collector_statuses_by_identity,
                    self.collector_statuses,
                    self.dut_collectors,
                    self.collector_groups,
                    self.stats,
                    self._last_aggregate_snapshot_at,
                ) = previous_state
                raise

            self._bound_plan_signature = signature
            self._lifecycle_state = _TrackerLifecycle.BOUND
            if publication_result is not None:
                self._raise_post_commit_control_flow(publication_result)
                if publication_result.candidate_cleanup_error is not None:
                    raise publication_result.candidate_cleanup_error

            for dut_id in roster:
                for message in (
                    f"Initialized collection with {len(roster)} DUTs and "
                    f"{len(collectors)} collectors",
                    f"Initial stats: {self.stats}",
                    f"Collector statuses keys: {list(self.collector_statuses.keys())}",
                ):
                    try:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "CollectionStatusTracker",
                            message,
                        )
                    except Exception:
                        # The plan and its initial snapshots are already
                        # committed. Optional diagnostics must not make the
                        # caller observe a failed/ambiguous bind.
                        continue

            if self._display_enabled:
                await self._start_live_display()

    async def initialize_collection(
        self, dut_ids: List[str], collector_ids: List[str], config_manager: Any
    ) -> None:
        """
        Compatibility wrapper for declaring and binding the run plan.

        The implementation uses ``dut_ids``, ``collector_ids``, and
        ``config_manager`` to compatibility wrapper for declaring and binding
        the run plan. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            collector_ids: Entries supplied as ``collector_ids`` without
                transferring container ownership.
            config_manager: Config manager governing compatibility wrapper for
                declaring and binding the run plan.
        """

        await self.bind_plan(dut_ids, collector_ids, config_manager)

    def _collector_mutation_allowed_unlocked(self) -> bool:
        """
        Return whether callbacks may mutate the bound in-memory plan.

        The implementation uses current instance state to determine whether
        callbacks may mutate the bound in-memory plan. If the function cannot
        determine whether callbacks may mutate the bound in-memory plan, its
        exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            Whether callbacks may mutate the bound in-memory plan.

        Raises:
            RuntimeError: If cannot update collection status before plan
                binding.
        """

        if self._finalized:
            return False
        if self._lifecycle_state is not _TrackerLifecycle.BOUND:
            raise RuntimeError("Cannot update collection status before plan binding")
        return True

    def _get_collector_status_entry(
        self, dut_id: str, collector_id: str
    ) -> Optional[CollectorStatusEntry]:
        """
        Resolve only the exact typed DUT/collector pair.

        The legacy string map remains available to readers and serializers, but
        is deliberately never used to infer a pair by splitting a composed key.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A ``CollectorStatusEntry`` representing collector status entry, or
            ``None`` when the requested value is unavailable.
        """

        identity = _CollectorIdentity(dut_id, collector_id)
        entry = self._collector_statuses_by_identity.get(identity)
        if entry is not None:
            return entry
        if self._lifecycle_state is _TrackerLifecycle.BOUND:
            return None

        # Retain compatibility for tests and integrations that construct a
        # read-only tracker projection directly.  The identity fields must agree
        # exactly, so an alternate split of a colon-bearing key cannot resolve.
        entry = self.collector_statuses.get(identity.legacy_key)
        if (
            entry is not None
            and entry.dut_id == dut_id
            and entry.collector_id == collector_id
        ):
            return entry
        return None

    async def start_collector(self, dut_id: str, collector_id: str) -> None:
        """
        Mark a collector as running unless finalization has begun.

        The implementation uses ``dut_id`` and ``collector_id`` to mark a
        collector as running unless finalization has begun. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        async with self._lifecycle_lock:
            if not self._collector_mutation_allowed_unlocked():
                return
            await self._start_collector_unlocked(dut_id, collector_id)

    async def _start_collector_unlocked(self, dut_id: str, collector_id: str) -> None:
        """
        Mark a collector as started/running.

        The implementation uses ``dut_id`` and ``collector_id`` to mark a
        collector as started/running. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        entry = self._get_collector_status_entry(dut_id, collector_id)
        if entry is not None:
            if entry.status != CollectorStatus.PENDING:
                return

            # Update stats before changing status
            self.stats["pending_collectors"] -= 1

            entry.status = CollectorStatus.RUNNING
            entry.start_time = datetime.now()
            entry.exclusion_type = None
            self.stats["running_collectors"] += 1

            # Debug logging
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "CollectionStatusTracker",
                f"Started {dut_id}:{collector_id}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "CollectionStatusTracker",
                f"Stats after start: {self.stats}",
            )

            await self._update_status(dut_id)

    @staticmethod
    def _normalize_completion_status(status: Any) -> CollectorStatus:
        """
        Map legacy completion aliases to one terminal collector state.

        The implementation uses ``status`` to map legacy completion aliases to
        one terminal collector state.

        Args:
            status: Status consumed while the function attempts to map legacy
                completion aliases to one terminal collector state.

        Returns:
            A ``CollectorStatus`` representing completion status.
        """

        if status is CollectorStatus.NOT_RAN:
            return CollectorStatus.SKIPPED
        if isinstance(status, CollectorStatus) and status not in {
            CollectorStatus.PENDING,
            CollectorStatus.RUNNING,
        }:
            return status
        if status is True or status in (
            "success",
            "pass",
            "complete",
            "completed",
        ):
            return CollectorStatus.SUCCESS
        if status == "partial":
            return CollectorStatus.PARTIAL
        if status == "degraded":
            return CollectorStatus.DEGRADED
        if status is False or status in ("error", "fail"):
            return CollectorStatus.ERROR
        if status in ("skipped", "not_ran"):
            return CollectorStatus.SKIPPED
        if status in ("cancelled", "canceled"):
            return CollectorStatus.CANCELLED
        return CollectorStatus.ERROR

    @staticmethod
    def _terminal_counter_key(status: CollectorStatus) -> str:
        """
        Return the statistics counter owned by a terminal state.

        The implementation uses ``status`` to produce the statistics counter
        owned by a terminal state.

        Args:
            status: Status consumed while the function attempts to produce the
                statistics counter owned by a terminal state.

        Returns:
            The canonical terminal counter key text.
        """

        return {
            CollectorStatus.SUCCESS: "completed_collectors",
            CollectorStatus.DEGRADED: "degraded_collectors",
            CollectorStatus.PARTIAL: "partial_collectors",
            CollectorStatus.ERROR: "failed_collectors",
            CollectorStatus.SKIPPED: "skipped_collectors",
            CollectorStatus.CANCELLED: "cancelled_collectors",
            CollectorStatus.NOT_RAN: "skipped_collectors",
        }[status]

    @staticmethod
    def _merge_terminal_metadata(
        entry: CollectorStatusEntry,
        *,
        reason: str,
        execution_time: float,
        output_files: Optional[List[str]],
        diagnostic_files: Optional[List[str]],
        error_files: Optional[List[str]],
        all_files: Optional[List[str]],
        discovered_files: Optional[Dict[str, List[str]]],
        context: Optional[Dict[str, Any]],
        failure_category: Optional[str],
        failure_category_supplied: bool,
    ) -> bool:
        """
        Refresh terminal details without changing the terminal state.

        Stage completion can precede the outer execution wrapper that owns the
        full duration and artifact inventory. Meaningful same-status details may
        therefore replace earlier details, while omitted details preserve the
        existing projection and explicit empty inventories clear it.

        Args:
            entry: Entry object whose ``context``, ``discovered_files``,
                ``end_time``, ``exclusion_type``, and ``execution_time`` state
                is read while performing refresh terminal details without
                changing the terminal state.
            reason: Text supplied as reason in the format accepted by this
                function.
            execution_time: Numeric execution time used while the operation
                performs bounded accounting.
            output_files: Entries supplied as ``output_files`` without
                transferring container ownership.
            diagnostic_files: Entries supplied as ``diagnostic_files`` without
                transferring container ownership.
            error_files: Entries supplied as ``error_files`` without
                transferring container ownership.
            all_files: Entries supplied as ``all_files`` without transferring
                container ownership.
            discovered_files: Mapping supplying fields for refresh terminal
                details without changing the terminal state.
            context: Runtime context carrying state shared across this
                operation.
            failure_category: Text supplied as failure category in the format
                accepted by this function.
            failure_category_supplied: Whether failure category supplied is
                enabled or required for this operation.

        Returns:
            Whether the refresh terminal details without changing the terminal
            state operation succeeds.
        """

        changed = False
        refresh_end_time = entry.end_time is None
        if execution_time > 0 and entry.execution_time != execution_time:
            entry.execution_time = execution_time
            changed = True
            refresh_end_time = True
        if reason and entry.reason != reason:
            entry.reason = reason
            changed = True
            refresh_end_time = True
        # A same-state completion can still explicitly correct a provisional
        # category to absence, while an outer detail-only wrapper that omits
        # the field must not erase the service-owned value.
        if failure_category_supplied and entry.failure_category != failure_category:
            entry.failure_category = failure_category
            changed = True
            refresh_end_time = True

        for field_name, incoming in (
            ("output_files", output_files),
            ("diagnostic_files", diagnostic_files),
            ("error_files", error_files),
            ("all_files", all_files),
        ):
            # ``None`` means the caller has no projection for this field. An
            # explicit empty list is authoritative and must be able to clear a
            # provisional misclassification (for example, an error artifact
            # initially reported as a primary output).
            if incoming is None:
                continue
            normalized = list(incoming)
            if getattr(entry, field_name) != normalized:
                setattr(entry, field_name, normalized)
                changed = True
                refresh_end_time = True

        if discovered_files is not None and entry.discovered_files != discovered_files:
            entry.discovered_files = dict(discovered_files)
            changed = True
            refresh_end_time = True

        if context:
            current_context = (
                dict(entry.context) if isinstance(entry.context, dict) else {}
            )
            merged_context = dict(current_context)
            merged_context.update(context)
            if merged_context != current_context:
                entry.context = merged_context
                changed = True
                refresh_end_time = True
        if refresh_end_time and not entry.exclusion_type:
            entry.end_time = datetime.now()
            changed = True
        return changed

    async def complete_collector(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str = "",
        execution_time: float = 0.0,
        output_files: Optional[List[str]] = None,
        discovered_files: Optional[Dict[str, List[str]]] = None,
        context: Optional[Dict[str, Any]] = None,
        exclusion_type: Optional[str] = None,
        skip_status_update: bool = False,
        diagnostic_files: Optional[List[str]] = None,
        error_files: Optional[List[str]] = None,
        all_files: Optional[List[str]] = None,
        failure_category: Any = _FAILURE_CATEGORY_UNSET,
    ) -> None:
        """
        Complete a collector unless finalization has frozen tracker state.

        Terminal publication is already committed. A secondary diagnostic
        failure must not make finalization ambiguous.

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
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            discovered_files: Optional discovered files; ``None`` selects the
                function's default behavior.
            context: Runtime context carrying state shared across this
                operation.
            exclusion_type: Optional exclusion type; ``None`` selects the
                function's default behavior.
            skip_status_update: Whether skip status update is enabled or
                required for this operation.
            diagnostic_files: Optional diagnostic files; ``None`` selects the
                function's default behavior.
            error_files: Optional error files; ``None`` selects the function's
                default behavior.
            all_files: Optional all files; ``None`` selects the function's
                default behavior.
            failure_category: Failure category consumed while the function
                attempts to complete a collector unless finalization has frozen
                tracker state.
        """
        async with self._lifecycle_lock:
            if not self._collector_mutation_allowed_unlocked():
                try:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "CollectionStatusTracker",
                        f"Discarding late completion after tracker finalization "
                        f"for {dut_id}:{collector_id} (status={status})",
                    )
                except Exception:
                    # Terminal publication is already committed. A secondary
                    # diagnostic failure must not make finalization ambiguous.
                    pass
                return
            await self._complete_collector_unlocked(
                dut_id,
                collector_id,
                status,
                reason=reason,
                execution_time=execution_time,
                output_files=output_files,
                discovered_files=discovered_files,
                context=context,
                exclusion_type=exclusion_type,
                skip_status_update=skip_status_update,
                diagnostic_files=diagnostic_files,
                error_files=error_files,
                all_files=all_files,
                failure_category=failure_category,
            )

    async def _complete_collector_unlocked(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str = "",
        execution_time: float = 0.0,
        output_files: Optional[List[str]] = None,
        discovered_files: Optional[Dict[str, List[str]]] = None,
        context: Optional[Dict[str, Any]] = None,
        exclusion_type: Optional[str] = None,
        skip_status_update: bool = False,
        diagnostic_files: Optional[List[str]] = None,
        error_files: Optional[List[str]] = None,
        all_files: Optional[List[str]] = None,
        failure_category: Any = _FAILURE_CATEGORY_UNSET,
    ) -> None:
        """
        Mark a collector as completed with final status.

        The planning mismatch remains fail-closed even when its optional
        diagnostic cannot be written.

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
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            discovered_files: Optional discovered files; ``None`` selects the
                function's default behavior.
            context: Runtime context carrying state shared across this
                operation.
            exclusion_type: Optional exclusion type; ``None`` selects the
                function's default behavior.
            skip_status_update: Whether skip status update is enabled or
                required for this operation.
            diagnostic_files: Optional diagnostic files; ``None`` selects the
                function's default behavior.
            error_files: Optional error files; ``None`` selects the function's
                default behavior.
            all_files: Optional all files; ``None`` selects the function's
                default behavior.
            failure_category: Failure category consumed while the function
                attempts to mark a collector as completed with final status.
        """
        entry = self._get_collector_status_entry(dut_id, collector_id)
        if entry is None:
            try:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "CollectionStatusTracker",
                    f"Discarding completion for unplanned pair "
                    f"{dut_id}:{collector_id} (status={status})",
                )
            except Exception:
                # The planning mismatch remains fail-closed even when its
                # optional diagnostic cannot be written.
                pass
            return

        next_status = self._normalize_completion_status(status)
        sanitizer = getattr(getattr(self.logger, "sanitizer", None), "sanitize", None)
        reason = sanitize_terminal_collector_reason(
            next_status,
            reason,
            sanitizer=sanitizer if callable(sanitizer) else None,
        )
        failure_category_supplied = failure_category is not _FAILURE_CATEGORY_UNSET
        category_source = failure_category if failure_category_supplied else None
        if (
            not failure_category_supplied
            and isinstance(context, dict)
            and "failure_category" in context
        ):
            category_source = context.get("failure_category")
            failure_category_supplied = True
        normalized_failure_category = (
            normalize_collector_failure_category(next_status, category_source)
            if failure_category_supplied
            else None
        )
        previous_status = entry.status
        previous_valid_not_applicable = is_valid_not_applicable_skip(
            previous_status,
            entry.context,
        )
        terminal_statuses = {
            CollectorStatus.SUCCESS,
            CollectorStatus.DEGRADED,
            CollectorStatus.PARTIAL,
            CollectorStatus.ERROR,
            CollectorStatus.SKIPPED,
            CollectorStatus.CANCELLED,
            CollectorStatus.NOT_RAN,
        }

        if previous_status in terminal_statuses:
            # A planning exclusion has no execution phase to enrich.  Once it
            # is terminal, later service callbacks cannot attach evidence or
            # turn it into a runtime result.
            if entry.exclusion_type:
                return

            if next_status is previous_status:
                merge_reason = reason
                canonical_failure_reason = sanitize_terminal_collector_reason(
                    next_status, ""
                )
                if (
                    reason == canonical_failure_reason
                    and entry.reason
                    and entry.reason != canonical_failure_reason
                ):
                    # A duplicate blank/success-only callback cannot erase an
                    # already-recorded failure diagnostic.
                    merge_reason = ""
                changed = self._merge_terminal_metadata(
                    entry,
                    reason=merge_reason,
                    execution_time=execution_time,
                    output_files=output_files,
                    diagnostic_files=diagnostic_files,
                    error_files=error_files,
                    all_files=all_files,
                    discovered_files=discovered_files,
                    context=context,
                    failure_category=normalized_failure_category,
                    failure_category_supplied=failure_category_supplied,
                )
                current_valid_not_applicable = is_valid_not_applicable_skip(
                    entry.status,
                    entry.context,
                )
                if current_valid_not_applicable != previous_valid_not_applicable:
                    adjustment = 1 if current_valid_not_applicable else -1
                    self.stats["capability_excluded"] += adjustment
                    changed = True
                if changed:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "CollectionStatusTracker",
                        f"Refreshed duplicate completion metadata for "
                        f"{dut_id}:{collector_id} with status {entry.status.value}",
                    )
                    if not skip_status_update:
                        await self._update_status(dut_id)
                return

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "CollectionStatusTracker",
                f"Correcting terminal status for {dut_id}:{collector_id} "
                f"from {previous_status.value} to {next_status.value}",
            )
            self.stats[self._terminal_counter_key(previous_status)] -= 1

        normalized_exclusion_type = (
            str(exclusion_type).strip() if exclusion_type is not None else None
        )
        has_execution_evidence = bool(
            entry.start_time is not None
            or execution_time
            or output_files
            or diagnostic_files
            or error_files
            or all_files
            or discovered_files
            or context
        )
        is_preexecution_exclusion = bool(
            previous_status is CollectorStatus.PENDING
            and normalized_exclusion_type
            and next_status is CollectorStatus.SKIPPED
            and not has_execution_evidence
        )

        entry.status = next_status
        entry.reason = reason
        entry.failure_category = normalized_failure_category
        entry.exclusion_type = (
            normalized_exclusion_type if is_preexecution_exclusion else None
        )
        self.stats[self._terminal_counter_key(next_status)] += 1

        if is_preexecution_exclusion:
            entry.end_time = None
            entry.execution_time = 0.0
            entry.output_files = []
            entry.diagnostic_files = []
            entry.error_files = []
            entry.all_files = []
            entry.discovered_files = {}
            entry.context = {}
            entry.failure_category = None
        else:
            entry.end_time = datetime.now()
            if previous_status not in terminal_statuses or execution_time > 0:
                entry.execution_time = execution_time
            if output_files is not None:
                entry.output_files = list(output_files)
            if diagnostic_files is not None:
                entry.diagnostic_files = list(diagnostic_files)
            if error_files is not None:
                entry.error_files = list(error_files)
            if all_files is not None:
                entry.all_files = list(all_files)
            if discovered_files is not None:
                entry.discovered_files = dict(discovered_files)
            if context is not None:
                entry.context = dict(context)

        current_valid_not_applicable = is_valid_not_applicable_skip(
            entry.status,
            entry.context,
        )
        if current_valid_not_applicable != previous_valid_not_applicable:
            adjustment = 1 if current_valid_not_applicable else -1
            self.stats["capability_excluded"] += adjustment

        if previous_status is CollectorStatus.RUNNING:
            self.stats["running_collectors"] -= 1
        elif previous_status is CollectorStatus.PENDING:
            self.stats["pending_collectors"] -= 1

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "CollectionStatusTracker",
            f"Completed {dut_id}:{collector_id} with status '{status}' -> "
            f"{entry.status.value}, previous: {previous_status.value}",
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "CollectionStatusTracker",
            f"Stats after completion: {self.stats}",
        )

        if not skip_status_update:
            await self._update_status(dut_id)

    async def increment_baseboard_excluded(
        self, skip_status_update: bool = False
    ) -> None:
        """
        Increment the count of collectors excluded by baseboard filtering.

        The implementation uses ``skip_status_update`` to increment the count of
        collectors excluded by baseboard filtering. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            skip_status_update: Whether skip status update is enabled or
                required for this operation.
        """
        async with self._lifecycle_lock:
            if not self._collector_mutation_allowed_unlocked():
                return
            self.stats["baseboard_excluded"] += 1

            if not skip_status_update:
                await self._update_status()

    async def increment_config_excluded(self, skip_status_update: bool = False) -> None:
        """
        Increment the count of collectors excluded by config filtering.

        The implementation uses ``skip_status_update`` to increment the count of
        collectors excluded by config filtering. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            skip_status_update: Whether skip status update is enabled or
                required for this operation.
        """
        async with self._lifecycle_lock:
            if not self._collector_mutation_allowed_unlocked():
                return
            self.stats["config_excluded"] += 1

            if not skip_status_update:
                await self._update_status()

    async def increment_capability_excluded(
        self, skip_status_update: bool = False
    ) -> None:
        """
        Increment the count of collectors excluded by capability discovery.

        The implementation uses ``skip_status_update`` to increment the count of
        collectors excluded by capability discovery. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            skip_status_update: Whether skip status update is enabled or
                required for this operation.
        """
        async with self._lifecycle_lock:
            if not self._collector_mutation_allowed_unlocked():
                return
            self.stats["capability_excluded"] += 1

            if not skip_status_update:
                await self._update_status()

    def _collector_duration_seconds(
        self, entry: CollectorStatusEntry
    ) -> Optional[float]:
        """
        Return the authoritative elapsed time available for a collector.

        TimingManager uses a monotonic clock around the collector and is the
        canonical duration source. Its scalar duration query keeps status
        refreshes independent of the size of recorded operation history.
        Older timing providers can still supply the detailed timing mapping.
        ``execution_time`` is retained as the
        compatibility fallback for callers without detailed timing data.
        Wall-clock timestamps are last because duplicate finalization updates
        can move ``end_time`` after collector execution has already stopped.

        Args:
            entry: Entry object whose ``collector_id``, ``dut_id``,
                ``end_time``, ``exclusion_type``, and ``execution_time`` state
                is read while performing authoritative elapsed time available
                for a collector.

        Returns:
            The numeric collector duration seconds, or ``None`` when the
            requested value is unavailable.
        """
        if entry.exclusion_type:
            return None

        if self.timing_manager:
            try:
                duration_reader = getattr(
                    self.timing_manager, "get_collector_duration_seconds", None
                )
                if callable(duration_reader):
                    duration = float(duration_reader(entry.dut_id, entry.collector_id))
                else:
                    detailed_timing = self.timing_manager.get_collector_timing(
                        entry.dut_id,
                        entry.collector_id,
                    )
                    duration = float(detailed_timing["wall_clock_duration_seconds"])
            except Exception:
                duration = -1.0
            if duration >= 0:
                return duration

        if entry.execution_time > 0:
            return entry.execution_time
        if entry.start_time and entry.end_time:
            return max((entry.end_time - entry.start_time).total_seconds(), 0.0)
        return None

    def get_dut_collector_span_seconds(self, dut_id: str) -> Optional[float]:
        """
        Return the wall-clock span of executed collectors for one DUT.

        The span begins with the first collector that actually started on the
        requested DUT and ends with its last completed collector. Pre-execution
        exclusions and skips without a start time do not inflate the value.
        Callers use this read-only snapshot after collector scheduling has
        stopped; canonical per-collector timing remains owned by the tracker and
        timing manager.

        Args:
            dut_id: Stable DUT identifier used to select tracker entries.

        Returns:
            The non-negative collector wall-clock span in seconds, or ``None``
            when the DUT has no completed collector interval.
        """

        normalized_dut_id = str(dut_id)
        executed_entries = [
            entry
            for collector_id in self.dut_collectors.get(normalized_dut_id, set())
            if (
                entry := self._get_collector_status_entry(
                    normalized_dut_id,
                    collector_id,
                )
            )
            is not None
            and not entry.exclusion_type
            and entry.start_time is not None
            and entry.end_time is not None
        ]
        if not executed_entries:
            return None
        first_start = min(entry.start_time for entry in executed_entries)
        last_end = max(entry.end_time for entry in executed_entries)
        return max((last_end - first_start).total_seconds(), 0.0)

    def _format_collector_duration(self, entry: CollectorStatusEntry) -> str:
        """
        Format a collector duration consistently across text summaries.

        The implementation uses ``entry`` to format a collector duration
        consistently across text summaries. The source value keeps its ownership
        while the normalized representation is returned separately.

        Args:
            entry: Entry evaluated while performing collector duration
                consistently across text summaries.

        Returns:
            The canonical collector duration text.
        """
        duration = self._collector_duration_seconds(entry)
        return f"{duration:.1f}s" if duration is not None else "N/A"

    @staticmethod
    def _collector_sort_key(entry: CollectorStatusEntry) -> tuple:
        """
        Return a natural-sort key (for example R2 before R10).

        After applying local validation, the function forwards ``entry`` to
        ``tuple`` and preserves its return and exception contract.

        Args:
            entry: Entry object whose ``collector_id`` state is read while
                performing natural-sort key (for example R2 before R10).

        Returns:
            A ``tuple`` representing collector sort key.
        """
        return tuple(
            int(part) if part.isdigit() else part.casefold()
            for part in re.split(r"(\d+)", entry.collector_id)
        )

    @staticmethod
    def _count_context_items(value: Any) -> int:
        """
        Normalize scalar or container context values to a non-negative count.

        The implementation uses ``value`` to normalize scalar or container
        context values to a non-negative count. The source value keeps its
        ownership while the normalized representation is returned separately.

        Args:
            value: Value evaluated while performing scalar or container context
                values to a non-negative count.

        Returns:
            The numeric count context items value.
        """
        if value is None:
            return 0
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return max(int(value), 0)
        if isinstance(value, str):
            try:
                return max(int(value), 0)
            except ValueError:
                return int(bool(value))
        try:
            return max(len(value), 0)
        except TypeError:
            return 1

    @classmethod
    def _format_collector_scope(cls, entry: CollectorStatusEntry) -> str:
        """
        Return a compact scope count without exposing raw system URIs.

        The implementation uses ``entry`` to produce a compact scope count
        without exposing raw system URIs.

        Args:
            entry: Entry object whose ``context`` state is read while performing
                compact scope count without exposing raw system URIs.

        Returns:
            The canonical collector scope text.
        """
        context = entry.context or {}
        if "collections_processed" in context:
            count = cls._count_context_items(context["collections_processed"])
            suffix = "collection" if count == 1 else "collections"
            return f"{count} {suffix}"

        scope_fields = (
            ("filtered_systems", "system", "systems"),
            ("entities_processed", "entity", "entities"),
            ("successful_collections", "collection", "collections"),
        )
        zero_scope = None
        for field_name, singular, plural in scope_fields:
            if field_name in context:
                count = cls._count_context_items(context[field_name])
                suffix = singular if count == 1 else plural
                scope = f"{count} {suffix}"
                if count > 0:
                    return scope
                if zero_scope is None:
                    zero_scope = scope
        return zero_scope or "N/A"

    @classmethod
    def _scope_context_counts(cls, entry: CollectorStatusEntry) -> Dict[str, int]:
        """
        Return JSON-safe scope counts without persisting raw target context.

        The implementation uses ``entry`` to produce JSON-safe scope counts
        without persisting raw target context.

        Args:
            entry: Entry object whose ``context`` state is read while performing
                JSON-safe scope counts without persisting raw target context.

        Returns:
            A mapping containing scope context counts.
        """
        context = entry.context or {}
        return {
            field_name: cls._count_context_items(context[field_name])
            for field_name in _SCOPE_CONTEXT_FIELDS
            if field_name in context
        }

    @staticmethod
    def _fixed_width_cell(value: Any, width: int) -> str:
        """
        Render one bounded table cell so later columns remain aligned.

        The implementation uses ``value`` and ``width`` to render one bounded
        table cell so later columns remain aligned. The source value keeps its
        ownership while the normalized representation is returned separately.

        Args:
            value: Value evaluated while performing one bounded table cell so
                later columns remain aligned.
            width: Numeric width used while the operation performs bounded
                accounting.

        Returns:
            The canonical fixed width cell text.
        """
        text = str(value)
        if len(text) > width:
            text = f"{text[: width - 3]}..." if width > 3 else text[:width]
        return f"{text:<{width}}"

    @staticmethod
    def _single_line_text(value: Any) -> str:
        """
        Collapse embedded whitespace so one collector occupies one table row.

        After applying local validation, the function forwards ``value`` to
        ``join`` and preserves its return and exception contract.

        Args:
            value: Value evaluated while performing collapse embedded whitespace
                so one collector occupies one table row.

        Returns:
            The canonical single line text.
        """
        return " ".join(str(value or "").split())

    def _observe_completed_progress(
        self, task: asyncio.Task[CapturedAwaitableOutcome]
    ) -> Optional[BaseException]:
        """
        Consume a completed live writer once and release its scheduling slot.

        A callback can observe the writer while an explicit flush is joining it.
        Only the current owner consumes its outcome, preventing duplicate failure
        diagnostics and preventing an older flush from clearing a newer writer.
        Failed batches remain dirty for the next callback or explicit retry.

        Args:
            task: Exact owned live writer whose completion is being observed.

        Returns:
            The consumed failure, or ``None`` for success or an already observed
            task. Ordinary failures are retained as bounded finalization evidence;
            callers still decide how to propagate process-control exceptions.

        Side Effects:
            Clears the completed writer before inspecting its result and records
            each ordinary publication failure at most once.
        """
        if self._progress_task is not task or not task.done():
            return None
        self._progress_task = None
        try:
            outcome = task.result()
            error = (
                outcome.error
                if type(outcome) is CapturedAwaitableOutcome
                else RuntimeError("Live status writer returned a malformed outcome")
            )
        except BaseException as outcome_error:
            error = outcome_error
        if isinstance(error, Exception) and not is_control_flow_exception(error):
            self._record_finalization_diagnostic(
                "live_status_snapshot", error, diagnostic_only=True
            )
        return error

    def _queue_progress_update(self, dut_id: Optional[str] = None) -> None:
        """
        Coalesce live changes into one owned writer without delaying collectors.

        The pending set is bounded by the validated DUT roster. A completed
        writer is consumed before another is scheduled. Ordinary live snapshot
        failures become bounded diagnostics and restored dirty DUTs are retried;
        they cannot change unrelated collectors' authoritative results.

        Args:
            dut_id: Changed DUT, or ``None`` to refresh the complete roster.

        Raises:
            BaseException: If the previous writer observed a process-control
                exception, after its scheduling slot has been released.

        Side Effects:
            Starts at most one task, retained until observed and joined.
        """

        if self._progress_task is not None and self._progress_task.done():
            error = self._observe_completed_progress(self._progress_task)
            if error is not None and (
                not isinstance(error, Exception) or is_control_flow_exception(error)
            ):
                raise error
        if dut_id is None:
            self._pending_progress_duts.update(self.dut_collectors)
            self._progress_full_snapshot_pending = True
        elif dut_id in self.dut_collectors:
            self._pending_progress_duts.add(dut_id)
        if self._progress_task is None and self._pending_progress_duts:
            self._progress_task = asyncio.create_task(
                capture_owned_awaitable(self._persist_queued_progress()),
                name="nvdebug-live-status",
            )

    def _register_live_dut_parents(self, dut_id: str) -> None:
        """
        Pin the two publication parents for one deferred DUT snapshot.

        All creation and no-follow identity checks use the existing descriptor
        walker. Repeated updates retain the original identities and revalidate
        them at each write rather than adopting a replacement directory.

        Args:
            dut_id: Declared DUT whose output and metadata directories are needed.

        Raises:
            OSError: If a directory cannot be opened or created.
            RuntimeError: If the output hierarchy changed or is unsafe.
        """

        for destination in (
            self.dut_summary_files[dut_id],
            self.dut_status_files[dut_id],
        ):
            relative_parent = self._relative_publication_path(destination).parent
            if relative_parent not in self._publication_parent_identities:
                self._register_publication_parent(destination)

    async def _persist_queued_progress(self) -> None:
        """
        Persist the latest rack state while new callbacks continue in memory.

        Each pass consumes a bounded set of dirty DUTs. Updates arriving during
        storage I/O request another pass, so intermediate events can coalesce
        without losing the final state. Live files use atomic replacement;
        terminal evidence retains the separate durable transaction.

        Raises:
            BaseException: If required status publication fails. The owning task
                captures the error for callbacks, flush, or finalization.

        Side Effects:
            Creates validated DUT directories and replaces readable status files.
        """

        async with self._status_update_lock:
            while self._pending_progress_duts:
                batch = self._pending_progress_duts.copy()
                self._pending_progress_duts.difference_update(batch)
                force_aggregate = self._progress_full_snapshot_pending
                self._progress_full_snapshot_pending = False
                stats_before = dict(self.stats)
                try:
                    aggregate_due = (
                        force_aggregate
                        or self._last_aggregate_snapshot_at is None
                        or time.monotonic() - self._last_aggregate_snapshot_at
                        >= self._aggregate_snapshot_interval_seconds
                    )
                    if aggregate_due and not await self._save_aggregate_snapshot():
                        raise RuntimeError("Failed to publish live aggregate status")
                    for dut_id in self.dut_collectors:
                        if dut_id not in batch:
                            continue
                        await run_managed_filesystem_operation(
                            self._register_live_dut_parents, dut_id
                        )
                        await self._save_dut_status_files(dut_id)
                        await self._save_dut_summary_files(dut_id)
                    # A slow initial pass or the final collector must not leave
                    # the aggregate stuck at its pre-write counts. Other rack
                    # events retain the configured aggregate refresh interval.
                    settled = not (
                        self.stats["pending_collectors"]
                        or self.stats["running_collectors"]
                    )
                    if self.stats != stats_before and (force_aggregate or settled):
                        if not await self._save_aggregate_snapshot():
                            raise RuntimeError(
                                "Failed to publish live aggregate status"
                            )
                except BaseException:
                    self._pending_progress_duts.update(batch)
                    self._progress_full_snapshot_pending |= force_aggregate
                    raise

    async def flush_progress(self, *, raise_on_error: bool = True) -> None:
        """
        Join live publication before reading persisted state or finalizing it.

        Cancellation waits for the owned writer and its filesystem workers to
        finish before propagating. Terminal publication calls this barrier before
        creating a candidate, preventing a delayed live write from replacing
        terminal evidence. An authoritative snapshot may supersede a failed live
        leaf after this barrier; its own required writes remain fail-closed.

        Args:
            raise_on_error: Report ordinary live publication errors to explicit
                callers. Authoritative publication disables this after joining
                the writer so it can independently attempt its complete snapshot.
                A failed live batch remains dirty until retry or terminal commit.

        Raises:
            BaseException: If the caller's wait or a process-control operation
                fails, or an ordinary publication fails with strict reporting.
        """

        if self._progress_task is None and self._pending_progress_duts:
            self._queue_progress_update()
        while self._progress_task is not None:
            task = self._progress_task
            error = None
            try:
                await drain_owned_tasks((task,), cancel_on_wait_error=False)
            finally:
                error = self._observe_completed_progress(task)
            if error is not None:
                if (
                    raise_on_error
                    or not isinstance(error, Exception)
                    or is_control_flow_exception(error)
                ):
                    raise error
                # Do not create an unbounded retry loop during finalization.
                # The terminal transaction renders all current DUT state itself.
                return

    async def aclose(self) -> None:
        """
        Drain live status work and release descriptors on every cleanup path.

        Cleanup attempts descriptor release even when the flush fails. The
        shared exception selector retains cancellation and other process-control
        errors instead of allowing a later close failure to replace them.

        Raises:
            BaseException: If flushing or descriptor cleanup fails, preserving
                process-control precedence when both operations fail.
        """

        errors: List[BaseException] = []
        try:
            await self.flush_progress()
        except BaseException as error:
            errors.append(error)
        try:
            self.close()
        except BaseException as error:
            errors.append(error)
        if errors:
            raise select_authoritative_exception(errors)

    async def _update_status(self, dut_id: Optional[str] = None) -> None:
        """
        Persist status and update the live display.

        Refresh the display immediately. Rack callbacks coalesce updates through
        the owned writer; omitting ``dut_id`` requests the complete roster and
        aggregate. Call ``flush_progress`` when persisted files are needed before
        finalization. Small single-DUT runs retain immediate full snapshots.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if self._display_enabled and self._live_display:
            try:
                self._live_display.update(self._generate_status_table())
            except Exception:
                self._live_display = None
                self._display_enabled = False
        if self._deferred_progress_enabled and not self._finalized:
            self._queue_progress_update(dut_id)
            return
        await self.flush_progress()
        async with self._status_update_lock:
            force_full_snapshot = dut_id is None
            use_incremental_persistence = (
                not force_full_snapshot
                and len(self.collector_statuses) >= self._incremental_status_min_entries
            )

            if use_incremental_persistence:
                await self._save_dut_status_files(dut_id)
                await self._save_dut_summary_files(dut_id)

                now = time.monotonic()
                aggregate_snapshot_due = (
                    self._last_aggregate_snapshot_at is None
                    or self._aggregate_snapshot_interval_seconds == 0
                    or now - self._last_aggregate_snapshot_at
                    >= self._aggregate_snapshot_interval_seconds
                )
                if aggregate_snapshot_due:
                    await self._save_aggregate_snapshot()
            else:
                await self._save_aggregate_snapshot()
                await self._save_dut_status_files()
                await self._save_dut_summary_files()

    async def _save_aggregate_snapshot(self, *, durable: bool = False) -> bool:
        """
        Save both aggregate files and record only a complete snapshot.

        Measure the interval from completion of the snapshot. A slow filesystem
        must not make the next queued event immediately due.

        Args:
            durable: Whether durable is enabled or required for this operation.

        Returns:
            Whether the both aggregate files and record only a complete snapshot
            operation succeeds.
        """
        if durable:
            status_saved = await self._save_global_status_file(durable=True)
            summary_saved = await self._save_global_summary_file(durable=True)
        else:
            status_saved = await self._save_global_status_file()
            summary_saved = await self._save_global_summary_file()
        if status_saved and summary_saved:
            # Measure the interval from completion of the snapshot.  A slow
            # filesystem must not make the next queued event immediately due.
            self._last_aggregate_snapshot_at = time.monotonic()
            return True
        return False

    async def _save_global_status_file(self, *, durable: bool = False) -> bool:
        """
        Save detailed global status to JSON file in .metadata directory.

        Single source of truth for run-level accounting.

        Args:
            durable: Whether durable is enabled or required for this operation.

        Returns:
            Whether the detailed global status to JSON file in .metadata
            directory operation succeeds.
        """
        async with self._file_lock:
            try:
                # Single source of truth for run-level accounting.
                aligned = self.compute_aligned_stats()
                snapshot_generation, terminal_finalized = self._snapshot_marker()

                # Build an aligned stats view for JSON consumers
                stats_aligned = dict(self.stats)
                stats_aligned["skipped_collectors"] = aligned["skipped"]
                stats_aligned["cancelled_collectors"] = aligned.get("cancelled", 0)
                stats_aligned["filtered_out_collectors"] = aligned["filtered_out"]
                stats_aligned["collectors_to_run"] = aligned["collectors_to_run"]

                status_data = {
                    "metadata": {
                        "last_updated": datetime.now().isoformat(),
                        "stats": stats_aligned,
                        "total_duts": len(self.dut_collectors),
                        "dut_roster": list(self._declared_dut_ids or ()),
                        "total_collectors": aligned["total"],
                        "collectors_to_run": aligned["collectors_to_run"],
                        "filtered_out": aligned["filtered_out"],
                        "run_outcome": dict(self.run_outcome),
                        "run_result": (
                            self.run_result.to_dict()
                            if self.run_result is not None
                            else None
                        ),
                        "collector_records_location": "per_dut",
                        "snapshot_generation": snapshot_generation,
                        "terminal_finalized": terminal_finalized,
                    },
                    # Per-DUT status files are authoritative for collector rows.
                    # Keeping a second run-wide copy makes the supported
                    # 500-DUT catalog exceed the bounded reader contract.
                    "collectors": {},
                }

                await self._write_snapshot_leaf_async(
                    self.global_status_file,
                    status_data,
                    durable=durable,
                )
                return True
            except Exception as e:
                if durable:
                    raise
                # Preserve root context while keeping required output fail-closed.
                print(f"Warning: Failed to save global status file: {e}")
                raise

    async def _save_run_result_files(self, *, durable: bool = False) -> bool:
        """
        Publish identical canonical result documents at root and per DUT.

        The implementation uses ``durable`` to publish identical canonical
        result documents at root and per DUT. Success is reported only after the
        owning output boundary has completed its required write or publication
        step. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind. If the function cannot publish
        identical canonical result documents at root and per DUT, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            durable: Whether durable is enabled or required for this operation.

        Returns:
            Whether the identical canonical result documents at root and per DUT
            operation succeeds.

        Raises:
            RuntimeError: If per-DUT RunResult destination is unavailable.
        """

        async with self._file_lock:
            document: Dict[str, Any]
            if self.run_result is None:
                document = {
                    "schema_version": "1.0",
                    "state": "candidate_pending",
                }
            else:
                document = self.run_result.to_dict()
            await self._write_snapshot_leaf_async(
                self.global_run_result_file,
                document,
                durable=durable,
            )
            for dut_id in self._declared_dut_ids or ():
                destination = self.dut_run_result_files.get(dut_id)
                if destination is None:
                    raise RuntimeError("Per-DUT RunResult destination is unavailable")
                await self._write_snapshot_leaf_async(
                    destination,
                    document,
                    durable=durable,
                )
            return True

    async def _save_dut_status_files(
        self, dut_id: Optional[str] = None, *, durable: bool = False
    ) -> bool:
        """
        Save one or all DUT-specific status files to JSON.

        The implementation uses ``dut_id`` and ``durable`` to save one or all
        DUT-specific status files to JSON. Success is reported only after the
        owning output boundary has completed its required write or publication
        step. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            durable: Whether durable is enabled or required for this operation.

        Returns:
            Whether the one or all DUT-specific status files to JSON operation
            succeeds.
        """
        all_saved = True
        async with self._file_lock:
            target_dut_ids = (
                [dut_id] if dut_id is not None else list(self.dut_collectors)
            )
            for target_dut_id in target_dut_ids:
                try:
                    # Get collectors for this DUT
                    discarded_counts: List[int] = []
                    dut_collectors = {}
                    for collector_id in sorted(
                        self.dut_collectors.get(target_dut_id, set())
                    ):
                        entry = self._get_collector_status_entry(
                            target_dut_id, collector_id
                        )
                        if entry is None:
                            continue
                        legacy_key = _CollectorIdentity(
                            target_dut_id, collector_id
                        ).legacy_key
                        dut_collectors[legacy_key] = self._collector_status_to_dut_dict(
                            target_dut_id,
                            entry,
                            discarded_counts=discarded_counts,
                        )
                    discarded_total = sum(discarded_counts)
                    if discarded_total:
                        await self._log_projection_summary(
                            "WARNING",
                            "Discarded "
                            f"{discarded_total} unsafe or missing artifact path(s) "
                            f"while saving status for {target_dut_id}",
                        )

                    dut_stats = self._get_dut_stats(target_dut_id)
                    snapshot_generation, terminal_finalized = self._snapshot_marker()
                    # Derive collectors_to_run for this DUT
                    collectors_to_run = max(
                        dut_stats["total"] - dut_stats.get("filtered_out", 0),
                        0,
                    )

                    # Also include collectors_to_run inside the stats block for parity
                    dut_stats_with_run = dict(dut_stats)
                    dut_stats_with_run["collectors_to_run"] = collectors_to_run
                    dut_stats_with_run["cancelled_collectors"] = dut_stats.get(
                        "cancelled", 0
                    )

                    dut_status_data = {
                        "metadata": {
                            "dut_id": target_dut_id,
                            "last_updated": datetime.now().isoformat(),
                            "stats": dut_stats_with_run,
                            "total_collectors": len(dut_collectors),
                            "collectors_to_run": collectors_to_run,
                            "filtered_out": dut_stats.get("filtered_out", 0),
                            "run_outcome": dict(self.run_outcome),
                            "run_result": (
                                self.run_result.to_dict()
                                if self.run_result is not None
                                else None
                            ),
                            "snapshot_generation": snapshot_generation,
                            "terminal_finalized": terminal_finalized,
                        },
                        "collectors": dut_collectors,
                    }

                    status_file = self.dut_status_files.get(target_dut_id)
                    if status_file:
                        await self._write_snapshot_leaf_async(
                            status_file,
                            dut_status_data,
                            durable=durable,
                        )
                    else:
                        all_saved = False

                except Exception as e:
                    if durable:
                        raise
                    # Log error but don't fail
                    print(
                        "Warning: Failed to save DUT status file for "
                        f"{target_dut_id}: {e}"
                    )
                    raise
        return all_saved

    def _collector_status_to_dut_dict(
        self,
        dut_id: str,
        entry: CollectorStatusEntry,
        *,
        discarded_counts: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """
        Convert a collector status entry to the per-DUT JSON representation.

        File references are stored relative to the bundle root so every metadata
        producer uses the same portable path namespace.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            entry: Entry object whose ``to_dict`` state is read while performing
                collector status entry to the per-DUT JSON representation.
            discarded_counts: Optional list receiving rejected artifact counts
                for one operator-visible aggregate warning.

        Returns:
            The validated ``data``.
        """
        data = entry.to_dict()
        safe_dut_id = run_tree_dut_component(dut_id)
        discard_observer = (
            discarded_counts.append if discarded_counts is not None else None
        )
        # Internal selection/preflight classification retains the original
        # diagnostic until the plan outcome is decided. Persist only the
        # scrubbed bounded projection so the post-snapshot privacy pass never
        # has to mutate a receipt-bound status leaf.
        data["reason"] = self._sanitize_run_outcome_reason(data.get("reason", ""))
        canonical_duration = self._collector_duration_seconds(entry)
        if canonical_duration is not None:
            data["execution_time"] = canonical_duration
        for field_name in (
            "output_files",
            "diagnostic_files",
            "error_files",
            "all_files",
        ):
            data[field_name] = normalize_artifact_file_list(
                data.get(field_name, []),
                self.output_dir,
                dut_id=safe_dut_id,
                on_discarded=discard_observer,
            )
        data["discovered_files"] = self._normalize_discovered_files_for_dut(
            safe_dut_id,
            data.get("discovered_files", {}),
            discarded_counts=discarded_counts,
        )
        scope_context_counts = self._scope_context_counts(entry)
        if scope_context_counts:
            data["scope"] = self._format_collector_scope(entry)
            data["scope_context_counts"] = scope_context_counts
        return data

    def _normalize_discovered_files_for_dut(
        self,
        dut_id: str,
        discovered_files: Dict[str, List[str]],
        *,
        discarded_counts: Optional[List[int]] = None,
    ) -> Dict[str, List[str]]:
        """
        Normalize discovered file values and derive their bundle-relative groups.

        The implementation uses ``dut_id`` and ``discovered_files`` to normalize
        discovered file values and derive their bundle-relative groups. The
        source value keeps its ownership while the normalized representation is
        returned separately.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            discovered_files: Mapping supplying fields for discovered file
                values and derive their bundle-relative groups.
            discarded_counts: Optional list receiving rejected artifact counts.

        Returns:
            The validated ``normalized``.
        """
        normalized: Dict[str, List[str]] = {}
        for files in (discovered_files or {}).values():
            for normalized_file in normalize_artifact_file_list(
                files,
                self.output_dir,
                dut_id=run_tree_dut_component(dut_id),
                on_discarded=(
                    discarded_counts.append if discarded_counts is not None else None
                ),
            ):
                normalized_folder = Path(normalized_file).parent.as_posix()
                normalized.setdefault(normalized_folder, [])
                if normalized_file not in normalized[normalized_folder]:
                    normalized[normalized_folder].append(normalized_file)
        return normalized

    def _to_dut_relative_path(self, dut_id: str, path_value: Any) -> str:
        """
        Return a DUT-relative path when an absolute path is inside the DUT log dir.

        Paths outside the DUT log directory are intentionally preserved. This
        avoids emitting misleading ``../`` paths for external references.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            path_value: Path value consumed while the function attempts to
                produce a DUT-relative path when an absolute path is inside the
                DUT log dir.

        Returns:
            The canonical DUT relative path.
        """
        path_str = str(path_value)
        if not path_str:
            return path_str

        candidate = Path(path_str)
        if not candidate.is_absolute():
            return candidate.as_posix()

        dut_log_dir = (self.output_dir / run_tree_dut_component(dut_id)).resolve(
            strict=False
        )
        try:
            relative_path = candidate.resolve(strict=False).relative_to(dut_log_dir)
        except ValueError:
            return path_str
        return relative_path.as_posix()

    async def _save_global_summary_file(self, *, durable: bool = False) -> bool:
        """
        Save human-readable global summary to text file in .metadata directory.

        Overall statistics use the same aligned accounting source.

        Args:
            durable: Whether durable is enabled or required for this operation.

        Returns:
            Whether the human-readable global summary to text file in .metadata
            directory operation succeeds.
        """
        async with self._file_lock:
            try:
                snapshot_generation, terminal_finalized = self._snapshot_marker()
                summary_lines = []
                summary_lines.append("Global Collection Status Summary")
                summary_lines.append("=" * 50)
                summary_lines.append(
                    f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                summary_lines.append(f"Snapshot Generation: {snapshot_generation}")
                summary_lines.append(
                    f"Terminal Finalized: {str(terminal_finalized).lower()}"
                )
                if self.run_result is not None:
                    summary_lines.append(
                        f"Runtime Status: {self.run_result.runtime_status.value}"
                    )
                    summary_lines.append(
                        f"Collection Status: {self.run_result.collection_status.value}"
                    )
                summary_lines.append("")

                # Overall statistics use the same aligned accounting source.
                summary_lines.append("Overall Statistics:")
                aligned = self.compute_aligned_stats()

                summary_lines.append(f"  Total Collectors: {aligned['total']}")
                summary_lines.append(
                    f"  Collectors to run: {aligned['collectors_to_run']}"
                )
                summary_lines.append(f"  FilteredOut: {aligned['filtered_out']}")
                summary_lines.append(f"  Pending: {aligned['pending']}")
                summary_lines.append(f"  Running: {aligned['running']}")
                summary_lines.append(f"  Completed: {aligned['completed']}")
                summary_lines.append(f"  Degraded: {aligned['degraded']}")
                summary_lines.append(f"  Partial: {aligned['partial']}")
                summary_lines.append(f"  Failed: {aligned['failed']}")
                summary_lines.append(f"  Skipped: {aligned['skipped']}")
                summary_lines.append(f"  Cancelled: {aligned['cancelled']}")
                summary_lines.append("")

                # Keep execution completion distinct from collection yield.  A run
                # with terminal failures/skips is still 100% finished even though
                # it did not obtain data from every selected collector.
                if aligned["collectors_to_run"] > 0:
                    obtained = (
                        aligned["completed"] + aligned["degraded"] + aligned["partial"]
                    )
                    summary_lines.append(
                        f"Execution progress: {aligned['execution_pct']:.1f}% "
                        f"({aligned['executed']}/{aligned['collectors_to_run']} terminal)"
                    )
                    summary_lines.append(
                        f"Data obtained: {aligned['collection_pct']:.1f}% "
                        f"({obtained}/{aligned['collectors_to_run']})"
                    )
                    summary_lines.append("")

                # Status by DUT
                summary_lines.append("Status by DUT:")
                for dut_id in sorted(self.dut_collectors.keys()):
                    dut_stats = self._get_dut_stats(dut_id)
                    filtered_out = dut_stats.get("filtered_out", 0)
                    collectors_to_run = max(dut_stats["total"] - filtered_out, 0)
                    summary_lines.append(f"  {dut_id}:")
                    summary_lines.append(f"    Total: {dut_stats['total']}")
                    summary_lines.append(f"    Collectors to run: {collectors_to_run}")
                    summary_lines.append(f"    FilteredOut: {filtered_out}")
                    summary_lines.append(f"    Completed: {dut_stats['completed']}")
                    summary_lines.append(f"    Degraded: {dut_stats['degraded']}")
                    summary_lines.append(f"    Partial: {dut_stats.get('partial', 0)}")
                    summary_lines.append(f"    Failed: {dut_stats['failed']}")
                    summary_lines.append(f"    Skipped: {dut_stats['skipped']}")
                    summary_lines.append(f"    Cancelled: {dut_stats['cancelled']}")
                    summary_lines.append(f"    Running: {dut_stats['running']}")
                    summary_lines.append(f"    Pending: {dut_stats['pending']}")
                    summary_lines.append("")

                # Recent activity (last 10 completed)
                recent_entries = [
                    entry
                    for entry in self._collector_statuses_by_identity.values()
                    if entry.status
                    in [
                        CollectorStatus.SUCCESS,
                        CollectorStatus.DEGRADED,
                        CollectorStatus.PARTIAL,
                        CollectorStatus.ERROR,
                        CollectorStatus.SKIPPED,
                        CollectorStatus.CANCELLED,
                    ]
                    and entry.end_time
                    and not entry.exclusion_type
                ]
                recent_entries.sort(key=lambda x: x.end_time, reverse=True)

                if recent_entries:
                    summary_lines.append("Recent Activity (Last 10):")
                    summary_lines.append("")

                    # Create table header
                    recent_group_width = 14
                    recent_header = (
                        f"{'DUT':<15} {'Collector':<12} {'Status':<12} "
                        f"{self._fixed_width_cell('Group', recent_group_width)} "
                        f"{'Level':<6} {'End Time':<10} {'Duration':<10}"
                    )
                    summary_lines.append(recent_header)
                    summary_lines.append("-" * len(recent_header))

                    # Add table rows
                    for entry in recent_entries[:10]:
                        status_icon = (
                            "✓"
                            if entry.status == CollectorStatus.SUCCESS
                            else ("✗" if entry.status == CollectorStatus.ERROR else "○")
                        )

                        duration_str = self._format_collector_duration(entry)

                        # Combine status icon and text
                        status_with_icon = f"{status_icon} {entry.status.value}"

                        summary_lines.append(
                            f"{entry.dut_id:<15} {entry.collector_id:<12} "
                            f"{status_with_icon:<12} "
                            f"{self._fixed_width_cell(entry.group, recent_group_width)} "
                            f"{entry.level:<6} "
                            f"{entry.end_time.strftime('%H:%M:%S'):<10} "
                            f"{duration_str:<10}"
                        )
                    summary_lines.append("")

                await self._write_snapshot_leaf_async(
                    self.global_summary_file,
                    "\n".join(summary_lines),
                    durable=durable,
                )
                return True

            except Exception as e:
                if durable:
                    raise
                # Log error but don't fail
                print(f"Warning: Failed to save global summary file: {e}")
                return False

    async def _save_dut_summary_files(
        self,
        dut_id: Optional[str] = None,
        *,
        durable: bool = False,
    ) -> bool:
        """
        Save one or all DUT-specific human-readable summary files.

        The implementation uses ``dut_id`` and ``durable`` to save one or all
        DUT-specific human-readable summary files. Success is reported only
        after the owning output boundary has completed its required write or
        publication step. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            durable: Whether durable is enabled or required for this operation.

        Returns:
            Whether the one or all DUT-specific human-readable summary files
            operation succeeds.
        """
        all_saved = True
        async with self._file_lock:
            target_dut_ids = (
                [dut_id] if dut_id is not None else list(self.dut_collectors)
            )
            for target_dut_id in target_dut_ids:
                try:
                    dut_stats = self._get_dut_stats(target_dut_id)
                    snapshot_generation, terminal_finalized = self._snapshot_marker()

                    summary_lines = []
                    summary_lines.append(f"Collection Status Summary - {target_dut_id}")
                    summary_lines.append("=" * 50)
                    summary_lines.append(
                        f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    summary_lines.append(f"Snapshot Generation: {snapshot_generation}")
                    summary_lines.append(
                        f"Terminal Finalized: {str(terminal_finalized).lower()}"
                    )
                    if self.run_result is not None:
                        summary_lines.append(
                            f"Runtime Status: {self.run_result.runtime_status.value}"
                        )
                        summary_lines.append(
                            "Collection Status: "
                            f"{self._get_dut_collection_status(dut_stats).value}"
                        )
                    summary_lines.append("")

                    # DUT statistics
                    summary_lines.append(f"Statistics for {target_dut_id}:")
                    # Pre-execution exclusions are explicit. Preflight failures
                    # can also have no start timestamp and must remain skips.
                    filtered_out = dut_stats.get("filtered_out", 0)
                    collectors_to_run = max(dut_stats["total"] - filtered_out, 0)

                    summary_lines.append(f"  Total Collectors: {dut_stats['total']}")
                    summary_lines.append(f"  Collectors to run: {collectors_to_run}")
                    summary_lines.append(f"  FilteredOut: {filtered_out}")
                    summary_lines.append(f"  Pending: {dut_stats['pending']}")
                    summary_lines.append(f"  Running: {dut_stats['running']}")
                    summary_lines.append(f"  Completed: {dut_stats['completed']}")
                    summary_lines.append(f"  Degraded: {dut_stats['degraded']}")
                    summary_lines.append(f"  Partial: {dut_stats.get('partial', 0)}")
                    summary_lines.append(f"  Failed: {dut_stats['failed']}")
                    summary_lines.append(f"  Skipped: {dut_stats['skipped']}")
                    summary_lines.append(f"  Cancelled: {dut_stats['cancelled']}")
                    summary_lines.append("")

                    # Progress percentage for this DUT
                    if collectors_to_run > 0:
                        # Denominator should exclude filtered-out collectors
                        # Include partial in the numerator; skipped here is runtime-skipped
                        finished = (
                            dut_stats["completed"]
                            + dut_stats["degraded"]
                            + dut_stats.get("partial", 0)
                            + dut_stats["failed"]
                            + dut_stats["skipped"]
                            + dut_stats["cancelled"]
                        )
                        progress = (finished / collectors_to_run) * 100
                        summary_lines.append(
                            f"Progress: {progress:.1f}% ({finished}/{collectors_to_run})"
                        )
                        summary_lines.append("")
                    elif dut_stats["total"] > 0:
                        summary_lines.append(
                            "Progress: N/A (no collectors selected for execution)"
                        )
                        summary_lines.append("")

                    # Collectors for this DUT
                    all_dut_entries = [
                        entry
                        for collector_id in sorted(
                            self.dut_collectors.get(target_dut_id, set())
                        )
                        if (
                            entry := self._get_collector_status_entry(
                                target_dut_id, collector_id
                            )
                        )
                        is not None
                    ]

                    # Human summary shows execution outcomes only. Explicit
                    # exclusions remain available in collection_status.json and
                    # in the aggregate FilteredOut count above.
                    dut_entries = [
                        e
                        for e in all_dut_entries
                        if not (
                            e.status == CollectorStatus.SKIPPED and e.exclusion_type
                        )
                    ]

                    if dut_entries:
                        summary_lines.append("Collectors:")
                        summary_lines.append("")

                        # Create table header
                        group_width = 14
                        scope_width = 18
                        collector_header = (
                            f"{'ID':<8} {'Status':<12} "
                            f"{self._fixed_width_cell('Group', group_width)} "
                            f"{'Level':<6} {'Start Time':<10} {'End Time':<10} "
                            f"{'Duration':<10} {'Timeout':<8} "
                            f"{self._fixed_width_cell('Scope', scope_width)} Reason"
                        )
                        summary_lines.append(collector_header)
                        summary_lines.append("-" * len(collector_header))

                        # Add table rows
                        for entry in sorted(dut_entries, key=self._collector_sort_key):
                            start_time_str = (
                                entry.start_time.strftime("%H:%M:%S")
                                if entry.start_time
                                else "N/A"
                            )
                            end_time_str = (
                                entry.end_time.strftime("%H:%M:%S")
                                if entry.end_time
                                else "N/A"
                            )

                            duration_str = self._format_collector_duration(entry)

                            # Keep the full reason, but collapse embedded newlines
                            # so one collector cannot corrupt the fixed-row table.
                            reason = self._single_line_text(
                                self._sanitize_run_outcome_reason(entry.reason)
                            )

                            # Use text-only status
                            status_with_icon = entry.status.value.upper()

                            # Extract timeout information
                            timeout_str = (
                                f"{entry.timeout}s" if entry.timeout else "N/A"
                            )

                            scope_info = self._format_collector_scope(entry)

                            summary_lines.append(
                                f"{entry.collector_id:<8} {status_with_icon:<12} "
                                f"{self._fixed_width_cell(entry.group, group_width)} "
                                f"{entry.level:<6} {start_time_str:<10} "
                                f"{end_time_str:<10} {duration_str:<10} "
                                f"{timeout_str:<8} "
                                f"{self._fixed_width_cell(scope_info, scope_width)} "
                                f"{reason}"
                            )

                        summary_lines.append("")

                    summary_file = self.dut_summary_files.get(target_dut_id)
                    if summary_file:
                        await self._write_snapshot_leaf_async(
                            summary_file,
                            "\n".join(summary_lines),
                            durable=durable,
                        )
                    else:
                        all_saved = False

                except Exception as e:
                    if durable:
                        raise
                    # Preserve DUT context while keeping required output fail-closed.
                    print(
                        "Warning: Failed to save DUT summary file for "
                        f"{target_dut_id}: {e}"
                    )
                    raise
        return all_saved

    async def _save_dut_timing_files(self, *, durable: bool = False) -> bool:
        """
        Save DUT-specific timing.json files with granular timing data.

        The implementation uses ``durable`` to save DUT-specific timing.json
        files with granular timing data. Success is reported only after the
        owning output boundary has completed its required write or publication
        step. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            durable: Whether durable is enabled or required for this operation.

        Returns:
            Whether the DUT-specific timing.json files with granular timing data
            operation succeeds.
        """
        all_saved = True
        async with self._file_lock:
            for dut_id in self.dut_collectors.keys():
                try:
                    # Get all entries for this DUT
                    dut_entries = [
                        entry
                        for collector_id in self.dut_collectors.get(dut_id, set())
                        if (
                            entry := self._get_collector_status_entry(
                                dut_id,
                                collector_id,
                            )
                        )
                        is not None
                    ]

                    # Timing reports describe work that remained in the execution
                    # plan.  Keep runtime skips (for example a preflight failure),
                    # but do not surface collectors removed before execution as
                    # zero-duration "skipped" work in timing.json or the SPA.
                    reportable_entries = [
                        entry
                        for entry in dut_entries
                        if not (
                            entry.status == CollectorStatus.SKIPPED
                            and entry.exclusion_type
                        )
                    ]
                    cancelled = sum(
                        entry.status.value == "cancelled"
                        for entry in reportable_entries
                    )

                    # Calculate overall timing
                    # Only include collectors that actually executed (have both start_time AND end_time)
                    # Skipped collectors have end_time set at finalization but no start_time,
                    # which would incorrectly inflate the wall clock duration
                    executed_entries = [
                        e for e in reportable_entries if e.start_time and e.end_time
                    ]
                    start_times = [e.start_time for e in executed_entries]
                    end_times = [e.end_time for e in executed_entries]

                    overall_start = min(start_times) if start_times else None
                    overall_end = max(end_times) if end_times else None
                    wall_clock_duration = (
                        (overall_end - overall_start).total_seconds()
                        if overall_start is not None and overall_end is not None
                        else 0.0
                    )

                    # Get DUT stats
                    dut_stats = self._get_dut_stats(dut_id)
                    exclusions_by_type: Dict[str, int] = {}
                    for entry in dut_entries:
                        if entry.exclusion_type:
                            exclusion_type = str(entry.exclusion_type).strip().lower()
                            exclusions_by_type[exclusion_type] = (
                                exclusions_by_type.get(exclusion_type, 0) + 1
                            )
                        elif is_valid_not_applicable_skip(
                            entry.status,
                            entry.context,
                        ):
                            exclusions_by_type["capability"] = (
                                exclusions_by_type.get("capability", 0) + 1
                            )

                    # Build collectors timing data
                    collectors_timing = {}
                    timing_discarded_counts: List[int] = []
                    for entry in reportable_entries:
                        collector_data = {
                            "collector_id": entry.collector_id,
                            "collector_name": entry.collector_name,
                            "group": entry.group,
                            "level": entry.level,
                            "status": entry.status.value,
                            "start_time": (
                                entry.start_time.isoformat()
                                if entry.start_time
                                else None
                            ),
                            "end_time": (
                                entry.end_time.isoformat() if entry.end_time else None
                            ),
                            "duration_seconds": (
                                entry.execution_time
                                if entry.execution_time > 0
                                else (
                                    (entry.end_time - entry.start_time).total_seconds()
                                    if entry.start_time and entry.end_time
                                    else 0.0
                                )
                            ),
                            "timeout_seconds": entry.timeout,
                            "reason": (
                                self._sanitize_run_outcome_reason(entry.reason)
                                if entry.reason
                                else None
                            ),
                        }
                        if self.timing_manager and hasattr(
                            self.timing_manager, "get_collector_timing"
                        ):
                            detailed_timing = self.timing_manager.get_collector_timing(
                                dut_id,
                                entry.collector_id,
                            )
                            if detailed_timing:
                                detailed_timing = normalize_timing_artifact_paths(
                                    detailed_timing,
                                    self.output_dir,
                                    dut_id=run_tree_dut_component(dut_id),
                                    on_discarded=timing_discarded_counts.append,
                                )
                                collector_data["duration_seconds"] = (
                                    detailed_timing.get(
                                        "wall_clock_duration_seconds",
                                        collector_data["duration_seconds"],
                                    )
                                )
                                collector_data["timing"] = detailed_timing
                        collectors_timing[entry.collector_id] = collector_data

                    timing_discarded_total = sum(timing_discarded_counts)
                    if timing_discarded_total:
                        await self._log_projection_summary(
                            "WARNING",
                            "Discarded "
                            f"{timing_discarded_total} unsafe or missing timing "
                            f"artifact path(s) for {dut_id}",
                        )

                    # Build service-level timing aggregation
                    by_service = {}
                    for entry in reportable_entries:
                        service = entry.group
                        if service not in by_service:
                            by_service[service] = {
                                "total_collectors": 0,
                                "completed": 0,
                                "degraded": 0,
                                "failed": 0,
                                "partial": 0,
                                "skipped": 0,
                                "total_duration_seconds": 0.0,
                                "collectors": [],
                            }

                        by_service[service]["total_collectors"] += 1
                        by_service[service]["collectors"].append(entry.collector_id)

                        # Count by status
                        if entry.status == CollectorStatus.SUCCESS:
                            by_service[service]["completed"] += 1
                        elif entry.status == CollectorStatus.DEGRADED:
                            by_service[service]["degraded"] += 1
                        elif entry.status == CollectorStatus.ERROR:
                            by_service[service]["failed"] += 1
                        elif entry.status == CollectorStatus.PARTIAL:
                            by_service[service]["partial"] += 1
                        elif entry.status == CollectorStatus.SKIPPED:
                            by_service[service]["skipped"] += 1

                        duration = self._collector_duration_seconds(entry)
                        if duration is not None:
                            by_service[service]["total_duration_seconds"] += duration

                    # Build timing.json structure
                    snapshot_generation, terminal_finalized = self._snapshot_marker()
                    timing_event_counters: Dict[str, int] = {}
                    get_event_counters = getattr(
                        self.timing_manager, "get_event_counters", None
                    )
                    if callable(get_event_counters):
                        candidate = get_event_counters(dut_id=dut_id)
                        if isinstance(candidate, dict):
                            timing_event_counters = {
                                str(key): int(value or 0)
                                for key, value in candidate.items()
                                if isinstance(value, (int, float))
                            }

                    timing_data = {
                        "schema_version": "2.0",
                        "dut_id": dut_id,
                        "generated_at": datetime.now().isoformat(),
                        "snapshot_generation": snapshot_generation,
                        "terminal_finalized": terminal_finalized,
                        "timing_event_counters": timing_event_counters,
                        "overall": {
                            "start_time": (
                                overall_start.isoformat() if overall_start else None
                            ),
                            "end_time": (
                                overall_end.isoformat() if overall_end else None
                            ),
                            "wall_clock_duration_seconds": round(
                                wall_clock_duration, 2
                            ),
                            "total_collectors": dut_stats["total"],
                            "collectors_to_run": max(
                                dut_stats["total"] - dut_stats["filtered_out"],
                                0,
                            ),
                            "filtered_out": dut_stats["filtered_out"],
                            "baseboard_excluded": exclusions_by_type.get(
                                "baseboard", 0
                            ),
                            "capability_excluded": exclusions_by_type.get(
                                "capability", 0
                            ),
                            "config_excluded": sum(
                                count
                                for exclusion_type, count in exclusions_by_type.items()
                                if exclusion_type.startswith("config")
                            ),
                            "completed": dut_stats["completed"],
                            "degraded": dut_stats["degraded"],
                            "partial": dut_stats["partial"],
                            "failed": dut_stats["failed"],
                            "skipped": dut_stats["skipped"],
                            "cancelled": cancelled,
                            "pending": dut_stats["pending"],
                            "running": dut_stats["running"],
                        },
                        "collectors": collectors_timing,
                        "by_service": by_service,
                    }

                    # Write to DUT's .metadata/timing.json
                    dut_metadata_dir = (
                        self.output_dir / run_tree_dut_component(dut_id) / ".metadata"
                    )
                    timing_file = dut_metadata_dir / "timing.json"

                    await self._write_snapshot_leaf_async(
                        timing_file,
                        timing_data,
                        durable=durable,
                    )

                except Exception as e:
                    all_saved = False
                    if durable:
                        raise
                    # Log error but don't fail
                    print(f"Warning: Failed to save timing file for {dut_id}: {e}")
        return all_saved

    def _get_dut_stats(self, dut_id: str) -> Dict[str, int]:
        """
        Get statistics for a specific DUT.

        The implementation uses ``dut_id`` to get statistics for a specific DUT.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``stats``.
        """
        stats = {
            "total": 0,
            "completed": 0,
            "degraded": 0,
            "partial": 0,
            "failed": 0,
            "skipped": 0,
            "cancelled": 0,
            "running": 0,
            "pending": 0,
            "filtered_out": 0,
            "valid_not_applicable": 0,
        }

        for collector_id in self.dut_collectors.get(dut_id, []):
            entry = self._get_collector_status_entry(dut_id, collector_id)
            if entry is not None:
                stats["total"] += 1

                # Map status values to stats keys
                if entry.status == CollectorStatus.SUCCESS:
                    stats["completed"] += 1
                elif entry.status == CollectorStatus.DEGRADED:
                    stats["degraded"] += 1
                elif entry.status == CollectorStatus.ERROR:
                    stats["failed"] += 1
                elif entry.status == CollectorStatus.PARTIAL:
                    stats["partial"] += 1
                elif entry.status == CollectorStatus.SKIPPED:
                    # Only explicitly classified pre-execution exclusions are
                    # filtered out. A preflight/runtime skip may have no start.
                    if entry.exclusion_type:
                        stats["filtered_out"] += 1
                    else:
                        stats["skipped"] += 1
                        if is_valid_not_applicable_skip(entry.status, entry.context):
                            stats["valid_not_applicable"] += 1
                elif entry.status == CollectorStatus.CANCELLED:
                    stats["cancelled"] += 1
                elif entry.status == CollectorStatus.RUNNING:
                    stats["running"] += 1
                elif entry.status == CollectorStatus.PENDING:
                    stats["pending"] += 1

        return stats

    @staticmethod
    def _get_dut_collection_status(dut_stats: Dict[str, int]) -> CollectionStatus:
        """
        Derive one DUT's collection status from its own collector counts.

        The run-level runtime status still describes the shared process and
        lifecycle. The collection status in a DUT-local summary must instead
        reflect only that DUT's evidence, so a failure or partial result on a
        peer does not incorrectly mark an otherwise successful DUT partial.

        Args:
            dut_stats: Per-DUT counts returned by :meth:`_get_dut_stats`.

        Returns:
            The canonical collector-domain status for the selected DUT.
        """
        completed = dut_stats.get("completed", 0)
        degraded = dut_stats.get("degraded", 0)
        partial = dut_stats.get("partial", 0)

        if dut_stats.get("pending", 0) or dut_stats.get("running", 0):
            return CollectionStatus.INCOMPLETE
        if dut_stats.get("failed", 0) or dut_stats.get("cancelled", 0):
            return (
                CollectionStatus.PARTIAL
                if completed or degraded or partial
                else CollectionStatus.FAILED
            )
        if degraded or partial:
            return CollectionStatus.PARTIAL
        unexpected_skips = max(
            dut_stats.get("skipped", 0) - dut_stats.get("valid_not_applicable", 0),
            0,
        )
        if unexpected_skips:
            return (
                CollectionStatus.PARTIAL if completed else CollectionStatus.INCOMPLETE
            )
        if dut_stats.get("total", 0) and not completed:
            return CollectionStatus.INCOMPLETE
        return CollectionStatus.SUCCESS

    def compute_aligned_stats(self) -> Dict[str, int]:
        """
        Compute the canonical run-level collector accounting.

        The aggregation sums per-DUT counters, keeps pre-execution exclusions
        separate from runtime skips, derives the runnable and executed totals,
        and calculates execution and collection percentages from the appropriate
        terminal outcomes.

        Returns:
            The validated ``agg``.
        """
        agg = {
            "total": 0,
            "completed": 0,
            "degraded": 0,
            "partial": 0,
            "failed": 0,
            "skipped": 0,
            "cancelled": 0,
            "filtered_out": 0,
            "running": 0,
            "pending": 0,
            "valid_not_applicable": 0,
        }
        for dut_id in self.dut_collectors:
            for key, value in self._get_dut_stats(dut_id).items():
                agg[key] += value

        collectors_to_run = max(agg["total"] - agg["filtered_out"], 0)
        executed = (
            agg["completed"]
            + agg["degraded"]
            + agg["partial"]
            + agg["failed"]
            + agg["skipped"]
            + agg["cancelled"]
        )
        obtained = agg["completed"] + agg["degraded"] + agg["partial"]
        agg["collectors_to_run"] = collectors_to_run
        agg["executed"] = executed
        agg["execution_pct"] = (
            round(executed / collectors_to_run * 100, 1) if collectors_to_run else 0.0
        )
        agg["collection_pct"] = (
            round(obtained / collectors_to_run * 100, 1) if collectors_to_run else 0.0
        )
        return agg

    def _generate_status_table(self) -> Table:
        """
        Generate Rich table for live display.

        The implementation uses current instance state to generate Rich table
        for live display.

        Returns:
            The validated ``table``.
        """
        table = Table(title="Collection Status")
        table.add_column("DUT", style="cyan", no_wrap=True)
        table.add_column("Collector", style="green")
        table.add_column("Group", style="blue")
        table.add_column("Level", style="yellow")
        table.add_column("Status", style="white")
        table.add_column("Time", style="magenta")
        table.add_column("Progress", style="white")

        # Add overall progress row
        if self.stats["total_collectors"] > 0:
            completed = (
                self.stats["completed_collectors"]
                + self.stats["degraded_collectors"]
                + self.stats["partial_collectors"]
                + self.stats["failed_collectors"]
                + self.stats["skipped_collectors"]
                + self.stats["cancelled_collectors"]
            )
            progress = (completed / self.stats["total_collectors"]) * 100
            table.add_row(
                "ALL",
                f"{completed}/{self.stats['total_collectors']}",
                "Overall",
                "",
                f"{progress:.1f}%",
                f"{progress:.1f}%",
                f"[{'█' * int(progress / 10)}{'░' * (10 - int(progress / 10))}]",
            )

        # Add recent entries (last 10)
        recent_entries = [
            entry
            for entry in self.collector_statuses.values()
            if entry.status
            in [
                CollectorStatus.SUCCESS,
                CollectorStatus.DEGRADED,
                CollectorStatus.PARTIAL,
                CollectorStatus.ERROR,
                CollectorStatus.SKIPPED,
                CollectorStatus.CANCELLED,
                CollectorStatus.RUNNING,
            ]
        ]
        recent_entries.sort(
            key=lambda x: x.end_time or x.start_time or datetime.min,
            reverse=True,
        )

        for entry in recent_entries[:10]:
            status_color = {
                CollectorStatus.SUCCESS: "green",
                CollectorStatus.DEGRADED: "yellow",
                CollectorStatus.PARTIAL: "yellow",
                CollectorStatus.ERROR: "red",
                CollectorStatus.SKIPPED: "yellow",
                CollectorStatus.CANCELLED: "magenta",
                CollectorStatus.RUNNING: "blue",
                CollectorStatus.PENDING: "white",
            }.get(entry.status, "white")

            time_str = ""
            if entry.end_time:
                time_str = entry.end_time.strftime("%H:%M:%S")
            elif entry.start_time:
                time_str = f"Started {entry.start_time.strftime('%H:%M:%S')}"

            table.add_row(
                entry.dut_id,
                entry.collector_id,
                entry.group,
                entry.level,
                f"[{status_color}]{entry.status.value}[/{status_color}]",
                time_str,
                "",
            )

        return table

    async def _start_live_display(self) -> None:
        """
        Start the Rich live display.

        The implementation uses current instance state to start the Rich live
        display. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind. It updates
        ``_display_enabled`` and ``_live_display`` on the instance as part of
        that state transition.
        """
        if self._live_display is None and self.console is not None:
            try:
                self._live_display = Live(
                    self._generate_status_table(),
                    console=self.console,
                    refresh_per_second=2,
                )
                self._live_display.start()
            except Exception:
                # If live display fails, just disable it
                self._live_display = None
                self._display_enabled = False

    async def stop_live_display(self) -> None:
        """
        Stop the Rich live display.

        Force multiple newlines after stopping the live display to ensure proper
        spacing.
        """
        if self._live_display:
            self._live_display.stop()
            self._live_display = None
            # Force multiple newlines after stopping the live display to ensure proper spacing
            if self.console:
                self.console.print("\n")  # Force a newline using console.print()

    def _record_finalization_diagnostic(
        self,
        phase: str,
        error: BaseException,
        *,
        diagnostic_only: bool = False,
    ) -> None:
        """
        Retain a bounded diagnostic without changing authoritative state.

        Diagnostics are evidence only; they cannot invalidate committed status
        or interrupt authoritative projection rollback.

        Args:
            phase: Text supplied as phase in the format accepted by this
                function.
            error: Exception or failure detail associated with the operation.
            diagnostic_only: Retain a recoverable live-status error outside the
                required failure list so a verified terminal commit can succeed.
        """

        destination = (
            self._nonfatal_finalization_diagnostics
            if diagnostic_only
            else self._finalization_diagnostic_failures
        )
        if len(destination) >= 64:
            return
        try:
            logger_sanitizer = getattr(
                getattr(self.logger, "sanitizer", None), "sanitize", None
            )
            destination.append(
                sanitize_finalization_failure(
                    phase,
                    error,
                    sanitizer=(
                        logger_sanitizer if callable(logger_sanitizer) else None
                    ),
                )
            )
        except BaseException:
            # Diagnostics are evidence only; they cannot invalidate committed
            # status or interrupt authoritative projection rollback.
            return

    async def _log_projection_summary(self, level: str, message: str) -> None:
        """
        Emit one best-effort projection diagnostic, never one per collector.

        The implementation uses ``level`` and ``message`` to emit one
        best-effort projection diagnostic, never one per collector. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """

        log_runtime = getattr(self.logger, "log_runtime", None)
        if not callable(log_runtime):
            return
        try:
            await log_runtime(level, "CollectionStatusTracker", message)
        except BaseException as error:
            if is_control_flow_exception(error):
                raise
            self._record_finalization_diagnostic("status_diagnostics", error)

    def _terminal_projection_checkpoint(
        self,
        _entry: Optional[CollectorStatusEntry],
        _projected_count: int,
    ) -> None:
        """
        Fault-injection seam after every authoritative projection mutation.

        The implementation uses ``_entry`` and ``_projected_count`` to
        fault-injection seam after every authoritative projection mutation.

        Args:
            _entry: Entry consumed while the function attempts to
                fault-injection seam after every authoritative projection
                mutation.
            _projected_count: Numeric projected count used by the operation's
                bounded accounting.
        """

    async def _mark_remaining_pending_as_skipped(self) -> None:
        """
        Mark any collectors that are still PENDING as SKIPPED.

        Explicit pre-execution exclusions are marked as SKIPPED before
        finalization and keep ``start_time=None`` so they are counted as
        filtered-out. Remaining PENDING collectors were still in the run map, so
        finalization records them as runtime skips.
        """
        pending_collectors = [
            entry
            for entry in self._collector_statuses_by_identity.values()
            if entry.status == CollectorStatus.PENDING
        ]

        if pending_collectors:
            completed_at = datetime.now()
            for projected_count, entry in enumerate(pending_collectors, start=1):
                # Mark as skipped
                entry.status = CollectorStatus.SKIPPED
                if entry.start_time is None:
                    entry.start_time = completed_at
                entry.end_time = completed_at
                if not entry.reason:
                    entry.reason = "Collector did not start before collection finalized"

                # Update stats
                self.stats["pending_collectors"] = max(
                    self.stats["pending_collectors"] - 1, 0
                )
                self.stats["skipped_collectors"] += 1
                self._terminal_projection_checkpoint(entry, projected_count)
            await self._log_projection_summary(
                "DEBUG",
                f"Projected {len(pending_collectors)} pending collectors as skipped",
            )

    async def _mark_remaining_running_as_error(self) -> None:
        """
        Mark any collectors that are still RUNNING as ERROR.

        A finalized report must not contain non-terminal states. RUNNING
        collectors reached execution but never completed, so they are counted as
        failed rather than filtered/skipped.
        """
        running_collectors = [
            entry
            for entry in self._collector_statuses_by_identity.values()
            if entry.status == CollectorStatus.RUNNING
        ]

        if running_collectors:
            completed_at = datetime.now()
            for projected_count, entry in enumerate(running_collectors, start=1):
                entry.status = CollectorStatus.ERROR
                entry.end_time = completed_at
                if entry.start_time:
                    entry.execution_time = (
                        completed_at - entry.start_time
                    ).total_seconds()
                if not entry.reason:
                    entry.reason = (
                        "Collector was still running when collection finalized"
                    )
                entry.failure_category = "internal-error"

                self.stats["running_collectors"] = max(
                    self.stats["running_collectors"] - 1, 0
                )
                self.stats["failed_collectors"] += 1
                self._terminal_projection_checkpoint(entry, projected_count)
            await self._log_projection_summary(
                "WARN",
                f"Projected {len(running_collectors)} running collectors as errors",
            )

    async def _mark_remaining_as_cancelled(self) -> None:
        """
        Project unfinished entries as cancelled for an interrupted run.

        The implementation uses current instance state to project unfinished
        entries as cancelled for an interrupted run. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.
        """

        unfinished = [
            entry
            for entry in self._collector_statuses_by_identity.values()
            if entry.status in {CollectorStatus.PENDING, CollectorStatus.RUNNING}
        ]
        if not unfinished:
            return

        completed_at = datetime.now()
        for projected_count, entry in enumerate(unfinished, start=1):
            previous_status = entry.status
            if previous_status == CollectorStatus.PENDING:
                self.stats["pending_collectors"] = max(
                    self.stats["pending_collectors"] - 1, 0
                )
            else:
                self.stats["running_collectors"] = max(
                    self.stats["running_collectors"] - 1, 0
                )
                if entry.start_time:
                    entry.execution_time = (
                        completed_at - entry.start_time
                    ).total_seconds()
            entry.status = CollectorStatus.CANCELLED
            entry.end_time = completed_at
            if not entry.reason:
                entry.reason = "Collector cancelled when collection was interrupted"
            self.stats["cancelled_collectors"] += 1
            self._terminal_projection_checkpoint(entry, projected_count)
        await self._log_projection_summary(
            "WARN",
            f"Projected {len(unfinished)} unfinished collectors as cancelled",
        )

    def _capture_terminal_projection_state(
        self,
    ) -> Tuple[Dict[str, int], Tuple[Tuple[Any, ...], ...]]:
        """
        Capture only fields changed while projecting unfinished collectors.

        The implementation uses current instance state to capture only fields
        changed while projecting unfinished collectors.

        Returns:
            A tuple containing ``dict`` and ``tuple`` in that order.
        """

        return (
            dict(self.stats),
            tuple(
                (
                    entry,
                    entry.status,
                    entry.start_time,
                    entry.end_time,
                    entry.execution_time,
                    entry.reason,
                    entry.failure_category,
                )
                for entry in self._collector_statuses_by_identity.values()
            ),
        )

    def _restore_terminal_projection_state(
        self,
        captured: Tuple[Dict[str, int], Tuple[Tuple[Any, ...], ...]],
    ) -> None:
        """
        Roll back an unpublished projection before a policy-aware retry.

        The implementation uses ``captured`` to roll back an unpublished
        projection before a policy-aware retry. It updates ``stats`` on the
        instance as part of that state transition.

        Args:
            captured: Mapping supplying fields for roll back an unpublished
                projection before a policy-aware retry.
        """

        stats, entries = captured
        self.stats = dict(stats)
        for (
            entry,
            status,
            start_time,
            end_time,
            execution_time,
            reason,
            failure_category,
        ) in entries:
            entry.status = status
            entry.start_time = start_time
            entry.end_time = end_time
            entry.execution_time = execution_time
            entry.reason = reason
            entry.failure_category = failure_category

    def _build_finalization_receipt(
        self,
        *,
        failures: Tuple[FinalizationFailure, ...] = (),
    ) -> FinalizationReceipt:
        """
        Freeze the authoritative in-memory plan and publication marker.

        After applying local validation, the function forwards ``failures`` to
        ``FinalizationReceipt`` and preserves its return and exception contract.

        Args:
            failures: Entries supplied as ``failures`` without transferring
                container ownership.

        Returns:
            A ``FinalizationReceipt`` representing finalization receipt.
        """

        intent = self._outcome_intent
        affected_duts = tuple(
            dut_id
            for dut_id in intent.affected_duts
            if dut_id in (self._declared_dut_ids or ())
        )
        return FinalizationReceipt(
            committed_generation=self._snapshot_generation,
            terminal_snapshot_committed=self.is_durably_finalized,
            dut_roster=self._declared_dut_ids or (),
            collector_counts=tuple(
                (name, int(value)) for name, value in self.stats.items()
            ),
            collector_statuses=tuple(
                FrozenCollectorStatus(
                    dut_id=entry.dut_id,
                    collector_id=entry.collector_id,
                    status=entry.status.value,
                )
                for entry in self._collector_statuses_by_identity.values()
            ),
            interrupted=self._finalization_interrupted,
            outcome_hint=FinalizationOutcomeHint(
                status=intent.status,
                failure_type=intent.failure_type,
                reason=intent.reason,
                affected_duts=affected_duts,
            ),
            snapshot_leaf_digests=self._snapshot_leaf_digests,
            failures=tuple(self._finalization_diagnostic_failures) + failures,
            diagnostics=tuple(self._nonfatal_finalization_diagnostics),
            run_identity=(
                self.run_result.run_identity if self.run_result is not None else None
            ),
        )

    def _raise_typed_finalization_error(self, error: BaseException) -> NoReturn:
        """
        Raise a typed failure carrying the current frozen tracker state.

        The implementation uses ``error`` to raise a typed failure carrying the
        current frozen tracker state. It updates ``_finalization_interrupted``
        and ``_finalization_receipt`` on the instance as part of that state
        transition. If the function cannot raise a typed failure carrying the
        current frozen tracker state, its exception reaches the caller instead
        of being converted into a successful result.

        Args:
            error: Exception or failure detail associated with the operation.

        Raises:
            FinalizationReceiptCancelledError: If the function cannot raise a
                typed failure carrying the current frozen tracker state safely.
            BaseException: If a delegated failure occurs while the function
                attempts to raise a typed failure carrying the current frozen
                tracker state.
            FinalizationReceiptError: If the function cannot raise a typed
                failure carrying the current frozen tracker state safely.
        """

        logger_state = getattr(self.logger, "__dict__", {})
        logger_sanitizer = (
            logger_state.get("sanitizer") if isinstance(logger_state, dict) else None
        )
        sanitizer = getattr(logger_sanitizer, "sanitize", None)
        failure = sanitize_finalization_failure(
            "status_snapshot",
            error,
            sanitizer=sanitizer if callable(sanitizer) else None,
        )
        receipt = self._build_finalization_receipt(failures=(failure,))
        self._finalization_receipt = receipt
        if is_interruption_exception(error):
            self._finalization_interrupted = True
            receipt = receipt.with_interruption()
            self._finalization_receipt = receipt
        if isinstance(error, asyncio.CancelledError):
            raise FinalizationReceiptCancelledError(receipt) from error
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise attach_finalization_receipt(error, receipt)
        raise FinalizationReceiptError(receipt) from error

    async def finalize(
        self,
        interrupted: bool = False,
        *,
        defer_close: bool = False,
    ) -> FinalizationReceipt:
        """
        Freeze the run and durably publish one retryable terminal snapshot.

        Freeze before the first await so cancellation cannot reopen collector
        callbacks or permit a different plan to bind.

        Args:
            interrupted: Whether interrupted is enabled or required for this
                operation.
            defer_close: Whether defer close is enabled or required for this
                operation.

        Returns:
            A ``FinalizationReceipt`` representing finalize.
        """
        async with self._lifecycle_lock:
            if self._lifecycle_state is _TrackerLifecycle.FINALIZED:
                if not defer_close:
                    try:
                        self.close()
                    except BaseException as error:
                        self._raise_typed_finalization_error(error)
                if self._finalization_receipt is None:
                    self._finalization_receipt = self._build_finalization_receipt()
                if interrupted and not self._finalization_receipt.interrupted:
                    self._finalization_interrupted = True
                    self._finalization_receipt = (
                        self._finalization_receipt.with_interruption()
                    )
                return self._finalization_receipt
            if self._lifecycle_state is _TrackerLifecycle.NEW:
                error = RuntimeError("Cannot finalize before a run is declared")
                self._raise_typed_finalization_error(error)
            if self._lifecycle_state is _TrackerLifecycle.DECLARED:
                error = RuntimeError("Cannot finalize before a plan is bound")
                self._raise_typed_finalization_error(error)
            if self._lifecycle_state is not _TrackerLifecycle.FROZEN:
                # Freeze before the first await so cancellation cannot reopen
                # collector callbacks or permit a different plan to bind.
                self._lifecycle_state = _TrackerLifecycle.FROZEN
                self._finalized = True

            self._finalization_interrupted = bool(
                self._finalization_interrupted or interrupted
            )

            # A prior attempt may have committed its exact terminal generation
            # and then lost control flow or failed while removing rollback
            # links. Never republish a second terminal generation in that case.
            if self.is_durably_finalized:
                try:
                    await run_managed_filesystem_operation(
                        self.cleanup_pending_candidate
                    )
                    await run_managed_filesystem_operation(
                        partial(
                            self.validate_durable_snapshot,
                            list(self._declared_dut_ids or ()),
                            _allow_pending_run_result=self.run_result is None,
                        )
                    )
                except BaseException as error:
                    self._raise_typed_finalization_error(error)
                self._finalization_receipt = self._build_finalization_receipt()
                if not defer_close:
                    try:
                        self.close()
                    except BaseException as error:
                        self._raise_typed_finalization_error(error)
                self._lifecycle_state = _TrackerLifecycle.FINALIZED
                return self._finalization_receipt

            projection_state = self._capture_terminal_projection_state()
            publication_result: Optional[_PublicationResult] = None

            try:
                self._terminal_projection_checkpoint(None, 0)
                try:
                    await self.stop_live_display()
                except BaseException as error:
                    if is_control_flow_exception(error):
                        raise
                    self._record_finalization_diagnostic(
                        "status_diagnostics",
                        error,
                    )

                # These helpers only select nonterminal entries, so rerunning them
                # is safe and lets a later finalize call recover if an earlier one
                # was cancelled during logging or persistence.
                if self._finalization_interrupted:
                    await self._mark_remaining_as_cancelled()
                else:
                    await self._mark_remaining_running_as_error()
                    await self._mark_remaining_pending_as_skipped()

                publication_result = await self._publish_candidate_snapshot(
                    include_summaries=True,
                    include_timing=True,
                    terminal=True,
                    new_generation=True,
                )
            except BaseException as error:
                if not self.is_durably_finalized:
                    self._restore_terminal_projection_state(projection_state)
                if is_control_flow_exception(error):
                    if is_interruption_exception(error):
                        self._finalization_interrupted = True
                    self._raise_typed_finalization_error(error)
                publication_error = RuntimeError(
                    "Failed to publish terminal collection snapshot"
                )
                publication_error.__cause__ = error
                self._raise_typed_finalization_error(publication_error)

            assert publication_result is not None
            if publication_result.candidate_cleanup_error is not None:
                self._raise_typed_finalization_error(
                    publication_result.candidate_cleanup_error
                )

            try:
                await run_managed_filesystem_operation(
                    partial(
                        self.validate_durable_snapshot,
                        list(self._declared_dut_ids or ()),
                        _allow_pending_run_result=self.run_result is None,
                    )
                )
            except BaseException as error:
                self._raise_typed_finalization_error(error)

            self._finalization_receipt = self._build_finalization_receipt()
            if not defer_close:
                try:
                    self.close()
                except BaseException as error:
                    self._raise_typed_finalization_error(error)
            self._lifecycle_state = _TrackerLifecycle.FINALIZED

            post_commit_control_flow = publication_result.post_commit_control_flow
            if post_commit_control_flow is not None:
                self._raise_typed_finalization_error(post_commit_control_flow)

        # Print final summary
        if self.console:
            try:
                # Force a minimal character to ensure proper newline rendering
                # self.console.print(
                #     "[dim]·[/dim]"
                # )
                # Print a dimmed dot to force newline
                aligned = self.compute_aligned_stats()
                completion_label = (
                    "Collection Interrupted"
                    if self._finalization_interrupted
                    else "Collection Complete!"
                )
                border_style = "yellow" if self._finalization_interrupted else "green"
                executed_count = aligned.get(
                    "executed",
                    aligned["total"] - aligned.get("collectors_to_run", 0),
                )
                summary_text = (
                    f"{completion_label}\n"
                    f"Total: {aligned['total']} | "
                    f"Executed: {executed_count} | "
                    f"Excluded: {aligned['filtered_out']}\n"
                    f"Completed: {aligned['completed']} | "
                    f"Degraded: {aligned['degraded']} | "
                    f"Failed: {aligned['failed']} | "
                    f"Partial: {aligned['partial']} | "
                    f"Skipped: {aligned['skipped']} | "
                    f"Cancelled: {aligned['cancelled']}"
                )

                self.console.print(
                    Panel(
                        summary_text,
                        title="Final Summary",
                        border_style=border_style,
                    )
                )
            except Exception:
                # If console printing fails, just skip it
                pass

        assert self._finalization_receipt is not None
        return self._finalization_receipt

    def _planning_metadata_projection(
        self,
        original: Dict[str, Any],
        result: RunResult,
        *,
        dut_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return one final planning metadata mirror without collection claims.

        ``run_outcome`` is a collection-only legacy adapter. Its planning
        mapping necessarily says "incomplete collection" and would contradict a
        successful transport-free plan, so planning metadata omits it and relies
        on the canonical RunResult plus the summary projection.

        Args:
            original: Mapping supplying fields for one final planning metadata
                mirror without collection claims.
            result: Result object whose ``run_identity``, ``runtime_status``,
                and ``value`` state is read while performing one final planning
                metadata mirror without collection claims.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``document``.

        Raises:
            RuntimeError: If planning metadata lacks a lifecycle object;
                planning metadata DUT identity is inconsistent; or planning root
                metadata lacks a summary object.
        """

        document = copy.deepcopy(original)
        lifecycle = document.get("metadata")
        if type(lifecycle) is not dict:  # noqa: E721 - subclasses are rejected
            raise RuntimeError("Planning metadata lacks a lifecycle object")
        if dut_id is not None and lifecycle.get("dut_id") != dut_id:
            raise RuntimeError("Planning metadata DUT identity is inconsistent")

        # ``run_outcome`` is a collection-only legacy adapter.  Its planning
        # mapping necessarily says "incomplete collection" and would contradict
        # a successful transport-free plan, so planning metadata omits it and
        # relies on the canonical RunResult plus the summary projection.
        lifecycle.pop("run_outcome", None)
        identity = result.run_identity
        if identity is not None:
            lifecycle.update(
                {
                    "run_identity": identity.to_dict(),
                    "tool_version": identity.tool_version,
                    "collection_level": identity.resolved_level,
                    "collection_profile": identity.resolved_profile,
                }
            )
        else:
            lifecycle.pop("run_identity", None)
            lifecycle.pop("collection_profile", None)

        if dut_id is None:
            summary = document.get("summary")
            if type(summary) is not dict:  # noqa: E721 - subclasses are rejected
                raise RuntimeError("Planning root metadata lacks a summary object")
            summary["overall_status"] = (
                "Interrupted"
                if result.runtime_status.value == "interrupted"
                else ("Failed" if result.runtime_status.value == "failed" else "Passed")
            )
        return document

    async def commit_planning_run_result(
        self,
        result: RunResult,
        evidence_receipt: FinalizationReceipt,
        *,
        close: bool = False,
    ) -> FinalizationReceipt:
        """
        Publish a planning result without creating collection snapshot evidence.

        The implementation uses ``result``, ``evidence_receipt``, and ``close``
        to publish a planning result without creating collection snapshot
        evidence. Success is reported only after the owning output boundary has
        completed its required write or publication step. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind. It updates ``_finalization_receipt``,
        ``_lifecycle_state``, ``_publication_deadline``, and ``run_result`` on
        the instance as part of that state transition. If the function cannot
        publish a planning result without creating collection snapshot evidence,
        its exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Args:
            result: Result object whose ``mode`` and ``to_dict`` state is read
                while performing planning result without creating collection
                snapshot evidence.
            evidence_receipt: Evidence receipt object whose ``dut_roster`` state
                is read while performing planning result without creating
                collection snapshot evidence.
            close: Whether close is enabled or required for this operation.

        Returns:
            A ``FinalizationReceipt`` representing commit planning run result.

        Raises:
            TypeError: If a canonical planning RunResult is required.
            RuntimeError: If planning RunResult differs from finalization
                evidence; planning RunResult publication root is closed;
                planning RunResult cannot reuse collection snapshot state; or
                planning root metadata is unavailable; or another input
                invariant is violated.
            BaseException: If a delegated failure occurs while the function
                attempts to publish a planning result without creating
                collection snapshot evidence.
        """

        if type(result) is not RunResult or result.mode is not RunMode.PLANNING:
            raise TypeError("A canonical planning RunResult is required")
        validate_structural_finalization_receipt(evidence_receipt)
        expected = RunResult.from_planning_receipt(evidence_receipt)
        if result != expected:
            raise RuntimeError("Planning RunResult differs from finalization evidence")

        async with self._lifecycle_lock:
            if self._lifecycle_state is _TrackerLifecycle.PLANNING_FINALIZED:
                if (
                    self.run_result == result
                    and self._finalization_receipt == evidence_receipt
                ):
                    if close:
                        self.close()
                    return evidence_receipt
                if self._output_root_fd < 0:
                    raise RuntimeError("Planning RunResult publication root is closed")
            elif (
                self._lifecycle_state is not _TrackerLifecycle.NEW
                or self._declared_dut_ids is not None
                or self._snapshot_generation is not None
                or self.is_durably_finalized
            ):
                raise RuntimeError(
                    "Planning RunResult cannot reuse collection snapshot state"
                )

            roster = self._validate_dut_roster(list(evidence_receipt.dut_roster))
            self._revalidate_output_root_path()
            root_result_relative = self._relative_publication_path(
                self.global_run_result_file
            )
            root_metadata_relative = self._relative_publication_path(
                self.global_metadata_file
            )
            self._register_publication_parent(self.global_metadata_file)

            dut_result_paths: list[tuple[str, Path]] = []
            dut_metadata_paths: list[tuple[str, Path]] = []
            for dut_id in roster:
                dut_root = self.output_dir / run_tree_dut_component(dut_id)
                result_path = dut_root / ".metadata" / "run_result.json"
                metadata_path = dut_root / ".metadata" / "metadata.json"
                self._register_publication_parent(result_path)
                self._register_publication_parent(metadata_path)
                dut_result_paths.append(
                    (dut_id, self._relative_publication_path(result_path))
                )
                dut_metadata_paths.append(
                    (dut_id, self._relative_publication_path(metadata_path))
                )

            publication_paths = [
                root_metadata_relative,
                *(relative for _dut_id, relative in dut_metadata_paths),
                *(relative for _dut_id, relative in dut_result_paths),
                root_result_relative,
            ]
            original_documents: Dict[
                Path,
                Optional[Tuple[str, Dict[str, Any]]],
            ] = {}
            for relative in publication_paths:
                try:
                    original_documents[relative] = self._read_public_json_snapshot(
                        relative,
                        maximum_bytes=self._snapshot_leaf_limit(relative),
                    )
                except FileNotFoundError:
                    original_documents[relative] = None

            original_root_metadata = original_documents[root_metadata_relative]
            if original_root_metadata is None:
                raise RuntimeError("Planning root metadata is unavailable")
            for _dut_id, relative in dut_metadata_paths:
                if original_documents[relative] is None:
                    raise RuntimeError("Planning DUT metadata is unavailable")

            if self._lifecycle_state is _TrackerLifecycle.NEW:
                if (
                    any(
                        original_documents[relative] is not None
                        for _dut_id, relative in dut_result_paths
                    )
                    or original_documents[root_result_relative] is not None
                ):
                    raise RuntimeError(
                        "Planning RunResult exists before its first publication"
                    )
            else:
                prior_result = self.run_result
                if type(prior_result) is not RunResult:
                    raise RuntimeError("Planning RunResult state is inconsistent")
                prior_document = prior_result.to_dict()
                if any(
                    original_documents[relative] is None
                    or original_documents[relative][1] != prior_document
                    for _dut_id, relative in dut_result_paths
                ) or (
                    original_documents[root_result_relative] is None
                    or original_documents[root_result_relative][1] != prior_document
                ):
                    raise RuntimeError(
                        "Existing planning RunResult projection is inconsistent"
                    )

            result_document = result.to_dict()
            root_metadata_document = self._planning_metadata_projection(
                original_root_metadata[1],
                result,
            )
            dut_metadata_documents = tuple(
                (
                    relative,
                    self._planning_metadata_projection(
                        original_documents[relative][1],
                        result,
                        dut_id=dut_id,
                    ),
                )
                for dut_id, relative in dut_metadata_paths
            )

            publications: list[tuple[Path, Dict[str, Any]]] = [
                (root_metadata_relative, root_metadata_document),
                *dut_metadata_documents,
                *(
                    (relative, result_document)
                    for _dut_id, relative in dut_result_paths
                ),
                # The root RunResult is the planning commit marker and is always last.
                (root_result_relative, result_document),
            ]
            self._publication_deadline = (
                time.monotonic() + self._snapshot_io_budget_seconds(len(roster))
            )
            try:
                non_marker_publications = publications[:-1]
                root_marker = publications[-1]
                for relative, document in non_marker_publications:
                    self._atomic_write_at(
                        self._require_output_root_fd(),
                        relative,
                        document,
                        durable=True,
                        public=True,
                    )
                for relative, document in non_marker_publications:
                    if (
                        self._read_public_json_document(
                            relative,
                            maximum_bytes=self._snapshot_leaf_limit(relative),
                        )
                        != document
                    ):
                        raise RuntimeError(
                            "Planning RunResult projection was not durable"
                        )
                # All outcome-bearing work is complete before this rename. The
                # durable root RunResult is the sole commit marker; no readback,
                # close, or diagnostic after it may turn this truth into a
                # command failure that cannot be reprojected.
                self._atomic_write_at(
                    self._require_output_root_fd(),
                    root_marker[0],
                    root_marker[1],
                    durable=True,
                    public=True,
                    terminal_commit=True,
                )
            except BaseException as error:
                self._publication_deadline = None
                rollback_errors: list[BaseException] = []
                # Restore the root commit marker last.  Until then no reader can
                # mistake a partially restored projection for a committed one.
                for relative in publication_paths:
                    original = original_documents[relative]
                    try:
                        if original is None:
                            self._unlink_public_leaf_if_present(relative)
                        else:
                            self._atomic_write_at(
                                self._require_output_root_fd(),
                                relative,
                                original[0],
                                durable=True,
                                public=True,
                            )
                    except BaseException as rollback_error:
                        rollback_errors.append(rollback_error)
                if rollback_errors:
                    rollback_failure = RuntimeError(
                        "Planning RunResult rollback could not be completed"
                    )
                    try:
                        rollback_failure.add_note(
                            f"publication failed: {type(error).__name__}"
                        )
                        for rollback_error in rollback_errors:
                            rollback_failure.add_note(
                                f"rollback failed: {type(rollback_error).__name__}"
                            )
                    except BaseException:
                        pass
                    raise rollback_failure from error
                raise
            finally:
                self._publication_deadline = None

            self.run_result = result
            self._finalization_receipt = evidence_receipt
            self._lifecycle_state = _TrackerLifecycle.PLANNING_FINALIZED
            if close:
                try:
                    self.close()
                except BaseException as error:
                    try:
                        if len(self._terminal_commit_diagnostics) < 8:
                            self._terminal_commit_diagnostics.append(
                                f"descriptor_close:{type(error).__name__}"
                            )
                    except BaseException:
                        pass
            return evidence_receipt

    async def commit_run_result(
        self,
        result: RunResult,
        evidence_receipt: FinalizationReceipt,
        *,
        close: bool = False,
    ) -> FinalizationReceipt:
        """
        Commit the sole result projection as a new terminal generation.

        Lifecycle teardown can fail after the first collector snapshot. The
        orchestrator therefore keeps this tracker's pinned descriptors open,
        derives a candidate from the teardown-bearing receipt, and commits it
        before reports or archives consume the tree. A late report/archive
        failure may call this method once more with a different result while the
        loose tree remains available.

        Args:
            result: Result object whose ``affected_duts``,
                ``collection_status``, ``explicit_domain_failure``, ``reasons``,
                and ``runtime_status`` state is read while performing commit the
                sole result projection as a new terminal generation.
            evidence_receipt: Evidence receipt object whose
                ``archive_artifact_digests``, ``archive_duration_seconds``,
                ``completed_teardown_phases``, and ``failures`` state is read
                while performing commit the sole result projection as a new
                terminal generation.
            close: Whether close is enabled or required for this operation.

        Returns:
            A ``FinalizationReceipt`` representing commit run result.

        Raises:
            TypeError: If a canonical RunResult is required.
            RuntimeError: If runResult differs from finalization evidence;
                runresult lacks a finalized collector snapshot; or runResult
                publication root is closed.
            BaseException: If a delegated failure occurs while the function
                attempts to commit the sole result projection as a new terminal
                generation.
        """

        if type(result) is not RunResult:
            raise TypeError("A canonical RunResult is required")
        validate_structural_finalization_receipt(evidence_receipt)
        expected = RunResult.from_finalization_receipt(evidence_receipt)
        if result != expected:
            raise RuntimeError("RunResult differs from finalization evidence")

        async with self._lifecycle_lock:
            if self._lifecycle_state is not _TrackerLifecycle.FINALIZED:
                raise RuntimeError("RunResult requires a finalized collector snapshot")
            if self._output_root_fd < 0:
                if self.run_result == result:
                    return evidence_receipt
                raise RuntimeError("RunResult publication root is closed")

            previous_result = self.run_result
            previous_intent = self._outcome_intent
            previous_outcome = self.run_outcome
            if previous_result != result:
                self.run_result = result
                preserve_explicit_selection = bool(
                    result.explicit_domain_failure
                    and previous_intent.status == "domain_failed"
                    and previous_intent.failure_type in EXPLICIT_SELECTION_FAILURE_TYPES
                    and previous_outcome.get("evidence")
                    == EXPLICIT_SELECTION_EVIDENCE_PATH
                )
                if preserve_explicit_selection:
                    # The canonical result owns severity while this flat hint
                    # retains the producer-specific selection classification.
                    self._outcome_intent = previous_intent
                else:
                    self._outcome_intent = FinalizationOutcomeHint(
                        status=(
                            "interrupted"
                            if result.runtime_status.value == "interrupted"
                            else (
                                "runtime_failed"
                                if result.runtime_status.value == "failed"
                                else (
                                    "domain_failed"
                                    if result.collection_status.value
                                    in {"partial", "failed"}
                                    else "success"
                                )
                            )
                        ),
                        failure_type=(
                            "finalization_failure"
                            if result.runtime_status.value == "failed"
                            else (
                                "collector_result_failure"
                                if result.collection_status.value
                                in {"partial", "failed"}
                                else ""
                            )
                        ),
                        reason=result.reasons[0] if result.reasons else "",
                        affected_duts=result.affected_duts,
                    )
                self.run_outcome = project_legacy_run_outcome(
                    result,
                    domain_hint=(
                        previous_outcome if preserve_explicit_selection else None
                    ),
                )
                try:
                    publication = await self._publish_candidate_snapshot(
                        include_summaries=True,
                        include_timing=True,
                        terminal=True,
                        new_generation=True,
                    )
                except BaseException:
                    self.run_result = previous_result
                    self._outcome_intent = previous_intent
                    self.run_outcome = previous_outcome
                    raise

            receipt = self._build_finalization_receipt().with_cleanup_evidence(
                completed_teardown_phases=evidence_receipt.completed_teardown_phases,
                failures=evidence_receipt.failures,
            )
            if evidence_receipt.archive_artifact_digests:
                assert evidence_receipt.archive_duration_seconds is not None
                receipt = receipt.with_archive_evidence(
                    evidence_receipt.archive_artifact_digests,
                    archive_duration_seconds=evidence_receipt.archive_duration_seconds,
                )
            self._finalization_receipt = receipt
            if previous_result != result:
                try:
                    self._raise_post_commit_control_flow(publication)
                    if publication.candidate_cleanup_error is not None:
                        raise publication.candidate_cleanup_error
                    await run_managed_filesystem_operation(
                        partial(
                            self.validate_durable_snapshot,
                            list(self._declared_dut_ids or ()),
                            _allow_pending_run_result=False,
                        )
                    )
                except BaseException as error:
                    raise attach_finalization_receipt(error, receipt)
            if close:
                self.close()
            return receipt
