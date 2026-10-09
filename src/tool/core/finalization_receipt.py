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
Immutable evidence returned by local collection finalization.

This module owns the finalization receipt boundary and exposes
``_has_exact_type``, ``FrozenCollectorStatus``, ``FinalizationFailure``,
``FinalizationOutcomeHint``, and ``CapturedAwaitableOutcome``. Keeping those
contracts together gives importers one source of truth for their validation,
lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import asyncio
import math
import re
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable, Iterable, Iterator, Optional, Tuple

from ..utils.run_limits import (
    MAX_COLLECTOR_ID_BYTES,
    MAX_DUT_ID_BYTES,
    MAX_DUTS,
    MAX_TRACKED_COLLECTOR_RECORDS,
    is_printable_identity,
)
from ..utils.sanitizer import BuiltInSanitizers, LogSanitizer
from .run_identity import RunIdentity, validate_sealed_run_identity

MANDATORY_TEARDOWN_PHASES: Tuple[str, ...] = (
    "extension_lifecycle",
    "request_capture",
    "run_provenance",
    "dut_manager_sessions",
    "service_sessions",
    "resource_monitor",
    "logger",
    "aiohttp_session_sweep",
)
DELIVERABLE_POST_COLLECTION_FAILURE_PHASES = frozenset(
    {
        "legacy_report",
        "spa_report",
        "report_reprojection",
        "archive",
    }
)

COLLECTOR_COUNT_FIELDS: Tuple[str, ...] = (
    "total_collectors",
    "pending_collectors",
    "running_collectors",
    "completed_collectors",
    "degraded_collectors",
    "partial_collectors",
    "failed_collectors",
    "skipped_collectors",
    "cancelled_collectors",
    "baseboard_excluded",
    "capability_excluded",
    "config_excluded",
)
LEGACY_COLLECTOR_COUNT_FIELDS: Tuple[str, ...] = tuple(
    name for name in COLLECTOR_COUNT_FIELDS if name != "degraded_collectors"
)

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|secret|credential|api[_-]?key)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_URI_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@")
_URI_QUERY_CREDENTIAL = re.compile(
    r"(?i)([?&](?:access[_-]?token|api[_-]?key|auth|credential|password|secret|"
    r"signature|x-amz-credential|x-amz-signature)=)[^&#\s]*"
)
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_MAX_FAILURE_MESSAGE_CHARS = 512
_UNCONDITIONAL_RECEIPT_SANITIZER = LogSanitizer(
    replacement_string="XXXX",
    additional_regex=[
        BuiltInSanitizers.TOKENS,
        BuiltInSanitizers.PRIVATE_KEYS,
        BuiltInSanitizers.COOKIES,
        BuiltInSanitizers.AWS_ACCESS_KEY_IDS,
    ],
    enabled=True,
)
CONTROL_FLOW_EXCEPTIONS = (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

SnapshotLeafDigest = Tuple[str, int, str]
ArchiveArtifactDigest = Tuple[str, int, str]


def _has_exact_type(value: object, expected_type: type) -> bool:
    """
    Reject subclasses while satisfying strict receipt value semantics.

    The implementation uses ``value`` and ``expected_type`` to reject subclasses
    while satisfying strict receipt value semantics. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        value: Value whose exact runtime type is inspected without accepting
            subclasses.
        expected_type: Exact runtime type required for ``value``.

    Returns:
        Whether the subclasses while satisfying strict receipt value semantics
        operation succeeds.
    """

    return object.__getattribute__(value, "__class__") is expected_type


@dataclass(frozen=True)
class FrozenCollectorStatus:
    """
    Terminal status for one exact DUT/collector identity.

    The immutable record keeps ``dut_id``, ``collector_id``, and ``status``
    together so consumers observe one frozen collector status state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        dut_id: Canonical text used as DUT identifier.
        collector_id: Canonical text used as collector identifier.
        status: Canonical status exposed to downstream status consumers.
    """

    dut_id: str
    collector_id: str
    status: str


@dataclass(frozen=True)
class FinalizationFailure:
    """
    Bounded, sanitized failure evidence in observation order.

    The immutable record keeps ``phase``, ``error_type``, and ``message``
    together so consumers observe one finalization failure state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        phase: Canonical text used as phase.
        error_type: Canonical text used as error type.
        message: Canonical text used as message.
    """

    phase: str
    error_type: str
    message: str


@dataclass(frozen=True)
class FinalizationOutcomeHint:
    """
    Flat pre-finalization domain evidence frozen into the receipt.

    This preserves explicit selection/runtime classifications without retaining
    the historical mutable or recursively nested ``run_outcome`` document.

    Attributes:
        status: Canonical status exposed to downstream status consumers.
        failure_type: Canonical text used as failure type.
        reason: Canonical reason exposed to downstream status consumers.
        affected_duts: Collection of affected duts entries retained by this
            record.
    """

    status: str = "success"
    failure_type: str = ""
    reason: str = ""
    affected_duts: Tuple[str, ...] = ()

    def to_legacy_run_outcome(self) -> dict[str, Any]:
        """
        Project the typed intent into the historical flat document.

        The implementation uses current instance state to project the typed
        intent into the historical flat document.

        Returns:
            The validated ``value``.
        """

        value: dict[str, Any] = {
            "adapter_schema_version": "1.0",
            "status": self.status,
            "reason": self.reason,
            "affected_duts": list(self.affected_duts),
        }
        if self.failure_type:
            value["failure_type"] = self.failure_type
        return value


@dataclass(frozen=True)
class CapturedAwaitableOutcome:
    """
    A child result whose ``BaseException`` cannot escape its task callback.

    The immutable record keeps ``value``, ``error``, and ``owner_cancelled``
    together so consumers observe one captured awaitable outcome state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        value: Value retained as part of the record's public state.
        error: Captured exception, or ``None`` when the operation completed
            normally.
        owner_cancelled: Whether owner cancelled applies to this record.
    """

    value: Any = None
    error: BaseException | None = None
    owner_cancelled: bool = False


async def capture_owned_awaitable(
    awaitable: Awaitable[Any],
) -> CapturedAwaitableOutcome:
    """
    Convert every child completion, including process controls, to data.

    ``asyncio`` task callbacks do not safely contain ``KeyboardInterrupt`` or
    ``SystemExit``. Owners which launch concurrent work must wrap the child
    coroutine itself, not merely use ``gather(return_exceptions=True)``.

    Args:
        awaitable: Awaitable consumed while the function attempts to convert
            every child completion, including process controls, to data.

    Returns:
        A ``CapturedAwaitableOutcome`` representing capture owned awaitable.
    """

    try:
        return CapturedAwaitableOutcome(value=await awaitable)
    except BaseException as error:
        return CapturedAwaitableOutcome(error=error)


async def drain_owned_tasks(
    tasks: Iterable[asyncio.Task[CapturedAwaitableOutcome]],
    *,
    cancel_on_error: Callable[[BaseException], bool] | None = None,
    cancel_on_wait_error: bool = True,
) -> Tuple[CapturedAwaitableOutcome, ...]:
    """
    Drain an exact owned task set without losing completion-edge controls.

    Caller cancellation is recorded before task-completion state is examined.
    Every owned child is then drained, and any child errors are combined with
    the caller-side control through the shared deterministic selector.

    Args:
        tasks: Entries supplied as ``tasks`` without transferring container
            ownership.
        cancel_on_error: Optional cancel on error; ``None`` selects the
            function's default behavior.
        cancel_on_wait_error: Whether cancel on wait error is enabled or
            required for this operation.

    Returns:
        The validated ``ordered_outcomes``.

    Raises:
        ValueError: If owned task set contains a duplicate task.
        BaseException: If a delegated failure occurs while the function attempts
            to drain an exact owned task set without losing completion-edge
            controls.
    """

    ordered_tasks = tuple(tasks)
    if len(ordered_tasks) != len({id(task) for task in ordered_tasks}):
        raise ValueError("Owned task set contains a duplicate task")
    pending = set(ordered_tasks)
    outcomes: dict[int, CapturedAwaitableOutcome] = {}
    wait_errors: list[BaseException] = []
    owner_cancelled_ids: set[int] = set()

    while pending:
        try:
            completed, still_pending = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_COMPLETED,
            )
        except BaseException as error:
            # Record first, even when cancellation arrived on the exact loop
            # turn where the final child completed.  Checking ``done()`` first
            # would silently discard that control-flow event.
            wait_errors.append(error)
            if cancel_on_wait_error:
                for task in pending:
                    if not task.done():
                        if task.cancel():
                            owner_cancelled_ids.add(id(task))
            continue

        pending = set(still_pending)
        cancel_remaining = False
        for task in completed:
            try:
                outcome = task.result()
            except BaseException as error:
                # Defend against an owner or event loop cancelling the wrapper
                # before its first instruction executes.
                outcome = CapturedAwaitableOutcome(error=error)
            if type(outcome) is not CapturedAwaitableOutcome:
                outcome = CapturedAwaitableOutcome(
                    error=RuntimeError("Owned child returned a malformed outcome")
                )
            outcomes[id(task)] = outcome
            if (
                outcome.error is not None
                and cancel_on_error is not None
                and cancel_on_error(outcome.error)
            ):
                cancel_remaining = True
        if cancel_remaining:
            for task in pending:
                if not task.done():
                    if task.cancel():
                        owner_cancelled_ids.add(id(task))

    ordered_outcomes = tuple(
        (
            replace(outcome, owner_cancelled=True)
            if id(task) in owner_cancelled_ids
            and isinstance(outcome.error, asyncio.CancelledError)
            else outcome
        )
        for task in ordered_tasks
        for outcome in (
            outcomes.get(
                id(task),
                CapturedAwaitableOutcome(
                    error=RuntimeError("Owned child completion was not retained")
                ),
            ),
        )
    )
    if wait_errors:
        child_errors = tuple(
            outcome.error
            for outcome in ordered_outcomes
            if outcome.error is not None and not outcome.owner_cancelled
        )
        raise select_authoritative_exception((*wait_errors, *child_errors))
    return ordered_outcomes


@dataclass(frozen=True)
class FinalizationReceipt:
    """
    Frozen local-run result; delivery state is deliberately out of scope.

    The immutable record keeps ``committed_generation``,
    ``terminal_snapshot_committed``, ``dut_roster``, ``collector_counts``, and
    ``collector_statuses`` together so consumers observe one finalization
    receipt state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        committed_generation: Canonical text used as committed generation.
        terminal_snapshot_committed: Whether terminal snapshot committed applies
            to this record.
        dut_roster: Collection of DUT roster entries retained by this record.
        collector_counts: Collection of collector counts entries retained by
            this record.
        collector_statuses: Collection of collector statuses entries retained by
            this record.
        interrupted: Whether interrupted applies to this record.
        outcome_hint: Numeric outcome hint retained by this record.
        snapshot_leaf_digests: Collection of snapshot leaf digests entries
            retained by this record.
        archive_artifact_digests: Collection of archive artifact digests entries
            retained by this record.
        archive_duration_seconds: Number of archive duration seconds represented
            by this record.
        completed_teardown_phases: Collection of completed teardown phases
            entries retained by this record.
        failures: Collection of failures entries retained by this record.
        run_identity: Run identity retained as part of the record's public
            state.
        diagnostics: Bounded nonfatal live-status publication errors. These are
            evidence of recovered progress failures and never replace required
            terminal snapshot, teardown, sanitization or delivery evidence.
    """

    committed_generation: Optional[str]
    terminal_snapshot_committed: bool
    dut_roster: Tuple[str, ...]
    collector_counts: Tuple[Tuple[str, int], ...]
    collector_statuses: Tuple[FrozenCollectorStatus, ...]
    interrupted: bool
    outcome_hint: FinalizationOutcomeHint = FinalizationOutcomeHint()
    snapshot_leaf_digests: Tuple[SnapshotLeafDigest, ...] = ()
    archive_artifact_digests: Tuple[ArchiveArtifactDigest, ...] = ()
    archive_duration_seconds: Optional[float] = None
    completed_teardown_phases: Tuple[str, ...] = ()
    failures: Tuple[FinalizationFailure, ...] = ()
    run_identity: RunIdentity | None = None
    diagnostics: Tuple[FinalizationFailure, ...] = ()

    def with_cleanup_evidence(
        self,
        *,
        completed_teardown_phases: Tuple[str, ...],
        failures: Tuple[FinalizationFailure, ...],
    ) -> "FinalizationReceipt":
        """
        Return a new receipt without mutating the frozen status result.

        After applying local validation, the function forwards
        ``completed_teardown_phases`` and ``failures`` to ``replace`` and
        preserves its return and exception contract. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Args:
            completed_teardown_phases: Entries supplied as
                ``completed_teardown_phases`` without transferring container
                ownership.
            failures: Entries supplied as ``failures`` without transferring
                container ownership.

        Returns:
            A ``FinalizationReceipt`` copy with cleanup evidence applied.
        """

        return replace(
            self,
            completed_teardown_phases=completed_teardown_phases,
            failures=failures,
        )

    def with_interruption(self, interrupted: bool = True) -> "FinalizationReceipt":
        """
        Return a receipt with a sticky interruption observation.

        After applying local validation, the function forwards ``interrupted``
        to ``replace`` and preserves its return and exception contract.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Args:
            interrupted: Whether interrupted is enabled or required for this
                operation.

        Returns:
            A ``FinalizationReceipt`` copy with interruption applied.
        """

        return replace(self, interrupted=bool(self.interrupted or interrupted))

    def with_archive_evidence(
        self,
        archive_artifact_digests: Tuple[ArchiveArtifactDigest, ...],
        *,
        archive_duration_seconds: float,
    ) -> "FinalizationReceipt":
        """
        Return a new receipt bound to the exact finalized archive files.

        After applying local validation, the function forwards
        ``archive_artifact_digests`` and ``archive_duration_seconds`` to
        ``replace`` and preserves its return and exception contract. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            archive_artifact_digests: Entries supplied as
                ``archive_artifact_digests`` without transferring container
                ownership.
            archive_duration_seconds: Maximum duration in seconds allowed for
                archive duration seconds.

        Returns:
            A ``FinalizationReceipt`` copy with archive evidence applied.
        """

        return replace(
            self,
            archive_artifact_digests=archive_artifact_digests,
            archive_duration_seconds=archive_duration_seconds,
        )

    def with_run_identity(self, run_identity: RunIdentity) -> "FinalizationReceipt":
        """
        Bind one sealed identity without permitting later replacement.

        After applying local validation, the function forwards ``run_identity``
        to ``replace`` and preserves its return and exception contract.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Args:
            run_identity: Run identity consumed while the function attempts to
                bind one sealed identity without permitting later replacement.

        Returns:
            A ``FinalizationReceipt`` copy with run identity applied.

        Raises:
            RuntimeError: If finalization receipt identity is already sealed.
        """

        validated = validate_sealed_run_identity(run_identity)
        if self.run_identity is not None and self.run_identity != validated:
            raise RuntimeError("Finalization receipt identity is already sealed")
        return replace(self, run_identity=validated)

    def require_run_identity(self) -> RunIdentity:
        """
        Return the sealed identity required by provenance-aware finalization.

        After applying local validation, the function forwards current instance
        state to ``validate_sealed_run_identity`` and preserves its return and
        exception contract.

        Returns:
            A ``RunIdentity`` representing require run identity.

        Raises:
            RuntimeError: If finalization receipt has no sealed RunIdentity.
        """

        if self.run_identity is None:
            raise RuntimeError("Finalization receipt has no sealed RunIdentity")
        return validate_sealed_run_identity(self.run_identity)

    @property
    def mandatory_teardown_complete(self) -> bool:
        """
        Return whether every mandatory local teardown phase completed.

        Each access computes the value from ``completed_teardown_phases`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            Whether every mandatory local teardown phase completed.
        """

        return self.completed_teardown_phases == MANDATORY_TEARDOWN_PHASES


def empty_finalization_receipt(
    *,
    dut_roster: Tuple[str, ...] = (),
    interrupted: bool = False,
) -> FinalizationReceipt:
    """
    Create a receipt for a mode with no transactional collection snapshot.

    After applying local validation, the function forwards ``dut_roster`` and
    ``interrupted`` to ``FinalizationReceipt`` and preserves its return and
    exception contract.

    Args:
        dut_roster: Entries supplied as ``dut_roster`` without transferring
            container ownership.
        interrupted: Whether interrupted is enabled or required for this
            operation.

    Returns:
        A ``FinalizationReceipt`` representing empty finalization receipt.
    """

    return FinalizationReceipt(
        committed_generation=None,
        terminal_snapshot_committed=False,
        dut_roster=dut_roster,
        collector_counts=(),
        collector_statuses=(),
        interrupted=interrupted,
    )


def validate_structural_finalization_receipt(
    receipt: FinalizationReceipt,
) -> Tuple[Optional[str], Tuple[str, ...]]:
    """
    Validate exact receipt structure, including incomplete failure evidence.

    The implementation uses ``receipt`` to validate exact receipt structure,
    including incomplete failure evidence. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        receipt: Receipt object whose ``archive_artifact_digests``,
            ``archive_duration_seconds``, ``collector_counts``,
            ``collector_statuses``, and ``committed_generation`` state is read
            while performing exact receipt structure, including incomplete
            failure evidence.

    Returns:
        A tuple containing ``generation`` and ``roster`` in that order.

    Raises:
        TypeError: If a FinalizationReceipt is required.
        RuntimeError: If receipt has a malformed snapshot commit state; receipt
            has a malformed snapshot generation; receipt contains a malformed
            DUT roster; or receipt contains too many DUT identities; or another
            input invariant is violated.
    """

    if type(receipt) is not FinalizationReceipt:
        raise TypeError("A FinalizationReceipt is required")
    generation = receipt.committed_generation
    if not _has_exact_type(receipt.terminal_snapshot_committed, bool):
        raise RuntimeError("Receipt has a malformed snapshot commit state")
    if generation is not None and (
        not _has_exact_type(generation, str)
        or re.fullmatch(r"[0-9a-f]{32}", generation) is None
    ):
        raise RuntimeError("Receipt has a malformed snapshot generation")
    if receipt.terminal_snapshot_committed and generation is None:
        raise RuntimeError("Receipt has a malformed snapshot generation")
    roster = receipt.dut_roster
    if type(roster) is not tuple:
        raise RuntimeError("Receipt contains a malformed DUT roster")
    if len(roster) > MAX_DUTS:
        raise RuntimeError("Receipt contains too many DUT identities")
    if any(not _has_exact_type(dut_id, str) for dut_id in roster):
        raise RuntimeError("Receipt contains an invalid DUT identity")
    if len(roster) != len(set(roster)):
        raise RuntimeError("Receipt contains a duplicate DUT roster")
    for dut_id in roster:
        if (
            not is_printable_identity(dut_id, maximum_bytes=MAX_DUT_ID_BYTES)
            or dut_id in {".", ".."}
            or "/" in dut_id
            or "\\" in dut_id
            or "\x00" in dut_id
        ):
            raise RuntimeError("Receipt contains an invalid DUT identity")
    if (
        type(receipt.collector_counts) is not tuple
        or len(receipt.collector_counts) > 128
    ):
        raise RuntimeError("Receipt contains malformed collector counts")
    normalized_counts = []
    for count in receipt.collector_counts:
        if type(count) is not tuple or tuple.__len__(count) != 2:
            raise RuntimeError("Receipt contains malformed collector counts")
        count_name = tuple.__getitem__(count, 0)
        count_value = tuple.__getitem__(count, 1)
        if (
            not _has_exact_type(count_name, str)
            or not is_printable_identity(count_name, maximum_bytes=128)
            or not _has_exact_type(count_value, int)
            or count_value < 0
            or count_value > MAX_TRACKED_COLLECTOR_RECORDS
        ):
            raise RuntimeError("Receipt contains malformed collector counts")
        normalized_counts.append((count_name, count_value))
    count_names = tuple(name for name, _value in normalized_counts)
    if normalized_counts and count_names not in {
        COLLECTOR_COUNT_FIELDS,
        LEGACY_COLLECTOR_COUNT_FIELDS,
    }:
        raise RuntimeError("Receipt contains malformed collector counts")
    counts_by_name = dict(normalized_counts)

    if (
        type(receipt.collector_statuses) is not tuple
        or len(receipt.collector_statuses) > MAX_TRACKED_COLLECTOR_RECORDS
    ):
        raise RuntimeError("Receipt contains too many collector records")
    seen_collector_identities = set()
    status_counts = {
        "success": 0,
        "degraded": 0,
        "partial": 0,
        "error": 0,
        "skipped": 0,
        "cancelled": 0,
        "not_ran": 0,
        "pending": 0,
        "running": 0,
    }
    for collector_status in receipt.collector_statuses:
        if type(collector_status) is not FrozenCollectorStatus:
            raise RuntimeError("Receipt contains an invalid collector identity")
        identity = (collector_status.dut_id, collector_status.collector_id)
        if (
            not _has_exact_type(collector_status.dut_id, str)
            or not _has_exact_type(collector_status.collector_id, str)
            or not _has_exact_type(collector_status.status, str)
            or collector_status.dut_id not in roster
            or not is_printable_identity(
                collector_status.collector_id,
                maximum_bytes=MAX_COLLECTOR_ID_BYTES,
            )
            or identity in seen_collector_identities
            or collector_status.status
            not in {
                "success",
                "degraded",
                "partial",
                "error",
                "skipped",
                "cancelled",
                "not_ran",
                "pending",
                "running",
            }
        ):
            raise RuntimeError("Receipt contains an invalid collector identity")
        seen_collector_identities.add(identity)
        status_counts[collector_status.status] += 1
    if not normalized_counts and receipt.collector_statuses:
        raise RuntimeError("Receipt collector counts are missing")
    if normalized_counts and (
        counts_by_name["total_collectors"] != len(receipt.collector_statuses)
        or counts_by_name["pending_collectors"] != status_counts["pending"]
        or counts_by_name["running_collectors"] != status_counts["running"]
        or counts_by_name["completed_collectors"] != status_counts["success"]
        or counts_by_name.get("degraded_collectors", 0) != status_counts["degraded"]
        or counts_by_name["partial_collectors"] != status_counts["partial"]
        or counts_by_name["failed_collectors"] != status_counts["error"]
        or counts_by_name["skipped_collectors"]
        != status_counts["skipped"] + status_counts["not_ran"]
        or counts_by_name["cancelled_collectors"] != status_counts["cancelled"]
        or sum(
            counts_by_name[name]
            for name in (
                "baseboard_excluded",
                "capability_excluded",
                "config_excluded",
            )
        )
        > counts_by_name["skipped_collectors"]
    ):
        raise RuntimeError("Receipt collector counts disagree with terminal statuses")
    if not _has_exact_type(receipt.interrupted, bool):
        raise RuntimeError("Receipt contains a malformed interruption state")
    hint = receipt.outcome_hint
    if (
        type(hint) is not FinalizationOutcomeHint
        or not _has_exact_type(hint.status, str)
        or hint.status
        not in {"success", "domain_failed", "runtime_failed", "interrupted"}
        or not _has_exact_type(hint.failure_type, str)
        or not _has_exact_type(hint.reason, str)
        or type(hint.affected_duts) is not tuple
        or any(not _has_exact_type(value, str) for value in hint.affected_duts)
        or len(hint.affected_duts) > MAX_DUTS
        or len(set(hint.affected_duts)) != len(hint.affected_duts)
        or not set(hint.affected_duts).issubset(roster)
        or (
            bool(hint.failure_type)
            and not is_printable_identity(hint.failure_type, maximum_bytes=256)
        )
        or (
            bool(hint.reason)
            and not is_printable_identity(
                hint.reason,
                maximum_bytes=_MAX_FAILURE_MESSAGE_CHARS * 4,
            )
        )
    ):
        raise RuntimeError("Receipt outcome hint is malformed")
    if hint.status in {"domain_failed", "runtime_failed"} and not hint.failure_type:
        raise RuntimeError("Receipt outcome hint is malformed")
    if hint.status in {"success", "interrupted"} and hint.failure_type:
        raise RuntimeError("Receipt outcome hint is malformed")
    if receipt.snapshot_leaf_digests:
        validate_snapshot_leaf_digests(receipt.snapshot_leaf_digests, roster)
    elif receipt.terminal_snapshot_committed:
        raise RuntimeError("Receipt snapshot digest evidence is incomplete")
    archive_digests = receipt.archive_artifact_digests
    if type(archive_digests) is not tuple:
        raise RuntimeError("Receipt archive artifact evidence is malformed")
    if archive_digests:
        from ..utils.zip_utils import validate_archive_artifact_digests

        try:
            validate_archive_artifact_digests(archive_digests)
        except (TypeError, ValueError) as error:
            raise RuntimeError(
                "Receipt archive artifact evidence is malformed"
            ) from error
    archive_duration = receipt.archive_duration_seconds
    if archive_digests:
        if (
            not (
                _has_exact_type(archive_duration, int)
                or _has_exact_type(archive_duration, float)
            )
            or not math.isfinite(float(archive_duration))
            or archive_duration < 0
        ):
            raise RuntimeError("Receipt archive duration evidence is malformed")
    elif archive_duration is not None:
        raise RuntimeError("Receipt archive duration evidence is malformed")
    if type(receipt.completed_teardown_phases) is not tuple or any(
        not _has_exact_type(phase, str) or phase not in MANDATORY_TEARDOWN_PHASES
        for phase in receipt.completed_teardown_phases
    ):
        raise RuntimeError("Receipt teardown evidence is malformed")
    if len(receipt.completed_teardown_phases) != len(
        set(receipt.completed_teardown_phases)
    ):
        raise RuntimeError("Receipt teardown evidence is malformed")
    if type(receipt.failures) is not tuple or len(receipt.failures) > 4096:
        raise RuntimeError("Receipt failure evidence is malformed")
    for failure in receipt.failures:
        if (
            type(failure) is not FinalizationFailure
            or not _has_exact_type(failure.phase, str)
            or not _has_exact_type(failure.error_type, str)
            or not _has_exact_type(failure.message, str)
            or not is_printable_identity(failure.phase, maximum_bytes=128)
            or not is_printable_identity(failure.error_type, maximum_bytes=256)
            or not is_printable_identity(
                failure.message,
                maximum_bytes=_MAX_FAILURE_MESSAGE_CHARS * 4,
            )
        ):
            raise RuntimeError("Receipt failure evidence is malformed")
    if type(receipt.diagnostics) is not tuple or len(receipt.diagnostics) > 64:
        raise RuntimeError("Receipt diagnostic evidence is malformed")
    for diagnostic in receipt.diagnostics:
        if (
            type(diagnostic) is not FinalizationFailure
            or type(diagnostic.phase) is not str
            or diagnostic.phase != "live_status_snapshot"
            or type(diagnostic.error_type) is not str
            or type(diagnostic.message) is not str
            or not is_printable_identity(diagnostic.error_type, maximum_bytes=256)
            or not is_printable_identity(
                diagnostic.message, maximum_bytes=_MAX_FAILURE_MESSAGE_CHARS * 4
            )
        ):
            raise RuntimeError("Receipt diagnostic evidence is malformed")
    if receipt.run_identity is not None:
        try:
            validate_sealed_run_identity(receipt.run_identity)
        except (TypeError, ValueError) as error:
            raise RuntimeError("Receipt run identity is malformed") from error
    return generation, roster


def validate_consumable_finalization_receipt(
    receipt: FinalizationReceipt,
) -> Tuple[str, Tuple[str, ...]]:
    """
    Return the exact generation/roster authorized for current-run consumers.

    The implementation uses ``receipt`` to produce the exact generation/roster
    authorized for current-run consumers. If the function cannot produce the
    exact generation/roster authorized for current-run consumers, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        receipt: Receipt object whose ``collector_counts`` and
            ``terminal_snapshot_committed`` state is read while performing exact
            generation/roster authorized for current-run consumers.

    Returns:
        A tuple containing ``generation`` and ``roster`` in that order.

    Raises:
        RuntimeError: If receipt does not authorize a terminal snapshot.
    """

    generation, roster = validate_structural_finalization_receipt(receipt)
    counts = dict(receipt.collector_counts)
    if (
        receipt.terminal_snapshot_committed is not True
        or generation is None
        or counts.get("pending_collectors") != 0
        or counts.get("running_collectors") != 0
    ):
        raise RuntimeError("Receipt does not authorize a terminal snapshot")
    return generation, roster


def finalization_failures_allow_delivery(receipt: FinalizationReceipt) -> bool:
    """
    Return whether failures still leave one verified safe archive to deliver.

    Collector/domain failures are represented outside ``receipt.failures`` and
    already permit delivery.  This exception is deliberately narrower: only
    post-collection report/archive phases may coexist with delivery, and only
    when immutable archive digest evidence proves the loose tree was replaced
    by a verified artifact.  Teardown, sanitization, provenance, status, and
    interruption failures remain hard delivery gates.

    Args:
        receipt: Exact finalization receipt whose failure and teardown evidence
            governs delivery.

    Returns:
        Whether the receipt authorizes delivery of its verified archive.

    Raises:
        TypeError: If ``receipt`` is not an exact ``FinalizationReceipt``.
    """

    if type(receipt) is not FinalizationReceipt:
        raise TypeError("Delivery policy requires an exact finalization receipt")
    if receipt.interrupted or not receipt.mandatory_teardown_complete:
        return False
    if not receipt.failures:
        return True
    return bool(receipt.archive_artifact_digests) and all(
        failure.phase in DELIVERABLE_POST_COLLECTION_FAILURE_PHASES
        for failure in receipt.failures
    )


def expected_snapshot_leaf_paths(roster: Tuple[str, ...]) -> Tuple[str, ...]:
    """
    Return the complete authoritative terminal-leaf path set.

    After applying local validation, the function forwards ``roster`` to
    ``tuple`` and preserves its return and exception contract.

    Args:
        roster: Entries supplied as ``roster`` without transferring container
            ownership.

    Returns:
        The expected snapshot leaf paths returned in operation-defined order.
    """

    paths = {
        ".metadata/collection_status.json",
        ".metadata/collection_status_summary.txt",
        ".metadata/run_result.json",
    }
    for dut_id in roster:
        paths.update(
            {
                f"{dut_id}/.metadata/collection_status.json",
                f"{dut_id}/.metadata/run_result.json",
                f"{dut_id}/.metadata/timing.json",
                f"{dut_id}/collection_status_summary.txt",
            }
        )
    return tuple(sorted(paths))


def validate_snapshot_leaf_digests(
    digests: Any,
    roster: Tuple[str, ...],
) -> Tuple[SnapshotLeafDigest, ...]:
    """
    Validate exact, ordered size+SHA-256 evidence for every terminal leaf.

    The implementation uses ``digests`` and ``roster`` to validate exact,
    ordered size+SHA-256 evidence for every terminal leaf. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        digests: Entries supplied as ``digests`` and processed in
            caller-provided order.
        roster: Entries supplied as ``roster`` without transferring container
            ownership.

    Returns:
        The validated ``normalized_tuple``.

    Raises:
        RuntimeError: If receipt snapshot digest evidence is malformed; or
            receipt snapshot digest evidence is incomplete.
    """

    if type(digests) is not tuple:
        raise RuntimeError("Receipt snapshot digest evidence is malformed")
    normalized = []
    for item in digests:
        if (
            type(item) is not tuple
            or tuple.__len__(item) != 3
            or not _has_exact_type(tuple.__getitem__(item, 0), str)
            or not _has_exact_type(tuple.__getitem__(item, 1), int)
            or tuple.__getitem__(item, 1) < 0
            or not _has_exact_type(tuple.__getitem__(item, 2), str)
            or _SHA256_PATTERN.fullmatch(tuple.__getitem__(item, 2)) is None
        ):
            raise RuntimeError("Receipt snapshot digest evidence is malformed")
        normalized.append(
            (
                tuple.__getitem__(item, 0),
                tuple.__getitem__(item, 1),
                tuple.__getitem__(item, 2),
            )
        )
    normalized_tuple = tuple(normalized)
    if tuple(item[0] for item in normalized_tuple) != expected_snapshot_leaf_paths(
        roster
    ):
        raise RuntimeError("Receipt snapshot digest evidence is incomplete")
    return normalized_tuple


def sanitize_finalization_message(
    value: Any,
    *,
    sanitizer: Optional[Callable[[str], Any]] = None,
) -> str:
    """
    Return an unconditionally scrubbed, bounded terminal diagnostic.

    The implementation uses ``value`` and ``sanitizer`` to produce an
    unconditionally scrubbed, bounded terminal diagnostic.

    Args:
        value: Value evaluated while performing unconditionally scrubbed,
            bounded terminal diagnostic.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.

    Returns:
        The validated ``message``.
    """

    try:
        message = str(value)
    except BaseException:
        message = "[unrenderable diagnostic]"
    if sanitizer is not None:
        try:
            sanitized = sanitizer(message)
            if isinstance(sanitized, str):
                message = sanitized
        except BaseException:
            message = "[message sanitization failed]"
    message = _URI_USERINFO.sub(r"\1XXXX@", message)
    message = _URI_QUERY_CREDENTIAL.sub(r"\1XXXX", message)
    message = _SECRET_ASSIGNMENT.sub(r"\1\2XXXX", message)
    message = _JWT.sub("XXXX", message)
    message = _UNCONDITIONAL_RECEIPT_SANITIZER.sanitize(message)
    message = " ".join(message.split())[:_MAX_FAILURE_MESSAGE_CHARS]
    if not message:
        message = "[no diagnostic detail]"
    return message


def sanitize_finalization_failure(
    phase: str,
    error: BaseException,
    *,
    sanitizer: Optional[Callable[[str], Any]] = None,
) -> FinalizationFailure:
    """
    Convert an exception into bounded transport-safe receipt evidence.

    After applying local validation, the function forwards ``phase``, ``error``,
    and ``sanitizer`` to ``FinalizationFailure`` and preserves its return and
    exception contract. The source value keeps its ownership while the
    normalized representation is returned separately.

    Args:
        phase: Text supplied as phase in the format accepted by this function.
        error: Exception or failure detail associated with the operation.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.

    Returns:
        A ``FinalizationFailure`` representing finalization failure.
    """

    message = sanitize_finalization_message(error, sanitizer=sanitizer)
    return FinalizationFailure(
        phase=phase,
        error_type=type(error).__name__,
        message=message,
    )


def _failure_message(receipt: FinalizationReceipt) -> str:
    """
    Return the failure message.

    The implementation uses ``receipt`` to produce the failure message.

    Args:
        receipt: Receipt object whose ``failures`` state is read while
            performing failure message.

    Returns:
        The canonical failure message.
    """
    if not receipt.failures:
        return "Collection finalization failed"
    detail = "; ".join(
        f"{failure.phase}: {failure.error_type}: {failure.message}"
        for failure in receipt.failures
    )
    return f"Collection finalization failed ({detail})"


class FinalizationReceiptError(RuntimeError):
    """
    A local finalization failure carrying immutable partial evidence.

    Callers receive this exception when the finalization receipt error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """

    def __init__(self, receipt: FinalizationReceipt) -> None:
        """
        Initialize a ``FinalizationReceiptError`` instance.

        The initializer records ``receipt`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            receipt: Receipt consumed while the function attempts to initialize
                a ``FinalizationReceiptError`` instance.
        """
        self.receipt = receipt
        super().__init__(_failure_message(receipt))


class FinalizationReceiptCancelledError(asyncio.CancelledError):
    """
    Cancellation carrying immutable partial local-finalization evidence.

    Callers receive this exception when the finalization receipt cancelled error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """

    def __init__(self, receipt: FinalizationReceipt) -> None:
        """
        Initialize a ``FinalizationReceiptCancelledError`` instance.

        The initializer records ``receipt`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            receipt: Receipt consumed while the function attempts to initialize
                a ``FinalizationReceiptCancelledError`` instance.
        """
        self.receipt = receipt
        super().__init__(_failure_message(receipt))


def is_control_flow_exception(error: BaseException) -> bool:
    """
    Return whether an exception represents Python task/process control flow.

    After applying local validation, the function forwards ``error`` to ``any``
    and preserves its return and exception contract.

    Args:
        error: Exception or failure detail associated with the operation.

    Returns:
        Whether an exception represents Python task/process control flow.
    """

    return any(
        isinstance(leaf, CONTROL_FLOW_EXCEPTIONS)
        for leaf in iter_exception_leaves(error)
    )


def is_interruption_exception(error: BaseException) -> bool:
    """
    Return whether control flow represents an actual interrupted command.

    After applying local validation, the function forwards ``error`` to ``any``
    and preserves its return and exception contract.

    Args:
        error: Exception or failure detail associated with the operation.

    Returns:
        Whether control flow represents an actual interrupted command.
    """

    return any(
        isinstance(leaf, (asyncio.CancelledError, KeyboardInterrupt))
        or (
            isinstance(leaf, SystemExit)
            and type(leaf.code) is int  # noqa: E721 - subclasses are rejected
            and leaf.code == 130  # noqa: E721 - subclasses are rejected
        )
        for leaf in iter_exception_leaves(error)
    )


def iter_exception_leaves(error: BaseException) -> Iterator[BaseException]:
    """
    Yield nested exception-group leaves in deterministic observation order.

    The implementation uses ``error`` to yield nested exception-group leaves in
    deterministic observation order.

    Args:
        error: Exception or failure detail associated with the operation.

    Yields:
        Each exception leaves admitted by the operation, in deterministic
        iteration order.
    """

    if isinstance(error, BaseExceptionGroup):
        for nested in error.exceptions:
            yield from iter_exception_leaves(nested)
        return
    yield error


def select_authoritative_exception(
    errors: Iterable[BaseException],
) -> BaseException:
    """
    Select cleanup control flow without depending on observation order.

    A real interruption must not be hidden by an earlier non-interrupting
    ``SystemExit``. Observation order remains stable within each priority class
    so repeated cleanup failures are deterministic.

    Args:
        errors: Entries supplied as ``errors`` without transferring container
            ownership.

    Returns:
        The validated ``winner``.

    Raises:
        ValueError: If at least one exception is required.
    """

    observed = tuple(errors)
    if not observed:
        raise ValueError("At least one exception is required")
    leaves = tuple(leaf for error in observed for leaf in iter_exception_leaves(error))
    winner: BaseException | None = None
    for error in leaves:
        if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt)) or (
            isinstance(error, SystemExit)
            and type(error.code) is int  # noqa: E721 - subclasses are rejected
            and error.code == 130
        ):
            winner = error
            break
    if winner is None:
        for error in leaves:
            if isinstance(error, SystemExit):
                winner = error
                break
    if winner is None:
        winner = leaves[0]
    secondary = tuple(leaf for leaf in leaves if leaf is not winner)
    if secondary:
        note = "Additional cleanup failures were retained: " + ", ".join(
            type(error).__name__ for error in secondary[:16]
        )
        try:
            existing_notes = tuple(getattr(winner, "__notes__", ()))
            if note not in existing_notes:
                winner.add_note(note)
        except BaseException:
            pass
    return winner


def attach_finalization_receipt(
    error: BaseException,
    receipt: FinalizationReceipt,
) -> BaseException:
    """
    Attach immutable finalization evidence without changing exception class.

    The implementation uses ``error`` and ``receipt`` to attach immutable
    finalization evidence without changing exception class.

    Args:
        error: Exception or failure detail associated with the operation.
        receipt: Receipt consumed while the function attempts to attach
            immutable finalization evidence without changing exception class.

    Returns:
        The validated ``error``.
    """

    try:
        error.receipt = receipt  # type: ignore[attr-defined]
    except BaseException:
        try:
            error.add_note("Immutable finalization evidence was retained by the caller")
        except BaseException:
            pass
    return error
