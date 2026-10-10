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
Canonical collection and optional-delivery terminal results.

``RunResult`` is the only supported authority for the outcome of a collection
run. It is deliberately flat, immutable, and derived from the exact
``FinalizationReceipt`` retained by the lifecycle owner. Optional artifact
delivery is a later operation and is represented by ``DeliveryResult`` so an
upload can never rewrite the truth about the local collection.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Tuple

from ..utils.run_limits import (
    MAX_DUT_ID_BYTES,
    MAX_DUTS,
    MAX_TRACKED_COLLECTOR_RECORDS,
    is_printable_identity,
)
from .finalization_receipt import (
    COLLECTOR_COUNT_FIELDS,
    LEGACY_COLLECTOR_COUNT_FIELDS,
    FinalizationReceipt,
    sanitize_finalization_message,
    validate_structural_finalization_receipt,
)
from .run_identity import (
    RunIdentity,
    validate_run_identity_document,
    validate_sealed_run_identity,
)

RUN_RESULT_SCHEMA_VERSION = "1.0"
RUN_RESULT_IDENTITY_SCHEMA_VERSION = "1.1"
DELIVERY_RESULT_SCHEMA_VERSION = "1.1"
LEGACY_DELIVERY_RESULT_SCHEMA_VERSION = "1.0"
LEGACY_RUN_OUTCOME_ADAPTER_VERSION = "1.0"
EXPLICIT_SELECTION_FAILURE_TYPES = frozenset(
    {
        "explicit_selection_no_execution",
        "explicit_selection_preflight_failure",
    }
)
EXPLICIT_SELECTION_EVIDENCE_PATH = ".metadata/selection_failure.json"

MAX_RESULT_REASONS = 32
MAX_RESULT_REASON_BYTES = 2048
MAX_DELIVERY_IDENTIFIERS = 16
MAX_DELIVERY_IDENTIFIER_BYTES = 512
MAX_DELIVERY_URIS = 16
MAX_DELIVERY_URI_BYTES = 2048

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SUCCESS_ONLY_RUN_REASONS = frozenset(
    {
        "complete",
        "completed",
        "completed successfully",
        "ok",
        "pass",
        "passed",
        "success",
        "successful",
    }
)
_RUN_FAILURE_REASON_DEFAULTS = {
    "domain_failed": "Collector outcomes include failures or partial results",
    "runtime_failed": "Collection finalization failed",
    "interrupted": "Collection was interrupted",
    "incomplete": "Collection did not reach a complete terminal outcome",
}


class RuntimeStatus(str, Enum):
    """
    Process/lifecycle domain status.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    SUCCESS = "success"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class CollectionStatus(str, Enum):
    """
    Collector-domain status.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    INCOMPLETE = "incomplete"


class RunMode(str, Enum):
    """
    Whether the result represents execution or transport-free planning.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    COLLECTION = "collection"
    PLANNING = "planning"


class DeliveryStatus(str, Enum):
    """
    Optional external artifact-delivery status.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    NOT_REQUESTED = "not_requested"
    SUCCESS = "success"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


def _bounded_text(value: Any, *, maximum_bytes: int) -> str:
    """
    Return unconditionally scrubbed UTF-8 text bounded by byte length.

    The implementation uses ``value`` and ``maximum_bytes`` to produce
    unconditionally scrubbed UTF-8 text bounded by byte length.

    Args:
        value: Value evaluated while performing unconditionally scrubbed UTF-8
            text bounded by byte length.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The canonical bounded text.
    """

    rendered = sanitize_finalization_message(value)
    rendered = _CONTROL_CHARACTERS.sub(" ", rendered)
    rendered = "".join(
        (
            character
            if not (
                unicodedata.category(character).startswith("C")
                or (
                    unicodedata.category(character).startswith("Z") and character != " "
                )
            )
            else " "
        )
        for character in rendered
    )
    rendered = " ".join(rendered.split())
    encoded = rendered.encode("utf-8", errors="replace")[:maximum_bytes]
    while encoded:
        try:
            return encoded.decode("utf-8")
        except UnicodeDecodeError:
            encoded = encoded[:-1]
    return ""


def is_success_only_run_reason(value: Any) -> bool:
    """
    Return whether text only asserts success and carries no failure detail.

    The implementation uses ``value`` to determine whether text only asserts
    success and carries no failure detail.

    Args:
        value: Value object whose ``split`` state is read while performing text
            only asserts success and carries no failure detail.

    Returns:
        Whether text only asserts success and carries no failure detail.
    """

    if not isinstance(value, str):
        return False
    normalized = " ".join(value.split()).strip(" .!").casefold()
    return normalized in _SUCCESS_ONLY_RUN_REASONS


def normalize_run_outcome_reason(status: Any, reason: Any) -> str:
    """
    Return a bounded reason whose wording agrees with a run outcome.

    Meaningful diagnostics survive unchanged after the common bounded scrub.
    Blank and exact success-only phrases are replaced only for non-success
    states.

    Args:
        status: Status consumed while the function attempts to produce a bounded
            reason whose wording agrees with a run outcome.
        reason: Reason consumed while the function attempts to produce a bounded
            reason whose wording agrees with a run outcome.

    Returns:
        The canonical run outcome reason text.
    """

    status_value = str(getattr(status, "value", status) or "").strip().casefold()
    raw_reason = reason if isinstance(reason, str) else ""
    fallback = _RUN_FAILURE_REASON_DEFAULTS.get(status_value)
    if fallback is not None and (
        not raw_reason.strip()
        or raw_reason == "[no diagnostic detail]"
        or is_success_only_run_reason(raw_reason)
    ):
        return fallback
    rendered = _bounded_text(reason, maximum_bytes=MAX_RESULT_REASON_BYTES)
    if fallback is not None and (
        not rendered
        or rendered == "[no diagnostic detail]"
        or is_success_only_run_reason(rendered)
    ):
        return fallback
    return rendered


def _reason_status(
    runtime_status: RuntimeStatus,
    collection_status: CollectionStatus,
) -> str:
    """
    Return the reason status.

    The implementation uses ``runtime_status`` and ``collection_status`` to
    produce the reason status.

    Args:
        runtime_status: Runtime status consumed while the function attempts to
            produce the reason status.
        collection_status: Collection status consumed while the function
            attempts to produce the reason status.

    Returns:
        The canonical reason status.
    """
    if (
        runtime_status is RuntimeStatus.INTERRUPTED
        or collection_status is CollectionStatus.INTERRUPTED
    ):
        return "interrupted"
    if runtime_status is RuntimeStatus.FAILED:
        return "runtime_failed"
    if collection_status in {CollectionStatus.PARTIAL, CollectionStatus.FAILED}:
        return "domain_failed"
    if collection_status is CollectionStatus.INCOMPLETE:
        return "incomplete"
    return "success"


def _exact_counts(receipt: FinalizationReceipt) -> Tuple[Tuple[str, int], ...]:
    """
    Return the exact counts.

    The implementation uses ``receipt`` to produce the exact counts. If the
    function cannot produce the exact counts, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        receipt: Receipt object whose ``collector_counts`` state is read while
            performing exact counts.

    Returns:
        The validated ``counts``.

    Raises:
        RuntimeError: If finalization receipt has noncanonical collector counts.
    """
    counts = tuple(receipt.collector_counts) or tuple(
        (name, 0) for name in COLLECTOR_COUNT_FIELDS
    )
    count_names = tuple(name for name, _value in counts)
    if count_names == LEGACY_COLLECTOR_COUNT_FIELDS:
        legacy_counts = dict(counts)
        counts = tuple(
            (name, legacy_counts.get(name, 0)) for name in COLLECTOR_COUNT_FIELDS
        )
    elif count_names != COLLECTOR_COUNT_FIELDS:
        raise RuntimeError("Finalization receipt has noncanonical collector counts")
    return counts


def _collection_status_from_counts(
    counts: Tuple[Tuple[str, int], ...],
    *,
    authoritative_interruption: bool,
    explicit_domain_failure: bool,
) -> CollectionStatus:
    """
    Return the collection status from counts.

    The implementation uses ``counts``, ``authoritative_interruption``, and
    ``explicit_domain_failure`` to produce the collection status from counts.

    Args:
        counts: Entries supplied as ``counts`` without transferring container
            ownership.
        authoritative_interruption: Whether authoritative interruption is
            enabled or required for this operation.
        explicit_domain_failure: Whether explicit domain failure is enabled or
            required for this operation.

    Returns:
        A ``CollectionStatus`` representing collection status from counts.
    """
    by_name = dict(counts)
    completed = by_name["completed_collectors"]
    degraded = by_name["degraded_collectors"]
    partial = by_name["partial_collectors"]
    failed = by_name["failed_collectors"]
    pending = by_name["pending_collectors"]
    running = by_name["running_collectors"]
    cancelled = by_name["cancelled_collectors"]
    total = by_name["total_collectors"]
    expected_exclusions = (
        by_name["baseboard_excluded"]
        + by_name["capability_excluded"]
        + by_name["config_excluded"]
    )
    runtime_skipped = by_name["skipped_collectors"] - expected_exclusions
    if authoritative_interruption:
        return CollectionStatus.INTERRUPTED
    if pending or running:
        return CollectionStatus.INCOMPLETE
    if explicit_domain_failure:
        return (
            CollectionStatus.PARTIAL
            if completed or degraded or partial
            else CollectionStatus.FAILED
        )
    if failed or cancelled:
        return (
            CollectionStatus.PARTIAL
            if completed or degraded or partial
            else CollectionStatus.FAILED
        )
    if degraded or partial:
        return CollectionStatus.PARTIAL
    if runtime_skipped:
        return CollectionStatus.PARTIAL if completed else CollectionStatus.INCOMPLETE
    # A committed collection which scheduled work but completed no collector
    # produced no evidence. Endpoint-advertised capability can suppress work,
    # so an all-skipped plan must not be reported as a successful collection.
    if total and not completed:
        return CollectionStatus.INCOMPLETE
    return CollectionStatus.SUCCESS


@dataclass(frozen=True)
class RunResult:
    """
    Frozen, flat result for one finalized local run.

    The immutable record keeps ``schema_version``, ``mode``, ``runtime_status``,
    ``collection_status``, and ``collector_counts`` together so consumers
    observe one run state. Construction validates cross-field invariants before
    the instance is exposed.

    Attributes:
        schema_version: Canonical text used as schema version.
        mode: Mode retained as part of the record's public state.
        runtime_status: Runtime status retained as part of the record's public
            state.
        collection_status: Collection status retained as part of the record's
            public state.
        collector_counts: Collection of collector counts entries retained by
            this record.
        terminal_snapshot_committed: Whether terminal snapshot committed applies
            to this record.
        explicit_domain_failure: Whether explicit domain failure applies to this
            record.
        dut_roster: Collection of DUT roster entries retained by this record.
        affected_duts: Collection of affected duts entries retained by this
            record.
        reasons: Collection of reasons entries retained by this record.
        run_identity: Run identity retained as part of the record's public
            state.
    """

    schema_version: str
    mode: RunMode
    runtime_status: RuntimeStatus
    collection_status: CollectionStatus
    collector_counts: Tuple[Tuple[str, int], ...]
    terminal_snapshot_committed: bool
    explicit_domain_failure: bool
    dut_roster: Tuple[str, ...]
    affected_duts: Tuple[str, ...]
    reasons: Tuple[str, ...]
    run_identity: RunIdentity | None = None

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized RunResult state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            ValueError: If unsupported RunResult schema; legacy RunResult cannot
                contain a run identity; identity-bearing runresult lacks a run
                identity; or runResult mode and identity profile disagree; or
                another input invariant is violated.
            TypeError: If the runresult mode is not canonical; the runresult
                runtime status are not canonical; the runresult collection
                status are not canonical; or the runresult counts are not a
                tuple; or another input invariant is violated.
        """
        if self.schema_version not in {
            RUN_RESULT_SCHEMA_VERSION,
            RUN_RESULT_IDENTITY_SCHEMA_VERSION,
        }:
            raise ValueError("Unsupported RunResult schema")
        if self.schema_version == RUN_RESULT_SCHEMA_VERSION:
            if self.run_identity is not None:
                raise ValueError("Legacy RunResult cannot contain a run identity")
        elif self.run_identity is None:
            raise ValueError("Identity-bearing RunResult requires a run identity")
        else:
            validate_sealed_run_identity(self.run_identity)
        if type(self.mode) is not RunMode:
            raise TypeError("RunResult mode must be canonical")
        if self.run_identity is not None:
            identity_is_planning = self.run_identity.resolved_profile == "planning"
            if (self.mode is RunMode.PLANNING) != identity_is_planning:
                raise ValueError("RunResult mode and identity profile disagree")
        if type(self.runtime_status) is not RuntimeStatus:
            raise TypeError("RunResult runtime status must be canonical")
        if type(self.collection_status) is not CollectionStatus:
            raise TypeError("RunResult collection status must be canonical")
        if type(self.collector_counts) is not tuple:
            raise TypeError("RunResult counts must be a tuple")
        if (
            type(  # noqa: E721 - subclasses are rejected
                self.terminal_snapshot_committed
            )  # noqa: E721 - subclasses are rejected
            is not bool  # noqa: E721 - subclasses are rejected
        ):  # noqa: E721 - subclasses are rejected
            raise TypeError("RunResult snapshot state must be a boolean")
        if (
            type(self.explicit_domain_failure)  # noqa: E721 - subclasses are rejected
            is not bool  # noqa: E721 - subclasses are rejected
        ):  # noqa: E721 - subclasses are rejected
            raise TypeError("RunResult domain-failure state must be a boolean")
        if self.mode is RunMode.PLANNING:
            if self.collector_counts:
                raise ValueError("Planning RunResult cannot contain collector counts")
            if self.terminal_snapshot_committed:
                raise ValueError(
                    "Planning RunResult cannot contain a terminal snapshot"
                )
            if self.explicit_domain_failure:
                raise ValueError("Planning RunResult cannot claim a domain failure")
            if self.runtime_status is RuntimeStatus.SUCCESS:
                expected_collection = CollectionStatus.INCOMPLETE
            elif self.runtime_status is RuntimeStatus.INTERRUPTED:
                expected_collection = CollectionStatus.INTERRUPTED
            else:
                expected_collection = CollectionStatus.INCOMPLETE
        else:
            if tuple(name for name, _value in self.collector_counts) != (
                COLLECTOR_COUNT_FIELDS
            ):
                raise ValueError("RunResult counts are noncanonical")
            count_values = []
            for name, value in self.collector_counts:
                if (
                    type(name) is not str  # noqa: E721 - subclasses are rejected
                    or type(value) is not int  # noqa: E721 - subclasses are rejected
                    or value < 0
                    or value > MAX_TRACKED_COLLECTOR_RECORDS
                ):
                    raise ValueError("RunResult count is invalid")
                count_values.append(value)
            by_name = dict(self.collector_counts)
            terminal_sum = sum(
                by_name[name]
                for name in (
                    "pending_collectors",
                    "running_collectors",
                    "completed_collectors",
                    "degraded_collectors",
                    "partial_collectors",
                    "failed_collectors",
                    "skipped_collectors",
                    "cancelled_collectors",
                )
            )
            if (
                by_name["total_collectors"] != terminal_sum
                or sum(
                    by_name[name]
                    for name in (
                        "baseboard_excluded",
                        "capability_excluded",
                        "config_excluded",
                    )
                )
                > by_name["skipped_collectors"]
            ):
                raise ValueError("RunResult counts are internally inconsistent")
            if self.runtime_status is RuntimeStatus.SUCCESS and (
                by_name["pending_collectors"] or by_name["running_collectors"]
            ):
                raise ValueError(
                    "Successful runtime cannot retain unfinished collectors"
                )
            expected_collection = (
                _collection_status_from_counts(
                    self.collector_counts,
                    authoritative_interruption=(
                        self.runtime_status is RuntimeStatus.INTERRUPTED
                    ),
                    explicit_domain_failure=self.explicit_domain_failure,
                )
                if self.terminal_snapshot_committed
                else (
                    CollectionStatus.INTERRUPTED
                    if self.runtime_status is RuntimeStatus.INTERRUPTED
                    else CollectionStatus.INCOMPLETE
                )
            )
            if (
                not self.terminal_snapshot_committed
                and self.runtime_status is RuntimeStatus.SUCCESS
            ):
                raise ValueError("Uncommitted snapshot cannot report runtime success")
            # A typed receipt may preserve an explicit zero-yield domain failure;
            # it has the same FAILED/PARTIAL projection as the count matrix.
        if self.collection_status is not expected_collection:
            raise ValueError("RunResult statuses contradict its canonical counts")
        if self.runtime_status is RuntimeStatus.INTERRUPTED and (
            self.collection_status is not CollectionStatus.INTERRUPTED
        ):
            raise ValueError("Interrupted runtime must project interrupted collection")
        if type(self.dut_roster) is not tuple or len(self.dut_roster) > MAX_DUTS:
            raise ValueError("RunResult DUT roster is invalid")
        if (
            self.mode is RunMode.COLLECTION
            and dict(self.collector_counts).get("total_collectors", 0) > 0
            and not self.dut_roster
        ):
            raise ValueError("Nonempty collection requires a DUT roster")
        if len(self.dut_roster) != len(set(self.dut_roster)) or any(
            type(value) is not str  # noqa: E721 - subclasses are rejected
            or not is_printable_identity(value, maximum_bytes=MAX_DUT_ID_BYTES)
            or value in {".", ".."}
            or "/" in value
            or "\\" in value
            for value in self.dut_roster
        ):
            raise ValueError("RunResult DUT roster is invalid")
        if (
            type(self.affected_duts) is not tuple
            or len(self.affected_duts) != len(set(self.affected_duts))
            or not set(self.affected_duts).issubset(self.dut_roster)
        ):
            raise ValueError("RunResult affected DUTs are invalid")
        if (
            self.mode is RunMode.COLLECTION
            and self.dut_roster
            and self.collection_status
            in {CollectionStatus.PARTIAL, CollectionStatus.FAILED}
            and not self.affected_duts
        ):
            raise ValueError("Domain-failed RunResult requires an affected DUT")
        if (
            type(self.reasons) is not tuple
            or len(self.reasons) > MAX_RESULT_REASONS
            or any(
                type(reason) is not str  # noqa: E721 - subclasses are rejected
                or not reason
                or _bounded_text(
                    reason,
                    maximum_bytes=MAX_RESULT_REASON_BYTES,
                )
                != reason
                for reason in self.reasons
            )
        ):
            raise ValueError("RunResult reasons are invalid")
        if (
            self.runtime_status is not RuntimeStatus.SUCCESS
            or self.collection_status is not CollectionStatus.SUCCESS
        ) and not self.reasons:
            raise ValueError("Non-success RunResult requires a bounded reason")
        if (
            _reason_status(self.runtime_status, self.collection_status) != "success"
            and self.reasons
            and is_success_only_run_reason(self.reasons[0])
        ):
            raise ValueError("Non-success RunResult cannot carry a success-only reason")

    @classmethod
    def from_finalization_receipt(
        cls,
        receipt: FinalizationReceipt,
    ) -> "RunResult":
        """
        Derive one result from a structurally exact committed receipt.

        The implementation uses ``receipt`` to derive one result from a
        structurally exact committed receipt. If the function cannot derive one
        result from a structurally exact committed receipt, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            receipt: Receipt object whose ``collector_statuses``,
                ``dut_roster``, ``failures``, ``interrupted``, and
                ``mandatory_teardown_complete`` state is read while performing
                derive one result from a structurally exact committed receipt.

        Returns:
            A ``RunResult`` initialized from finalization receipt.

        Raises:
            TypeError: If a FinalizationReceipt is required.
        """

        if type(receipt) is not FinalizationReceipt:
            raise TypeError("A FinalizationReceipt is required")
        try:
            validate_structural_finalization_receipt(receipt)
        except (RuntimeError, TypeError, ValueError) as error:
            reason = _bounded_text(
                f"receipt_validation: {type(error).__name__}: {error}",
                maximum_bytes=MAX_RESULT_REASON_BYTES,
            )
            return cls(
                schema_version=RUN_RESULT_SCHEMA_VERSION,
                mode=RunMode.COLLECTION,
                runtime_status=RuntimeStatus.FAILED,
                collection_status=CollectionStatus.INCOMPLETE,
                collector_counts=tuple((name, 0) for name in COLLECTOR_COUNT_FIELDS),
                terminal_snapshot_committed=False,
                explicit_domain_failure=False,
                dut_roster=(),
                affected_duts=(),
                reasons=(reason,),
            )
        counts = _exact_counts(receipt)
        counts_by_name = dict(counts)
        unfinished_collectors = bool(
            counts_by_name["pending_collectors"] or counts_by_name["running_collectors"]
        )
        hint = receipt.outcome_hint

        if receipt.interrupted or hint.status == "interrupted":
            runtime_status = RuntimeStatus.INTERRUPTED
        elif (
            not receipt.terminal_snapshot_committed
            or receipt.failures
            or not receipt.mandatory_teardown_complete
            or hint.status == "runtime_failed"
            or unfinished_collectors
        ):
            runtime_status = RuntimeStatus.FAILED
        else:
            runtime_status = RuntimeStatus.SUCCESS

        collection_status = _collection_status_from_counts(
            counts,
            authoritative_interruption=(
                receipt.interrupted or hint.status == "interrupted"
            ),
            explicit_domain_failure=hint.status == "domain_failed",
        )
        if not receipt.terminal_snapshot_committed:
            collection_status = (
                CollectionStatus.INTERRUPTED
                if runtime_status is RuntimeStatus.INTERRUPTED
                else CollectionStatus.INCOMPLETE
            )

        reason_values = [
            f"{failure.phase}: {failure.error_type}: {failure.message}"
            for failure in receipt.failures
        ]
        if unfinished_collectors:
            reason_values.insert(0, "Terminal snapshot retained unfinished collectors")
        if not receipt.terminal_snapshot_committed:
            reason_values.insert(0, "Terminal collection snapshot was not committed")
        reason_status = _reason_status(runtime_status, collection_status)
        if hint.reason and not (
            reason_status != "success" and is_success_only_run_reason(hint.reason)
        ):
            reason_values.insert(0, hint.reason)
        if runtime_status is RuntimeStatus.FAILED and not reason_values:
            reason_values.append(normalize_run_outcome_reason(reason_status, ""))
        elif runtime_status is RuntimeStatus.INTERRUPTED and not reason_values:
            reason_values.append(normalize_run_outcome_reason(reason_status, ""))
        elif (
            collection_status
            in {
                CollectionStatus.PARTIAL,
                CollectionStatus.FAILED,
            }
            and not reason_values
        ):
            reason_values.append(normalize_run_outcome_reason(reason_status, ""))
        elif collection_status is CollectionStatus.INCOMPLETE and not reason_values:
            reason_values.append(normalize_run_outcome_reason(reason_status, ""))
        reasons = []
        for value in reason_values:
            rendered = normalize_run_outcome_reason(reason_status, value)
            if rendered and rendered not in reasons:
                reasons.append(rendered)
            if len(reasons) == MAX_RESULT_REASONS:
                break

        affected = list(hint.affected_duts)
        runtime_skipped = (
            counts_by_name["skipped_collectors"]
            - counts_by_name["baseboard_excluded"]
            - counts_by_name["capability_excluded"]
            - counts_by_name["config_excluded"]
        )
        affected_statuses = {"degraded", "partial", "error", "cancelled"}
        if runtime_skipped > 0 and collection_status in {
            CollectionStatus.PARTIAL,
            CollectionStatus.FAILED,
        }:
            # Frozen receipts intentionally keep collector identities compact
            # and do not retain per-record exclusion types. Counts still prove
            # that at least one skip happened at runtime. Conservatively include
            # DUTs with skipped records so the domain-failure projection can
            # never claim an empty affected set.
            affected_statuses.add("skipped")
        for status in receipt.collector_statuses:
            if status.status in affected_statuses:
                if status.dut_id not in affected:
                    affected.append(status.dut_id)

        return cls(
            schema_version=(
                RUN_RESULT_IDENTITY_SCHEMA_VERSION
                if receipt.run_identity is not None
                else RUN_RESULT_SCHEMA_VERSION
            ),
            mode=RunMode.COLLECTION,
            runtime_status=runtime_status,
            collection_status=collection_status,
            collector_counts=counts,
            terminal_snapshot_committed=receipt.terminal_snapshot_committed,
            explicit_domain_failure=(
                hint.status == "domain_failed"
                or collection_status
                in {CollectionStatus.PARTIAL, CollectionStatus.FAILED}
            ),
            dut_roster=tuple(receipt.dut_roster),
            affected_duts=tuple(affected),
            reasons=tuple(reasons),
            run_identity=receipt.run_identity,
        )

    @classmethod
    def from_planning_receipt(cls, receipt: FinalizationReceipt) -> "RunResult":
        """
        Represent a transport-free plan without fabricating collection success.

        A transport-free operation has no collector domain in which a domain
        failure could truthfully live. Preserve that intent as a conservative
        runtime failure instead of silently turning it into.

        Args:
            receipt: Receipt object whose ``archive_artifact_digests``,
                ``collector_counts``, ``collector_statuses``,
                ``committed_generation``, and ``completed_teardown_phases``
                state is read while performing represent a transport-free plan
                without fabricating collection success.

        Returns:
            A ``RunResult`` initialized from planning receipt.

        Raises:
            TypeError: If a FinalizationReceipt is required.
            RuntimeError: If planning receipt contains collection evidence.
        """

        if type(receipt) is not FinalizationReceipt:
            raise TypeError("A FinalizationReceipt is required")
        validate_structural_finalization_receipt(receipt)
        if (
            receipt.terminal_snapshot_committed
            or receipt.committed_generation is not None
            or receipt.collector_counts
            or receipt.collector_statuses
            or receipt.archive_artifact_digests
        ):
            raise RuntimeError("Planning receipt contains collection evidence")
        hint = receipt.outcome_hint
        if receipt.interrupted or hint.status == "interrupted":
            runtime_status = RuntimeStatus.INTERRUPTED
        elif (
            hint.status in {"runtime_failed", "domain_failed"}
            or receipt.failures
            or (
                receipt.completed_teardown_phases
                and not receipt.mandatory_teardown_complete
            )
        ):
            # A transport-free operation has no collector domain in which a
            # domain failure could truthfully live.  Preserve that intent as a
            # conservative runtime failure instead of silently turning it into
            # planning success.
            runtime_status = RuntimeStatus.FAILED
        else:
            runtime_status = RuntimeStatus.SUCCESS
        reason_status = _reason_status(
            runtime_status,
            (
                CollectionStatus.INTERRUPTED
                if runtime_status is RuntimeStatus.INTERRUPTED
                else CollectionStatus.INCOMPLETE
            ),
        )
        reason_values = []
        if hint.reason and not is_success_only_run_reason(hint.reason):
            reason_values.append(hint.reason)
        reason_values.extend(
            f"{failure.phase}: {failure.error_type}: {failure.message}"
            for failure in receipt.failures
        )
        reasons = []
        for value in reason_values:
            rendered = normalize_run_outcome_reason(reason_status, value)
            if rendered and rendered not in reasons:
                reasons.append(rendered)
            if len(reasons) == MAX_RESULT_REASONS:
                break
        if not reasons:
            if runtime_status is RuntimeStatus.INTERRUPTED:
                reasons.append("Transport-free planning was interrupted")
            elif runtime_status is RuntimeStatus.FAILED:
                reasons.append(
                    "Transport-free planning cannot represent collection-domain "
                    "failure intent"
                    if hint.status == "domain_failed"
                    else "Transport-free planning finalization did not complete"
                )
            else:
                reasons.append(
                    "Transport-free planning completed; no collection was executed"
                )
        return cls(
            schema_version=(
                RUN_RESULT_IDENTITY_SCHEMA_VERSION
                if receipt.run_identity is not None
                else RUN_RESULT_SCHEMA_VERSION
            ),
            mode=RunMode.PLANNING,
            runtime_status=runtime_status,
            collection_status=(
                CollectionStatus.INTERRUPTED
                if runtime_status is RuntimeStatus.INTERRUPTED
                else CollectionStatus.INCOMPLETE
            ),
            collector_counts=(),
            terminal_snapshot_committed=False,
            explicit_domain_failure=False,
            dut_roster=tuple(receipt.dut_roster),
            affected_duts=(
                tuple(hint.affected_duts)
                if hint.affected_duts
                else (
                    tuple(receipt.dut_roster)
                    if runtime_status is RuntimeStatus.INTERRUPTED
                    else ()
                )
            ),
            reasons=tuple(reasons),
            run_identity=receipt.run_identity,
        )

    @property
    def exit_code(self) -> int:
        """
        Return the deterministic collection command exit policy.

        Runtime interruption and failure take precedence. Planning remains a
        successful command even though it intentionally has no collection
        result. Finalized collection-domain failures and partial results return
        three, while incomplete collection evidence returns one. Each access
        derives the value from canonical state rather than storing an
        independent result.

        Returns:
            The numeric exit code value.
        """

        if self.runtime_status is RuntimeStatus.INTERRUPTED:
            return 130
        if self.runtime_status is RuntimeStatus.FAILED:
            return 1
        if self.mode is RunMode.PLANNING:
            return 0
        if self.collection_status is CollectionStatus.INTERRUPTED:
            return 130
        if self.collection_status in {
            CollectionStatus.PARTIAL,
            CollectionStatus.FAILED,
        }:
            return 3
        if self.collection_status is CollectionStatus.INCOMPLETE:
            return 1
        return 0

    def to_dict(self) -> dict[str, Any]:
        """
        Return a fresh JSON-compatible projection.

        The implementation uses current instance state to produce a fresh
        JSON-compatible projection.

        Returns:
            The validated ``document``.
        """

        document = {
            "schema_version": self.schema_version,
            "mode": self.mode.value,
            "runtime_status": self.runtime_status.value,
            "collection_status": self.collection_status.value,
            "exit_code": self.exit_code,
            "collector_counts": dict(self.collector_counts),
            "terminal_snapshot_committed": self.terminal_snapshot_committed,
            "explicit_domain_failure": self.explicit_domain_failure,
            "dut_roster": list(self.dut_roster),
            "affected_duts": list(self.affected_duts),
            "reasons": list(self.reasons),
        }
        if self.run_identity is not None:
            document["run_identity"] = self.run_identity.to_dict()
        return document

    def to_legacy_run_outcome(self) -> dict[str, Any]:
        """
        Return the versioned, one-way legacy adapter.

        No legacy document is read while deriving ``RunResult`` and the adapter
        never embeds another outcome, preventing recursive state growth.

        Returns:
            The validated ``adapter``.
        """

        reason = self.reasons[0] if self.reasons else ""
        if self.runtime_status is RuntimeStatus.INTERRUPTED:
            status = "interrupted"
            failure_type = None
        elif self.runtime_status is RuntimeStatus.FAILED:
            status = "runtime_failed"
            failure_type = "finalization_failure"
        elif self.collection_status is CollectionStatus.SUCCESS:
            status = "success"
            failure_type = None
        elif self.collection_status is CollectionStatus.INCOMPLETE:
            status = "runtime_failed"
            failure_type = "incomplete_collection"
            reason = reason or "Collection did not reach a complete terminal outcome"
        elif self.collection_status is CollectionStatus.INTERRUPTED:
            status = "interrupted"
            failure_type = None
        else:
            status = "domain_failed"
            failure_type = "collector_result_failure"

        adapter: dict[str, Any] = {
            "adapter_schema_version": LEGACY_RUN_OUTCOME_ADAPTER_VERSION,
            "status": status,
            "canonical_runtime_status": self.runtime_status.value,
            "canonical_collection_status": self.collection_status.value,
            "reason": reason,
            "affected_duts": list(self.affected_duts),
        }
        if failure_type is not None:
            adapter["failure_type"] = failure_type
        return adapter


def project_legacy_run_outcome(
    result: RunResult,
    *,
    domain_hint: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Project canonical truth while retaining validated selection evidence.

    ``RunResult`` owns terminal severity and collection truth, but its compact
    schema intentionally does not encode producer-specific domain subtypes. An
    explicit-selection hint may therefore refine only the legacy projection when
    it agrees with the canonical result and its bounded evidence.

    Args:
        result: Result object whose ``affected_duts``,
            ``explicit_domain_failure``, ``reasons``, and
            ``to_legacy_run_outcome`` state is read while performing project
            canonical truth while retaining validated selection evidence.
        domain_hint: Optional domain hint; ``None`` selects the function's
            default behavior.

    Returns:
        A mapping containing project legacy run outcome.

    Raises:
        TypeError: If a canonical RunResult is required.
    """

    if type(result) is not RunResult:
        raise TypeError("A canonical RunResult is required")
    adapter = result.to_legacy_run_outcome()
    if not result.explicit_domain_failure or not isinstance(domain_hint, Mapping):
        return adapter

    failure_type = domain_hint.get("failure_type")
    reason = domain_hint.get("reason")
    evidence = domain_hint.get("evidence")
    affected_duts = domain_hint.get("affected_duts")
    if not (
        domain_hint.get("status") == "domain_failed"
        and failure_type in EXPLICIT_SELECTION_FAILURE_TYPES
        and evidence == EXPLICIT_SELECTION_EVIDENCE_PATH
        and isinstance(reason, str)
        and bool(reason.strip())
        and reason in result.reasons
        and isinstance(affected_duts, list)
        and bool(affected_duts)
        and all(type(dut_id) is str for dut_id in affected_duts)
        and len(affected_duts) == len(set(affected_duts))
        and set(affected_duts).issubset(result.affected_duts)
    ):
        return adapter

    adapter.update(
        {
            "status": "domain_failed",
            "failure_type": failure_type,
            "reason": reason,
            "evidence": evidence,
            "affected_duts": list(affected_duts),
        }
    )
    return adapter


@dataclass(frozen=True)
class DeliveryResult:
    """
    Frozen result for one optional external publisher attempt.

    The immutable record keeps ``schema_version``, ``status``, ``delivery_ids``,
    ``delivery_uris``, and ``reason`` together so consumers observe one delivery
    state. Construction validates cross-field invariants before the instance is
    exposed.

    Attributes:
        schema_version: Canonical text used as schema version.
        status: Canonical status exposed to downstream status consumers.
        delivery_ids: Collection of delivery identifiers entries retained by
            this record.
        delivery_uris: Canonical provider URIs retained for direct navigation to
            the delivered artifacts.
        reason: Canonical reason exposed to downstream status consumers.
    """

    schema_version: str
    status: DeliveryStatus
    delivery_ids: Tuple[str, ...] = ()
    reason: str = ""
    delivery_uris: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """
        Reject noncanonical direct construction at every boundary.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            ValueError: If unsupported DeliveryResult schema; too many delivery
                references; an invalid delivery reference or diagnostic is
                supplied; or another input invariant is violated.
            TypeError: If the deliveryresult status are not canonical; or the
                delivery reference collections are not tuples.
        """

        if self.schema_version not in {
            DELIVERY_RESULT_SCHEMA_VERSION,
            LEGACY_DELIVERY_RESULT_SCHEMA_VERSION,
        }:
            raise ValueError("Unsupported DeliveryResult schema")
        if type(self.status) is not DeliveryStatus:
            raise TypeError("DeliveryResult status must be canonical")
        if type(self.delivery_ids) is not tuple:
            raise TypeError("Delivery identifiers must be a tuple")
        if len(self.delivery_ids) > MAX_DELIVERY_IDENTIFIERS:
            raise ValueError("Too many delivery identifiers")
        if len(set(self.delivery_ids)) != len(self.delivery_ids) or any(
            type(value) is not str  # noqa: E721 - subclasses are rejected
            or not value
            or _bounded_text(
                value,
                maximum_bytes=MAX_DELIVERY_IDENTIFIER_BYTES,
            )
            != value
            for value in self.delivery_ids
        ):
            raise ValueError("Invalid delivery identifier")
        if type(self.delivery_uris) is not tuple:
            raise TypeError("Delivery URIs must be a tuple")
        if self.schema_version == LEGACY_DELIVERY_RESULT_SCHEMA_VERSION:
            if self.delivery_uris:
                raise ValueError("Legacy DeliveryResult cannot contain delivery URIs")
        elif (
            len(self.delivery_uris) > MAX_DELIVERY_URIS
            or len(set(self.delivery_uris)) != len(self.delivery_uris)
            or any(
                type(value) is not str  # noqa: E721 - subclasses are rejected
                or not value
                or _bounded_text(value, maximum_bytes=MAX_DELIVERY_URI_BYTES) != value
                for value in self.delivery_uris
            )
        ):
            raise ValueError("Invalid delivery URI")
        if type(self.reason) is not str or (  # noqa: E721 - subclasses are rejected
            self.reason
            and _bounded_text(
                self.reason,
                maximum_bytes=MAX_RESULT_REASON_BYTES,
            )
            != self.reason
        ):
            raise ValueError("Invalid delivery diagnostic")
        if self.status in {DeliveryStatus.FAILED, DeliveryStatus.INTERRUPTED}:
            if not self.reason:
                raise ValueError("Unsuccessful delivery requires a reason")
            if self.delivery_uris:
                raise ValueError("Unsuccessful delivery cannot contain URIs")
        elif self.reason:
            raise ValueError("Successful delivery cannot contain a failure reason")
        if self.status is DeliveryStatus.SUCCESS and not self.delivery_ids:
            raise ValueError("Successful delivery requires an identifier")
        if self.status is DeliveryStatus.NOT_REQUESTED and (
            self.delivery_ids or self.delivery_uris
        ):
            raise ValueError("Unrequested delivery cannot contain references")

    @classmethod
    def create(
        cls,
        status: DeliveryStatus,
        *,
        delivery_ids: tuple[str, ...] = (),
        delivery_uris: tuple[str, ...] = (),
        reason: Any = "",
    ) -> "DeliveryResult":
        """
        Create the configured resource.

        After applying local validation, the function forwards ``status``,
        ``delivery_ids``, and ``reason`` to ``cls`` and preserves its return and
        exception contract.

        Args:
            status: Status consumed while the function attempts to create the
                configured resource.
            delivery_ids: Entries supplied as ``delivery_ids`` without
                transferring container ownership.
            delivery_uris: Canonical provider URIs retained for direct navigation
                to the delivered artifacts.
            reason: Reason consumed while the function attempts to create the
                configured resource.

        Returns:
            A validated ``DeliveryResult`` instance initialized from the
            supplied fields.

        Raises:
            TypeError: If the delivery reference collections are not tuples;
                their entries are not strings; or the delivery status is not
                canonical.
            ValueError: If a delivery identifier or URI is not canonical.
        """
        if type(delivery_ids) is not tuple:
            raise TypeError("Delivery identifiers must be a tuple")
        if type(delivery_uris) is not tuple:
            raise TypeError("Delivery URIs must be a tuple")
        normalized: list[str] = []
        for value in delivery_ids:
            if type(value) is not str:  # noqa: E721 - subclasses are rejected
                raise TypeError("Delivery identifiers must be strings")
            identifier = _bounded_text(
                value,
                maximum_bytes=MAX_DELIVERY_IDENTIFIER_BYTES,
            )
            if not identifier or identifier != value or identifier in normalized:
                raise ValueError("Invalid delivery identifier")
            normalized.append(identifier)
        normalized_uris: list[str] = []
        for value in delivery_uris:
            if type(value) is not str:  # noqa: E721 - subclasses are rejected
                raise TypeError("Delivery URIs must be strings")
            uri = _bounded_text(value, maximum_bytes=MAX_DELIVERY_URI_BYTES)
            if not uri or uri != value or uri in normalized_uris:
                raise ValueError("Invalid delivery URI")
            normalized_uris.append(uri)
        rendered_reason = _bounded_text(
            reason,
            maximum_bytes=MAX_RESULT_REASON_BYTES,
        )
        if type(status) is not DeliveryStatus:
            raise TypeError("Delivery status must be canonical")
        if status in {DeliveryStatus.FAILED, DeliveryStatus.INTERRUPTED}:
            if not rendered_reason or rendered_reason == "[no diagnostic detail]":
                rendered_reason = "External artifact delivery did not complete"
        elif status in {DeliveryStatus.SUCCESS, DeliveryStatus.NOT_REQUESTED}:
            rendered_reason = ""
        return cls(
            schema_version=DELIVERY_RESULT_SCHEMA_VERSION,
            status=status,
            delivery_ids=tuple(normalized),
            delivery_uris=tuple(normalized_uris),
            reason=rendered_reason,
        )

    @property
    def exit_code(self) -> int:
        """
        Return the exit code.

        Each access computes the value from ``status`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            The numeric exit code value.
        """
        if self.status is DeliveryStatus.INTERRUPTED:
            return 130
        if self.status is DeliveryStatus.FAILED:
            return 1
        return 0

    def to_dict(self) -> dict[str, Any]:
        """
        Return the to dict.

        The implementation uses current instance state to produce the to dict.

        Returns:
            A mapping containing the ``schema_version``, ``status``,
            ``delivery_ids``, ``delivery_uris``, and ``reason`` fields.
        """
        document = {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "delivery_ids": list(self.delivery_ids),
            "reason": self.reason,
        }
        if self.schema_version == DELIVERY_RESULT_SCHEMA_VERSION:
            document["delivery_uris"] = list(self.delivery_uris)
        return document


def validate_run_result_document(document: Mapping[str, Any]) -> RunResult:
    """
    Reconstruct a strict result at an untrusted JSON boundary.

    After applying local validation, the function forwards ``document`` to
    ``RunResult`` and preserves its return and exception contract.

    Args:
        document: Mapping supplying fields for reconstruct a strict result at an
            untrusted JSON boundary.

    Returns:
        A ``RunResult`` representing run result document.

    Raises:
        TypeError: If the run result document is not an object; the run result
            counts are not an object; the run result sequences are not arrays;
            or run result sequences must contain strings.
        ValueError: If run result document has unexpected fields; legacy run
            result cannot contain a run identity; identity-bearing run result is
            missing its identity; or unsupported run result schema; or another
            input invariant is violated.
    """

    if type(document) is not dict:  # noqa: E721 - subclasses are rejected
        raise TypeError("Run result document must be an object")
    base_fields = {
        "schema_version",
        "mode",
        "runtime_status",
        "collection_status",
        "collector_counts",
        "terminal_snapshot_committed",
        "explicit_domain_failure",
        "dut_roster",
        "affected_duts",
        "reasons",
    }
    document_fields = set(document)
    if document_fields not in {
        frozenset(base_fields),
        frozenset((*base_fields, "run_identity")),
        frozenset((*base_fields, "exit_code")),
        frozenset((*base_fields, "exit_code", "run_identity")),
    }:
        raise ValueError("Run result document has unexpected fields")
    schema_version = document["schema_version"]
    if schema_version == RUN_RESULT_SCHEMA_VERSION:
        if "run_identity" in document:
            raise ValueError("Legacy run result cannot contain a run identity")
        run_identity = None
    elif schema_version == RUN_RESULT_IDENTITY_SCHEMA_VERSION:
        if "run_identity" not in document:
            raise ValueError("Identity-bearing run result is missing its identity")
        run_identity = validate_run_identity_document(document["run_identity"])
    else:
        raise ValueError("Unsupported run result schema")
    counts_mapping = document["collector_counts"]
    if type(counts_mapping) is not dict:  # noqa: E721 - subclasses are rejected
        raise TypeError("Run result counts must be an object")
    count_names = set(counts_mapping)
    mode = RunMode(document["mode"])
    if mode is RunMode.COLLECTION and frozenset(count_names) not in {
        frozenset(COLLECTOR_COUNT_FIELDS),
        frozenset(LEGACY_COLLECTOR_COUNT_FIELDS),
    }:
        raise ValueError("Run result counts are noncanonical")
    if mode is RunMode.PLANNING and count_names:
        raise ValueError("Planning result cannot contain collection counts")
    counts = []
    ordered_count_names = COLLECTOR_COUNT_FIELDS if count_names else ()
    for name in ordered_count_names:
        value = counts_mapping.get(name, 0)
        if type(value) is not int or value < 0:  # noqa: E721 - subclasses are rejected
            raise ValueError("Run result count is invalid")
        counts.append((name, value))
    roster = document["dut_roster"]
    affected = document["affected_duts"]
    reasons = document["reasons"]
    if not all(
        type(values) is list  # noqa: E721 - subclasses are rejected
        for values in (
            roster,
            affected,
            reasons,
        )  # noqa: E721 - subclasses are rejected
    ):  # noqa: E721 - subclasses are rejected
        raise TypeError("Run result sequences must be arrays")
    if not all(
        type(value) is str  # noqa: E721 - subclasses are rejected
        for value in (
            *roster,
            *affected,
            *reasons,
        )  # noqa: E721 - subclasses are rejected
    ):  # noqa: E721 - subclasses are rejected
        raise TypeError("Run result sequences must contain strings")
    if len(set(roster)) != len(roster) or not set(affected).issubset(roster):
        raise ValueError("Run result DUT identities are inconsistent")
    if len(reasons) > MAX_RESULT_REASONS or any(
        _bounded_text(reason, maximum_bytes=MAX_RESULT_REASON_BYTES) != reason
        for reason in reasons
    ):
        raise ValueError("Run result reasons are invalid")
    result = RunResult(
        schema_version=schema_version,
        mode=mode,
        runtime_status=RuntimeStatus(document["runtime_status"]),
        collection_status=CollectionStatus(document["collection_status"]),
        collector_counts=tuple(counts),
        terminal_snapshot_committed=document["terminal_snapshot_committed"],
        explicit_domain_failure=document["explicit_domain_failure"],
        dut_roster=tuple(roster),
        affected_duts=tuple(affected),
        reasons=tuple(reasons),
        run_identity=run_identity,
    )
    if "exit_code" in document and (
        type(document["exit_code"]) is not int  # noqa: E721 - reject booleans
        or document["exit_code"] != result.exit_code
    ):
        raise ValueError("Run result exit code contradicts canonical result state")
    return result


def validate_delivery_result_document(document: Mapping[str, Any]) -> DeliveryResult:
    """
    Reconstruct strict delivery evidence at an untrusted JSON boundary.

    The implementation uses ``document`` to reconstruct strict delivery evidence
    at an untrusted JSON boundary. If the function cannot reconstruct strict
    delivery evidence at an untrusted JSON boundary, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        document: Mapping supplying fields for reconstruct strict delivery
            evidence at an untrusted JSON boundary.

    Returns:
        The validated ``result``.

    Raises:
        ValueError: If delivery result document has unexpected fields;
            unsupported delivery result schema; delivery status is invalid; or
            delivery result document is noncanonical.
        TypeError: If the delivery identifiers are not an array of strings; or
            the delivery diagnostic is not a string.
    """

    if type(document) is not dict:  # noqa: E721 - subclasses are rejected
        raise ValueError("Delivery result document has unexpected fields")
    schema_version = document.get("schema_version")
    if schema_version not in {
        DELIVERY_RESULT_SCHEMA_VERSION,
        LEGACY_DELIVERY_RESULT_SCHEMA_VERSION,
    }:
        raise ValueError("Unsupported delivery result schema")
    expected_fields = {
        "schema_version",
        "status",
        "delivery_ids",
        "reason",
    }
    if schema_version == DELIVERY_RESULT_SCHEMA_VERSION:
        expected_fields.add("delivery_uris")
    if set(document) != expected_fields:
        raise ValueError("Delivery result document has unexpected fields")
    raw_identifiers = document.get("delivery_ids")
    if type(raw_identifiers) is not list or any(  # noqa: E721 - subclasses are rejected
        type(identifier) is not str  # noqa: E721 - subclasses are rejected
        for identifier in raw_identifiers  # noqa: E721 - subclasses are rejected
    ):
        raise TypeError("Delivery identifiers must be an array of strings")
    if type(document.get("reason")) is not str:  # noqa: E721 - subclasses are rejected
        raise TypeError("Delivery diagnostic must be a string")
    raw_uris = document.get("delivery_uris", [])
    if type(raw_uris) is not list or any(  # noqa: E721 - subclasses are rejected
        type(uri) is not str for uri in raw_uris  # noqa: E721 - reject subclasses
    ):
        raise TypeError("Delivery URIs must be an array of strings")
    try:
        status = DeliveryStatus(document.get("status"))
    except (TypeError, ValueError) as error:
        raise ValueError("Delivery status is invalid") from error
    result = DeliveryResult(
        schema_version=schema_version,
        status=status,
        delivery_ids=tuple(raw_identifiers),
        delivery_uris=tuple(raw_uris),
        reason=document["reason"],
    )
    if result.to_dict() != document:
        raise ValueError("Delivery result document is noncanonical")
    return result
