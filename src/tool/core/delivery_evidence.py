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
Durable evidence for optional delivery without rewriting local-run truth.

This module owns the delivery evidence boundary and exposes
``_canonical_bytes``, ``canonical_receipt_document``, ``_receipt_digest``,
``finalization_receipt_from_document``, and ``_run_result_digest``. Keeping
those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

from ..utils.filesystem_identity import directory_security_identity
from ..utils.status_snapshot import validate_terminal_snapshot_tree
from ..utils.zip_utils import (
    validate_archive_target_identity,
    verify_archive_artifact_digests,
)
from .finalization_receipt import (
    FinalizationFailure,
    FinalizationOutcomeHint,
    FinalizationReceipt,
    FrozenCollectorStatus,
    finalization_failures_allow_delivery,
    select_authoritative_exception,
    validate_consumable_finalization_receipt,
    validate_structural_finalization_receipt,
)
from .run_identity import validate_run_identity_document
from .run_result import (
    MAX_DELIVERY_URIS,
    MAX_DELIVERY_URI_BYTES,
    DeliveryResult,
    RunResult,
    validate_delivery_result_document,
    validate_run_result_document,
)

DELIVERY_EVIDENCE_SCHEMA_VERSION = "1.2"
DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION = "1.3"
DELIVERY_EVIDENCE_DIAGNOSTICS_SCHEMA_VERSION = "1.4"
DELIVERY_EVIDENCE_DIAGNOSTICS_IDENTITY_SCHEMA_VERSION = "1.5"
_LEGACY_DELIVERY_EVIDENCE_SCHEMA_VERSION = "1.0"
_LEGACY_DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION = "1.1"
_DELIVERY_SANITIZATION_STATES = frozenset(
    {"enabled", "write_time_only", "disabled_by_user", "failed_safe"}
)
TERMINAL_OUTCOME_OVERRIDE_SCHEMA_VERSION = "2.0"
TERMINAL_OUTCOME_OVERRIDE_IDENTITY_SCHEMA_VERSION = "2.1"
TERMINAL_OUTCOME_OVERRIDE_DIAGNOSTICS_SCHEMA_VERSION = "2.2"
TERMINAL_OUTCOME_OVERRIDE_DIAGNOSTICS_IDENTITY_SCHEMA_VERSION = "2.3"
MAX_DELIVERY_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_TERMINAL_OUTCOME_OVERRIDE_BYTES = 128 * 1024 * 1024
# Delivery is an optional post-collection operation.  Keep a finite admission
# bound below the 100,000-record collection contract, then size the exact
# projected sidecar against ``MAX_DELIVERY_EVIDENCE_BYTES`` below before a
# provider is called.  Rack platforms legitimately exceed 4,096 records.
MAX_DELIVERY_EVIDENCE_COLLECTOR_STATUSES = 32_768
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_LEAF_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


def _canonical_bytes(document: object) -> bytes:
    """
    Serialize an identity document into its canonical digest bytes.

    Keys are sorted, insignificant whitespace is removed, non-ASCII text is
    escaped, and non-finite numbers are rejected before ASCII encoding. The
    resulting bytes are stable input for identity digests.

    Args:
        document: Document consumed while the function attempts to serialize an
            identity document into its canonical digest bytes.

    Returns:
        The canonical ASCII bytes used as digest input.
    """
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def canonical_receipt_document(receipt: FinalizationReceipt) -> dict[str, Any]:
    """
    Return the complete bounded JSON projection of an exact receipt.

    The implementation uses ``receipt`` to produce the complete bounded JSON
    projection of an exact receipt.

    Args:
        receipt: Receipt object whose ``archive_artifact_digests``,
            ``archive_duration_seconds``, ``collector_counts``,
            ``collector_statuses``, and ``committed_generation`` state is read
            while performing complete bounded JSON projection of an exact
            receipt.

    Returns:
        The validated ``document``.
    """

    validate_structural_finalization_receipt(receipt)
    hint = receipt.outcome_hint
    document = {
        "committed_generation": receipt.committed_generation,
        "terminal_snapshot_committed": receipt.terminal_snapshot_committed,
        "dut_roster": list(receipt.dut_roster),
        "collector_counts": [list(item) for item in receipt.collector_counts],
        "collector_statuses": [
            {
                "dut_id": item.dut_id,
                "collector_id": item.collector_id,
                "status": item.status,
            }
            for item in receipt.collector_statuses
        ],
        "interrupted": receipt.interrupted,
        "outcome_hint": {
            "status": hint.status,
            "failure_type": hint.failure_type,
            "reason": hint.reason,
            "affected_duts": list(hint.affected_duts),
        },
        "snapshot_leaf_digests": [list(item) for item in receipt.snapshot_leaf_digests],
        "archive_artifact_digests": [
            list(item) for item in receipt.archive_artifact_digests
        ],
        "archive_duration_seconds": receipt.archive_duration_seconds,
        "completed_teardown_phases": list(receipt.completed_teardown_phases),
        "failures": [
            {
                "phase": failure.phase,
                "error_type": failure.error_type,
                "message": failure.message,
            }
            for failure in receipt.failures
        ],
    }
    if receipt.diagnostics:
        document["diagnostics"] = [
            {
                "phase": item.phase,
                "error_type": item.error_type,
                "message": item.message,
            }
            for item in receipt.diagnostics
        ]
    if receipt.run_identity is not None:
        document["run_identity"] = receipt.run_identity.to_dict()
    return document


def _receipt_digest(receipt: FinalizationReceipt) -> str:
    """
    Bind the sidecar to every exact field of the frozen receipt.

    After applying local validation, the function forwards ``receipt`` to
    ``hexdigest`` and preserves its return and exception contract.

    Args:
        receipt: Receipt consumed while the function attempts to bind the
            sidecar to every exact field of the frozen receipt.

    Returns:
        The canonical receipt digest.
    """

    return hashlib.sha256(
        _canonical_bytes(canonical_receipt_document(receipt))
    ).hexdigest()


def finalization_receipt_from_document(
    document: object,
) -> FinalizationReceipt:
    """
    Reconstruct a strict receipt from an untrusted sidecar projection.

    The implementation uses ``document`` to reconstruct a strict receipt from an
    untrusted sidecar projection. If the function cannot reconstruct a strict
    receipt from an untrusted sidecar projection, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        document: Document object whose ``get`` state is read while performing
            reconstruct a strict receipt from an untrusted sidecar projection.

    Returns:
        The validated ``receipt``.

    Raises:
        ValueError: If delivery receipt projection has unexpected fields;
            delivery receipt projection has a malformed outcome hint; delivery
            receipt collector status is malformed; or delivery receipt failure
            is malformed; or another input invariant is violated.
        TypeError: If delivery receipt projection contains malformed arrays; or
            the delivery receipt affected_duts are not an array.
    """

    expected_fields = {
        "committed_generation",
        "terminal_snapshot_committed",
        "dut_roster",
        "collector_counts",
        "collector_statuses",
        "interrupted",
        "outcome_hint",
        "snapshot_leaf_digests",
        "archive_artifact_digests",
        "archive_duration_seconds",
        "completed_teardown_phases",
        "failures",
    }
    if type(document) is not dict or set(  # noqa: E721 - subclasses are rejected
        document
    ) not in {  # noqa: E721 - subclasses are rejected
        frozenset(expected_fields),
        frozenset((*expected_fields, "run_identity")),
        frozenset((*expected_fields, "diagnostics")),
        frozenset((*expected_fields, "run_identity", "diagnostics")),
    }:
        raise ValueError("Delivery receipt projection has unexpected fields")
    sequence_fields = (
        "dut_roster",
        "collector_counts",
        "collector_statuses",
        "snapshot_leaf_digests",
        "archive_artifact_digests",
        "completed_teardown_phases",
        "failures",
    )
    if any(
        type(document[field]) is not list  # noqa: E721 - subclasses are rejected
        for field in sequence_fields  # noqa: E721 - subclasses are rejected
    ):  # noqa: E721 - subclasses are rejected
        raise TypeError("Delivery receipt projection contains malformed arrays")
    hint = document.get("outcome_hint")
    if type(hint) is not dict or set(hint) != {  # noqa: E721 - subclasses are rejected
        "status",
        "failure_type",
        "reason",
        "affected_duts",
    }:
        raise ValueError("Delivery receipt projection has a malformed outcome hint")
    if type(hint["affected_duts"]) is not list:  # noqa: E721 - subclasses are rejected
        raise TypeError("Delivery receipt affected_duts must be an array")

    def exact_pairs(values: object, *, width: int) -> tuple[tuple[Any, ...], ...]:
        """
        Return the exact pairs.

        After applying local validation, the function forwards ``values`` and
        ``width`` to ``tuple`` and preserves its return and exception contract.

        Args:
            values: Values consumed while the function attempts to produce the
                exact pairs.
            width: Numeric width used while the operation performs bounded
                accounting.

        Returns:
            The exact pairs returned in operation-defined order.

        Raises:
            ValueError: If delivery receipt tuple projection is malformed.
        """
        if type(values) is not list or any(  # noqa: E721 - subclasses are rejected
            type(item) is not list  # noqa: E721 - subclasses are rejected
            or len(item) != width  # noqa: E721 - subclasses are rejected
            for item in values  # noqa: E721 - subclasses are rejected
        ):
            raise ValueError("Delivery receipt tuple projection is malformed")
        return tuple(tuple(item) for item in values)

    collector_statuses = []
    for value in document["collector_statuses"]:
        if type(value) is not dict or set(  # noqa: E721 - subclasses are rejected
            value
        ) != {  # noqa: E721 - subclasses are rejected
            "dut_id",
            "collector_id",
            "status",
        }:
            raise ValueError("Delivery receipt collector status is malformed")
        collector_statuses.append(FrozenCollectorStatus(**value))
    failures = []
    for value in document["failures"]:
        if type(value) is not dict or set(  # noqa: E721 - subclasses are rejected
            value
        ) != {  # noqa: E721 - subclasses are rejected
            "phase",
            "error_type",
            "message",
        }:
            raise ValueError("Delivery receipt failure is malformed")
        failures.append(FinalizationFailure(**value))
    diagnostics = document.get("diagnostics", [])
    if type(diagnostics) is not list or len(diagnostics) > 64:
        raise ValueError("Delivery receipt diagnostics are malformed")
    diagnostic_records = []
    for value in diagnostics:
        if type(value) is not dict or set(value) != {"phase", "error_type", "message"}:
            raise ValueError("Delivery receipt diagnostic is malformed")
        diagnostic_records.append(FinalizationFailure(**value))
    archive_duration = document["archive_duration_seconds"]
    if archive_duration is not None and (
        type(archive_duration) not in {int, float}
        or not math.isfinite(archive_duration)
    ):
        raise ValueError("Delivery receipt archive duration is malformed")
    receipt = FinalizationReceipt(
        committed_generation=document["committed_generation"],
        terminal_snapshot_committed=document["terminal_snapshot_committed"],
        dut_roster=tuple(document["dut_roster"]),
        collector_counts=exact_pairs(document["collector_counts"], width=2),
        collector_statuses=tuple(collector_statuses),
        interrupted=document["interrupted"],
        outcome_hint=FinalizationOutcomeHint(
            status=hint["status"],
            failure_type=hint["failure_type"],
            reason=hint["reason"],
            affected_duts=tuple(hint["affected_duts"]),
        ),
        snapshot_leaf_digests=exact_pairs(document["snapshot_leaf_digests"], width=3),
        archive_artifact_digests=exact_pairs(
            document["archive_artifact_digests"], width=3
        ),
        archive_duration_seconds=archive_duration,
        completed_teardown_phases=tuple(document["completed_teardown_phases"]),
        failures=tuple(failures),
        diagnostics=tuple(diagnostic_records),
        run_identity=(
            validate_run_identity_document(document["run_identity"])
            if "run_identity" in document
            else None
        ),
    )
    validate_structural_finalization_receipt(receipt)
    if canonical_receipt_document(receipt) != document:
        raise ValueError("Delivery receipt projection is noncanonical")
    return receipt


def _run_result_digest(run_result: RunResult) -> str:
    """
    Run result digest.

    After applying local validation, the function forwards ``run_result`` to
    ``hexdigest`` and preserves its return and exception contract. Terminal
    status is emitted only after result digest and its owned cleanup have
    completed.

    Args:
        run_result: Run result object whose ``to_dict`` state is read while
            performing result digest.

    Returns:
        The canonical run result digest.
    """
    return hashlib.sha256(_canonical_bytes(run_result.to_dict())).hexdigest()


def _identity_evidence_schema_version(
    receipt: FinalizationReceipt,
    run_result: RunResult,
    *,
    legacy_version: str,
    identity_version: str,
) -> str:
    """
    Select one outer schema whose version agrees with both inner records.

    The implementation uses ``receipt``, ``run_result``, ``legacy_version``, and
    ``identity_version`` to select one outer schema whose version agrees with
    both inner records. If the function cannot select one outer schema whose
    version agrees with both inner records, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        receipt: Receipt object whose ``run_identity`` state is read while
            performing one outer schema whose version agrees with both inner
            records.
        run_result: Run result object whose ``run_identity`` state is read while
            performing one outer schema whose version agrees with both inner
            records.
        legacy_version: Text supplied as legacy version in the format accepted
            by this function.
        identity_version: Text supplied as identity version in the format
            accepted by this function.

    Returns:
        The canonical identity evidence schema version text.

    Raises:
        ValueError: If receipt and RunResult identity presence disagree.
    """

    receipt_has_identity = receipt.run_identity is not None
    result_has_identity = run_result.run_identity is not None
    if receipt_has_identity != result_has_identity:
        raise ValueError("Receipt and RunResult identity presence disagree")
    version = identity_version if receipt_has_identity else legacy_version
    if receipt.diagnostics:
        diagnostic_versions = {
            DELIVERY_EVIDENCE_SCHEMA_VERSION: DELIVERY_EVIDENCE_DIAGNOSTICS_SCHEMA_VERSION,
            DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION: DELIVERY_EVIDENCE_DIAGNOSTICS_IDENTITY_SCHEMA_VERSION,
            TERMINAL_OUTCOME_OVERRIDE_SCHEMA_VERSION: TERMINAL_OUTCOME_OVERRIDE_DIAGNOSTICS_SCHEMA_VERSION,
            TERMINAL_OUTCOME_OVERRIDE_IDENTITY_SCHEMA_VERSION: TERMINAL_OUTCOME_OVERRIDE_DIAGNOSTICS_IDENTITY_SCHEMA_VERSION,
        }
        if version not in diagnostic_versions:
            raise ValueError("Legacy evidence schema cannot carry receipt diagnostics")
        return diagnostic_versions[version]
    return version


def _validate_run_result_leaf_evidence(
    receipt: FinalizationReceipt,
    run_result: RunResult,
) -> None:
    """
    Require receipt leaves to contain the exact committed result bytes.

    The implementation uses ``receipt`` and ``run_result`` to require receipt
    leaves to contain the exact committed result bytes. Every required invariant
    is checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        receipt: Receipt object whose ``dut_roster`` and
            ``snapshot_leaf_digests`` state is read while performing receipt
            leaves to contain the exact committed result bytes.
        run_result: Run result object whose ``to_dict`` state is read while
            performing receipt leaves to contain the exact committed result
            bytes.

    Raises:
        RuntimeError: If finalization receipt does not bind the canonical
            RunResult bytes.
    """

    serialized = json.dumps(run_result.to_dict(), indent=2).encode("utf-8")
    expected_size = len(serialized)
    expected_digest = hashlib.sha256(serialized).hexdigest()
    expected_paths = tuple(
        sorted(
            (
                ".metadata/run_result.json",
                *(
                    f"{dut_id}/.metadata/run_result.json"
                    for dut_id in receipt.dut_roster
                ),
            )
        )
    )
    observed = tuple(
        item
        for item in receipt.snapshot_leaf_digests
        if item[0] == ".metadata/run_result.json"
        or item[0].endswith("/.metadata/run_result.json")
    )
    leaves_match = tuple(item[0] for item in observed) == expected_paths and not any(
        size != expected_size or digest != expected_digest
        for _path, size, digest in observed
    )
    if not leaves_match and not (
        bool(receipt.failures) and finalization_failures_allow_delivery(receipt)
    ):
        raise RuntimeError(
            "Finalization receipt does not bind the canonical RunResult bytes"
        )


def _validate_delivery_terminal_truth(
    receipt: FinalizationReceipt,
    run_result: RunResult,
    run_directory: Path,
    archive_paths: Sequence[Path],
) -> None:
    """
    Validate the late terminal override required by deliverable failures.

    A failed finalization may proceed to delivery only when the failure phase is
    explicitly allowed and a receipt-bound override proves the immutable archive
    carries the later terminal truth.

    Args:
        receipt: Finalization receipt authorizing the delivery decision.
        run_result: Canonical terminal result projected from ``receipt``.
        run_directory: Filesystem location of the completed collection run.
        archive_paths: Ordered archive artifacts selected for delivery.

    Raises:
        RuntimeError: If the finalization failures do not authorize delivery.
    """

    if not receipt.failures:
        return
    if not finalization_failures_allow_delivery(receipt):
        raise RuntimeError("Finalization failures do not authorize delivery")
    paths = validate_archive_target_identity(run_directory, archive_paths)
    sidecar = paths[0].parent / f"{Path(run_directory).name}.terminal_outcome.json"
    verify_terminal_outcome_override_evidence(
        sidecar,
        run_directory=run_directory,
        archive_paths=paths,
        expected_receipt=receipt,
        expected_run_result=run_result,
    )


def _open_directory(path: Path) -> int:
    """
    Open every absolute path component without following symbolic links.

    The implementation uses ``path`` to open every absolute path component
    without following symbolic links. If the function cannot open every absolute
    path component without following symbolic links, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The validated ``descriptor``.

    Raises:
        RuntimeError: If delivery evidence lacks no-follow file access; delivery
            evidence directory is malformed; or delivery evidence parent is not
            a directory.
    """

    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("Delivery evidence requires no-follow file access")
    lexical = Path(os.path.abspath(os.fspath(path)))
    descriptor: int | None = None
    try:
        descriptor = os.open(os.path.sep, _DIRECTORY_FLAGS)
        for component in lexical.parts[1:]:
            if component in {"", ".", ".."} or not component.isprintable():
                raise RuntimeError("Delivery evidence directory is malformed")
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            previous = descriptor
            descriptor = child
            _close_evidence_descriptors(
                (previous,), context="Delivery evidence path traversal"
            )
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("Delivery evidence parent is not a directory")
        return descriptor
    except BaseException:
        _close_evidence_descriptors(
            (descriptor,), context="Delivery evidence directory open"
        )
        raise


def _directory_identity(descriptor: int) -> tuple[int, int, int, int, int]:
    """
    Return the directory identity.

    The implementation uses ``descriptor`` to produce the directory identity. If
    the function cannot produce the directory identity, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.

    Returns:
        Device, inode, full mode, owner UID, and owner GID.

    Raises:
        RuntimeError: If delivery evidence parent is not a directory.
    """
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("Delivery evidence parent is not a directory")
    return directory_security_identity(metadata)


def _close_evidence_descriptors(
    descriptors: Sequence[int | None],
    *,
    context: str,
) -> None:
    """
    Close every owned descriptor without replacing authoritative failure.

    The implementation uses ``descriptors`` and ``context`` to close every owned
    descriptor without replacing authoritative failure. If the function cannot
    close every owned descriptor without replacing authoritative failure, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        descriptors: Optional descriptors; ``None`` selects the function's
            default behavior.
        context: Runtime context carrying state shared across this operation.

    Raises:
        BaseException: If a delegated failure occurs while the function attempts
            to close every owned descriptor without replacing authoritative
            failure.
    """

    active_error = sys.exc_info()[1]
    close_errors: list[BaseException] = []
    closed: set[int] = set()
    for descriptor in descriptors:
        if descriptor is None or descriptor in closed:
            continue
        closed.add(descriptor)
        try:
            os.close(descriptor)
        except BaseException as close_error:
            close_errors.append(close_error)
    if not close_errors:
        return
    observed: list[BaseException] = list(close_errors)
    if active_error is not None:
        observed.insert(0, active_error)
    authoritative = select_authoritative_exception(observed)
    if active_error is not None and authoritative is active_error:
        try:
            active_error.add_note(
                f"{context} also reported descriptor-close failures: "
                + ", ".join(type(error).__name__ for error in close_errors)
            )
        except BaseException:
            pass
        return
    raise authoritative from active_error


def _revalidate_parent_path(parent: Path, expected: tuple[int, int]) -> None:
    """
    Prove the visible no-follow path still names the pinned parent.

    The implementation uses ``parent`` and ``expected`` to prove the visible
    no-follow path still names the pinned parent. If the function cannot prove
    the visible no-follow path still names the pinned parent, its exception
    reaches the caller instead of being converted into a successful result.
    Cleanup in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        parent: filesystem location used as the parent for this operation.
        expected: Entries supplied as ``expected`` without transferring
            container ownership.

    Raises:
        RuntimeError: If delivery evidence parent identity changed.
    """

    confirmation = _open_directory(parent)
    try:
        if _directory_identity(confirmation) != expected:
            raise RuntimeError("Delivery evidence parent identity changed")
    finally:
        _close_evidence_descriptors(
            (confirmation,), context="Delivery evidence parent revalidation"
        )


def _read_existing(
    parent_fd: int,
    name: str,
    *,
    maximum_bytes: int = MAX_DELIVERY_EVIDENCE_BYTES,
) -> bytes:
    """
    Read existing.

    The implementation uses ``parent_fd``, ``name``, and ``maximum_bytes`` to
    read existing. Parsing or I/O must finish before the validated
    representation is made available to the caller. If the function cannot read
    existing, its exception reaches the caller instead of being converted into a
    successful result. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The validated ``data``.

    Raises:
        RuntimeError: If existing delivery evidence is not a private regular
            file; or delivery evidence changed while being verified.
    """
    descriptor = os.open(name, _LEAF_FLAGS, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(visible.st_mode)
            or before.st_dev != visible.st_dev
            or before.st_ino != visible.st_ino
            or before.st_nlink != 1
            or visible.st_nlink != 1
            or before.st_mode & 0o077
            or before.st_size > maximum_bytes
        ):
            raise RuntimeError(
                "Existing delivery evidence is not a private regular file"
            )
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        visible_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            len(data) != before.st_size
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
            or after.st_nlink != 1
            or not stat.S_ISREG(visible_after.st_mode)
            or visible_after.st_dev != before.st_dev
            or visible_after.st_ino != before.st_ino
            or visible_after.st_mode != before.st_mode
            or visible_after.st_nlink != before.st_nlink
            or visible_after.st_size != before.st_size
            or visible_after.st_mtime_ns != before.st_mtime_ns
            or visible_after.st_ctime_ns != before.st_ctime_ns
        ):
            raise RuntimeError("Delivery evidence changed while being verified")
        return data
    finally:
        _close_evidence_descriptors(
            (descriptor,), context="Existing delivery evidence read"
        )


def _pin_evidence_leaf(
    parent_fd: int,
    name: str,
    *,
    maximum_bytes: int,
) -> tuple[int, os.stat_result]:
    """
    Retain one exact evidence inode across long downstream verification.

    The implementation uses ``parent_fd``, ``name``, and ``maximum_bytes`` to
    retain one exact evidence inode across long downstream verification.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot retain one exact evidence
    inode across long downstream verification, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        A tuple containing ``descriptor`` and ``metadata`` in that order.

    Raises:
        RuntimeError: If delivery evidence is not a private stable file.
    """

    descriptor = os.open(name, _LEAF_FLAGS, dir_fd=parent_fd)
    try:
        metadata = os.fstat(descriptor)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > maximum_bytes
            or (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_size,
            )
            != (
                visible.st_dev,
                visible.st_ino,
                visible.st_mode,
                visible.st_size,
            )
        ):
            raise RuntimeError("Delivery evidence is not a private stable file")
        return descriptor, metadata
    except BaseException:
        _close_evidence_descriptors((descriptor,), context="Delivery evidence leaf pin")
        raise


def _confirm_pinned_evidence_leaf(
    parent_fd: int,
    name: str,
    descriptor: int,
    before: os.stat_result,
) -> None:
    """
    Require the initially pinned evidence inode to remain visible unchanged.

    The implementation uses ``parent_fd``, ``name``, ``descriptor``, and
    ``before`` to require the initially pinned evidence inode to remain visible
    unchanged. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        before: Before consumed while the function attempts to require the
            initially pinned evidence inode to remain visible unchanged.

    Raises:
        RuntimeError: If delivery evidence changed during downstream
            verification.
    """

    after = os.fstat(descriptor)
    visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    identity_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(
        getattr(before, field) != getattr(after, field)
        or getattr(before, field) != getattr(visible, field)
        for field in identity_fields
    ):
        raise RuntimeError("Delivery evidence changed during downstream verification")


def _read_pinned_evidence_leaf(
    parent_fd: int,
    name: str,
    descriptor: int,
    before: os.stat_result,
    *,
    maximum_bytes: int,
) -> bytes:
    """
    Read the already-pinned inode and keep it bound to its parent entry.

    The implementation uses ``parent_fd``, ``name``, ``descriptor``, ``before``,
    and ``maximum_bytes`` to read the already-pinned inode and keep it bound to
    its parent entry. Parsing or I/O must finish before the validated
    representation is made available to the caller. If the function cannot read
    the already-pinned inode and keep it bound to its parent entry, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        before: Before object whose ``st_size`` state is read while performing
            already-pinned inode and keep it bound to its parent entry.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The validated ``serialized``.

    Raises:
        RuntimeError: If delivery evidence changed before it was read; or
            delivery evidence changed while being verified.
    """

    visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    identity_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if before.st_size > maximum_bytes or any(
        getattr(before, field) != getattr(visible, field) for field in identity_fields
    ):
        raise RuntimeError("Delivery evidence changed before it was read")

    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    serialized = b"".join(chunks)
    after = os.fstat(descriptor)
    visible_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        len(serialized) != before.st_size
        or any(
            getattr(before, field) != getattr(after, field) for field in identity_fields
        )
        or any(
            getattr(before, field) != getattr(visible_after, field)
            for field in identity_fields
        )
    ):
        raise RuntimeError("Delivery evidence changed while being verified")
    return serialized


def _publish_once(
    parent: Path,
    name: str,
    serialized: bytes,
    *,
    maximum_bytes: int = MAX_DELIVERY_EVIDENCE_BYTES,
) -> Path:
    """
    Create one private sidecar, accepting only exact idempotent replay.

    The implementation uses ``parent``, ``name``, ``serialized``, and
    ``maximum_bytes`` to create one private sidecar, accepting only exact
    idempotent replay. Filesystem effects remain confined to the caller-selected
    paths and the owning resource lifecycle. If the function cannot create one
    private sidecar, accepting only exact idempotent replay, its exception
    reaches the caller instead of being converted into a successful result.
    Cleanup in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        parent: filesystem location used as the parent for this operation.
        name: Stable name used for lookup and operator-facing diagnostics.
        serialized: Bounded byte sequence supplied as serialized.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The validated publish once filesystem path.

    Raises:
        RuntimeError: If delivery evidence target is malformed; conflicting
            delivery evidence already exists; existing delivery evidence is
            inconsistent; or could not persist delivery evidence; or another
            input invariant is violated.
        BaseException: If a delegated failure occurs while the function attempts
            to create one private sidecar, accepting only exact idempotent
            replay.
    """

    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or not name.isprintable()
        or len(serialized) > maximum_bytes
    ):
        raise RuntimeError("Delivery evidence target is malformed")
    parent_fd = _open_directory(parent)
    parent_identity = _directory_identity(parent_fd)
    temporary_name = f".{name}.{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None
    created_final = False
    durable_commit = False
    owned_final_identity: tuple[int, int] | None = None
    try:
        try:
            existing = _read_existing(
                parent_fd,
                name,
                maximum_bytes=maximum_bytes,
            )
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if existing != serialized:
                raise RuntimeError("Conflicting delivery evidence already exists")
            # Exact replay is also the recovery path after a prior process lost
            # certainty about the directory-entry fsync. Re-establish durability
            # and re-read the same stable inode before accepting it.
            os.fsync(parent_fd)
            if (
                _read_existing(
                    parent_fd,
                    name,
                    maximum_bytes=maximum_bytes,
                )
                != serialized
            ):
                raise RuntimeError("Existing delivery evidence is inconsistent")
            _revalidate_parent_path(parent, parent_identity)
            return parent / name

        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o600)
        view = memoryview(serialized)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("Could not persist delivery evidence")
            view = view[written:]
        os.fsync(descriptor)
        temporary_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or temporary_metadata.st_nlink != 1
            or temporary_metadata.st_size != len(serialized)
            or temporary_metadata.st_mode & 0o077
        ):
            raise RuntimeError("Delivery evidence temporary file is unsafe")
        descriptor_to_close = descriptor
        descriptor = None
        _close_evidence_descriptors(
            (descriptor_to_close,),
            context="Delivery evidence temporary publish",
        )
        owned_final_identity = (
            temporary_metadata.st_dev,
            temporary_metadata.st_ino,
        )

        try:
            os.link(
                temporary_name,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            created_final = True
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
            existing = _read_existing(
                parent_fd,
                name,
                maximum_bytes=maximum_bytes,
            )
            if existing != serialized:
                raise RuntimeError("Conflicting delivery evidence won publication")
        finally:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        post_link_errors: list[BaseException] = []
        try:
            os.fsync(parent_fd)
            durable_commit = True
        except BaseException as sync_error:
            # A failed fsync has ambiguous commit state. If the exact owned (or
            # exact race-winning) bytes remain visible, retry the durability
            # barrier before deciding whether rollback is still permissible.
            post_link_errors.append(sync_error)
            try:
                if (
                    _read_existing(
                        parent_fd,
                        name,
                        maximum_bytes=maximum_bytes,
                    )
                    != serialized
                ):
                    raise RuntimeError("Published delivery evidence is inconsistent")
                os.fsync(parent_fd)
                durable_commit = True
            except BaseException as retry_error:
                post_link_errors.append(retry_error)
        if durable_commit:
            try:
                if (
                    _read_existing(
                        parent_fd,
                        name,
                        maximum_bytes=maximum_bytes,
                    )
                    != serialized
                ):
                    raise RuntimeError("Published delivery evidence is inconsistent")
            except BaseException as confirmation_error:
                post_link_errors.append(confirmation_error)
            try:
                _revalidate_parent_path(parent, parent_identity)
            except BaseException as confirmation_error:
                post_link_errors.append(confirmation_error)
        if post_link_errors:
            raise select_authoritative_exception(post_link_errors)
        return parent / name
    except BaseException as primary_error:
        cleanup_errors: list[BaseException] = []
        if created_final and not durable_commit and owned_final_identity is not None:
            try:
                visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            else:
                if (
                    stat.S_ISREG(visible.st_mode)
                    and (visible.st_dev, visible.st_ino) == owned_final_identity
                ):
                    try:
                        os.unlink(name, dir_fd=parent_fd)
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)
                else:
                    cleanup_errors.append(
                        RuntimeError(
                            "Owned delivery evidence path changed before rollback"
                        )
                    )
            try:
                os.fsync(parent_fd)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            authoritative = select_authoritative_exception(
                [primary_error, *cleanup_errors]
            )
            if authoritative is primary_error:
                try:
                    primary_error.add_note(
                        "Delivery evidence rollback also reported: "
                        + ", ".join(type(error).__name__ for error in cleanup_errors)
                    )
                except BaseException:
                    pass
                raise
            raise authoritative from primary_error
        raise
    finally:
        active_error = sys.exc_info()[1]
        final_cleanup_errors: list[BaseException] = []
        # This is deliberately one combined drain instead of nested calls to
        # ``_close_evidence_descriptors``: leaf close, temporary unlink, and
        # parent close must all be attempted before one global winner is
        # selected below.  Thus neither raw close can replace an active error
        # or prevent the other owned resources from being released.
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                final_cleanup_errors.append(cleanup_error)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        except BaseException as cleanup_error:
            final_cleanup_errors.append(cleanup_error)
        try:
            os.close(parent_fd)
        except BaseException as cleanup_error:
            final_cleanup_errors.append(cleanup_error)
        if final_cleanup_errors:
            observed_errors = [*final_cleanup_errors]
            if active_error is not None:
                observed_errors.insert(0, active_error)
            authoritative = select_authoritative_exception(observed_errors)
            if active_error is not None and authoritative is active_error:
                try:
                    active_error.add_note(
                        "Delivery evidence final cleanup also reported: "
                        + ", ".join(
                            type(error).__name__ for error in final_cleanup_errors
                        )
                    )
                except BaseException:
                    pass
            else:
                raise authoritative from active_error


def _archive_binding(
    receipt: FinalizationReceipt,
    run_directory: Path,
    archive_paths: Sequence[Path],
) -> tuple[Path, str, dict[str, Any]]:
    """
    Archive binding.

    The implementation uses ``receipt``, ``run_directory``, and
    ``archive_paths`` to archive binding. Success is reported only after the
    owning output boundary has completed its required write or publication step.
    If the function cannot archive binding, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        receipt: Receipt object whose ``archive_artifact_digests`` state is read
            while performing binding.
        run_directory: filesystem location used as the run directory for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.

    Returns:
        A tuple containing ``parent``, ``message text``, and ``metadata
        mapping`` in that order.

    Raises:
        RuntimeError: If archive delivery evidence targets are inconsistent.
    """
    archive_paths = validate_archive_target_identity(run_directory, archive_paths)
    verified = verify_archive_artifact_digests(
        archive_paths,
        receipt.archive_artifact_digests,
    )
    if not verified or any(path.parent != verified[0].parent for path in verified):
        raise RuntimeError("Archive delivery evidence targets are inconsistent")
    records = [
        {
            "name": Path(path_value).name,
            "size_bytes": size,
            "sha256": digest,
        }
        for path_value, size, digest in receipt.archive_artifact_digests
    ]
    bundle_name = (
        verified[0].name.split(".zip", 1)[0]
        if ".zip" in verified[0].name
        else verified[0].stem
    )
    return (
        verified[0].parent,
        f"{bundle_name}.delivery_result.json",
        {"representation": "archive", "artifacts": records},
    )


def _snapshot_binding(
    receipt: FinalizationReceipt,
    run_directory: Path,
) -> tuple[Path, str, dict[str, Any]]:
    """
    Return the snapshot binding.

    The implementation uses ``receipt`` and ``run_directory`` to produce the
    snapshot binding. If the function cannot produce the snapshot binding, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        receipt: Receipt object whose ``snapshot_leaf_digests`` state is read
            while performing snapshot binding.
        run_directory: filesystem location used as the run directory for this
            operation.

    Returns:
        A tuple containing ``metadata``, ``status text``, and ``metadata
        mapping`` in that order.

    Raises:
        RuntimeError: If loose delivery snapshot differs from its receipt.
    """
    generation, roster = validate_consumable_finalization_receipt(receipt)
    observed = validate_terminal_snapshot_tree(
        run_directory,
        roster,
        expected_generation=generation,
        expected_leaf_digests=receipt.snapshot_leaf_digests,
    )
    if observed != generation:
        raise RuntimeError("Loose delivery snapshot differs from its receipt")
    metadata = run_directory / ".metadata"
    records = [
        {"path": path, "size_bytes": size, "sha256": digest}
        for path, size, digest in receipt.snapshot_leaf_digests
    ]
    return (
        metadata,
        "delivery_result.json",
        {"representation": "loose_snapshot", "artifacts": records},
    )


def _delivery_binding(
    receipt: FinalizationReceipt,
    run_directory: Path,
    archive_paths: Sequence[Path],
) -> tuple[Path, str, dict[str, Any]]:
    """
    Resolve the one receipt-authorized delivery-evidence location.

    The implementation uses ``receipt``, ``run_directory``, and
    ``archive_paths`` to resolve the one receipt-authorized delivery-evidence
    location. If the function cannot resolve the one receipt-authorized
    delivery-evidence location, its exception reaches the caller instead of
    being converted into a successful result.

    Args:
        receipt: Receipt object whose ``archive_artifact_digests`` state is read
            while performing one receipt-authorized delivery-evidence location.
        run_directory: filesystem location used as the run directory for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.

    Returns:
        A tuple containing the fields that represent delivery binding.

    Raises:
        RuntimeError: If archive delivery targets lack receipt evidence.
    """

    if receipt.archive_artifact_digests:
        return _archive_binding(receipt, run_directory, archive_paths)
    if archive_paths:
        raise RuntimeError("Archive delivery targets lack receipt evidence")
    return _snapshot_binding(receipt, run_directory)


def resolve_delivery_result_evidence_path(
    *,
    receipt: FinalizationReceipt,
    run_directory: Path,
    archive_paths: Sequence[Path] = (),
) -> Path:
    """
    Return the exact sidecar path after validating its local binding.

    This is used only to recover certainty after a publisher observed process
    control while persisting evidence. The caller must still independently
    verify and compare the visible sidecar before adopting it.

    Args:
        receipt: Receipt consumed while the function attempts to produce the
            exact sidecar path after validating its local binding.
        run_directory: filesystem location used as the run directory for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.

    Returns:
        The validated delivery result evidence path filesystem path.

    Raises:
        TypeError: If delivery evidence lacks an exact receipt.
    """

    if type(receipt) is not FinalizationReceipt:
        raise TypeError("Delivery evidence requires an exact receipt")
    run_result = RunResult.from_finalization_receipt(receipt)
    _validate_delivery_terminal_truth(
        receipt,
        run_result,
        Path(run_directory),
        archive_paths,
    )
    parent, name, _binding = _delivery_binding(
        receipt,
        Path(run_directory),
        archive_paths,
    )
    return parent / name


def _validate_terminal_override_representation(
    run_directory: Path,
    archive_paths: Sequence[Path],
) -> None:
    """
    Reject loose residue or an additional ZIP representation.

    The implementation uses ``run_directory`` and ``archive_paths`` to reject
    loose residue or an additional ZIP representation. Every required invariant
    is checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        run_directory: filesystem location used as the run directory for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.

    Raises:
        RuntimeError: If terminal override cannot coexist with a visible loose
            run root; or terminal override archive representation is ambiguous.
    """

    run_directory = Path(run_directory)
    paths = validate_archive_target_identity(run_directory, archive_paths)
    if os.path.lexists(run_directory):
        raise RuntimeError(
            "Terminal override cannot coexist with a visible loose run root"
        )
    expected_names = {path.name for path in paths}
    archive_prefix = f"{run_directory.name}.zip"
    observed_names: set[str] = set()
    with os.scandir(paths[0].parent) as entries:
        for entry in entries:
            if entry.name == archive_prefix or entry.name.startswith(
                f"{archive_prefix}.part"
            ):
                observed_names.add(entry.name)
                if len(observed_names) > 4096:
                    raise RuntimeError(
                        "Terminal override archive representation is ambiguous"
                    )
    if observed_names != expected_names:
        raise RuntimeError("Terminal override archive representation is ambiguous")


def _projected_binding(receipt: FinalizationReceipt) -> dict[str, Any]:
    """
    Return the largest exact binding shape without touching local paths.

    The implementation uses ``receipt`` to produce the largest exact binding
    shape without touching local paths.

    Args:
        receipt: Receipt object whose ``archive_artifact_digests`` and
            ``snapshot_leaf_digests`` state is read while performing largest
            exact binding shape without touching local paths.

    Returns:
        A mapping containing the ``representation`` and ``artifacts`` fields.
    """

    if receipt.archive_artifact_digests:
        return {
            "representation": "archive",
            "artifacts": [
                {
                    "name": Path(path_value).name,
                    "size_bytes": size,
                    "sha256": digest,
                }
                for path_value, size, digest in receipt.archive_artifact_digests
            ],
        }
    return {
        "representation": "loose_snapshot",
        "artifacts": [
            {"path": path, "size_bytes": size, "sha256": digest}
            for path, size, digest in receipt.snapshot_leaf_digests
        ],
    }


def validate_delivery_evidence_eligibility(
    *,
    receipt: FinalizationReceipt,
    run_result: RunResult,
) -> None:
    """
    Prove a delivery attempt can always publish bounded local evidence.

    This check intentionally has no filesystem side effects and is suitable for
    the pre-dispatch authorization boundary. It sizes a maximum legal successful
    ``DeliveryResult`` so every actual terminal delivery result will fit after
    the provider has been called.

    Args:
        receipt: Receipt object whose ``collector_statuses``, ``failures``,
            ``interrupted``, and ``mandatory_teardown_complete`` state is read
            while performing prove a delivery attempt can always publish bounded
            local evidence.
        run_result: Run result object whose ``to_dict`` state is read while
            performing prove a delivery attempt can always publish bounded local
            evidence.

    Raises:
        TypeError: If delivery evidence lacks an exact RunResult.
        RuntimeError: If finalization receipt does not authorize delivery
            evidence; collection topology exceeds bounded delivery evidence
            capacity; or delivery RunResult differs from its finalization
            receipt.
    """

    if type(run_result) is not RunResult:
        raise TypeError("Delivery evidence requires an exact RunResult")
    validate_consumable_finalization_receipt(receipt)
    if (
        receipt.interrupted
        or not finalization_failures_allow_delivery(receipt)
        or not receipt.mandatory_teardown_complete
    ):
        raise RuntimeError("Finalization receipt does not authorize delivery evidence")
    if len(receipt.collector_statuses) > MAX_DELIVERY_EVIDENCE_COLLECTOR_STATUSES:
        raise RuntimeError(
            "Collection topology exceeds bounded delivery evidence capacity"
        )
    expected_result = RunResult.from_finalization_receipt(receipt)
    if expected_result != run_result:
        raise RuntimeError("Delivery RunResult differs from its finalization receipt")
    _validate_run_result_leaf_evidence(receipt, run_result)

    receipt_document = canonical_receipt_document(receipt)
    run_result_document = run_result.to_dict()
    maximum_identifiers = [f"{index:02d}" + ("x" * (510)) for index in range(16)]
    maximum_delivery_result = {
        "schema_version": "1.1",
        "status": "success",
        "delivery_ids": maximum_identifiers,
        "delivery_uris": [
            (prefix := f"https://delivery.invalid/{index:02d}/")
            + ("x" * (MAX_DELIVERY_URI_BYTES - len(prefix)))
            for index in range(MAX_DELIVERY_URIS)
        ],
        "reason": "",
    }
    maximum_document = {
        "schema_version": _identity_evidence_schema_version(
            receipt,
            run_result,
            legacy_version=DELIVERY_EVIDENCE_SCHEMA_VERSION,
            identity_version=DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION,
        ),
        "receipt": receipt_document,
        "receipt_sha256": hashlib.sha256(
            _canonical_bytes(receipt_document)
        ).hexdigest(),
        "run_result": run_result_document,
        "run_result_sha256": hashlib.sha256(
            _canonical_bytes(run_result_document)
        ).hexdigest(),
        "delivery_result": maximum_delivery_result,
        "binding": _projected_binding(receipt),
        "sanitization": "disabled_by_user",
    }
    if len(_canonical_bytes(maximum_document)) > MAX_DELIVERY_EVIDENCE_BYTES:
        raise RuntimeError(
            "Collection topology exceeds bounded delivery evidence capacity"
        )


def write_delivery_result_evidence(
    *,
    receipt: FinalizationReceipt,
    run_result: RunResult,
    delivery_result: DeliveryResult,
    run_directory: Path,
    archive_paths: Sequence[Path] = (),
    sanitization_state: str = "write_time_only",
) -> Path:
    """
    Bind a terminal delivery result to the receipt-authorized local bytes.

    After applying local validation, the function forwards ``receipt``,
    ``run_result``, ``delivery_result``, ``run_directory``, and
    ``archive_paths`` to ``_publish_once`` and preserves its return and
    exception contract.

    Args:
        receipt: Receipt consumed while the function attempts to bind a terminal
            delivery result to the receipt-authorized local bytes.
        run_result: Run result object whose ``to_dict`` state is read while
            performing bind a terminal delivery result to the receipt-authorized
            local bytes.
        delivery_result: Delivery result object whose ``to_dict`` state is read
            while performing bind a terminal delivery result to the
            receipt-authorized local bytes.
        run_directory: filesystem location used as the run directory for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.
        sanitization_state: Canonical lifecycle state for the distributable
            bundle sanitization controls.

    Returns:
        The validated write delivery result evidence filesystem path.

    Raises:
        TypeError: If delivery evidence lacks an exact RunResult; or delivery
            evidence lacks an exact DeliveryResult.
    """

    if type(run_result) is not RunResult:
        raise TypeError("Delivery evidence requires an exact RunResult")
    if type(delivery_result) is not DeliveryResult:
        raise TypeError("Delivery evidence requires an exact DeliveryResult")
    if sanitization_state not in _DELIVERY_SANITIZATION_STATES:
        raise ValueError("Delivery evidence sanitization state is invalid")
    DeliveryResult.__post_init__(delivery_result)
    validate_delivery_evidence_eligibility(
        receipt=receipt,
        run_result=run_result,
    )
    _validate_delivery_terminal_truth(
        receipt,
        run_result,
        Path(run_directory),
        archive_paths,
    )
    parent, name, binding = _delivery_binding(
        receipt,
        run_directory,
        archive_paths,
    )
    document = {
        "schema_version": _identity_evidence_schema_version(
            receipt,
            run_result,
            legacy_version=DELIVERY_EVIDENCE_SCHEMA_VERSION,
            identity_version=DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION,
        ),
        "receipt": canonical_receipt_document(receipt),
        "receipt_sha256": _receipt_digest(receipt),
        "run_result": run_result.to_dict(),
        "run_result_sha256": _run_result_digest(run_result),
        "delivery_result": delivery_result.to_dict(),
        "binding": binding,
        "sanitization": sanitization_state,
    }
    return _publish_once(parent, name, _canonical_bytes(document))


def _verify_delivery_result_evidence_unpinned(
    sidecar: Path,
    *,
    run_directory: Path,
    archive_paths: Sequence[Path] = (),
    expected_receipt: FinalizationReceipt | None = None,
    expected_run_result: RunResult | None = None,
    _serialized: bytes | None = None,
) -> dict[str, Any]:
    """
    Read and independently verify one receipt-bound delivery sidecar.

    The implementation uses ``sidecar``, ``run_directory``, ``archive_paths``,
    ``expected_receipt``, and ``expected_run_result`` to read and independently
    verify one receipt-bound delivery sidecar. Parsing or I/O must finish before
    the validated representation is made available to the caller. If the
    function cannot read and independently verify one receipt-bound delivery
    sidecar, its exception reaches the caller instead of being converted into a
    successful result. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        sidecar: filesystem location used as the sidecar for this operation.
        run_directory: filesystem location used as the run directory for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.
        expected_receipt: Optional expected receipt; ``None`` selects the
            function's default behavior.
        expected_run_result: Optional expected run result; ``None`` selects the
            function's default behavior.
        _serialized: Optional serialized; ``None`` selects the function's
            default behavior.

    Returns:
        The validated ``document``.

    Raises:
        ValueError: If delivery evidence is not canonical JSON; delivery
            evidence fields are not exact; unsupported delivery evidence schema;
            or delivery evidence schema contradicts its run identity; or another
            input invariant is violated.
    """

    sidecar = Path(sidecar)
    if _serialized is None:
        parent_fd = _open_directory(sidecar.parent)
        parent_identity = _directory_identity(parent_fd)
        try:
            serialized = _read_existing(parent_fd, sidecar.name)
            _revalidate_parent_path(sidecar.parent, parent_identity)
        finally:
            _close_evidence_descriptors(
                (parent_fd,), context="Delivery evidence unpinned verification"
            )
    else:
        serialized = _serialized
    try:
        document = json.loads(serialized.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Delivery evidence is not canonical JSON") from error
    if type(document) is not dict:  # noqa: E721 - subclasses are rejected
        raise ValueError("Delivery evidence fields are not exact")
    schema_version = document.get("schema_version")
    expected_fields = {
        "schema_version",
        "receipt",
        "receipt_sha256",
        "run_result",
        "run_result_sha256",
        "delivery_result",
        "binding",
    }
    if schema_version in {
        DELIVERY_EVIDENCE_SCHEMA_VERSION,
        DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION,
        DELIVERY_EVIDENCE_DIAGNOSTICS_SCHEMA_VERSION,
        DELIVERY_EVIDENCE_DIAGNOSTICS_IDENTITY_SCHEMA_VERSION,
    }:
        expected_fields.add("sanitization")
    if set(document) != expected_fields:
        raise ValueError("Delivery evidence fields are not exact")
    if serialized != _canonical_bytes(document):
        raise ValueError("Delivery evidence is not canonical JSON")
    if document["schema_version"] not in {
        DELIVERY_EVIDENCE_SCHEMA_VERSION,
        DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION,
        DELIVERY_EVIDENCE_DIAGNOSTICS_SCHEMA_VERSION,
        DELIVERY_EVIDENCE_DIAGNOSTICS_IDENTITY_SCHEMA_VERSION,
        _LEGACY_DELIVERY_EVIDENCE_SCHEMA_VERSION,
        _LEGACY_DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION,
    }:
        raise ValueError("Unsupported delivery evidence schema")
    receipt = finalization_receipt_from_document(document["receipt"])
    run_result = validate_run_result_document(document["run_result"])
    if document["schema_version"] in {
        _LEGACY_DELIVERY_EVIDENCE_SCHEMA_VERSION,
        _LEGACY_DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION,
    }:
        expected_schema_version = _identity_evidence_schema_version(
            receipt,
            run_result,
            legacy_version=_LEGACY_DELIVERY_EVIDENCE_SCHEMA_VERSION,
            identity_version=_LEGACY_DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION,
        )
    else:
        expected_schema_version = _identity_evidence_schema_version(
            receipt,
            run_result,
            legacy_version=DELIVERY_EVIDENCE_SCHEMA_VERSION,
            identity_version=DELIVERY_EVIDENCE_IDENTITY_SCHEMA_VERSION,
        )
    if document["schema_version"] != expected_schema_version:
        raise ValueError("Delivery evidence schema contradicts its run identity")
    delivery_result = validate_delivery_result_document(document["delivery_result"])
    if "sanitization" in document and (
        document["sanitization"] not in _DELIVERY_SANITIZATION_STATES
    ):
        raise ValueError("Delivery evidence sanitization state is invalid")
    receipt_digest = hashlib.sha256(_canonical_bytes(document["receipt"])).hexdigest()
    result_digest = hashlib.sha256(_canonical_bytes(document["run_result"])).hexdigest()
    if (
        type(document["receipt_sha256"])  # noqa: E721 - subclasses are rejected
        is not str  # noqa: E721 - subclasses are rejected
        or document["receipt_sha256"] != receipt_digest
    ):
        raise ValueError("Delivery receipt hash is inconsistent")
    if (
        type(document["run_result_sha256"])  # noqa: E721 - subclasses are rejected
        is not str  # noqa: E721 - subclasses are rejected
        or document["run_result_sha256"] != result_digest
    ):
        raise ValueError("Delivery RunResult hash is inconsistent")
    validate_consumable_finalization_receipt(receipt)
    if (
        receipt.interrupted
        or not finalization_failures_allow_delivery(receipt)
        or not receipt.mandatory_teardown_complete
    ):
        raise ValueError("Delivery receipt does not prove safe local finalization")
    if RunResult.from_finalization_receipt(receipt) != run_result:
        raise ValueError("Delivery RunResult differs from its receipt projection")
    _validate_run_result_leaf_evidence(receipt, run_result)
    if expected_receipt is not None and (
        type(expected_receipt) is not FinalizationReceipt or expected_receipt != receipt
    ):
        raise ValueError("Delivery receipt differs from expected evidence")
    if expected_run_result is not None and (
        type(expected_run_result) is not RunResult or expected_run_result != run_result
    ):
        raise ValueError("Delivery RunResult differs from expected evidence")

    _validate_delivery_terminal_truth(
        receipt,
        run_result,
        Path(run_directory),
        archive_paths,
    )

    binding = document["binding"]
    if receipt.archive_artifact_digests:
        expected_parent, expected_name, expected_binding = _archive_binding(
            receipt,
            Path(run_directory),
            archive_paths,
        )
    else:
        if archive_paths:
            raise ValueError("Loose delivery evidence was given archive targets")
        expected_parent, expected_name, expected_binding = _snapshot_binding(
            receipt,
            Path(run_directory),
        )
    expected_path = Path(os.path.abspath(expected_parent / expected_name))
    observed_path = Path(os.path.abspath(sidecar))
    if observed_path != expected_path or binding != expected_binding:
        raise ValueError("Delivery artifact binding is inconsistent")
    # Keep the exact validated value live in this boundary; construction above
    # ensures hostile delivery-result documents cannot hide behind truthiness.
    if delivery_result.to_dict() != document["delivery_result"]:
        raise ValueError("Delivery result projection is inconsistent")
    return document


def verify_delivery_result_evidence(
    sidecar: Path,
    *,
    run_directory: Path,
    archive_paths: Sequence[Path] = (),
    expected_receipt: FinalizationReceipt | None = None,
    expected_run_result: RunResult | None = None,
) -> dict[str, Any]:
    """
    Verify delivery evidence while pinning its leaf and parent until return.

    The implementation uses ``sidecar``, ``run_directory``, ``archive_paths``,
    ``expected_receipt``, and ``expected_run_result`` to verify delivery
    evidence while pinning its leaf and parent until return. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path. Cleanup in the ``finally``
    path runs for successful, failed, and cancelled execution.

    Args:
        sidecar: filesystem location used as the sidecar for this operation.
        run_directory: filesystem location used as the run directory for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.
        expected_receipt: Optional expected receipt; ``None`` selects the
            function's default behavior.
        expected_run_result: Optional expected run result; ``None`` selects the
            function's default behavior.

    Returns:
        The validated ``document``.
    """

    sidecar = Path(sidecar)
    parent_fd = _open_directory(sidecar.parent)
    parent_identity = _directory_identity(parent_fd)
    descriptor: int | None = None
    try:
        descriptor, leaf_identity = _pin_evidence_leaf(
            parent_fd,
            sidecar.name,
            maximum_bytes=MAX_DELIVERY_EVIDENCE_BYTES,
        )
        serialized = _read_pinned_evidence_leaf(
            parent_fd,
            sidecar.name,
            descriptor,
            leaf_identity,
            maximum_bytes=MAX_DELIVERY_EVIDENCE_BYTES,
        )
        document = _verify_delivery_result_evidence_unpinned(
            sidecar,
            run_directory=run_directory,
            archive_paths=archive_paths,
            expected_receipt=expected_receipt,
            expected_run_result=expected_run_result,
            _serialized=serialized,
        )
        _confirm_pinned_evidence_leaf(
            parent_fd,
            sidecar.name,
            descriptor,
            leaf_identity,
        )
        _revalidate_parent_path(sidecar.parent, parent_identity)
        return document
    finally:
        _close_evidence_descriptors(
            (descriptor, parent_fd), context="Delivery evidence verification"
        )


def write_terminal_outcome_override_evidence(
    *,
    receipt: FinalizationReceipt,
    run_result: RunResult,
    run_directory: Path,
    archive_paths: Sequence[Path],
) -> Path:
    """
    Publish a canonical late-outcome override beside immutable archives.

    After applying local validation, the function forwards ``receipt``,
    ``run_result``, ``run_directory``, and ``archive_paths`` to
    ``_publish_once`` and preserves its return and exception contract. Success
    is reported only after the owning output boundary has completed its required
    write or publication step.

    Args:
        receipt: Receipt object whose ``archive_artifact_digests`` state is read
            while performing canonical late-outcome override beside immutable
            archives.
        run_result: Run result object whose ``exit_code``, ``to_dict``, and
            ``to_legacy_run_outcome`` state is read while performing canonical
            late-outcome override beside immutable archives.
        run_directory: filesystem location used as the run directory for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.

    Returns:
        The validated write terminal outcome override evidence filesystem path.

    Raises:
        TypeError: If terminal override lacks an exact RunResult.
        RuntimeError: If terminal override lacks receipt-bound archive evidence;
            terminal override RunResult differs from its receipt; or terminal
            override cannot replace an archive with success.
    """

    if type(run_result) is not RunResult:
        raise TypeError("Terminal override requires an exact RunResult")
    validate_structural_finalization_receipt(receipt)
    if not receipt.archive_artifact_digests:
        raise RuntimeError("Terminal override requires receipt-bound archive evidence")
    if RunResult.from_finalization_receipt(receipt) != run_result:
        raise RuntimeError("Terminal override RunResult differs from its receipt")
    if run_result.exit_code == 0:
        raise RuntimeError("Terminal override cannot replace an archive with success")
    _validate_terminal_override_representation(run_directory, archive_paths)
    parent, _delivery_name, binding = _archive_binding(
        receipt,
        Path(run_directory),
        archive_paths,
    )
    bundle_name = Path(run_directory).name
    document = {
        "schema_version": _identity_evidence_schema_version(
            receipt,
            run_result,
            legacy_version=TERMINAL_OUTCOME_OVERRIDE_SCHEMA_VERSION,
            identity_version=TERMINAL_OUTCOME_OVERRIDE_IDENTITY_SCHEMA_VERSION,
        ),
        "operation": "terminal_outcome_override",
        "bundle_name": bundle_name,
        "representation": "split_zip" if len(archive_paths) > 1 else "zip",
        "receipt": canonical_receipt_document(receipt),
        "receipt_sha256": _receipt_digest(receipt),
        "run_result": run_result.to_dict(),
        "run_result_sha256": _run_result_digest(run_result),
        "outcome": run_result.to_legacy_run_outcome(),
        "immutable_artifacts": binding["artifacts"],
    }
    return _publish_once(
        parent,
        f"{bundle_name}.terminal_outcome.json",
        _canonical_bytes(document),
        maximum_bytes=MAX_TERMINAL_OUTCOME_OVERRIDE_BYTES,
    )


def _verify_terminal_outcome_override_evidence_unpinned(
    sidecar: Path,
    *,
    run_directory: Path,
    archive_paths: Sequence[Path],
    expected_receipt: FinalizationReceipt | None = None,
    expected_run_result: RunResult | None = None,
    _serialized: bytes | None = None,
) -> dict[str, Any]:
    """
    Verify one canonical, no-clobber late-outcome archive override.

    The implementation uses ``sidecar``, ``run_directory``, ``archive_paths``,
    ``expected_receipt``, and ``expected_run_result`` to verify one canonical,
    no-clobber late-outcome archive override. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        sidecar: filesystem location used as the sidecar for this operation.
        run_directory: filesystem location used as the run directory for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.
        expected_receipt: Optional expected receipt; ``None`` selects the
            function's default behavior.
        expected_run_result: Optional expected run result; ``None`` selects the
            function's default behavior.
        _serialized: Optional serialized; ``None`` selects the function's
            default behavior.

    Returns:
        The validated ``document``.

    Raises:
        ValueError: If terminal override is not canonical JSON; terminal
            override fields are not exact; terminal override identity is
            inconsistent; or terminal override schema contradicts its run
            identity; or another input invariant is violated.
    """

    sidecar = Path(sidecar)
    if _serialized is None:
        parent_fd = _open_directory(sidecar.parent)
        parent_identity = _directory_identity(parent_fd)
        try:
            serialized = _read_existing(
                parent_fd,
                sidecar.name,
                maximum_bytes=MAX_TERMINAL_OUTCOME_OVERRIDE_BYTES,
            )
            _revalidate_parent_path(sidecar.parent, parent_identity)
        finally:
            _close_evidence_descriptors(
                (parent_fd,), context="Terminal override unpinned verification"
            )
    else:
        serialized = _serialized
    try:
        document = json.loads(serialized.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Terminal override is not canonical JSON") from error
    if serialized != _canonical_bytes(document):
        raise ValueError("Terminal override is not canonical JSON")
    expected_fields = {
        "schema_version",
        "operation",
        "bundle_name",
        "representation",
        "receipt",
        "receipt_sha256",
        "run_result",
        "run_result_sha256",
        "outcome",
        "immutable_artifacts",
    }
    if (
        type(document) is not dict  # noqa: E721 - subclasses are rejected
        or set(document) != expected_fields  # noqa: E721 - subclasses are rejected
    ):  # noqa: E721 - subclasses are rejected
        raise ValueError("Terminal override fields are not exact")
    run_directory = Path(run_directory)
    bundle_name = run_directory.name
    if (
        document["schema_version"]
        not in {
            TERMINAL_OUTCOME_OVERRIDE_SCHEMA_VERSION,
            TERMINAL_OUTCOME_OVERRIDE_IDENTITY_SCHEMA_VERSION,
            TERMINAL_OUTCOME_OVERRIDE_DIAGNOSTICS_SCHEMA_VERSION,
            TERMINAL_OUTCOME_OVERRIDE_DIAGNOSTICS_IDENTITY_SCHEMA_VERSION,
        }
        or document["operation"] != "terminal_outcome_override"
        or document["bundle_name"] != bundle_name
        or sidecar.name != f"{bundle_name}.terminal_outcome.json"
        or document["representation"]
        != ("split_zip" if len(archive_paths) > 1 else "zip")
    ):
        raise ValueError("Terminal override identity is inconsistent")

    receipt = finalization_receipt_from_document(document["receipt"])
    run_result = validate_run_result_document(document["run_result"])
    expected_schema_version = _identity_evidence_schema_version(
        receipt,
        run_result,
        legacy_version=TERMINAL_OUTCOME_OVERRIDE_SCHEMA_VERSION,
        identity_version=TERMINAL_OUTCOME_OVERRIDE_IDENTITY_SCHEMA_VERSION,
    )
    if document["schema_version"] != expected_schema_version:
        raise ValueError("Terminal override schema contradicts its run identity")
    if (
        document["receipt_sha256"]
        != hashlib.sha256(_canonical_bytes(document["receipt"])).hexdigest()
        or document["run_result_sha256"]
        != hashlib.sha256(_canonical_bytes(document["run_result"])).hexdigest()
    ):
        raise ValueError("Terminal override hash is inconsistent")
    if not receipt.archive_artifact_digests:
        raise ValueError("Terminal override lacks archive receipt evidence")
    if RunResult.from_finalization_receipt(receipt) != run_result:
        raise ValueError("Terminal override RunResult differs from its receipt")
    if run_result.exit_code == 0:
        raise ValueError("Terminal override cannot authorize success")
    if document["outcome"] != run_result.to_legacy_run_outcome():
        raise ValueError("Terminal override legacy projection is inconsistent")
    if expected_receipt is not None and (
        type(expected_receipt) is not FinalizationReceipt or expected_receipt != receipt
    ):
        raise ValueError("Terminal override receipt differs from expected evidence")
    if expected_run_result is not None and (
        type(expected_run_result) is not RunResult or expected_run_result != run_result
    ):
        raise ValueError("Terminal override RunResult differs from expected evidence")

    _validate_terminal_override_representation(run_directory, archive_paths)
    expected_parent, _delivery_name, binding = _archive_binding(
        receipt,
        run_directory,
        archive_paths,
    )
    if (
        Path(os.path.abspath(sidecar.parent)) != Path(os.path.abspath(expected_parent))
        or document["immutable_artifacts"] != binding["artifacts"]
    ):
        raise ValueError("Terminal override archive binding is inconsistent")
    return document


def verify_terminal_outcome_override_evidence(
    sidecar: Path,
    *,
    run_directory: Path,
    archive_paths: Sequence[Path],
    expected_receipt: FinalizationReceipt | None = None,
    expected_run_result: RunResult | None = None,
) -> dict[str, Any]:
    """
    Verify terminal override while pinning its leaf and parent until return.

    The implementation uses ``sidecar``, ``run_directory``, ``archive_paths``,
    ``expected_receipt``, and ``expected_run_result`` to verify terminal
    override while pinning its leaf and parent until return. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path. Cleanup in the ``finally``
    path runs for successful, failed, and cancelled execution.

    Args:
        sidecar: filesystem location used as the sidecar for this operation.
        run_directory: filesystem location used as the run directory for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.
        expected_receipt: Optional expected receipt; ``None`` selects the
            function's default behavior.
        expected_run_result: Optional expected run result; ``None`` selects the
            function's default behavior.

    Returns:
        The validated ``document``.
    """

    sidecar = Path(sidecar)
    parent_fd = _open_directory(sidecar.parent)
    parent_identity = _directory_identity(parent_fd)
    descriptor: int | None = None
    try:
        descriptor, leaf_identity = _pin_evidence_leaf(
            parent_fd,
            sidecar.name,
            maximum_bytes=MAX_TERMINAL_OUTCOME_OVERRIDE_BYTES,
        )
        serialized = _read_pinned_evidence_leaf(
            parent_fd,
            sidecar.name,
            descriptor,
            leaf_identity,
            maximum_bytes=MAX_TERMINAL_OUTCOME_OVERRIDE_BYTES,
        )
        document = _verify_terminal_outcome_override_evidence_unpinned(
            sidecar,
            run_directory=run_directory,
            archive_paths=archive_paths,
            expected_receipt=expected_receipt,
            expected_run_result=expected_run_result,
            _serialized=serialized,
        )
        _confirm_pinned_evidence_leaf(
            parent_fd,
            sidecar.name,
            descriptor,
            leaf_identity,
        )
        _revalidate_parent_path(sidecar.parent, parent_identity)
        return document
    finally:
        _close_evidence_descriptors(
            (descriptor, parent_fd), context="Terminal override verification"
        )
