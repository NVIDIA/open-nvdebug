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
Typed producer-side archive provenance and publication primitives.

This module owns the archive publication boundary and exposes
``ArchiveContentIdentity``, ``_DiagnosticFileSnapshot``,
``ArchivePublicationCapabilities``, ``canonical_receipt_is_well_formed``, and
``atomic_write_bytes``. Keeping those contracts together gives importers one
source of truth for their validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..utils.archive_validation import (
    ARCHIVE_VALIDATION_PRIMARY_ROLE,
    ARCHIVE_VALIDATION_PRODUCER,
    ARCHIVE_VALIDATION_REFERENCE_ROLE,
    ARCHIVE_VALIDATION_SCHEMA,
    archive_validation_is_sha256,
    archive_validation_load_json,
    archive_validation_path_sha256,
    archive_validation_receipt_id,
)

_NORMALIZATION = "removed_exact_trailing_empty_json_array"
_IDENTITY_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_UNCONSTRAINED = object()


@dataclass(frozen=True)
class ArchiveContentIdentity:
    """
    Identity captured from the exact bytes considered for publication.

    The immutable record keeps ``size``, ``sha256``,
    ``appended_empty_array_sha256``, and ``prefix`` together so consumers
    observe one archive content identity state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        size: Cumulative byte count represented by this record.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        appended_empty_array_sha256: Lowercase SHA-256 digest binding the
            appended empty array content.
        prefix: Bounded byte sequence retained as prefix.
    """

    size: int
    sha256: str
    appended_empty_array_sha256: str
    prefix: bytes = b""


@dataclass(frozen=True)
class _DiagnosticFileSnapshot:
    """
    Represent diagnostic file snapshot data exchanged by the runtime.

    The immutable record keeps ``device``, ``inode``, ``mode``, ``links``, and
    ``size`` together so consumers observe one diagnostic file state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        device: Numeric device retained by this record.
        inode: Numeric inode retained by this record.
        mode: Numeric mode retained by this record.
        links: Number of links represented by this record.
        size: Cumulative byte count represented by this record.
        mtime_ns: Number of mtime ns represented by this record.
        ctime_ns: Number of ctime ns represented by this record.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
    """

    device: int
    inode: int
    mode: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str


class ArchivePublicationCapabilities:
    """
    Service-owned, one-use capabilities for prevalidated archive bytes.

    The type coordinates ``issue``, ``consume``, ``complete``, and ``take`` and
    retains the state those operations share between calls. Resource ownership
    remains inside the instance until the matching close, exit, or cleanup
    operation completes.
    """

    def __init__(self) -> None:
        """
        Initialize an ``ArchivePublicationCapabilities`` instance.

        The initializer records ``_completed`` and ``_issued`` for later
        operations and establishes the instance invariants before any public
        method runs.
        """
        self._issued: dict[int, tuple[object, dict[str, Any]]] = {}
        self._completed: dict[int, tuple[object, dict[str, Any]]] = {}

    def issue(self, validation: Mapping[str, Any]) -> object:
        """
        Return the issue.

        The implementation uses ``validation`` to produce the issue. If the
        function cannot produce the issue, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            validation: Mapping supplying fields for issue.

        Returns:
            The validated ``token``.

        Raises:
            ValueError: If only accepted archive evidence can be issued.
        """
        if not isinstance(validation, dict) or validation.get("status") not in {
            "valid",
            "normalized",
        }:
            raise ValueError("only accepted archive evidence can be issued")
        token = object()
        self._issued[id(token)] = (token, dict(validation))
        return token

    def consume(self, token: object) -> dict[str, Any]:
        """
        Consume the supplied value under the current boundary.

        The implementation uses ``token`` to consume the supplied value under
        the current boundary. If the function cannot consume the supplied value
        under the current boundary, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            token: Sensitive value supplied through the approved input boundary
                and never logged.

        Returns:
            A mapping containing consume.

        Raises:
            TypeError: If archive publication capability was not issued by this
                service.
        """
        entry = self._issued.get(id(token))
        if entry is None or entry[0] is not token:
            raise TypeError(
                "archive publication capability was not issued by this service"
            )
        del self._issued[id(token)]
        return entry[1]

    def complete(self, token: object, reference: Mapping[str, Any]) -> None:
        """
        Mark the publication capability result as complete.

        The implementation uses ``token`` and ``reference`` to mark the
        publication capability result as complete.

        Args:
            token: Sensitive value supplied through the approved input boundary
                and never logged.
            reference: Mapping supplying fields for mark the publication
                capability result as complete.
        """
        self._completed[id(token)] = (token, dict(reference))

    def take(self, token: object) -> dict[str, Any] | None:
        """
        Return the take.

        After applying local validation, the function forwards ``token`` to
        ``dict`` and preserves its return and exception contract.

        Args:
            token: Sensitive value supplied through the approved input boundary
                and never logged.

        Returns:
            A mapping containing take, or ``None`` when the requested value is
            unavailable.
        """
        entry = self._completed.get(id(token))
        if entry is None or entry[0] is not token:
            return None
        del self._completed[id(token)]
        return dict(entry[1])


def canonical_receipt_is_well_formed(record: Any) -> bool:
    """
    Return whether a persisted receipt is safe to retain and extend.

    The implementation uses ``record`` to determine whether a persisted receipt
    is safe to retain and extend.

    Args:
        record: Record object whose ``get`` state is read while performing
            persisted receipt is safe to retain and extend.

    Returns:
        Whether a persisted receipt is safe to retain and extend.
    """

    if type(record) is not dict:
        return False
    status = record.get("status")
    if (
        record.get("schema") != ARCHIVE_VALIDATION_SCHEMA
        or record.get("producer") != ARCHIVE_VALIDATION_PRODUCER
        or record.get("receipt_role") != ARCHIVE_VALIDATION_PRIMARY_ROLE
        or status not in {"valid", "normalized", "invalid"}
        or not archive_validation_is_sha256(record.get("validation_id"))
        or archive_validation_receipt_id(record) != record.get("validation_id")
    ):
        return False
    if status == "invalid":
        return (
            record.get("normalization") is None
            and archive_validation_is_sha256(record.get("requested_filename_sha256"))
            and "artifact_path" not in record
            and "artifact_path_sha256" not in record
        )
    if (
        not isinstance(record.get("artifact_path"), str)
        or not archive_validation_is_sha256(record.get("artifact_path_sha256"))
        or type(record.get("original_size")) is not int
        or record["original_size"] <= 0
        or type(record.get("saved_size")) is not int
        or record["saved_size"] <= 0
        or not archive_validation_is_sha256(record.get("original_sha256"))
        or not archive_validation_is_sha256(record.get("saved_sha256"))
    ):
        return False
    producer_size = record.get("pre_sanitization_saved_size", record["saved_size"])
    producer_sha256 = record.get(
        "pre_sanitization_saved_sha256", record["saved_sha256"]
    )
    if (
        type(producer_size) is not int
        or producer_size <= 0
        or not archive_validation_is_sha256(producer_sha256)
    ):
        return False
    if status == "valid":
        return record.get("normalization") is None and (
            record["original_size"],
            record["original_sha256"],
        ) == (producer_size, producer_sha256)
    return (
        record.get("normalization") == _NORMALIZATION
        and record["original_size"] == producer_size + 2
    )


def read_diagnostic_bytes(path: Path, *, max_bytes: int) -> bytes:
    """
    Read one bounded diagnostic file through pinned, link-free descriptors.

    The caller owns any read-modify-write serialization. The reader rejects
    links, non-regular files, oversized input, and identity changes during the
    read, and closes every descriptor before returning or raising.

    Args:
        path: Diagnostic artifact beneath its caller-selected output directory.
        max_bytes: Maximum encoded input size admitted by the owning format.

    Returns:
        The complete bytes from the validated file snapshot.

    Raises:
        OSError: If a directory or file cannot be opened without following links.
        ValueError: If the limit is invalid or the file is not a stable, bounded,
            singly linked regular file.
    """

    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("diagnostic byte limit must be a nonnegative integer")
    path = Path(path)
    parent_fd = _open_directory_nofollow(path.parent)
    try:
        data, _snapshot = _read_diagnostic_file_at(parent_fd, path.name, max_bytes)
        return data
    finally:
        os.close(parent_fd)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """
    Replace one regular diagnostic file durably and atomically.

    The implementation uses ``path`` and ``data`` to replace one regular
    diagnostic file durably and atomically. Cleanup in the ``finally`` path runs
    for successful, failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.
        data: Bounded byte sequence supplied as data.
    """

    path = Path(path)
    parent_fd = _open_directory_nofollow(path.parent, create=True)
    try:
        _atomic_write_bytes_at(
            parent_fd,
            path.name,
            data,
            binding_path=path.parent,
        )
    finally:
        os.close(parent_fd)


def append_canonical_receipt(
    path: Path,
    record: Mapping[str, Any],
    *,
    max_records: int,
    max_bytes: int,
) -> bool:
    """
    Append one strict receipt under a pinned cross-process directory lock.

    The implementation uses ``path``, ``record``, ``max_records``, and
    ``max_bytes`` to append one strict receipt under a pinned cross-process
    directory lock. If the function cannot append one strict receipt under a
    pinned cross-process directory lock, its exception reaches the caller
    instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.
        record: Mapping supplying fields for append one strict receipt under a
            pinned cross-process directory lock.
        max_records: Upper bound enforced for max records; the consuming
            boundary rejects or truncates values that exceed it.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        Whether the append one strict receipt under a pinned cross-process
        directory lock operation succeeds.

    Raises:
        ValueError: If refusing to persist malformed archive receipt; archive
            receipt history is at record limit; or archive receipt exceeds byte
            limit.
        RuntimeError: If refusing to replace malformed archive receipt history;
            or conflicting receipt already binds archive path.
    """

    if not canonical_receipt_is_well_formed(record):
        raise ValueError("refusing to persist malformed archive receipt")
    path = Path(path)
    parent_fd = _open_directory_nofollow(path.parent, create=True)
    try:
        fcntl.flock(parent_fd, fcntl.LOCK_EX)
        try:
            try:
                raw_history, snapshot = _read_diagnostic_file_at(
                    parent_fd, path.name, max_bytes
                )
            except FileNotFoundError:
                existing: list[dict[str, Any]] = []
                snapshot = None
            else:
                try:
                    loaded = archive_validation_load_json(raw_history)
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                    raise RuntimeError(
                        "refusing to replace malformed archive receipt history"
                    ) from None
                if (
                    type(loaded) is not list
                    or len(loaded) > max_records
                    or any(
                        not canonical_receipt_is_well_formed(item) for item in loaded
                    )
                ):
                    raise RuntimeError(
                        "refusing to replace malformed archive receipt history"
                    )
                existing = loaded

            validation_id = record["validation_id"]
            artifact_key = record.get("artifact_path_sha256")
            for prior in existing:
                if prior.get("validation_id") == validation_id:
                    return False
                if (
                    artifact_key is not None
                    and prior.get("artifact_path_sha256") == artifact_key
                ):
                    raise RuntimeError("conflicting receipt already binds archive path")
            if len(existing) >= max_records:
                raise ValueError("archive receipt history is at record limit")

            encoded = json.dumps(
                [*existing, dict(record)],
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(encoded) > max_bytes:
                raise ValueError("archive receipt exceeds byte limit")
            _atomic_write_bytes_at(
                parent_fd,
                path.name,
                encoded,
                expected=snapshot,
                binding_path=path.parent,
            )
            return True
        finally:
            fcntl.flock(parent_fd, fcntl.LOCK_UN)
    finally:
        os.close(parent_fd)


def canonical_invalid_validation(validation: Mapping[str, Any]) -> dict[str, Any]:
    """
    Version immutable evidence for a rejected, unpublished attachment.

    The implementation uses ``validation`` to version immutable evidence for a
    rejected, unpublished attachment.

    Args:
        validation: Mapping supplying fields for version immutable evidence for
            a rejected, unpublished attachment.

    Returns:
        The validated ``canonical``.
    """

    canonical = _raw_validation_fields(validation)
    canonical.update(
        {
            "schema": ARCHIVE_VALIDATION_SCHEMA,
            "producer": ARCHIVE_VALIDATION_PRODUCER,
            "receipt_role": ARCHIVE_VALIDATION_PRIMARY_ROLE,
            "requested_filename_sha256": archive_validation_path_sha256(
                str(canonical.get("filename") or "")
            ),
        }
    )
    canonical["validation_id"] = archive_validation_receipt_id(canonical)
    return canonical


def canonical_persisted_validation(
    validation: Mapping[str, Any], artifact_path: str
) -> dict[str, Any]:
    """
    Bind validated producer bytes to the exact published relative path.

    The implementation uses ``validation`` and ``artifact_path`` to bind
    validated producer bytes to the exact published relative path.

    Args:
        validation: Mapping supplying fields for bind validated producer bytes
            to the exact published relative path.
        artifact_path: filesystem location used as the artifact path for this
            operation.

    Returns:
        The validated ``canonical``.
    """

    canonical = _raw_validation_fields(validation)
    canonical.update(
        {
            "schema": ARCHIVE_VALIDATION_SCHEMA,
            "producer": ARCHIVE_VALIDATION_PRODUCER,
            "receipt_role": ARCHIVE_VALIDATION_PRIMARY_ROLE,
            "filename": artifact_path,
            "artifact_path": artifact_path,
            "artifact_path_sha256": archive_validation_path_sha256(artifact_path),
        }
    )
    canonical["validation_id"] = archive_validation_receipt_id(canonical)
    return canonical


def _raw_validation_fields(validation: Mapping[str, Any]) -> dict[str, Any]:
    """
    Return the raw validation fields.

    The implementation uses ``validation`` to produce the raw validation fields.

    Args:
        validation: Mapping supplying fields for raw validation fields.

    Returns:
        A mapping containing raw validation fields.
    """
    return {
        field: validation[field]
        for field in (
            "filename",
            "original_size",
            "original_sha256",
            "saved_size",
            "saved_sha256",
            "status",
            "normalization",
            "validation_error",
        )
        if field in validation
    }


def validate_accepted_provenance(
    validation: Mapping[str, Any], identity: ArchiveContentIdentity
) -> None:
    """
    Reject accepted evidence inconsistent with the bytes being published.

    The implementation uses ``validation`` and ``identity`` to reject accepted
    evidence inconsistent with the bytes being published. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        validation: Mapping supplying fields for accepted evidence inconsistent
            with the bytes being published.
        identity: Identity object whose ``appended_empty_array_sha256``,
            ``sha256``, and ``size`` state is read while performing accepted
            evidence inconsistent with the bytes being published.

    Raises:
        ValueError: If accepted archive provenance has an invalid identity;
            valid archive provenance is inconsistent; normalized archive
            provenance is inconsistent; or only accepted archive provenance can
            be published.
    """

    original_size = validation.get("original_size")
    original_sha256 = validation.get("original_sha256")
    if (
        identity.size <= 0
        or not archive_validation_is_sha256(identity.sha256)
        or validation.get("saved_size") != identity.size
        or validation.get("saved_sha256") != identity.sha256
        or type(original_size) is not int
        or original_size <= 0
        or not archive_validation_is_sha256(original_sha256)
    ):
        raise ValueError("accepted archive provenance has an invalid identity")

    status = validation.get("status")
    normalization = validation.get("normalization")
    if status == "valid":
        if normalization is not None or (original_size, original_sha256) != (
            identity.size,
            identity.sha256,
        ):
            raise ValueError("valid archive provenance is inconsistent")
    elif status == "normalized":
        if (
            normalization != _NORMALIZATION
            or original_size != identity.size + 2
            or original_sha256 != identity.appended_empty_array_sha256
        ):
            raise ValueError("normalized archive provenance is inconsistent")
    else:
        raise ValueError("only accepted archive provenance can be published")


def validation_reference(validation: Mapping[str, Any]) -> dict[str, Any]:
    """
    Return the immutable summary embedded in diagnostic responses.

    The implementation uses ``validation`` to produce the immutable summary
    embedded in diagnostic responses.

    Args:
        validation: Mapping supplying fields for immutable summary embedded in
            diagnostic responses.

    Returns:
        A mapping containing the ``schema``, ``producer``, ``receipt_role``,
        ``validation_id``, and ``status`` fields.
    """

    return {
        "schema": ARCHIVE_VALIDATION_SCHEMA,
        "producer": ARCHIVE_VALIDATION_PRODUCER,
        "receipt_role": ARCHIVE_VALIDATION_REFERENCE_ROLE,
        "validation_id": validation["validation_id"],
        "status": validation.get("status"),
        "normalization": validation.get("normalization"),
    }


def restore_canonical_evidence(
    source: Mapping[str, Any], bounded: dict[str, Any]
) -> dict[str, Any]:
    """
    Keep receipt identities exact after bounded diagnostic sanitization.

    The implementation uses ``source`` and ``bounded`` to keep receipt
    identities exact after bounded diagnostic sanitization.

    Args:
        source: Mapping supplying fields for keep receipt identities exact after
            bounded diagnostic sanitization.
        bounded: Mapping supplying fields for keep receipt identities exact
            after bounded diagnostic sanitization.

    Returns:
        The validated ``bounded``.
    """

    def has_summary(value: Any, role: str) -> bool:
        """
        Return whether ``value`` has summary.

        The implementation uses ``value`` and ``role`` to determine whether
        ``value`` has summary.

        Args:
            value: Value object whose ``get`` state is read while performing
                ``value`` has summary.
            role: Text supplied as role in the format accepted by this function.

        Returns:
            Whether ``value`` has summary.
        """
        if type(value) is not dict:
            return False
        return (
            value.get("schema") == ARCHIVE_VALIDATION_SCHEMA
            and value.get("producer") == ARCHIVE_VALIDATION_PRODUCER
            and value.get("receipt_role") == role
            and archive_validation_is_sha256(value.get("validation_id"))
            and value.get("status") in {"valid", "normalized", "invalid"}
            and value.get("normalization") in {None, _NORMALIZATION}
        )

    if has_summary(source, ARCHIVE_VALIDATION_PRIMARY_ROLE) and (
        archive_validation_receipt_id(dict(source)) == source["validation_id"]
    ):
        for field in (
            "schema",
            "producer",
            "receipt_role",
            "validation_id",
            "artifact_path_sha256",
            "requested_filename_sha256",
            "status",
            "normalization",
            "original_size",
            "original_sha256",
            "saved_size",
            "saved_sha256",
        ):
            if field not in source:
                continue
            value = source[field]
            if field.endswith("sha256") and not archive_validation_is_sha256(value):
                continue
            if field.endswith("size") and (type(value) is not int or value < 0):
                continue
            bounded[field] = value

    reference = source.get("archive_validation")
    if has_summary(reference, ARCHIVE_VALIDATION_REFERENCE_ROLE):
        bounded["archive_validation"] = {
            field: reference[field]
            for field in (
                "schema",
                "producer",
                "receipt_role",
                "validation_id",
                "status",
                "normalization",
            )
        }
    return bounded


def identity_from_bytes(payload: bytes) -> ArchiveContentIdentity:
    """
    Return the identity from bytes.

    After applying local validation, the function forwards ``payload`` to
    ``ArchiveContentIdentity`` and preserves its return and exception contract.

    Args:
        payload: Bounded byte sequence supplied as payload.

    Returns:
        An ``ArchiveContentIdentity`` representing identity from bytes.
    """
    digest = hashlib.sha256(payload)
    appended_digest = digest.copy()
    appended_digest.update(b"[]")
    return ArchiveContentIdentity(
        len(payload), digest.hexdigest(), appended_digest.hexdigest(), payload[:512]
    )


def stable_file_identity(path: Path) -> ArchiveContentIdentity:
    """
    Hash one regular file through a pinned descriptor and detect mutation.

    After applying local validation, the function forwards ``path`` to
    ``_copy_and_hash_file`` and preserves its return and exception contract.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        An ``ArchiveContentIdentity`` representing stable file identity.
    """

    descriptor = os.open(path, _READ_FLAGS)
    try:
        return _copy_and_hash_file(descriptor)
    finally:
        os.close(descriptor)


def publish_archive_no_replace(
    destination: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    payload: bytes | None = None,
    source_path: Path | None = None,
) -> ArchiveContentIdentity:
    """
    Durably publish exactly one validated byte or file source without replace.

    The implementation uses ``destination``, ``expected_size``,
    ``expected_sha256``, ``payload``, and ``source_path`` to durably publish
    exactly one validated byte or file source without replace. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot durably publish exactly one validated byte
    or file source without replace, its exception reaches the caller instead of
    being converted into a successful result. Cleanup in the ``finally`` path
    runs for successful, failed, and cancelled execution.

    Args:
        destination: filesystem location used as the destination for this
            operation.
        expected_size: Numeric expected size used by the operation's bounded
            accounting.
        expected_sha256: Text supplied as expected SHA-256 in the format
            accepted by this function.
        payload: Optional payload; ``None`` selects the function's default
            behavior.
        source_path: Optional filesystem location used as the source for this
            operation.

    Returns:
        The validated ``identity``.

    Raises:
        TypeError: If archive publication lacks exactly one byte or file source.
        ValueError: If archive staging bytes changed before publication; or
            published archive bytes differ from validated bytes.
        FileExistsError: If refusing to replace a concurrently published
            archive.
        OSError: If archive parent changed during publication.
    """

    if (payload is None) == (source_path is None):
        raise TypeError("archive publication requires exactly one byte or file source")
    destination = Path(destination)
    parent_fd = _open_directory_nofollow(destination.parent, create=True)
    source_parent_fd = -1
    source_name: str | None = None
    source_inode: tuple[int, int] | None = None
    staging_fd = -1
    staging_name: str | None = None
    published = False
    try:
        staging_fd, staging_name = _create_staging_file(parent_fd)
        if source_path is not None:
            source_path = Path(source_path)
            source_parent_fd = _open_directory_nofollow(source_path.parent)
            source_name = source_path.name
            source_fd = os.open(source_name, _READ_FLAGS, dir_fd=source_parent_fd)
            try:
                identity = _copy_and_hash_file(source_fd, staging_fd)
                source_stat = os.fstat(source_fd)
                source_inode = (source_stat.st_dev, source_stat.st_ino)
            finally:
                os.close(source_fd)
        else:
            assert payload is not None
            identity = identity_from_bytes(payload)
            _write_all(staging_fd, payload)
        if (identity.size, identity.sha256) != (expected_size, expected_sha256):
            raise ValueError("archive staging bytes changed before publication")
        os.fsync(staging_fd)

        try:
            os.link(
                staging_name,
                destination.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            published = True
        except FileExistsError:
            if _file_identity_at(parent_fd, destination.name, expected_size) != (
                expected_size,
                expected_sha256,
            ):
                raise FileExistsError(
                    "refusing to replace a concurrently published archive"
                ) from None
        if published:
            final_stat = os.stat(
                destination.name, dir_fd=parent_fd, follow_symlinks=False
            )
            staged_stat = os.fstat(staging_fd)
            if (final_stat.st_dev, final_stat.st_ino) != (
                staged_stat.st_dev,
                staged_stat.st_ino,
            ) or _file_identity_at(parent_fd, destination.name, expected_size) != (
                expected_size,
                expected_sha256,
            ):
                raise ValueError("published archive bytes differ from validated bytes")
        if not _directory_binding_matches(destination.parent, parent_fd):
            raise OSError("archive parent changed during publication")

        os.unlink(staging_name, dir_fd=parent_fd)
        staging_name = None
        os.fsync(parent_fd)
        if (
            source_parent_fd >= 0
            and source_name is not None
            and source_inode is not None
        ):
            try:
                if _unlink_if_same_inode(source_parent_fd, source_name, source_inode):
                    os.fsync(source_parent_fd)
            except OSError:
                # The validated destination is already durable. Private source
                # cleanup is non-authoritative and cannot undo that commit.
                pass
        return identity
    except BaseException:
        if published and staging_fd >= 0:
            try:
                final_stat = os.stat(
                    destination.name, dir_fd=parent_fd, follow_symlinks=False
                )
                staged_stat = os.fstat(staging_fd)
                if (final_stat.st_dev, final_stat.st_ino) == (
                    staged_stat.st_dev,
                    staged_stat.st_ino,
                ):
                    os.unlink(destination.name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        if staging_name is not None:
            try:
                os.unlink(staging_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        if source_parent_fd >= 0:
            os.close(source_parent_fd)
        os.close(parent_fd)


def _copy_and_hash_file(
    source_fd: int, destination_fd: int | None = None
) -> ArchiveContentIdentity:
    """
    Copy and hash file.

    After applying local validation, the function forwards ``source_fd`` and
    ``destination_fd`` to ``ArchiveContentIdentity`` and preserves its return
    and exception contract. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        source_fd: Numeric source fd used while the operation performs bounded
            accounting.
        destination_fd: Optional destination fd; ``None`` selects the function's
            default behavior.

    Returns:
        An ``ArchiveContentIdentity`` representing copy and hash file.

    Raises:
        ValueError: If the archive staging source is not a nonempty regular
            file; or archive staging source changed while hashing.
    """
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise ValueError("archive staging source must be a nonempty regular file")
    digest = hashlib.sha256()
    prefix = b""
    total = 0
    while chunk := os.read(source_fd, 1024 * 1024):
        if not prefix:
            prefix = chunk[:512]
        digest.update(chunk)
        total += len(chunk)
        if destination_fd is not None:
            _write_all(destination_fd, chunk)
    after = os.fstat(source_fd)
    if total != before.st_size or any(
        getattr(before, field) != getattr(after, field) for field in _IDENTITY_FIELDS
    ):
        raise ValueError("archive staging source changed while hashing")
    appended_digest = digest.copy()
    appended_digest.update(b"[]")
    return ArchiveContentIdentity(
        total, digest.hexdigest(), appended_digest.hexdigest(), prefix
    )


def _read_diagnostic_file_at(
    parent_fd: int, name: str, limit: int
) -> tuple[bytes, _DiagnosticFileSnapshot]:
    """
    Read diagnostic file at.

    The implementation uses ``parent_fd``, ``name``, and ``limit`` to read
    diagnostic file at. Parsing or I/O must finish before the validated
    representation is made available to the caller. If the function cannot read
    diagnostic file at, its exception reaches the caller instead of being
    converted into a successful result. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        A tuple containing ``data`` and ``diagnostic file snapshot`` in that
        order.

    Raises:
        ValueError: If diagnostic history is not a bounded regular file;
            diagnostic history exceeds byte limit; or diagnostic history changed
            while reading.
    """
    descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > limit
        ):
            raise ValueError("diagnostic history is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, limit - total + 1)):
            total += len(chunk)
            if total > limit:
                raise ValueError("diagnostic history exceeds byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if total != before.st_size or any(
            getattr(before, field) != getattr(after, field)
            for field in _IDENTITY_FIELDS
        ):
            raise ValueError("diagnostic history changed while reading")
        data = b"".join(chunks)
        return data, _DiagnosticFileSnapshot(
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            hashlib.sha256(data).hexdigest(),
        )
    finally:
        os.close(descriptor)


def _atomic_write_bytes_at(
    parent_fd: int,
    name: str,
    data: bytes,
    *,
    expected: _DiagnosticFileSnapshot | None | object = _UNCONSTRAINED,
    binding_path: Path | None = None,
) -> None:
    """
    Atomically publish bytes through a directory-relative file descriptor.

    The implementation uses ``parent_fd``, ``name``, ``data``, ``expected``, and
    ``binding_path`` to atomically publish bytes through a directory-relative
    file descriptor. Filesystem effects remain confined to the caller-selected
    paths and the owning resource lifecycle. If the function cannot atomically
    publish bytes through a directory-relative file descriptor, its exception
    reaches the caller instead of being converted into a successful result.
    Cleanup in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        data: Bounded byte sequence supplied as data.
        expected: Optional expected; ``None`` selects the function's default
            behavior.
        binding_path: Optional filesystem location used as the binding path for
            this operation.

    Raises:
        ValueError: If the diagnostic destination is not a regular file.
        OSError: If diagnostic parent changed during publication.
        RuntimeError: If archive receipt history changed before commit.
    """
    existing_mode: int | None = None
    if isinstance(expected, _DiagnosticFileSnapshot):
        existing_mode = stat.S_IMODE(expected.mode)
    elif expected is _UNCONSTRAINED:
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(current.st_mode):
                raise ValueError("diagnostic destination must be a regular file")
            existing_mode = stat.S_IMODE(current.st_mode)

    staging_fd, staging_name = _create_staging_file(parent_fd)
    try:
        if existing_mode is not None:
            os.fchmod(staging_fd, existing_mode)
        _write_all(staging_fd, data)
        os.fsync(staging_fd)
        if binding_path is not None and not _directory_binding_matches(
            binding_path, parent_fd
        ):
            raise OSError("diagnostic parent changed during publication")
        if expected is None:
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("archive receipt history changed before commit")
        elif isinstance(expected, _DiagnosticFileSnapshot):
            try:
                _, current = _read_diagnostic_file_at(parent_fd, name, expected.size)
            except (FileNotFoundError, OSError, ValueError):
                raise RuntimeError(
                    "archive receipt history changed before commit"
                ) from None
            if current != expected:
                raise RuntimeError("archive receipt history changed before commit")
        os.replace(
            staging_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        staging_name = ""
        os.fsync(parent_fd)
        if binding_path is not None and not _directory_binding_matches(
            binding_path, parent_fd
        ):
            raise OSError("diagnostic parent changed during publication")
    finally:
        os.close(staging_fd)
        if staging_name:
            try:
                os.unlink(staging_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass


def _create_staging_file(parent_fd: int) -> tuple[int, str]:
    """
    Create staging file.

    The implementation uses ``parent_fd`` to create staging file. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot create staging file, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.

    Returns:
        A tuple containing ``open`` and ``name`` in that order.

    Raises:
        FileExistsError: If unable to reserve archive publication staging file.
    """
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _attempt in range(128):
        name = f".nvdebug-publish-{secrets.token_hex(16)}.tmp"
        try:
            return os.open(name, flags, 0o600, dir_fd=parent_fd), name
        except FileExistsError:
            continue
    raise FileExistsError("unable to reserve archive publication staging file")


def _write_all(descriptor: int, data: bytes) -> None:
    """
    Write all.

    The implementation uses ``descriptor`` and ``data`` to write all. Success is
    reported only after the owning output boundary has completed its required
    write or publication step. If the function cannot write all, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        data: Bounded byte sequence supplied as data.

    Raises:
        OSError: If short write while staging archive publication.
    """
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while staging archive publication")
        view = view[written:]


def _file_identity_at(parent_fd: int, name: str, limit: int) -> tuple[int, str]:
    """
    Return the file identity at.

    The implementation uses ``parent_fd``, ``name``, and ``limit`` to produce
    the file identity at. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. If the function
    cannot produce the file identity at, its exception reaches the caller
    instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        A tuple containing ``total`` and ``hexdigest`` in that order.

    Raises:
        ValueError: If archive artifact is not a bounded regular file; top-level
            artifact exceeds ``limit`` bytes; or artifact changed while its
            identity was captured.
    """
    descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("archive artifact is not a bounded regular file")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, limit - total + 1)):
            total += len(chunk)
            if total > limit:
                raise ValueError(f"top-level artifact exceeds {limit} bytes")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if total != before.st_size or any(
            getattr(before, field) != getattr(after, field)
            for field in _IDENTITY_FIELDS
        ):
            raise ValueError("artifact changed while its identity was captured")
        return total, digest.hexdigest()
    finally:
        os.close(descriptor)


def _open_directory_nofollow(path: Path, *, create: bool = False) -> int:
    """
    Open directory nofollow.

    The implementation uses ``path`` and ``create`` to open directory nofollow.

    Args:
        path: filesystem location used as the path for this operation.
        create: Whether create is enabled or required for this operation.

    Returns:
        The validated ``descriptor``.
    """
    absolute = Path(os.path.abspath(os.fspath(path)))
    descriptor = os.open(os.sep, _DIRECTORY_FLAGS)
    try:
        for part in absolute.parts[1:]:
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o755, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directory_binding_matches(path: Path, descriptor: int) -> bool:
    """
    Return the directory binding matches.

    The implementation uses ``path`` and ``descriptor`` to produce the directory
    binding matches. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.

    Returns:
        Whether the directory binding matches operation succeeds.
    """
    try:
        current_fd = _open_directory_nofollow(path)
    except OSError:
        return False
    try:
        expected = os.fstat(descriptor)
        current = os.fstat(current_fd)
        return (expected.st_dev, expected.st_ino) == (current.st_dev, current.st_ino)
    finally:
        os.close(current_fd)


def _unlink_if_same_inode(parent_fd: int, name: str, identity: tuple[int, int]) -> bool:
    """
    Remove if same inode.

    The implementation uses ``parent_fd``, ``name``, and ``identity`` to remove
    if same inode.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        identity: Entries supplied as ``identity`` without transferring
            container ownership.

    Returns:
        Whether the remove if same inode operation succeeds.
    """
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
        os.unlink(name, dir_fd=parent_fd)
        return True
    return False
