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
Zip utilities for NVDebug Tool.

Implements zip archiving, splitting, and skip functionality with support for
large files and sanitized naming.
"""

import hashlib
import json
import logging
import math
import os
import re
import secrets
import shutil  # noqa: F401 - retained for compatibility with existing test hooks
import stat
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator, Optional, Sequence, Union

from ..utils.filesystem_identity import filesystem_owner_uid

from ..config import MIN_ZIP_SPLIT_THRESHOLD_MB
from ..core.finalization_receipt import (
    CONTROL_FLOW_EXCEPTIONS,
    select_authoritative_exception,
)
from ..core.run_result import EXPLICIT_SELECTION_EVIDENCE_PATH
from .archive_member_policy import has_unsafe_member_characters
from .bounded_archive import (
    ArchiveLimits,
    ArchivePolicyError,
    extract_open_zip,
    resolve_archive_creation_limits,
    validate_open_zip_stream_for_creation,
)
from .cpu_resources import available_cpus
from .parallel_deflate import MAX_DEFLATE_WORKERS, parallel_zip_compression

logger = logging.getLogger(__name__)

MAX_SPLIT_ARCHIVE_PARTS = 4096
MAX_REQUIRED_ARCHIVE_MEMBER_DIGESTS = 4096
MAX_ARCHIVE_MEMBER_PATH_BYTES = 1024
MAX_ARCHIVE_MEMBER_COMPONENT_BYTES = 255
MAX_REQUIRED_ARCHIVE_PATH_MATERIAL_BYTES = 2 * 1024 * 1024
MAX_REQUIRED_ARCHIVE_MEMBER_SIZE_BYTES = 32 * 1024 * 1024
MAX_FINAL_ARCHIVE_ARTIFACTS = 4096
MAX_FINAL_ARCHIVE_PATH_BYTES = 4096
MAX_ARCHIVE_NAME_BYTES = 200
MAX_BUNDLE_METADATA_BYTES = 1024 * 1024
_PRIVATE_ARCHIVE_MODE = 0o600
_SHARED_READ_ARCHIVE_MODE = 0o755
_SHARED_READ_ARCHIVE_MEMBER_MODE = 0o755
_PRIVATE_LOOSE_DIRECTORY_MODE = 0o700
_SHARED_READ_LOOSE_DIRECTORY_MODE = 0o755

ArchiveMemberDigest = tuple[str, int, str]
SnapshotLeafDigest = ArchiveMemberDigest
ArchiveArtifactDigest = tuple[str, int, str]
ArchiveEvidenceSink = Callable[[tuple[ArchiveArtifactDigest, ...]], None]
ArchiveProgressCallback = Callable[[str, Optional[int], Optional[int]], None]


def _published_bundle_file_mode(
    relative_path: str, shared_mode: int = _SHARED_READ_ARCHIVE_MODE
) -> int:
    """
    Select final file permissions without exposing owner-private evidence.

    Normal sanitized reports and logs are shared-readable. The canonical
    selection-failure record retains the private mode required by its contract,
    both in loose output and in the permission metadata of a delivered ZIP.

    Args:
        relative_path: Validated POSIX file path relative to the bundle root.
        shared_mode: Validated publication mode for ordinary completed files.

    Returns:
        ``0600`` for selection evidence and the selected mode for other files.
    """

    if relative_path == EXPLICIT_SELECTION_EVIDENCE_PATH:
        return _PRIVATE_ARCHIVE_MODE
    return shared_mode


def _validated_archive_member_mode(value: Optional[int]) -> Optional[int]:
    """
    Validate the optional mode recorded for regular members in a final ZIP.

    Sanitized delivery uses 0755 for completed files. The historical 0644
    override remains available to direct callers. Neither policy grants write
    access to another account; all other overrides fail before archive mutation.

    Args:
        value: Optional permission bits requested for every regular member.

    Returns:
        ``None`` for source-mode preservation or the exact shared-read mode.

    Raises:
        ValueError: If ``value`` is not the reviewed shared-read mode.
    """

    if value is None:
        return None
    if type(value) is not int or value not in {0o644, _SHARED_READ_ARCHIVE_MEMBER_MODE}:
        raise ValueError("Archive member permission mode is invalid")
    return value


def _emit_archive_progress(
    progress_callback: Optional[ArchiveProgressCallback],
    description: str,
    completed: Optional[int] = None,
    total: Optional[int] = None,
) -> None:
    """
    Emit one best-effort archive progress update.

    Archive creation, verification, and publication remain authoritative when
    presentation code is absent or defective. Descriptions contain only static
    host-owned stage names; source paths and member names never cross this
    display boundary.

    Args:
        progress_callback: Optional presentation callback owned by the caller.
        description: Static operator-visible archive stage description.
        completed: Completed bytes or units for a determinate stage.
        total: Total bytes or units for a determinate stage.
    """

    if progress_callback is None:
        return
    try:
        progress_callback(description, completed, total)
    except Exception:
        # Presentation must never change archive transaction semantics.
        pass


@dataclass(frozen=True)
class _ArchiveSourceLeaf:
    """
    One source leaf and the identity approved during tree validation.

    The immutable record keeps ``path`` and ``identity`` together so consumers
    observe one archive source leaf state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        identity: Collection of identity entries retained by this record.
    """

    path: Path
    identity: tuple[int, ...]


@dataclass(frozen=True)
class _ArchiveSourceDirectory:
    """
    One source directory and the identity approved during tree validation.

    The immutable record keeps ``path`` and ``identity`` together so a later
    permission-only publication can bind each directory to the exact tree that
    passed the bounded, no-follow source walk.

    Attributes:
        path: Validated filesystem location associated with the directory.
        identity: Stable source identity captured during tree validation.
    """

    path: Path
    identity: tuple[int, ...]


@dataclass(frozen=True)
class _OwnedArchiveLeaf:
    """
    A staging or published leaf owned by this archive transaction.

    The immutable record keeps ``path``, ``device``, and ``inode`` together so
    consumers observe one owned archive leaf state. Consumers receive the fields
    as one unit instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        device: Numeric device retained by this record.
        inode: Numeric inode retained by this record.
    """

    path: Path
    device: int
    inode: int


@dataclass(frozen=True)
class _OwnedArchiveSourceRoot:
    """
    The exact loose run root authorized for bounded post-publication removal.

    The immutable record keeps ``path``, ``device``, ``inode``,
    ``parent_device``, and ``parent_inode`` together so consumers observe one
    owned archive source root state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        device: Numeric device retained by this record.
        inode: Numeric inode retained by this record.
        parent_device: Numeric parent device retained by this record.
        parent_inode: Numeric parent inode retained by this record.
    """

    path: Path
    device: int
    inode: int
    parent_device: int
    parent_inode: int


def _has_exact_type(value: object, expected_type: type) -> bool:
    """
    Reject subclasses in security-boundary archive evidence.

    The implementation uses ``value`` and ``expected_type`` to reject subclasses
    in security-boundary archive evidence. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        value: Value whose exact runtime type is inspected without accepting
            subclasses.
        expected_type: Exact runtime type required for ``value``.

    Returns:
        Whether the subclasses in security-boundary archive evidence operation
        succeeds.
    """

    return object.__getattribute__(value, "__class__") is expected_type


class ArchiveFinalizationError(Exception):
    """
    Compatibility error for pre-transactional archive implementations.

    Callers receive this exception when the archive finalization error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """

    def __init__(
        self,
        message: str,
        *,
        phase: str,
        verified_archive_paths: list[str] | None = None,
    ) -> None:
        """
        Initialize an ``ArchiveFinalizationError`` instance.

        The initializer records ``phase`` and ``verified_archive_paths`` for
        later operations and establishes the instance invariants before any
        public method runs.

        Args:
            message: Operator-facing text carried by the reported event or
                failure.
            phase: Text supplied as phase in the format accepted by this
                function.
            verified_archive_paths: Filesystem locations processed in
                caller-provided order.
        """
        super().__init__(message)
        self.phase = phase
        self.verified_archive_paths = tuple(verified_archive_paths or ())

    @property
    def verified_archive_retained(self) -> bool:
        """
        Whether a verified archive representation survived the failure.

        Each access computes the value from ``verified_archive_paths`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            Whether the whether a verified archive representation survived the
            failure operation succeeds.
        """

        return bool(self.verified_archive_paths)


class ArchiveValidationError(ArchiveFinalizationError, ValueError):
    """
    The source tree or produced archive failed validation.

    Callers receive this exception when the archive validation error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


class ArchiveOperationError(ArchiveFinalizationError, OSError):
    """
    An archive or filesystem operation failed.

    Callers receive this exception when the archive operation error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


def _fsync_file(path: str | Path) -> None:
    """
    Flush a completed archive file to durable storage.

    The implementation uses ``path`` to flush a completed archive file to
    durable storage. Filesystem effects remain confined to the caller-selected
    paths and the owning resource lifecycle.

    Args:
        path: filesystem location used as the path for this operation.
    """

    with open(path, "rb") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: str | Path) -> None:
    """
    Flush directory-entry changes to durable storage.

    The implementation uses ``path`` to flush directory-entry changes to durable
    storage. Filesystem effects remain confined to the caller-selected paths and
    the owning resource lifecycle. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.
    """

    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _normalize_expected_leaf_digests(
    expected_snapshot_leaf_digests: Optional[Sequence[ArchiveMemberDigest]],
) -> dict[str, tuple[int, str]]:
    """
    Return validated receipt-bound leaf evidence keyed by relative path.

    The implementation uses ``expected_snapshot_leaf_digests`` to produce
    validated receipt-bound leaf evidence keyed by relative path. If the
    function cannot produce validated receipt-bound leaf evidence keyed by
    relative path, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        expected_snapshot_leaf_digests: Entries supplied as
            ``expected_snapshot_leaf_digests`` without transferring container
            ownership.

    Returns:
        A mapping containing expected leaf digests.

    Raises:
        ValueError: If expected snapshot leaf digests are malformed; too many
            required archive member digests; expected snapshot leaf path is
            malformed; or expected snapshot leaf path is unsafe; or another
            input invariant is violated.
    """

    if expected_snapshot_leaf_digests is None:
        return {}
    if isinstance(expected_snapshot_leaf_digests, (str, bytes)):
        raise ValueError("Expected snapshot leaf digests are malformed")

    normalized: dict[str, tuple[int, str]] = {}
    path_material_bytes = 0
    for item in expected_snapshot_leaf_digests:
        if len(normalized) >= MAX_REQUIRED_ARCHIVE_MEMBER_DIGESTS:
            raise ValueError("Too many required archive member digests")
        if not isinstance(item, tuple):
            raise ValueError("Expected snapshot leaf digests are malformed")
        if tuple.__len__(item) != 3:
            raise ValueError("Expected snapshot leaf digests are malformed")
        relative_path = tuple.__getitem__(item, 0)
        expected_size = tuple.__getitem__(item, 1)
        expected_sha256 = tuple.__getitem__(item, 2)
        if (
            not isinstance(relative_path, str)
            or not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
            or expected_size > MAX_REQUIRED_ARCHIVE_MEMBER_SIZE_BYTES
            or not isinstance(expected_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        ):
            raise ValueError("Expected snapshot leaf digests are malformed")
        try:
            relative_path_bytes = str.encode(relative_path, "utf-8")
        except UnicodeError as error:
            raise ValueError("Expected snapshot leaf path is malformed") from error
        path = PurePosixPath(relative_path)
        if (
            not relative_path
            or not relative_path.isprintable()
            or len(relative_path_bytes) > MAX_ARCHIVE_MEMBER_PATH_BYTES
            or "\\" in relative_path
            or path.is_absolute()
            or path.as_posix() != relative_path
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("Expected snapshot leaf path is unsafe")
        try:
            component_bytes = tuple(len(part.encode("utf-8")) for part in path.parts)
        except UnicodeError as error:
            raise ValueError("Expected snapshot leaf path is malformed") from error
        if any(
            not component_size or component_size > MAX_ARCHIVE_MEMBER_COMPONENT_BYTES
            for component_size in component_bytes
        ):
            raise ValueError("Expected snapshot leaf path component is too large")
        path_material_bytes += len(relative_path_bytes)
        if path_material_bytes > MAX_REQUIRED_ARCHIVE_PATH_MATERIAL_BYTES:
            raise ValueError("Required archive member path material is too large")
        if relative_path in normalized:
            raise ValueError("Expected snapshot leaf path is duplicated")
        normalized[relative_path] = (expected_size, expected_sha256)
    return normalized


def _required_member_digest_map(
    expected_snapshot_leaf_digests: Optional[Sequence[ArchiveMemberDigest]],
    required_member_digests: Optional[Sequence[ArchiveMemberDigest]],
) -> dict[str, tuple[int, str]]:
    """
    Merge mandatory receipt leaves with bounded additional immutable members.

    The implementation uses ``expected_snapshot_leaf_digests`` and
    ``required_member_digests`` to merge mandatory receipt leaves with bounded
    additional immutable members. If the function cannot merge mandatory receipt
    leaves with bounded additional immutable members, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        expected_snapshot_leaf_digests: Entries supplied as
            ``expected_snapshot_leaf_digests`` without transferring container
            ownership.
        required_member_digests: Entries supplied as ``required_member_digests``
            without transferring container ownership.

    Returns:
        A mapping containing required member digest map.

    Raises:
        ValueError: If required archive member digest path overlaps receipt
            evidence; too many required archive member digests; or required
            archive member path material is too large.
    """

    snapshot_digests = _normalize_expected_leaf_digests(expected_snapshot_leaf_digests)
    additional_digests = _normalize_expected_leaf_digests(required_member_digests)
    overlap = set(snapshot_digests).intersection(additional_digests)
    if overlap:
        raise ValueError(
            "Required archive member digest path overlaps receipt evidence"
        )
    if (
        len(snapshot_digests) + len(additional_digests)
        > MAX_REQUIRED_ARCHIVE_MEMBER_DIGESTS
    ):
        raise ValueError("Too many required archive member digests")
    if (
        sum(len(path.encode("utf-8")) for path in snapshot_digests)
        + sum(len(path.encode("utf-8")) for path in additional_digests)
        > MAX_REQUIRED_ARCHIVE_PATH_MATERIAL_BYTES
    ):
        raise ValueError("Required archive member path material is too large")
    return {**snapshot_digests, **additional_digests}


def _verify_zip_archive(
    zip_path: str | Path,
    expected_root: str,
    *,
    expected_snapshot_leaf_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    required_member_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    limits: Optional[ArchiveLimits] = None,
) -> None:
    """
    Reopen a completed ZIP and validate integrity, root, and receipt leaves.

    Validate every member's bytes and CRC through the shared finite policy on
    this exact inode. The standard whole-archive helper inflates members without
    aggregate or elapsed-time caps.

    Args:
        zip_path: filesystem location used as the ZIP path for this operation.
        expected_root: filesystem location used as the expected root for this
            operation.
        expected_snapshot_leaf_digests: Optional expected snapshot leaf digests;
            ``None`` selects the function's default behavior.
        required_member_digests: Optional required member digests; ``None``
            selects the function's default behavior.
        limits: Optional Limits governing reopen a completed ZIP and validate
            integrity, root, and receipt leaves.

    Raises:
        ValueError: If ZIP changed during bounded integrity validation; ZIP
            semantic verification deadline exceeded; ZIP contains unsafe member
            path: ``filename``; or ZIP contains duplicate member path: ``name``;
            or another input invariant is violated.
    """

    active_limits = resolve_archive_creation_limits(limits)
    deadline = time.monotonic() + active_limits.max_seconds
    expected_digests = _required_member_digest_map(
        expected_snapshot_leaf_digests,
        required_member_digests,
    )
    verified_expected: set[str] = set()
    seen: set[str] = set()
    roots: set[str] = set()
    normalized, descriptor, before = _open_archive_artifact(zip_path)
    try:
        os.fsync(descriptor)
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            # Validate every member's bytes and CRC through the shared finite
            # policy on this exact inode.  The standard whole-archive helper
            # inflates members without aggregate or elapsed-time caps.
            validate_open_zip_stream_for_creation(handle, limits=active_limits)
            if _archive_artifact_identity(os.fstat(descriptor)) != (
                _archive_artifact_identity(before)
            ):
                raise ValueError("ZIP changed during bounded integrity validation")

            handle.seek(0)
            with zipfile.ZipFile(handle, "r") as archive:
                for info in archive.infolist():
                    if time.monotonic() > deadline:
                        raise ValueError("ZIP semantic verification deadline exceeded")
                    # A backslash is refused, not folded into a separator:
                    # the shared policy rejects it at every producer, so a name
                    # carrying one here means the member was never validated.
                    if has_unsafe_member_characters(info.filename):
                        raise ValueError(
                            f"ZIP contains unsafe member path: {info.filename!r}"
                        )
                    name = info.filename.rstrip("/")
                    if not name:
                        continue
                    path = PurePosixPath(name)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or any(part in {"", "."} for part in path.parts)
                    ):
                        raise ValueError(
                            f"ZIP contains unsafe member path: {info.filename}"
                        )
                    if name in seen:
                        raise ValueError(f"ZIP contains duplicate member path: {name}")
                    seen.add(name)
                    roots.add(path.parts[0])
                    mode = (info.external_attr >> 16) & 0xFFFF
                    if stat.S_ISLNK(mode):
                        raise ValueError(f"ZIP contains symbolic-link member: {name}")

                    if path.parts[0] != expected_root or len(path.parts) < 2:
                        continue
                    relative_path = PurePosixPath(*path.parts[1:]).as_posix()
                    expected = expected_digests.get(relative_path)
                    if expected is None:
                        continue
                    expected_size, expected_sha256 = expected
                    digest = hashlib.sha256()
                    actual_size = 0
                    with archive.open(info, "r") as member:
                        for chunk in iter(lambda: member.read(1024 * 1024), b""):
                            if time.monotonic() > deadline:
                                raise ValueError(
                                    "ZIP semantic verification deadline exceeded"
                                )
                            actual_size += len(chunk)
                            if actual_size > expected_size:
                                raise ValueError(
                                    "ZIP authoritative snapshot member exceeds "
                                    f"receipt size: {relative_path}"
                                )
                            digest.update(chunk)
                    if (
                        actual_size != expected_size
                        or info.file_size != expected_size
                        or digest.hexdigest() != expected_sha256
                    ):
                        raise ValueError(
                            "ZIP authoritative snapshot member differs from receipt: "
                            f"{relative_path}"
                        )
                    verified_expected.add(relative_path)

        after = os.fstat(descriptor)
        visible = normalized.lstat()
        if _archive_artifact_identity(after) != _archive_artifact_identity(
            before
        ) or _archive_artifact_identity(visible) != _archive_artifact_identity(before):
            raise ValueError("ZIP changed during semantic verification")
    finally:
        os.close(descriptor)

    if roots != {expected_root}:
        raise ValueError(
            f"ZIP must contain exactly root {expected_root!r}; found {sorted(roots)}"
        )
    missing = set(expected_digests).difference(verified_expected)
    if missing:
        raise ValueError(
            "ZIP is missing authoritative snapshot member(s): "
            + ", ".join(sorted(missing))
        )


def _file_digest(path: str | Path) -> bytes:
    """
    Return the file digest.

    After applying local validation, the function forwards ``path`` to
    ``digest.digest`` and preserves its return and exception contract.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The bounded file digest.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def _verify_raw_parts(
    zip_path: str | Path,
    part_files: list[str],
    *,
    expected_part_names: Optional[Sequence[str]] = None,
    verify_names: bool = True,
) -> None:
    """
    Prove lexical part concatenation is byte-identical to the verified ZIP.

    The implementation uses ``zip_path``, ``part_files``, and
    ``expected_part_names`` to prove lexical part concatenation is
    byte-identical to the verified ZIP. Filesystem effects remain confined to
    the caller-selected paths and the owning resource lifecycle. If the function
    cannot prove lexical part concatenation is byte-identical to the verified
    ZIP, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        zip_path: filesystem location used as the ZIP path for this operation.
        part_files: Entries supplied as ``part_files`` without transferring
            container ownership.
        expected_part_names: Optional expected part names; ``None`` selects the
            function's default behavior.
        verify_names: Whether the visible part leaf names must match the
            expected contiguous sequence. Private randomized staging leaves
            disable this check until publication.

    Raises:
        ValueError: If archive splitting produced no parts; archive parts are
            not contiguous: expected ``expected_names``, got ``actual_names``;
            or archive parts do not reconstruct the verified ZIP.
    """

    if not part_files:
        raise ValueError("Archive splitting produced no parts")
    expected = _file_digest(zip_path)
    combined = hashlib.sha256()
    part_width = max(3, len(str(len(part_files))))
    if expected_part_names is None:
        expected_names = [
            f"{Path(zip_path).name}.part{index:0{part_width}d}"
            for index in range(1, len(part_files) + 1)
        ]
    else:
        expected_names = list(expected_part_names)
    actual_names = [Path(path).name for path in part_files]
    if len(expected_names) != len(part_files) or (
        verify_names and actual_names != expected_names
    ):
        raise ValueError(
            f"Archive parts are not contiguous: expected {expected_names}, "
            f"got {actual_names}"
        )
    for part in part_files:
        _fsync_file(part)
        with open(part, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                combined.update(chunk)
    if combined.digest() != expected:
        raise ValueError("Archive parts do not reconstruct the verified ZIP")


def _archive_artifact_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """
    Return the stable identity used while binding one finalized archive.

    The implementation uses ``metadata`` to produce the stable identity used
    while binding one finalized archive.

    Args:
        metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing
            stable identity used while binding one finalized archive.

    Returns:
        A tuple containing ``st dev``, ``st ino``, ``st mode``, ``st nlink``,
        ``st size``, ``st mtime ns``, and ``st ctime ns`` in that order.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _source_leaf_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """
    Return the identity frozen before any archive member is opened.

    The implementation uses ``metadata`` to produce the identity frozen before
    any archive member is opened.

    Args:
        metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing
            identity frozen before any archive member is opened.

    Returns:
        A tuple containing ``st dev``, ``st ino``, ``st mode``, ``st nlink``,
        ``st size``, ``st mtime ns``, and ``st ctime ns`` in that order.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _normalized_archive_artifact_path(path: str | Path) -> Path:
    """
    Return one bounded absolute archive path without resolving symlinks.

    The implementation uses ``path`` to produce one bounded absolute archive
    path without resolving symlinks. If the function cannot produce one bounded
    absolute archive path without resolving symlinks, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The validated ``normalized``.

    Raises:
        ValueError: If final archive artifact path is malformed.
    """

    try:
        normalized = Path(os.path.abspath(os.fspath(path)))
        encoded = os.fspath(normalized).encode("utf-8")
    except (TypeError, UnicodeError) as error:
        raise ValueError("Final archive artifact path is malformed") from error
    if (
        not encoded
        or len(encoded) > MAX_FINAL_ARCHIVE_PATH_BYTES
        or not os.fspath(normalized).isprintable()
    ):
        raise ValueError("Final archive artifact path is malformed")
    return normalized


def _open_archive_artifact(
    path: str | Path,
) -> tuple[Path, int, os.stat_result]:
    """
    Open and identity-check one protected archive without following links.

    The implementation uses ``path`` to open and identity-check one protected
    archive without following links. If the function cannot open and
    identity-check one protected archive without following links, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        A tuple containing ``normalized``, ``descriptor``, and ``before`` in
        that order.

    Raises:
        RuntimeError: If final archive binding lacks no-follow file access.
        ValueError: If final archive artifact is not a protected regular file:
            ``name``.
    """

    normalized = _normalized_archive_artifact_path(path)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("Final archive binding requires no-follow file access")
    flags = os.O_RDONLY | no_follow
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)

    descriptor = os.open(normalized, flags)
    try:
        before = os.fstat(descriptor)
        visible = normalized.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode)
            not in {_PRIVATE_ARCHIVE_MODE, 0o644, _SHARED_READ_ARCHIVE_MODE}
            or not stat.S_ISREG(visible.st_mode)
            or visible.st_nlink != 1
            or stat.S_IMODE(visible.st_mode)
            not in {_PRIVATE_ARCHIVE_MODE, 0o644, _SHARED_READ_ARCHIVE_MODE}
            or _archive_artifact_identity(before) != _archive_artifact_identity(visible)
        ):
            raise ValueError(
                "Final archive artifact is not a protected regular file: "
                f"{normalized.name}"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return normalized, descriptor, before


def publish_archive_artifacts_shared_read(
    archive_paths: Sequence[str | Path],
) -> tuple[Path, ...]:
    """
    Make finalized explicit-output archives readable but never shared-writable.

    All archive inodes are opened without following links and pinned before any
    permission changes begin. The function accepts only transaction-produced
    ``0600`` files, historical ``0644`` publications, or an idempotent ``0755``
    replay. It publishes ``0755`` and verifies identity, ownership, size, and
    modification time after publication. A failed multi-part transition is
    rolled back to each part's original protected mode.

    Args:
        archive_paths: Final single or split archive artifacts selected for
            read-only report-server publication.

    Returns:
        Canonical paths to the verified shared-read archive artifacts.

    Raises:
        RuntimeError: If no-follow file access is unavailable.
        ValueError: If the target set is empty, too large, replaced, not owned
            by the effective user, or does not have a protected archive mode.
        OSError: If descriptor, permission, or durability operations fail.
    """

    if isinstance(archive_paths, (str, bytes, Path)):
        raise ValueError("Final archive artifact targets are malformed")
    paths = tuple(_normalized_archive_artifact_path(path) for path in archive_paths)
    if (
        not paths
        or len(paths) > MAX_FINAL_ARCHIVE_ARTIFACTS
        or len(set(paths)) != len(paths)
    ):
        raise ValueError("Final archive artifact targets are malformed")

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("Shared-read archive publication requires no-follow access")
    flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    opened: list[tuple[Path, int, os.stat_result, int]] = []
    changed: list[tuple[int, int]] = []
    try:
        for path in paths:
            descriptor = os.open(path, flags)
            try:
                before = os.fstat(descriptor)
                visible = path.lstat()
                owner_uid = filesystem_owner_uid(
                    path.parent, observed_uid=before.st_uid
                )
                mode = stat.S_IMODE(before.st_mode)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != owner_uid
                    or before.st_nlink != 1
                    or mode
                    not in {_PRIVATE_ARCHIVE_MODE, 0o644, _SHARED_READ_ARCHIVE_MODE}
                    or _archive_artifact_identity(before)
                    != _archive_artifact_identity(visible)
                ):
                    raise ValueError(
                        "Final archive artifact is not eligible for shared-read "
                        f"publication: {path.name}"
                    )
            except BaseException:
                os.close(descriptor)
                raise
            opened.append((path, descriptor, before, mode))

        for _path, descriptor, _before, original_mode in opened:
            if original_mode == _SHARED_READ_ARCHIVE_MODE:
                continue
            os.fchmod(descriptor, _SHARED_READ_ARCHIVE_MODE)
            os.fsync(descriptor)
            changed.append((descriptor, original_mode))

        for path, descriptor, before, _original_mode in opened:
            after = os.fstat(descriptor)
            visible = path.lstat()
            if (
                not stat.S_ISREG(after.st_mode)
                or after.st_uid != before.st_uid
                or after.st_nlink != 1
                or stat.S_IMODE(after.st_mode) != _SHARED_READ_ARCHIVE_MODE
                or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                or _archive_artifact_identity(after)
                != _archive_artifact_identity(visible)
            ):
                raise ValueError(
                    "Shared-read archive artifact changed during publication: "
                    f"{path.name}"
                )
        for parent in {path.parent for path in paths}:
            _fsync_directory(parent)
        return paths
    except BaseException as error:
        rollback_errors: list[BaseException] = []
        for descriptor, original_mode in reversed(changed):
            try:
                os.fchmod(descriptor, original_mode)
                os.fsync(descriptor)
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)
        authoritative = select_authoritative_exception([error, *rollback_errors])
        raise authoritative
    finally:
        for _path, descriptor, _before, _mode in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _digest_archive_artifact(path: str | Path) -> ArchiveArtifactDigest:
    """
    Hash one protected regular archive while pinning its exact visible inode.

    The implementation uses ``path`` to hash one protected regular archive while
    pinning its exact visible inode.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        An ``ArchiveArtifactDigest`` representing digest archive artifact.
    """

    return issue_archive_artifact_digests((path,))[0]


def _digest_open_archive_artifact(
    normalized: Path,
    descriptor: int,
    before: os.stat_result,
) -> ArchiveArtifactDigest:
    """
    Hash one already-pinned archive descriptor.

    The implementation uses ``normalized``, ``descriptor``, and ``before`` to
    hash one already-pinned archive descriptor. If the function cannot hash one
    already-pinned archive descriptor, its exception reaches the caller instead
    of being converted into a successful result.

    Args:
        normalized: filesystem location used as the normalized for this
            operation.
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        before: Before object whose ``st_size`` state is read while performing
            hash one already-pinned archive descriptor.

    Returns:
        A tuple containing ``fspath``, ``st size``, and ``hexdigest`` in that
        order.

    Raises:
        ValueError: If final archive artifact changed while hashing: ``name``.
    """

    digest = hashlib.sha256()
    bytes_read = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    for chunk in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
        bytes_read += len(chunk)
        digest.update(chunk)
    after = os.fstat(descriptor)
    if (
        _archive_artifact_identity(before) != _archive_artifact_identity(after)
        or bytes_read != before.st_size
    ):
        raise ValueError(
            f"Final archive artifact changed while hashing: {normalized.name}"
        )
    return os.fspath(normalized), before.st_size, digest.hexdigest()


def validate_archive_artifact_digests(
    digests: object,
    archive_paths: Optional[Sequence[str | Path]] = None,
) -> tuple[ArchiveArtifactDigest, ...]:
    """
    Validate bounded whole-archive evidence and its exact target ordering.

    The implementation uses ``digests`` and ``archive_paths`` to validate
    bounded whole-archive evidence and its exact target ordering. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        digests: Entries supplied as ``digests`` and processed in
            caller-provided order.
        archive_paths: Optional filesystem location used as the archive paths
            for this operation.

    Returns:
        The validated ``result``.

    Raises:
        ValueError: If final archive artifact evidence is malformed; final
            archive artifact targets are malformed; or final archive artifact
            targets differ from the receipt.
    """

    if type(digests) is not tuple:
        raise ValueError("Final archive artifact evidence is malformed")
    if not digests or len(digests) > MAX_FINAL_ARCHIVE_ARTIFACTS:
        raise ValueError("Final archive artifact evidence is malformed")

    normalized: list[ArchiveArtifactDigest] = []
    seen_paths: set[str] = set()
    for item in digests:
        if type(item) is not tuple or tuple.__len__(item) != 3:
            raise ValueError("Final archive artifact evidence is malformed")
        path_value = tuple.__getitem__(item, 0)
        size_value = tuple.__getitem__(item, 1)
        sha256_value = tuple.__getitem__(item, 2)
        if (
            not _has_exact_type(path_value, str)
            or not _has_exact_type(size_value, int)
            or size_value < 0
            or not _has_exact_type(sha256_value, str)
            or re.fullmatch(r"[0-9a-f]{64}", sha256_value) is None
        ):
            raise ValueError("Final archive artifact evidence is malformed")
        normalized_path = os.fspath(_normalized_archive_artifact_path(path_value))
        if path_value != normalized_path or normalized_path in seen_paths:
            raise ValueError("Final archive artifact evidence is malformed")
        seen_paths.add(normalized_path)
        normalized.append((normalized_path, size_value, sha256_value))

    result = tuple(normalized)
    if archive_paths is not None:
        if isinstance(archive_paths, (str, bytes, Path)):
            raise ValueError("Final archive artifact targets are malformed")
        if len(archive_paths) > MAX_FINAL_ARCHIVE_ARTIFACTS:
            raise ValueError("Final archive artifact targets are malformed")
        expected_paths = tuple(
            os.fspath(_normalized_archive_artifact_path(path)) for path in archive_paths
        )
        if tuple(item[0] for item in result) != expected_paths:
            raise ValueError("Final archive artifact targets differ from the receipt")
    return result


def validate_archive_target_identity(
    bundle_root: str | Path,
    archive_paths: Sequence[str | Path],
) -> tuple[Path, ...]:
    """
    Require the exact normal or contiguous split ZIP names for one run root.

    The implementation uses ``bundle_root`` and ``archive_paths`` to require the
    exact normal or contiguous split ZIP names for one run root. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        bundle_root: filesystem location used as the bundle root for this
            operation.
        archive_paths: filesystem location used as the archive paths for this
            operation.

    Returns:
        The validated ``paths``.

    Raises:
        ValueError: If final archive artifact targets are malformed; final
            archive artifact target parent differs from the run; or final
            archive artifact targets differ from the run.
    """

    root = _normalized_archive_artifact_path(bundle_root)
    if isinstance(archive_paths, (str, bytes, Path)):
        raise ValueError("Final archive artifact targets are malformed")
    paths = tuple(_normalized_archive_artifact_path(path) for path in archive_paths)
    if not paths or len(paths) > MAX_FINAL_ARCHIVE_ARTIFACTS:
        raise ValueError("Final archive artifact targets are malformed")
    if any(path.parent != root.parent for path in paths):
        raise ValueError("Final archive artifact target parent differs from the run")

    archive_name = f"{root.name}.zip"
    if len(paths) == 1:
        expected_names = (archive_name,)
    else:
        width = max(3, len(str(len(paths))))
        expected_names = tuple(
            f"{archive_name}.part{index:0{width}d}"
            for index in range(1, len(paths) + 1)
        )
    if tuple(path.name for path in paths) != expected_names:
        raise ValueError("Final archive artifact targets differ from the run")
    return paths


def issue_archive_artifact_digests(
    archive_paths: Sequence[str | Path],
) -> tuple[ArchiveArtifactDigest, ...]:
    """
    Issue exact path, size, and SHA-256 evidence for completed archive files.

    Pin the complete representation before hashing any part. This makes the
    evidence a stable-set proof rather than a sequence of unrelated per-path
    observations.

    Args:
        archive_paths: filesystem location used as the archive paths for this
            operation.

    Returns:
        The issue archive artifact digests returned in operation-defined order.

    Raises:
        ValueError: If final archive artifact targets are malformed; or final
            archive artifact set changed while hashing: ``name``.
    """

    if isinstance(archive_paths, (str, bytes, Path)):
        raise ValueError("Final archive artifact targets are malformed")
    paths = tuple(archive_paths)
    if not paths or len(paths) > MAX_FINAL_ARCHIVE_ARTIFACTS:
        raise ValueError("Final archive artifact targets are malformed")
    opened: list[tuple[Path, int, os.stat_result]] = []
    try:
        # Pin the complete representation before hashing any part. This makes
        # the evidence a stable-set proof rather than a sequence of unrelated
        # per-path observations.
        for path in paths:
            opened.append(_open_archive_artifact(path))
        evidence = tuple(
            _digest_open_archive_artifact(normalized, descriptor, before)
            for normalized, descriptor, before in opened
        )
        for normalized, descriptor, before in opened:
            after = os.fstat(descriptor)
            visible_after = normalized.lstat()
            if _archive_artifact_identity(after) != _archive_artifact_identity(
                before
            ) or _archive_artifact_identity(
                visible_after
            ) != _archive_artifact_identity(
                before
            ):
                raise ValueError(
                    "Final archive artifact set changed while hashing: "
                    f"{normalized.name}"
                )
        return validate_archive_artifact_digests(evidence, paths)
    finally:
        for _normalized, descriptor, _before in opened:
            try:
                os.close(descriptor)
            except OSError:
                pass


def verify_archive_artifact_digests(
    archive_paths: Sequence[str | Path],
    expected_digests: object,
) -> tuple[Path, ...]:
    """
    Rehash exact delivery targets and reject any post-finalization change.

    After applying local validation, the function forwards ``archive_paths`` and
    ``expected_digests`` to ``tuple`` and preserves its return and exception
    contract.

    Args:
        archive_paths: filesystem location used as the archive paths for this
            operation.
        expected_digests: Expected digests consumed while the function attempts
            to rehash exact delivery targets and reject any post-finalization
            change.

    Returns:
        The verify archive artifact digests returned in operation-defined order.

    Raises:
        ValueError: If final archive artifact bytes differ from the receipt.
    """

    paths = tuple(archive_paths)
    expected = validate_archive_artifact_digests(expected_digests, paths)
    observed = issue_archive_artifact_digests(paths)
    if observed != expected:
        raise ValueError("Final archive artifact bytes differ from the receipt")
    return tuple(_normalized_archive_artifact_path(path) for path in paths)


def _issue_archive_evidence(
    archive_paths: Sequence[str | Path],
    archive_evidence_sink: Optional[ArchiveEvidenceSink],
) -> None:
    """
    Issue evidence at the verified ZIP boundary when a caller requested it.

    The implementation uses ``archive_paths`` and ``archive_evidence_sink`` to
    issue evidence at the verified ZIP boundary when a caller requested it.

    Args:
        archive_paths: filesystem location used as the archive paths for this
            operation.
        archive_evidence_sink: Archive evidence sink consumed while the function
            attempts to issue evidence at the verified ZIP boundary when a
            caller requested it.
    """

    if archive_evidence_sink is None:
        return
    archive_evidence_sink(issue_archive_artifact_digests(archive_paths))


def _write_zip_archive(
    zip_path: str | Path,
    directory: str | Path,
    archive_files: list[_ArchiveSourceLeaf] | list[Path],
    *,
    compression_level: int,
    expected_snapshot_leaf_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    required_member_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    archive_member_mode: Optional[int] = None,
    limits: Optional[ArchiveLimits] = None,
    progress_callback: Optional[ArchiveProgressCallback] = None,
    prepare_metadata: Optional[Callable[[int], list[_ArchiveSourceLeaf]]] = None,
) -> None:
    """
    Write files while validating receipt-bound source bytes as copied.

    The implementation uses ``zip_path``, ``directory``, ``archive_files``,
    ``compression_level``, and ``expected_snapshot_leaf_digests`` to write files
    while validating receipt-bound source bytes as copied. Success is reported
    only after the owning output boundary has completed its required write or
    publication step. If the function cannot write files while validating
    receipt-bound source bytes as copied, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        zip_path: filesystem location used as the ZIP path for this operation.
        directory: filesystem location used as the directory for this operation.
        archive_files: filesystem location used as the archive files for this
            operation.
        compression_level: Numeric compression level used while the operation
            performs bounded accounting.
        expected_snapshot_leaf_digests: Optional expected snapshot leaf digests;
            ``None`` selects the function's default behavior.
        required_member_digests: Optional required member digests; ``None``
            selects the function's default behavior.
        archive_member_mode: Optional sharing mode for regular ZIP members,
            retaining owner-private selection evidence and recording parent
            directories as 0755. ``None`` preserves source file modes.
        limits: Optional Limits governing files while validating receipt-bound
            source bytes as copied.
        progress_callback: Optional best-effort callback for aggregate byte
            progress while source leaves are compressed.
        prepare_metadata: Optional transaction-owned callback receiving the
            compressed byte count after ordinary files have been written. It
            may update lifecycle metadata and returns the validated metadata
            leaves to write last. Other source identities must remain fixed.

    Raises:
        ValueError: If ZIP creation deadline exceeded; archive source escaped
            its root: ``file_path``; archive source contains duplicate path:
            ``arcname``; or archive source contains duplicate authoritative
            path: ``relative_path``; or another input invariant is violated.
    """

    archive_member_mode = _validated_archive_member_mode(archive_member_mode)
    active_limits = resolve_archive_creation_limits(limits)
    deadline = time.monotonic() + active_limits.max_seconds
    root = Path(directory)
    expected_digests = _required_member_digest_map(
        expected_snapshot_leaf_digests,
        required_member_digests,
    )
    verified_expected: set[str] = set()
    seen_members: set[str] = set()
    approved_timestamps_ns = [
        (
            source_leaf.identity[5]
            if isinstance(source_leaf, _ArchiveSourceLeaf)
            else _source_leaf_identity(Path(source_leaf).lstat())[5]
        )
        for source_leaf in archive_files
    ]
    approved_sizes = [
        (
            source_leaf.identity[4]
            if isinstance(source_leaf, _ArchiveSourceLeaf)
            else _source_leaf_identity(Path(source_leaf).lstat())[4]
        )
        for source_leaf in archive_files
    ]
    total_source_bytes = sum(approved_sizes)
    progress_total = max(1, total_source_bytes)
    completed_source_bytes = 0
    normalized_timestamp_ns = (
        min(approved_timestamps_ns) if approved_timestamps_ns else None
    )
    _emit_archive_progress(
        progress_callback,
        "Compressing ZIP archive",
        0,
        progress_total,
    )

    def compression_order(
        archive: zipfile.ZipFile,
    ) -> Iterator[_ArchiveSourceLeaf | Path]:
        """
        Defer lifecycle metadata until the transaction knows the payload size.

        Ordinary ZIP writers retain their original ordering. The split writer
        can update only metadata after it observes a sufficient compressed
        size, avoiding a second compression of unchanged diagnostic payloads.

        Args:
            archive: Open private ZIP receiving the approved source leaves.

        Yields:
            Original ordinary leaves followed by the callback's validated
            metadata leaves, or the original sequence when no callback exists.

        Raises:
            ValueError: If the private ZIP is closed before metadata preparation.
            Exception: If the transaction rejects a metadata or source change.

        Side Effects:
            Invokes the owned metadata callback and adjusts byte progress for
            its updated metadata sizes. No compressed payload is rewritten.
        """

        nonlocal progress_total
        if prepare_metadata is None:
            yield from archive_files
            return
        original_metadata_bytes = 0
        for source_leaf, approved_size in zip(archive_files, approved_sizes):
            path = (
                source_leaf.path
                if isinstance(source_leaf, _ArchiveSourceLeaf)
                else Path(source_leaf)
            )
            if _is_bundle_metadata_path(path.relative_to(root).as_posix()):
                original_metadata_bytes += approved_size
            else:
                yield source_leaf
        if archive.fp is None:
            raise ValueError("ZIP closed before metadata preparation")
        metadata_leaves = prepare_metadata(archive.fp.tell())
        progress_total = max(
            1,
            total_source_bytes
            - original_metadata_bytes
            + sum(item.identity[4] for item in metadata_leaves),
        )
        yield from metadata_leaves

    compression_workers = min(MAX_DEFLATE_WORKERS, max(1, int(available_cpus())))
    with (
        ThreadPoolExecutor(
            max_workers=compression_workers, thread_name_prefix="nvdebug-archive"
        ) as compression_executor,
        zipfile.ZipFile(
            zip_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=compression_level,
        ) as archive,
    ):
        for source_leaf in compression_order(archive):
            if time.monotonic() > deadline:
                raise ValueError("ZIP creation deadline exceeded")
            if isinstance(source_leaf, _ArchiveSourceLeaf):
                file_path = source_leaf.path
                approved_identity = source_leaf.identity
            else:
                # Compatibility for direct/internal tests. Production callers
                # always pass the identity frozen by _validated_archive_files.
                file_path = Path(source_leaf)
                approved_identity = _source_leaf_identity(file_path.lstat())
            try:
                relative_path = file_path.relative_to(root).as_posix()
            except ValueError as error:
                raise ValueError(
                    f"Archive source escaped its root: {file_path}"
                ) from error
            arcname = f"{root.name}/{relative_path}"
            if arcname in seen_members:
                raise ValueError(f"Archive source contains duplicate path: {arcname}")
            if archive_member_mode is not None:
                # ZIP readers otherwise invent parent directories using their
                # local umask. Explicit entries retain traversal access even
                # when extraction runs under umask 077. Derive them only from
                # already admitted file paths; no extra source walk is needed.
                parts = PurePosixPath(arcname).parts
                for depth in range(1, len(parts)):
                    directory_name = "/".join(parts[:depth]) + "/"
                    if directory_name in seen_members:
                        continue
                    if time.monotonic() > deadline:
                        raise ValueError("ZIP creation deadline exceeded")
                    if len(seen_members) >= active_limits.max_members:
                        raise ValueError("ZIP member-count limit exceeded")
                    directory_info = zipfile.ZipInfo(directory_name)
                    directory_info.create_system = 3
                    directory_info.external_attr = (
                        (stat.S_IFDIR | _SHARED_READ_LOOSE_DIRECTORY_MODE) << 16
                    ) | 0x10
                    archive.writestr(directory_info, b"")
                    seen_members.add(directory_name)
            if len(seen_members) >= active_limits.max_members:
                raise ValueError("ZIP member-count limit exceeded")
            seen_members.add(arcname)

            actual_size, actual_sha256 = _copy_receipt_bound_leaf(
                archive,
                file_path,
                arcname,
                compression_level=compression_level,
                approved_identity=approved_identity,
                max_bytes=active_limits.max_member_bytes,
                normalized_timestamp_ns=normalized_timestamp_ns,
                archive_member_mode=archive_member_mode,
                deadline=deadline,
                archive_progress_callback=progress_callback,
                progress_base_bytes=completed_source_bytes,
                progress_total_bytes=progress_total,
                compression_executor=(
                    compression_executor if compression_workers > 1 else None
                ),
                compression_workers=compression_workers,
            )
            completed_source_bytes += actual_size
            expected = expected_digests.get(relative_path)
            if expected is None:
                continue
            if relative_path in verified_expected:
                raise ValueError(
                    "Archive source contains duplicate authoritative path: "
                    f"{relative_path}"
                )
            expected_size, expected_sha256 = expected
            if actual_size != expected_size or actual_sha256 != expected_sha256:
                raise ValueError(
                    "Archive source authoritative snapshot leaf differs from receipt: "
                    f"{relative_path}"
                )
            verified_expected.add(relative_path)

    _emit_archive_progress(
        progress_callback,
        "Compressing ZIP archive",
        progress_total,
        progress_total,
    )

    missing = set(expected_digests).difference(verified_expected)
    if missing:
        raise ValueError(
            "Archive source is missing authoritative snapshot leaf(s): "
            + ", ".join(sorted(missing))
        )


def _copy_receipt_bound_leaf(
    archive: zipfile.ZipFile,
    file_path: Path,
    arcname: str,
    *,
    compression_level: int,
    approved_identity: tuple[int, ...],
    max_bytes: Optional[int] = None,
    normalized_timestamp_ns: Optional[int] = None,
    archive_member_mode: Optional[int] = None,
    deadline: Optional[float] = None,
    archive_progress_callback: Optional[ArchiveProgressCallback] = None,
    progress_base_bytes: int = 0,
    progress_total_bytes: int = 1,
    compression_executor: Optional[ThreadPoolExecutor] = None,
    compression_workers: int = 1,
) -> tuple[int, str]:
    """
    Copy one leaf from a no-follow descriptor and hash those exact bytes.

    ZIP timestamps have a 1980-2107 range. The source mode and timestamp come
    from the same descriptor whose bytes are copied below.

    Args:
        archive: Archive object whose ``open`` state is read while performing
            copy one leaf from a no-follow descriptor and hash those exact
            bytes.
        file_path: filesystem location used as the file path for this operation.
        arcname: Text supplied as arcname in the format accepted by this
            function.
        compression_level: Numeric compression level used while the operation
            performs bounded accounting.
        approved_identity: Entries supplied as ``approved_identity`` without
            transferring container ownership.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.
        normalized_timestamp_ns: Optional normalized timestamp ns; ``None``
            selects the function's default behavior.
        archive_member_mode: Optional shared-read policy for the regular ZIP
            member, retaining owner-private selection evidence. ``None``
            preserves the source file's mode.
        deadline: Absolute monotonic deadline after which the operation must
            stop.
        archive_progress_callback: Optional best-effort callback for aggregate
            archive progress.
        progress_base_bytes: Bytes completed before this source leaf began.
        progress_total_bytes: Total source bytes represented by the current ZIP
            write stage.
        compression_executor: Optional archive-owned pool for large-member
            compression. Source reads and ZIP writes remain on the caller.
        compression_workers: Bound on pending one-MiB blocks, selected using the
            process CPU capacity and capped at eight by the archive writer.

    Returns:
        A tuple containing ``actual size`` and ``hexdigest`` in that order.

    Raises:
        RuntimeError: If archive creation lacks no-follow file access.
        ValueError: If archive source changed after validation: ``file_path``;
            archive source exceeds policy: ``file_path``; ZIP creation deadline
            exceeded; or archive source grew while copied: ``file_path``; or
            another input invariant is violated.
    """

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("Archive creation requires no-follow file access")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(file_path, flags)
    try:
        source_stat = os.fstat(descriptor)
        visible_before = file_path.lstat()
        if (
            not stat.S_ISREG(source_stat.st_mode)
            or not stat.S_ISREG(visible_before.st_mode)
            or _source_leaf_identity(source_stat) != approved_identity
            or _source_leaf_identity(visible_before) != approved_identity
        ):
            raise ValueError(f"Archive source changed after validation: {file_path}")
        if max_bytes is not None and source_stat.st_size > max_bytes:
            raise ValueError(f"Archive source exceeds policy: {file_path}")

        # ZIP timestamps have a 1980-2107 range.  The source mode and timestamp
        # come from the same descriptor whose bytes are copied below.
        if deadline is not None and time.monotonic() > deadline:
            raise ValueError("ZIP creation deadline exceeded")
        source_timestamp = (
            source_stat.st_mtime
            if normalized_timestamp_ns is None
            else normalized_timestamp_ns / 1_000_000_000
        )
        timestamp = min(max(source_timestamp, 315532800), 4354819198)
        date_time = time.localtime(timestamp)[:6]
        info = zipfile.ZipInfo(arcname, date_time=date_time)
        info.create_system = 3
        info.compress_type = zipfile.ZIP_DEFLATED
        info._compresslevel = compression_level
        archive_member_mode = _validated_archive_member_mode(archive_member_mode)
        if archive_member_mode is not None:
            relative_path = PurePosixPath(*PurePosixPath(arcname).parts[1:]).as_posix()
            member_mode = stat.S_IFREG | _published_bundle_file_mode(
                relative_path, archive_member_mode
            )
        else:
            member_mode = source_stat.st_mode
        info.external_attr = (member_mode & 0xFFFF) << 16

        digest = hashlib.sha256()
        actual_size = 0
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            with (
                archive.open(info, "w", force_zip64=True) as destination,
                parallel_zip_compression(
                    destination,
                    executor=compression_executor,
                    workers=compression_workers,
                    level=compression_level,
                    source_bytes=source_stat.st_size,
                    deadline=deadline,
                ),
            ):
                while True:
                    if deadline is not None and time.monotonic() > deadline:
                        raise ValueError("ZIP creation deadline exceeded")
                    remaining = source_stat.st_size - actual_size
                    chunk = source.read(min(1024 * 1024, max(1, remaining + 1)))
                    if deadline is not None and time.monotonic() > deadline:
                        raise ValueError("ZIP creation deadline exceeded")
                    if not chunk:
                        break
                    actual_size += len(chunk)
                    if actual_size > source_stat.st_size:
                        raise ValueError(
                            f"Archive source grew while copied: {file_path}"
                        )
                    digest.update(chunk)
                    destination.write(chunk)
                    _emit_archive_progress(
                        archive_progress_callback,
                        "Compressing ZIP archive",
                        progress_base_bytes + actual_size,
                        progress_total_bytes,
                    )
                    if deadline is not None and time.monotonic() > deadline:
                        raise ValueError("ZIP creation deadline exceeded")
        source_after = os.fstat(descriptor)
        visible_after = file_path.lstat()
        if (
            _source_leaf_identity(source_after) != approved_identity
            or _source_leaf_identity(visible_after) != approved_identity
            or actual_size != source_stat.st_size
        ):
            raise ValueError(f"Archive source changed while copied: {file_path}")
        return actual_size, digest.hexdigest()
    finally:
        os.close(descriptor)


def _open_relative_source_leaf(
    root_descriptor: int,
    relative_parts: tuple[str, ...],
) -> tuple[int, int]:
    """
    Open one leaf below a pinned root without following any component.

    The implementation uses ``root_descriptor`` and ``relative_parts`` to open
    one leaf below a pinned root without following any component. If the
    function cannot open one leaf below a pinned root without following any
    component, its exception reaches the caller instead of being converted into
    a successful result.

    Args:
        root_descriptor: Numeric root descriptor used while the operation
            performs bounded accounting.
        relative_parts: Entries supplied as ``relative_parts`` without
            transferring container ownership.

    Returns:
        A tuple containing ``current`` and ``leaf`` in that order.

    Raises:
        ValueError: If archive source relative path is unsafe; or archive source
            parent is not a directory.
        RuntimeError: If archive source access lacks no-follow support.
    """

    if not relative_parts or any(part in {"", ".", ".."} for part in relative_parts):
        raise ValueError("Archive source relative path is unsafe")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("Archive source access requires no-follow support")
    directory_flags = (
        os.O_RDONLY
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    current = os.dup(root_descriptor)
    try:
        for component in relative_parts[:-1]:
            child = os.open(
                component,
                directory_flags,
                dir_fd=current,
            )
            opened = os.fstat(child)
            if not stat.S_ISDIR(opened.st_mode):
                os.close(child)
                raise ValueError("Archive source parent is not a directory")
            os.close(current)
            current = child
        leaf = os.open(
            relative_parts[-1],
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=current,
        )
        return current, leaf
    except BaseException:
        os.close(current)
        raise


def _read_open_regular_file(
    descriptor: int,
    *,
    maximum_bytes: int,
    deadline: float,
) -> bytes:
    """
    Read one already-pinned regular file under byte and elapsed-time caps.

    After applying local validation, the function forwards ``descriptor``,
    ``maximum_bytes``, and ``deadline`` to ``bytes`` and preserves its return
    and exception contract. Parsing or I/O must finish before the validated
    representation is made available to the caller.

    Args:
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The bounded open regular file bytes.

    Raises:
        ValueError: If bundle metadata read deadline exceeded; or bundle
            metadata exceeds its byte limit.
    """

    content = bytearray()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        if time.monotonic() > deadline:
            raise ValueError("Bundle metadata read deadline exceeded")
        chunk = os.read(
            descriptor,
            min(64 * 1024, max(1, maximum_bytes - len(content) + 1)),
        )
        if not chunk:
            return bytes(content)
        content.extend(chunk)
        if len(content) > maximum_bytes:
            raise ValueError("Bundle metadata exceeds its byte limit")


def _json_object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    """
    Return the JSON object without duplicate keys.

    The implementation uses ``pairs`` to produce the JSON object without
    duplicate keys. If the function cannot produce the JSON object without
    duplicate keys, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        pairs: Entries supplied as ``pairs`` without transferring container
            ownership.

    Returns:
        The validated ``result``.

    Raises:
        ValueError: If duplicate bundle metadata key: ``key``.
    """
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate bundle metadata key: {key!r}")
        result[key] = value
    return result


def _metadata_relative_path(root: Path, item: _ArchiveSourceLeaf) -> str:
    """
    Return the metadata relative path.

    After applying local validation, the function forwards ``root`` and ``item``
    to ``as_posix`` and preserves its return and exception contract.

    Args:
        root: filesystem location used as the root for this operation.
        item: Item object whose ``path`` and ``relative_to`` state is read while
            performing metadata relative path.

    Returns:
        The canonical metadata relative path.
    """
    return item.path.relative_to(root).as_posix()


def _is_bundle_metadata_path(relative: str) -> bool:
    """
    Return whether ``relative`` is bundle metadata path.

    The implementation uses ``relative`` to determine whether ``relative`` is
    bundle metadata path.

    Args:
        relative: Text supplied as relative in the format accepted by this
            function.

    Returns:
        Whether ``relative`` is bundle metadata path.
    """
    parts = PurePosixPath(relative).parts
    return parts == (".metadata", "metadata.json") or (
        len(parts) == 3 and parts[1:] == (".metadata", "metadata.json")
    )


def _set_bundle_mode(
    directory: str | Path,
    bundle_mode: str,
    *,
    limits: Optional[ArchiveLimits] = None,
    excluded_source_paths: Optional[Sequence[str | Path]] = None,
    expected_source_snapshot: Optional[Sequence[_ArchiveSourceLeaf]] = None,
) -> list[_ArchiveSourceLeaf]:
    """
    Align lifecycle metadata and return its fully revalidated source snapshot.

    A bounded no-follow walk always precedes the update. An optional previous
    snapshot binds that walk to already copied diagnostic bytes. After durable
    metadata replacement, another complete walk rejects membership changes and
    changes to ordinary files. Returning that checked inventory lets the owning
    archive transaction avoid repeating the same walk at the handoff boundary.
    Callers must still revalidate source identities after compression and before
    deletion; this snapshot is not permission to skip those later checks.

    Args:
        directory: Root of the caller-owned source bundle.
        bundle_mode: Lifecycle mode recorded in root and per-DUT metadata.
        limits: Optional finite source-enumeration and metadata-update bounds.
        excluded_source_paths: Exact managed-publication names which must remain
            absent from both the initial and final source walks.
        expected_source_snapshot: Optional frozen inventory which the initial
            walk must match before any metadata is changed.

    Returns:
        The post-update validated leaf inventory, or the initial validated
        inventory when no lifecycle metadata exists.

    Raises:
        RuntimeError: If bundle metadata updates require no-follow support.
        ValueError: If bundle root changed before metadata update; bundle
            metadata update deadline exceeded; bundle metadata changed before
            update; or bundle metadata changed while read; or another input
            invariant is violated.
        OSError: If could not reserve bundle metadata staging leaf; or bundle
            metadata staging write made no progress.

    Side Effects:
        Atomically replaces changed lifecycle metadata on the selected source
        filesystem and fsyncs each replacement. Closes all owned descriptors
        and removes unpublished temporary metadata on every exit path.
    """

    active_limits = resolve_archive_creation_limits(limits)
    deadline = time.monotonic() + active_limits.max_seconds
    root = Path(directory)
    snapshot = _validated_archive_files(
        root,
        limits=active_limits,
        excluded_source_paths=excluded_source_paths,
    )
    if expected_source_snapshot is not None and snapshot != list(
        expected_source_snapshot
    ):
        raise ValueError("Archive source changed before bundle metadata update")
    snapshot_by_relative = {
        _metadata_relative_path(root, item): item for item in snapshot
    }
    metadata_items = [
        item
        for relative, item in snapshot_by_relative.items()
        if _is_bundle_metadata_path(relative)
    ]
    if not metadata_items:
        return snapshot

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("Bundle metadata updates require no-follow support")
    root_details = root.lstat()
    root_descriptor = os.open(
        root,
        os.O_RDONLY
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        if _source_leaf_identity(os.fstat(root_descriptor)) != (
            _source_leaf_identity(root_details)
        ):
            raise ValueError("Bundle root changed before metadata update")
        for item in sorted(metadata_items, key=lambda candidate: candidate.path):
            if time.monotonic() > deadline:
                raise ValueError("Bundle metadata update deadline exceeded")
            relative = _metadata_relative_path(root, item)
            parts = PurePosixPath(relative).parts
            parent_descriptor, descriptor = _open_relative_source_leaf(
                root_descriptor,
                parts,
            )
            temporary_name: Optional[str] = None
            try:
                before = os.fstat(descriptor)
                visible = os.stat(
                    parts[-1],
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or _source_leaf_identity(before) != item.identity
                    or _source_leaf_identity(visible) != item.identity
                    or before.st_size > MAX_BUNDLE_METADATA_BYTES
                ):
                    raise ValueError("Bundle metadata changed before update")
                raw = _read_open_regular_file(
                    descriptor,
                    maximum_bytes=MAX_BUNDLE_METADATA_BYTES,
                    deadline=deadline,
                )
                after_read = os.fstat(descriptor)
                if _source_leaf_identity(after_read) != item.identity:
                    raise ValueError("Bundle metadata changed while read")
                try:
                    payload = json.loads(
                        raw.decode("utf-8"),
                        object_pairs_hook=_json_object_without_duplicate_keys,
                    )
                except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                    raise ValueError("Bundle metadata JSON is invalid") from error
                if type(payload) is not dict:
                    raise ValueError("Bundle metadata root must be an object")
                metadata = payload.get("metadata")
                if metadata is None:
                    metadata = {}
                    payload["metadata"] = metadata
                if type(metadata) is not dict:
                    raise ValueError("Bundle metadata field must be an object")
                if metadata.get("bundle_mode") == bundle_mode:
                    continue
                metadata["bundle_mode"] = bundle_mode
                encoded = (json.dumps(payload, indent=4) + "\n").encode("utf-8")
                if len(encoded) > MAX_BUNDLE_METADATA_BYTES:
                    raise ValueError("Updated bundle metadata exceeds its byte limit")

                for _attempt in range(16):
                    candidate = f".metadata.json.{secrets.token_hex(16)}"
                    try:
                        temporary_descriptor = os.open(
                            candidate,
                            os.O_WRONLY
                            | os.O_CREAT
                            | os.O_EXCL
                            | no_follow
                            | getattr(os, "O_CLOEXEC", 0),
                            0o600,
                            dir_fd=parent_descriptor,
                        )
                    except FileExistsError:
                        continue
                    temporary_name = candidate
                    break
                else:
                    raise OSError("Could not reserve bundle metadata staging leaf")
                try:
                    offset = 0
                    while offset < len(encoded):
                        if time.monotonic() > deadline:
                            raise ValueError("Bundle metadata update deadline exceeded")
                        written = os.write(temporary_descriptor, encoded[offset:])
                        if written <= 0:
                            raise OSError(
                                "Bundle metadata staging write made no progress"
                            )
                        offset += written
                    os.fsync(temporary_descriptor)
                finally:
                    os.close(temporary_descriptor)

                visible_before_replace = os.stat(
                    parts[-1],
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    _source_leaf_identity(os.fstat(descriptor)) != item.identity
                    or _source_leaf_identity(visible_before_replace) != item.identity
                ):
                    raise ValueError("Bundle metadata changed before replacement")
                os.replace(
                    temporary_name,
                    parts[-1],
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
                temporary_name = None
                os.fsync(parent_descriptor)
            finally:
                if temporary_name is not None:
                    try:
                        os.unlink(temporary_name, dir_fd=parent_descriptor)
                    except OSError:
                        pass
                os.close(descriptor)
                os.close(parent_descriptor)

        observed = _validated_archive_files(
            root,
            limits=active_limits,
            excluded_source_paths=excluded_source_paths,
        )
        observed_by_relative = {
            _metadata_relative_path(root, item): item for item in observed
        }
        if set(observed_by_relative) != set(snapshot_by_relative):
            raise ValueError("Bundle source membership changed during metadata update")
        metadata_paths = {
            relative
            for relative in snapshot_by_relative
            if _is_bundle_metadata_path(relative)
        }
        if any(
            observed_by_relative[relative].identity != item.identity
            for relative, item in snapshot_by_relative.items()
            if relative not in metadata_paths
        ):
            raise ValueError("Bundle source changed during metadata update")
        return observed
    finally:
        os.close(root_descriptor)


def _normalized_archive_source_exclusions(
    directory: str | Path,
    excluded_source_paths: Optional[Sequence[str | Path]],
    *,
    limits: Optional[ArchiveLimits] = None,
) -> frozenset[str]:
    """
    Return bounded lexical exclusion names confined to one archive root.

    The normalization preserves exact directory-entry names without resolving
    their occupants. Relative inputs are interpreted below ``directory`` and
    every returned name is proven to stay within that root under archive path
    count, depth, and metadata-material limits.

    Args:
        directory: Filesystem root selected for archive creation.
        excluded_source_paths: Optional exact names which must not occur in the
            archive source transaction.
        limits: Optional limits governing path count and material.

    Returns:
        Lexically normalized absolute exclusion names.

    Raises:
        ValueError: If the exclusions are malformed, exceed policy, or escape
            the archive source root.
    """

    if excluded_source_paths is None:
        return frozenset()
    if isinstance(excluded_source_paths, (str, bytes, Path)):
        raise ValueError("Archive source exclusions are malformed")
    active_limits = resolve_archive_creation_limits(limits)
    if len(excluded_source_paths) > active_limits.max_members:
        raise ValueError("Archive source exclusion count exceeds policy")
    root = os.path.abspath(os.path.normpath(os.fspath(directory)))
    normalized: set[str] = set()
    path_material_bytes = 0
    for raw_path in excluded_source_paths:
        try:
            rendered = os.fspath(raw_path)
            if not isinstance(rendered, str) or not rendered:
                raise ValueError("Archive source exclusion is malformed")
            candidate = os.path.abspath(
                os.path.normpath(
                    rendered
                    if os.path.isabs(rendered)
                    else os.path.join(root, rendered)
                )
            )
            relative = os.path.relpath(candidate, root)
            relative_bytes = relative.encode("utf-8")
        except (TypeError, UnicodeError, OSError) as error:
            raise ValueError("Archive source exclusion is malformed") from error
        if (
            candidate == root
            or os.path.commonpath((root, candidate)) != root
            or not relative
            or relative in {".", ".."}
            or len(relative_bytes) > active_limits.max_metadata_member_bytes
            or len(PurePosixPath(relative).parts) > active_limits.max_path_depth
        ):
            raise ValueError("Archive source exclusion escapes policy")
        path_material_bytes += len(relative_bytes)
        if path_material_bytes > active_limits.max_metadata_bytes:
            raise ValueError("Archive source exclusion metadata exceeds policy")
        normalized.add(candidate)
    return frozenset(normalized)


def _validated_archive_files(
    directory: str | Path,
    *,
    limits: Optional[ArchiveLimits] = None,
    excluded_source_paths: Optional[Sequence[str | Path]] = None,
    validated_directories: Optional[list[_ArchiveSourceDirectory]] = None,
) -> list[_ArchiveSourceLeaf]:
    """
    Return regular files below a directory or reject unsafe entries.

    The implementation uses ``directory``, ``limits``,
    ``excluded_source_paths``, and the optional ``validated_directories`` sink
    to produce regular files below a directory or reject unsafe entries.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot produce regular files
    below a directory or reject unsafe entries, its exception reaches the
    caller instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        directory: filesystem location used as the directory for this operation.
        limits: Optional Limits governing regular files below a directory or
            reject unsafe entries.
        excluded_source_paths: Optional exact lexical names which must remain
            absent from this source snapshot.
        validated_directories: Optional empty list populated in post-order with
            the exact non-root directories approved by the same source walk.

    Returns:
        The validated ``regular_files``.

    Raises:
        ValueError: If cannot inspect archive source ``root``: ``exc``; refusing
            to archive symbolic-link root: ``root``; archive source is not a
            directory: ``root``; or cannot safely open archive source ``root``;
            or another input invariant is violated.
        RuntimeError: If archive creation lacks no-follow directory access.
    """

    active_limits = resolve_archive_creation_limits(limits)
    if validated_directories is not None and (
        type(validated_directories) is not list or validated_directories
    ):
        raise ValueError("Validated archive directory sink must be an empty list")
    active_exclusions = _normalized_archive_source_exclusions(
        directory,
        excluded_source_paths,
        limits=active_limits,
    )
    deadline = time.monotonic() + active_limits.max_seconds
    root = Path(directory)
    try:
        root_details = root.lstat()
    except OSError as exc:
        raise ValueError(f"Cannot inspect archive source {root}: {exc}") from exc
    if stat.S_ISLNK(root_details.st_mode):
        raise ValueError(f"Refusing to archive symbolic-link root: {root}")
    if not stat.S_ISDIR(root_details.st_mode):
        raise ValueError(f"Archive source is not a directory: {root}")

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("Archive creation requires no-follow directory access")
    directory_flags = (
        os.O_RDONLY
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    root_descriptor: Optional[int] = None
    try:
        root_descriptor = os.open(root, directory_flags)
        opened_root = os.fstat(root_descriptor)
    except OSError as error:
        if root_descriptor is not None:
            os.close(root_descriptor)
        raise ValueError(f"Cannot safely open archive source {root}") from error
    if not stat.S_ISDIR(opened_root.st_mode) or _source_leaf_identity(
        opened_root
    ) != _source_leaf_identity(root_details):
        os.close(root_descriptor)
        raise ValueError("Archive source identity changed before enumeration")

    regular_files: list[_ArchiveSourceLeaf] = []
    path_nodes = 0
    path_material_bytes = 0
    total_bytes = 0

    def visit_directory(
        descriptor: int,
        current_path: Path,
        relative_parts: tuple[str, ...],
    ) -> None:
        """
        Visit directory.

        The implementation uses ``descriptor``, ``current_path``, and
        ``relative_parts`` to visit directory. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot visit directory, its exception reaches the caller
        instead of being converted into a successful result. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            descriptor: Numeric descriptor used while the operation performs
                bounded accounting.
            current_path: filesystem location used as the current path for this
                operation.
            relative_parts: Entries supplied as ``relative_parts`` without
                transferring container ownership.

        Raises:
            ValueError: If archive source enumeration deadline exceeded; archive
                source path-node limit exceeded; cannot enumerate archive
                source: ``current_path``; or refusing to archive symbolic link:
                ``entry``; or another input invariant is violated.
        """
        nonlocal path_nodes, path_material_bytes, total_bytes
        if time.monotonic() > deadline:
            raise ValueError("Archive source enumeration deadline exceeded")
        directory_before = os.fstat(descriptor)
        children: list[tuple[str, os.stat_result]] = []
        try:
            with os.scandir(descriptor) as entries:
                for scanned in entries:
                    path_nodes += 1
                    if path_nodes > active_limits.max_path_nodes:
                        raise ValueError("Archive source path-node limit exceeded")
                    metadata = scanned.stat(follow_symlinks=False)
                    children.append((scanned.name, metadata))
                    if time.monotonic() > deadline:
                        raise ValueError("Archive source enumeration deadline exceeded")
        except OSError as error:
            raise ValueError(
                f"Cannot enumerate archive source: {current_path}"
            ) from error

        for name, metadata in sorted(children, key=lambda item: item[0]):
            entry = current_path / name
            entry_key = os.path.abspath(os.path.normpath(os.fspath(entry)))
            if entry_key in active_exclusions:
                raise ValueError(
                    "Archive source contains an excluded managed publication name"
                )
            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                raise ValueError(f"Refusing to archive symbolic link: {entry}")
            # Judge each component before it is joined, so a name that the
            # shared policy would refuse on the consuming side fails this
            # archive at source validation instead of producing a bundle that
            # has to be discarded after the loose run tree is gone.
            if has_unsafe_member_characters(name):
                raise ValueError(
                    f"Archive source path is not distributable: {str(entry)!r}"
                )
            try:
                relative = PurePosixPath(*relative_parts, name).as_posix()
                relative_bytes = relative.encode("utf-8")
            except (UnicodeError, ValueError) as error:
                raise ValueError(
                    f"Archive source path is malformed: {entry}"
                ) from error
            relative_path = PurePosixPath(relative)
            if (
                not relative
                or len(relative_bytes) > active_limits.max_metadata_member_bytes
                or len(relative_path.parts) > active_limits.max_path_depth
            ):
                raise ValueError(f"Archive source path exceeds policy: {entry}")
            path_material_bytes += len(relative_bytes)
            if path_material_bytes > active_limits.max_metadata_bytes:
                raise ValueError("Archive source path metadata limit exceeded")

            if stat.S_ISDIR(mode):
                try:
                    child_descriptor = os.open(
                        name,
                        directory_flags,
                        dir_fd=descriptor,
                    )
                except OSError as error:
                    raise ValueError(
                        f"Cannot safely traverse archive source directory: {entry}"
                    ) from error
                try:
                    child_opened = os.fstat(child_descriptor)
                    if not stat.S_ISDIR(child_opened.st_mode) or _source_leaf_identity(
                        child_opened
                    ) != _source_leaf_identity(metadata):
                        raise ValueError(
                            "Archive source directory changed before traversal: "
                            f"{entry}"
                        )
                    visit_directory(
                        child_descriptor,
                        entry,
                        (*relative_parts, name),
                    )
                    child_after = os.fstat(child_descriptor)
                    visible_after = os.stat(
                        name,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                    if _source_leaf_identity(child_after) != _source_leaf_identity(
                        metadata
                    ) or _source_leaf_identity(visible_after) != _source_leaf_identity(
                        metadata
                    ):
                        raise ValueError(
                            "Archive source directory changed during traversal: "
                            f"{entry}"
                        )
                    if validated_directories is not None:
                        validated_directories.append(
                            _ArchiveSourceDirectory(
                                entry,
                                _source_leaf_identity(metadata),
                            )
                        )
                finally:
                    os.close(child_descriptor)
                continue
            if not stat.S_ISREG(mode):
                raise ValueError(
                    f"Refusing to archive non-regular filesystem entry: {entry}"
                )
            if metadata.st_nlink != 1:
                raise ValueError(f"Refusing to archive multiply-linked file: {entry}")
            if len(regular_files) >= active_limits.max_members:
                raise ValueError("Archive source member-count limit exceeded")
            if metadata.st_size > active_limits.max_member_bytes:
                raise ValueError(f"Archive source member exceeds policy: {entry}")
            total_bytes += metadata.st_size
            if total_bytes > active_limits.max_total_bytes:
                raise ValueError("Archive source total-byte limit exceeded")
            regular_files.append(
                _ArchiveSourceLeaf(entry, _source_leaf_identity(metadata))
            )

        if _source_leaf_identity(os.fstat(descriptor)) != _source_leaf_identity(
            directory_before
        ):
            raise ValueError(
                f"Archive source directory changed during traversal: {current_path}"
            )

    try:
        visit_directory(root_descriptor, root, ())
        visible_after = root.lstat()
        if _source_leaf_identity(os.fstat(root_descriptor)) != _source_leaf_identity(
            root_details
        ) or _source_leaf_identity(visible_after) != _source_leaf_identity(
            root_details
        ):
            raise ValueError("Archive source identity changed during enumeration")
    finally:
        os.close(root_descriptor)
    return regular_files


def _loose_publication_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """
    Return inode state that must remain stable across a permission transition.

    Mode and change time are intentionally omitted because ``fchmod`` changes
    both. Ownership, file type, link count, size, and modification time remain
    bound so publication cannot silently switch to or modify another entry.

    Args:
        metadata: Metadata captured from a pinned loose-bundle descriptor.

    Returns:
        Stable identity fields used before, during, and after publication.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _open_validated_loose_publication_entry(
    root: Path,
    root_descriptor: int,
    item: _ArchiveSourceLeaf | _ArchiveSourceDirectory,
    *,
    is_directory: bool,
    required_mode: Optional[int],
    owner_uid: int,
) -> tuple[int, int, os.stat_result, tuple[str, ...]]:
    """
    Open one inventoried loose-bundle entry through a pinned private root.

    Every path component is opened without following links. The visible entry
    and descriptor must still match the exact identity approved by the bounded
    source walk, and every published inode must be owned by the effective user.

    Args:
        root: Validated loose-bundle root used to derive a relative path.
        root_descriptor: Pinned descriptor for ``root``.
        item: Validated file or directory inventory record to open.
        is_directory: Whether the inventory record must name a directory.
        owner_uid: Filesystem UID verified before freezing the root inventory.
        required_mode: Optional exact permission mode required before opening
            succeeds; ``None`` accepts the current mode for later normalization.

    Returns:
        Parent descriptor, entry descriptor, entry metadata, and relative path
        components. The caller owns and must close both descriptors.

    Raises:
        ValueError: If the entry escaped the root, changed after validation,
            has the wrong type or ownership, or does not have ``required_mode``.
        RuntimeError: If no-follow access is unavailable.
        OSError: If a component cannot be opened or inspected.
    """

    try:
        relative_parts = PurePosixPath(item.path.relative_to(root).as_posix()).parts
    except ValueError as error:
        raise ValueError("Loose publication entry escaped its root") from error
    parent_descriptor, descriptor = _open_relative_source_leaf(
        root_descriptor,
        relative_parts,
    )
    try:
        before = os.fstat(descriptor)
        visible = os.stat(
            relative_parts[-1],
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        expected_type = stat.S_ISDIR if is_directory else stat.S_ISREG
        mode = stat.S_IMODE(before.st_mode)
        if (
            not expected_type(before.st_mode)
            or not expected_type(visible.st_mode)
            or before.st_uid != owner_uid
            or before.st_dev != os.fstat(root_descriptor).st_dev
            or _source_leaf_identity(before) != item.identity
            or _source_leaf_identity(visible) != item.identity
            or (not is_directory and before.st_nlink != 1)
            or (required_mode is not None and mode != required_mode)
        ):
            raise ValueError(
                "Loose output entry is not eligible for shared-read publication"
            )
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.close(parent_descriptor)
        except OSError:
            pass
        raise
    return parent_descriptor, descriptor, before, relative_parts


def publish_loose_bundle_shared_read(
    directory: str | Path,
    *,
    excluded_source_paths: Optional[Sequence[str | Path]] = None,
    limits: Optional[ArchiveLimits] = None,
    allow_live_shared_root: bool = False,
) -> Path:
    """
    Publish one finalized sanitized loose bundle for a local report server.

    The completed tree first passes the same bounded, no-follow, regular-file
    policy used for final ZIP creation. Descendant files are normalized to
    ``0755`` (owner-private selection evidence stays ``0600``) and directories
    to ``0755`` while the run root remains ``0700``;
    the root changes to ``0755`` only after every descendant is durable and
    verified. A failure restores the root's private mode before attempting to
    roll back descendant modes, so partially prepared content is not exposed.
    An exact already-published tree is accepted as an idempotent replay.
    A caller that has authorized finalized sanitized delivery may also normalize
    private descendants of a root which was readable during collection.

    Args:
        directory: Finalized timestamped run directory selected for publication.
        excluded_source_paths: Optional exact managed-publication names which
            must remain absent from the delivered tree.
        limits: Optional bounds applied to traversal, members, bytes, depth,
            path material, and elapsed publication time.
        allow_live_shared_root: Whether finalized delivery authorizes publishing
            remaining private descendants beneath an already readable run root.

    Returns:
        The verified loose-bundle root after shared-read publication.

    Raises:
        RuntimeError: If no-follow access is unavailable.
        ValueError: If the tree is unsafe, changed, not privately rooted, not
            owned by the effective user, or exceeds a configured bound.
        OSError: If descriptor, permission, or durability operations fail.

    Side Effects:
        Changes finalized bundle directories to ``0755`` and normal regular
        files to ``0755``, retaining selection evidence as ``0600``. On failure,
        keeps or restores the root to ``0700`` when this invocation began with
        a private root.
    """

    active_limits = resolve_archive_creation_limits(limits)
    deadline = time.monotonic() + active_limits.max_seconds
    root = Path(directory)
    root_metadata = root.lstat()
    # Resolve beside the run on the same filesystem so an idempotent second
    # publication does not change the already-published root's timestamps.
    # A filesystem mounted directly at the root needs its probe inside it.
    probe_parent = (
        root.parent if root.parent.lstat().st_dev == root_metadata.st_dev else root
    )
    owner_uid = filesystem_owner_uid(probe_parent, observed_uid=root_metadata.st_uid)
    root_before = root.lstat()
    validated_directories: list[_ArchiveSourceDirectory] = []
    files = _validated_archive_files(
        root,
        limits=active_limits,
        excluded_source_paths=excluded_source_paths,
        validated_directories=validated_directories,
    )
    root_visible = root.lstat()
    if (
        not stat.S_ISDIR(root_before.st_mode)
        or root_before.st_uid != owner_uid
        or _source_leaf_identity(root_visible) != _source_leaf_identity(root_before)
    ):
        raise ValueError("Loose output root changed before publication")

    root_mode = stat.S_IMODE(root_before.st_mode)
    if root_mode not in {
        _PRIVATE_LOOSE_DIRECTORY_MODE,
        _SHARED_READ_LOOSE_DIRECTORY_MODE,
    }:
        raise ValueError("Loose output root is not eligible for publication")
    started_private = root_mode == _PRIVATE_LOOSE_DIRECTORY_MODE

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("Loose output publication requires no-follow access")
    root_descriptor = os.open(
        root,
        os.O_RDONLY
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    changed: list[tuple[tuple[str, ...], bool, int, tuple[int, ...]]] = []
    expected_identities = {
        item.path.relative_to(root).as_posix(): item.identity
        for item in (*files, *validated_directories)
    }
    try:
        opened_root = os.fstat(root_descriptor)
        if (
            _source_leaf_identity(opened_root) != _source_leaf_identity(root_before)
            or opened_root.st_uid != owner_uid
        ):
            raise ValueError("Loose output root changed before publication")

        entries: tuple[
            tuple[_ArchiveSourceLeaf | _ArchiveSourceDirectory, bool, int], ...
        ] = tuple(
            (
                item,
                False,
                _published_bundle_file_mode(item.path.relative_to(root).as_posix()),
            )
            for item in files
        ) + tuple(
            (item, True, _SHARED_READ_LOOSE_DIRECTORY_MODE)
            for item in validated_directories
        )

        # Preflight every inode before the first permission change. A root that
        # is already shared-readable is accepted only when the complete tree is
        # already in its final form.
        for item, is_directory, target_mode in entries:
            if time.monotonic() > deadline:
                raise ValueError("Loose output publication deadline exceeded")
            required_mode = (
                target_mode
                if not started_private and not allow_live_shared_root
                else None
            )
            parent_descriptor, descriptor, _before, _parts = (
                _open_validated_loose_publication_entry(
                    root,
                    root_descriptor,
                    item,
                    is_directory=is_directory,
                    required_mode=required_mode,
                    owner_uid=owner_uid,
                )
            )
            try:
                os.close(descriptor)
            finally:
                try:
                    os.close(parent_descriptor)
                except OSError:
                    pass

        published_root_identity = _source_leaf_identity(opened_root)
        if started_private or allow_live_shared_root:
            for item, is_directory, target_mode in entries:
                if time.monotonic() > deadline:
                    raise ValueError("Loose output publication deadline exceeded")
                parent_descriptor, descriptor, before, parts = (
                    _open_validated_loose_publication_entry(
                        root,
                        root_descriptor,
                        item,
                        is_directory=is_directory,
                        required_mode=None,
                        owner_uid=owner_uid,
                    )
                )
                try:
                    original_mode = stat.S_IMODE(before.st_mode)
                    if original_mode == target_mode:
                        continue
                    stable_identity = _loose_publication_identity(before)
                    changed.append(
                        (parts, is_directory, original_mode, stable_identity)
                    )
                    os.fchmod(descriptor, target_mode)
                    os.fsync(descriptor)
                    after = os.fstat(descriptor)
                    visible = os.stat(
                        parts[-1],
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    expected_type = stat.S_ISDIR if is_directory else stat.S_ISREG
                    if (
                        not expected_type(after.st_mode)
                        or stat.S_IMODE(after.st_mode) != target_mode
                        or _loose_publication_identity(after) != stable_identity
                        or _source_leaf_identity(visible)
                        != _source_leaf_identity(after)
                    ):
                        raise ValueError(
                            "Loose output entry changed during publication"
                        )
                    expected_identities[item.path.relative_to(root).as_posix()] = (
                        _source_leaf_identity(after)
                    )
                finally:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    try:
                        os.close(parent_descriptor)
                    except OSError:
                        pass

            root_stable_identity = _loose_publication_identity(opened_root)
            os.fchmod(root_descriptor, _SHARED_READ_LOOSE_DIRECTORY_MODE)
            os.fsync(root_descriptor)
            root_after = os.fstat(root_descriptor)
            visible_after = root.lstat()
            if (
                not stat.S_ISDIR(root_after.st_mode)
                or stat.S_IMODE(root_after.st_mode) != _SHARED_READ_LOOSE_DIRECTORY_MODE
                or _loose_publication_identity(root_after) != root_stable_identity
                or _source_leaf_identity(visible_after)
                != _source_leaf_identity(root_after)
            ):
                raise ValueError("Loose output root changed during publication")
            published_root_identity = _source_leaf_identity(root_after)

        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise ValueError("Loose output publication deadline exceeded")
        final_limits = replace(active_limits, max_seconds=remaining_seconds)
        final_directories: list[_ArchiveSourceDirectory] = []
        observed_files = _validated_archive_files(
            root,
            limits=final_limits,
            excluded_source_paths=excluded_source_paths,
            validated_directories=final_directories,
        )
        observed_identities = {
            item.path.relative_to(root).as_posix(): item.identity
            for item in (*observed_files, *final_directories)
        }
        if observed_identities != expected_identities:
            raise ValueError("Loose output tree changed during publication")
        final_root = os.fstat(root_descriptor)
        final_visible_root = root.lstat()
        if (
            stat.S_IMODE(final_root.st_mode) != _SHARED_READ_LOOSE_DIRECTORY_MODE
            or _source_leaf_identity(final_root) != published_root_identity
            or _source_leaf_identity(final_visible_root) != published_root_identity
        ):
            raise ValueError("Loose output root mode changed during publication")
        return root
    except BaseException as error:
        rollback_errors: list[BaseException] = []
        if started_private:
            try:
                os.fchmod(root_descriptor, _PRIVATE_LOOSE_DIRECTORY_MODE)
                os.fsync(root_descriptor)
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)
        for parts, is_directory, original_mode, stable_identity in reversed(changed):
            parent_descriptor = None
            descriptor = None
            try:
                parent_descriptor, descriptor = _open_relative_source_leaf(
                    root_descriptor,
                    parts,
                )
                before = os.fstat(descriptor)
                visible = os.stat(
                    parts[-1],
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                expected_type = stat.S_ISDIR if is_directory else stat.S_ISREG
                if (
                    not expected_type(before.st_mode)
                    or before.st_uid != owner_uid
                    or _loose_publication_identity(before) != stable_identity
                    or _source_leaf_identity(visible) != _source_leaf_identity(before)
                ):
                    raise ValueError(
                        "Loose output entry changed before publication rollback"
                    )
                os.fchmod(descriptor, original_mode)
                os.fsync(descriptor)
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)
            finally:
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                if parent_descriptor is not None:
                    try:
                        os.close(parent_descriptor)
                    except OSError:
                        pass
        authoritative = select_authoritative_exception([error, *rollback_errors])
        raise authoritative
    finally:
        try:
            os.close(root_descriptor)
        except OSError:
            pass


def _validated_archive_name(
    directory: str | Path,
    name: Optional[str],
    *,
    receipt_bound: bool,
) -> str:
    """
    Return a bounded simple archive basename before any output is opened.

    The implementation uses ``directory``, ``name``, and ``receipt_bound`` to
    produce a bounded simple archive basename before any output is opened. If
    the function cannot produce a bounded simple archive basename before any
    output is opened, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        directory: filesystem location used as the directory for this operation.
        name: Stable name used for lookup and operator-facing diagnostics.
        receipt_bound: Whether receipt bound is enabled or required for this
            operation.

    Returns:
        The validated ``candidate``.

    Raises:
        ValueError: If receipt-bound archive name must match the run root.
    """

    root_name = Path(os.path.abspath(directory)).name
    candidate: object = root_name if name is None else name

    def validate_simple(value: object) -> str:
        """
        Validate simple.

        The implementation uses ``value`` to validate simple. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path.

        Args:
            value: Value object whose ``encode`` and ``isprintable`` state is
                read while performing simple.

        Returns:
            The validated ``value``.

        Raises:
            ValueError: If the archive name is not a string; archive name is
                malformed; or the archive name is not a bounded printable simple
                name.
        """
        if type(value) is not str:
            raise ValueError("Archive name must be a string")
        try:
            encoded = value.encode("utf-8")
        except UnicodeError as error:
            raise ValueError("Archive name is malformed") from error
        if (
            not value
            or value in {".", ".."}
            or not value.isprintable()
            or len(encoded) > MAX_ARCHIVE_NAME_BYTES
            or "/" in value
            or "\\" in value
            or Path(value).name != value
        ):
            raise ValueError("Archive name must be a bounded printable simple name")
        return value

    validate_simple(root_name)
    candidate = validate_simple(candidate)
    if receipt_bound and candidate != root_name:
        raise ValueError("Receipt-bound archive name must match the run root")
    return candidate


def _capture_archive_source_root(directory: str | Path) -> _OwnedArchiveSourceRoot:
    """
    Pin one safe archive source root and reject process-owned ancestors.

    After applying local validation, the function forwards ``directory`` to
    ``_OwnedArchiveSourceRoot`` and preserves its return and exception contract.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        directory: filesystem location used as the directory for this operation.

    Returns:
        A ``_OwnedArchiveSourceRoot`` representing capture archive source root.

    Raises:
        ValueError: If refusing to archive symbolic-link root: ``root``; the
            archive source root is not a real directory; archive source root
            contains the active process, executable, or archive implementation;
            or archive source deletion lacks symlink-safe rmtree.
    """

    root = Path(os.path.abspath(directory))
    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Refusing to archive symbolic-link root: {root}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("Archive source root must be a real directory")
    parent_metadata = root.parent.stat()

    protected_paths = {
        Path(os.path.abspath(os.getcwd())),
        Path(os.path.realpath(sys.executable)),
        Path(os.path.realpath(__file__)),
    }
    for protected in protected_paths:
        if protected == root or root in protected.parents:
            raise ValueError(
                "Archive source root contains the active process, executable, "
                "or archive implementation"
            )
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ValueError("Archive source deletion requires symlink-safe rmtree")
    return _OwnedArchiveSourceRoot(
        path=root,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        parent_device=parent_metadata.st_dev,
        parent_inode=parent_metadata.st_ino,
    )


def _archive_source_root_matches(source: _OwnedArchiveSourceRoot) -> bool:
    """
    Return whether the source pathname still names the approved inode.

    The implementation uses ``source`` to determine whether the source pathname
    still names the approved inode. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        source: Source object whose ``device``, ``inode``, ``lstat``,
            ``parent``, and ``parent_device`` state is read while performing
            source pathname still names the approved inode.

    Returns:
        Whether the source pathname still names the approved inode.
    """

    try:
        metadata = source.path.lstat()
        parent_metadata = source.path.parent.stat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_dev == source.device
        and metadata.st_ino == source.inode
        and parent_metadata.st_dev == source.parent_device
        and parent_metadata.st_ino == source.parent_inode
    )


def _delete_archive_source(source: _OwnedArchiveSourceRoot) -> None:
    """
    Delete only the descriptor-bound loose root approved at preflight.

    The implementation uses ``source`` to delete only the descriptor-bound loose
    root approved at preflight. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. If the function
    cannot delete only the descriptor-bound loose root approved at preflight,
    its exception reaches the caller instead of being converted into a
    successful result. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        source: Source object whose ``device``, ``inode``, ``name``, ``parent``,
            and ``parent_device`` state is read while performing delete only the
            descriptor-bound loose root approved at preflight.

    Raises:
        RuntimeError: If archive source parent identity changed; archive source
            root identity changed; archive source root changed while opening; or
            archive source root identity changed before removal.
    """

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(source.path.parent, directory_flags)
    root_fd = -1
    try:
        parent_metadata = os.fstat(parent_fd)
        if (
            parent_metadata.st_dev != source.parent_device
            or parent_metadata.st_ino != source.parent_inode
        ):
            raise RuntimeError("Archive source parent identity changed")
        visible = os.stat(
            source.path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(visible.st_mode)
            or visible.st_dev != source.device
            or visible.st_ino != source.inode
        ):
            raise RuntimeError("Archive source root identity changed")

        root_fd = os.open(source.path.name, directory_flags, dir_fd=parent_fd)
        opened = os.fstat(root_fd)
        if opened.st_dev != source.device or opened.st_ino != source.inode:
            raise RuntimeError("Archive source root changed while opening")

        for name in os.listdir(root_fd):
            child = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISDIR(child.st_mode):
                shutil.rmtree(name, dir_fd=root_fd)
            else:
                os.unlink(name, dir_fd=root_fd)

        visible = os.stat(
            source.path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if visible.st_dev != source.device or visible.st_ino != source.inode:
            raise RuntimeError("Archive source root identity changed before removal")
        os.rmdir(source.path.name, dir_fd=parent_fd)
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        os.close(parent_fd)


def _archive_preflight(
    directory: str | Path,
    name: Optional[str],
    *,
    expected_snapshot_leaf_digests: Optional[Sequence[ArchiveMemberDigest]],
    required_member_digests: Optional[Sequence[ArchiveMemberDigest]],
    limits: ArchiveLimits,
    excluded_source_paths: Optional[Sequence[str | Path]] = None,
) -> tuple[str, _OwnedArchiveSourceRoot]:
    """
    Validate all caller-controlled archive metadata before any mutation.

    Reject a pre-existing unsafe tree before bundle-mode metadata or source
    timestamps can be changed. The archive path is validated again after those
    intentional mutations so a concurrent replacement still fails closed at the
    write boundary.

    Args:
        directory: filesystem location used as the directory for this operation.
        name: Stable name used for lookup and operator-facing diagnostics.
        expected_snapshot_leaf_digests: Entries supplied as
            ``expected_snapshot_leaf_digests`` without transferring container
            ownership.
        required_member_digests: Entries supplied as ``required_member_digests``
            without transferring container ownership.
        excluded_source_paths: Optional exact lexical names which must remain
            absent from the source transaction.
        limits: Resolved finite limits governing source-tree admission.

    Returns:
        A tuple containing ``archive name`` and ``source root`` in that order.

    Raises:
        ArchiveValidationError: If archive preparation failed: ``error``; or
            archive source_validation failed: ``error``.
        ValueError: If archive source root identity changed during validation.
    """

    try:
        archive_name = _validated_archive_name(
            directory,
            name,
            receipt_bound=expected_snapshot_leaf_digests is not None,
        )
        _required_member_digest_map(
            expected_snapshot_leaf_digests,
            required_member_digests,
        )
        _normalized_archive_source_exclusions(
            directory,
            excluded_source_paths,
        )
    except ArchiveFinalizationError:
        raise
    except BaseException as error:
        if isinstance(error, CONTROL_FLOW_EXCEPTIONS):
            raise
        raise ArchiveValidationError(
            f"Archive preparation failed: {error}",
            phase="preparation",
        ) from error

    # Reject a pre-existing unsafe tree before bundle-mode metadata or source
    # timestamps can be changed.  The archive path is validated again after
    # those intentional mutations so a concurrent replacement still fails
    # closed at the write boundary.
    try:
        source_root = _capture_archive_source_root(directory)
        _validated_archive_files(
            directory,
            limits=limits,
            excluded_source_paths=excluded_source_paths,
        )
        if not _archive_source_root_matches(source_root):
            raise ValueError("Archive source root identity changed during validation")
    except ArchiveFinalizationError:
        raise
    except BaseException as error:
        if isinstance(error, CONTROL_FLOW_EXCEPTIONS):
            raise
        raise ArchiveValidationError(
            f"Archive source_validation failed: {error}",
            phase="source_validation",
        ) from error
    return archive_name, source_root


def _private_staging_leaf(parent: Path, final_name: str) -> _OwnedArchiveLeaf:
    """
    Create a randomized 0600 staging leaf beside its final target.

    After applying local validation, the function forwards ``parent`` and
    ``final_name`` to ``_OwnedArchiveLeaf`` and preserves its return and
    exception contract. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        parent: filesystem location used as the parent for this operation.
        final_name: Stable final name used for lookup and operator-facing
            diagnostics.

    Returns:
        A ``_OwnedArchiveLeaf`` representing private staging leaf.
    """

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{final_name}.stage-",
        dir=parent,
    )
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return _OwnedArchiveLeaf(Path(temporary_name), metadata.st_dev, metadata.st_ino)


def _owned_leaf_matches(owned: _OwnedArchiveLeaf) -> bool:
    """
    Return whether a visible path is still the inode created by this run.

    The implementation uses ``owned`` to determine whether a visible path is
    still the inode created by this run. Filesystem effects remain confined to
    the caller-selected paths and the owning resource lifecycle.

    Args:
        owned: Owned object whose ``device``, ``inode``, ``lstat``, and ``path``
            state is read while performing visible path is still the inode
            created by this run.

    Returns:
        Whether a visible path is still the inode created by this run.
    """

    try:
        metadata = owned.path.lstat()
    except FileNotFoundError:
        return False
    return metadata.st_dev == owned.device and metadata.st_ino == owned.inode


def _owned_leaf_from_path(path: str | Path) -> _OwnedArchiveLeaf:
    """
    Return the owned leaf from path.

    After applying local validation, the function forwards ``path`` to
    ``_OwnedArchiveLeaf`` and preserves its return and exception contract.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        A ``_OwnedArchiveLeaf`` representing owned leaf from path.
    """
    candidate = Path(path)
    metadata = candidate.lstat()
    return _OwnedArchiveLeaf(candidate, metadata.st_dev, metadata.st_ino)


def _unlink_owned_leaf(owned: _OwnedArchiveLeaf) -> None:
    """
    Unlink only the exact inode created by this archive transaction.

    The implementation uses ``owned`` to unlink only the exact inode created by
    this archive transaction. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        owned: Owned object whose ``path`` and ``unlink`` state is read while
            performing unlink only the exact inode created by this archive
            transaction.
    """

    if not _owned_leaf_matches(owned):
        return
    owned.path.unlink()


def _publish_archive_leaf_no_clobber(
    staging: _OwnedArchiveLeaf,
    final_path: Path,
) -> _OwnedArchiveLeaf:
    """
    Publish one staged inode under its exact final name without replacement.

    The implementation uses ``staging`` and ``final_path`` to publish one staged
    inode under its exact final name without replacement. Success is reported
    only after the owning output boundary has completed its required write or
    publication step. If the function cannot publish one staged inode under its
    exact final name without replacement, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        staging: Staging object whose ``device``, ``inode``, ``lstat``, and
            ``path`` state is read while performing one staged inode under its
            exact final name without replacement.
        final_path: filesystem location used as the final path for this
            operation.

    Returns:
        The validated ``final_owned``.

    Raises:
        ValueError: If archive staging leaf changed before publication; archive
            staging leaf is not a private regular file; archive final path
            changed during publication; or published archive leaf is not private
            and stable.
        BaseException: If a delegated failure occurs while the function attempts
            to publish one staged inode under its exact final name without
            replacement.
    """

    if not _owned_leaf_matches(staging):
        raise ValueError("Archive staging leaf changed before publication")
    metadata = staging.path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_nlink != 1
    ):
        raise ValueError("Archive staging leaf is not a private regular file")

    final_owned = _OwnedArchiveLeaf(final_path, staging.device, staging.inode)
    linked = False
    try:
        os.link(staging.path, final_path, follow_symlinks=False)
        linked = True
        _fsync_directory(final_path.parent)
        if not _owned_leaf_matches(final_owned):
            raise ValueError("Archive final path changed during publication")
        _unlink_owned_leaf(staging)
        _fsync_directory(final_path.parent)
        final_metadata = final_path.lstat()
        if (
            not _owned_leaf_matches(final_owned)
            or not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_nlink != 1
            or stat.S_IMODE(final_metadata.st_mode) & 0o077
        ):
            raise ValueError("Published archive leaf is not private and stable")
        return final_owned
    except BaseException as error:
        rollback_errors: list[BaseException] = []
        if linked:
            try:
                _unlink_owned_leaf(final_owned)
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)
            try:
                _fsync_directory(final_path.parent)
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)
        authoritative = select_authoritative_exception([error, *rollback_errors])
        try:
            setattr(authoritative, "owned_archive_leaf", final_owned)
            if rollback_errors:
                authoritative.add_note(
                    "Archive publication rollback also reported: "
                    + ", ".join(type(item).__name__ for item in rollback_errors[:16])
                )
        except BaseException:
            pass
        raise authoritative


def _remove_archive_outputs(
    owned_paths: Sequence[_OwnedArchiveLeaf],
    *,
    retained_paths: Sequence[str | Path] = (),
) -> list[BaseException]:
    """
    Remove only transaction-owned outputs without touching name collisions.

    The implementation uses ``owned_paths`` and ``retained_paths`` to remove
    only transaction-owned outputs without touching name collisions.

    Args:
        owned_paths: Filesystem locations processed in caller-provided order.
        retained_paths: filesystem location used as the retained paths for this
            operation.

    Returns:
        The validated ``errors``.
    """

    retained = {
        os.fspath(_normalized_archive_artifact_path(path)) for path in retained_paths
    }
    errors: list[BaseException] = []
    parents: set[Path] = set()
    for owned in owned_paths:
        candidate = owned.path
        parents.add(candidate.parent)
        if os.fspath(_normalized_archive_artifact_path(candidate)) in retained:
            continue
        try:
            _unlink_owned_leaf(owned)
        except BaseException as exc:
            errors.append(exc)
            quarantine = candidate.parent / (
                f".{candidate.name}.unbound-{secrets.token_hex(16)}"
            )
            try:
                if _owned_leaf_matches(owned):
                    os.replace(candidate, quarantine)
            except BaseException as quarantine_error:
                errors.append(quarantine_error)
    for parent in parents:
        try:
            _fsync_directory(parent)
        except BaseException as exc:
            errors.append(exc)
    return errors


def _source_snapshot_is_complete(
    root: Path,
    snapshot: Sequence[_ArchiveSourceLeaf],
    required_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    *,
    limits: Optional[ArchiveLimits] = None,
) -> bool:
    """
    Prove a failed archive still has the complete frozen loose tree.

    The implementation uses ``root``, ``snapshot``, and ``required_digests`` to
    prove a failed archive still has the complete frozen loose tree. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle. Cleanup in the ``finally`` path runs for successful, failed, and
    cancelled execution.

    Args:
        root: filesystem location used as the root for this operation.
        snapshot: Entries supplied as ``snapshot`` without transferring
            container ownership.
        required_digests: Optional required digests; ``None`` selects the
            function's default behavior.
        limits: Optional creation limits used to revalidate the retained loose
            tree; ``None`` selects the compatibility creation limits.

    Returns:
        Whether the prove a failed archive still has the complete frozen loose
        tree operation succeeds.
    """

    if not snapshot or not root.is_dir() or root.is_symlink():
        return False
    try:
        observed = _validated_archive_files(root, limits=limits)
    except BaseException:
        return False
    expected_by_path = {os.fspath(item.path): item.identity for item in snapshot}
    observed_by_path = {os.fspath(item.path): item.identity for item in observed}
    if observed_by_path != expected_by_path:
        return False
    try:
        required = _normalize_expected_leaf_digests(required_digests)
        snapshot_by_relative = {
            item.path.relative_to(root).as_posix(): item for item in observed
        }
        for relative_path, (expected_size, expected_sha256) in required.items():
            item = snapshot_by_relative.get(relative_path)
            if item is None:
                return False
            no_follow = getattr(os, "O_NOFOLLOW", None)
            if no_follow is None:
                return False
            descriptor = os.open(
                item.path,
                os.O_RDONLY
                | no_follow
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            try:
                before = os.fstat(descriptor)
                digest = hashlib.sha256()
                size = 0
                for chunk in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
                    size += len(chunk)
                    digest.update(chunk)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if (
                _source_leaf_identity(before) != item.identity
                or _source_leaf_identity(after) != item.identity
                or size != expected_size
                or digest.hexdigest() != expected_sha256
            ):
                return False
    except BaseException:
        return False
    return True


def _archive_source_exclusion_is_present(
    root: Path,
    excluded_source_paths: Optional[Sequence[str | Path]],
    *,
    limits: Optional[ArchiveLimits] = None,
) -> bool:
    """
    Return whether any excluded lexical source name has an occupant.

    Inspection failures are treated as occupied so archive recovery never
    deletes or relabels a source tree which may contain an unowned replacement.

    Args:
        root: Archive source root holding the excluded names.
        excluded_source_paths: Optional exact lexical source exclusions.
        limits: Optional limits governing exclusion validation.

    Returns:
        Whether an excluded source name exists or cannot be verified absent.
    """

    try:
        exclusions = _normalized_archive_source_exclusions(
            root,
            excluded_source_paths,
            limits=limits,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return True
    for excluded in exclusions:
        try:
            os.lstat(excluded)
        except FileNotFoundError:
            continue
        except OSError:
            return True
        return True
    return False


def _quarantine_owned_leaf(owned: _OwnedArchiveLeaf) -> bool:
    """
    Hide an owned final leaf, or make it unusable if rename is impossible.

    The implementation uses ``owned`` to hide an owned final leaf, or make it
    unusable if rename is impossible. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        owned: Owned object whose ``lstat``, ``name``, ``parent``, and ``path``
            state is read while performing hide an owned final leaf, or make it
            unusable if rename is impossible.

    Returns:
        Whether the hide an owned final leaf, or make it unusable if rename is
        impossible operation succeeds.
    """

    if not _owned_leaf_matches(owned):
        return True
    quarantine = owned.path.parent / (
        f".{owned.path.name}.unbound-{secrets.token_hex(16)}"
    )
    try:
        os.replace(owned.path, quarantine)
        _fsync_directory(owned.path.parent)
        return True
    except BaseException:
        try:
            if _owned_leaf_matches(owned):
                descriptor = os.open(
                    owned.path,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                )
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        metadata.st_dev != owned.device
                        or metadata.st_ino != owned.inode
                        or not stat.S_ISREG(metadata.st_mode)
                    ):
                        return False
                    os.fchmod(descriptor, 0)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                _fsync_directory(owned.path.parent)
            return not _owned_leaf_matches(owned) or (
                stat.S_IMODE(owned.path.lstat().st_mode) == 0
            )
        except BaseException:
            return False


def _scan_owned_directory_contents_fd(
    directory_fd: int,
    *,
    root_device: int,
    limits: ArchiveLimits,
    excluded_relative_paths: frozenset[str],
    depth: int = 0,
    relative_parts: tuple[str, ...] = (),
    remaining_entries: list[int] | None = None,
) -> dict[str, tuple[int, ...]]:
    """
    Read-only scan one quarantined source before any destructive traversal.

    The descriptor walk rejects every excluded name and unsafe filesystem type
    before returning the exact regular-leaf identities observed in the hidden
    owned root. Callers compare this complete snapshot with the archive source
    snapshot before allowing the first unlink.

    Args:
        directory_fd: Open descriptor for the current owned directory.
        root_device: Device identifier pinned for the archive source root.
        limits: Limits governing traversal depth and entry count.
        excluded_relative_paths: Exact source names which must remain untouched
            when occupied.
        depth: Current directory depth below the source root.
        relative_parts: Lexical current-directory components below the root.
        remaining_entries: Shared bounded entry counter.

    Returns:
        Mapping of relative regular-file names to stable source identities.

    Raises:
        OSError: If an exclusion is occupied, a source entry is unsafe, or a
            directory changes during the read-only scan.
        RuntimeError: If no-follow directory traversal is unavailable.
    """

    if depth > limits.max_path_depth:
        raise OSError("Archive source cleanup exceeded its depth limit")
    if remaining_entries is None:
        remaining_entries = [limits.max_path_nodes]
    names = os.listdir(directory_fd)
    remaining_entries[0] -= len(names)
    if remaining_entries[0] < 0:
        raise OSError("Archive source cleanup exceeded its entry limit")

    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_only = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_only is None:
        raise RuntimeError("Archive source cleanup requires no-follow directories")
    open_flags = os.O_RDONLY | no_follow | directory_only
    open_flags |= getattr(os, "O_CLOEXEC", 0)
    observed: dict[str, tuple[int, ...]] = {}
    directory_before = os.fstat(directory_fd)
    for name in sorted(names):
        relative_path = PurePosixPath(*relative_parts, name).as_posix()
        if relative_path in excluded_relative_paths:
            raise OSError(
                "Archive source cleanup found an excluded managed publication name"
            )
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_dev != root_device:
                raise OSError("Archive source cleanup refused a mounted subtree")
            child_fd = os.open(name, open_flags, dir_fd=directory_fd)
            try:
                opened = os.fstat(child_fd)
                if _source_leaf_identity(opened) != _source_leaf_identity(metadata):
                    raise OSError("Archive source directory changed during cleanup")
                observed.update(
                    _scan_owned_directory_contents_fd(
                        child_fd,
                        root_device=root_device,
                        limits=limits,
                        excluded_relative_paths=excluded_relative_paths,
                        depth=depth + 1,
                        relative_parts=(*relative_parts, name),
                        remaining_entries=remaining_entries,
                    )
                )
                visible = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if _source_leaf_identity(visible) != _source_leaf_identity(metadata):
                    raise OSError("Archive source directory changed during cleanup")
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError("Archive source cleanup found an unsafe source entry")
        observed[relative_path] = _source_leaf_identity(metadata)

    if _source_leaf_identity(os.fstat(directory_fd)) != _source_leaf_identity(
        directory_before
    ):
        raise OSError("Archive source directory changed during cleanup")
    return observed


def _delete_owned_directory_contents_fd(
    directory_fd: int,
    *,
    root_device: int,
    limits: ArchiveLimits,
    depth: int = 0,
    remaining_entries: list[int] | None = None,
    relative_parts: tuple[str, ...] = (),
    excluded_relative_paths: frozenset[str] = frozenset(),
    expected_leaf_identities: Optional[dict[str, tuple[int, ...]]] = None,
) -> None:
    """
    Delete one already-open owned tree without following path replacements.

    The implementation uses ``directory_fd``, ``root_device``, ``limits``,
    ``depth``, ``remaining_entries``, ``relative_parts``, and
    ``excluded_relative_paths``, and ``expected_leaf_identities`` to delete one
    already-open owned tree without following path replacements. Filesystem
    effects remain confined to the caller-selected paths and the owning
    resource lifecycle. If the function cannot delete one already-open owned
    tree without following path replacements, its exception reaches the caller
    instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        directory_fd: Numeric directory fd used while the operation performs
            bounded accounting.
        root_device: Numeric root device used while the operation performs
            bounded accounting.
        limits: Limits governing delete one already-open owned tree without
            following path replacements.
        depth: Numeric depth used while the operation performs bounded
            accounting.
        remaining_entries: Optional remaining entries; ``None`` selects the
            function's default behavior.
        relative_parts: Lexical directory components below the source root.
        excluded_relative_paths: Exact source names which cleanup must never
            remove when occupied.
        expected_leaf_identities: Optional exact regular-leaf snapshot approved
            before destructive traversal.

    Raises:
        OSError: If archive source cleanup exceeded its depth limit; archive
            source cleanup exceeded its entry limit; archive source cleanup
            refused a mounted subtree; or archive source directory changed
            during cleanup; or another input invariant is violated.
        RuntimeError: If archive source cleanup lacks no-follow directories.
    """

    if depth > limits.max_path_depth:
        raise OSError("Archive source cleanup exceeded its depth limit")
    if remaining_entries is None:
        remaining_entries = [limits.max_members]
    names = os.listdir(directory_fd)
    remaining_entries[0] -= len(names)
    if remaining_entries[0] < 0:
        raise OSError("Archive source cleanup exceeded its entry limit")

    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_only = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_only is None:
        raise RuntimeError("Archive source cleanup requires no-follow directories")
    open_flags = os.O_RDONLY | no_follow | directory_only
    open_flags |= getattr(os, "O_CLOEXEC", 0)

    for name in names:
        relative_path = PurePosixPath(*relative_parts, name).as_posix()
        if relative_path in excluded_relative_paths:
            raise OSError(
                "Archive source cleanup found an excluded managed publication name"
            )
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_dev != root_device:
                raise OSError("Archive source cleanup refused a mounted subtree")
            child_fd = os.open(name, open_flags, dir_fd=directory_fd)
            try:
                opened = os.fstat(child_fd)
                child_identity = (opened.st_dev, opened.st_ino)
                if child_identity != (metadata.st_dev, metadata.st_ino):
                    raise OSError("Archive source directory changed during cleanup")
                _delete_owned_directory_contents_fd(
                    child_fd,
                    root_device=root_device,
                    limits=limits,
                    depth=depth + 1,
                    remaining_entries=remaining_entries,
                    relative_parts=(*relative_parts, name),
                    excluded_relative_paths=excluded_relative_paths,
                    expected_leaf_identities=expected_leaf_identities,
                )
            finally:
                os.close(child_fd)
            visible = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (visible.st_dev, visible.st_ino) != child_identity:
                raise OSError("Archive source directory changed before removal")
            os.rmdir(name, dir_fd=directory_fd)
        else:
            if expected_leaf_identities is not None and (
                expected_leaf_identities.get(relative_path)
                != _source_leaf_identity(metadata)
            ):
                raise OSError("Archive source leaf changed before cleanup")
            # unlinkat removes only this directory entry. A symlink or hardlink
            # can never make cleanup traverse or erase its target.
            os.unlink(name, dir_fd=directory_fd)


def _quarantine_and_delete_archive_source(
    owned: _OwnedArchiveSourceRoot,
    *,
    limits: ArchiveLimits,
    excluded_source_paths: Optional[Sequence[str | Path]] = None,
    source_snapshot: Sequence[_ArchiveSourceLeaf] = (),
) -> None:
    """
    Atomically hide, identity-check, and descriptor-delete an owned source.

    The implementation uses ``owned``, ``limits``, and
    ``excluded_source_paths``, and ``source_snapshot`` to atomically hide,
    identity-check, and descriptor-delete an owned source. Filesystem effects
    remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot atomically hide, identity-check, and
    descriptor-delete an owned source, its exception reaches the caller instead
    of being converted into a successful result. Cleanup in the ``finally``
    path runs for successful, failed, and cancelled execution.

    Args:
        owned: Owned object whose ``device``, ``inode``, ``name``, ``parent``,
            and ``parent_device`` state is read while performing atomically
            hide, identity-check, and descriptor-delete an owned source.
        limits: Limits governing atomically hide, identity-check, and
            descriptor-delete an owned source.
        excluded_source_paths: Optional exact lexical names which cleanup must
            preserve when occupied.
        source_snapshot: Exact regular-leaf identities approved by final source
            revalidation.

    Raises:
        RuntimeError: If archive source cleanup lacks no-follow directories.
        OSError: If archive source parent identity changed before cleanup;
            archive source root was replaced before cleanup; archive source root
            changed during quarantine; or quarantined archive source identity
            changed; or another input invariant is violated.
    """

    parent = owned.path.parent
    source_name = owned.path.name
    absolute_exclusions = _normalized_archive_source_exclusions(
        owned.path,
        excluded_source_paths,
        limits=limits,
    )
    excluded_relative_paths = frozenset(
        Path(excluded).relative_to(owned.path).as_posix()
        for excluded in absolute_exclusions
    )
    expected_leaf_identities = {
        Path(os.path.abspath(os.path.normpath(os.fspath(item.path))))
        .relative_to(owned.path)
        .as_posix(): item.identity
        for item in source_snapshot
    }
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_only = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_only is None:
        raise RuntimeError("Archive source cleanup requires no-follow directories")
    parent_fd = os.open(
        parent,
        os.O_RDONLY | no_follow | directory_only | getattr(os, "O_CLOEXEC", 0),
    )
    quarantine_name = f".{source_name}.archive-delete-{secrets.token_hex(16)}"
    quarantine_fd: Optional[int] = None
    moved_to_quarantine = False
    try:
        opened_parent = os.fstat(parent_fd)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            owned.parent_device,
            owned.parent_inode,
        ):
            raise OSError("Archive source parent identity changed before cleanup")
        visible = os.stat(source_name, dir_fd=parent_fd, follow_symlinks=False)
        expected_identity = (owned.device, owned.inode)
        if (
            not stat.S_ISDIR(visible.st_mode)
            or (visible.st_dev, visible.st_ino) != expected_identity
        ):
            raise OSError("Archive source root was replaced before cleanup")

        os.rename(
            source_name,
            quarantine_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        moved_to_quarantine = True
        moved = os.stat(quarantine_name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(moved.st_mode)
            or (moved.st_dev, moved.st_ino) != expected_identity
        ):
            # A replacement raced the identity check. Never delete it. It is
            # retained under the private quarantine name as recovery evidence.
            raise OSError("Archive source root changed during quarantine")

        quarantine_fd = os.open(
            quarantine_name,
            os.O_RDONLY | no_follow | directory_only | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        opened = os.fstat(quarantine_fd)
        if (opened.st_dev, opened.st_ino) != expected_identity:
            raise OSError("Quarantined archive source identity changed")
        observed_leaf_identities = _scan_owned_directory_contents_fd(
            quarantine_fd,
            root_device=owned.device,
            limits=limits,
            excluded_relative_paths=excluded_relative_paths,
        )
        if observed_leaf_identities != expected_leaf_identities:
            raise OSError("Archive source changed before destructive cleanup")
        _delete_owned_directory_contents_fd(
            quarantine_fd,
            root_device=owned.device,
            limits=limits,
            excluded_relative_paths=excluded_relative_paths,
            expected_leaf_identities=expected_leaf_identities,
        )
        os.close(quarantine_fd)
        quarantine_fd = None
        final = os.stat(quarantine_name, dir_fd=parent_fd, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != expected_identity:
            raise OSError("Quarantined archive source changed before removal")
        os.rmdir(quarantine_name, dir_fd=parent_fd)
        moved_to_quarantine = False
        os.fsync(parent_fd)
    except BaseException as error:
        restore_errors: list[BaseException] = []
        if quarantine_fd is not None:
            os.close(quarantine_fd)
            quarantine_fd = None
        if moved_to_quarantine:
            try:
                moved = os.stat(
                    quarantine_name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if not stat.S_ISDIR(moved.st_mode) or (moved.st_dev, moved.st_ino) != (
                    owned.device,
                    owned.inode,
                ):
                    raise OSError(
                        "Quarantined archive source cannot be safely restored"
                    )
                try:
                    os.stat(source_name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise OSError("Archive source name is occupied during restore")
                os.rename(
                    quarantine_name,
                    source_name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                moved_to_quarantine = False
                os.fsync(parent_fd)
            except BaseException as restore_error:
                restore_errors.append(restore_error)
        authoritative = select_authoritative_exception((error, *restore_errors))
        if restore_errors:
            try:
                authoritative.add_note(
                    "Archive source restore also failed: "
                    + ", ".join(
                        type(restore_error).__name__
                        for restore_error in restore_errors[:16]
                    )
                )
            except BaseException:
                pass
        raise authoritative
    finally:
        if quarantine_fd is not None:
            os.close(quarantine_fd)
        os.close(parent_fd)


def _raise_archive_failure(
    error: BaseException,
    *,
    phase: str,
    directory: str | Path,
    zip_path: str | Path,
    outputs_started: bool,
    owned_output_paths: Sequence[_OwnedArchiveLeaf] = (),
    verified_archive_paths: list[str] | None = None,
    source_snapshot: Sequence[_ArchiveSourceLeaf] = (),
    required_loose_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    owned_source_root: Optional[_OwnedArchiveSourceRoot] = None,
    archive_limits: Optional[ArchiveLimits] = None,
    excluded_source_paths: Optional[Sequence[str | Path]] = None,
) -> None:
    """
    Raise one typed error after preserving the best available evidence.

    The implementation uses ``error``, ``phase``, ``directory``, ``zip_path``,
    and ``outputs_started`` to raise one typed error after preserving the best
    available evidence. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. If the function
    cannot raise one typed error after preserving the best available evidence,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        error: Exception or failure detail associated with the operation.
        phase: Text supplied as phase in the format accepted by this function.
        directory: filesystem location used as the directory for this operation.
        zip_path: filesystem location used as the ZIP path for this operation.
        outputs_started: Whether outputs started is enabled or required for this
            operation.
        owned_output_paths: Filesystem locations processed in caller-provided
            order.
        verified_archive_paths: Filesystem locations processed in
            caller-provided order.
        source_snapshot: Entries supplied as ``source_snapshot`` without
            transferring container ownership.
        required_loose_digests: Optional required loose digests; ``None``
            selects the function's default behavior.
        owned_source_root: Optional filesystem location used as the source for
            this operation.
        archive_limits: Optional Archive limits governing raise one typed error
            after preserving the best available evidence.
        excluded_source_paths: Optional exact lexical names which archive
            recovery must never delete or relabel when occupied.

    Raises:
        BaseException: If a delegated failure occurs while the function attempts
            to raise one typed error after preserving the best available
            evidence.
    """

    retained = list(verified_archive_paths or [])
    recovery_errors: list[BaseException] = []
    root = Path(directory)
    retained_exclusion = _archive_source_exclusion_is_present(
        root,
        excluded_source_paths,
        limits=archive_limits,
    )
    foreign_source_root = False
    if owned_source_root is not None:
        try:
            visible_root = root.lstat()
            visible_parent = root.parent.stat()
            foreign_source_root = (
                visible_root.st_dev,
                visible_root.st_ino,
                visible_parent.st_dev,
                visible_parent.st_ino,
            ) != (
                owned_source_root.device,
                owned_source_root.inode,
                owned_source_root.parent_device,
                owned_source_root.parent_inode,
            )
        except FileNotFoundError:
            pass
        except BaseException as identity_error:
            foreign_source_root = True
            recovery_errors.append(identity_error)
    if retained and owned_source_root is not None and not retained_exclusion:
        # rmtree may have been interrupted after deleting only part of the
        # source.  Such residue is never a valid loose representation once a
        # verified archive has been issued.
        try:
            _quarantine_and_delete_archive_source(
                owned_source_root,
                limits=resolve_archive_creation_limits(archive_limits),
                excluded_source_paths=excluded_source_paths,
                source_snapshot=source_snapshot,
            )
            _fsync_directory(root.parent)
        except BaseException as exc:
            recovery_errors.append(exc)
    if retained and root.exists():
        # Never advertise a verified archive while a competing loose name is
        # still visible. Hide every owned final (or chmod it unusable) and
        # suppress archive authority if the source cannot be eliminated.
        recovery_errors.extend(_remove_archive_outputs(owned_output_paths))
        unusable = all(
            _quarantine_owned_leaf(owned)
            for owned in owned_output_paths
            if os.fspath(owned.path) in retained
        )
        if not unusable:
            recovery_errors.append(
                RuntimeError("Could not make ambiguous archive outputs unusable")
            )
        retained = []
    elif outputs_started:
        recovery_errors.extend(
            _remove_archive_outputs(owned_output_paths, retained_paths=retained)
        )

    loose_retained = False
    if not retained and not outputs_started:
        # Source validation and metadata admission are deliberately completed
        # before any archive output begins.  A failure at that boundary must
        # not rename, delete, or otherwise quarantine user-owned evidence.
        loose_retained = root.exists() or root.is_symlink()
    elif (
        not retained
        and not retained_exclusion
        and not foreign_source_root
        and root.is_dir()
        and not root.is_symlink()
    ):
        if _source_snapshot_is_complete(
            root,
            source_snapshot,
            required_loose_digests,
            limits=archive_limits,
        ):
            try:
                _set_bundle_mode(root, "loose", limits=archive_limits)
                _validated_archive_files(root, limits=archive_limits)
                loose_retained = True
            except BaseException as exc:
                recovery_errors.append(exc)
        if (
            not loose_retained
            and owned_source_root is not None
            and _archive_source_root_matches(owned_source_root)
        ):
            quarantine = root.parent / (
                f".{root.name}.invalid-loose-{secrets.token_hex(16)}"
            )
            try:
                os.replace(root, quarantine)
                _fsync_directory(root.parent)
            except BaseException as exc:
                recovery_errors.append(exc)

    all_errors = [error, *recovery_errors]
    authoritative = select_authoritative_exception(all_errors)
    if isinstance(authoritative, CONTROL_FLOW_EXCEPTIONS):
        try:
            setattr(authoritative, "phase", phase)
            setattr(authoritative, "verified_archive_paths", tuple(retained))
            setattr(authoritative, "loose_bundle_retained", loose_retained)
            if recovery_errors:
                authoritative.add_note(
                    "Archive recovery also reported: "
                    + ", ".join(
                        type(recovery_error).__name__
                        for recovery_error in recovery_errors[:16]
                    )
                )
        except BaseException:
            pass
        raise authoritative
    try:
        rendered_error = str(authoritative)
    except BaseException as render_error:
        authoritative = select_authoritative_exception([authoritative, render_error])
        if isinstance(authoritative, CONTROL_FLOW_EXCEPTIONS):
            try:
                setattr(authoritative, "phase", phase)
                setattr(authoritative, "verified_archive_paths", tuple(retained))
                setattr(authoritative, "loose_bundle_retained", loose_retained)
            except BaseException:
                pass
            raise authoritative
        rendered_error = f"[{type(authoritative).__name__}]"
    message = f"Archive {phase} failed: {rendered_error}"
    if recovery_errors:
        message += "; recovery warnings: " + ", ".join(
            type(recovery_error).__name__ for recovery_error in recovery_errors[:16]
        )
    if isinstance(authoritative, OSError):
        error_type = ArchiveOperationError
    elif isinstance(authoritative, (ValueError, zipfile.BadZipFile)):
        error_type = ArchiveValidationError
    else:
        error_type = ArchiveOperationError

    wrapped = error_type(
        message,
        phase=phase,
        verified_archive_paths=retained,
    )
    wrapped.loose_bundle_retained = loose_retained
    raise wrapped from authoritative


def _find_chunked_archive_parts(base_dir: Path, archive_name: str) -> list[str]:
    """
    Return raw chunked archive parts in lexical volume order.

    The implementation uses ``base_dir`` and ``archive_name`` to produce raw
    chunked archive parts in lexical volume order.

    Args:
        base_dir: filesystem location used as the base dir for this operation.
        archive_name: Stable archive name used for lookup and operator-facing
            diagnostics.

    Returns:
        The chunked archive parts returned in operation-defined order.
    """
    part_pattern = re.compile(rf"^{re.escape(archive_name)}\.part(\d+)$")
    numbered_parts: list[tuple[int, str]] = []

    for entry in base_dir.iterdir():
        if not entry.is_file():
            continue
        match = part_pattern.fullmatch(entry.name)
        if match:
            numbered_parts.append((int(match.group(1)), str(entry)))

    numbered_parts.sort(key=lambda item: item[0])
    return [path for _, path in numbered_parts]


def _log_chunked_archive_instructions(archive_name: str, part_files: list[str]) -> None:
    """
    Log chunked archive part names and reconstruction instructions.

    The implementation uses ``archive_name`` and ``part_files`` to log chunked
    archive part names and reconstruction instructions.

    Args:
        archive_name: Stable archive name used for lookup and operator-facing
            diagnostics.
        part_files: Entries supplied as ``part_files`` without transferring
            container ownership.
    """
    logger.info("\nChunked ZIP parts created:")
    for part in part_files:
        logger.info(f"  {os.path.basename(part)}")

    logger.info("\nTo recombine the archive on Linux:")
    logger.info(f"  cat {archive_name}.part* > {archive_name}")
    logger.info("\nThen extract the reconstructed ZIP:")
    logger.info(f"  unzip {archive_name}")


def _split_file_into_chunks(zip_path: str, max_size_bytes: int) -> list[str]:
    """
    Split a complete ZIP file into raw chunks that can be reassembled with cat.

    This fallback does not create a multi-volume ZIP. It creates numbered chunks
    named <archive>.part001, <archive>.part002, ... so very old Linux systems
    can always reconstruct the original ZIP without relying on Info-ZIP
    split-archive support.

    Args:
        zip_path: filesystem location used as the ZIP path for this operation.
        max_size_bytes: Upper bound enforced for max size bytes; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        The validated ``part_files``.

    Raises:
        FileNotFoundError: If the function cannot split a complete ZIP file into
            raw chunks that can be reassembled with cat safely.
        ValueError: If the split size is not greater than 0; or split archive
            would require ``total_parts`` parts; maximum is
            ``MAX_SPLIT_ARCHIVE_PARTS``.
        BaseException: If a delegated failure occurs while the function attempts
            to split a complete ZIP file into raw chunks that can be reassembled
            with cat.
    """
    source_path = Path(zip_path)
    if not source_path.exists():
        raise FileNotFoundError(zip_path)
    if max_size_bytes <= 0:
        raise ValueError("Split size must be greater than 0")

    base_dir = source_path.parent
    archive_name = source_path.name
    total_parts = max(1, math.ceil(source_path.stat().st_size / max_size_bytes))
    if total_parts > MAX_SPLIT_ARCHIVE_PARTS:
        raise ValueError(
            f"split archive would require {total_parts} parts; "
            f"maximum is {MAX_SPLIT_ARCHIVE_PARTS}"
        )

    part_width = max(3, len(str(total_parts)))
    expected_names = [
        f"{archive_name}.part{part_number:0{part_width}d}"
        for part_number in range(1, total_parts + 1)
    ]
    staging, final_paths = _stage_split_chunks(
        source_path,
        max_size_bytes,
        expected_names,
    )
    published: list[_OwnedArchiveLeaf] = []
    predicted: list[_OwnedArchiveLeaf] = []
    try:
        _verify_raw_parts(
            source_path,
            [os.fspath(item.path) for item in staging],
            expected_part_names=expected_names,
            verify_names=False,
        )
        for item, final_path in zip(staging, final_paths):
            predicted_leaf = _OwnedArchiveLeaf(
                final_path,
                item.device,
                item.inode,
            )
            predicted.append(predicted_leaf)
            published.append(_publish_archive_leaf_no_clobber(item, final_path))
        _verify_raw_parts(source_path, [os.fspath(path) for path in final_paths])
        part_files = [os.fspath(path) for path in final_paths]
        _log_chunked_archive_instructions(archive_name, part_files)
        return part_files
    except BaseException as error:
        recovery_errors = _remove_archive_outputs([*staging, *predicted, *published])
        raise select_authoritative_exception([error, *recovery_errors])


def _stage_split_chunks(
    source_path: Path,
    max_size_bytes: int,
    expected_names: Sequence[str],
) -> tuple[list[_OwnedArchiveLeaf], list[Path]]:
    """
    Write raw parts into randomized 0600 leaves without publishing them.

    The implementation uses ``source_path``, ``max_size_bytes``, and
    ``expected_names`` to write raw parts into randomized 0600 leaves without
    publishing them. Success is reported only after the owning output boundary
    has completed its required write or publication step. If the function cannot
    write raw parts into randomized 0600 leaves without publishing them, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        source_path: filesystem location used as the source for this operation.
        max_size_bytes: Upper bound enforced for max size bytes; the consuming
            boundary rejects or truncates values that exceed it.
        expected_names: Entries supplied as ``expected_names`` without
            transferring container ownership.

    Returns:
        A tuple containing ``staging`` and ``final paths`` in that order.

    Raises:
        ValueError: If archive split produced fewer parts than expected; archive
            part staging leaf changed while writing; or archive split produced
            more parts than expected.
        BaseException: If a delegated failure occurs while the function attempts
            to write raw parts into randomized 0600 leaves without publishing
            them.
    """

    staging: list[_OwnedArchiveLeaf] = []
    final_paths = [source_path.parent / name for name in expected_names]
    try:
        with source_path.open("rb") as source:
            for expected_name in expected_names:
                chunk = source.read(max_size_bytes)
                if not chunk:
                    raise ValueError("Archive split produced fewer parts than expected")
                owned = _private_staging_leaf(source_path.parent, expected_name)
                staging.append(owned)
                with owned.path.open("wb") as destination:
                    destination.write(chunk)
                    destination.flush()
                    os.fsync(destination.fileno())
                if not _owned_leaf_matches(owned):
                    raise ValueError("Archive part staging leaf changed while writing")
            if source.read(1):
                raise ValueError("Archive split produced more parts than expected")
        _fsync_directory(source_path.parent)
        return staging, final_paths
    except BaseException as error:
        recovery_errors = _remove_archive_outputs(staging)
        raise select_authoritative_exception([error, *recovery_errors])


def safe_extract_zip(zip_ref: zipfile.ZipFile, extract_path: Union[str, Path]) -> None:
    """
    Compatibility wrapper for extracting an already-open ZIP.

    The historical public contract is best-effort: callers receive ``None`` and
    extraction failures are logged instead of raised. The shared primitive still
    validates the complete archive before writing and rolls back every entry it
    created if extraction fails. Security-sensitive internal callers that need a
    raising contract must call
    :func:`tool.utils.bounded_archive.extract_open_zip` directly.

    Args:
        zip_ref: ZIP ref consumed while the function attempts to compatibility
            wrapper for extracting an already-open ZIP.
        extract_path: filesystem location used as the extract path for this
            operation.
    """
    try:
        extract_open_zip(zip_ref, extract_path)
    except Exception as error:
        logger.warning(
            "ZIP extraction failed safely; created output was rolled back (%s)",
            error,
        )


def fix_file_timestamps(directory: str) -> None:
    """
    Best-effort bounded timestamp normalization for compatibility callers.

    Archive creation no longer mutates source timestamps: the ZIP writer applies
    one frozen timestamp directly to member headers. This retained helper uses
    the same bounded no-follow source policy for callers that still invoke it
    explicitly.

    Args:
        directory: filesystem location used as the directory for this operation.

    Raises:
        RuntimeError: If timestamp normalization lacks no-follow support.
        ValueError: If timestamp source root changed before update; timestamp
            normalization deadline exceeded; timestamp source changed before
            update; or timestamp source changed during update.
    """

    try:
        limits = resolve_archive_creation_limits()
        deadline = time.monotonic() + limits.max_seconds
        root = Path(directory)
        snapshot = _validated_archive_files(root, limits=limits)
        if not snapshot:
            return
        minimum_modified_ns = min(item.identity[5] for item in snapshot)
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None:
            raise RuntimeError("Timestamp normalization requires no-follow support")
        root_details = root.lstat()
        root_descriptor = os.open(
            root,
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            if _source_leaf_identity(os.fstat(root_descriptor)) != (
                _source_leaf_identity(root_details)
            ):
                raise ValueError("Timestamp source root changed before update")
            for item in snapshot:
                if time.monotonic() > deadline:
                    raise ValueError("Timestamp normalization deadline exceeded")
                parts = PurePosixPath(item.path.relative_to(root).as_posix()).parts
                parent_descriptor, descriptor = _open_relative_source_leaf(
                    root_descriptor,
                    parts,
                )
                try:
                    before = os.fstat(descriptor)
                    if _source_leaf_identity(before) != item.identity:
                        raise ValueError("Timestamp source changed before update")
                    try:
                        os.utime(
                            descriptor,
                            ns=(minimum_modified_ns, minimum_modified_ns),
                        )
                    except OSError:
                        continue
                    after = os.fstat(descriptor)
                    visible = os.stat(
                        parts[-1],
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    stable_fields = (0, 1, 2, 3, 4)
                    if (
                        any(
                            _source_leaf_identity(after)[index] != item.identity[index]
                            for index in stable_fields
                        )
                        or _source_leaf_identity(after)[5] != minimum_modified_ns
                        or _source_leaf_identity(visible)
                        != _source_leaf_identity(after)
                    ):
                        raise ValueError("Timestamp source changed during update")
                finally:
                    os.close(descriptor)
                    os.close(parent_descriptor)
        finally:
            os.close(root_descriptor)
    except Exception as error:
        logger.warning("Failed to normalize archive source timestamps: %s", error)


def create_zip(
    directory: str,
    name: Optional[str] = None,
    *,
    expected_snapshot_leaf_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    required_member_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    excluded_source_paths: Optional[Sequence[str | Path]] = None,
    archive_evidence_sink: Optional[ArchiveEvidenceSink] = None,
    archive_member_mode: Optional[int] = None,
    archive_limits: Optional[ArchiveLimits] = None,
    progress_callback: Optional[ArchiveProgressCallback] = None,
) -> str:
    """
    Create a zip archive from a directory.

    The implementation uses ``directory``, ``name``,
    ``expected_snapshot_leaf_digests``, ``required_member_digests``,
    ``excluded_source_paths``, and ``archive_evidence_sink`` to create a zip
    archive from a directory. If the function cannot create a zip archive from
    a directory, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        directory: filesystem location used as the directory for this operation.
        name: Stable name used for lookup and operator-facing diagnostics.
        expected_snapshot_leaf_digests: Optional expected snapshot leaf digests;
            ``None`` selects the function's default behavior.
        required_member_digests: Optional required member digests; ``None``
            selects the function's default behavior.
        excluded_source_paths: Optional exact lexical names which must remain
            absent from the source transaction.
        archive_evidence_sink: Optional archive evidence sink; ``None`` selects
            the function's default behavior.
        archive_member_mode: Optional sharing mode for regular ZIP members,
            retaining owner-private selection evidence and recording parent
            directories as 0755. ``None`` preserves source file modes.
        archive_limits: Optional creation limits; ``None`` selects the
            code-owned compatibility limits.
        progress_callback: Optional best-effort callback for archive stage and
            compression-byte progress.

    Returns:
        The validated ``zip_path``.

    Raises:
        ValueError: If archive source root changed before ZIP creation; or
            archive source changed while ZIP was created.
    """
    archive_member_mode = _validated_archive_member_mode(archive_member_mode)
    parent_path = Path(os.path.abspath(directory)).parent
    parent_of_directory = os.fspath(parent_path)
    archive_limits = resolve_archive_creation_limits(archive_limits)
    try:
        archive_name, source_root = _archive_preflight(
            directory,
            name,
            expected_snapshot_leaf_digests=expected_snapshot_leaf_digests,
            required_member_digests=required_member_digests,
            limits=archive_limits,
            excluded_source_paths=excluded_source_paths,
        )
    except ArchiveFinalizationError as error:
        # Preflight runs before any output or source mutation. Preserve that
        # affirmative lifecycle fact so the finalization owner can publish an
        # adjacent record without traversing the unvalidated loose bundle.
        source_path = Path(directory)
        error.loose_bundle_retained = bool(
            source_path.is_dir() and not source_path.is_symlink()
        )
        error.archive_source_validation_complete = False
        raise
    zip_path = os.fspath(parent_path / f"{archive_name}.zip")
    phase = "preparation"
    outputs_started = False
    verified_archive_paths: list[str] = []
    owned_output_paths: list[_OwnedArchiveLeaf] = []
    archive_files: list[_ArchiveSourceLeaf] = []
    owned_source_root: Optional[_OwnedArchiveSourceRoot] = source_root
    try:
        phase = "source_validation"
        _emit_archive_progress(progress_callback, "Scanning archive files")
        archive_files = _set_bundle_mode(
            directory,
            "zip",
            limits=archive_limits,
            excluded_source_paths=excluded_source_paths,
        )
        if not _archive_source_root_matches(owned_source_root):
            raise ValueError("Archive source root changed before ZIP creation")
        phase = "zip_write"
        outputs_started = True
        staging_zip = _private_staging_leaf(parent_path, Path(zip_path).name)
        owned_output_paths.append(staging_zip)
        _write_zip_archive(
            staging_zip.path,
            directory,
            archive_files,
            compression_level=9,
            expected_snapshot_leaf_digests=expected_snapshot_leaf_digests,
            required_member_digests=required_member_digests,
            archive_member_mode=archive_member_mode,
            limits=archive_limits,
            progress_callback=progress_callback,
        )
        phase = "source_revalidation"
        _emit_archive_progress(progress_callback, "Revalidating archive files")
        if (
            _validated_archive_files(
                directory,
                limits=archive_limits,
                excluded_source_paths=excluded_source_paths,
            )
            != archive_files
        ):
            raise ValueError("Archive source changed while ZIP was created")
        phase = "zip_verification"
        _emit_archive_progress(progress_callback, "Verifying ZIP archive")
        _verify_zip_archive(
            staging_zip.path,
            Path(directory).name,
            expected_snapshot_leaf_digests=expected_snapshot_leaf_digests,
            required_member_digests=required_member_digests,
            limits=archive_limits,
        )
        phase = "archive_durability"
        _fsync_directory(parent_of_directory)
        phase = "archive_publication"
        _emit_archive_progress(progress_callback, "Publishing ZIP archive")
        predicted_final = _OwnedArchiveLeaf(
            Path(zip_path), staging_zip.device, staging_zip.inode
        )
        owned_output_paths.append(predicted_final)
        published_zip = _publish_archive_leaf_no_clobber(
            staging_zip,
            Path(zip_path),
        )
        phase = "published_archive_verification"
        _verify_zip_archive(
            zip_path,
            Path(directory).name,
            expected_snapshot_leaf_digests=expected_snapshot_leaf_digests,
            required_member_digests=required_member_digests,
            limits=archive_limits,
        )
        verified_archive_paths = [zip_path]
        phase = "final_source_revalidation"
        if (
            _validated_archive_files(
                directory,
                limits=archive_limits,
                excluded_source_paths=excluded_source_paths,
            )
            != archive_files
        ):
            raise ValueError("Archive source changed before loose-source deletion")
        phase = "loose_source_deletion"
        _emit_archive_progress(progress_callback, "Finalizing ZIP archive")
        _quarantine_and_delete_archive_source(
            owned_source_root,
            limits=archive_limits,
            excluded_source_paths=excluded_source_paths,
            source_snapshot=archive_files,
        )
        phase = "loose_source_deletion_durability"
        _fsync_directory(parent_of_directory)
        phase = "archive_evidence"
        _issue_archive_evidence(verified_archive_paths, archive_evidence_sink)
        _emit_archive_progress(progress_callback, "ZIP archive complete", 1, 1)
        try:
            logger.info(f"Zip archive created at {os.path.abspath(zip_path)}")
        except BaseException:
            # The archive and source deletion are already durably committed.
            pass
        return zip_path
    except BaseException as error:
        try:
            logger.error(f"Error creating zip during {phase}: {error}")
        except BaseException:
            pass
        _raise_archive_failure(
            error,
            phase=phase,
            directory=directory,
            zip_path=zip_path,
            outputs_started=outputs_started,
            owned_output_paths=owned_output_paths,
            verified_archive_paths=verified_archive_paths,
            source_snapshot=archive_files,
            required_loose_digests=tuple(expected_snapshot_leaf_digests or ())
            + tuple(required_member_digests or ()),
            owned_source_root=owned_source_root,
            archive_limits=archive_limits,
            excluded_source_paths=excluded_source_paths,
        )


if "ArchiveFinalizationError" not in globals():

    class ArchiveFinalizationError(Exception):
        """
        Compatibility error for pre-transactional archive implementations.

        Callers receive this exception when the archive finalization error
        invariant prevents the requested operation from completing. The distinct
        type lets them handle that boundary without parsing an error message.
        """

        def __init__(
            self,
            message: str,
            *,
            phase: str,
            verified_archive_paths: list[str] | None = None,
        ) -> None:
            """
            Initialize an ``ArchiveFinalizationError`` instance.

            The initializer records ``phase`` and ``verified_archive_paths`` for
            later operations and establishes the instance invariants before any
            public method runs.

            Args:
                message: Operator-facing text carried by the reported event or
                    failure.
                phase: Text supplied as phase in the format accepted by this
                    function.
                verified_archive_paths: Filesystem locations processed in
                    caller-provided order.
            """
            super().__init__(message)
            self.phase = phase
            self.verified_archive_paths = tuple(verified_archive_paths or ())

        @property
        def verified_archive_retained(self) -> bool:
            """
            Whether a verified archive representation survived the failure.

            Each access computes the value from ``verified_archive_paths`` on
            the current instance; the derived view is not stored as independent
            state.

            Returns:
                Whether the whether a verified archive representation survived
                the failure operation succeeds.
            """

            return bool(self.verified_archive_paths)

    class ArchiveValidationError(ArchiveFinalizationError, ValueError):
        """
        The source tree or produced archive failed validation.

        Callers receive this exception when the archive validation error
        invariant prevents the requested operation from completing. The distinct
        type lets them handle that boundary without parsing an error message.
        """


def _validated_split_size_bytes(max_size_mb: float) -> int:
    """
    Return a safe raw-part size or fail before archive output begins.

    The implementation uses ``max_size_mb`` to produce a safe raw-part size or
    fail before archive output begins. If the function cannot produce a safe
    raw-part size or fail before archive output begins, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        max_size_mb: Upper bound enforced for max size mb; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        The validated ``max_size_bytes``.

    Raises:
        ArchiveValidationError: If the split threshold is not finite and at
            least ``MIN_ZIP_SPLIT_THRESHOLD_MB`` MB; or split threshold
            underflowed to zero bytes.
    """

    try:
        threshold_mb = float(max_size_mb)
    except (TypeError, ValueError, OverflowError) as error:
        raise ArchiveValidationError(
            "split threshold must be finite and at least "
            f"{MIN_ZIP_SPLIT_THRESHOLD_MB:g} MB",
            phase="preparation",
        ) from error

    if not math.isfinite(threshold_mb) or threshold_mb < MIN_ZIP_SPLIT_THRESHOLD_MB:
        raise ArchiveValidationError(
            "split threshold must be finite and at least "
            f"{MIN_ZIP_SPLIT_THRESHOLD_MB:g} MB",
            phase="preparation",
        )

    max_size_bytes = int(threshold_mb * 1024 * 1024)
    if max_size_bytes <= 0:
        raise ArchiveValidationError(
            "split threshold underflowed to zero bytes",
            phase="preparation",
        )
    return max_size_bytes


def create_zip_split(
    directory: str,
    name: Optional[str] = None,
    split: bool = False,
    max_size_mb: float = 200.0,
    compression_level: int = 9,
    *,
    expected_snapshot_leaf_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    required_member_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    excluded_source_paths: Optional[Sequence[str | Path]] = None,
    archive_evidence_sink: Optional[ArchiveEvidenceSink] = None,
    archive_member_mode: Optional[int] = None,
    archive_limits: Optional[ArchiveLimits] = None,
    progress_callback: Optional[ArchiveProgressCallback] = None,
) -> Union[str, list[str]]:
    """
    Create a zip archive and split it into parts if it exceeds a specified size.

    Uses maximum compression by default (ZIP_DEFLATED, compresslevel=9).
    When splitting is enabled, lifecycle metadata is written after diagnostic
    payloads. If the payload alone exceeds the threshold, its final split mode
    can be selected without compressing those payloads again. A bundle crossing
    the threshold only when metadata or ZIP directory records are added retains
    the verified rebuild path.

    Args:
        directory: filesystem location used as the directory for this operation.
        name: Stable name used for lookup and operator-facing diagnostics.
        split: Whether split is enabled or required for this operation.
        max_size_mb: Upper bound enforced for max size mb; the consuming
            boundary rejects or truncates values that exceed it.
        compression_level: Numeric compression level used while the operation
            performs bounded accounting.
        expected_snapshot_leaf_digests: Optional expected snapshot leaf digests;
            ``None`` selects the function's default behavior.
        required_member_digests: Optional required member digests; ``None``
            selects the function's default behavior.
        excluded_source_paths: Optional exact lexical names which must remain
            absent from the source transaction.
        archive_evidence_sink: Optional archive evidence sink; ``None`` selects
            the function's default behavior.
        archive_member_mode: Optional sharing mode for regular ZIP members,
            retaining owner-private selection evidence and recording parent
            directories as 0755. ``None`` preserves source file modes.
        archive_limits: Optional creation limits; ``None`` selects the
            code-owned compatibility limits.
        progress_callback: Optional best-effort callback for archive stage and
            compression-byte progress.

    Returns:
        The canonical ZIP split text.

    Raises:
        ValueError: If archive source root changed before ZIP creation; archive
            source changed while split ZIP was created; split archive would
            require ``total_parts`` parts; maximum is
            ``MAX_SPLIT_ARCHIVE_PARTS``; or archive source changed while ZIP was
            created.
    """
    archive_member_mode = _validated_archive_member_mode(archive_member_mode)
    parent_path = Path(os.path.abspath(directory)).parent
    parent_of_directory = os.fspath(parent_path)
    archive_limits = resolve_archive_creation_limits(archive_limits)
    try:
        archive_name, source_root = _archive_preflight(
            directory,
            name,
            expected_snapshot_leaf_digests=expected_snapshot_leaf_digests,
            required_member_digests=required_member_digests,
            limits=archive_limits,
            excluded_source_paths=excluded_source_paths,
        )
    except ArchiveFinalizationError as error:
        # Preflight runs before any output or source mutation. Preserve that
        # affirmative lifecycle fact so the finalization owner can publish an
        # adjacent record without traversing the unvalidated loose bundle.
        source_path = Path(directory)
        error.loose_bundle_retained = bool(
            source_path.is_dir() and not source_path.is_symlink()
        )
        error.archive_source_validation_complete = False
        raise
    zip_path = os.fspath(parent_path / f"{archive_name}.zip")

    max_size_bytes = _validated_split_size_bytes(max_size_mb)

    phase = "preparation"
    outputs_started = False
    verified_archive_paths: list[str] = []
    owned_output_paths: list[_OwnedArchiveLeaf] = []
    archive_files: list[_ArchiveSourceLeaf] = []
    owned_source_root: Optional[_OwnedArchiveSourceRoot] = source_root
    split_metadata_prepared = False

    def prepare_split_metadata(compressed_bytes: int) -> list[_ArchiveSourceLeaf]:
        """
        Select split mode once the compressed payload proves splitting necessary.

        The transaction rechecks the frozen source before updating lifecycle
        metadata, then accepts new identities only for those metadata leaves.
        Compressed diagnostic entries remain bound to their original identities
        and receipt digests throughout the normal verification/publication path.

        Args:
            compressed_bytes: Bytes already written to the private ZIP before
                lifecycle metadata and the central directory are appended.

        Returns:
            Validated root and per-DUT lifecycle metadata leaves to write last.

        Raises:
            ValueError: If source membership or a disallowed source identity
                changes while lifecycle metadata is being prepared.
            OSError: If metadata cannot be read or durably updated.

        Side Effects:
            May update bundle mode to ``split_zip``, refresh the owned metadata
            snapshot, and report the transaction's current phase and progress.
        """

        nonlocal archive_files, phase, split_metadata_prepared
        root = Path(directory)
        if compressed_bytes > max_size_bytes:
            phase = "split_metadata"
            _emit_archive_progress(progress_callback, "Preparing split ZIP metadata")
            archive_files = _set_bundle_mode(
                directory,
                "split_zip",
                limits=archive_limits,
                excluded_source_paths=excluded_source_paths,
                expected_source_snapshot=archive_files,
            )
            split_metadata_prepared = True
            phase = "zip_write"
        return [
            item
            for item in archive_files
            if _is_bundle_metadata_path(item.path.relative_to(root).as_posix())
        ]

    try:
        phase = "source_validation"
        _emit_archive_progress(progress_callback, "Scanning archive files")
        archive_files = _set_bundle_mode(
            directory,
            "zip",
            limits=archive_limits,
            excluded_source_paths=excluded_source_paths,
        )
        if not _archive_source_root_matches(owned_source_root):
            raise ValueError("Archive source root changed before ZIP creation")
        phase = "zip_write"
        outputs_started = True
        staging_zip = _private_staging_leaf(parent_path, Path(zip_path).name)
        owned_output_paths.append(staging_zip)
        _write_zip_archive(
            staging_zip.path,
            directory,
            archive_files,
            compression_level=compression_level,
            expected_snapshot_leaf_digests=expected_snapshot_leaf_digests,
            required_member_digests=required_member_digests,
            archive_member_mode=archive_member_mode,
            limits=archive_limits,
            progress_callback=progress_callback,
            prepare_metadata=prepare_split_metadata if split else None,
        )
        final_size = staging_zip.path.stat().st_size
        phase = "zip_verification"
        _emit_archive_progress(progress_callback, "Verifying ZIP archive")
        _verify_zip_archive(
            staging_zip.path,
            Path(directory).name,
            expected_snapshot_leaf_digests=expected_snapshot_leaf_digests,
            required_member_digests=required_member_digests,
            limits=archive_limits,
        )
        phase = "archive_durability"
        _fsync_directory(parent_of_directory)

        if split and final_size > max_size_bytes:
            if not split_metadata_prepared:
                phase = "split_metadata"
                _emit_archive_progress(progress_callback, "Preparing split ZIP archive")
                archive_files = _set_bundle_mode(
                    directory,
                    "split_zip",
                    limits=archive_limits,
                    excluded_source_paths=excluded_source_paths,
                    expected_source_snapshot=archive_files,
                )
                phase = "split_zip_write"
                _write_zip_archive(
                    staging_zip.path,
                    directory,
                    archive_files,
                    compression_level=compression_level,
                    expected_snapshot_leaf_digests=expected_snapshot_leaf_digests,
                    required_member_digests=required_member_digests,
                    archive_member_mode=archive_member_mode,
                    limits=archive_limits,
                    progress_callback=progress_callback,
                )
            phase = "split_source_revalidation"
            _emit_archive_progress(progress_callback, "Revalidating archive files")
            if (
                _validated_archive_files(
                    directory,
                    limits=archive_limits,
                    excluded_source_paths=excluded_source_paths,
                )
                != archive_files
            ):
                raise ValueError("Archive source changed while split ZIP was created")
            if not split_metadata_prepared:
                phase = "split_zip_verification"
                _emit_archive_progress(progress_callback, "Verifying split ZIP archive")
                _verify_zip_archive(
                    staging_zip.path,
                    Path(directory).name,
                    expected_snapshot_leaf_digests=expected_snapshot_leaf_digests,
                    required_member_digests=required_member_digests,
                    limits=archive_limits,
                )
            phase = "split_part_production"
            final_size = staging_zip.path.stat().st_size
            total_parts = max(1, math.ceil(final_size / max_size_bytes))
            if total_parts > MAX_SPLIT_ARCHIVE_PARTS:
                raise ValueError(
                    f"split archive would require {total_parts} parts; "
                    f"maximum is {MAX_SPLIT_ARCHIVE_PARTS}"
                )
            part_width = max(3, len(str(total_parts)))
            expected_part_names = [
                f"{Path(zip_path).name}.part{index:0{part_width}d}"
                for index in range(1, total_parts + 1)
            ]
            _emit_archive_progress(
                progress_callback,
                "Writing split ZIP parts",
                0,
                total_parts,
            )
            staged_parts, final_part_paths = _stage_split_chunks(
                staging_zip.path,
                max_size_bytes,
                expected_part_names,
            )
            _emit_archive_progress(
                progress_callback,
                "Writing split ZIP parts",
                total_parts,
                total_parts,
            )
            owned_output_paths.extend(staged_parts)
            phase = "split_part_verification"
            _verify_raw_parts(
                staging_zip.path,
                [os.fspath(item.path) for item in staged_parts],
                expected_part_names=expected_part_names,
                verify_names=False,
            )
            phase = "split_part_durability"
            _fsync_directory(parent_of_directory)
            phase = "split_part_publication"
            published_parts: list[_OwnedArchiveLeaf] = []
            for part_index, (staged_part, final_part) in enumerate(
                zip(staged_parts, final_part_paths),
                start=1,
            ):
                predicted_final = _OwnedArchiveLeaf(
                    final_part,
                    staged_part.device,
                    staged_part.inode,
                )
                owned_output_paths.append(predicted_final)
                published = _publish_archive_leaf_no_clobber(
                    staged_part,
                    final_part,
                )
                published_parts.append(published)
                _emit_archive_progress(
                    progress_callback,
                    "Publishing split ZIP parts",
                    part_index,
                    total_parts,
                )
            split_files = [os.fspath(path) for path in final_part_paths]
            phase = "published_split_verification"
            _verify_raw_parts(
                staging_zip.path,
                split_files,
                expected_part_names=expected_part_names,
            )
            # Pin and hash the complete final set before the intermediate ZIP
            # can disappear.
            issue_archive_artifact_digests(split_files)
            verified_archive_paths = list(split_files)
            phase = "split_intermediate_cleanup"
            _unlink_owned_leaf(staging_zip)
            _fsync_directory(parent_of_directory)
        else:
            phase = "source_revalidation"
            _emit_archive_progress(progress_callback, "Revalidating archive files")
            if (
                _validated_archive_files(
                    directory,
                    limits=archive_limits,
                    excluded_source_paths=excluded_source_paths,
                )
                != archive_files
            ):
                raise ValueError("Archive source changed while ZIP was created")
            phase = "archive_publication"
            _emit_archive_progress(progress_callback, "Publishing ZIP archive")
            predicted_final = _OwnedArchiveLeaf(
                Path(zip_path), staging_zip.device, staging_zip.inode
            )
            owned_output_paths.append(predicted_final)
            published_zip = _publish_archive_leaf_no_clobber(
                staging_zip,
                Path(zip_path),
            )
            phase = "published_archive_verification"
            _verify_zip_archive(
                zip_path,
                Path(directory).name,
                expected_snapshot_leaf_digests=expected_snapshot_leaf_digests,
                required_member_digests=required_member_digests,
                limits=archive_limits,
            )
            verified_archive_paths = [zip_path]

        phase = "final_source_revalidation"
        if (
            _validated_archive_files(
                directory,
                limits=archive_limits,
                excluded_source_paths=excluded_source_paths,
            )
            != archive_files
        ):
            raise ValueError("Archive source changed before loose-source deletion")
        phase = "loose_source_deletion"
        _emit_archive_progress(progress_callback, "Finalizing ZIP archive")
        _quarantine_and_delete_archive_source(
            owned_source_root,
            limits=archive_limits,
            excluded_source_paths=excluded_source_paths,
            source_snapshot=archive_files,
        )
        phase = "loose_source_deletion_durability"
        _fsync_directory(parent_of_directory)
        phase = "archive_evidence"
        _issue_archive_evidence(verified_archive_paths, archive_evidence_sink)
        _emit_archive_progress(progress_callback, "ZIP archive complete", 1, 1)
        if len(verified_archive_paths) > 1:
            return verified_archive_paths
        return verified_archive_paths[0]
    except BaseException as error:
        try:
            logger.error(f"Error creating split zip during {phase}: {error}")
        except BaseException:
            pass
        _raise_archive_failure(
            error,
            phase=phase,
            directory=directory,
            zip_path=zip_path,
            outputs_started=outputs_started,
            owned_output_paths=owned_output_paths,
            verified_archive_paths=verified_archive_paths,
            source_snapshot=archive_files,
            required_loose_digests=tuple(expected_snapshot_leaf_digests or ())
            + tuple(required_member_digests or ()),
            owned_source_root=owned_source_root,
            archive_limits=archive_limits,
            excluded_source_paths=excluded_source_paths,
        )


def split_zip(
    zip_path: str,
    max_size_bytes: int,
    *,
    limits: Optional[ArchiveLimits] = None,
) -> list[str]:
    """
    Split a ZIP archive into raw chunks that can be reassembled with cat.

    The implementation uses ``zip_path`` and ``max_size_bytes`` to split a ZIP
    archive into raw chunks that can be reassembled with cat. If the function
    cannot split a ZIP archive into raw chunks that can be reassembled with cat,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        zip_path: filesystem location used as the ZIP path for this operation.
        max_size_bytes: Upper bound enforced for max size bytes; the consuming
            boundary rejects or truncates values that exceed it.
        limits: Optional archive-creation limits; ``None`` resolves the shared
            operator-configurable finalization profile.

    Returns:
        The split ZIP returned in operation-defined order.

    Raises:
        FileNotFoundError: If the ZIP path does not exist.
        ArchiveValidationError: If the input cannot be proven to be a bounded,
            complete ZIP archive before chunking.
    """
    source_path = Path(zip_path)
    if not source_path.exists():
        raise FileNotFoundError(zip_path)

    active_limits = resolve_archive_creation_limits(limits)
    try:
        with source_path.open("rb") as source:
            result = validate_open_zip_stream_for_creation(
                source,
                limits=active_limits,
            )
    except (ArchivePolicyError, OSError, RuntimeError, ValueError) as error:
        raise ArchiveValidationError(
            f"Archive split_validation failed: {error}",
            phase="split_validation",
        ) from error
    if result.members == 0:
        return [str(source_path)]

    return _split_file_into_chunks(str(source_path), max_size_bytes)


def should_skip_collector(
    collector_id: str,
    skip_collectors: Optional[list] = None,
    include_collectors: Optional[list] = None,
) -> bool:
    """
    Determine if a collector should be skipped based on skip/include lists.

    Only run collectors that are in the include list.

    Args:
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        skip_collectors: Whether skip collectors is enabled or required for this
            operation.
        include_collectors: Whether include collectors is enabled or required
            for this operation.

    Returns:
        Whether the determine if a collector should be skipped based on
        skip/include lists operation succeeds.
    """
    # If include_collectors is specified, it takes precedence
    if include_collectors:
        # Only run collectors that are in the include list
        return collector_id not in include_collectors

    # If no include_collectors specified, check skip_collectors
    if skip_collectors and collector_id in skip_collectors:
        return True

    return False


def should_skip_zip_creation(skip_zip: bool, skip_zip_split: bool) -> bool:
    """
    Determine if zip creation should be skipped.

    The implementation uses ``skip_zip`` and ``skip_zip_split`` to determine if
    zip creation should be skipped.

    Args:
        skip_zip: Whether skip ZIP is enabled or required for this operation.
        skip_zip_split: Whether skip ZIP split is enabled or required for this
            operation.

    Returns:
        Whether the determine if zip creation should be skipped operation
        succeeds.
    """
    return skip_zip
