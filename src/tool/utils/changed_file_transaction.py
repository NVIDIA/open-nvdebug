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
Descriptor-pinned, restartable publication of changed bundle files only.

This module owns the changed file transaction boundary and exposes
``SnapshotFile``, ``SnapshotDirectory``, ``StagedReplacement``, ``_HashBudget``,
and ``_hit``. Keeping those contracts together gives importers one source of
truth for their validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from ..utils.filesystem_identity import filesystem_owner_uid

_SCHEMA = "open-nvdebug.changed-file-transaction/v1"
_STATE_DIRECTORY = ".nvdebug-sanitize-transactions"
_TEMP_IDENTITY_SCHEMA = "open-nvdebug.changed-file-temp-identity/v1"
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2
# Linux UAPI syscall numbers for the two supported LP64 release architectures.
# arch/x86/entry/syscalls/syscall_64.tbl and include/uapi/asm-generic/unistd.h.
_RENAMEAT2_SYSCALLS = {"x86_64": 316, "aarch64": 276}
_JOURNAL_LIMIT = 16 * 1024 * 1024
_TEMP_IDENTITY_LIMIT = 4096
_JOURNAL_PATH_LIMIT = 4 * 1024 * 1024
_FILE_SIZE_LIMIT = 16 * 1024 * 1024 * 1024
_RECOVERY_HASH_BYTES_LIMIT = 32 * 1024 * 1024 * 1024
_RECOVERY_WORK_LIMIT = 60_000
_ENTRY_LIMIT = 20_000
_EXPECTED_FILE_LIMIT = 40_000
_STATES = {"staging", "prepared", "committing", "committed"}
_FAILPOINT: Any = None


@dataclass(frozen=True)
class SnapshotFile:
    """
    Identity a changed source file must retain until publication.

    The immutable record keeps ``size``, ``sha256``, ``device``, ``inode``, and
    ``links`` together so consumers observe one snapshot file state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        size: Cumulative byte count represented by this record.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        device: Numeric device retained by this record.
        inode: Numeric inode retained by this record.
        links: Number of links represented by this record.
        mode: Numeric mode retained by this record.
        mtime_ns: Number of mtime ns represented by this record.
        ctime_ns: Number of ctime ns represented by this record.
    """

    size: int
    sha256: str
    device: int
    inode: int
    links: int
    mode: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class SnapshotDirectory:
    """
    Exact enumerated directory identity and its direct child namespace.

    The immutable record keeps ``device``, ``inode``, ``links``, ``mode``, and
    ``size`` together so consumers observe one snapshot directory state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        device: Numeric device retained by this record.
        inode: Numeric inode retained by this record.
        links: Number of links represented by this record.
        mode: Numeric mode retained by this record.
        size: Cumulative byte count represented by this record.
        mtime_ns: Number of mtime ns represented by this record.
        ctime_ns: Number of ctime ns represented by this record.
        children: Collection of children entries retained by this record.
    """

    device: int
    inode: int
    links: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    children: tuple[str, ...]


@dataclass(frozen=True)
class StagedReplacement:
    """
    Private spool file containing one final replacement payload.

    The immutable record keeps ``path``, ``size``, and ``sha256`` together so
    consumers observe one staged replacement state. Consumers receive the fields
    as one unit instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        size: Cumulative byte count represented by this record.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
    """

    path: Path
    size: int
    sha256: str


@dataclass
class _HashBudget:
    """
    Implement the hash budget boundary used by the NVDebug runtime.

    The coherent record keeps ``remaining_bytes`` and ``remaining_files``
    together so consumers observe one hash budget state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        remaining_bytes: Byte count recorded for remaining.
        remaining_files: Number of remaining files represented by this record.
    """

    remaining_bytes: int = _RECOVERY_HASH_BYTES_LIMIT
    remaining_files: int = _RECOVERY_WORK_LIMIT

    def charge(self, size: int) -> None:
        """
        Charge resource use against the configured budget.

        The implementation uses ``size`` to charge resource use against the
        configured budget. It updates ``remaining_bytes`` and
        ``remaining_files`` on the instance as part of that state transition. If
        the function cannot charge resource use against the configured budget,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Raises:
            ValueError: If transaction recovery hash budget exceeded.
        """
        if self.remaining_files <= 0 or size > self.remaining_bytes:
            raise ValueError("transaction recovery hash budget exceeded")
        self.remaining_files -= 1
        self.remaining_bytes -= size


def _hit(name: str) -> None:
    """
    Record a successful lookup or matching event.

    The implementation uses ``name`` to record a successful lookup or matching
    event.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.
    """
    if _FAILPOINT is not None:
        _FAILPOINT(name)


def _dir_flags() -> int:
    """
    Return the dir flags.

    The implementation uses current instance state to produce the dir flags.

    Returns:
        The numeric dir flags value.
    """
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags() -> int:
    """
    Return the file flags.

    The implementation uses current instance state to produce the file flags.

    Returns:
        The numeric file flags value.
    """
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _open_absolute_directory(path: Path) -> int:
    """
    Open absolute directory.

    The implementation uses ``path`` to open absolute directory.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The validated ``current``.
    """
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = os.open("/", _dir_flags())
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, _dir_flags(), dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _state_names(root_fd: int) -> tuple[str, str]:
    """
    Return the state names.

    The implementation uses ``root_fd`` to produce the state names.

    Args:
        root_fd: Numeric root fd used while the operation performs bounded
            accounting.

    Returns:
        A tuple containing ``message text`` and ``message text`` in that order.
    """
    metadata = os.fstat(root_fd)
    prefix = f"{metadata.st_dev:x}-{metadata.st_ino:x}"
    return f"{prefix}.json", f"{prefix}.next"


def _open_state_directory(root_fd: int, *, create: bool) -> int | None:
    """
    Open the trusted transaction namespace adjacent to the bundle root.

    The implementation uses ``root_fd`` and ``create`` to open the trusted
    transaction namespace adjacent to the bundle root. If the function cannot
    open the trusted transaction namespace adjacent to the bundle root, its
    exception reaches the caller instead of being converted into a successful
    result. Cleanup in the ``finally`` path runs for successful, failed, and
    cancelled execution.

    Args:
        root_fd: Numeric root fd used while the operation performs bounded
            accounting.
        create: Whether create is enabled or required for this operation.

    Returns:
        The validated ``state_fd``, or ``None`` when no value qualifies.

    Raises:
        ValueError: If transaction state directory is not private; or
            transaction state directory is on another filesystem.
    """

    parent_fd = os.open("..", _dir_flags(), dir_fd=root_fd)
    try:
        try:
            state_fd = os.open(_STATE_DIRECTORY, _dir_flags(), dir_fd=parent_fd)
        except FileNotFoundError:
            if not create:
                return None
            try:
                os.mkdir(_STATE_DIRECTORY, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
            else:
                os.fsync(parent_fd)
            state_fd = os.open(_STATE_DIRECTORY, _dir_flags(), dir_fd=parent_fd)
        metadata = os.fstat(state_fd)
        try:
            owner_uid = filesystem_owner_uid(state_fd, observed_uid=metadata.st_uid)
        except BaseException:
            os.close(state_fd)
            raise
        if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) & 0o077:
            os.close(state_fd)
            raise ValueError("transaction state directory is not private")
        if metadata.st_dev != os.fstat(root_fd).st_dev:
            os.close(state_fd)
            raise ValueError("transaction state directory is on another filesystem")
        return state_fd
    finally:
        os.close(parent_fd)


def _journal_path(root: str | Path) -> Path:
    """
    Return the sidecar journal path for diagnostics and focused tests.

    The implementation uses ``root`` to produce the sidecar journal path for
    diagnostics and focused tests. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        root: filesystem location used as the root for this operation.

    Returns:
        The validated journal path filesystem path.
    """

    root_path = Path(root)
    metadata = root_path.stat(follow_symlinks=False)
    name = f"{metadata.st_dev:x}-{metadata.st_ino:x}.json"
    return root_path.parent / _STATE_DIRECTORY / name


def _parts(relative: str) -> tuple[str, ...]:
    """
    Return the parts.

    The implementation uses ``relative`` to produce the parts. If the function
    cannot produce the parts, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        relative: Text supplied as relative in the format accepted by this
            function.

    Returns:
        The parts returned in operation-defined order.

    Raises:
        ValueError: If transaction path is unsafe.
    """
    pure = PurePosixPath(relative)
    raw = relative.split("/")
    if (
        not relative
        or len(os.fsencode(relative)) > 4096
        or pure.is_absolute()
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in raw)
    ):
        raise ValueError("transaction path is unsafe")
    return pure.parts


def _directory_parts(relative: str) -> tuple[str, ...]:
    """
    Return the directory parts.

    The implementation uses ``relative`` to produce the directory parts.

    Args:
        relative: Text supplied as relative in the format accepted by this
            function.

    Returns:
        The directory parts returned in operation-defined order.
    """
    if relative == ".":
        return ()
    return _parts(relative)


def _open_directory(root_fd: int, relative: str) -> int:
    """
    Open directory.

    The implementation uses ``root_fd`` and ``relative`` to open directory.

    Args:
        root_fd: Numeric root fd used while the operation performs bounded
            accounting.
        relative: Text supplied as relative in the format accepted by this
            function.

    Returns:
        The validated ``current``.
    """
    current = os.dup(root_fd)
    try:
        for part in _directory_parts(relative):
            child = os.open(part, _dir_flags(), dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _open_parent(root_fd: int, relative: str) -> tuple[int, str]:
    """
    Open parent.

    The implementation uses ``root_fd`` and ``relative`` to open parent.

    Args:
        root_fd: Numeric root fd used while the operation performs bounded
            accounting.
        relative: Text supplied as relative in the format accepted by this
            function.

    Returns:
        A tuple containing ``current`` and ``status or message text`` in that
        order.
    """
    parts = _parts(relative)
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, _dir_flags(), dir_fd=current)
            os.close(current)
            current = child
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def _write_all(fd: int, data: bytes) -> None:
    """
    Write all.

    The implementation uses ``fd`` and ``data`` to write all. Success is
    reported only after the owning output boundary has completed its required
    write or publication step. If the function cannot write all, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        fd: Numeric fd used while the operation performs bounded accounting.
        data: Bounded byte sequence supplied as data.

    Raises:
        OSError: If short transaction write.
    """
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:  # pragma: no cover - defensive OS contract guard
            raise OSError("short transaction write")
        offset += written


def _stat_key(metadata: os.stat_result) -> tuple[int, ...]:
    """
    Return the stat key.

    The implementation uses ``metadata`` to produce the stat key.

    Args:
        metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing stat
            key.

    Returns:
        A tuple containing ``st dev``, ``st ino``, ``st nlink``, ``st mode``,
        ``st size``, ``st mtime ns``, and ``st ctime ns`` in that order.
    """
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_open_file(
    fd: int,
    maximum: int,
    budget: _HashBudget | None = None,
) -> SnapshotFile:
    """
    Hash open file.

    After applying local validation, the function forwards ``fd``, ``maximum``,
    and ``budget`` to ``SnapshotFile`` and preserves its return and exception
    contract. Filesystem effects remain confined to the caller-selected paths
    and the owning resource lifecycle.

    Args:
        fd: Numeric fd used while the operation performs bounded accounting.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.
        budget: Optional budget; ``None`` selects the function's default
            behavior.

    Returns:
        A ``SnapshotFile`` representing open file.

    Raises:
        ValueError: If transaction source is not a bounded regular file;
            transaction source exceeds its declared size; or transaction source
            changed while hashing.
    """
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("transaction source is not a bounded regular file")
    if budget is not None:
        budget.charge(before.st_size)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, min(1024 * 1024, maximum - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise ValueError("transaction source exceeds its declared size")
        digest.update(chunk)
    after = os.fstat(fd)
    if _stat_key(before) != _stat_key(after) or total != before.st_size:
        raise ValueError("transaction source changed while hashing")
    return SnapshotFile(
        total,
        digest.hexdigest(),
        after.st_dev,
        after.st_ino,
        after.st_nlink,
        after.st_mode,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _identity_at(
    parent_fd: int,
    name: str,
    maximum: int,
    budget: _HashBudget | None = None,
) -> SnapshotFile | None:
    """
    Return the identity at.

    After applying local validation, the function forwards ``parent_fd``,
    ``name``, ``maximum``, and ``budget`` to ``_hash_open_file`` and preserves
    its return and exception contract. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.
        budget: Optional budget; ``None`` selects the function's default
            behavior.

    Returns:
        A ``SnapshotFile`` representing identity at, or ``None`` when the
        requested value is unavailable.
    """
    try:
        fd = os.open(name, _file_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    try:
        return _hash_open_file(fd, maximum, budget)
    finally:
        os.close(fd)


def _stable_matches(actual: SnapshotFile | None, expected: SnapshotFile) -> bool:
    """
    Return the stable matches.

    The implementation uses ``actual`` and ``expected`` to produce the stable
    matches.

    Args:
        actual: Optional actual; ``None`` selects the function's default
            behavior.
        expected: Expected object whose ``device``, ``inode``, ``links``,
            ``mode``, and ``mtime_ns`` state is read while performing stable
            matches.

    Returns:
        Whether the stable matches operation succeeds.
    """
    return actual is not None and (
        actual.size,
        actual.sha256,
        actual.device,
        actual.inode,
        actual.links,
        stat.S_IMODE(actual.mode),
        actual.mtime_ns,
    ) == (
        expected.size,
        expected.sha256,
        expected.device,
        expected.inode,
        expected.links,
        stat.S_IMODE(expected.mode),
        expected.mtime_ns,
    )


def _renameat2(
    source_fd: int,
    source: str,
    destination_fd: int,
    destination: str,
    flags: int,
) -> None:
    """
    Invoke ``renameat2`` with directory-relative validated paths.

    Prefer the libc wrapper when present. Glibc before 2.28 lacks that wrapper,
    so supported Linux LP64 runtimes invoke the same kernel operation through
    ``syscall``. Never emulate exchange or no-replace with separate renames:
    transaction publication and recovery depend on their atomic guarantees.

    Args:
        source_fd: Pinned directory descriptor containing the source entry.
        source: Validated directory-relative source name.
        destination_fd: Pinned directory descriptor for the destination entry.
        destination: Validated directory-relative destination name.
        flags: Kernel rename flags preserving exchange or no-replace semantics.

    Raises:
        RuntimeError: If the wrapper is missing and no reviewed syscall ABI is
            available for this process.
        OSError: If the kernel or filesystem rejects the atomic operation.

    Side Effects:
        Atomically exchanges or moves the selected directory entries.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    argument_types = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    arguments = (
        source_fd,
        os.fsencode(source),
        destination_fd,
        os.fsencode(destination),
        flags,
    )
    result_type = ctypes.c_int
    if renameat2 is None:
        if (
            sys.platform != "linux"
            or ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_long) != 8
        ):
            raise RuntimeError("atomic file exchange has no supported syscall ABI")
        number = _RENAMEAT2_SYSCALLS.get(os.uname().machine)
        renameat2 = getattr(libc, "syscall", None)
        if number is None or renameat2 is None:
            raise RuntimeError("atomic file exchange has no supported syscall ABI")
        argument_types.insert(0, ctypes.c_long)
        arguments = (number, *arguments)
        result_type = ctypes.c_long
    renameat2.argtypes = argument_types
    renameat2.restype = result_type
    if renameat2(*arguments) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _exchange(parent_fd: int, first: str, second: str) -> None:
    """
    Atomically exchange the prepared and published filesystem entries.

    The implementation uses ``parent_fd``, ``first``, and ``second`` to
    atomically exchange the prepared and published filesystem entries.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        first: Text supplied as first in the format accepted by this function.
        second: Text supplied as second in the format accepted by this function.
    """
    _renameat2(parent_fd, first, parent_fd, second, _RENAME_EXCHANGE)


def _rename_noreplace(
    source_fd: int,
    source: str,
    destination_fd: int,
    destination: str,
) -> None:
    """
    Rename a filesystem entry without replacing an existing target.

    The implementation uses ``source_fd``, ``source``, ``destination_fd``, and
    ``destination`` to rename a filesystem entry without replacing an existing
    target.

    Args:
        source_fd: Numeric source fd used while the operation performs bounded
            accounting.
        source: Text supplied as source in the format accepted by this function.
        destination_fd: Numeric destination fd used while the operation performs
            bounded accounting.
        destination: Text supplied as destination in the format accepted by this
            function.
    """
    _renameat2(
        source_fd,
        source,
        destination_fd,
        destination,
        _RENAME_NOREPLACE,
    )


def _journal_bytes(document: dict[str, Any]) -> bytes:
    """
    Return the journal bytes.

    The implementation uses ``document`` to produce the journal bytes. If the
    function cannot produce the journal bytes, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        document: Mapping supplying fields for journal bytes.

    Returns:
        The validated ``rendered``.

    Raises:
        ValueError: If transaction journal paths exceed their byte limit; or
            transaction journal exceeds its byte limit.
    """
    entries = document.get("entries")
    guards = document.get("guards")
    directory_guards = document.get("directory_guards")
    if (
        not isinstance(entries, list)
        or not isinstance(guards, list)
        or not isinstance(directory_guards, list)
        or len(entries) > _ENTRY_LIMIT
        or len(entries)
        + len(guards)
        + len(directory_guards)
        + sum(
            len(guard.get("identity", {}).get("children", ()))
            for guard in directory_guards
            if isinstance(guard, dict)
            and isinstance(guard.get("identity"), dict)
            and isinstance(guard.get("identity", {}).get("children"), (list, tuple))
        )
        > _EXPECTED_FILE_LIMIT
        or sum(
            len(os.fsencode(str(entry.get("path", ""))))
            + len(os.fsencode(str(entry.get("temporary", ""))))
            for entry in entries
            if isinstance(entry, dict)
        )
        + sum(
            len(os.fsencode(str(guard.get("path", ""))))
            for guard in guards
            if isinstance(guard, dict)
        )
        + sum(
            len(os.fsencode(str(guard.get("path", ""))))
            + sum(
                len(os.fsencode(str(name)))
                for name in guard.get("identity", {}).get("children", ())
            )
            for guard in directory_guards
            if isinstance(guard, dict) and isinstance(guard.get("identity"), dict)
        )
        > _JOURNAL_PATH_LIMIT
    ):
        raise ValueError("transaction journal paths exceed their byte limit")
    rendered = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if len(rendered) > _JOURNAL_LIMIT:
        raise ValueError("transaction journal exceeds its byte limit")
    return rendered


def _write_journal(
    state_fd: int,
    journal_name: str,
    next_name: str,
    document: dict[str, Any],
) -> None:
    """
    Write journal.

    The implementation uses ``state_fd``, ``journal_name``, ``next_name``, and
    ``document`` to write journal. Success is reported only after the owning
    output boundary has completed its required write or publication step.
    Cleanup in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        journal_name: Stable journal name used for lookup and operator-facing
            diagnostics.
        next_name: Stable next name used for lookup and operator-facing
            diagnostics.
        document: Mapping supplying fields for journal.
    """
    data = _journal_bytes(document)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        os.unlink(next_name, dir_fd=state_fd)
    except FileNotFoundError:
        pass
    fd = os.open(next_name, flags, 0o600, dir_fd=state_fd)
    try:
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(
        next_name,
        journal_name,
        src_dir_fd=state_fd,
        dst_dir_fd=state_fd,
    )
    os.fsync(state_fd)


def _read_bounded_json(
    state_fd: int,
    name: str,
    limit: int,
) -> dict[str, Any] | None:
    """
    Read bounded JSON.

    The implementation uses ``state_fd``, ``name``, and ``limit`` to read
    bounded JSON. Parsing or I/O must finish before the validated representation
    is made available to the caller. If the function cannot read bounded JSON,
    its exception reaches the caller instead of being converted into a
    successful result. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        The validated ``document``, or ``None`` when no value qualifies.

    Raises:
        ValueError: If transaction state is not a bounded regular file;
            transaction state exceeds its byte limit; transaction state changed
            while reading; or transaction state is malformed.
    """
    try:
        fd = os.open(name, _file_flags(), dir_fd=state_fd)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("transaction state is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0 and os.read(fd, 1):
            raise ValueError("transaction state exceeds its byte limit")
        after = os.fstat(fd)
    finally:
        os.close(fd)

    data = b"".join(chunks)
    if _stat_key(before) != _stat_key(after) or len(data) != before.st_size:
        raise ValueError("transaction state changed while reading")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """
        Reject duplicate keys.

        The implementation uses ``pairs`` to reject duplicate keys. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            pairs: Entries supplied as ``pairs`` without transferring container
                ownership.

        Returns:
            The validated ``document``.

        Raises:
            ValueError: If transaction state contains a duplicate key.
        """
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError("transaction state contains a duplicate key")
            document[key] = value
        return document

    document = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=reject_duplicate_keys,
    )
    if not isinstance(document, dict):
        raise ValueError("transaction state is malformed")
    return document


def _read_journal(state_fd: int, journal_name: str) -> dict[str, Any] | None:
    """
    Read journal.

    After applying local validation, the function forwards ``state_fd`` and
    ``journal_name`` to ``_read_bounded_json`` and preserves its return and
    exception contract. Parsing or I/O must finish before the validated
    representation is made available to the caller.

    Args:
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        journal_name: Stable journal name used for lookup and operator-facing
            diagnostics.

    Returns:
        A mapping containing journal, or ``None`` when the requested value is
        unavailable.
    """
    return _read_bounded_json(state_fd, journal_name, _JOURNAL_LIMIT)


def _snapshot_from_json(value: Any) -> SnapshotFile:
    """
    Return the snapshot from JSON.

    The implementation uses ``value`` to produce the snapshot from JSON. If the
    function cannot produce the snapshot from JSON, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        value: Value object whose ``get`` state is read while performing
            snapshot from JSON.

    Returns:
        The validated ``snapshot``.

    Raises:
        ValueError: If transaction journal identity is malformed.
    """
    if not isinstance(value, dict):
        raise ValueError("transaction journal identity is malformed")
    integer_fields = (
        "size",
        "device",
        "inode",
        "links",
        "mode",
        "mtime_ns",
        "ctime_ns",
    )
    if set(value) != {*integer_fields, "sha256"} or any(
        type(value.get(field)) is not int for field in integer_fields
    ):
        raise ValueError("transaction journal identity is malformed")
    try:
        snapshot = SnapshotFile(**value)
    except (TypeError, ValueError) as error:
        raise ValueError("transaction journal identity is malformed") from error
    if (
        snapshot.size < 0
        or snapshot.device < 0
        or snapshot.inode < 0
        or snapshot.links <= 0
        or snapshot.mode < 0
        or snapshot.size > _FILE_SIZE_LIMIT
        or not stat.S_ISREG(snapshot.mode)
        or not isinstance(snapshot.sha256, str)
        or len(snapshot.sha256) != 64
        or any(character not in "0123456789abcdef" for character in snapshot.sha256)
    ):
        raise ValueError("transaction journal identity is malformed")
    return snapshot


def _directory_snapshot_from_json(value: Any) -> SnapshotDirectory:
    """
    Return the directory snapshot from JSON.

    The implementation uses ``value`` to produce the directory snapshot from
    JSON. If the function cannot produce the directory snapshot from JSON, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        value: Value object whose ``get`` state is read while performing
            directory snapshot from JSON.

    Returns:
        The validated ``snapshot``.

    Raises:
        ValueError: If transaction journal directory identity is malformed.
    """
    if not isinstance(value, dict):
        raise ValueError("transaction journal directory identity is malformed")
    integer_fields = (
        "device",
        "inode",
        "links",
        "mode",
        "size",
        "mtime_ns",
        "ctime_ns",
    )
    if set(value) != {*integer_fields, "children"} or any(
        type(value.get(field)) is not int for field in integer_fields
    ):
        raise ValueError("transaction journal directory identity is malformed")
    children = value.get("children")
    if (
        not isinstance(children, (list, tuple))
        or any(
            not isinstance(name, str)
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or len(os.fsencode(name)) > 255
            for name in children
        )
        or list(children) != sorted(set(children))
    ):
        raise ValueError("transaction journal directory identity is malformed")
    try:
        snapshot = SnapshotDirectory(
            **{field: value[field] for field in integer_fields},
            children=tuple(children),
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "transaction journal directory identity is malformed"
        ) from error
    if (
        snapshot.device < 0
        or snapshot.inode < 0
        or snapshot.links <= 0
        or snapshot.mode < 0
        or snapshot.size < 0
        or not stat.S_ISDIR(snapshot.mode)
    ):
        raise ValueError("transaction journal directory identity is malformed")
    return snapshot


def _validated_document(
    document: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, SnapshotFile],
    dict[str, SnapshotDirectory],
    str,
]:
    """
    Return the validated document.

    The implementation uses ``document`` to produce the validated document. If
    the function cannot produce the validated document, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        document: Mapping supplying fields for validated document.

    Returns:
        A tuple containing ``validated``, ``guards``, ``directory guards``, and
        ``intent`` in that order.

    Raises:
        ValueError: If transaction journal is malformed; transaction journal
            entry count exceeds its limit; transaction journal directory guard
            is malformed; or transaction recovery work budget exceeded; or
            another input invariant is violated.
    """
    state = document.get("state")
    entries = document.get("entries")
    guard_values = document.get("guards")
    directory_guard_values = document.get("directory_guards")
    intent = document.get("intent")
    if (
        set(document)
        != {
            "schema",
            "root",
            "state",
            "intent",
            "entries",
            "guards",
            "directory_guards",
        }
        or document.get("schema") != _SCHEMA
        or state not in _STATES
        or not isinstance(entries, list)
        or not isinstance(guard_values, list)
        or not isinstance(directory_guard_values, list)
        or not isinstance(intent, str)
        or len(intent) != 64
        or any(character not in "0123456789abcdef" for character in intent)
    ):
        raise ValueError("transaction journal is malformed")
    if (
        len(entries) > _ENTRY_LIMIT
        or len(entries) + len(guard_values) + len(directory_guard_values)
        > _EXPECTED_FILE_LIMIT
    ):
        raise ValueError("transaction journal entry count exceeds its limit")
    if any(
        not isinstance(guard, dict)
        or not isinstance(guard.get("identity"), dict)
        or not isinstance(guard["identity"].get("children"), list)
        for guard in directory_guard_values
    ):
        raise ValueError("transaction journal directory guard is malformed")
    raw_child_count = sum(
        len(guard["identity"]["children"]) for guard in directory_guard_values
    )
    if (
        len(entries) + len(guard_values) + len(directory_guard_values) + raw_child_count
        > _EXPECTED_FILE_LIMIT
        or 2
        * (
            len(entries)
            + len(guard_values)
            + len(directory_guard_values)
            + raw_child_count
        )
        > _RECOVERY_WORK_LIMIT
    ):
        raise ValueError("transaction recovery work budget exceeded")
    root = document.get("root")
    if (
        not isinstance(root, dict)
        or set(root) != {"device", "inode"}
        or type(root.get("device")) is not int
        or type(root.get("inode")) is not int
        or root["device"] < 0
        or root["inode"] < 0
    ):
        raise ValueError("transaction journal root identity is malformed")
    seen_paths: set[str] = set()
    seen_temporaries: set[str] = set()
    validated: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "temporary",
            "original",
            "replacement",
            "staged",
        }:
            raise ValueError("transaction journal entry is malformed")
        relative = entry.get("path")
        temporary = entry.get("temporary")
        staged = entry.get("staged")
        if (
            not isinstance(relative, str)
            or not isinstance(temporary, str)
            or type(staged) is not bool
        ):
            raise ValueError("transaction journal entry is malformed")
        _parts(relative)
        if (
            "/" in temporary
            or "\\" in temporary
            or not temporary.startswith(".nvdebug-sanitize-")
            or relative in seen_paths
            or temporary in seen_temporaries
            or _parts(relative)[-1] == temporary
        ):
            raise ValueError("transaction journal entry is unsafe")
        seen_paths.add(relative)
        seen_temporaries.add(temporary)
        validated.append(
            {
                "path": relative,
                "temporary": temporary,
                "original": _snapshot_from_json(entry.get("original")),
                "replacement": _snapshot_from_json(entry.get("replacement")),
                "staged": staged,
            }
        )
    if state != "staging" and any(not entry["staged"] for entry in validated):
        raise ValueError("transaction journal has an unstaged replacement")
    guards: dict[str, SnapshotFile] = {}
    for guard in guard_values:
        if not isinstance(guard, dict) or set(guard) != {"path", "identity"}:
            raise ValueError("transaction journal guard is malformed")
        relative = guard.get("path")
        if not isinstance(relative, str):
            raise ValueError("transaction journal guard is malformed")
        _parts(relative)
        if relative in seen_paths or relative in guards:
            raise ValueError("transaction journal guard is duplicated")
        guards[relative] = _snapshot_from_json(guard.get("identity"))

    directory_guards: dict[str, SnapshotDirectory] = {}
    for guard in directory_guard_values:
        if not isinstance(guard, dict) or set(guard) != {"path", "identity"}:
            raise ValueError("transaction journal directory guard is malformed")
        relative = guard.get("path")
        if not isinstance(relative, str):
            raise ValueError("transaction journal directory guard is malformed")
        _directory_parts(relative)
        if relative in directory_guards:
            raise ValueError("transaction journal directory guard is duplicated")
        directory_guards[relative] = _directory_snapshot_from_json(
            guard.get("identity")
        )
    expected = {entry["path"]: entry["original"] for entry in validated}
    expected.update(guards)
    if directory_guards:
        if "." not in directory_guards or set(expected).intersection(directory_guards):
            raise ValueError("transaction journal namespace is malformed")
        declared_children = set(expected).union(directory_guards) - {"."}
        enumerated_children: set[str] = set()
        for relative, directory in directory_guards.items():
            prefix = "" if relative == "." else f"{relative}/"
            enumerated_children.update(f"{prefix}{name}" for name in directory.children)
        if enumerated_children != declared_children:
            raise ValueError("transaction journal namespace is incomplete")
    replacements = {entry["path"]: entry["replacement"] for entry in validated}
    intent_document = {
        "expected": [
            {"path": relative, "identity": asdict(expected[relative])}
            for relative in sorted(expected)
        ],
        "replacements": [
            {
                "path": relative,
                "size": replacements[relative].size,
                "sha256": replacements[relative].sha256,
            }
            for relative in sorted(replacements)
        ],
        "directories": [
            {
                "path": relative,
                "identity": asdict(directory_guards[relative]),
            }
            for relative in sorted(directory_guards)
        ],
    }
    recovered_intent = hashlib.sha256(
        json.dumps(intent_document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if recovered_intent != intent:
        raise ValueError("transaction journal intent does not describe its entries")

    path_bytes = sum(
        len(os.fsencode(entry["path"])) + len(os.fsencode(entry["temporary"]))
        for entry in validated
    ) + sum(len(os.fsencode(path)) for path in guards)
    path_bytes += sum(
        len(os.fsencode(path))
        + sum(len(os.fsencode(name)) for name in identity.children)
        for path, identity in directory_guards.items()
    )
    namespace_work = len(directory_guards) + sum(
        len(identity.children) for identity in directory_guards.values()
    )
    work = 2 * (len(validated) + len(guards) + namespace_work)
    hash_bytes = sum(
        entry["original"].size + entry["replacement"].size for entry in validated
    ) + 2 * sum(identity.size for identity in guards.values())
    if path_bytes > _JOURNAL_PATH_LIMIT:
        raise ValueError("transaction recovery path budget exceeded")
    if work > _RECOVERY_WORK_LIMIT:
        raise ValueError("transaction recovery work budget exceeded")
    if hash_bytes > _RECOVERY_HASH_BYTES_LIMIT:
        raise ValueError("transaction recovery hash budget exceeded")
    return validated, guards, directory_guards, intent


def _remove_if_present(parent_fd: int, name: str) -> None:
    """
    Remove the selected filesystem entry when it still exists.

    The implementation uses ``parent_fd`` and ``name`` to remove the selected
    filesystem entry when it still exists.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
    """
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass


def _root_identity(root_fd: int) -> dict[str, int]:
    """
    Return the root identity.

    The implementation uses ``root_fd`` to produce the root identity.

    Args:
        root_fd: Numeric root fd used while the operation performs bounded
            accounting.

    Returns:
        A mapping containing the ``device`` and ``inode`` fields.
    """
    metadata = os.fstat(root_fd)
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


def _state_file_bytes(document: dict[str, Any], limit: int) -> bytes:
    """
    Return the state file bytes.

    The implementation uses ``document`` and ``limit`` to produce the state file
    bytes. If the function cannot produce the state file bytes, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        document: Mapping supplying fields for state file bytes.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        The validated ``rendered``.

    Raises:
        ValueError: If transaction state exceeds its byte limit.
    """
    rendered = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if len(rendered) > limit:
        raise ValueError("transaction state exceeds its byte limit")
    return rendered


def _write_state_file(
    state_fd: int,
    name: str,
    document: dict[str, Any],
    limit: int,
) -> None:
    """
    Write state file.

    The implementation uses ``state_fd``, ``name``, ``document``, and ``limit``
    to write state file. Success is reported only after the owning output
    boundary has completed its required write or publication step. Cleanup in
    the ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        document: Mapping supplying fields for state file.
        limit: Numeric limit used while the operation performs bounded
            accounting.
    """
    data = _state_file_bytes(document, limit)
    next_name = f"{name}.next"
    _remove_if_present(state_fd, next_name)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = os.open(next_name, flags, 0o600, dir_fd=state_fd)
    try:
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(next_name, name, src_dir_fd=state_fd, dst_dir_fd=state_fd)
    os.fsync(state_fd)


def _entry_state_name(journal_name: str, temporary: str, kind: str) -> str:
    """
    Return the entry state name.

    The implementation uses ``journal_name``, ``temporary``, and ``kind`` to
    produce the entry state name.

    Args:
        journal_name: Stable journal name used for lookup and operator-facing
            diagnostics.
        temporary: Text supplied as temporary in the format accepted by this
            function.
        kind: Text supplied as kind in the format accepted by this function.

    Returns:
        The canonical entry state name.
    """
    root_prefix = journal_name.removesuffix(".json")
    suffix = hashlib.sha256(temporary.encode()).hexdigest()[:24]
    return f"{root_prefix}-{suffix}.{kind}"


def _write_temp_identity(
    state_fd: int,
    journal_name: str,
    root: dict[str, int],
    intent: str,
    relative: str,
    temporary: str,
    metadata: os.stat_result,
) -> None:
    """
    Write temp identity.

    The implementation uses ``state_fd``, ``journal_name``, ``root``,
    ``intent``, and ``relative`` to write temp identity. Success is reported
    only after the owning output boundary has completed its required write or
    publication step. If the function cannot write temp identity, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        journal_name: Stable journal name used for lookup and operator-facing
            diagnostics.
        root: filesystem location used as the root for this operation.
        intent: Text supplied as intent in the format accepted by this function.
        relative: Text supplied as relative in the format accepted by this
            function.
        temporary: Text supplied as temporary in the format accepted by this
            function.
        metadata: Metadata object whose ``st_dev``, ``st_ino``, ``st_mode``, and
            ``st_nlink`` state is read while performing temp identity.

    Raises:
        ValueError: If staged replacement is not a private regular file.
    """
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("staged replacement is not a private regular file")
    document = {
        "schema": _TEMP_IDENTITY_SCHEMA,
        "root": root,
        "intent": intent,
        "path": relative,
        "temporary": temporary,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "links": metadata.st_nlink,
    }
    _write_state_file(
        state_fd,
        _entry_state_name(journal_name, temporary, "temp.json"),
        document,
        _TEMP_IDENTITY_LIMIT,
    )


def _read_temp_identity(
    state_fd: int,
    journal_name: str,
    root: dict[str, int],
    intent: str,
    entry: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Read temp identity.

    The implementation uses ``state_fd``, ``journal_name``, ``root``,
    ``intent``, and ``entry`` to read temp identity. Parsing or I/O must finish
    before the validated representation is made available to the caller. If the
    function cannot read temp identity, its exception reaches the caller instead
    of being converted into a successful result.

    Args:
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        journal_name: Stable journal name used for lookup and operator-facing
            diagnostics.
        root: filesystem location used as the root for this operation.
        intent: Text supplied as intent in the format accepted by this function.
        entry: Mapping supplying fields for temp identity.

    Returns:
        The validated ``document``, or ``None`` when no value qualifies.

    Raises:
        ValueError: If transaction temporary identity is malformed.
    """
    name = _entry_state_name(journal_name, entry["temporary"], "temp.json")
    document = _read_bounded_json(state_fd, name, _TEMP_IDENTITY_LIMIT)
    if document is None:
        return None
    if (
        set(document)
        != {
            "schema",
            "root",
            "intent",
            "path",
            "temporary",
            "device",
            "inode",
            "links",
        }
        or document.get("schema") != _TEMP_IDENTITY_SCHEMA
        or document.get("root") != root
        or document.get("intent") != intent
        or document.get("path") != entry["path"]
        or document.get("temporary") != entry["temporary"]
        or any(
            type(document.get(field)) is not int
            for field in ("device", "inode", "links")
        )
        or document["device"] < 0
        or document["inode"] < 0
        or document["links"] != 1
    ):
        raise ValueError("transaction temporary identity is malformed")
    return document


def _lstat_at(parent_fd: int, name: str) -> os.stat_result | None:
    """
    Return the lstat at.

    After applying local validation, the function forwards ``parent_fd`` and
    ``name`` to ``os.stat`` and preserves its return and exception contract.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        A ``stat_result`` representing lstat at, or ``None`` when the requested
        value is unavailable.
    """
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _move_to_quarantine(
    source_fd: int,
    source_name: str,
    state_fd: int,
    quarantine_name: str,
) -> bool:
    """
    Return the move to quarantine.

    The implementation uses ``source_fd``, ``source_name``, ``state_fd``, and
    ``quarantine_name`` to produce the move to quarantine. Filesystem effects
    remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot produce the move to quarantine, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        source_fd: Numeric source fd used while the operation performs bounded
            accounting.
        source_name: Stable source name used for lookup and operator-facing
            diagnostics.
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        quarantine_name: Stable quarantine name used for lookup and
            operator-facing diagnostics.

    Returns:
        Whether the move to quarantine operation succeeds.

    Raises:
        ValueError: If transaction recovery quarantine is ambiguous.
    """
    source_exists = _lstat_at(source_fd, source_name) is not None
    quarantine_exists = _lstat_at(state_fd, quarantine_name) is not None
    if source_exists and quarantine_exists:
        raise ValueError("transaction recovery quarantine is ambiguous")
    if source_exists:
        _rename_noreplace(
            source_fd,
            source_name,
            state_fd,
            quarantine_name,
        )
        os.fsync(source_fd)
        os.fsync(state_fd)
        return True
    return quarantine_exists


def _restore_from_quarantine(
    state_fd: int,
    quarantine_name: str,
    parent_fd: int,
    target: str,
) -> None:
    """
    Restore from quarantine.

    The implementation uses ``state_fd``, ``quarantine_name``, ``parent_fd``,
    and ``target`` to restore from quarantine. Filesystem effects remain
    confined to the caller-selected paths and the owning resource lifecycle.

    Args:
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        quarantine_name: Stable quarantine name used for lookup and
            operator-facing diagnostics.
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        target: Text supplied as target in the format accepted by this function.
    """
    _rename_noreplace(state_fd, quarantine_name, parent_fd, target)
    os.fsync(parent_fd)
    os.fsync(state_fd)


def _unlink_authenticated(
    state_fd: int,
    quarantine_name: str,
    actual: SnapshotFile,
    expected: SnapshotFile,
) -> None:
    """
    Remove authenticated.

    The implementation uses ``state_fd``, ``quarantine_name``, ``actual``, and
    ``expected`` to remove authenticated. If the function cannot remove
    authenticated, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        quarantine_name: Stable quarantine name used for lookup and
            operator-facing diagnostics.
        actual: Actual consumed while the function attempts to remove
            authenticated.
        expected: Expected consumed while the function attempts to remove
            authenticated.

    Raises:
        ValueError: If transaction quarantine identity drifted.
    """
    if not _stable_matches(actual, expected):
        raise ValueError("transaction quarantine identity drifted")
    os.unlink(quarantine_name, dir_fd=state_fd)
    os.fsync(state_fd)


def _token_authenticates(
    actual: SnapshotFile,
    token: dict[str, Any],
) -> bool:
    """
    Return the token authenticates.

    The implementation uses ``actual`` and ``token`` to produce the token
    authenticates.

    Args:
        actual: Actual object whose ``device``, ``inode``, and ``links`` state
            is read while performing token authenticates.
        token: Sensitive value supplied through the approved input boundary and
            never logged.

    Returns:
        Whether the token authenticates operation succeeds.
    """
    return (actual.device, actual.inode, actual.links) == (
        token["device"],
        token["inode"],
        token["links"],
    )


def _unlink_token_authenticated(
    state_fd: int,
    quarantine_name: str,
    actual: SnapshotFile,
    token: dict[str, Any],
) -> None:
    """
    Remove token authenticated.

    The implementation uses ``state_fd``, ``quarantine_name``, ``actual``, and
    ``token`` to remove token authenticated. If the function cannot remove token
    authenticated, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        quarantine_name: Stable quarantine name used for lookup and
            operator-facing diagnostics.
        actual: Actual consumed while the function attempts to remove token
            authenticated.
        token: Sensitive value supplied through the approved input boundary and
            never logged.

    Raises:
        ValueError: If transaction temporary inode drifted during recovery.
    """
    if not _token_authenticates(actual, token):
        raise ValueError("transaction temporary inode drifted during recovery")
    os.unlink(quarantine_name, dir_fd=state_fd)
    os.fsync(state_fd)


def _recover_entry(
    root_fd: int,
    state_fd: int,
    journal_name: str,
    root: dict[str, int],
    intent: str,
    state: str,
    entry: dict[str, Any],
    budget: _HashBudget,
) -> None:
    """
    Recover one interrupted changed-file transaction entry.

    The implementation uses ``root_fd``, ``state_fd``, ``journal_name``,
    ``root``, and ``intent`` to recover one interrupted changed-file transaction
    entry. Filesystem effects remain confined to the caller-selected paths and
    the owning resource lifecycle. If the function cannot recover one
    interrupted changed-file transaction entry, its exception reaches the caller
    instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        root_fd: Numeric root fd used while the operation performs bounded
            accounting.
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        journal_name: Stable journal name used for lookup and operator-facing
            diagnostics.
        root: filesystem location used as the root for this operation.
        intent: Text supplied as intent in the format accepted by this function.
        state: Text supplied as state in the format accepted by this function.
        entry: Mapping supplying fields for recover one interrupted changed-file
            transaction entry.
        budget: Budget consumed while the function attempts to recover one
            interrupted changed-file transaction entry.

    Raises:
        ValueError: If transaction temporary inode drifted during recovery;
            transaction target identity drifted during recovery; committed
            transaction target identity drifted; or transaction replacement
            drifted during recovery; or another input invariant is violated.
    """
    parent_fd, target = _open_parent(root_fd, entry["path"])
    temporary = entry["temporary"]
    temp_quarantine = _entry_state_name(journal_name, temporary, "temp.q")
    target_quarantine = _entry_state_name(journal_name, temporary, "target.q")
    token_name = _entry_state_name(journal_name, temporary, "temp.json")
    token_next_name = f"{token_name}.next"
    original = entry["original"]
    replacement = entry["replacement"]
    maximum = max(original.size, replacement.size)
    try:
        temp_present = _move_to_quarantine(
            parent_fd,
            temporary,
            state_fd,
            temp_quarantine,
        )
        temp_identity = (
            _identity_at(state_fd, temp_quarantine, maximum, budget)
            if temp_present
            else None
        )
        unknown_temp = False
        temp_token: dict[str, Any] | None = None
        if state == "staging" and not entry["staged"]:
            temp_token = _read_temp_identity(
                state_fd,
                journal_name,
                root,
                intent,
                entry,
            )
            if temp_identity is not None and temp_token is None:
                unknown_temp = True
            elif temp_identity is not None and not _token_authenticates(
                temp_identity,
                temp_token,
            ):
                raise ValueError("transaction temporary inode drifted during recovery")
        elif state == "committing":
            if temp_identity is not None and not (
                _stable_matches(temp_identity, original)
                or _stable_matches(temp_identity, replacement)
            ):
                raise ValueError("transaction temporary inode drifted during recovery")
        else:
            expected_temp = original if state == "committed" else replacement
            if temp_identity is not None and not _stable_matches(
                temp_identity,
                expected_temp,
            ):
                raise ValueError("transaction temporary inode drifted during recovery")

        if unknown_temp:
            target_identity = _identity_at(parent_fd, target, original.size, budget)
            if target_identity != original:
                raise ValueError("transaction target identity drifted during recovery")
            _remove_if_present(state_fd, token_name)
            _remove_if_present(state_fd, token_next_name)
            os.fsync(state_fd)
            return

        if not temp_present and _lstat_at(state_fd, target_quarantine) is None:
            target_identity = _identity_at(parent_fd, target, maximum, budget)
            expected_target = replacement if state == "committed" else original
            if _stable_matches(target_identity, expected_target):
                _remove_if_present(state_fd, token_name)
                _remove_if_present(state_fd, token_next_name)
                os.fsync(state_fd)
                return

        target_present = _move_to_quarantine(
            parent_fd,
            target,
            state_fd,
            target_quarantine,
        )
        target_identity = (
            _identity_at(state_fd, target_quarantine, maximum, budget)
            if target_present
            else None
        )

        if state == "committed":
            if not _stable_matches(target_identity, replacement):
                raise ValueError("committed transaction target identity drifted")
            if temp_identity is not None:
                _unlink_authenticated(
                    state_fd,
                    temp_quarantine,
                    temp_identity,
                    original,
                )
            _restore_from_quarantine(
                state_fd,
                target_quarantine,
                parent_fd,
                target,
            )
        elif state in {"staging", "prepared"}:
            if not _stable_matches(target_identity, original):
                raise ValueError("transaction target identity drifted during recovery")
            if temp_identity is not None and not unknown_temp:
                if not entry["staged"]:
                    assert temp_token is not None
                    _unlink_token_authenticated(
                        state_fd,
                        temp_quarantine,
                        temp_identity,
                        temp_token,
                    )
                else:
                    _unlink_authenticated(
                        state_fd,
                        temp_quarantine,
                        temp_identity,
                        replacement,
                    )
            _restore_from_quarantine(
                state_fd,
                target_quarantine,
                parent_fd,
                target,
            )
        elif _stable_matches(target_identity, original):
            if temp_identity is not None and not _stable_matches(
                temp_identity,
                replacement,
            ):
                raise ValueError("transaction replacement drifted during recovery")
            if temp_identity is not None:
                _unlink_authenticated(
                    state_fd,
                    temp_quarantine,
                    temp_identity,
                    replacement,
                )
            _restore_from_quarantine(
                state_fd,
                target_quarantine,
                parent_fd,
                target,
            )
        elif _stable_matches(target_identity, replacement):
            if not _stable_matches(temp_identity, original):
                raise ValueError("transaction original disappeared during recovery")
            _unlink_authenticated(
                state_fd,
                target_quarantine,
                target_identity,
                replacement,
            )
            _restore_from_quarantine(
                state_fd,
                temp_quarantine,
                parent_fd,
                target,
            )
        elif target_identity is None and _stable_matches(temp_identity, original):
            _restore_from_quarantine(
                state_fd,
                temp_quarantine,
                parent_fd,
                target,
            )
        else:
            raise ValueError("transaction target identity drifted during recovery")
        _remove_if_present(state_fd, token_name)
        _remove_if_present(state_fd, token_next_name)
        os.fsync(state_fd)
    finally:
        os.close(parent_fd)


def _recover_locked(
    root_fd: int,
    state_fd: int,
    journal_name: str,
    next_name: str,
    expected_intent: str | None = None,
) -> str:
    """
    Return the recover locked.

    The implementation uses ``root_fd``, ``state_fd``, ``journal_name``,
    ``next_name``, and ``expected_intent`` to produce the recover locked.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot produce the recover
    locked, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        root_fd: Numeric root fd used while the operation performs bounded
            accounting.
        state_fd: Numeric state fd used while the operation performs bounded
            accounting.
        journal_name: Stable journal name used for lookup and operator-facing
            diagnostics.
        next_name: Stable next name used for lookup and operator-facing
            diagnostics.
        expected_intent: Optional expected intent; ``None`` selects the
            function's default behavior.

    Returns:
        The canonical recover locked text.

    Raises:
        ValueError: If transaction journal is bound to a different bundle root;
            or committed transaction intent does not match this invocation.
    """
    document = _read_journal(state_fd, journal_name)
    if document is None:
        _remove_if_present(state_fd, next_name)
        os.fsync(state_fd)
        return "none"
    if document.get("root") != _root_identity(root_fd):
        raise ValueError("transaction journal is bound to a different bundle root")
    entries, guards, directory_guards, intent = _validated_document(document)
    committed = document["state"] == "committed"
    if committed and expected_intent is not None and intent != expected_intent:
        raise ValueError("committed transaction intent does not match this invocation")
    budget = _HashBudget(
        remaining_bytes=_RECOVERY_HASH_BYTES_LIMIT,
        remaining_files=_RECOVERY_WORK_LIMIT,
    )
    mutable_directories, allowed_temporaries, allowed_missing_targets = (
        _transaction_directory_state(entries)
    )
    if committed:
        _validate_directory_guards(
            root_fd,
            directory_guards,
            mutable_directories=mutable_directories,
            allowed_temporary_names=allowed_temporaries,
            allowed_missing_names=allowed_missing_targets,
        )
        _validate_guards(root_fd, guards, budget)
    for entry in reversed(entries):
        _recover_entry(
            root_fd,
            state_fd,
            journal_name,
            document["root"],
            intent,
            document["state"],
            entry,
            budget,
        )
    _validate_guards(root_fd, guards, budget)
    _validate_directory_guards(
        root_fd,
        directory_guards,
        mutable_directories=mutable_directories,
    )
    _remove_if_present(state_fd, journal_name)
    _remove_if_present(state_fd, next_name)
    os.fsync(state_fd)
    return "committed" if committed else "rolled_back"


def recover_changed_file_transaction(root: str | Path) -> None:
    """
    Recover an interrupted transaction before inspecting the bundle.

    The implementation uses ``root`` to recover an interrupted transaction
    before inspecting the bundle. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        root: filesystem location used as the root for this operation.
    """

    root_fd = _open_absolute_directory(Path(root))
    try:
        fcntl.flock(root_fd, fcntl.LOCK_EX)
        state_fd = _open_state_directory(root_fd, create=False)
        if state_fd is not None:
            try:
                journal_name, next_name = _state_names(root_fd)
                _recover_locked(root_fd, state_fd, journal_name, next_name)
            finally:
                os.close(state_fd)
    finally:
        os.close(root_fd)


def _copy_spool_to_temporary(
    parent_fd: int,
    temporary: str,
    replacement: StagedReplacement,
    mode: int,
    opened: Callable[[os.stat_result], None] | None = None,
) -> SnapshotFile:
    """
    Copy spool to temporary.

    The implementation uses ``parent_fd``, ``temporary``, ``replacement``,
    ``mode``, and ``opened`` to copy spool to temporary. Filesystem effects
    remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot copy spool to temporary, its exception
    reaches the caller instead of being converted into a successful result.
    Cleanup in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        temporary: Text supplied as temporary in the format accepted by this
            function.
        replacement: Replacement object whose ``path``, ``sha256``, and ``size``
            state is read while performing copy spool to temporary.
        mode: Numeric mode used while the operation performs bounded accounting.
        opened: Optional opened; ``None`` selects the function's default
            behavior.

    Returns:
        The validated ``identity``.

    Raises:
        ValueError: If replacement spool is not a private regular file;
            replacement spool exceeds its declared size; replacement spool
            identity drifted; or staged replacement disappeared.
    """
    source_fd = os.open(replacement.path, _file_flags())
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        output_fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        try:
            if opened is not None:
                opened(os.fstat(output_fd))
            source_before = os.fstat(source_fd)
            if not stat.S_ISREG(source_before.st_mode) or source_before.st_nlink != 1:
                raise ValueError("replacement spool is not a private regular file")
            digest = hashlib.sha256()
            total = 0
            while chunk := os.read(source_fd, 1024 * 1024):
                total += len(chunk)
                if total > replacement.size:
                    raise ValueError("replacement spool exceeds its declared size")
                digest.update(chunk)
                _write_all(output_fd, chunk)
            source_after = os.fstat(source_fd)
            if _stat_key(source_before) != _stat_key(source_after) or (
                total,
                digest.hexdigest(),
            ) != (replacement.size, replacement.sha256):
                raise ValueError("replacement spool identity drifted")
            os.fchmod(output_fd, stat.S_IMODE(mode))
            os.fsync(output_fd)
        finally:
            os.close(output_fd)
    finally:
        os.close(source_fd)
    identity = _identity_at(parent_fd, temporary, replacement.size)
    if identity is None or identity.links != 1:
        raise ValueError("staged replacement disappeared")
    return identity


def _identity_for_relative(
    root_fd: int,
    relative: str,
    maximum: int,
    budget: _HashBudget | None = None,
) -> SnapshotFile | None:
    """
    Return the identity for relative.

    After applying local validation, the function forwards ``root_fd``,
    ``relative``, ``maximum``, and ``budget`` to ``_identity_at`` and preserves
    its return and exception contract. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        root_fd: Numeric root fd used while the operation performs bounded
            accounting.
        relative: Text supplied as relative in the format accepted by this
            function.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.
        budget: Optional budget; ``None`` selects the function's default
            behavior.

    Returns:
        A ``SnapshotFile`` representing identity for relative, or ``None`` when
        the requested value is unavailable.
    """
    parent_fd, target = _open_parent(root_fd, relative)
    try:
        return _identity_at(parent_fd, target, maximum, budget)
    finally:
        os.close(parent_fd)


def _validate_guards(
    root_fd: int,
    guards: Mapping[str, SnapshotFile],
    budget: _HashBudget | None = None,
) -> None:
    """
    Validate guards.

    The implementation uses ``root_fd``, ``guards``, and ``budget`` to validate
    guards. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        root_fd: Numeric root fd used while the operation performs bounded
            accounting.
        guards: Mapping supplying fields for guards.
        budget: Optional budget; ``None`` selects the function's default
            behavior.

    Raises:
        ValueError: If bundle transaction guard changed during publication.
    """
    for relative, expected in guards.items():
        try:
            actual = _identity_for_relative(root_fd, relative, expected.size, budget)
        except (OSError, ValueError) as error:
            raise ValueError(
                "bundle transaction guard changed during publication"
            ) from error
        if actual != expected:
            raise ValueError("bundle transaction guard changed during publication")


def _directory_metadata_matches(
    metadata: os.stat_result,
    expected: SnapshotDirectory,
    *,
    exact: bool,
) -> bool:
    """
    Return the directory metadata matches.

    The implementation uses ``metadata``, ``expected``, and ``exact`` to produce
    the directory metadata matches.

    Args:
        metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing
            directory metadata matches.
        expected: Expected object whose ``ctime_ns``, ``device``, ``inode``,
            ``links``, and ``mode`` state is read while performing directory
            metadata matches.
        exact: Whether exact is enabled or required for this operation.

    Returns:
        Whether the directory metadata matches operation succeeds.
    """
    stable_actual = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        stat.S_IMODE(metadata.st_mode),
    )
    stable_expected = (
        expected.device,
        expected.inode,
        expected.links,
        stat.S_IMODE(expected.mode),
    )
    if stable_actual != stable_expected or not stat.S_ISDIR(metadata.st_mode):
        return False
    return not exact or (
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    ) == (expected.size, expected.mtime_ns, expected.ctime_ns)


def _validate_directory_guards(
    root_fd: int,
    guards: Mapping[str, SnapshotDirectory],
    *,
    mutable_directories: set[str] | frozenset[str] = frozenset(),
    allowed_temporary_names: Mapping[str, set[str]] | None = None,
    allowed_missing_names: Mapping[str, set[str]] | None = None,
) -> None:
    """
    Validate directory guards.

    The implementation uses ``root_fd``, ``guards``, ``mutable_directories``,
    ``allowed_temporary_names``, and ``allowed_missing_names`` to validate
    directory guards. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path. Cleanup in the ``finally`` path runs for successful, failed, and
    cancelled execution.

    Args:
        root_fd: Numeric root fd used while the operation performs bounded
            accounting.
        guards: Mapping supplying fields for directory guards.
        mutable_directories: Entries supplied as ``mutable_directories`` without
            transferring container ownership.
        allowed_temporary_names: Optional allowed temporary names; ``None``
            selects the function's default behavior.
        allowed_missing_names: Optional allowed missing names; ``None`` selects
            the function's default behavior.

    Raises:
        ValueError: If directory namespace exceeds its guard; directory changed
            while enumerating; or bundle transaction namespace changed during
            publication.
    """
    allowed = allowed_temporary_names or {}
    allowed_missing = allowed_missing_names or {}
    for relative, expected in guards.items():
        permitted = allowed.get(relative, set())
        maximum_names = len(expected.children) + len(permitted)
        maximum_name_bytes = sum(
            len(os.fsencode(name)) for name in (*expected.children, *permitted)
        )
        try:
            descriptor = _open_directory(root_fd, relative)
            try:
                metadata = os.fstat(descriptor)
                discovered: list[str] = []
                discovered_bytes = 0
                with os.scandir(descriptor) as iterator:
                    for entry in iterator:
                        discovered.append(entry.name)
                        discovered_bytes += len(os.fsencode(entry.name))
                        if (
                            len(discovered) > maximum_names
                            or discovered_bytes > maximum_name_bytes
                        ):
                            raise ValueError("directory namespace exceeds its guard")
                names = tuple(sorted(discovered))
                after = os.fstat(descriptor)
                if _stat_key(metadata) != _stat_key(after):
                    raise ValueError("directory changed while enumerating")
            finally:
                os.close(descriptor)
        except (OSError, ValueError) as error:
            raise ValueError(
                "bundle transaction namespace changed during publication"
            ) from error
        visible_names = tuple(name for name in names if name not in permitted)
        missing = allowed_missing.get(relative, set())
        expected_name_set = set(expected.children)
        visible_name_set = set(visible_names)
        namespace_matches = (
            missing.issubset(expected_name_set)
            and visible_name_set.issubset(expected_name_set)
            and expected_name_set.difference(visible_name_set).issubset(missing)
        )
        if not namespace_matches or not _directory_metadata_matches(
            metadata,
            expected,
            exact=relative not in mutable_directories,
        ):
            raise ValueError("bundle transaction namespace changed during publication")


def _transaction_directory_state(
    entries: list[dict[str, Any]],
) -> tuple[set[str], dict[str, set[str]], dict[str, set[str]]]:
    """
    Return the transaction directory state.

    The implementation uses ``entries`` to produce the transaction directory
    state.

    Args:
        entries: Mapping supplying fields for transaction directory state.

    Returns:
        A tuple containing ``mutable``, ``allowed``, and ``targets`` in that
        order.
    """
    mutable: set[str] = set()
    allowed: dict[str, set[str]] = {}
    targets: dict[str, set[str]] = {}
    for entry in entries:
        pure = PurePosixPath(entry["path"])
        parent = pure.parent.as_posix()
        mutable.add(parent)
        allowed.setdefault(parent, set()).add(entry["temporary"])
        targets.setdefault(parent, set()).add(pure.name)
    return mutable, allowed, targets


def _validate_declared_inputs(
    expected_files: Mapping[str, SnapshotFile],
    expected_directories: Mapping[str, SnapshotDirectory],
    replacements: Mapping[str, StagedReplacement],
    *,
    require_replacements: bool,
) -> None:
    """
    Validate declared inputs.

    The implementation uses ``expected_files``, ``expected_directories``,
    ``replacements``, and ``require_replacements`` to validate declared inputs.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path.

    Args:
        expected_files: Mapping supplying fields for declared inputs.
        expected_directories: Mapping supplying fields for declared inputs.
        replacements: Mapping supplying fields for declared inputs.
        require_replacements: Whether require replacements is enabled or
            required for this operation.

    Raises:
        ValueError: If every replacement lacks an expected source identity;
            transaction file count exceeds its limit; transaction path is
            unsafe; or transaction directory path is unsafe; or another input
            invariant is violated.
    """
    replacement_paths = set(replacements)
    if (require_replacements and not replacements) or not replacement_paths.issubset(
        expected_files
    ):
        raise ValueError("every replacement requires an expected source identity")
    namespace_work = len(expected_directories) + sum(
        len(identity.children)
        for identity in expected_directories.values()
        if isinstance(identity, SnapshotDirectory)
    )
    if (
        len(replacements) > _ENTRY_LIMIT
        or len(expected_files) + namespace_work > _EXPECTED_FILE_LIMIT
    ):
        raise ValueError("transaction file count exceeds its limit")
    path_bytes = 0
    hash_bytes = 0
    for relative, expected in expected_files.items():
        if not isinstance(relative, str) or not isinstance(expected, SnapshotFile):
            raise ValueError("transaction path is unsafe")
        _parts(relative)
        path_bytes += len(os.fsencode(relative))
        validated = _snapshot_from_json(asdict(expected))
        hash_bytes += validated.size
    for relative, expected in expected_directories.items():
        if not isinstance(relative, str) or not isinstance(expected, SnapshotDirectory):
            raise ValueError("transaction directory path is unsafe")
        _directory_parts(relative)
        validated_directory = _directory_snapshot_from_json(asdict(expected))
        path_bytes += len(os.fsencode(relative)) + sum(
            len(os.fsencode(name)) for name in validated_directory.children
        )
    if expected_directories and "." not in expected_directories:
        raise ValueError("transaction root directory guard is missing")
    if expected_directories:
        if set(expected_files).intersection(expected_directories):
            raise ValueError("transaction namespace declaration overlaps")
        declared_children = set(expected_files).union(expected_directories) - {"."}
        enumerated_children: set[str] = set()
        for relative, directory in expected_directories.items():
            prefix = "" if relative == "." else f"{relative}/"
            enumerated_children.update(f"{prefix}{name}" for name in directory.children)
        if enumerated_children != declared_children:
            raise ValueError("transaction namespace declaration is incomplete")
    for relative in replacements:
        parent = PurePosixPath(relative).parent.as_posix()
        if expected_directories and parent not in expected_directories:
            raise ValueError("transaction replacement parent is not guarded")
    for relative, replacement in replacements.items():
        if (
            not isinstance(replacement, StagedReplacement)
            or type(replacement.size) is not int
            or replacement.size < 0
            or replacement.size > _FILE_SIZE_LIMIT
            or not isinstance(replacement.sha256, str)
            or len(replacement.sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in replacement.sha256
            )
        ):
            raise ValueError("replacement spool declaration is malformed")
        hash_bytes += replacement.size
        path_bytes += 64
    hash_bytes += sum(
        expected.size
        for relative, expected in expected_files.items()
        if relative not in replacement_paths
    )
    work = 2 * (len(expected_files) + namespace_work)
    if path_bytes > _JOURNAL_PATH_LIMIT:
        raise ValueError("transaction recovery path budget exceeded")
    if work > _RECOVERY_WORK_LIMIT:
        raise ValueError("transaction recovery work budget exceeded")
    if hash_bytes > _RECOVERY_HASH_BYTES_LIMIT:
        raise ValueError("transaction recovery hash budget exceeded")


def _intent_digest(
    expected_files: Mapping[str, SnapshotFile],
    replacements: Mapping[str, StagedReplacement],
    expected_directories: Mapping[str, SnapshotDirectory] | None = None,
) -> str:
    """
    Return the intent digest.

    After applying local validation, the function forwards ``expected_files``,
    ``replacements``, and ``expected_directories`` to ``hexdigest`` and
    preserves its return and exception contract.

    Args:
        expected_files: Mapping supplying fields for intent digest.
        replacements: Mapping supplying fields for intent digest.
        expected_directories: Optional expected directories; ``None`` selects
            the function's default behavior.

    Returns:
        The canonical intent digest.
    """
    directories = expected_directories or {}
    document = {
        "expected": [
            {"path": relative, "identity": asdict(expected_files[relative])}
            for relative in sorted(expected_files)
        ],
        "replacements": [
            {
                "path": relative,
                "size": replacements[relative].size,
                "sha256": replacements[relative].sha256,
            }
            for relative in sorted(replacements)
        ],
        "directories": [
            {"path": relative, "identity": asdict(directories[relative])}
            for relative in sorted(directories)
        ],
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _validate_replacement_spools(
    replacements: Mapping[str, StagedReplacement],
) -> None:
    """
    Validate replacement spools.

    The implementation uses ``replacements`` to validate replacement spools.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle. Cleanup in the ``finally`` path runs for successful, failed, and
    cancelled execution.

    Args:
        replacements: Mapping supplying fields for replacement spools.

    Raises:
        ValueError: If replacement spool identity drifted.
    """
    for replacement in replacements.values():
        fd = os.open(replacement.path, _file_flags())
        try:
            identity = _hash_open_file(fd, replacement.size)
        finally:
            os.close(fd)
        if (
            identity.size,
            identity.sha256,
            identity.links,
        ) != (replacement.size, replacement.sha256, 1):
            raise ValueError("replacement spool identity drifted")


def validate_unchanged_files(
    root: str | Path,
    expected_files: Mapping[str, SnapshotFile],
    expected_directories: Mapping[str, SnapshotDirectory],
) -> None:
    """
    Validate a complete read-only bundle snapshot before reporting success.

    The implementation uses ``root``, ``expected_files``, and
    ``expected_directories`` to validate a complete read-only bundle snapshot
    before reporting success. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path. Cleanup in the ``finally`` path runs for successful, failed,
    and cancelled execution.

    Args:
        root: filesystem location used as the root for this operation.
        expected_files: Mapping supplying fields for complete read-only bundle
            snapshot before reporting success.
        expected_directories: Mapping supplying fields for complete read-only
            bundle snapshot before reporting success.

    Raises:
        ValueError: If read-only bundle validation lacks namespace guards;
            transaction files must share the root filesystem; or transaction
            directories must share the root filesystem.
    """

    if not expected_directories:
        raise ValueError("read-only bundle validation requires namespace guards")
    _validate_declared_inputs(
        expected_files,
        expected_directories,
        {},
        require_replacements=False,
    )
    root_fd = _open_absolute_directory(Path(root))
    state_fd: int | None = None
    try:
        fcntl.flock(root_fd, fcntl.LOCK_EX)
        journal_name, next_name = _state_names(root_fd)
        state_fd = _open_state_directory(root_fd, create=False)
        if state_fd is not None:
            _recover_locked(root_fd, state_fd, journal_name, next_name)
        root_device = os.fstat(root_fd).st_dev
        if any(expected.device != root_device for expected in expected_files.values()):
            raise ValueError("transaction files must share the root filesystem")
        if any(
            expected.device != root_device for expected in expected_directories.values()
        ):
            raise ValueError("transaction directories must share the root filesystem")
        _validate_directory_guards(root_fd, expected_directories)
        _validate_guards(root_fd, expected_files)
        _validate_directory_guards(root_fd, expected_directories)
    finally:
        if state_fd is not None:
            os.close(state_fd)
        os.close(root_fd)


def publish_changed_files(
    root: str | Path,
    expected_files: Mapping[str, SnapshotFile],
    replacements: Mapping[str, StagedReplacement],
    expected_directories: Mapping[str, SnapshotDirectory] | None = None,
) -> None:
    """
    Publish only the requested changed files with rollback and recovery.

    The implementation uses ``root``, ``expected_files``, ``replacements``, and
    ``expected_directories`` to publish only the requested changed files with
    rollback and recovery. Success is reported only after the owning output
    boundary has completed its required write or publication step. If the
    function cannot publish only the requested changed files with rollback and
    recovery, its exception reaches the caller instead of being converted into a
    successful result. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        root: filesystem location used as the root for this operation.
        expected_files: Mapping supplying fields for only the requested changed
            files with rollback and recovery.
        replacements: Mapping supplying fields for only the requested changed
            files with rollback and recovery.
        expected_directories: Optional expected directories; ``None`` selects
            the function's default behavior.

    Raises:
        ValueError: If transaction files must share the root filesystem;
            transaction directories must share the root filesystem; transaction
            entry changed before exchange; or transaction entry drifted during
            exchange.
        RuntimeError: If changed-file transaction failed and recovery is
            incomplete.
    """

    directories = expected_directories or {}
    _validate_declared_inputs(
        expected_files,
        directories,
        replacements,
        require_replacements=True,
    )
    replacement_paths = set(replacements)
    guards = {
        relative: expected
        for relative, expected in expected_files.items()
        if relative not in replacement_paths
    }
    intent = _intent_digest(expected_files, replacements, directories)
    root_fd = _open_absolute_directory(Path(root))
    state_fd: int | None = None
    committed = False
    transaction_started = False
    try:
        fcntl.flock(root_fd, fcntl.LOCK_EX)
        journal_name, next_name = _state_names(root_fd)
        state_fd = _open_state_directory(root_fd, create=False)
        if state_fd is not None:
            initial_outcome = _recover_locked(
                root_fd,
                state_fd,
                journal_name,
                next_name,
                intent,
            )
            if initial_outcome == "committed":
                return
        root_device = os.fstat(root_fd).st_dev
        if any(expected.device != root_device for expected in expected_files.values()):
            raise ValueError("transaction files must share the root filesystem")
        if any(expected.device != root_device for expected in directories.values()):
            raise ValueError("transaction directories must share the root filesystem")
        _validate_directory_guards(root_fd, directories)
        _validate_guards(root_fd, expected_files)
        _validate_replacement_spools(replacements)
        if state_fd is None:
            state_fd = _open_state_directory(root_fd, create=True)
            assert state_fd is not None
        transaction_id = os.urandom(12).hex()
        entries: list[dict[str, Any]] = []
        for index, relative in enumerate(sorted(replacements)):
            expected = expected_files[relative]
            entries.append(
                {
                    "path": relative,
                    "temporary": f".nvdebug-sanitize-{transaction_id}-{index}.tmp",
                    "original": asdict(expected),
                    "replacement": {
                        "size": replacements[relative].size,
                        "sha256": replacements[relative].sha256,
                        "device": 0,
                        "inode": 0,
                        "links": 1,
                        "mode": expected.mode,
                        "mtime_ns": 0,
                        "ctime_ns": 0,
                    },
                    "staged": False,
                }
            )
        document = {
            "schema": _SCHEMA,
            "root": _root_identity(root_fd),
            "state": "staging",
            "intent": intent,
            "entries": entries,
            "guards": [
                {"path": relative, "identity": asdict(guards[relative])}
                for relative in sorted(guards)
            ],
            "directory_guards": [
                {"path": relative, "identity": asdict(directories[relative])}
                for relative in sorted(directories)
            ],
        }
        mutable_directories, allowed_temporaries, _targets = (
            _transaction_directory_state(entries)
        )
        transaction_started = True
        _write_journal(state_fd, journal_name, next_name, document)
        for entry in entries:
            parent_fd, _target = _open_parent(root_fd, entry["path"])
            try:

                def record_identity(
                    metadata: os.stat_result,
                    current: dict[str, Any] = entry,
                ) -> None:
                    """
                    Record identity.

                    The implementation uses ``metadata`` and ``current`` to
                    record identity.

                    Args:
                        metadata: Metadata consumed while the function attempts
                            to record identity.
                        current: Mapping supplying fields for record identity.
                    """
                    _write_temp_identity(
                        state_fd,
                        journal_name,
                        document["root"],
                        intent,
                        current["path"],
                        current["temporary"],
                        metadata,
                    )

                staged = _copy_spool_to_temporary(
                    parent_fd,
                    entry["temporary"],
                    replacements[entry["path"]],
                    entry["original"]["mode"],
                    record_identity,
                )
                entry["replacement"] = asdict(staged)
                entry["staged"] = True
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        document["state"] = "prepared"
        _write_journal(state_fd, journal_name, next_name, document)
        _hit("prepared")
        _validate_directory_guards(
            root_fd,
            directories,
            mutable_directories=mutable_directories,
            allowed_temporary_names=allowed_temporaries,
        )
        _validate_guards(root_fd, guards)
        document["state"] = "committing"
        _write_journal(state_fd, journal_name, next_name, document)
        for index, entry in enumerate(entries):
            parent_fd, target = _open_parent(root_fd, entry["path"])
            try:
                original = _snapshot_from_json(entry["original"])
                replacement = _snapshot_from_json(entry["replacement"])
                if (
                    _identity_at(parent_fd, target, original.size) != original
                    or _identity_at(
                        parent_fd,
                        entry["temporary"],
                        replacement.size,
                    )
                    != replacement
                ):
                    raise ValueError("transaction entry changed before exchange")
                _exchange(parent_fd, target, entry["temporary"])
                os.fsync(parent_fd)
                if not _stable_matches(
                    _identity_at(parent_fd, target, replacement.size),
                    replacement,
                ) or not _stable_matches(
                    _identity_at(parent_fd, entry["temporary"], original.size),
                    original,
                ):
                    raise ValueError("transaction entry drifted during exchange")
                _hit(f"exchanged:{index}")
            finally:
                os.close(parent_fd)
        _validate_guards(root_fd, guards)
        _validate_directory_guards(
            root_fd,
            directories,
            mutable_directories=mutable_directories,
            allowed_temporary_names=allowed_temporaries,
        )
        document["state"] = "committed"
        _write_journal(state_fd, journal_name, next_name, document)
        committed = True
        _validate_guards(root_fd, guards)
        _validate_directory_guards(
            root_fd,
            directories,
            mutable_directories=mutable_directories,
            allowed_temporary_names=allowed_temporaries,
        )
        _hit("committed")
        _recover_locked(root_fd, state_fd, journal_name, next_name, intent)
    except BaseException as error:
        try:
            outcome = (
                _recover_locked(
                    root_fd,
                    state_fd,
                    journal_name,
                    next_name,
                    intent,
                )
                if state_fd is not None and transaction_started
                else "none"
            )
        except BaseException as recovery_error:
            raise RuntimeError(
                "changed-file transaction failed and recovery is incomplete"
            ) from recovery_error
        if isinstance(error, Exception) and (committed or outcome == "committed"):
            return
        raise
    finally:
        if state_fd is not None:
            os.close(state_fd)
        os.close(root_fd)
