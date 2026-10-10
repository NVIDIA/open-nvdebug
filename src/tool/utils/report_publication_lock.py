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
Process-safe serialization for one published report directory.

This module owns the report publication lock boundary and exposes
``_directory_identity``, ``_validated_interval``, ``PinnedDirectoryLock``,
``_notify_wait``, and ``report_publication_lock``. Keeping those contracts
together gives importers one source of truth for their validation, lifecycle,
and compatibility behavior.
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import math
import os
import stat
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

from .filesystem_identity import directory_security_identity
from .managed_filesystem import run_managed_filesystem_operation

DEFAULT_LOCK_POLL_SECONDS = 0.05
DEFAULT_LOCK_NOTICE_SECONDS = 5.0
DEFAULT_SYNC_LOCK_TIMEOUT_SECONDS = 300.0

_INVALID_DIRECTORY = "Report publication directory is not a stable directory"
_CHANGED_DIRECTORY = "Report publication directory changed while waiting"
_LOCK_FAILURE = "Unable to acquire the report publication lock"
_LOCK_TIMEOUT = "Timed out waiting for another report publication"


_directory_identity = directory_security_identity


def _validated_interval(value: float, label: str, *, allow_zero: bool = False) -> float:
    """
    Return the validated interval.

    The implementation uses ``value``, ``label``, and ``allow_zero`` to produce
    the validated interval. If the function cannot produce the validated
    interval, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        value: Numeric value used while the operation performs bounded
            accounting.
        label: Text supplied as label in the format accepted by this function.
        allow_zero: Whether allow zero is enabled or required for this
            operation.

    Returns:
        The validated ``normalized``.

    Raises:
        ValueError: If the ``label`` is not a finite number; or the ``label`` is
            not finite and ``comparison``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a finite number")
    normalized = float(value)
    minimum_ok = normalized >= 0 if allow_zero else normalized > 0
    if not math.isfinite(normalized) or not minimum_ok:
        comparison = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{label} must be finite and {comparison}")
    return normalized


class PinnedDirectoryLock:
    """
    An advisory lock owned by a no-follow descriptor for one directory.

    The descriptor, rather than a removable lockfile, is the lock authority. The
    pathname is revalidated after acquisition and at commit boundaries so a
    directory replaced while the caller was waiting cannot be mistaken for the
    pinned publication destination.
    """

    __slots__ = (
        "_descriptor",
        "_identity",
        "_locked",
        "_parent_descriptor",
        "_parent_identity",
        "_path",
    )

    def __init__(
        self,
        path: Path,
        descriptor: int,
        parent_descriptor: int,
        identity: tuple[int, ...],
        parent_identity: tuple[int, ...],
    ) -> None:
        """
        Initialize a ``PinnedDirectoryLock`` instance.

        The initializer records ``_descriptor``, ``_identity``, ``_locked``,
        ``_parent_descriptor``, and ``_parent_identity`` for later operations
        and establishes the instance invariants before any public method runs.

        Args:
            path: filesystem location used as the path for this operation.
            descriptor: Numeric descriptor used while the operation performs
                bounded accounting.
            parent_descriptor: Numeric parent descriptor used while the
                operation performs bounded accounting.
            identity: Entries supplied as ``identity`` without transferring
                container ownership.
            parent_identity: Entries supplied as ``parent_identity`` without
                transferring container ownership.
        """
        self._path = path
        self._descriptor = descriptor
        self._parent_descriptor = parent_descriptor
        self._identity = identity
        self._parent_identity = parent_identity
        self._locked = False

    @classmethod
    def open(cls, directory: Path) -> PinnedDirectoryLock:
        """
        Open and pin an existing directory without following its leaf.

        After applying local validation, the function forwards ``directory`` to
        ``cls`` and preserves its return and exception contract.

        Args:
            directory: filesystem location used as the directory for this
                operation.

        Returns:
            A ``PinnedDirectoryLock`` representing open.

        Raises:
            OSError: If an owned resource fails while the function attempts to
                open and pin an existing directory without following its leaf.
        """

        path = Path(directory).expanduser().absolute()
        if path.parent == path or not path.name:
            raise OSError(_INVALID_DIRECTORY)

        parent_descriptor = -1
        descriptor = -1
        try:
            parent_descriptor = os.open(
                path.parent,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0),
            )
            path_metadata = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISDIR(
                path_metadata.st_mode
            ):
                raise OSError(_INVALID_DIRECTORY)
            descriptor = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            opened_metadata = os.fstat(descriptor)
            opened_parent_metadata = os.fstat(parent_descriptor)
            visible_metadata = path.lstat()
            visible_parent_metadata = path.parent.stat()
            if (
                not stat.S_ISDIR(opened_metadata.st_mode)
                or not stat.S_ISDIR(opened_parent_metadata.st_mode)
                or _directory_identity(path_metadata)
                != _directory_identity(opened_metadata)
                or _directory_identity(visible_metadata)
                != _directory_identity(opened_metadata)
                or _directory_identity(visible_parent_metadata)
                != _directory_identity(opened_parent_metadata)
            ):
                raise OSError(_INVALID_DIRECTORY)
            return cls(
                path,
                descriptor,
                parent_descriptor,
                _directory_identity(opened_metadata),
                _directory_identity(opened_parent_metadata),
            )
        except OSError:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if parent_descriptor >= 0:
                try:
                    os.close(parent_descriptor)
                except OSError:
                    pass
            raise OSError(_INVALID_DIRECTORY) from None

    @property
    def pinned_path(self) -> Path:
        """
        Return a process-local path anchored to the locked directory fd.

        Each access computes the value from ``_descriptor`` and
        ``require_current`` on the current instance; the derived view is not
        stored as independent state.

        Returns:
            The validated pinned path filesystem path.
        """

        self.require_current()
        return Path("/proc/self/fd") / str(self._descriptor)

    @property
    def pinned_parent_path(self) -> Path:
        """
        Return a process-local path anchored to the directory's parent fd.

        Each access computes the value from ``_parent_descriptor`` and
        ``require_current`` on the current instance; the derived view is not
        stored as independent state. If the function cannot produce a
        process-local path anchored to the directory's parent fd, its exception
        reaches the caller instead of being converted into a successful result.

        Returns:
            The validated pinned parent path filesystem path.

        Raises:
            RuntimeError: If report publication lock parent is closed.
        """

        self.require_current()
        if self._parent_descriptor < 0:
            raise RuntimeError("Report publication lock parent is closed")
        return Path("/proc/self/fd") / str(self._parent_descriptor)

    def duplicate_descriptor(self) -> int:
        """
        Duplicate the locked directory descriptor for relative operations.

        After applying local validation, the function forwards current instance
        state to ``os.dup`` and preserves its return and exception contract.

        Returns:
            The numeric duplicate descriptor value.
        """

        self.require_current()
        return os.dup(self._descriptor)

    def duplicate_parent_descriptor(self) -> int:
        """
        Duplicate the pinned parent descriptor for private sibling trees.

        After applying local validation, the function forwards current instance
        state to ``os.dup`` and preserves its return and exception contract.

        Returns:
            The numeric duplicate parent descriptor value.

        Raises:
            RuntimeError: If report publication lock parent is closed.
        """

        self.require_current()
        if self._parent_descriptor < 0:
            raise RuntimeError("Report publication lock parent is closed")
        return os.dup(self._parent_descriptor)

    def try_acquire(self) -> bool:
        """
        Try to acquire exclusive ownership without blocking the caller.

        The implementation uses current instance state to try to acquire
        exclusive ownership without blocking the caller. It updates ``_locked``
        on the instance as part of that state transition. If the function cannot
        try to acquire exclusive ownership without blocking the caller, its
        exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            Whether the try to acquire exclusive ownership without blocking the
            caller operation succeeds.

        Raises:
            RuntimeError: If report publication lock is closed.
            OSError: If an owned resource fails while the function attempts to
                try to acquire exclusive ownership without blocking the caller.
        """

        if self._descriptor < 0:
            raise RuntimeError("Report publication lock is closed")
        if self._locked:
            return True
        try:
            fcntl.flock(self._descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                return False
            raise OSError(_LOCK_FAILURE) from None
        self._locked = True
        return True

    def require_current(self) -> None:
        """
        Fail closed unless the locked descriptor still owns this path.

        The implementation uses current instance state to fail closed unless the
        locked descriptor still owns this path. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot fail closed unless the locked descriptor still
        owns this path, its exception reaches the caller instead of being
        converted into a successful result.

        Raises:
            RuntimeError: If report publication lock is not held.
            OSError: If an owned resource fails while the function attempts to
                fail closed unless the locked descriptor still owns this path.
        """

        if self._descriptor < 0 or not self._locked:
            raise RuntimeError("Report publication lock is not held")
        try:
            opened_metadata = os.fstat(self._descriptor)
            opened_parent_metadata = os.fstat(self._parent_descriptor)
            anchored_metadata = os.stat(
                self._path.name,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
            path_metadata = self._path.lstat()
            path_parent_metadata = self._path.parent.stat()
        except OSError:
            raise OSError(_CHANGED_DIRECTORY) from None
        if (
            not stat.S_ISDIR(opened_metadata.st_mode)
            or not stat.S_ISDIR(opened_parent_metadata.st_mode)
            or stat.S_ISLNK(anchored_metadata.st_mode)
            or not stat.S_ISDIR(anchored_metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or not stat.S_ISDIR(path_metadata.st_mode)
            or _directory_identity(opened_metadata) != self._identity
            or _directory_identity(opened_parent_metadata) != self._parent_identity
            or _directory_identity(path_parent_metadata) != self._parent_identity
            or _directory_identity(anchored_metadata) != self._identity
            or _directory_identity(path_metadata) != self._identity
        ):
            raise OSError(_CHANGED_DIRECTORY)

    def close(self) -> None:
        """
        Close the descriptor, which atomically releases any held lock.

        The implementation uses current instance state to close the descriptor,
        which atomically releases any held lock. It updates ``_descriptor``,
        ``_locked``, and ``_parent_descriptor`` on the instance as part of that
        state transition. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.
        """

        descriptor = self._descriptor
        parent_descriptor = self._parent_descriptor
        self._descriptor = -1
        self._parent_descriptor = -1
        self._locked = False
        try:
            if descriptor >= 0:
                os.close(descriptor)
        finally:
            if parent_descriptor >= 0:
                os.close(parent_descriptor)


def _notify_wait(callback: Callable[[float], None] | None, elapsed: float) -> None:
    """
    Notify wait.

    The implementation uses ``callback`` and ``elapsed`` to notify wait.

    Args:
        callback: Callable invoked at the callback boundary.
        elapsed: Numeric elapsed used while the operation performs bounded
            accounting.
    """
    if callback is not None:
        callback(max(0.0, elapsed))


@contextmanager
def report_publication_lock(
    directory: Path,
    *,
    timeout_seconds: float = DEFAULT_SYNC_LOCK_TIMEOUT_SECONDS,
    poll_seconds: float = DEFAULT_LOCK_POLL_SECONDS,
    notice_seconds: float = DEFAULT_LOCK_NOTICE_SECONDS,
    on_wait: Callable[[float], None] | None = None,
) -> Iterator[PinnedDirectoryLock]:
    """
    Acquire a bounded synchronous report-publication lock.

    Check the absolute deadline before retrying. A delayed scheduler wake-up
    must not turn a bounded wait into a late successful acquisition merely
    because the owner released the lock after the caller's timeout had already
    expired.

    Args:
        directory: filesystem location used as the directory for this operation.
        timeout_seconds: Maximum duration in seconds allowed for timeout
            seconds.
        poll_seconds: Maximum duration in seconds allowed for poll seconds.
        notice_seconds: Maximum duration in seconds allowed for notice seconds.
        on_wait: Optional on wait; ``None`` selects the function's default
            behavior.

    Yields:
        Each report publication lock admitted by the operation, in deterministic
        iteration order.

    Raises:
        TimeoutError: If the function cannot acquire a bounded synchronous
            report-publication lock safely.
    """

    timeout = _validated_interval(timeout_seconds, "timeout_seconds", allow_zero=True)
    poll = _validated_interval(poll_seconds, "poll_seconds")
    notice = _validated_interval(notice_seconds, "notice_seconds")
    lock = PinnedDirectoryLock.open(directory)
    started = time.monotonic()
    deadline = started + timeout
    next_notice = started
    try:
        if not lock.try_acquire():
            while True:
                now = time.monotonic()
                if now >= next_notice:
                    _notify_wait(on_wait, now - started)
                    now = time.monotonic()
                    next_notice = now + notice
                if now >= deadline:
                    raise TimeoutError(_LOCK_TIMEOUT)
                time.sleep(min(poll, max(0.0, deadline - now)))
                # Check the absolute deadline before retrying. A delayed
                # scheduler wake-up must not turn a bounded wait into a late
                # successful acquisition merely because the owner released
                # the lock after the caller's timeout had already expired.
                if time.monotonic() >= deadline:
                    raise TimeoutError(_LOCK_TIMEOUT)
                if lock.try_acquire():
                    break
        lock.require_current()
        yield lock
    finally:
        lock.close()


@asynccontextmanager
async def async_report_publication_lock(
    directory: Path,
    *,
    timeout_seconds: float = DEFAULT_SYNC_LOCK_TIMEOUT_SECONDS,
    poll_seconds: float = DEFAULT_LOCK_POLL_SECONDS,
    notice_seconds: float = DEFAULT_LOCK_NOTICE_SECONDS,
    on_wait: Callable[[float], None] | None = None,
) -> AsyncIterator[PinnedDirectoryLock]:
    """
    Pin a directory off the event loop and poll its publication lock asynchronously.

    Directory opens and identity checks can issue NFS metadata requests, so those
    operations use the bounded filesystem pool. Nonblocking directory-lock retries
    sleep asynchronously without occupying a worker. Cancellation joins any admitted
    metadata operation before closing its descriptors, including an open whose
    result has not yet reached the asynchronous caller. The yielded lock remains
    owned until the caller finishes its publication and leaves the context.
    Contention has the same finite deadline as the synchronous API. This bounds
    lock waiting, not kernel I/O on an unavailable hard-mounted filesystem.

    Args:
        directory: Existing publication directory whose leaf must not be a symlink.
        timeout_seconds: Nonnegative contention budget after the directory opens;
            zero permits only the initial nonblocking acquisition attempt.
        poll_seconds: Positive interval between nonblocking lock attempts.
        notice_seconds: Positive minimum interval between contention notifications.
        on_wait: Optional synchronous callback receiving elapsed lock-wait seconds.

    Yields:
        The locked directory after its pinned identity has been revalidated.

    Raises:
        ValueError: If a timeout, polling or notification interval is invalid.
        TimeoutError: If directory-lock contention exceeds the allowed budget.
        OSError: If the directory cannot be pinned, changes, or cannot be locked.
        asyncio.CancelledError: After admitted metadata work and descriptor cleanup
            finish when the asynchronous owner is cancelled.
    """

    timeout = _validated_interval(timeout_seconds, "timeout_seconds", allow_zero=True)
    poll = _validated_interval(poll_seconds, "poll_seconds")
    notice = _validated_interval(notice_seconds, "notice_seconds")
    lock: PinnedDirectoryLock | None = None

    def open_directory() -> None:
        """
        Retain newly opened descriptors even if cancellation interrupts handoff.

        The managed runner joins this worker before propagating cancellation, so
        the outer cleanup always observes and closes any successfully opened lock.
        Open failures retain the descriptor cleanup owned by PinnedDirectoryLock.
        """

        nonlocal lock
        lock = PinnedDirectoryLock.open(directory)

    try:
        await run_managed_filesystem_operation(open_directory)
        started = time.monotonic()
        deadline = started + timeout
        next_notice = started
        if not lock.try_acquire():
            while True:
                now = time.monotonic()
                if now >= next_notice:
                    _notify_wait(on_wait, now - started)
                    now = time.monotonic()
                    next_notice = now + notice
                if now >= deadline:
                    raise TimeoutError(_LOCK_TIMEOUT)
                await asyncio.sleep(min(poll, max(0.0, deadline - now)))
                if time.monotonic() >= deadline:
                    raise TimeoutError(_LOCK_TIMEOUT)
                if lock.try_acquire():
                    break
        await run_managed_filesystem_operation(lock.require_current)
        yield lock
    finally:
        if lock is not None:
            lock.close()
