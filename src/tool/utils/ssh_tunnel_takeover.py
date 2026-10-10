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
Replace an exactly matching local SSH tunnel without signalling arbitrary PIDs.

Linux procfs proves executable, argument, UID and listener ownership. A pidfd pins
the selected process across revalidation and TERM/KILL, preventing PID reuse from
redirecting a signal. Callers run this finite blocking operation on an owned worker.
"""

from __future__ import annotations

import ctypes
import errno
import math
import os
import platform
import select
import shutil
import signal
import sys
import threading
import time
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Optional, Sequence

_PROC_ROOT = Path("/proc")
_MAX_PROCESS_ENTRIES = 16384
_MAX_DESCRIPTORS = 4096
_MAX_PROCESS_BYTES = 65536
_MAX_TABLE_BYTES = 8 * 1024 * 1024
_DISCOVERY_SECONDS = 2.0


def _pidfd_syscall(number: int, *arguments: object) -> int:
    """
    Access Linux pidfds when the packaged Python omits its optional wrappers.

    The shipped x86_64 and aarch64 Linux ABIs use syscall numbers 434 and 424
    for pidfd_open and pidfd_send_signal. Older build headers can omit Python's
    wrappers even when the running kernel implements these calls. Restrict the
    fallback to those 64-bit ABIs; never substitute PID-based signalling.

    Args:
        number: Kernel syscall number selected by an internal pidfd wrapper.
        arguments: Explicitly typed ctypes values for the variadic libc call.

    Returns:
        The nonnegative kernel result, including an owned fd for pidfd_open.

    Raises:
        OSError: If the ABI, libc, kernel, or process policy disallows the call.
    """

    if (
        sys.platform != "linux"
        or platform.machine() not in {"x86_64", "aarch64"}
        or ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(ctypes.c_long) != 8
        or number not in {424, 434}
    ):
        raise OSError(errno.ENOSYS, "Safe pidfd syscall ABI is unavailable")
    try:
        syscall = ctypes.CDLL(None, use_errno=True).syscall
    except (AttributeError, OSError) as exc:
        raise OSError(errno.ENOSYS, "libc syscall entry point is unavailable") from exc
    syscall.restype = ctypes.c_long
    result = syscall(ctypes.c_long(number), *arguments)
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _open_pidfd(pid: int) -> int:
    """
    Pin the selected process using the stdlib or the supported Linux syscall.

    Prefer the interpreter's API whenever it exists. Missing build-time wrappers
    do not imply a missing kernel capability; all actual open failures propagate.

    Args:
        pid: Process whose identity has been inspected by the caller.

    Returns:
        An owned close-on-exec descriptor requiring closure by the caller.

    Raises:
        OSError: If process pinning is unavailable or the process has exited.
    """

    native = getattr(os, "pidfd_open", None)
    if native is not None:
        return native(pid, 0)
    return _pidfd_syscall(434, ctypes.c_int(pid), ctypes.c_uint(0))


def _signal_pidfd(pidfd: int, signum: int) -> None:
    """
    Signal only the process pinned by the supplied descriptor.

    The descriptor is retained across TERM and KILL, including the compatibility
    path. No failure authorizes conversion back to an integer process identity.

    Args:
        pidfd: Owned descriptor retained across identity revalidation.
        signum: Signal number selected by the bounded takeover lifecycle.

    Raises:
        OSError: If descriptor-based signalling is unavailable or refused.
    """

    native = getattr(signal, "pidfd_send_signal", None)
    if native is not None:
        native(pidfd, signum)
        return
    _pidfd_syscall(
        424,
        ctypes.c_int(pidfd),
        ctypes.c_int(signum),
        ctypes.c_void_p(),
        ctypes.c_uint(0),
    )


@dataclass(frozen=True)
class _TunnelIdentity:
    """
    Retain the immutable identity of one verified SSH listener.

    The start tick is compared again after pinning the process so a recycled PID
    cannot authorize signalling a different process.

    Attributes:
        pid: Local process identifier selected by socket ownership.
        start_ticks: Kernel process start time protecting against PID reuse.
    """

    pid: int
    start_ticks: str


def _read_bounded(path: Path, limit: int) -> Optional[bytes]:
    """
    Read a bounded procfs record and reject unreadable or oversized data.

    Reading one extra byte distinguishes a complete record from a truncated one.
    Missing inspection evidence never grants permission to replace a listener.

    Args:
        path: Kernel record to read without logging its contents.
        limit: Maximum accepted record size in bytes.

    Returns:
        The complete record, or None when it cannot be safely inspected.
    """

    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


def _listener_inodes(port: int) -> Optional[tuple[set[str], set[str]]]:
    """
    Separate the requested TCP listeners from other TCP and Unix listeners.

    Rejecting other owned listeners avoids terminating a shared SSH connection
    or multiplexing master that also serves unrelated forwarding routes.

    Args:
        port: Local TCP port requested for replacement.

    Returns:
        Requested and unrelated listener inode sets, or None on incomplete data.
    """

    wanted: set[str] = set()
    unrelated: set[str] = set()
    for name in ("tcp", "tcp6"):
        raw = _read_bounded(_PROC_ROOT / "net" / name, _MAX_TABLE_BYTES)
        if raw is None:
            return None
        for line in raw.decode("ascii", errors="replace").splitlines()[1:]:
            fields = line.split()
            if len(fields) <= 9 or fields[3] != "0A":
                continue
            try:
                local_port = int(fields[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                return None
            (wanted if local_port == port else unrelated).add(fields[9])
    raw = _read_bounded(_PROC_ROOT / "net" / "unix", _MAX_TABLE_BYTES)
    if raw is None:
        return None
    for line in raw.decode("ascii", errors="replace").splitlines()[1:]:
        fields = line.split()
        if len(fields) <= 6:
            continue
        try:
            if int(fields[3], 16) & 0x10000:
                unrelated.add(fields[6])
        except ValueError:
            return None
    return wanted, unrelated


def _matching_identity(
    pid: int,
    expected_argv: tuple[str, ...],
    executable_identity: tuple[int, int],
    listeners: tuple[set[str], set[str]],
) -> Optional[_TunnelIdentity]:
    """
    Prove that one same-user OpenSSH process owns only the requested listeners.

    The executable inode must match the SSH program selected for the new
    invocation. Arguments after argv[0] must match exactly, including forwarding
    endpoints, SSH account, port and options. No shell command or port substring
    can authorize replacement.

    Args:
        pid: Candidate process identifier from the bounded procfs scan.
        expected_argv: New SSH invocation with any sshpass wrapper removed.
        executable_identity: Device and inode of the selected SSH executable.
        listeners: Requested and unrelated listener inode sets.

    Returns:
        The immutable process identity, or None when any proof is missing.
    """

    entry = _PROC_ROOT / str(pid)
    try:
        if entry.stat().st_uid != os.geteuid():
            return None
        executable = (entry / "exe").stat()
        if (executable.st_dev, executable.st_ino) != executable_identity:
            return None
        argv_raw = _read_bounded(entry / "cmdline", _MAX_PROCESS_BYTES)
        stat_raw = _read_bounded(entry / "stat", _MAX_PROCESS_BYTES)
        if argv_raw is None or stat_raw is None:
            return None
        argv = tuple(
            os.fsdecode(value) for value in argv_raw.rstrip(b"\0").split(b"\0")
        )
        if not argv or argv[1:] != expected_argv[1:]:
            return None
        # comm is parenthesized and may contain spaces or parentheses.
        fields = stat_raw.rsplit(b")", 1)[1].split()
        if fields[0] == b"Z":
            return None
        started = fields[19].decode("ascii")
        owned: set[str] = set()
        descriptors = list(islice((entry / "fd").iterdir(), _MAX_DESCRIPTORS + 1))
        if len(descriptors) > _MAX_DESCRIPTORS:
            return None
        for descriptor in descriptors:
            target = os.readlink(descriptor)
            if target.startswith("socket:[") and target.endswith("]"):
                owned.add(target[8:-1])
        wanted, unrelated = listeners
        if not wanted.intersection(owned) or unrelated.intersection(owned):
            return None
        final_stat = _read_bounded(entry / "stat", _MAX_PROCESS_BYTES)
        if final_stat is None:
            return None
        final_fields = final_stat.rsplit(b")", 1)[1].split()
        if final_fields[0] == b"Z" or final_fields[19].decode("ascii") != started:
            return None
        return _TunnelIdentity(pid, started)
    except (OSError, IndexError, ValueError, UnicodeError):
        return None


def _wait_for_exit(
    pidfd: int, timeout: float, cancellation_event: threading.Event
) -> bool:
    """
    Wait for the pinned process to exit within a finite grace period.

    Cancellation shortens the TERM grace so the owner can complete exact cleanup
    with KILL before propagating cancellation from its worker boundary. Polling
    supports pidfds above the fixed descriptor limit imposed by select().

    Args:
        pidfd: Descriptor pinning the process selected for replacement.
        timeout: Maximum grace period in seconds.
        cancellation_event: Cooperative cancellation requested by the caller.

    Returns:
        Whether the pinned process has exited, including an unreaped zombie.
    """

    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        milliseconds = math.ceil(
            1000 * min(0.05, max(0.0, deadline - time.monotonic()))
        )
        events = poller.poll(milliseconds)
        if events:
            return any(flags & (select.POLLIN | select.POLLHUP) for _, flags in events)
        if cancellation_event.is_set():
            return False
    return any(flags & (select.POLLIN | select.POLLHUP) for _, flags in poller.poll(0))


def stop_matching_ssh_listener(
    expected_argv: Sequence[str],
    port: int,
    timeout: float,
    cancellation_event: threading.Event,
) -> bool:
    """
    Stop one proven matching SSH listener and observe its exit.

    Discovery is bounded by entry counts, file sizes and elapsed time. The
    candidate is revalidated after opening a pidfd, and signals use that fd only.
    No process group or arbitrary port owner is signalled. Systems without pidfd
    support fail closed. Cancellation before TERM leaves the process untouched;
    cancellation after TERM completes bounded cleanup on this owned worker.

    Args:
        expected_argv: Exact shell-free SSH invocation for the requested route.
        port: Local TCP listener port requested by the caller.
        timeout: TERM and KILL grace, each greater than zero and at most 30 seconds.
        cancellation_event: Event set when the asynchronous owner is cancelled.

    Returns:
        True only after the verified matching process has exited.
    """

    expected = tuple(expected_argv)
    if (
        not expected
        or "-N" not in expected
        or expected.count("-L") != 1
        or not 0 < int(port) < 65536
        or not 0 < timeout <= 30
        or cancellation_event.is_set()
    ):
        return False
    executable = shutil.which(expected[0])
    if executable is None:
        return False
    pidfd = None
    try:
        executable_stat = Path(executable).stat()
        executable_identity = (executable_stat.st_dev, executable_stat.st_ino)
        listeners = _listener_inodes(port)
        if listeners is None or not listeners[0]:
            return False
        deadline = time.monotonic() + _DISCOVERY_SECONDS
        candidates: list[_TunnelIdentity] = []
        for index, entry in enumerate(
            islice(_PROC_ROOT.iterdir(), _MAX_PROCESS_ENTRIES + 1)
        ):
            if (
                index >= _MAX_PROCESS_ENTRIES
                or time.monotonic() >= deadline
                or cancellation_event.is_set()
            ):
                return False
            if not entry.name.isdigit():
                continue
            identity = _matching_identity(
                int(entry.name), expected, executable_identity, listeners
            )
            if identity is not None:
                candidates.append(identity)
                if len(candidates) > 1:
                    return False
        if len(candidates) != 1 or cancellation_event.is_set():
            return False
        candidate = candidates[0]
        pidfd = _open_pidfd(candidate.pid)
        current_listeners = _listener_inodes(port)
        if current_listeners is None:
            return False
        current = _matching_identity(
            candidate.pid, expected, executable_identity, current_listeners
        )
        if current != candidate or cancellation_event.is_set():
            return False
        _signal_pidfd(pidfd, signal.SIGTERM)
        if _wait_for_exit(pidfd, timeout, cancellation_event):
            return True
        _signal_pidfd(pidfd, signal.SIGKILL)
        # KILL cleanup remains owned even when cancellation shortened TERM.
        return _wait_for_exit(pidfd, timeout, threading.Event())
    except (OSError, ValueError):
        return False
    finally:
        if pidfd is not None:
            os.close(pidfd)
