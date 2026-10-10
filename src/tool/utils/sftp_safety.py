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
Safety guards for SFTP transfers of device-supplied files.

A device under test controls the objects it exposes over SFTP. ``sftp.get`` does
not follow a remote symbolic link by default; it reproduces the link locally
with the device-chosen target. A later write to that same local path then lands
wherever the device pointed, which is an arbitrary write on the operator
workstation.

These helpers apply the same policy the Managed Host transfer path already uses:
reject any remote object that is not a lone regular file, reject an unsafe local
destination before writing, and verify after the transfer that the local
artifact really is a regular file.
"""

import os
import stat
from typing import Any, Callable, Optional

import asyncssh


class SFTPTransferSafetyError(ValueError):
    """
    A remote source or local destination failed a transfer safety check.

    Callers receive this exception when the sftp transfer safety error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


def bounded_transfer_progress_handler(
    *,
    source: str,
    max_bytes: int,
    expected_size: Optional[int] = None,
) -> Callable[[Any, Any, int, int], None]:
    """
    Return an AsyncSSH progress callback enforcing one transfer budget.

    The remote size check before a transfer and the local-file check afterward
    do not stop a server which changes the file after ``lstat`` from writing an
    arbitrarily large partial file. This callback rejects malformed counters,
    changing declared sizes, and either counter crossing ``max_bytes`` while
    the transfer is still in flight.

    Args:
        source: Stable remote source label used in contained diagnostics.
        max_bytes: Maximum admitted declared or copied byte count.
        expected_size: Optional size established by the pre-transfer ``lstat``.

    Returns:
        A synchronous callback compatible with AsyncSSH transfer APIs.

    Raises:
        ValueError: If the configured transfer boundary is invalid.
    """

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("SFTP transfer byte ceiling must be a non-negative integer")
    if expected_size is not None and (
        isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or expected_size < 0
        or expected_size > max_bytes
    ):
        raise ValueError("SFTP expected size is outside its transfer byte ceiling")

    declared_size = expected_size

    def enforce_progress(
        _source: Any,
        _destination: Any,
        bytes_copied: int,
        total_bytes: int,
    ) -> None:
        """
        Validate one progress event before AsyncSSH writes more bytes.

        Each event must retain the preflight size and remain within the caller's
        transfer budget, closing the race between remote ``lstat`` and download.

        Args:
            _source: AsyncSSH source label; the validated closure value is used.
            _destination: AsyncSSH destination label, unused by this boundary.
            bytes_copied: Bytes copied according to the current progress event.
            total_bytes: Total remote bytes declared by the progress event.

        Raises:
            SFTPTransferSafetyError: If counters are malformed, inconsistent,
                or exceed the admitted byte budget.
        """

        nonlocal declared_size
        for label, value in (
            ("bytes copied", bytes_copied),
            ("declared size", total_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SFTPTransferSafetyError(
                    f"SFTP reported an invalid {label} for {source}"
                )
        if bytes_copied > total_bytes:
            raise SFTPTransferSafetyError(
                f"SFTP reported {bytes_copied} bytes copied from a "
                f"{total_bytes} byte file"
            )
        if bytes_copied > max_bytes or total_bytes > max_bytes:
            raise SFTPTransferSafetyError(
                f"Remote path {source} is above the {max_bytes} byte ceiling"
            )
        if declared_size is None:
            declared_size = total_bytes
        elif declared_size != total_bytes:
            raise SFTPTransferSafetyError(
                f"SFTP changed the declared size for {source}"
            )

    return enforce_progress


async def require_regular_remote_file(
    sftp: Any,
    source: str,
    *,
    max_bytes: Optional[int] = None,
) -> Optional[int]:
    """
    Reject a remote path that is not a single, unlinked regular file.

    Uses ``lstat`` rather than ``stat`` so a symbolic link is reported as a link
    instead of being resolved to its target. Returns the remote size when the
    server reported one.

    The remote link count is opportunistic hardening only. SFTPv3 -- the
    asyncssh default -- never carries ``FILEXFER_ATTR_LINK_COUNT``, so
    ``status.nlink`` is ``None`` and the count cannot be confirmed at this
    boundary; when the server does report a concrete count it must be exactly
    one, otherwise the object is refused. The authoritative lone-regular-file
    guarantee is re-established locally by ``verify_local_regular_file`` against
    OS ``os.lstat`` after the transfer, which the device cannot influence.

    Args:
        sftp: Sftp object whose ``lstat`` state is read while performing remote
            path that is not a single, unlinked regular file.
        source: Text supplied as source in the format accepted by this function.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The validated ``size``, or ``None`` when no value qualifies.

    Raises:
        SFTPTransferSafetyError: If remote path ``source`` is not a regular
            file; remote path ``source`` has extra hard links; remote path
            ``source`` reported a negative size; or remote path ``source`` is
            ``size`` bytes, above the ``max_bytes`` byte ceiling.
    """

    status = await sftp.lstat(source)

    if getattr(status, "type", None) != asyncssh.FILEXFER_TYPE_REGULAR:
        raise SFTPTransferSafetyError(f"Remote path {source} is not a regular file")

    # Fail closed only when the remote count is actually known. ``None`` means
    # the negotiated SFTP version did not carry a link count (e.g. the default
    # SFTPv3), so it is treated as "cannot confirm" and admission relies on the
    # documented local ``os.lstat`` re-verification after the transfer. A
    # reported count -- integer or otherwise -- that is not exactly one cannot
    # prove a lone link and is refused here.
    links = getattr(status, "nlink", None)
    if links is not None and (
        isinstance(links, bool) or not isinstance(links, int) or links != 1
    ):
        raise SFTPTransferSafetyError(f"Remote path {source} has extra hard links")

    size = getattr(status, "size", None)
    if isinstance(size, bool) or not isinstance(size, int):
        return None
    if size < 0:
        raise SFTPTransferSafetyError(f"Remote path {source} reported a negative size")
    if max_bytes is not None and size > max_bytes:
        raise SFTPTransferSafetyError(
            f"Remote path {source} is {size} bytes, above the {max_bytes} byte ceiling"
        )
    return size


def prepare_local_destination(local_path: str) -> None:
    """
    Make a local destination safe to write, without breaking retries.

    A pre-existing symbolic link is removed so the transfer cannot follow it out
    of the run directory -- this is the case a failed earlier attempt leaves
    behind. A plain file is left alone and may be overwritten, because the
    transfer fallback ladder legitimately re-downloads to the same path. A
    directory is refused rather than removed.

    ``lexists``/``lstat`` are deliberate: a dangling link must be seen as
    present, since opening it for write follows it to the device-chosen target.

    Args:
        local_path: filesystem location used as the local path for this
            operation.

    Raises:
        SFTPTransferSafetyError: If refusing to transfer onto existing directory
            ``local_path``; or refusing to transfer onto hard-linked file
            ``local_path``.
    """

    if not os.path.lexists(local_path):
        return

    status = os.lstat(local_path)

    if stat.S_ISDIR(status.st_mode):
        raise SFTPTransferSafetyError(
            f"Refusing to transfer onto existing directory {local_path}"
        )

    if not stat.S_ISREG(status.st_mode):
        # Symbolic link, FIFO, socket or device node: never write through it.
        discard_unsafe_local_path(local_path)
        return

    if status.st_nlink != 1:
        raise SFTPTransferSafetyError(
            f"Refusing to transfer onto hard-linked file {local_path}"
        )


def verify_local_regular_file(
    local_path: str,
    *,
    expected_size: Optional[int] = None,
    max_bytes: Optional[int] = None,
) -> None:
    """
    Confirm a completed transfer produced a plain local file.

    Guards the window between the remote check and the transfer: if the object
    changed underneath us, the local artifact is removed rather than left for a
    later write to follow.

    Args:
        local_path: filesystem location used as the local path for this
            operation.
        expected_size: Numeric expected size used by the operation's bounded
            accounting.
        max_bytes: Maximum local file size admitted after transfer.

    Raises:
        SFTPTransferSafetyError: If transfer of ``local_path`` produced no local
            file; transfer produced a non-regular local file at ``local_path``;
            transfer produced a hard-linked local file at ``local_path``; or
            transfer of ``local_path`` wrote ``st_size`` bytes, expected
            ``expected_size``.
    """

    try:
        status = os.lstat(local_path)
    except FileNotFoundError:
        raise SFTPTransferSafetyError(
            f"Transfer of {local_path} produced no local file"
        ) from None

    if not stat.S_ISREG(status.st_mode):
        discard_unsafe_local_path(local_path)
        raise SFTPTransferSafetyError(
            f"Transfer produced a non-regular local file at {local_path}"
        )

    if status.st_nlink != 1:
        discard_unsafe_local_path(local_path)
        raise SFTPTransferSafetyError(
            f"Transfer produced a hard-linked local file at {local_path}"
        )

    if expected_size is not None and status.st_size != expected_size:
        discard_unsafe_local_path(local_path)
        raise SFTPTransferSafetyError(
            f"Transfer of {local_path} wrote {status.st_size} bytes, "
            f"expected {expected_size}"
        )
    if max_bytes is not None and status.st_size > max_bytes:
        discard_unsafe_local_path(local_path)
        raise SFTPTransferSafetyError(
            f"Transfer of {local_path} wrote {status.st_size} bytes, above the "
            f"{max_bytes} byte ceiling"
        )


def discard_unsafe_local_path(local_path: str) -> None:
    """
    Remove a local path that failed a safety check, ignoring only absence.

    Uses ``os.unlink`` so a symbolic link is removed rather than its target. Any
    other removal failure is terminal: continuing would let the transfer write
    through the path which failed its safety check.

    Args:
        local_path: filesystem location used as the local path for this
            operation.

    Raises:
        SFTPTransferSafetyError: If unable to remove unsafe local path
            ``local_path``; or unsafe local path remained after removal:
            ``local_path``.
    """

    try:
        os.unlink(local_path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise SFTPTransferSafetyError(
            f"Unable to remove unsafe local path {local_path}"
        ) from error

    if os.path.lexists(local_path):
        raise SFTPTransferSafetyError(
            f"Unsafe local path remained after removal: {local_path}"
        )
