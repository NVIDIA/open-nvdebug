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
Publish complete prepared bytes through private staging and atomic replacement.

Collector output, metadata and execution-summary rewrites share the same byte
publication boundary. Locked read/modify/write callers additionally use pinned
directory descriptors; no regular-file NFS advisory lock is requested. Callers
own sanitization, input bounds and asynchronous worker lifetime.
"""

from __future__ import annotations

import os
import stat
import uuid
from collections.abc import Callable
from pathlib import Path

from .report_publication_lock import PinnedDirectoryLock


def _publish_bytes(
    destination: Path,
    content: bytes,
    *,
    inherit_creation_mode: bool,
    directory_fd: int | None = None,
    revalidate: Callable[[], None] | None = None,
) -> None:
    """
    Write private staging bytes and replace one final leaf only after fsync.

    A same-directory staging file keeps rename on the selected filesystem. The
    pathname mode preserves collector publication behavior; pinned metadata
    callers additionally reject unsafe leaves and revalidate directory identity
    immediately before and after commit.

    Args:
        destination: Full pathname, or a single relative leaf with a directory fd.
        content: Complete prepared bytes; no transformation occurs at this boundary.
        inherit_creation_mode: Preserve normal 0666 creation policy for a new file.
        directory_fd: Pinned parent for descriptor-relative publication, if supplied.
        revalidate: Pinned-directory identity check at replacement boundaries.

    Raises:
        OSError: If a leaf is unsafe, staging fails, or publication/cleanup fails.
        FileExistsError: If ten private staging names collide.

    Side Effects:
        Retains the old complete destination until rename. New private staging
        files are removed on failure; successful replacements retain existing
        access modes without reading or changing the process umask.
    """
    relative_options = {} if directory_fd is None else {"dir_fd": directory_fd}
    existing_mode = None
    try:
        metadata = (
            destination.lstat()
            if directory_fd is None
            else os.stat(destination, follow_symlinks=False, **relative_options)
        )
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISREG(metadata.st_mode):
            existing_mode = stat.S_IMODE(metadata.st_mode)
        elif directory_fd is not None:
            raise OSError("Metadata publication target is not a regular file")

    descriptor = None
    staging_path = None
    new_mode = 0o644
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        for _ in range(10):
            candidate = (
                destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
            )
            try:
                descriptor = os.open(
                    candidate,
                    flags,
                    0o666 if inherit_creation_mode else 0o600,
                    **relative_options,
                )
                staging_path = candidate
                if inherit_creation_mode:
                    new_mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
                    os.fchmod(descriptor, 0o600)
                break
            except FileExistsError:
                continue
        if descriptor is None or staging_path is None:
            raise FileExistsError(
                "Unable to allocate an atomic publication staging file"
            )
        with os.fdopen(descriptor, "wb") as staging_file:
            descriptor = None
            staging_file.write(content)
            staging_file.flush()
            os.fchmod(
                staging_file.fileno(),
                existing_mode if existing_mode is not None else new_mode,
            )
            os.fsync(staging_file.fileno())
        if revalidate is not None:
            revalidate()
        if directory_fd is None:
            os.replace(staging_path, destination)
        else:
            os.replace(
                staging_path,
                destination,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
        staging_path = None
        if revalidate is not None:
            revalidate()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if staging_path is not None:
            try:
                if directory_fd is None:
                    staging_path.unlink()
                else:
                    os.unlink(staging_path, **relative_options)
            except FileNotFoundError:
                pass


def atomic_publish_bytes(
    destination: Path, content: bytes, *, inherit_creation_mode: bool = False
) -> None:
    """
    Publish prepared collector bytes on the selected destination filesystem.

    This is the shared implementation of the logger's existing byte publisher.
    Keeping its creation-mode option preserves output readability without a
    process-wide umask change or a local temporary-directory fallback.

    Args:
        destination: Validated final pathname selected by the owning caller.
        content: Complete sanitized bytes to publish.
        inherit_creation_mode: Use normal file creation policy instead of 0644
            for a new destination; replacements always preserve their mode.

    Raises:
        OSError: If directory creation, staging, fsync or replacement fails.

    Side Effects:
        Creates the parent and one private same-directory staging file. This
        synchronous operation must be owned by a worker for asynchronous callers.
    """
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _publish_bytes(destination, content, inherit_creation_mode=inherit_creation_mode)


def _validate_leaf(filename: str) -> Path:
    """
    Reject directory components at the pinned publication boundary.

    Descriptor-relative filesystem calls must receive only the leaf owned by
    their caller. Reject both path separators and special components before any
    file descriptor is borrowed or filesystem operation is attempted.

    Args:
        filename: Single destination component chosen by the metadata owner.

    Returns:
        A relative path containing exactly the admitted leaf.

    Raises:
        ValueError: If the value is empty, special, absolute or contains a separator.
    """
    if not isinstance(filename, str) or filename in {"", ".", ".."}:
        raise ValueError("Pinned publication requires a single filename")
    if "/" in filename or "\\" in filename or "\x00" in filename:
        raise ValueError("Pinned publication requires a single filename")
    return Path(filename)


def atomic_publish_locked_bytes(
    publication_lock: PinnedDirectoryLock, filename: str, content: bytes
) -> None:
    """
    Replace a metadata leaf while retaining its pinned directory ownership.

    The borrowed directory descriptor survives pathname replacement and bounds
    both staging and cleanup to the original directory. Identity checks detect
    substitution around commit without following a replacement directory.

    Args:
        publication_lock: Acquired directory lock held through worker completion.
        filename: Single relative metadata or summary filename.
        content: Complete prepared replacement bytes.

    Raises:
        OSError: If the directory changes, the leaf is unsafe, or writing fails.
        ValueError: If the filename is not a single safe leaf.

    Side Effects:
        Replaces the final leaf atomically and closes the borrowed descriptor.
        Normal creation modes and existing replacement modes are preserved.
    """
    leaf = _validate_leaf(filename)
    directory_fd = publication_lock.duplicate_descriptor()
    try:
        _publish_bytes(
            leaf,
            content,
            inherit_creation_mode=True,
            directory_fd=directory_fd,
            revalidate=publication_lock.require_current,
        )
    finally:
        os.close(directory_fd)


def read_locked_bytes(
    publication_lock: PinnedDirectoryLock, filename: str, *, max_bytes: int
) -> bytes:
    """
    Read a bounded stable metadata leaf without creating an empty public file.

    A missing document is a normal initial merge. Existing input must be a
    regular no-follow leaf within the caller's byte ceiling; descriptor metadata
    before and after reading detects concurrent mutation by other writers.

    Args:
        publication_lock: Acquired directory ownership protecting a cooperating merge.
        filename: Single relative metadata filename.
        max_bytes: Positive maximum size of the complete existing document.

    Returns:
        Complete existing bytes, or empty bytes when the file does not exist.

    Raises:
        OSError: If the leaf is linked, non-regular, oversized or changes on read.
        ValueError: If the leaf or byte ceiling is invalid.

    Side Effects:
        Opens only read-only no-follow descriptors, closing all of them on exit.
    """
    leaf = _validate_leaf(filename)
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("Metadata read ceiling must be a positive integer")
    directory_fd = publication_lock.duplicate_descriptor()
    descriptor = None
    try:
        try:
            descriptor = os.open(
                leaf,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return b""
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise OSError("Metadata merge input is not a bounded regular file")
        payload = bytearray()
        while len(payload) < before.st_size:
            block = os.read(descriptor, min(64 * 1024, before.st_size - len(payload)))
            if not block:
                raise OSError("Metadata merge input changed while reading")
            payload.extend(block)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise OSError("Metadata merge input changed while reading")
        return bytes(payload)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)
