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
File and directory utility functions for the NVDebug Tool.

Provides utilities for file system operations including directory management,
empty directory cleanup, and collector file organization.
"""

import os
import stat
from enum import Enum
from typing import List

from ..utils.filesystem_identity import filesystem_owner_uid

from .enums import CollectorServiceMapping

_DIRECTORY_FD_SAFETY_SUPPORTED = (
    hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.rmdir in os.supports_dir_fd
    and os.scandir in os.supports_fd
)
_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_MAX_EMPTY_TREE_DEPTH = 64
_MAX_EMPTY_TREE_ENTRIES = 100_000
_MAX_UID = (1 << 32) - 1


class _EmptyTreeRemovalResult(str, Enum):
    """
    Internal outcome preserving whether another cleanup pass is safe.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    REMOVED = "removed"
    ABSENT = "absent"
    NOT_EMPTY = "not_empty"
    UNSAFE = "unsafe"


def _safe_component(value: str) -> bool:
    """
    Return the safe component.

    After applying local validation, the function forwards ``value`` to ``bool``
    and preserves its return and exception contract.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        Whether the safe component operation succeeds.
    """
    return bool(
        isinstance(value, str)
        and value not in {"", ".", ".."}
        and os.sep not in value
        and (os.altsep is None or os.altsep not in value)
        and "\x00" not in value
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
        and len(value) <= 255
    )


def _trusted_cleanup_owner_ids() -> frozenset[int]:
    """
    Return owners allowed to mutate the active run tree.

    After applying local validation, the function forwards current instance
    state to ``frozenset`` and preserves its return and exception contract.

    Returns:
        The unique trusted cleanup owner identifiers returned by the operation.
    """

    trusted = {0, os.getuid(), os.geteuid()}
    sudo_uid = os.environ.get("SUDO_UID", "")
    if (
        os.geteuid() == 0
        and sudo_uid.isascii()
        and sudo_uid.isdecimal()
        and len(sudo_uid) <= 10
    ):
        parsed_uid = int(sudo_uid)
        if parsed_uid <= _MAX_UID:
            trusted.add(parsed_uid)
    return frozenset(trusted)


def _trusted_cleanup_directory(
    metadata: os.stat_result, owner_uid: int | None = None
) -> bool:
    """
    Return whether untrusted local users cannot replace child entries.

    After applying local validation, the function forwards ``metadata`` to
    ``bool`` and preserves its return and exception contract.

    Args:
        metadata: Metadata object whose ``st_mode`` and ``st_uid`` state is read
            while performing untrusted local users cannot replace child entries.
        owner_uid: Optional verified filesystem UID for this cleanup operation.

    Returns:
        Whether untrusted local users cannot replace child entries.
    """

    return bool(
        stat.S_ISDIR(metadata.st_mode)
        and (
            metadata.st_uid in _trusted_cleanup_owner_ids()
            or metadata.st_uid == owner_uid
        )
        and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _bounded_directory_names(
    directory_fd: int, entry_budget: List[int]
) -> List[str] | None:
    """
    Stream at most the remaining number of safe child names.

    The implementation uses ``directory_fd`` and ``entry_budget`` to stream at
    most the remaining number of safe child names.

    Args:
        directory_fd: Numeric directory fd used while the operation performs
            bounded accounting.
        entry_budget: Entries supplied as ``entry_budget`` without transferring
            container ownership.

    Returns:
        The validated ``names``, or ``None`` when no value qualifies.
    """

    names = []
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                entry_budget[0] -= 1
                if entry_budget[0] < 0 or not _safe_component(entry.name):
                    return None
                names.append(entry.name)
    except OSError:
        return None
    return names


def _directory_fd_is_empty(directory_fd: int) -> bool:
    """
    Check the current descriptor without materializing its entries.

    The implementation uses ``directory_fd`` to check the current descriptor
    without materializing its entries. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        directory_fd: Numeric directory fd used while the operation performs
            bounded accounting.

    Returns:
        Whether the current descriptor without materializing its entries
        operation succeeds.
    """

    try:
        with os.scandir(directory_fd) as entries:
            return next(entries, None) is None
    except (OSError, TypeError, ValueError):
        return False


def _directory_tree_is_empty_fd(
    directory_fd: int,
    *,
    depth: int = 0,
    entry_budget: List[int] | None = None,
) -> bool:
    """
    Inspect a directory tree without following any link or path swap.

    Files, devices, FIFOs, and symlinks all make the directory non-empty. In
    particular, a symlink is never traversed.

    Args:
        directory_fd: Numeric directory fd used while the operation performs
            bounded accounting.
        depth: Numeric depth used while the operation performs bounded
            accounting.
        entry_budget: Optional entry budget; ``None`` selects the function's
            default behavior.

    Returns:
        Whether the inspect a directory tree without following any link or path
        swap operation succeeds.
    """

    if depth > _MAX_EMPTY_TREE_DEPTH:
        return False
    if entry_budget is None:
        entry_budget = [_MAX_EMPTY_TREE_ENTRIES]
    names = _bounded_directory_names(directory_fd, entry_budget)
    if names is None:
        return False

    for name in names:
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return False
        if not stat.S_ISDIR(metadata.st_mode):
            # Files, devices, FIFOs, and symlinks all make the directory
            # non-empty. In particular, a symlink is never traversed.
            return False
        try:
            child_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=directory_fd)
        except OSError:
            return False
        try:
            opened = os.fstat(child_fd)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                return False
            if not _directory_tree_is_empty_fd(
                child_fd,
                depth=depth + 1,
                entry_budget=entry_budget,
            ):
                return False
        finally:
            os.close(child_fd)
    return True


def _remove_empty_tree_at(
    parent_fd: int,
    name: str,
    *,
    depth: int = 0,
    entry_budget: List[int] | None = None,
    _prevalidated_empty: bool = False,
    owner_uid: int | None = None,
) -> _EmptyTreeRemovalResult:
    """
    Remove an empty directory tree relative to an owned private parent.

    The implementation uses ``parent_fd``, ``name``, ``depth``,
    ``entry_budget``, and ``_prevalidated_empty`` to remove an empty directory
    tree relative to an owned private parent. Cleanup in the ``finally`` path
    runs for successful, failed, and cancelled execution.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        depth: Numeric depth used while the operation performs bounded
            accounting.
        entry_budget: Optional entry budget; ``None`` selects the function's
            default behavior.
        _prevalidated_empty: Whether prevalidated empty is enabled or required
            for this operation.
        owner_uid: Filesystem UID verified before the cleanup traversal. A
            direct caller resolves it through the pinned parent once.

    Returns:
        A ``_EmptyTreeRemovalResult`` representing remove empty tree at.
    """

    if (
        not _DIRECTORY_FD_SAFETY_SUPPORTED
        or not _safe_component(name)
        or depth > _MAX_EMPTY_TREE_DEPTH
    ):
        return _EmptyTreeRemovalResult.UNSAFE
    if entry_budget is None:
        entry_budget = [_MAX_EMPTY_TREE_ENTRIES]
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return _EmptyTreeRemovalResult.ABSENT
    except OSError:
        return _EmptyTreeRemovalResult.UNSAFE
    if owner_uid is None:
        try:
            owner_uid = filesystem_owner_uid(parent_fd, observed_uid=before.st_uid)
        except OSError:
            return _EmptyTreeRemovalResult.UNSAFE
    if not _trusted_cleanup_directory(before, owner_uid):
        return _EmptyTreeRemovalResult.UNSAFE
    try:
        directory_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
    except OSError:
        return _EmptyTreeRemovalResult.UNSAFE

    try:
        opened = os.fstat(directory_fd)
        identity = (opened.st_dev, opened.st_ino)
        if identity != (before.st_dev, before.st_ino) or not _trusted_cleanup_directory(
            opened, owner_uid
        ):
            return _EmptyTreeRemovalResult.UNSAFE
        if not _prevalidated_empty and not _directory_tree_is_empty_fd(
            directory_fd,
            depth=depth,
        ):
            return _EmptyTreeRemovalResult.NOT_EMPTY
        names = _bounded_directory_names(directory_fd, entry_budget)
        if names is None:
            return _EmptyTreeRemovalResult.UNSAFE
        for child_name in names:
            try:
                child_metadata = os.stat(
                    child_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError:
                return _EmptyTreeRemovalResult.UNSAFE
            if not stat.S_ISDIR(child_metadata.st_mode):
                # The read-only preflight proved that every original entry was
                # a directory. A file here is concurrent mutation, not normal
                # non-empty content, so no later cleanup pass is authorized.
                return _EmptyTreeRemovalResult.UNSAFE
            child_result = _remove_empty_tree_at(
                directory_fd,
                child_name,
                depth=depth + 1,
                entry_budget=entry_budget,
                _prevalidated_empty=True,
                owner_uid=owner_uid,
            )
            if child_result is _EmptyTreeRemovalResult.NOT_EMPTY:
                return child_result
            if child_result is not _EmptyTreeRemovalResult.REMOVED:
                return _EmptyTreeRemovalResult.UNSAFE
        if not _directory_fd_is_empty(directory_fd):
            return _EmptyTreeRemovalResult.UNSAFE
    finally:
        os.close(directory_fd)

    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            current.st_dev,
            current.st_ino,
        ) != identity or not _trusted_cleanup_directory(current, owner_uid):
            return _EmptyTreeRemovalResult.UNSAFE
        os.rmdir(name, dir_fd=parent_fd)
        return _EmptyTreeRemovalResult.REMOVED
    except OSError:
        # rmdir never follows a swapped symlink. Replacement directories are
        # rejected by identity and by the private-parent invariant.
        return _EmptyTreeRemovalResult.UNSAFE


def is_directory_empty(directory: str) -> bool:
    """
    Check if a directory is empty or only contains empty subdirectories.

    The implementation uses ``directory`` to check if a directory is empty or
    only contains empty subdirectories. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        directory: filesystem location used as the directory for this operation.

    Returns:
        Whether the if a directory is empty or only contains empty
        subdirectories operation succeeds.
    """
    if not _DIRECTORY_FD_SAFETY_SUPPORTED:
        return False
    try:
        before = os.lstat(directory)
        if not stat.S_ISDIR(before.st_mode):
            return False
        directory_fd = os.open(directory, _DIRECTORY_OPEN_FLAGS)
    except FileNotFoundError:
        return True
    except (OSError, TypeError, ValueError):
        return False
    try:
        opened = os.fstat(directory_fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            return False
        return _directory_tree_is_empty_fd(directory_fd)
    finally:
        os.close(directory_fd)


def cleanup_empty_directories(base_dir: str, dut_ids: List[str]) -> List[str]:
    """
    Remove empty collector group directories and error-logs if no content.

    Also removes empty DUT directories if they become empty after cleanup.

    Args:
        base_dir: filesystem location used as the base dir for this operation.
        dut_ids: Entries supplied as ``dut_ids`` without transferring container
            ownership.

    Returns:
        The cleanup empty directories returned in operation-defined order.
    """
    removed_dirs = []

    if not _DIRECTORY_FD_SAFETY_SUPPORTED:
        return removed_dirs
    try:
        base_fd = os.open(base_dir, _DIRECTORY_OPEN_FLAGS)
    except FileNotFoundError:
        return removed_dirs
    except (OSError, TypeError, ValueError) as error:
        print(f"Warning: Error during directory cleanup: {error}")
        return removed_dirs

    try:
        base_metadata = os.fstat(base_fd)
        try:
            owner_uid = filesystem_owner_uid(base_fd, observed_uid=base_metadata.st_uid)
        except OSError:
            return removed_dirs
        if not _trusted_cleanup_directory(base_metadata, owner_uid):
            return removed_dirs

        for dut_id in dut_ids:
            if not _safe_component(dut_id):
                continue
            dut_dir = os.path.join(base_dir, dut_id)
            try:
                dut_fd = os.open(dut_id, _DIRECTORY_OPEN_FLAGS, dir_fd=base_fd)
            except OSError:
                continue
            try:
                if not _trusted_cleanup_directory(os.fstat(dut_fd), owner_uid):
                    continue
                dut_cleanup_safe = True
                for group in (
                    "redfish",
                    "ipmi",
                    "ssh",
                    "host",
                    "health_check",
                    "error-logs",
                ):
                    result = _remove_empty_tree_at(dut_fd, group, owner_uid=owner_uid)
                    if result is _EmptyTreeRemovalResult.REMOVED:
                        removed_dirs.append(os.path.join(dut_dir, group))
                    elif result is _EmptyTreeRemovalResult.UNSAFE:
                        dut_cleanup_safe = False
            finally:
                os.close(dut_fd)

            if not dut_cleanup_safe:
                continue
            if (
                _remove_empty_tree_at(base_fd, dut_id, owner_uid=owner_uid)
                is _EmptyTreeRemovalResult.REMOVED
            ):
                removed_dirs.append(dut_dir)
    except Exception as e:
        # Log error but don't fail
        print(f"Warning: Error during directory cleanup: {e}")
    finally:
        os.close(base_fd)

    return removed_dirs


def ensure_directory_exists(directory: str) -> None:
    """
    Ensure a directory exists, creating it if necessary.

    The implementation uses ``directory`` to ensure a directory exists, creating
    it if necessary.

    Args:
        directory: filesystem location used as the directory for this operation.
    """
    os.makedirs(directory, exist_ok=True)


def get_collector_group_from_id(collector_id: str) -> str:
    """
    Get collector group from ID.

    After applying local validation, the function forwards ``collector_id`` to
    ``CollectorServiceMapping.get_service_from_collector_id`` and preserves its
    return and exception contract.

    Args:
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.

    Returns:
        The canonical collector group from identifier text.
    """
    return CollectorServiceMapping.get_service_from_collector_id(collector_id)
