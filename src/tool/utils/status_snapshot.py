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
Bounded, symlink-safe validation for collection-status generations.

This module owns the status snapshot boundary and exposes
``SnapshotConsistencyError``, ``SnapshotArtifactFormatError``,
``_safe_component``, ``_directory_identity``, and ``_leaf_identity``. Keeping
those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

from .filesystem_identity import directory_security_identity
from .run_limits import (
    MAX_DUT_ID_BYTES,
    MAX_DUTS,
    MAX_SNAPSHOT_ROOT_ENTRIES,
    is_printable_identity,
    snapshot_directory_scan_budget_seconds,
)

MAX_ROOT_STATUS_BYTES = 32 * 1024 * 1024
MAX_DUT_STATUS_BYTES = 16 * 1024 * 1024
MAX_TIMING_BYTES = 16 * 1024 * 1024
MAX_RUN_RESULT_BYTES = 256 * 1024
MAX_SUMMARY_BYTES = 2 * 1024 * 1024
RECEIPTLESS_SNAPSHOT_COMPATIBILITY_VERSION = "1.0"

_GENERATION_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_CANDIDATE_PREFIX = ".collection-status-candidate-"
_NON_DUT_ROOT_DIRECTORIES = {
    ".metadata",
    "backup",
    "config",
    "report",
    "reports",
    "temp",
}
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


class SnapshotConsistencyError(RuntimeError):
    """
    A status consumer observed an unsafe, incomplete, or mixed snapshot.

    Callers receive this exception when the snapshot consistency error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


class SnapshotArtifactFormatError(SnapshotConsistencyError):
    """
    A bounded legacy artifact could not be decoded or parsed.

    Callers receive this exception when the snapshot artifact format error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _safe_component(value: Any, *, label: str) -> str:
    """
    Return the safe component.

    The implementation uses ``value`` and ``label`` to produce the safe
    component. If the function cannot produce the safe component, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        value: Value evaluated while performing safe component.
        label: Text supplied as label in the format accepted by this function.

    Returns:
        The validated ``value``.

    Raises:
        SnapshotConsistencyError: If invalid ``label`` component.
    """
    if (
        not is_printable_identity(value, maximum_bytes=MAX_DUT_ID_BYTES)
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise SnapshotConsistencyError(f"Invalid {label} component")
    return value


def _directory_identity(descriptor: int) -> Tuple[int, int, int, int, int]:
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
        SnapshotConsistencyError: If status snapshot parent is not a directory.
    """
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise SnapshotConsistencyError("Status snapshot parent is not a directory")
    return directory_security_identity(metadata)


def _leaf_identity(metadata: os.stat_result) -> Tuple[int, ...]:
    """
    Return the leaf identity.

    The implementation uses ``metadata`` to produce the leaf identity.

    Args:
        metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing leaf
            identity.

    Returns:
        A tuple containing ``st dev``, ``st ino``, ``st mode``, ``st size``,
        ``st mtime ns``, and ``st ctime ns`` in that order.
    """
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_directory_path(path: Path) -> int:
    """
    Open directory path.

    The implementation uses ``path`` to open directory path. If the function
    cannot open directory path, its exception reaches the caller instead of
    being converted into a successful result.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The validated ``descriptor``.

    Raises:
        SnapshotConsistencyError: If could not safely open status snapshot root:
            ``lexical``.
    """
    lexical = Path(os.path.abspath(os.fspath(path)))
    descriptor = os.open(os.path.sep, _DIRECTORY_FLAGS)
    try:
        for component in lexical.parts[1:]:
            component = _safe_component(component, label="bundle root")
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        _directory_identity(descriptor)
        return descriptor
    except BaseException as error:
        os.close(descriptor)
        if isinstance(error, SnapshotConsistencyError):
            raise
        raise SnapshotConsistencyError(
            f"Could not safely open status snapshot root: {lexical}"
        ) from error


def _open_child_directory(
    parent_descriptor: int,
    component: str,
    *,
    source: Path,
    missing_ok: bool = False,
) -> Optional[int]:
    """
    Open child directory.

    The implementation uses ``parent_descriptor``, ``component``, ``source``,
    and ``missing_ok`` to open child directory. If the function cannot open
    child directory, its exception reaches the caller instead of being converted
    into a successful result. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        parent_descriptor: Numeric parent descriptor used while the operation
            performs bounded accounting.
        component: Text supplied as component in the format accepted by this
            function.
        source: filesystem location used as the source for this operation.
        missing_ok: Whether missing ok is enabled or required for this
            operation.

    Returns:
        The validated ``descriptor``, or ``None`` when no value qualifies.

    Raises:
        SnapshotConsistencyError: If status snapshot directory is missing:
            ``source``; or could not safely open status snapshot directory:
            ``source``.
    """
    component = _safe_component(component, label="snapshot directory")
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent_descriptor)
        _directory_identity(descriptor)
        return descriptor
    except FileNotFoundError:
        if missing_ok:
            return None
        raise SnapshotConsistencyError(
            f"Status snapshot directory is missing: {source}"
        ) from None
    except BaseException as error:
        raise SnapshotConsistencyError(
            f"Could not safely open status snapshot directory: {source}"
        ) from error
    finally:
        if descriptor is not None:
            try:
                _directory_identity(descriptor)
            except BaseException:
                os.close(descriptor)


def _revalidate_child_directory(
    parent_descriptor: int,
    component: str,
    expected: Tuple[int, int, int],
    *,
    source: Path,
) -> None:
    """
    Revalidate a child directory against its pinned filesystem identity.

    The implementation uses ``parent_descriptor``, ``component``, ``expected``,
    and ``source`` to revalidate a child directory against its pinned filesystem
    identity. If the function cannot revalidate a child directory against its
    pinned filesystem identity, its exception reaches the caller instead of
    being converted into a successful result. Cleanup in the ``finally`` path
    runs for successful, failed, and cancelled execution.

    Args:
        parent_descriptor: Numeric parent descriptor used while the operation
            performs bounded accounting.
        component: Text supplied as component in the format accepted by this
            function.
        expected: Entries supplied as ``expected`` without transferring
            container ownership.
        source: filesystem location used as the source for this operation.

    Raises:
        SnapshotConsistencyError: If status snapshot directory changed while
            reading: ``source``.
    """
    confirmation = _open_child_directory(
        parent_descriptor,
        component,
        source=source,
    )
    assert confirmation is not None
    try:
        if _directory_identity(confirmation) != expected:
            raise SnapshotConsistencyError(
                f"Status snapshot directory changed while reading: {source}"
            )
    finally:
        os.close(confirmation)


def _read_regular_leaf(
    parent_descriptor: int,
    name: str,
    *,
    source: Path,
    byte_limit: int,
    missing_ok: bool = False,
) -> Optional[bytes]:
    """
    Read regular leaf.

    The implementation uses ``parent_descriptor``, ``name``, ``source``,
    ``byte_limit``, and ``missing_ok`` to read regular leaf. Parsing or I/O must
    finish before the validated representation is made available to the caller.
    If the function cannot read regular leaf, its exception reaches the caller
    instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        parent_descriptor: Numeric parent descriptor used while the operation
            performs bounded accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        source: filesystem location used as the source for this operation.
        byte_limit: Upper bound enforced for byte limit; the consuming boundary
            rejects or truncates values that exceed it.
        missing_ok: Whether missing ok is enabled or required for this
            operation.

    Returns:
        The validated ``data``, or ``None`` when no value qualifies.

    Raises:
        SnapshotConsistencyError: If status snapshot artifact is missing:
            ``source``; could not safely open status snapshot artifact:
            ``source``; status snapshot artifact is not a regular file:
            ``source``; or status snapshot artifact exceeds ``byte_limit``
            bytes: ``source``; or another input invariant is violated.
    """
    name = _safe_component(name, label="snapshot leaf")
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(name, _LEAF_FLAGS, dir_fd=parent_descriptor)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise SnapshotConsistencyError(
            f"Status snapshot artifact is missing: {source}"
        ) from None
    except BaseException as error:
        raise SnapshotConsistencyError(
            f"Could not safely open status snapshot artifact: {source}"
        ) from error

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SnapshotConsistencyError(
                f"Status snapshot artifact is not a regular file: {source}"
            )
        if before.st_size > byte_limit:
            raise SnapshotConsistencyError(
                f"Status snapshot artifact exceeds {byte_limit} bytes: {source}"
            )

        chunks = []
        remaining = byte_limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > byte_limit:
            raise SnapshotConsistencyError(
                f"Status snapshot artifact exceeds {byte_limit} bytes: {source}"
            )

        after = os.fstat(descriptor)
        if _leaf_identity(before) != _leaf_identity(after):
            raise SnapshotConsistencyError(
                f"Status snapshot artifact changed while reading: {source}"
            )

        try:
            confirmation = os.open(name, _LEAF_FLAGS, dir_fd=parent_descriptor)
        except BaseException as error:
            raise SnapshotConsistencyError(
                f"Status snapshot artifact changed while reading: {source}"
            ) from error
        try:
            if _leaf_identity(os.fstat(confirmation)) != _leaf_identity(after):
                raise SnapshotConsistencyError(
                    f"Status snapshot artifact changed while reading: {source}"
                )
        finally:
            os.close(confirmation)
        return data
    finally:
        os.close(descriptor)


def _decode_json_object(data: bytes, *, source: Path) -> Dict[str, Any]:
    """
    Decode JSON object.

    The implementation uses ``data`` and ``source`` to decode JSON object.
    Parsing or I/O must finish before the validated representation is made
    available to the caller. If the function cannot decode JSON object, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        data: Bounded byte sequence supplied as data.
        source: filesystem location used as the source for this operation.

    Returns:
        The validated ``document``.

    Raises:
        SnapshotArtifactFormatError: If could not parse status snapshot
            artifact: ``source``.
        SnapshotConsistencyError: If status snapshot artifact is not a JSON
            object: ``source``.
    """
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SnapshotArtifactFormatError(
            f"Could not parse status snapshot artifact: {source}"
        ) from error
    if not isinstance(document, dict):
        raise SnapshotConsistencyError(
            f"Status snapshot artifact is not a JSON object: {source}"
        )
    return document


def _validate_marker(
    marker: Any,
    expected_generation: str,
    *,
    source: Path,
) -> None:
    """
    Validate marker.

    The implementation uses ``marker``, ``expected_generation``, and ``source``
    to validate marker. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        marker: Marker object whose ``get`` state is read while performing
            marker.
        expected_generation: Text supplied as expected generation in the format
            accepted by this function.
        source: filesystem location used as the source for this operation.

    Raises:
        SnapshotConsistencyError: If status snapshot marker is missing:
            ``source``; or status snapshot generation is incomplete or mixed:
            ``source``.
    """
    if not isinstance(marker, dict):
        raise SnapshotConsistencyError(f"Status snapshot marker is missing: {source}")
    generation = marker.get("snapshot_generation")
    if (
        generation != expected_generation
        or marker.get("terminal_finalized") is not True
    ):
        raise SnapshotConsistencyError(
            f"Status snapshot generation is incomplete or mixed: {source}"
        )


def _root_generation(
    document: Dict[str, Any],
    *,
    source: Path,
    required: bool,
) -> Optional[str]:
    """
    Return the root generation.

    The implementation uses ``document``, ``source``, and ``required`` to
    produce the root generation. If the function cannot produce the root
    generation, its exception reaches the caller instead of being converted into
    a successful result.

    Args:
        document: Mapping supplying fields for root generation.
        source: filesystem location used as the source for this operation.
        required: Whether required is enabled or required for this operation.

    Returns:
        The validated ``generation``, or ``None`` when no value qualifies.

    Raises:
        SnapshotConsistencyError: If root status snapshot metadata is missing:
            ``source``; or root status snapshot generation is invalid:
            ``source``.
    """
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        if not required:
            return None
        raise SnapshotConsistencyError(
            f"Root status snapshot metadata is missing: {source}"
        )
    generation = metadata.get("snapshot_generation")
    terminal = metadata.get("terminal_finalized")
    if generation is None and terminal is None and not required:
        return None
    if not isinstance(generation, str) or not _GENERATION_PATTERN.fullmatch(generation):
        raise SnapshotConsistencyError(
            f"Root status snapshot generation is invalid: {source}"
        )
    _validate_marker(metadata, generation, source=source)
    return generation


class _SnapshotSession:
    """
    Pin one lexical bundle root for a coherent set of bounded reads.

    The type coordinates ``close``, ``load_root``, ``_open_dut_metadata``,
    ``read_dut_json``, and ``read_summary`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(self, bundle_root: Path) -> None:
        """
        Initialize a ``_SnapshotSession`` instance.

        The initializer records ``generation``, ``metadata_descriptor``,
        ``metadata_identity``, ``root``, and ``root_bytes`` for later operations
        and establishes the instance invariants before any public method runs.

        Args:
            bundle_root: filesystem location used as the bundle root for this
                operation.
        """
        self.root = Path(bundle_root)
        self.root_descriptor = _open_directory_path(self.root)
        self.root_identity = _directory_identity(self.root_descriptor)
        self.metadata_descriptor: Optional[int] = None
        self.metadata_identity: Optional[Tuple[int, int, int]] = None
        self.root_document: Optional[Dict[str, Any]] = None
        self.root_bytes: Optional[bytes] = None
        self.generation: Optional[str] = None

    def close(self) -> None:
        """
        Close the _SnapshotSession.

        The implementation uses current instance state to close the
        _SnapshotSession. It updates ``metadata_descriptor`` and
        ``root_descriptor`` on the instance as part of that state transition.
        Cleanup in the ``finally`` path runs for successful, failed, and
        cancelled execution.
        """
        metadata_descriptor = self.metadata_descriptor
        root_descriptor = self.root_descriptor
        self.metadata_descriptor = None
        self.root_descriptor = -1
        try:
            if metadata_descriptor is not None:
                os.close(metadata_descriptor)
        finally:
            if root_descriptor >= 0:
                os.close(root_descriptor)

    def __enter__(self) -> "_SnapshotSession":
        """
        Enter the _SnapshotSession context.

        Entering the scope acquires or validates its owned resources and returns
        the value used until the matching exit method completes cleanup.

        Returns:
            The validated ``self``.
        """
        return self

    def __exit__(self, *_args: Any) -> None:
        """
        Exit the _SnapshotSession context.

        Leaving the scope releases resources owned by the context while
        preserving the exception-propagation behavior declared by the
        context-manager protocol.

        Args:
            _args: Additional positional values forwarded in caller-provided
                order.
        """
        self.close()

    def load_root(self, *, required: bool) -> Optional[str]:
        """
        Load root.

        The implementation uses ``required`` to load root. Parsing or I/O must
        finish before the validated representation is made available to the
        caller. It updates ``generation``, ``metadata_descriptor``,
        ``metadata_identity``, ``root_bytes``, and ``root_document`` on the
        instance as part of that state transition.

        Args:
            required: Whether required is enabled or required for this
                operation.

        Returns:
            The canonical root text, or ``None`` when the requested value is
            unavailable.
        """
        metadata_source = self.root / ".metadata"
        self.metadata_descriptor = _open_child_directory(
            self.root_descriptor,
            ".metadata",
            source=metadata_source,
            missing_ok=not required,
        )
        if self.metadata_descriptor is None:
            return None
        self.metadata_identity = _directory_identity(self.metadata_descriptor)
        source = metadata_source / "collection_status.json"
        self.root_bytes = _read_regular_leaf(
            self.metadata_descriptor,
            "collection_status.json",
            source=source,
            byte_limit=MAX_ROOT_STATUS_BYTES,
            missing_ok=not required,
        )
        if self.root_bytes is None:
            return None
        self.root_document = _decode_json_object(self.root_bytes, source=source)
        self.generation = _root_generation(
            self.root_document,
            source=source,
            required=required,
        )
        return self.generation

    def _open_dut_metadata(
        self,
        dut_id: str,
        *,
        missing_ok: bool,
    ) -> Optional[Tuple[int, int, Tuple[int, int, int], Tuple[int, int, int]]]:
        """
        Open DUT metadata.

        The implementation uses ``dut_id`` and ``missing_ok`` to open DUT
        metadata. Cleanup in the ``finally`` path runs for successful, failed,
        and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            missing_ok: Whether missing ok is enabled or required for this
                operation.

        Returns:
            A tuple containing ``DUT descriptor``, ``metadata descriptor``,
            ``DUT identity``, and ``directory identity`` in that order.
        """
        dut_id = _safe_component(dut_id, label="DUT")
        dut_source = self.root / dut_id
        dut_descriptor = _open_child_directory(
            self.root_descriptor,
            dut_id,
            source=dut_source,
            missing_ok=missing_ok,
        )
        if dut_descriptor is None:
            return None
        metadata_descriptor: Optional[int] = None
        try:
            dut_identity = _directory_identity(dut_descriptor)
            metadata_source = dut_source / ".metadata"
            metadata_descriptor = _open_child_directory(
                dut_descriptor,
                ".metadata",
                source=metadata_source,
                missing_ok=missing_ok,
            )
            if metadata_descriptor is None:
                os.close(dut_descriptor)
                return None
            return (
                dut_descriptor,
                metadata_descriptor,
                dut_identity,
                _directory_identity(metadata_descriptor),
            )
        except BaseException:
            try:
                if metadata_descriptor is not None:
                    os.close(metadata_descriptor)
            finally:
                os.close(dut_descriptor)
            raise

    def read_dut_json(
        self,
        dut_id: str,
        name: str,
        *,
        byte_limit: int,
        required: bool,
    ) -> Optional[Dict[str, Any]]:
        """
        Read DUT JSON.

        After applying local validation, the function forwards ``dut_id``,
        ``name``, ``byte_limit``, and ``required`` to ``_decode_json_object``
        and preserves its return and exception contract. Parsing or I/O must
        finish before the validated representation is made available to the
        caller. Cleanup in the ``finally`` path runs for successful, failed, and
        cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            name: Stable name used for lookup and operator-facing diagnostics.
            byte_limit: Upper bound enforced for byte limit; the consuming
                boundary rejects or truncates values that exceed it.
            required: Whether required is enabled or required for this
                operation.

        Returns:
            A mapping containing DUT JSON, or ``None`` when the requested value
            is unavailable.
        """
        opened = self._open_dut_metadata(dut_id, missing_ok=not required)
        if opened is None:
            return None
        (
            dut_descriptor,
            metadata_descriptor,
            dut_identity,
            metadata_identity,
        ) = opened
        source = self.root / dut_id / ".metadata" / name
        try:
            data = _read_regular_leaf(
                metadata_descriptor,
                name,
                source=source,
                byte_limit=byte_limit,
                missing_ok=not required,
            )
            if data is None:
                return None
            return _decode_json_object(data, source=source)
        finally:
            try:
                _revalidate_child_directory(
                    dut_descriptor,
                    ".metadata",
                    metadata_identity,
                    source=self.root / dut_id / ".metadata",
                )
            finally:
                try:
                    _revalidate_child_directory(
                        self.root_descriptor,
                        dut_id,
                        dut_identity,
                        source=self.root / dut_id,
                    )
                finally:
                    try:
                        os.close(metadata_descriptor)
                    finally:
                        os.close(dut_descriptor)

    def read_summary(
        self,
        dut_id: Optional[str],
        *,
        required: bool,
    ) -> Optional[str]:
        """
        Read summary.

        The implementation uses ``dut_id`` and ``required`` to read summary.
        Parsing or I/O must finish before the validated representation is made
        available to the caller. If the function cannot read summary, its
        exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            required: Whether required is enabled or required for this
                operation.

        Returns:
            The canonical summary text, or ``None`` when the requested value is
            unavailable.

        Raises:
            SnapshotConsistencyError: If terminal status snapshot metadata is
                missing.
            SnapshotArtifactFormatError: If could not parse status snapshot
                artifact: ``source``.
        """
        if dut_id is None:
            if self.metadata_descriptor is None:
                if required:
                    raise SnapshotConsistencyError(
                        "Terminal status snapshot metadata is missing"
                    )
                return None
            descriptor = self.metadata_descriptor
            source = self.root / ".metadata" / "collection_status_summary.txt"
            data = _read_regular_leaf(
                descriptor,
                "collection_status_summary.txt",
                source=source,
                byte_limit=MAX_SUMMARY_BYTES,
                missing_ok=not required,
            )
            try:
                return data.decode("utf-8") if data is not None else None
            except UnicodeError as error:
                raise SnapshotArtifactFormatError(
                    f"Could not parse status snapshot artifact: {source}"
                ) from error

        dut_id = _safe_component(dut_id, label="DUT")
        dut_source = self.root / dut_id
        dut_descriptor = _open_child_directory(
            self.root_descriptor,
            dut_id,
            source=dut_source,
            missing_ok=not required,
        )
        if dut_descriptor is None:
            return None
        dut_identity = _directory_identity(dut_descriptor)
        source = dut_source / "collection_status_summary.txt"
        try:
            data = _read_regular_leaf(
                dut_descriptor,
                "collection_status_summary.txt",
                source=source,
                byte_limit=MAX_SUMMARY_BYTES,
                missing_ok=not required,
            )
            return data.decode("utf-8") if data is not None else None
        except UnicodeError as error:
            raise SnapshotArtifactFormatError(
                f"Could not parse status snapshot artifact: {source}"
            ) from error
        finally:
            try:
                _revalidate_child_directory(
                    self.root_descriptor,
                    dut_id,
                    dut_identity,
                    source=dut_source,
                )
            finally:
                os.close(dut_descriptor)

    def finish(self) -> None:
        """
        Finalize the current operation.

        The implementation uses current instance state to finalize the current
        operation. If the function cannot finalize the current operation, its
        exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Raises:
            SnapshotConsistencyError: If root status snapshot changed while
                reading: ``source``; or status snapshot root changed while
                reading.
        """
        if self.metadata_descriptor is not None:
            if self.root_bytes is not None:
                source = self.root / ".metadata" / "collection_status.json"
                confirmation = _read_regular_leaf(
                    self.metadata_descriptor,
                    "collection_status.json",
                    source=source,
                    byte_limit=MAX_ROOT_STATUS_BYTES,
                )
                if confirmation != self.root_bytes:
                    raise SnapshotConsistencyError(
                        f"Root status snapshot changed while reading: {source}"
                    )
            assert self.metadata_identity is not None
            _revalidate_child_directory(
                self.root_descriptor,
                ".metadata",
                self.metadata_identity,
                source=self.root / ".metadata",
            )

        confirmation = _open_directory_path(self.root)
        try:
            if _directory_identity(confirmation) != self.root_identity:
                raise SnapshotConsistencyError(
                    "Status snapshot root changed while reading"
                )
        finally:
            os.close(confirmation)


_ConcretePath = type(Path())


class _PinnedDUTPath(_ConcretePath):
    """
    A descriptor-backed path whose root retains its logical DUT name.

    The type coordinates ``with_segments``, ``_make_child``,
    ``_make_child_relpath``, and ``name`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    def __new__(cls, path: Path, logical_name: str) -> "_PinnedDUTPath":
        """
        Create a new _PinnedDUTPath instance.

        After applying local validation, the function forwards ``path`` and
        ``logical_name`` to ``__new__`` and preserves its return and exception
        contract.

        Args:
            path: filesystem location used as the path for this operation.
            logical_name: Stable logical name used for lookup and
                operator-facing diagnostics.

        Returns:
            The validated new filesystem path.
        """
        return super().__new__(cls, path)

    def __init__(self, path: Path, logical_name: str) -> None:
        # pathlib.Path is initialized entirely by ``__new__`` on Python 3.11,
        # where its inherited initializer is ``object.__init__``.  Python 3.12
        # moved part of Path initialization into ``__init__``.  Invoke that
        # initializer only when the concrete Path implementation provides it.
        """
        Initialize a ``_PinnedDUTPath`` instance.

        The initializer records ``_logical_name`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            path: filesystem location used as the path for this operation.
            logical_name: Stable logical name used for lookup and
                operator-facing diagnostics.
        """
        if _ConcretePath.__init__ is not object.__init__:
            super().__init__(path)
        self._logical_name = logical_name

    def with_segments(self, *pathsegments: Any) -> Path:
        # Descendants need their real leaf names. Only the pinned DUT root
        # projects the receipt identity through ``Path.name``.
        """
        Return the with segments.

        After applying local validation, the function forwards ``pathsegments``
        to ``Path`` and preserves its return and exception contract.

        Args:
            pathsegments: Additional positional values forwarded in
                caller-provided order.

        Returns:
            The validated with segments filesystem path.
        """
        return Path(*pathsegments)

    def _make_child(self, args: Tuple[Any, ...]) -> Path:
        # Python 3.11 implements ``/`` and ``joinpath()`` through this private
        # hook instead of ``with_segments()``.  Returning a normal Path keeps
        # the logical DUT name scoped to this descriptor-backed root.
        """
        Return the make child.

        After applying local validation, the function forwards ``args`` to
        ``joinpath`` and preserves its return and exception contract.

        Args:
            args: Entries supplied as ``args`` without transferring container
                ownership.

        Returns:
            The validated make child filesystem path.
        """
        return Path(os.fspath(self)).joinpath(*args)

    def _make_child_relpath(self, part: str) -> Path:
        # Python 3.11 also uses this hook for iterdir/glob descendants.
        """
        Return the make child relpath.

        After applying local validation, the function forwards ``part`` to
        ``joinpath`` and preserves its return and exception contract.

        Args:
            part: Text supplied as part in the format accepted by this function.

        Returns:
            The validated make child relpath filesystem path.
        """
        return Path(os.fspath(self)).joinpath(part)

    @property
    def name(self) -> str:
        """
        Return the name.

        Each access computes the value from ``_logical_name`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The canonical name.
        """
        return self._logical_name


class TerminalSnapshotBinding:
    """
    Pin a receipt-authorized root and every DUT for one consumer session.

    The type coordinates ``root_path``, ``dut_directories``, ``leaf_digests``,
    ``_digest``, and ``_record_digest`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        bundle_root: Path,
        dut_ids: Iterable[str],
        *,
        expected_generation: Optional[str] = None,
        expected_leaf_digests: Optional[Tuple[Tuple[str, int, str], ...]] = None,
        allow_candidate_directories: bool = False,
        allow_pending_run_result: bool = False,
    ) -> None:
        """
        Initialize a ``TerminalSnapshotBinding`` instance.

        The initializer records ``_dut_descriptors``, ``_leaf_digests``,
        ``_run_result_bytes``, ``_session``, and ``bundle_root`` for later
        operations and establishes the instance invariants before any public
        method runs. If the function cannot initialize a
        ``TerminalSnapshotBinding`` instance, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            bundle_root: filesystem location used as the bundle root for this
                operation.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            expected_generation: Optional expected generation; ``None`` selects
                the function's default behavior.
            expected_leaf_digests: Optional expected leaf digests; ``None``
                selects the function's default behavior.
            allow_candidate_directories: Whether allow candidate directories is
                enabled or required for this operation.
            allow_pending_run_result: Whether allow pending run result is
                enabled or required for this operation.

        Raises:
            SnapshotConsistencyError: If snapshot roster exceeds the supported
                maximum of ``MAX_DUTS`` DUTs; duplicate DUT component in
                snapshot roster; or terminal snapshot leaf bytes differ from the
                receipt.
        """
        roster = tuple(_safe_component(dut_id, label="DUT") for dut_id in dut_ids)
        if len(roster) > MAX_DUTS:
            raise SnapshotConsistencyError(
                f"Snapshot roster exceeds the supported maximum of {MAX_DUTS} DUTs"
            )
        if len(roster) != len(set(roster)):
            raise SnapshotConsistencyError("Duplicate DUT component in snapshot roster")

        self.bundle_root = Path(bundle_root)
        self.roster = roster
        self.generation = ""
        self._session: Optional[_SnapshotSession] = None
        self._dut_descriptors: Dict[str, int] = {}
        self._leaf_digests: Dict[str, Tuple[str, int, str]] = {}
        self._run_result_bytes: Optional[bytes] = None
        session = _SnapshotSession(self.bundle_root)
        self._session = session
        try:
            self.generation = self._validate_and_pin(
                expected_generation=expected_generation,
                allow_candidate_directories=allow_candidate_directories,
                allow_pending_run_result=allow_pending_run_result,
            )
            observed_digests = self.leaf_digests
            if (
                expected_leaf_digests is not None
                and observed_digests != expected_leaf_digests
            ):
                raise SnapshotConsistencyError(
                    "Terminal snapshot leaf bytes differ from the receipt"
                )
            session.finish()
        except BaseException:
            self.close(verify=False)
            raise

    @property
    def root_path(self) -> Path:
        """
        Return a path that resolves only through the retained root descriptor.

        Each access computes the value from ``_require_open_session`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The validated root path filesystem path.
        """

        session = self._require_open_session()
        return Path("/proc/self/fd") / str(session.root_descriptor)

    @property
    def dut_directories(self) -> Tuple[Path, ...]:
        """
        Return descriptor-backed DUT roots in exact receipt order.

        Each access computes the value from ``_dut_descriptors``,
        ``_require_open_session``, and ``roster`` on the current instance; the
        derived view is not stored as independent state.

        Returns:
            The DUT directories returned in operation-defined order.
        """

        self._require_open_session()
        return tuple(
            _PinnedDUTPath(
                Path("/proc/self/fd") / str(self._dut_descriptors[dut_id]),
                dut_id,
            )
            for dut_id in self.roster
        )

    @property
    def leaf_digests(self) -> Tuple[Tuple[str, int, str], ...]:
        """
        Return ordered exact-byte evidence for every authoritative leaf.

        Each access computes the value from ``_leaf_digests`` and
        ``_require_open_session`` on the current instance; the derived view is
        not stored as independent state.

        Returns:
            The leaf digests returned in operation-defined order.
        """

        self._require_open_session()
        return tuple(self._leaf_digests[path] for path in sorted(self._leaf_digests))

    @staticmethod
    def _digest(relative: str, data: bytes) -> Tuple[str, int, str]:
        """
        Return the digest.

        The implementation uses ``relative`` and ``data`` to produce the digest.

        Args:
            relative: Text supplied as relative in the format accepted by this
                function.
            data: Bounded byte sequence supplied as data.

        Returns:
            A tuple containing ``relative``, ``len``, and ``hexdigest`` in that
            order.
        """
        return relative, len(data), hashlib.sha256(data).hexdigest()

    def _record_digest(self, relative: str, data: bytes) -> None:
        """
        Record digest.

        The implementation uses ``relative`` and ``data`` to record digest.

        Args:
            relative: Text supplied as relative in the format accepted by this
                function.
            data: Bounded byte sequence supplied as data.
        """
        self._leaf_digests[relative] = self._digest(relative, data)

    def _verify_digest(self, relative: str, data: bytes) -> None:
        """
        Verify digest.

        The implementation uses ``relative`` and ``data`` to verify digest.
        Every required invariant is checked before a successful value is
        returned; invalid input follows the function's explicit exception path.

        Args:
            relative: Text supplied as relative in the format accepted by this
                function.
            data: Bounded byte sequence supplied as data.

        Raises:
            SnapshotConsistencyError: If terminal snapshot leaf bytes changed
                while consuming: ``relative``.
        """
        if self._leaf_digests.get(relative) != self._digest(relative, data):
            raise SnapshotConsistencyError(
                f"Terminal snapshot leaf bytes changed while consuming: {relative}"
            )

    def read_status(self, dut_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Read one committed status document through retained descriptors.

        The implementation uses ``dut_id`` to read one committed status document
        through retained descriptors. Parsing or I/O must finish before the
        validated representation is made available to the caller. If the
        function cannot read one committed status document through retained
        descriptors, its exception reaches the caller instead of being converted
        into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing status.

        Raises:
            SnapshotConsistencyError: If root status snapshot is unavailable.
        """

        session = self._require_open_session()
        if dut_id is None:
            if session.metadata_descriptor is None:
                raise SnapshotConsistencyError("Root status snapshot is unavailable")
            source = self.bundle_root / ".metadata" / "collection_status.json"
            data = _read_regular_leaf(
                session.metadata_descriptor,
                "collection_status.json",
                source=source,
                byte_limit=MAX_ROOT_STATUS_BYTES,
            )
            assert data is not None
            self._verify_digest(".metadata/collection_status.json", data)
            document = _decode_json_object(data, source=source)
            validate_status_document(document, self.generation, source=source)
            return document
        document = self._read_pinned_dut_json(
            dut_id,
            "collection_status.json",
            byte_limit=MAX_DUT_STATUS_BYTES,
        )
        validate_status_document(
            document,
            self.generation,
            source=self.bundle_root / dut_id / ".metadata" / "collection_status.json",
        )
        return document

    def read_timing(self, dut_id: str) -> Dict[str, Any]:
        """
        Read one committed timing document through a retained DUT.

        The implementation uses ``dut_id`` to read one committed timing document
        through a retained DUT. Parsing or I/O must finish before the validated
        representation is made available to the caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``document``.
        """

        document = self._read_pinned_dut_json(
            dut_id,
            "timing.json",
            byte_limit=MAX_TIMING_BYTES,
        )
        validate_timing_document(
            document,
            self.generation,
            source=self.bundle_root / dut_id / ".metadata" / "timing.json",
        )
        return document

    def _read_pinned_dut_json(
        self,
        dut_id: str,
        name: str,
        *,
        byte_limit: int,
    ) -> Dict[str, Any]:
        """
        Read pinned DUT JSON.

        After applying local validation, the function forwards ``dut_id``,
        ``name``, and ``byte_limit`` to ``_decode_json_object`` and preserves
        its return and exception contract. Parsing or I/O must finish before the
        validated representation is made available to the caller. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            name: Stable name used for lookup and operator-facing diagnostics.
            byte_limit: Upper bound enforced for byte limit; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A mapping containing pinned DUT JSON.

        Raises:
            SnapshotConsistencyError: If DUT is not present in the bound roster.
        """
        dut_id = _safe_component(dut_id, label="DUT")
        if dut_id not in self._dut_descriptors:
            raise SnapshotConsistencyError("DUT is not present in the bound roster")
        dut_descriptor = self._dut_descriptors[dut_id]
        metadata_source = self.bundle_root / dut_id / ".metadata"
        metadata_descriptor = _open_child_directory(
            dut_descriptor,
            ".metadata",
            source=metadata_source,
        )
        assert metadata_descriptor is not None
        metadata_identity = _directory_identity(metadata_descriptor)
        source = metadata_source / name
        relative = f"{dut_id}/.metadata/{name}"
        try:
            data = _read_regular_leaf(
                metadata_descriptor,
                name,
                source=source,
                byte_limit=byte_limit,
            )
            assert data is not None
            self._verify_digest(relative, data)
            return _decode_json_object(data, source=source)
        finally:
            try:
                _revalidate_child_directory(
                    dut_descriptor,
                    ".metadata",
                    metadata_identity,
                    source=metadata_source,
                )
            finally:
                os.close(metadata_descriptor)

    def _require_open_session(self) -> _SnapshotSession:
        """
        Require open session.

        The implementation uses current instance state to require open session.
        Every required invariant is checked before a successful value is
        returned; invalid input follows the function's explicit exception path.

        Returns:
            The validated ``session``.

        Raises:
            SnapshotConsistencyError: If terminal snapshot binding is closed.
        """
        session = self._session
        if session is None or session.root_descriptor < 0:
            raise SnapshotConsistencyError("Terminal snapshot binding is closed")
        return session

    def _validate_and_pin(
        self,
        *,
        expected_generation: Optional[str],
        allow_candidate_directories: bool,
        allow_pending_run_result: bool,
    ) -> str:
        """
        Validate and pin.

        The implementation uses ``expected_generation``,
        ``allow_candidate_directories``, and ``allow_pending_run_result`` to
        validate and pin. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path. It updates ``_run_result_bytes`` on the
        instance as part of that state transition. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        Remote I/O uses the configured transport policy and returns only after
        its response or failure has been observed.

        Args:
            expected_generation: Text supplied as expected generation in the
                format accepted by this function.
            allow_candidate_directories: Whether allow candidate directories is
                enabled or required for this operation.
            allow_pending_run_result: Whether allow pending run result is
                enabled or required for this operation.

        Returns:
            The validated ``generation``.

        Raises:
            SnapshotConsistencyError: If terminal status snapshot generation
                differs from the receipt; terminal status snapshot DUT roster is
                missing or invalid; terminal status snapshot DUT roster is
                mixed; or pending RunResult is not consumable; or another input
                invariant is violated.
            SnapshotArtifactFormatError: If could not parse canonical RunResult:
                ``run_result_source``.
        """
        session = self._require_open_session()
        generation = session.load_root(required=True)
        assert generation is not None
        assert session.root_bytes is not None
        self._record_digest(
            ".metadata/collection_status.json",
            session.root_bytes,
        )
        if expected_generation is not None and generation != expected_generation:
            raise SnapshotConsistencyError(
                "Terminal status snapshot generation differs from the receipt"
            )

        root_metadata = session.root_document.get("metadata", {})
        committed_roster = (
            root_metadata.get("dut_roster") if isinstance(root_metadata, dict) else None
        )
        if not isinstance(committed_roster, list):
            raise SnapshotConsistencyError(
                "Terminal status snapshot DUT roster is missing or invalid"
            )
        validated_committed_roster = tuple(
            _safe_component(dut_id, label="DUT") for dut_id in committed_roster
        )
        if validated_committed_roster != self.roster:
            raise SnapshotConsistencyError(
                "Terminal status snapshot DUT roster is mixed"
            )

        assert session.metadata_descriptor is not None
        run_result_source = self.bundle_root / ".metadata" / "run_result.json"
        run_result_data = _read_regular_leaf(
            session.metadata_descriptor,
            "run_result.json",
            source=run_result_source,
            byte_limit=MAX_RUN_RESULT_BYTES,
        )
        assert run_result_data is not None
        run_result_document = _decode_json_object(
            run_result_data,
            source=run_result_source,
        )
        projected_result = root_metadata.get("run_result")
        if run_result_document == {
            "schema_version": "1.0",
            "state": "candidate_pending",
        }:
            if not allow_pending_run_result:
                raise SnapshotConsistencyError("Pending RunResult is not consumable")
            if projected_result is not None:
                raise SnapshotConsistencyError(
                    "Pending RunResult disagrees with root status"
                )
        else:
            try:
                from ..core.run_result import validate_run_result_document

                canonical_result = validate_run_result_document(run_result_document)
            except (TypeError, ValueError) as error:
                raise SnapshotArtifactFormatError(
                    f"Could not parse canonical RunResult: {run_result_source}"
                ) from error
            if projected_result != canonical_result.to_dict():
                raise SnapshotConsistencyError(
                    "Canonical RunResult disagrees with root status"
                )
        self._run_result_bytes = run_result_data
        self._record_digest(".metadata/run_result.json", run_result_data)

        observed_duts = set()
        scan_deadline = time.monotonic() + snapshot_directory_scan_budget_seconds(
            len(self.roster)
        )
        with os.scandir(session.root_descriptor) as entries:
            for entry_count, entry in enumerate(entries, start=1):
                if (
                    entry_count > MAX_SNAPSHOT_ROOT_ENTRIES
                    or time.monotonic() > scan_deadline
                ):
                    raise SnapshotConsistencyError(
                        "Terminal snapshot root enumeration exceeded its bound"
                    )
                name = _safe_component(entry.name, label="snapshot root")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise SnapshotConsistencyError(
                        f"Terminal snapshot root contains a symbolic link: {name}"
                    )
                if not stat.S_ISDIR(metadata.st_mode):
                    continue
                if name in self.roster:
                    observed_duts.add(name)
                    continue
                if name in _NON_DUT_ROOT_DIRECTORIES:
                    continue
                if allow_candidate_directories and name.startswith(_CANDIDATE_PREFIX):
                    continue
                raise SnapshotConsistencyError(
                    f"Terminal snapshot contains an unexpected DUT directory: {name}"
                )
        if time.monotonic() > scan_deadline:
            raise SnapshotConsistencyError(
                "Terminal snapshot root enumeration exceeded its bound"
            )
        if observed_duts != set(self.roster):
            raise SnapshotConsistencyError(
                "Terminal snapshot DUT directories differ from the receipt roster"
            )

        global_summary = session.read_summary(None, required=True)
        assert global_summary is not None
        self._record_digest(
            ".metadata/collection_status_summary.txt",
            global_summary.encode("utf-8"),
        )
        validate_summary_document(
            global_summary,
            generation,
            source=self.bundle_root / ".metadata" / "collection_status_summary.txt",
        )

        for dut_id in self.roster:
            self._pin_and_validate_dut(dut_id, generation)
        return generation

    def _pin_and_validate_dut(self, dut_id: str, generation: str) -> None:
        """
        Pin and validate the DUT directory used by the terminal snapshot.

        The implementation uses ``dut_id`` and ``generation`` to pin and
        validate the DUT directory used by the terminal snapshot. Remote I/O
        uses the configured transport policy and returns only after its response
        or failure has been observed. If the function cannot pin and validate
        the DUT directory used by the terminal snapshot, its exception reaches
        the caller instead of being converted into a successful result. Cleanup
        in the ``finally`` path runs for successful, failed, and cancelled
        execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            generation: Text supplied as generation in the format accepted by
                this function.

        Raises:
            SnapshotConsistencyError: If per-DUT RunResult differs from the root
                projection; or per-DUT RunResult disagrees with status metadata.
            SnapshotArtifactFormatError: If could not parse status snapshot
                artifact: ``summary_source``.
        """
        session = self._require_open_session()
        dut_source = self.bundle_root / dut_id
        dut_descriptor = _open_child_directory(
            session.root_descriptor,
            dut_id,
            source=dut_source,
        )
        assert dut_descriptor is not None
        dut_identity = _directory_identity(dut_descriptor)
        metadata_descriptor: Optional[int] = None
        try:
            metadata_source = dut_source / ".metadata"
            metadata_descriptor = _open_child_directory(
                dut_descriptor,
                ".metadata",
                source=metadata_source,
            )
            assert metadata_descriptor is not None
            metadata_identity = _directory_identity(metadata_descriptor)

            status_source = metadata_source / "collection_status.json"
            status_data = _read_regular_leaf(
                metadata_descriptor,
                "collection_status.json",
                source=status_source,
                byte_limit=MAX_DUT_STATUS_BYTES,
            )
            assert status_data is not None
            self._record_digest(
                f"{dut_id}/.metadata/collection_status.json",
                status_data,
            )
            status_document = _decode_json_object(status_data, source=status_source)
            validate_status_document(
                status_document,
                generation,
                source=status_source,
            )

            run_result_source = metadata_source / "run_result.json"
            run_result_data = _read_regular_leaf(
                metadata_descriptor,
                "run_result.json",
                source=run_result_source,
                byte_limit=MAX_RUN_RESULT_BYTES,
            )
            assert run_result_data is not None
            if run_result_data != self._run_result_bytes:
                raise SnapshotConsistencyError(
                    "Per-DUT RunResult differs from the root projection"
                )
            self._record_digest(
                f"{dut_id}/.metadata/run_result.json",
                run_result_data,
            )
            run_result_document = _decode_json_object(
                run_result_data,
                source=run_result_source,
            )
            if status_document.get("metadata", {}).get("run_result") != (
                None
                if run_result_document.get("state") == "candidate_pending"
                else run_result_document
            ):
                raise SnapshotConsistencyError(
                    "Per-DUT RunResult disagrees with status metadata"
                )

            timing_source = metadata_source / "timing.json"
            timing_data = _read_regular_leaf(
                metadata_descriptor,
                "timing.json",
                source=timing_source,
                byte_limit=MAX_TIMING_BYTES,
            )
            assert timing_data is not None
            self._record_digest(
                f"{dut_id}/.metadata/timing.json",
                timing_data,
            )
            timing_document = _decode_json_object(timing_data, source=timing_source)
            validate_timing_document(
                timing_document,
                generation,
                source=timing_source,
            )

            summary_source = dut_source / "collection_status_summary.txt"
            summary_data = _read_regular_leaf(
                dut_descriptor,
                "collection_status_summary.txt",
                source=summary_source,
                byte_limit=MAX_SUMMARY_BYTES,
            )
            assert summary_data is not None
            self._record_digest(
                f"{dut_id}/collection_status_summary.txt",
                summary_data,
            )
            try:
                summary_content = summary_data.decode("utf-8")
            except UnicodeError as error:
                raise SnapshotArtifactFormatError(
                    f"Could not parse status snapshot artifact: {summary_source}"
                ) from error
            validate_summary_document(
                summary_content,
                generation,
                source=summary_source,
            )

            _revalidate_child_directory(
                dut_descriptor,
                ".metadata",
                metadata_identity,
                source=metadata_source,
            )
            _revalidate_child_directory(
                session.root_descriptor,
                dut_id,
                dut_identity,
                source=dut_source,
            )
        except BaseException:
            os.close(dut_descriptor)
            raise
        finally:
            if metadata_descriptor is not None:
                os.close(metadata_descriptor)
        self._dut_descriptors[dut_id] = dut_descriptor

    def close(self, *, verify: bool = True) -> None:
        """
        Close every retained descriptor, optionally rechecking the root marker.

        The implementation uses ``verify`` to close every retained descriptor,
        optionally rechecking the root marker. It updates ``_session`` on the
        instance as part of that state transition. If the function cannot close
        every retained descriptor, optionally rechecking the root marker, its
        exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Args:
            verify: Whether verify is enabled or required for this operation.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to close every retained descriptor, optionally
                rechecking the root marker.
        """

        session = self._session
        if session is None:
            return
        self._session = None
        verification_error: Optional[BaseException] = None
        if verify:
            try:
                session.finish()
            except BaseException as error:
                verification_error = error
        try:
            for descriptor in self._dut_descriptors.values():
                os.close(descriptor)
            self._dut_descriptors.clear()
        finally:
            session.close()
        if verification_error is not None:
            raise verification_error

    def __enter__(self) -> "TerminalSnapshotBinding":
        """
        Enter the TerminalSnapshotBinding context.

        Entering the scope acquires or validates its owned resources and returns
        the value used until the matching exit method completes cleanup.

        Returns:
            The validated ``self``.
        """
        return self

    def __exit__(
        self,
        exception_type: Any,
        _exception: Any,
        _traceback: Any,
    ) -> None:
        """
        Exit the TerminalSnapshotBinding context.

        Leaving the scope releases resources owned by the context while
        preserving the exception-propagation behavior declared by the
        context-manager protocol.

        Args:
            exception_type: Exception type consumed while the function attempts
                to exit the TerminalSnapshotBinding context.
            _exception: Exception consumed while the function attempts to exit
                the TerminalSnapshotBinding context.
            _traceback: Traceback consumed while the function attempts to exit
                the TerminalSnapshotBinding context.
        """
        self.close(verify=exception_type is None)


def _load_session_generation(
    session: _SnapshotSession,
    *,
    expected_generation: Optional[str],
    required: bool,
) -> Optional[str]:
    """
    Load session generation.

    The implementation uses ``session``, ``expected_generation``, and
    ``required`` to load session generation. Parsing or I/O must finish before
    the validated representation is made available to the caller. If the
    function cannot load session generation, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        session: Transport session governed by the configured authentication and
            trust policy.
        expected_generation: Text supplied as expected generation in the format
            accepted by this function.
        required: Whether required is enabled or required for this operation.

    Returns:
        The validated ``generation``, or ``None`` when no value qualifies.

    Raises:
        SnapshotConsistencyError: If root status snapshot generation changed.
    """
    generation = session.load_root(required=required or expected_generation is not None)
    if expected_generation is not None and generation != expected_generation:
        raise SnapshotConsistencyError("Root status snapshot generation changed")
    return generation


def terminal_snapshot_generation(
    bundle_root: Path,
    *,
    required: bool = False,
) -> Optional[str]:
    """
    Return the bounded root commit generation, rejecting unsafe traversal.

    The implementation uses ``bundle_root`` and ``required`` to produce the
    bounded root commit generation, rejecting unsafe traversal.

    Args:
        bundle_root: filesystem location used as the bundle root for this
            operation.
        required: Whether required is enabled or required for this operation.

    Returns:
        The validated ``generation``, or ``None`` when no value qualifies.
    """

    with _SnapshotSession(bundle_root) as session:
        generation = session.load_root(required=required)
        session.finish()
        return generation


def terminal_snapshot_roster(
    bundle_root: Path,
    expected_generation: str,
) -> Tuple[str, ...]:
    """
    Return the validated DUT roster committed by a terminal root marker.

    The implementation uses ``bundle_root`` and ``expected_generation`` to
    produce the validated DUT roster committed by a terminal root marker. If the
    function cannot produce the validated DUT roster committed by a terminal
    root marker, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        bundle_root: filesystem location used as the bundle root for this
            operation.
        expected_generation: Text supplied as expected generation in the format
            accepted by this function.

    Returns:
        The validated ``validated``.

    Raises:
        SnapshotConsistencyError: If terminal status snapshot DUT roster is
            missing; or terminal status snapshot DUT roster is invalid.
    """

    document = read_snapshot_status(
        bundle_root,
        expected_generation=expected_generation,
        required=True,
    )
    assert document is not None
    metadata = document.get("metadata")
    roster = metadata.get("dut_roster") if isinstance(metadata, dict) else None
    if not isinstance(roster, list):
        raise SnapshotConsistencyError("Terminal status snapshot DUT roster is missing")
    validated = tuple(_safe_component(dut_id, label="DUT") for dut_id in roster)
    if len(validated) > MAX_DUTS or len(validated) != len(set(validated)):
        raise SnapshotConsistencyError("Terminal status snapshot DUT roster is invalid")
    return validated


def validate_committed_terminal_snapshot(
    bundle_root: Path,
    *,
    compatibility_version: str,
) -> Optional[str]:
    """
    Validate an offline tree under the named receipt-less read contract.

    Version 1.0 accepts either a fully committed transactional generation or an
    unmarked legacy tree. A tree carrying any incomplete/mixed generation marker
    remains an error and is never downgraded to legacy input.

    Args:
        bundle_root: filesystem location used as the bundle root for this
            operation.
        compatibility_version: Text supplied as compatibility version in the
            format accepted by this function.

    Returns:
        The canonical committed terminal snapshot text, or ``None`` when the
        requested value is unavailable.

    Raises:
        SnapshotConsistencyError: If unsupported receipt-less snapshot
            compatibility version.
    """

    if compatibility_version != RECEIPTLESS_SNAPSHOT_COMPATIBILITY_VERSION:
        raise SnapshotConsistencyError(
            "Unsupported receipt-less snapshot compatibility version"
        )

    generation = terminal_snapshot_generation(bundle_root)
    if generation is None:
        return None
    roster = terminal_snapshot_roster(bundle_root, generation)
    return validate_terminal_snapshot_tree(bundle_root, roster)


def validate_status_document(
    document: Any,
    expected_generation: Optional[str],
    *,
    source: Path,
) -> None:
    """
    Validate one already-bounded global or per-DUT status document.

    The implementation uses ``document``, ``expected_generation``, and
    ``source`` to validate one already-bounded global or per-DUT status
    document. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        document: Document object whose ``get`` state is read while performing
            one already-bounded global or per-DUT status document.
        expected_generation: Text supplied as expected generation in the format
            accepted by this function.
        source: filesystem location used as the source for this operation.

    Raises:
        SnapshotConsistencyError: If status snapshot artifact is not a JSON
            object: ``source``.
    """

    if expected_generation is None:
        return
    if not isinstance(document, dict):
        raise SnapshotConsistencyError(
            f"Status snapshot artifact is not a JSON object: {source}"
        )
    _validate_marker(document.get("metadata"), expected_generation, source=source)


def validate_timing_document(
    document: Any,
    expected_generation: Optional[str],
    *,
    source: Path,
) -> None:
    """
    Validate one already-bounded per-DUT timing document.

    The implementation uses ``document``, ``expected_generation``, and
    ``source`` to validate one already-bounded per-DUT timing document. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        document: Document consumed while the function attempts to validate one
            already-bounded per-DUT timing document.
        expected_generation: Text supplied as expected generation in the format
            accepted by this function.
        source: filesystem location used as the source for this operation.
    """

    if expected_generation is None:
        return
    _validate_marker(document, expected_generation, source=source)


def validate_summary_document(
    content: str,
    expected_generation: Optional[str],
    *,
    source: Path,
) -> None:
    """
    Validate one already-bounded human-readable status summary marker.

    The implementation uses ``content``, ``expected_generation``, and ``source``
    to validate one already-bounded human-readable status summary marker. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        content: Text supplied as content in the format accepted by this
            function.
        expected_generation: Text supplied as expected generation in the format
            accepted by this function.
        source: filesystem location used as the source for this operation.

    Raises:
        SnapshotConsistencyError: If status summary generation is incomplete or
            mixed: ``source``.
    """

    if expected_generation is None:
        return
    generation_lines = [
        line.removeprefix("Snapshot Generation: ")
        for line in content.splitlines()
        if line.startswith("Snapshot Generation: ")
    ]
    terminal_lines = [
        line.removeprefix("Terminal Finalized: ")
        for line in content.splitlines()
        if line.startswith("Terminal Finalized: ")
    ]
    if generation_lines != [expected_generation] or terminal_lines != ["true"]:
        raise SnapshotConsistencyError(
            f"Status summary generation is incomplete or mixed: {source}"
        )


def read_snapshot_status(
    bundle_root: Path,
    *,
    dut_id: Optional[str] = None,
    expected_generation: Optional[str] = None,
    required: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Read one status document through a freshly pinned bundle root.

    The implementation uses ``bundle_root``, ``dut_id``,
    ``expected_generation``, and ``required`` to read one status document
    through a freshly pinned bundle root. Parsing or I/O must finish before the
    validated representation is made available to the caller.

    Args:
        bundle_root: filesystem location used as the bundle root for this
            operation.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        expected_generation: Optional expected generation; ``None`` selects the
            function's default behavior.
        required: Whether required is enabled or required for this operation.

    Returns:
        The validated ``document``, or ``None`` when no value qualifies.
    """

    with _SnapshotSession(bundle_root) as session:
        generation = _load_session_generation(
            session,
            expected_generation=expected_generation,
            required=required,
        )
        if dut_id is None:
            document = session.root_document
        else:
            document = session.read_dut_json(
                dut_id,
                "collection_status.json",
                byte_limit=MAX_DUT_STATUS_BYTES,
                required=required,
            )
        if document is not None:
            validate_status_document(
                document,
                generation,
                source=(
                    Path(bundle_root) / ".metadata" / "collection_status.json"
                    if dut_id is None
                    else Path(bundle_root)
                    / dut_id
                    / ".metadata"
                    / "collection_status.json"
                ),
            )
        session.finish()
        return document


def read_snapshot_timing(
    bundle_root: Path,
    dut_id: str,
    *,
    expected_generation: Optional[str] = None,
    required: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Read one timing document through a freshly pinned bundle root.

    The implementation uses ``bundle_root``, ``dut_id``,
    ``expected_generation``, and ``required`` to read one timing document
    through a freshly pinned bundle root. Parsing or I/O must finish before the
    validated representation is made available to the caller.

    Args:
        bundle_root: filesystem location used as the bundle root for this
            operation.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        expected_generation: Optional expected generation; ``None`` selects the
            function's default behavior.
        required: Whether required is enabled or required for this operation.

    Returns:
        The validated ``document``, or ``None`` when no value qualifies.
    """

    dut_id = _safe_component(dut_id, label="DUT")
    with _SnapshotSession(bundle_root) as session:
        generation = _load_session_generation(
            session,
            expected_generation=expected_generation,
            required=required,
        )
        document = session.read_dut_json(
            dut_id,
            "timing.json",
            byte_limit=MAX_TIMING_BYTES,
            required=required,
        )
        if document is not None:
            validate_timing_document(
                document,
                generation,
                source=Path(bundle_root) / dut_id / ".metadata" / "timing.json",
            )
        session.finish()
        return document


def read_snapshot_summary(
    bundle_root: Path,
    *,
    dut_id: Optional[str] = None,
    expected_generation: Optional[str] = None,
    required: bool = False,
) -> Optional[str]:
    """
    Read one summary document through a freshly pinned bundle root.

    The implementation uses ``bundle_root``, ``dut_id``,
    ``expected_generation``, and ``required`` to read one summary document
    through a freshly pinned bundle root. Parsing or I/O must finish before the
    validated representation is made available to the caller.

    Args:
        bundle_root: filesystem location used as the bundle root for this
            operation.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        expected_generation: Optional expected generation; ``None`` selects the
            function's default behavior.
        required: Whether required is enabled or required for this operation.

    Returns:
        The validated ``content``, or ``None`` when no value qualifies.
    """

    if dut_id is not None:
        dut_id = _safe_component(dut_id, label="DUT")
    with _SnapshotSession(bundle_root) as session:
        generation = _load_session_generation(
            session,
            expected_generation=expected_generation,
            required=required,
        )
        content = session.read_summary(
            dut_id,
            required=required,
        )
        if content is not None:
            validate_summary_document(
                content,
                generation,
                source=(
                    Path(bundle_root)
                    / (
                        f"{dut_id}/collection_status_summary.txt"
                        if dut_id is not None
                        else ".metadata/collection_status_summary.txt"
                    )
                ),
            )
        session.finish()
        return content


def validate_terminal_snapshot_tree(
    bundle_root: Path,
    dut_ids: Iterable[str],
    *,
    expected_generation: Optional[str] = None,
    expected_leaf_digests: Optional[Tuple[Tuple[str, int, str], ...]] = None,
    allow_candidate_directories: bool = False,
    allow_pending_run_result: bool = False,
) -> str:
    """
    Validate every bounded terminal leaf against one pinned root marker.

    The implementation uses ``bundle_root``, ``dut_ids``,
    ``expected_generation``, ``expected_leaf_digests``, and
    ``allow_candidate_directories`` to validate every bounded terminal leaf
    against one pinned root marker. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        bundle_root: filesystem location used as the bundle root for this
            operation.
        dut_ids: Entries supplied as ``dut_ids`` without transferring container
            ownership.
        expected_generation: Optional expected generation; ``None`` selects the
            function's default behavior.
        expected_leaf_digests: Optional expected leaf digests; ``None`` selects
            the function's default behavior.
        allow_candidate_directories: Whether allow candidate directories is
            enabled or required for this operation.
        allow_pending_run_result: Whether allow pending run result is enabled or
            required for this operation.

    Returns:
        The canonical terminal snapshot tree text.
    """

    with TerminalSnapshotBinding(
        bundle_root,
        dut_ids,
        expected_generation=expected_generation,
        expected_leaf_digests=expected_leaf_digests,
        allow_candidate_directories=allow_candidate_directories,
        allow_pending_run_result=allow_pending_run_result,
    ) as binding:
        return binding.generation
