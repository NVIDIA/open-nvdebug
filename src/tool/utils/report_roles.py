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
Resolve report inputs from catalog-owned collector roles.

This module owns the report roles boundary and exposes
``ReportRoleInputLimitError``, ``_roles``, ``_collector_mapping``,
``collector_ids_for_report_role``, and ``_file_identity``. Keeping those
contracts together gives importers one source of truth for their validation,
lifecycle, and compatibility behavior.
"""

import json
import logging
import os
import re
import stat
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

MAX_REPORT_ROLE_METADATA_FILES = 512
MAX_REPORT_ROLE_JSON_FILE_BYTES = 8 * 1024 * 1024
MAX_REPORT_ROLE_JSON_TOTAL_BYTES = 64 * 1024 * 1024
MAX_REPORT_ROLE_JSON_NODES = 100_000
MAX_REPORT_ROLE_JSON_DEPTH = 64
MAX_REPORT_ROLE_PATH_NODES = 100_000
MAX_REPORT_ROLE_ARTIFACTS = 4096
MAX_REPORT_ROLE_COLLECTORS = 4096
MAX_REPORT_ROLE_CACHE_KEYS = 64


class ReportRoleSnapshotChangedError(OSError):
    """
    Report-role source metadata changed during one manifest's DUT projection.

    Cached role resolution is valid only within the source snapshot from which
    it was derived. Callers must discard a projection when this check fails.
    """


@dataclass
class _ReportRoleSnapshot:
    """
    Retain bounded role metadata and resolutions for one synchronous DUT read.

    Metadata keeps its existing aggregate byte and node limits. Resolved-path
    caching is optional and capped across all keys, so large valid inputs can
    still resolve without expanding retained memory beyond the artifact cap.

    Attributes:
        dut_dir: Exact DUT path owned by the projection scope.
        metadata: Validated metadata documents, loaded once on first use.
        catalog: Parsed root catalog, including a valid absent result.
        catalog_loaded: Whether the optional root catalog was already examined.
        identities: Validated source file and metadata-directory identities.
        paths: Immutable cached resolutions keyed by role, IDs, and suffixes.
        cached_paths: Total retained path references across all resolution keys.
    """

    dut_dir: Path
    metadata: Optional[Tuple[Any, ...]] = None
    catalog: Any = None
    catalog_loaded: bool = False
    identities: Dict[Path, Optional[Tuple[int, ...]]] = field(default_factory=dict)
    paths: Dict[tuple, Tuple[Path, ...]] = field(default_factory=dict)
    cached_paths: int = 0


_active_report_role_snapshot: ContextVar[Optional[_ReportRoleSnapshot]] = ContextVar(
    "nvdebug_report_role_snapshot", default=None
)


@contextmanager
def report_role_snapshot(dut_dir: Path) -> Iterator[None]:
    """
    Reuse role metadata within one DUT projection and verify its sources on exit.

    Every original read retains its no-follow, type, identity, and size checks.
    The scope revalidates source identities before its caller accepts the derived
    projection, and never shares cached data across DUTs, reports, or workers.

    Args:
        dut_dir: DUT directory from the report owner's selected output tree.

    Yields:
        Control while synchronous report-role lookups share a bounded snapshot.

    Raises:
        ReportRoleSnapshotChangedError: If a source changes during projection.
    """

    snapshot = _ReportRoleSnapshot(Path(dut_dir))
    token = _active_report_role_snapshot.set(snapshot)
    try:
        yield
        for path, expected in snapshot.identities.items():
            try:
                observed = _file_identity(path.lstat())
            except FileNotFoundError:
                observed = None
            if observed != expected:
                raise ReportRoleSnapshotChangedError(
                    "Report-role sources changed during DUT projection"
                )
    finally:
        _active_report_role_snapshot.reset(token)


def _snapshot_for_dut(dut_dir: Path) -> Optional[_ReportRoleSnapshot]:
    """
    Return the active cache only for its exact DUT path.

    Exact lexical matching preserves descriptor-bound namespaces and keeps an
    independent lookup from reusing another DUT's source records.

    Args:
        dut_dir: Path supplied by the current role lookup.

    Returns:
        The matching scope, or ``None`` for an independent lookup.
    """

    snapshot = _active_report_role_snapshot.get()
    return snapshot if snapshot is not None and snapshot.dut_dir == dut_dir else None


class ReportRoleInputLimitError(ValueError):
    """
    A report-role input exceeded a bounded offline parsing budget.

    Callers receive this exception when the report role input limit error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _roles(value: Any) -> List[str]:
    """
    Return the roles.

    The implementation uses ``value`` to produce the roles.

    Args:
        value: Value object whose ``strip`` state is read while performing
            roles.

    Returns:
        The roles returned in operation-defined order.
    """
    if isinstance(value, str):
        role = value.strip().lower()
        return [role] if role else []
    if isinstance(value, (list, tuple, set)):
        return [role for item in value for role in _roles(item)]
    return []


def _collector_mapping(definitions: Any) -> Dict[str, Any]:
    """
    Return the collector mapping.

    The implementation uses ``definitions`` to produce the collector mapping.

    Args:
        definitions: Definitions object whose ``get`` state is read while
            performing collector mapping.

    Returns:
        A mapping containing collector mapping.
    """
    if isinstance(definitions, dict):
        nested = definitions.get("collectors")
        return nested if isinstance(nested, dict) else definitions
    if isinstance(definitions, list):
        return {
            str(item.get("id") or item.get("collector_id")): item
            for item in definitions
            if isinstance(item, dict) and (item.get("id") or item.get("collector_id"))
        }
    return {}


def collector_ids_for_report_role(
    role: str,
    *definition_sources: Any,
) -> List[str]:
    """
    Return every collector ID assigned to ``role`` by supplied metadata.

    After applying local validation, the function forwards ``role`` and
    ``definition_sources`` to ``sorted`` and preserves its return and exception
    contract.

    Args:
        role: Text supplied as role in the format accepted by this function.
        definition_sources: Additional positional values forwarded in
            caller-provided order.

    Returns:
        The collector identifiers for report role returned in operation-defined
        order.

    Raises:
        ReportRoleInputLimitError: If report-role collector limit exceeded.
    """
    normalized_role = str(role or "").strip().lower()
    collector_ids: Set[str] = set()
    for source in definition_sources:
        for collector_id, definition in _collector_mapping(source).items():
            if not isinstance(definition, dict):
                continue
            if normalized_role in _roles(definition.get("report_role")):
                collector_ids.add(str(collector_id))
                if len(collector_ids) > MAX_REPORT_ROLE_COLLECTORS:
                    raise ReportRoleInputLimitError(
                        "report-role collector limit exceeded"
                    )
    return sorted(collector_ids, key=str.upper)


def _file_identity(metadata: os.stat_result) -> Tuple[int, ...]:
    """
    Return the file identity.

    The implementation uses ``metadata`` to produce the file identity.

    Args:
        metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing file
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


def _read_regular_file_bounded(path: Path) -> bytes:
    """
    Read regular file bounded.

    After applying local validation, the function forwards ``path`` to ``join``
    and preserves its return and exception contract. Parsing or I/O must finish
    before the validated representation is made available to the caller. Cleanup
    in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The regular file bounded bytes.

    Raises:
        OSError: If report-role input is not a regular file; report-role input
            lacks no-follow file access; report-role input changed before it was
            opened; or report-role input changed while it was read; or another
            input invariant is violated.
        ReportRoleInputLimitError: If report-role JSON file limit exceeded.
    """
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise OSError("report-role input is not a regular file")
    if before.st_size > MAX_REPORT_ROLE_JSON_FILE_BYTES:
        raise ReportRoleInputLimitError("report-role JSON file limit exceeded")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise OSError("report-role input requires no-follow file access")
    descriptor = os.open(
        path,
        os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise OSError("report-role input changed before it was opened")
        chunks: List[bytes] = []
        observed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_REPORT_ROLE_JSON_FILE_BYTES + 1 - observed),
            )
            if not chunk:
                break
            observed += len(chunk)
            if observed > MAX_REPORT_ROLE_JSON_FILE_BYTES:
                raise ReportRoleInputLimitError("report-role JSON file limit exceeded")
            chunks.append(chunk)
        if _file_identity(os.fstat(descriptor)) != _file_identity(before):
            raise OSError("report-role input changed while it was read")
        if _file_identity(path.lstat()) != _file_identity(before):
            raise OSError("report-role input path changed while it was read")
        snapshot = _active_report_role_snapshot.get()
        if snapshot is not None and (
            path == snapshot.dut_dir.parent / "collector_catalog.json"
            or (
                path.parent.parent == snapshot.dut_dir
                and path.parent.name in {".metadata", "metadata"}
            )
        ):
            snapshot.identities[path] = _file_identity(before)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_json_shape(document: Any) -> None:
    """
    Validate JSON shape.

    The implementation uses ``document`` to validate JSON shape. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        document: Document consumed while the function attempts to validate JSON
            shape.

    Raises:
        ReportRoleInputLimitError: If report-role JSON node limit exceeded; or
            report-role JSON depth limit exceeded.
    """
    stack = [(document, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_REPORT_ROLE_JSON_NODES:
            raise ReportRoleInputLimitError("report-role JSON node limit exceeded")
        if depth > MAX_REPORT_ROLE_JSON_DEPTH:
            raise ReportRoleInputLimitError("report-role JSON depth limit exceeded")
        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)


def _read_json_with_size(path: Path) -> Tuple[Any, int]:
    """
    Read JSON with size.

    The implementation uses ``path`` to read JSON with size. Parsing or I/O must
    finish before the validated representation is made available to the caller.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        A tuple containing ``returned value`` and ``integer count`` in that
        order.
    """
    try:
        raw = _read_regular_file_bounded(path)
        document = json.loads(raw.decode("utf-8"))
        _validate_json_shape(document)
        return document, len(raw)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        return None, 0


def _read_json(path: Path) -> Any:
    """
    Read JSON.

    The implementation uses ``path`` to read JSON. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The validated ``document``.
    """
    try:
        document, _ = _read_json_with_size(path)
        return document
    except ReportRoleInputLimitError:
        return None


def _metadata_sources(dut_dir: Path) -> Tuple[Any, ...]:
    """
    Read bounded collector metadata that can declare report roles.

    Scan the current and legacy metadata directories without following file
    links. The reserved ``timing.json`` belongs to the timing manager and carries
    operation traces, not report-role declarations; exclude it before parsing so
    large collections do not exhaust the role reader's JSON limits. All candidate
    role sources retain those limits and active snapshot identity checks.

    Args:
        dut_dir: DUT output directory containing current or legacy metadata.

    Returns:
        Valid collector mappings in directory and case-insensitive filename
        order, reused for the remainder of an active report projection.

    Raises:
        ReportRoleInputLimitError: If candidate metadata exceeds file count,
            individual or aggregate byte limits, or JSON shape limits.
        OSError: If a metadata directory cannot be inspected.
    """
    snapshot = _snapshot_for_dut(dut_dir)
    if snapshot is not None and snapshot.metadata is not None:
        return snapshot.metadata
    sources: List[Any] = []
    total_bytes = 0
    file_count = 0
    for metadata_name in (".metadata", "metadata"):
        metadata_dir = dut_dir / metadata_name
        try:
            directory_metadata = metadata_dir.lstat()
        except FileNotFoundError:
            if snapshot is not None:
                snapshot.identities[metadata_dir] = None
            continue
        if snapshot is not None:
            snapshot.identities[metadata_dir] = _file_identity(directory_metadata)
        if not stat.S_ISDIR(directory_metadata.st_mode):
            continue
        with os.scandir(metadata_dir) as entries:
            paths = sorted(
                (
                    Path(entry.path)
                    for entry in entries
                    if entry.name.endswith(".json")
                    and entry.name != "timing.json"
                    and entry.is_file(follow_symlinks=False)
                ),
                key=lambda path: path.name.casefold(),
            )
        for path in paths:
            file_count += 1
            if file_count > MAX_REPORT_ROLE_METADATA_FILES:
                raise ReportRoleInputLimitError(
                    "report-role metadata file limit exceeded"
                )
            payload, consumed = _read_json_with_size(path)
            total_bytes += consumed
            if total_bytes > MAX_REPORT_ROLE_JSON_TOTAL_BYTES:
                raise ReportRoleInputLimitError(
                    "report-role metadata aggregate limit exceeded"
                )
            if isinstance(payload, dict) and isinstance(
                payload.get("collectors"), dict
            ):
                sources.append(payload)
    result = tuple(sources)
    if snapshot is not None:
        snapshot.metadata = result
    return result


def _root_catalog(dut_dir: Path) -> Any:
    """
    Read the optional bounded catalog once within an active DUT projection.

    Missing catalogs remain a valid offline input. Existing regular catalogs
    retain the bounded reader's source checks; symbolic links are rejected.

    Args:
        dut_dir: DUT directory whose parent owns the optional catalog.

    Returns:
        The parsed catalog, or ``None`` when there is no regular catalog file.

    Raises:
        OSError: If the catalog is linked, unreadable, or changes during reading.
        ReportRoleInputLimitError: If catalog bytes or JSON shape exceed bounds.
    """
    snapshot = _snapshot_for_dut(dut_dir)
    if snapshot is not None and snapshot.catalog_loaded:
        return snapshot.catalog
    catalog_path = dut_dir.parent / "collector_catalog.json"
    try:
        metadata = catalog_path.lstat()
    except FileNotFoundError:
        result = None
        if snapshot is not None:
            snapshot.identities[catalog_path] = None
    else:
        if stat.S_ISLNK(metadata.st_mode):
            raise OSError("report-role catalog must not be a symbolic link")
        result = _read_json(catalog_path) if stat.S_ISREG(metadata.st_mode) else None
        if snapshot is not None and catalog_path not in snapshot.identities:
            snapshot.identities[catalog_path] = _file_identity(metadata)
    if snapshot is not None:
        snapshot.catalog = result
        snapshot.catalog_loaded = True
    return result


def _resolve_recorded_file(dut_dir: Path, value: Any) -> Optional[Path]:
    """
    Resolve recorded file.

    The implementation uses ``dut_dir`` and ``value`` to resolve recorded file.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot resolve recorded file, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        dut_dir: filesystem location used as the DUT dir for this operation.
        value: Value evaluated while performing recorded file.

    Returns:
        The validated ``normalized``, or ``None`` when no value qualifies.

    Raises:
        OSError: If recorded report artifact traverses a link; or recorded
            report artifact parent is not a directory.
    """
    if not isinstance(value, (str, Path)) or not str(value).strip():
        return None

    try:
        dut_root = dut_dir.resolve()
        bundle_root = dut_dir.parent.resolve()
    except (OSError, RuntimeError):
        return None

    path = Path(value)
    candidates = [path] if path.is_absolute() else [dut_root / path, bundle_root / path]
    for candidate in candidates:
        try:
            normalized = Path(os.path.abspath(os.fspath(candidate)))
        except (OSError, RuntimeError, ValueError):
            continue
        containing_root: Optional[Path] = None
        for root in (dut_root, bundle_root):
            if normalized.is_relative_to(root):
                containing_root = root
                break
        if containing_root is None:
            continue
        try:
            relative = normalized.relative_to(containing_root)
            cursor = containing_root
            for index, part in enumerate(relative.parts):
                cursor = cursor / part
                metadata = cursor.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    raise OSError("recorded report artifact traverses a link")
                if index < len(relative.parts) - 1 and not stat.S_ISDIR(
                    metadata.st_mode
                ):
                    raise OSError("recorded report artifact parent is not a directory")
            if relative.parts and stat.S_ISREG(cursor.lstat().st_mode):
                return normalized
        except OSError:
            continue
    return None


def _scan_role_artifacts(
    dut_dir: Path,
    id_patterns: Iterable[re.Pattern[str]],
    allowed_suffixes: Optional[Set[str]],
) -> Set[Path]:
    """
    Scan role artifacts.

    The implementation uses ``dut_dir``, ``id_patterns``, and
    ``allowed_suffixes`` to scan role artifacts. If the function cannot scan
    role artifacts, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        dut_dir: filesystem location used as the DUT dir for this operation.
        id_patterns: Entries supplied as ``id_patterns`` without transferring
            container ownership.
        allowed_suffixes: Entries supplied as ``allowed_suffixes`` without
            transferring container ownership.

    Returns:
        The validated ``paths``.

    Raises:
        ReportRoleInputLimitError: If report-role path traversal limit exceeded;
            or report-role artifact limit exceeded.
    """
    paths: Set[Path] = set()
    stack = [dut_dir]
    visited = 0
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                visited += 1
                if visited > MAX_REPORT_ROLE_PATH_NODES:
                    raise ReportRoleInputLimitError(
                        "report-role path traversal limit exceeded"
                    )
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                path = Path(entry.path)
                if (
                    allowed_suffixes is not None
                    and path.suffix.lower() not in allowed_suffixes
                ):
                    continue
                relative = path.relative_to(dut_dir).as_posix()
                if any(pattern.search(relative) for pattern in id_patterns):
                    paths.add(path)
                    if len(paths) > MAX_REPORT_ROLE_ARTIFACTS:
                        raise ReportRoleInputLimitError(
                            "report-role artifact limit exceeded"
                        )
    return paths


def report_role_artifact_paths(
    dut_dir: Path,
    role: str,
    *,
    collector_definitions: Any = None,
    suffixes: Optional[Iterable[str]] = None,
) -> List[Path]:
    """
    Return all artifacts owned by collectors assigned to a report role.

    Group metadata is self-contained for offline report generation. The root
    collector catalog and live definitions are accepted as additional sources.
    Malformed, linked, or over-budget offline inputs fail closed. Metadata and
    directory discovery may spell the same file differently; retain one path per
    physical file, preferring discovery within the caller's DUT namespace. This
    preserves descriptor-bound paths used during offline report generation.

    Args:
        dut_dir: DUT root, including relative or descriptor-bound paths.
        role: Case-insensitive report-role name assigned by collector metadata.
        collector_definitions: Additional catalog definitions, when available.
        suffixes: Case-insensitive suffix allowlist, or ``None`` for all suffixes.

    Returns:
        Unique regular-file paths in case-insensitive lexical order. Invalid or
        over-budget discovery returns an empty list and logs the rejection.
    """
    dut_dir = Path(dut_dir)
    try:
        metadata_sources = list(_metadata_sources(dut_dir))
        sources = [collector_definitions, _root_catalog(dut_dir), *metadata_sources]
        collector_ids = collector_ids_for_report_role(role, *sources)
    except (OSError, ReportRoleInputLimitError) as exc:
        logger.warning("Report-role metadata rejected: %s", exc)
        return []
    if not collector_ids:
        return []

    allowed_suffixes = (
        {str(suffix).lower() for suffix in suffixes} if suffixes is not None else None
    )
    snapshot = _snapshot_for_dut(dut_dir)
    cache_key = (
        str(role or "").strip().lower(),
        tuple(sorted(collector_ids)),
        tuple(sorted(allowed_suffixes)) if allowed_suffixes is not None else None,
    )
    if snapshot is not None and cache_key in snapshot.paths:
        # Artifact contents are read by their normal bounded consumers. Recheck
        # the entire path before returning a cached resolution so a
        # late symlink or directory substitution cannot bypass discovery rules.
        validated = []
        for path in snapshot.paths[cache_key]:
            try:
                recorded_path = path.relative_to(dut_dir)
            except ValueError:
                # Recorded artifacts may use absolute or bundle-relative paths,
                # while discovery preserves a descriptor-bound DUT namespace.
                recorded_path = path.absolute()
            if _resolve_recorded_file(dut_dir, recorded_path) is not None:
                validated.append(path)
        return validated
    paths: Set[Path] = set()

    normalized_role = str(role or "").strip().lower()
    for source in metadata_sources:
        for collector_id, definition in _collector_mapping(source).items():
            if not isinstance(definition, dict):
                continue
            if normalized_role not in _roles(definition.get("report_role")):
                continue
            recorded_files = definition.get("files", [])
            if not isinstance(recorded_files, (list, tuple)):
                continue
            for value in recorded_files:
                path = _resolve_recorded_file(dut_dir, value)
                if path is not None and (
                    allowed_suffixes is None or path.suffix.lower() in allowed_suffixes
                ):
                    paths.add(path)
                    if len(paths) > MAX_REPORT_ROLE_ARTIFACTS:
                        logger.warning("Report-role artifact limit exceeded")
                        return []

    id_patterns = [
        re.compile(
            rf"(?<![A-Za-z0-9]){re.escape(collector_id)}(?![A-Za-z0-9])",
            re.IGNORECASE,
        )
        for collector_id in collector_ids
    ]
    try:
        paths.update(_scan_role_artifacts(dut_dir, id_patterns, allowed_suffixes))
    except (OSError, ReportRoleInputLimitError) as exc:
        logger.warning("Report-role artifact discovery rejected: %s", exc)
        return []
    if len(paths) > MAX_REPORT_ROLE_ARTIFACTS:
        logger.warning("Report-role artifact limit exceeded")
        return []

    # Recorded absolute paths can alias paths discovered beneath a relative,
    # symlink-parent, or descriptor-bound DUT root. Keep the caller's namespace
    # when both refer to the same file; never merge distinct firmware sources
    # merely because their rows or contents happen to match.
    unique_paths: Dict[Tuple[int, int], Path] = {}
    try:
        for path in sorted(
            paths,
            key=lambda path: (
                not path.is_relative_to(dut_dir),
                str(path).lower(),
                str(path),
            ),
        ):
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode):
                unique_paths.setdefault((metadata.st_dev, metadata.st_ino), path)
    except OSError as exc:
        logger.warning("Report-role artifact identity rejected: %s", exc)
        return []
    result = sorted(
        unique_paths.values(), key=lambda path: (str(path).lower(), str(path))
    )
    if (
        snapshot is not None
        and len(snapshot.paths) < MAX_REPORT_ROLE_CACHE_KEYS
        and snapshot.cached_paths + len(result) <= MAX_REPORT_ROLE_ARTIFACTS
    ):
        snapshot.paths[cache_key] = tuple(result)
        snapshot.cached_paths += len(result)
    return result
