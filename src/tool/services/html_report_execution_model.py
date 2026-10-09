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
Immutable execution-summary policy for the HTML report service.

The records in this module are the internal parsing and projection boundary. The
HTML service still exposes its historical dictionary/list facade through the
explicit adapters below so existing renderers and callers retain their exact
data shape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence

from ..core.collector_outcome import normalize_collector_failure_category

__all__ = [
    "ExecutionSummaryEntryRecord",
    "ExecutionSummaryRecord",
    "MetadataExecutionSummaryEntryRecord",
    "SummaryDiagnosticRecord",
    "combine_execution_statuses",
    "create_execution_summary_from_metadata",
    "execution_summary_to_legacy_dict",
    "metadata_execution_summary_to_legacy_list",
    "parse_execution_summary_lines",
    "summary_diagnostics_to_legacy_list",
]


@dataclass(frozen=True, slots=True)
class ExecutionSummaryEntryRecord:
    """
    One parsed execution-summary row with immutable path collections.

    The immutable record keeps ``collection_name``, ``execution_status``,
    ``log_paths``, ``collector_id``, and ``duration_seconds`` together so
    consumers observe one execution summary entry state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        collection_name: Canonical text used as collection name.
        execution_status: Canonical text used as execution status.
        log_paths: Collection of log paths entries retained by this record.
        collector_id: Canonical text used as collector identifier.
        duration_seconds: Number of duration seconds represented by this record.
        reason: Canonical reason exposed to downstream status consumers.
        artifact_paths: Collection of artifact paths entries retained by this
            record.
        diagnostic_paths: Collection of diagnostic paths entries retained by
            this record.
        failure_category: Canonical text used as failure category.
    """

    collection_name: str
    execution_status: str
    log_paths: tuple[str, ...]
    collector_id: str | None
    duration_seconds: float | None
    reason: str
    artifact_paths: tuple[str, ...]
    diagnostic_paths: tuple[str, ...]
    failure_category: str | None = None


@dataclass(frozen=True, slots=True)
class ExecutionSummaryRecord:
    """
    Parsed execution-summary data independent of file I/O and rendering.

    The immutable record keeps ``entries`` and ``log_collection_time`` together
    so consumers observe one execution summary state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        entries: Collection of entries retained by this record.
        log_collection_time: Canonical text used as log collection time.
    """

    entries: tuple[ExecutionSummaryEntryRecord, ...] = ()
    log_collection_time: str = ""


MetadataScalar = str | int | float | bool | None


@dataclass(frozen=True, slots=True)
class _FrozenMetadataSequence:
    """
    Immutable snapshot of a legacy list or tuple value.

    The immutable record keeps ``kind`` and ``values`` together so consumers
    observe one frozen metadata sequence state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        kind: Container-kind discriminator; accepted values are ``'list',
            'tuple'``.
        values: Values retained by the snapshot in the source sequence's order.
    """

    kind: Literal["list", "tuple"]
    values: tuple["FrozenMetadataValue", ...]


@dataclass(frozen=True, slots=True)
class _FrozenMetadataMapping:
    """
    Immutable, insertion-ordered snapshot of a legacy mapping value.

    The immutable record keeps ``items`` together so consumers observe one
    frozen metadata mapping state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        items: Key/value pairs retained by the snapshot in insertion order.
    """

    items: tuple[tuple["FrozenMetadataValue", "FrozenMetadataValue"], ...]


@dataclass(frozen=True, slots=True)
class _FrozenMetadataSet:
    """
    Immutable snapshot of a legacy set or frozenset value.

    The immutable record keeps ``kind`` and ``values`` together so consumers
    observe one frozen metadata set state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        kind: Container-kind discriminator; accepted values are ``'set',
            'frozenset'``.
        values: Values retained by the snapshot in the source sequence's order.
    """

    kind: Literal["set", "frozenset"]
    values: frozenset["FrozenMetadataValue"]


FrozenMetadataValue = (
    MetadataScalar
    | _FrozenMetadataSequence
    | _FrozenMetadataMapping
    | _FrozenMetadataSet
)
_MAX_FROZEN_METADATA_DEPTH = 64
_METADATA_DEPTH_MARKER = "[metadata nesting depth exceeded]"


@dataclass(frozen=True, slots=True)
class MetadataExecutionSummaryEntryRecord:
    """
    One immutable projection of collector metadata for summary rendering.

    The immutable record keeps ``collection_name``, ``execution_status``,
    ``log_paths``, ``collector_id``, and ``name`` together so consumers observe
    one metadata execution summary entry state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        collection_name: Canonical text used as collection name.
        execution_status: Execution status retained as part of the record's
            public state.
        log_paths: Collection of log paths entries retained by this record.
        collector_id: Canonical text used as collector identifier.
        name: Name retained as part of the record's public state.
        group_name: Canonical text used as group name.
        duration_seconds: Duration seconds retained as part of the record's
            public state.
        reason: Canonical reason exposed to downstream status consumers.
        artifact_paths: Collection of artifact paths entries retained by this
            record.
        diagnostic_paths: Collection of diagnostic paths entries retained by
            this record.
        failure_category: Canonical text used as failure category.
    """

    collection_name: str
    execution_status: FrozenMetadataValue
    log_paths: tuple[str, ...]
    collector_id: str
    name: FrozenMetadataValue
    group_name: str
    duration_seconds: FrozenMetadataValue
    reason: FrozenMetadataValue
    artifact_paths: tuple[str, ...]
    diagnostic_paths: tuple[str, ...]
    failure_category: str | None = None


SummaryDiagnosticCode = Literal[
    "empty",
    "missing_path_columns",
    "missing_required_columns",
    "missing_columns",
]


@dataclass(frozen=True, slots=True)
class SummaryDiagnosticRecord:
    """
    Value-free parser diagnostic rendered by the service logging facade.

    The immutable record keeps ``code``, ``line_number``, and ``headers``
    together so consumers observe one summary diagnostic state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        code: Code retained as part of the record's public state.
        line_number: Numeric line number retained by this record.
        headers: Collection of headers entries retained by this record.
    """

    code: SummaryDiagnosticCode
    line_number: int | None = None
    headers: tuple[str, ...] = ()


_LOG_PATH_HEADERS = frozenset(
    {
        "log path",
        "log_paths",
        "log_path",
        "log paths",
    }
)
_ARTIFACT_PATH_HEADERS = frozenset({"artifact paths", "artifact path"})
_DIAGNOSTIC_PATH_HEADERS = frozenset({"diagnostic paths", "diagnostic path"})
_DURATION_HEADERS = frozenset({"duration", "duration (s)", "duration_seconds"})
_FAILURE_CATEGORY_HEADERS = frozenset({"failure category", "failure_category"})


def _normalize_failure_category(status: Any, value: Any) -> str | None:
    """
    Contain legacy report aliases before applying canonical outcome policy.

    After applying local validation, the function forwards ``status`` and
    ``value`` to ``normalize_collector_failure_category`` and preserves its
    return and exception contract.

    Args:
        status: Status consumed while the function attempts to contain legacy
            report aliases before applying canonical outcome policy.
        value: Value evaluated while performing contain legacy report aliases
            before applying canonical outcome policy.

    Returns:
        The canonical failure category text, or ``None`` when the requested
        value is unavailable.
    """

    status_value = str(getattr(status, "value", status) or "").strip().casefold()
    status_value = status_value.split()[0] if status_value else ""
    canonical_status = {
        "degraded": "degraded",
        "error": "error",
        "fail": "error",
        "failed": "error",
        "partial": "partial",
    }.get(status_value)
    if canonical_status is None:
        return None
    return normalize_collector_failure_category(canonical_status, value)


def _header_index(headers: Sequence[str], candidates: frozenset[str]) -> int | None:
    """
    Return the leftmost matching source column.

    Header position is the deterministic tie-breaker when malformed input
    contains more than one accepted alias.

    Args:
        headers: Entries supplied as ``headers`` without transferring container
            ownership.
        candidates: Entries supplied as ``candidates`` without transferring
            container ownership.

    Returns:
        The numeric header index, or ``None`` when the requested value is
        unavailable.
    """

    return next(
        (index for index, header in enumerate(headers) if header in candidates),
        None,
    )


def _parse_paths(parts: Sequence[str], index: int | None) -> tuple[str, ...]:
    """
    Parse paths.

    The implementation uses ``parts`` and ``index`` to parse paths. Parsing or
    I/O must finish before the validated representation is made available to the
    caller.

    Args:
        parts: Entries supplied as ``parts`` without transferring container
            ownership.
        index: Zero-based position within the containing sequence.

    Returns:
        The paths returned in operation-defined order.
    """
    if index is None or index >= len(parts):
        return ()
    return tuple(path.strip() for path in parts[index].split(",") if path.strip())


def parse_execution_summary_lines(
    lines: Sequence[str],
) -> tuple[ExecutionSummaryRecord, tuple[SummaryDiagnosticRecord, ...]]:
    """
    Parse legacy or tabular execution-summary text without I/O or logging.

    The implementation uses ``lines`` to parse legacy or tabular
    execution-summary text without I/O or logging. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        lines: Entries supplied as ``lines`` without transferring container
            ownership.

    Returns:
        A tuple containing ``execution summary record`` and ``tuple[summary
        diagnostic record,...]`` in that order.
    """

    if not lines:
        return ExecutionSummaryRecord(), (SummaryDiagnosticRecord(code="empty"),)

    header_line = lines[0].strip()
    if "\t" in header_line:
        headers = tuple(header.strip().lower() for header in header_line.split("\t"))
    else:
        headers = tuple(re.split(r"\s{2,}", header_line.lower()))

    log_path_idx = _header_index(headers, _LOG_PATH_HEADERS)
    artifact_path_idx = _header_index(headers, _ARTIFACT_PATH_HEADERS)
    diagnostic_path_idx = _header_index(headers, _DIAGNOSTIC_PATH_HEADERS)
    if (
        log_path_idx is None
        and artifact_path_idx is None
        and diagnostic_path_idx is None
    ):
        return ExecutionSummaryRecord(), (
            SummaryDiagnosticRecord(
                code="missing_path_columns",
                headers=headers,
            ),
        )

    collection_name_idx: int | None = None
    collector_id_idx: int | None = None
    execution_status_idx: int | None = None
    for index, header in enumerate(headers):
        if "collection name" in header:
            collection_name_idx = index
        elif header in {"id", "collector id"}:
            collector_id_idx = index
        elif "execution status" in header:
            execution_status_idx = index

    if collection_name_idx is None or execution_status_idx is None:
        return ExecutionSummaryRecord(), (
            SummaryDiagnosticRecord(
                code="missing_required_columns",
                headers=headers,
            ),
        )

    duration_idx = _header_index(headers, _DURATION_HEADERS)
    failure_category_idx = _header_index(headers, _FAILURE_CATEGORY_HEADERS)
    reason_idx = next(
        (index for index, header in enumerate(headers) if header == "reason"),
        None,
    )
    entries: list[ExecutionSummaryEntryRecord] = []
    diagnostics: list[SummaryDiagnosticRecord] = []
    seen_entries: set[ExecutionSummaryEntryRecord] = set()
    log_collection_time = ""

    for line_number, raw_line in enumerate(lines[1:], start=2):
        line = raw_line.strip()
        if not line:
            continue
        if "\t" not in line and (
            line.lower().startswith("log collection took")
            or line.lower().startswith("total execution time:")
        ):
            log_collection_time = line
            continue

        if "\t" in line:
            parts = [part.strip() for part in line.split("\t")]
        else:
            parts = re.split(r"\s{2,}", line)
        if len(parts) < len(headers):
            diagnostics.append(
                SummaryDiagnosticRecord(
                    code="missing_columns",
                    line_number=line_number,
                )
            )
            parts += [""] * (len(headers) - len(parts))

        artifact_paths = _parse_paths(parts, artifact_path_idx)
        diagnostic_paths = _parse_paths(parts, diagnostic_path_idx)
        log_paths = _parse_paths(parts, log_path_idx)
        if not log_paths:
            log_paths = tuple(dict.fromkeys((*artifact_paths, *diagnostic_paths)))

        duration_seconds: float | None = None
        if duration_idx is not None and duration_idx < len(parts):
            try:
                duration_seconds = max(
                    0.0,
                    float(parts[duration_idx].removesuffix("s")),
                )
            except (TypeError, ValueError, OverflowError):
                duration_seconds = None
        reason = (
            parts[reason_idx]
            if reason_idx is not None and reason_idx < len(parts)
            else ""
        )

        collector_id: str | None = None
        if collector_id_idx is not None and collector_id_idx < len(parts):
            collector_id = parts[collector_id_idx].strip()
            if collector_id == "N/A":
                collector_id = None

        entry = ExecutionSummaryEntryRecord(
            collection_name=parts[collection_name_idx],
            execution_status=parts[execution_status_idx],
            log_paths=log_paths,
            collector_id=collector_id,
            duration_seconds=duration_seconds,
            reason=reason,
            artifact_paths=artifact_paths,
            diagnostic_paths=diagnostic_paths,
            failure_category=_normalize_failure_category(
                parts[execution_status_idx],
                (
                    parts[failure_category_idx]
                    if failure_category_idx is not None
                    and failure_category_idx < len(parts)
                    else None
                ),
            ),
        )
        if entry not in seen_entries:
            entries.append(entry)
            seen_entries.add(entry)

    return (
        ExecutionSummaryRecord(
            entries=tuple(entries),
            log_collection_time=log_collection_time,
        ),
        tuple(diagnostics),
    )


def execution_summary_to_legacy_dict(summary: ExecutionSummaryRecord) -> dict[str, Any]:
    """
    Adapt immutable parsed data to the historical service dictionary shape.

    The implementation uses ``summary`` to adapt immutable parsed data to the
    historical service dictionary shape.

    Args:
        summary: Summary object whose ``entries`` and ``log_collection_time``
            state is read while performing adapt immutable parsed data to the
            historical service dictionary shape.

    Returns:
        A mapping containing the ``entries`` and ``log_collection_time`` fields.
    """

    return {
        "entries": [
            {
                "collection name": entry.collection_name,
                "execution status": entry.execution_status,
                "log path": list(entry.log_paths),
                "collector_id": entry.collector_id,
                "duration_seconds": entry.duration_seconds,
                "reason": entry.reason,
                "artifact paths": list(entry.artifact_paths),
                "diagnostic paths": list(entry.diagnostic_paths),
                **(
                    {"failure_category": entry.failure_category}
                    if entry.failure_category is not None
                    else {}
                ),
            }
            for entry in summary.entries
        ],
        "log_collection_time": summary.log_collection_time,
    }


def summary_diagnostics_to_legacy_list(
    diagnostics: Sequence[SummaryDiagnosticRecord],
) -> list[dict[str, Any]]:
    """
    Adapt immutable diagnostics to the historical logging facade shape.

    The implementation uses ``diagnostics`` to adapt immutable diagnostics to
    the historical logging facade shape.

    Args:
        diagnostics: Entries supplied as ``diagnostics`` without transferring
            container ownership.

    Returns:
        The summary diagnostics to legacy list returned in operation-defined
        order.
    """

    return [
        {
            "code": diagnostic.code,
            "line_number": diagnostic.line_number,
            "headers": list(diagnostic.headers),
        }
        for diagnostic in diagnostics
    ]


def combine_execution_statuses(summary_status: str, metadata_status: str) -> str:
    """
    Combine summary and metadata status using the legacy report policy.

    The implementation uses ``summary_status`` and ``metadata_status`` to
    combine summary and metadata status using the legacy report policy.

    Args:
        summary_status: Text supplied as summary status in the format accepted
            by this function.
        metadata_status: Text supplied as metadata status in the format accepted
            by this function.

    Returns:
        The canonical combine execution statuses text.
    """

    priority = [
        "Error",
        "Partial",
        "Degraded",
        "Complete",
        "Skipped",
        "NotRan",
        "Unknown",
    ]
    summary_token = (summary_status or "Unknown").split()[0]
    metadata_token = (metadata_status or "Unknown").split()[0]

    metadata_token = {
        "passed": "Complete",
        "failed": "Error",
        "partial": "Partial",
        "degraded": "Degraded",
        "skipped": "Skipped",
        "notran": "NotRan",
    }.get(metadata_token.lower(), metadata_token)

    if summary_token not in priority:
        summary_token = "Unknown"
    if metadata_token not in priority:
        metadata_token = "Unknown"
    final_status = priority[
        min(priority.index(summary_token), priority.index(metadata_token))
    ]
    return "N/A" if final_status == "NotRan" else final_status


def _freeze_metadata_value(
    value: Any,
    active_containers: set[int] | None = None,
    depth: int = 0,
    max_depth: int = _MAX_FROZEN_METADATA_DEPTH,
) -> FrozenMetadataValue:
    """
    Detach and recursively freeze one legacy metadata value.

    The implementation uses ``value`` and ``active_containers`` to detach and
    recursively freeze one legacy metadata value. The operation mutates
    ``active_containers`` in place; ownership of those objects remains with the
    caller. If the function cannot detach and recursively freeze one legacy
    metadata value, its exception reaches the caller instead of being converted
    into a successful result. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        value: Value object whose ``items`` state is read while performing
            detach and recursively freeze one legacy metadata value.
        active_containers: Object identities on the current recursion stack;
            ``None`` starts a new cycle check.
        depth: Current nested container depth.
        max_depth: Maximum nested container depth retained in the snapshot.

    Returns:
        A ``FrozenMetadataValue`` representing freeze metadata value.

    Raises:
        ValueError: If collector metadata values must not contain cycles.
    """

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if depth > max_depth:
        return _METADATA_DEPTH_MARKER

    if active_containers is None:
        active_containers = set()
    marker = id(value)
    if marker in active_containers:
        raise ValueError("Collector metadata values must not contain cycles")

    active_containers.add(marker)
    try:
        if isinstance(value, Mapping):
            return _FrozenMetadataMapping(
                items=tuple(
                    (
                        _freeze_metadata_value(
                            key, active_containers, depth + 1, max_depth
                        ),
                        _freeze_metadata_value(
                            item, active_containers, depth + 1, max_depth
                        ),
                    )
                    for key, item in value.items()
                )
            )
        if isinstance(value, (list, tuple)):
            return _FrozenMetadataSequence(
                kind="list" if isinstance(value, list) else "tuple",
                values=tuple(
                    _freeze_metadata_value(
                        item, active_containers, depth + 1, max_depth
                    )
                    for item in value
                ),
            )
        if isinstance(value, (set, frozenset)):
            return _FrozenMetadataSet(
                kind="set" if isinstance(value, set) else "frozenset",
                values=frozenset(
                    _freeze_metadata_value(
                        item, active_containers, depth + 1, max_depth
                    )
                    for item in value
                ),
            )
    finally:
        active_containers.remove(marker)

    # Collector metadata is JSON-derived in production. Contain unexpected
    # programmatic values at this boundary rather than retaining an alias to a
    # potentially mutable object.
    return str(value)


def _thaw_metadata_value(
    value: FrozenMetadataValue,
    depth: int = 0,
    max_depth: int = _MAX_FROZEN_METADATA_DEPTH,
) -> Any:
    """
    Return a detached value in the historical mutable facade shape.

    The implementation uses ``value`` to produce a detached value in the
    historical mutable facade shape.

    Args:
        value: Value object whose ``items``, ``kind``, and ``values`` state is
            read while performing detached value in the historical mutable
            facade shape.
        depth: Current nested container depth.
        max_depth: Maximum nested container depth materialized in the facade.

    Returns:
        A detached value in the historical mutable facade shape.
    """

    if depth > max_depth:
        return _METADATA_DEPTH_MARKER
    if isinstance(value, _FrozenMetadataMapping):
        return {
            _thaw_metadata_value(key, depth + 1, max_depth): _thaw_metadata_value(
                item, depth + 1, max_depth
            )
            for key, item in value.items
        }
    if isinstance(value, _FrozenMetadataSequence):
        sequence_items = tuple(
            _thaw_metadata_value(item, depth + 1, max_depth) for item in value.values
        )
        return list(sequence_items) if value.kind == "list" else sequence_items
    if isinstance(value, _FrozenMetadataSet):
        set_items = frozenset(
            _thaw_metadata_value(item, depth + 1, max_depth) for item in value.values
        )
        return set(set_items) if value.kind == "set" else set_items
    return value


def create_execution_summary_from_metadata(
    node_data: Mapping[str, Mapping[str, Mapping[str, Any]]],
    requested_collector_ids: Sequence[str] | None,
) -> tuple[MetadataExecutionSummaryEntryRecord, ...]:
    """
    Project collector metadata into immutable execution-summary records.

    After applying local validation, the function forwards ``node_data`` and
    ``requested_collector_ids`` to ``tuple`` and preserves its return and
    exception contract.

    Args:
        node_data: Mapping supplying fields for project collector metadata into
            immutable execution-summary records.
        requested_collector_ids: Optional requested collector identifiers;
            ``None`` selects the function's default behavior.

    Returns:
        The execution summary from metadata returned in operation-defined order.
    """

    entries: list[MetadataExecutionSummaryEntryRecord] = []
    for group_name, collectors in node_data.items():
        for collector_id, collector_info in collectors.items():
            if requested_collector_ids and collector_id.upper() not in [
                requested_id.upper() for requested_id in requested_collector_ids
            ]:
                continue
            collector_name = collector_info.get("name", "N/A")
            entries.append(
                MetadataExecutionSummaryEntryRecord(
                    collection_name=f"{group_name}_{collector_id}_{collector_name}",
                    execution_status=_freeze_metadata_value(
                        collector_info.get("status", "NotRan")
                    ),
                    log_paths=(
                        f"{group_name.lower()}/{collector_id}_{collector_name}",
                    ),
                    collector_id=collector_id,
                    name=_freeze_metadata_value(collector_name),
                    group_name=group_name,
                    duration_seconds=_freeze_metadata_value(
                        collector_info.get("execution_time_seconds", 0.0)
                    ),
                    reason=_freeze_metadata_value(collector_info.get("reason", "")),
                    artifact_paths=(),
                    diagnostic_paths=(),
                    failure_category=_normalize_failure_category(
                        collector_info.get("status", "NotRan"),
                        collector_info.get("failure_category"),
                    ),
                )
            )
    return tuple(entries)


def metadata_execution_summary_to_legacy_list(
    entries: Sequence[MetadataExecutionSummaryEntryRecord],
) -> list[dict[str, Any]]:
    """
    Adapt immutable metadata projections to the historical list facade.

    The implementation uses ``entries`` to adapt immutable metadata projections
    to the historical list facade.

    Args:
        entries: Entries supplied as ``entries`` without transferring container
            ownership.

    Returns:
        The metadata execution summary to legacy list returned in
        operation-defined order.
    """

    return [
        {
            "collection name": entry.collection_name,
            "execution status": _thaw_metadata_value(entry.execution_status),
            "log path": list(entry.log_paths),
            "collector_id": entry.collector_id,
            "name": _thaw_metadata_value(entry.name),
            "group_name": entry.group_name,
            "duration_seconds": _thaw_metadata_value(entry.duration_seconds),
            "reason": _thaw_metadata_value(entry.reason),
            "artifact paths": list(entry.artifact_paths),
            "diagnostic paths": list(entry.diagnostic_paths),
            **(
                {"failure_category": entry.failure_category}
                if entry.failure_category is not None
                else {}
            ),
        }
        for entry in entries
    ]
