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
Portable path helpers for distributable collection metadata.

This module owns the artifact paths boundary and exposes
``bundle_relative_artifact_path``, ``run_tree_dut_component``,
``normalize_artifact_file_list``,
``normalize_artifact_timings``, and ``normalize_timing_artifact_paths``. Keeping
those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

import os
import re
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:/")
_RUN_TREE_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9._ '\-]+")


def run_tree_path_component(value: Any, fallback: str) -> str:
    """
    Return one canonical component for the run-owned output tree.

    Separators, non-portable characters, leading or trailing dots/spaces, and
    parent-directory spellings are normalized identically for every producer
    and metadata consumer. The caller-selected fallback is used only when the
    normalized component would otherwise be empty.

    Args:
        value: Value to normalize without invoking filesystem resolution.
        fallback: Non-empty component used when ``value`` has no safe content.

    Returns:
        The canonical single run-tree path component.
    """
    text = str(value or "").strip()
    text = text.replace("/", "_").replace("\\", "_")
    text = _RUN_TREE_UNSAFE_PATH_CHARS.sub("_", text).strip(" .")
    while ".." in text:
        text = text.replace("..", "_")
    return text or fallback


def run_tree_dut_component(dut_id: Any) -> str:
    """
    Return the canonical DUT directory component used by the run tree.

    This public helper is the single owner of DUT directory spelling. Artifact
    producers, status envelopes, timing output, and path resolvers must use it
    so a configured DUT identifier cannot create competing directory trees.

    Args:
        dut_id: Stable configured DUT identifier.

    Returns:
        A non-empty, filesystem-safe DUT directory component.
    """
    return run_tree_path_component(dut_id, "dut")


class ArtifactRole(str, Enum):
    """
    Identify how one collector artifact participates in status accounting.

    Diagnostic captures and error evidence remain publishable, but neither is
    primary collected content. Keeping the role vocabulary at the portable
    artifact-path boundary prevents lifecycle, logger, and finalizer logic from
    drifting into incompatible success predicates.
    """

    PRIMARY = "primary"
    DIAGNOSTIC = "diagnostic"
    ERROR = "error"


def classify_artifact_path(
    path_value: Any,
    *,
    bundle_root: Optional[Path] = None,
) -> ArtifactRole:
    """
    Return the authoritative accounting role for an artifact path.

    The classifier accepts absolute or relative runtime path spellings and is
    intentionally lexical: callers may classify a path before or after its
    physical publication. When ``bundle_root`` is supplied, an absolute path is
    first made relative to that root so reserved directory names in an output
    root's ancestors cannot change artifact accounting. Error evidence takes
    precedence over diagnostic naming so an ``error-logs`` artifact can never
    count as primary content.

    Args:
        path_value: Path-like value supplied by an artifact producer.
        bundle_root: Optional run root used to remove unrelated absolute-path
            ancestors before applying reserved-directory rules.

    Returns:
        The canonical :class:`ArtifactRole` used by lifecycle accounting.
    """
    normalized = str(path_value or "").replace("\\", "/")
    if bundle_root is not None and normalized:
        try:
            candidate = Path(normalized).expanduser()
            root = Path(bundle_root).expanduser()
            if candidate.is_absolute():
                candidate = Path(os.path.abspath(os.fspath(candidate)))
                root = Path(os.path.abspath(os.fspath(root)))
                normalized = candidate.relative_to(root).as_posix()
        except (OSError, RuntimeError, TypeError, ValueError):
            # Preserve the existing lexical fallback for external, malformed,
            # or platform-specific path spellings.
            pass
    parts = [part.lower() for part in normalized.split("/") if part]
    if "error-logs" in parts[:-1]:
        return ArtifactRole.ERROR
    if "diagnostic" in parts[:-1]:
        return ArtifactRole.DIAGNOSTIC

    basename = parts[-1] if parts else ""
    if basename.endswith(".unvalidated"):
        return ArtifactRole.DIAGNOSTIC
    if basename.startswith("ssh_") and basename.endswith("_execution_policy.txt"):
        return ArtifactRole.DIAGNOSTIC
    if basename.startswith(
        (
            "diagnostic_request_",
            "diagnostic_requests_",
            "diagnostic_response_",
            "diagnostic_responses_",
            "diagnostic_error_",
            "diagnostic_errors_",
            "task_completions_",
            "task_status_updates_",
            "taskservice_snapshot_",
            "redfish_request_response_log",
            "host_execution_log",
            "request_validate_",
            "request_discover_",
            "request_collect_",
        )
    ):
        return ArtifactRole.DIAGNOSTIC
    return ArtifactRole.PRIMARY


def bundle_relative_artifact_path(
    bundle_root: Path,
    path_value: Any,
    *,
    dut_id: Optional[str] = None,
) -> Optional[str]:
    """
    Return a physical artifact as a bundle-root-relative POSIX path.

    Runtime producers use absolute, run-relative, DUT-relative, and (for a
    relative output directory) cwd-relative paths. This function accepts all
    four internal forms while refusing external files, escaping symlinks,
    Windows absolute paths on POSIX, and unresolved references.

    Args:
        bundle_root: filesystem location used as the bundle root for this
            operation.
        path_value: Path value consumed while the function attempts to produce a
            physical artifact as a bundle-root-relative POSIX path.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.

    Returns:
        The validated ``portable``, or ``None`` when no value qualifies.
    """
    if path_value in (None, ""):
        return None

    raw_value = str(path_value).replace("\\", "/")
    if not raw_value or "\x00" in raw_value or _WINDOWS_ABSOLUTE_PATH.match(raw_value):
        return None

    try:
        root_path = Path(bundle_root)
        resolved_root = root_path.resolve(strict=False)
        raw_path = Path(raw_value).expanduser()
    except (OSError, RuntimeError, ValueError):
        return None

    if raw_path.is_absolute():
        candidates = [raw_path]
    else:
        dut_root = root_path / dut_id if dut_id else None
        root_relative = root_path / raw_path
        cwd_relative = raw_path
        starts_with_dut = bool(
            dut_id and raw_path.parts and raw_path.parts[0] == str(dut_id)
        )
        if starts_with_dut:
            candidates = [root_relative]
            if dut_root is not None:
                candidates.append(dut_root / raw_path)
        else:
            candidates = []
            if dut_root is not None:
                candidates.append(dut_root / raw_path)
            candidates.append(root_relative)
        candidates.append(cwd_relative)

    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=False)
            relative = resolved.relative_to(resolved_root)
            if not resolved.is_file():
                continue
        except (OSError, RuntimeError, ValueError):
            continue
        portable = relative.as_posix()
        if portable and portable != ".":
            return portable
    return None


def normalize_artifact_file_list(
    values: Any,
    bundle_root: Path,
    *,
    dut_id: Optional[str] = None,
    on_discarded: Optional[Callable[[int], None]] = None,
) -> List[str]:
    """
    Normalize and de-duplicate a list of physical artifact references.

    The implementation uses ``values``, ``bundle_root``, and ``dut_id`` to
    normalize and de-duplicate a list of physical artifact references. The
    source value keeps its ownership while the normalized representation is
    returned separately.

    Args:
        values: Entries supplied as ``values`` and processed in caller-provided
            order.
        bundle_root: filesystem location used as the bundle root for this
            operation.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        on_discarded: Optional observer called once with the number of physical
            references rejected by containment or existence checks.

    Returns:
        The artifact file list returned in operation-defined order.
    """
    normalized: List[str] = []
    if not isinstance(values, (list, tuple, set)):
        return normalized
    discarded = 0
    for value in values:
        path = bundle_relative_artifact_path(
            bundle_root,
            value,
            dut_id=dut_id,
        )
        if path is None:
            discarded += 1
        elif path not in normalized:
            normalized.append(path)
    if discarded and callable(on_discarded):
        on_discarded(discarded)
    return normalized


def normalize_artifact_timings(
    artifact_timings: Any,
    bundle_root: Path,
    *,
    dut_id: Optional[str] = None,
    on_discarded: Optional[Callable[[int], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Copy timed artifact records with portable paths, omitting unsafe ones.

    The implementation uses ``artifact_timings``, ``bundle_root``, and
    ``dut_id`` to copy timed artifact records with portable paths, omitting
    unsafe ones.

    Args:
        artifact_timings: Entries supplied as ``artifact_timings`` and processed
            in caller-provided order.
        bundle_root: filesystem location used as the bundle root for this
            operation.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        on_discarded: Optional observer called with rejected artifact counts.

    Returns:
        The artifact timings returned in operation-defined order.
    """
    normalized: List[Dict[str, Any]] = []
    if not isinstance(artifact_timings, list):
        return normalized
    for item in artifact_timings:
        if not isinstance(item, dict):
            continue
        relative_path = bundle_relative_artifact_path(
            bundle_root,
            item.get("path"),
            dut_id=dut_id,
        )
        if relative_path is None:
            if callable(on_discarded):
                on_discarded(1)
            continue
        normalized_item = dict(item)
        normalized_item["path"] = relative_path
        normalized.append(normalized_item)
    return normalized


def normalize_timing_artifact_paths(
    timing: Any,
    bundle_root: Path,
    *,
    dut_id: Optional[str] = None,
    on_discarded: Optional[Callable[[int], None]] = None,
) -> Dict[str, Any]:
    """
    Copy a timing payload and normalize all of its artifact references.

    The implementation uses ``timing``, ``bundle_root``, and ``dut_id`` to copy
    a timing payload and normalize all of its artifact references.

    Args:
        timing: Timing consumed while the function attempts to copy a timing
            payload and normalize all of its artifact references.
        bundle_root: filesystem location used as the bundle root for this
            operation.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        on_discarded: Optional observer called with rejected artifact counts.

    Returns:
        A mapping containing timing artifact paths.
    """
    if not isinstance(timing, dict):
        return {}

    def normalize(value: Any, key: Optional[str] = None) -> Any:
        """
        Normalize the supplied value.

        The implementation uses ``value`` and ``key`` to normalize the supplied
        value. The source value keeps its ownership while the normalized
        representation is returned separately.

        Args:
            value: Value object whose ``items`` state is read while performing
                supplied value.
            key: Stable key used for lookup and operator-facing diagnostics.

        Returns:
            The result value selected by the operation.
        """
        if key == "artifact_timings":
            return normalize_artifact_timings(
                value,
                bundle_root,
                dut_id=dut_id,
                on_discarded=on_discarded,
            )
        if key == "artifact_paths":
            return normalize_artifact_file_list(
                value,
                bundle_root,
                dut_id=dut_id,
                on_discarded=on_discarded,
            )
        if isinstance(value, dict):
            return {
                child_key: normalize(child, str(child_key))
                for child_key, child in value.items()
            }
        if isinstance(value, list):
            return [normalize(child) for child in value]
        return value

    return normalize(timing)
