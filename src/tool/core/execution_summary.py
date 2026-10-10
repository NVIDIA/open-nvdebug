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
Execution Summary Management.

This module handles the generation of execution summary files in the legacy
nvdebug format with per-DUT summary tracking and status reporting.
"""

import asyncio
import fcntl
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO

from ..utils.atomic_publication import atomic_publish_locked_bytes
from ..utils.managed_filesystem import run_managed_filesystem_operation
from ..utils.report_publication_lock import (
    PinnedDirectoryLock,
    async_report_publication_lock,
    report_publication_lock,
)
from ..utils.status_snapshot import (
    SnapshotArtifactFormatError,
    SnapshotConsistencyError,
    read_snapshot_status,
    read_snapshot_timing,
    terminal_snapshot_generation,
    validate_terminal_snapshot_tree,
)
from .collector_outcome import (
    normalize_collector_failure_category,
    sanitize_terminal_collector_reason,
)
from .finalization_receipt import (
    FinalizationReceipt,
    validate_consumable_finalization_receipt,
)


class ExecutionSummaryManager:
    """
    Manages execution summary file generation in legacy nvdebug format.

    Handles per-DUT execution summary tracking with collector status, timing
    information, and file paths.
    """

    def __init__(self, log_dir: Path):
        """
        Initialize execution summary manager.

        The initializer records ``_finalization_receipt``,
        ``_terminal_dut_roster``, ``_terminal_snapshot_generation``,
        ``dut_start_times``, and ``entries`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
        """
        self.log_dir = log_dir
        self.summary_file = "Execution_Summary_Report.txt"
        self.summary_files: Dict[str, Path] = {}  # DUT-specific summary files
        self.entries: Dict[str, List[Dict[str, Any]]] = {}  # DUT-specific entries
        self._publication_locks: Dict[str, asyncio.Lock] = {}
        self.start_time = (
            datetime.now()
        )  # Keep global start time for backward compatibility
        self.dut_start_times: Dict[str, datetime] = {}  # DUT-specific start times
        self._finalization_receipt: Optional[FinalizationReceipt] = None
        self._terminal_snapshot_generation: Optional[str] = None
        self._terminal_dut_roster: Optional[tuple[str, ...]] = None

    def _sanitize_terminal_reason(self, status: Any, reason: Any) -> str:
        """
        Project a terminal reason through the active run sanitizer.

        Execution summaries are distributable tool-authored text. Applying the
        logger's configured sanitizer here keeps that write boundary safe even
        when the optional completed-bundle scan is disabled.

        Args:
            status: Terminal collector status associated with the reason.
            reason: Free-form terminal diagnostic supplied by the caller.

        Returns:
            The bounded canonical reason with configured sensitive values
            removed.
        """
        sanitizer = getattr(
            getattr(getattr(self, "logger", None), "sanitizer", None),
            "sanitize",
            None,
        )
        return sanitize_terminal_collector_reason(
            status,
            reason,
            sanitizer=sanitizer if callable(sanitizer) else None,
        )

    def bind_finalization_receipt(
        self,
        receipt: FinalizationReceipt,
        *,
        _allow_pending_run_result: bool = False,
    ) -> None:
        """
        Authorize current-run reads from one exact committed generation.

        The private pending allowance is reserved for the orchestrator's bounded
        pre-projection window. Public consumers require the committed RunResult
        leaf.

        Args:
            receipt: Receipt object whose ``snapshot_leaf_digests`` state is
                read while performing authorize current-run reads from one exact
                committed generation.
            _allow_pending_run_result: Whether allow pending run result is
                enabled or required for this operation.

        Raises:
            RuntimeError: If execution summaries differ from the receipt roster.
        """

        generation, roster = validate_consumable_finalization_receipt(receipt)
        known_duts = set(self.entries) | set(self.summary_files)
        if not known_duts.issubset(roster):
            raise RuntimeError("Execution summaries differ from the receipt roster")
        validate_terminal_snapshot_tree(
            self.log_dir,
            roster,
            expected_generation=generation,
            expected_leaf_digests=receipt.snapshot_leaf_digests,
            allow_pending_run_result=_allow_pending_run_result,
        )
        self._finalization_receipt = receipt
        self._terminal_snapshot_generation = generation
        self._terminal_dut_roster = roster

    def _status_snapshot_generation(self) -> Optional[str]:
        """
        Use receipt evidence for current runs; discover only offline bundles.

        The implementation uses current instance state to use receipt evidence
        for current runs; discover only offline bundles.

        Returns:
            The canonical status snapshot generation text, or ``None`` when the
            requested value is unavailable.
        """

        if self._finalization_receipt is not None:
            return self._terminal_snapshot_generation
        return terminal_snapshot_generation(self.log_dir)

    _SUMMARY_HEADERS = (
        "Collection Name",
        "ID",
        "Execution Status",
        "Log Path",
        "Duration (s)",
        "Reason",
        "Artifact Paths",
        "Diagnostic Paths",
        "Failure Category",
    )
    _EXECUTION_TIME_LINE_RE = re.compile(
        r"^(?:Log collection took\b|Total execution time:)",
        re.IGNORECASE,
    )

    def set_dut_start_time(self, dut_id: str, start_time: datetime) -> None:
        """
        Set the start time for a specific DUT.

        This should be called when the collection actually starts for the DUT.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            start_time: Start time consumed while the function attempts to set
                the start time for a specific DUT.
        """
        self.dut_start_times[dut_id] = start_time

    async def add_entry(
        self,
        dut_id: str,
        collection_name: str,
        status: str,
        log_paths: List[str],
        custom_reason: Optional[str] = None,
        collector_id: Optional[str] = None,
        failure_category: Optional[str] = None,
    ) -> None:
        """
        Add an entry to the execution summary for a specific DUT.

        Preserve per-DUT ordering through owned inventory discovery and summary
        publication. Filesystem-dependent path normalization and traversal run
        off the event loop, and cancellation joins admitted work before releasing
        the DUT's ownership. Only set start time if not already set explicitly.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collection_name: Stable collection name used for lookup and
                operator-facing diagnostics.
            status: Text supplied as status in the format accepted by this
                function.
            log_paths: Filesystem locations processed in caller-provided order.
            custom_reason: Optional custom reason; ``None`` selects the
                function's default behavior.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            failure_category: Optional failure category; ``None`` selects the
                function's default behavior.
        """
        async with self._publication_locks.setdefault(dut_id, asyncio.Lock()):
            # Initialize DUT-specific data structures
            if dut_id not in self.entries:
                self.entries[dut_id] = []
                # Only set start time if not already set via set_dut_start_time
                if dut_id not in self.dut_start_times:
                    self.dut_start_times[dut_id] = datetime.now()
            if dut_id not in self.summary_files:
                dut_log_dir = self.log_dir / dut_id
                self.summary_files[dut_id] = dut_log_dir / self.summary_file

            # Normalize status text
            status_text = self._normalize_status(status)
            custom_reason = self._sanitize_terminal_reason(status, custom_reason)
            failure_category = normalize_collector_failure_category(
                status,
                failure_category,
            )

            cleaned_paths, discovered_files = await run_managed_filesystem_operation(
                self._prepare_entry_inventory, log_paths, dut_id
            )

            # Create entry
            entry = {
                "collection_name": collection_name,
                "status": status_text,
                "log_paths": cleaned_paths,
                "discovered_files": discovered_files,
                "reason": custom_reason,
                "collector_id": collector_id,
            }
            if failure_category is not None:
                entry["failure_category"] = failure_category

            self.entries[dut_id].append(entry)

            # Required summary publication must fail closed.
            await self._publish_summary(dut_id, self._write_entry_to_file, entry)
            # Update collector status in metadata with discovered files
            self._update_collector_metadata_with_files(dut_id, entry)

    async def correct_collector_entry(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        log_paths: List[str],
        custom_reason: Optional[str] = None,
        failure_category: Optional[str] = None,
    ) -> None:
        """
        Replace one collector's provisional summary with a correction.

        This boundary is reserved for a terminal lifecycle correction after a
        previously published result becomes non-durable. Unlike ``add_entry``,
        it removes earlier rows for the exact DUT/collector before rewriting
        the summary, so stale artifact paths cannot survive duplicate-row
        merging during finalization. Per-DUT serialization stays held until the
        owned filesystem worker finishes, including inventory discovery and
        cancellation. A cancelled discovery cannot replace the earlier row.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration,
                logs, and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            status: Corrected terminal collector status.
            log_paths: Authoritative paths retained by the correction.
            custom_reason: Optional corrected terminal reason.
            failure_category: Optional corrected failure category.

        Side Effects:
            Replaces the collector's in-memory entry, rewrites its DUT summary
            under the existing file lock, and refreshes pending file metadata.
        """
        async with self._publication_locks.setdefault(dut_id, asyncio.Lock()):

            existing_entries = self.entries.setdefault(dut_id, [])
            matching_entries = [
                entry
                for entry in existing_entries
                if str(entry.get("collector_id", "")).casefold()
                == str(collector_id).casefold()
            ]
            collection_name = (
                matching_entries[-1].get("collection_name")
                if matching_entries
                else collector_id
            )
            if dut_id not in self.dut_start_times:
                self.dut_start_times[dut_id] = datetime.now()
            if dut_id not in self.summary_files:
                self.summary_files[dut_id] = self.log_dir / dut_id / self.summary_file

            status_text = self._normalize_status(status)
            custom_reason = self._sanitize_terminal_reason(status, custom_reason)
            failure_category = normalize_collector_failure_category(
                status,
                failure_category,
            )
            if log_paths:
                cleaned_paths, discovered_files = (
                    await run_managed_filesystem_operation(
                        self._prepare_entry_inventory, log_paths, dut_id
                    )
                )
            else:
                cleaned_paths, discovered_files = [], {}
            corrected_entry = {
                "collection_name": collection_name,
                "status": status_text,
                "log_paths": cleaned_paths,
                "discovered_files": discovered_files,
                "reason": custom_reason,
                "collector_id": collector_id,
            }
            if failure_category is not None:
                corrected_entry["failure_category"] = failure_category

            retained_entries = [
                entry
                for entry in existing_entries
                if str(entry.get("collector_id", "")).casefold()
                != str(collector_id).casefold()
            ]
            retained_entries.append(corrected_entry)
            self.entries[dut_id] = retained_entries
            pending_updates = getattr(self, "_pending_file_updates", None)
            if isinstance(pending_updates, dict):
                pending_updates.pop(f"{dut_id}:{collector_id}", None)
            await self._publish_summary(
                dut_id, self._rewrite_entries_to_file, retained_entries
            )
            self._update_collector_metadata_with_files(dut_id, corrected_entry)

    def _prepare_entry_inventory(
        self, log_paths: List[str], dut_id: str
    ) -> tuple[List[str], Dict[str, List[str]]]:
        """
        Normalize paths and discover summary artifacts in one owned worker.

        Keep filesystem lookups and traversal inside the same admission. Return
        local results for the async owner to adopt only after completion; no
        entry or pending metadata is mutated by the worker. Preserve the existing
        fallback to an empty inventory when discovery fails.

        Args:
            log_paths: Collector output paths accepted by the normalizer.
            dut_id: DUT selecting the output root and relative path boundary.

        Returns:
            The normalized summary paths and discovered files by directory.

        Raises:
            Exception: If path normalization fails before discovery begins.
        """
        cleaned_paths = self._clean_log_paths(log_paths, dut_id)
        try:
            discovered_files = self._discover_files_in_paths(cleaned_paths, dut_id)
        except Exception:
            discovered_files = {}
        return cleaned_paths, discovered_files

    def _deduplicate_log_paths(self, log_paths: List[str]) -> List[str]:
        """
        Deduplicate log paths, handling comma-separated strings.

        The implementation uses ``log_paths`` to deduplicate log paths, handling
        comma-separated strings.

        Args:
            log_paths: Filesystem locations processed in caller-provided order.

        Returns:
            The deduplicate log paths returned in operation-defined order.
        """
        if not log_paths:
            return []

        # Collect all individual paths
        all_paths = []
        for path in log_paths:
            if not path:
                continue
            # Split by comma in case this is a comma-separated string
            if "," in path:
                parts = [p.strip() for p in path.split(",") if p.strip()]
                all_paths.extend(parts)
            else:
                all_paths.append(path.strip())

        # Use dict to preserve order while removing duplicates (Python 3.7+)
        unique_paths = list(dict.fromkeys(all_paths))
        return unique_paths

    def _normalize_status(self, status: str) -> str:
        """
        Normalize status to legacy format.

        The implementation uses ``status`` to normalize status to legacy format.
        The source value keeps its ownership while the normalized representation
        is returned separately.

        Args:
            status: Text supplied as status in the format accepted by this
                function.

        Returns:
            The validated ``result``.
        """
        # print(
        #     f"DEBUG: _normalize_status called with status='{status}' (type: {type(status)})"
        # )
        if status is None:
            result = "Unknown"
        elif status == "degraded":
            result = "Degraded"
        elif status == "partial":
            result = "Partial"
        elif status is True or status == "success" or status == "pass":
            result = "Complete"
        elif status is False or status == "error" or status == "fail":
            result = "Error"
        elif status == "skipped" or status == "not_ran":
            result = "Skipped"
        elif status == "cancelled" or status == "canceled":
            result = "Cancelled"
        else:
            result = str(status)
        # print(f"DEBUG: _normalize_status returning '{result}'")
        return result

    def _clean_log_paths(self, log_paths: List[str], dut_id: str) -> List[str]:
        """
        Clean and normalize log paths to parent directories.

        The implementation uses ``log_paths`` and ``dut_id`` to clean and
        normalize log paths to parent directories.

        Args:
            log_paths: Filesystem locations processed in caller-provided order.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The clean log paths returned in operation-defined order.
        """
        if not log_paths:
            return [""]

        # Convert to list if single path
        if isinstance(log_paths, str):
            log_paths = [log_paths]

        # Remove empty or None values
        cleaned_paths = [p for p in log_paths if p]
        if not cleaned_paths:
            return [""]

        # Convert to relative paths from DUT log directory
        dut_log_dir = self.log_dir / dut_id
        result_paths = set()

        for path in cleaned_paths:
            if os.path.exists(path):
                # Make path relative to DUT log directory
                try:
                    rel_path = os.path.relpath(path, dut_log_dir)

                    # For error logs, keep the specific file path
                    if "error-logs" in rel_path:
                        result_paths.add(rel_path)
                    else:
                        # For other files, get parent directory
                        parent_dir = str(Path(rel_path).parent)
                        if parent_dir and parent_dir != ".":
                            result_paths.add(parent_dir)
                        else:
                            result_paths.add(rel_path)
                except ValueError:
                    # If paths are on different drives or outside DUT directory, use absolute path
                    if "error-logs" in path:
                        result_paths.add(path)
                    else:
                        result_paths.add(str(Path(path).parent))
            else:
                # For non-existent paths, check if they're outside DUT directory
                try:
                    rel_path = os.path.relpath(path, dut_log_dir)
                    # If path is outside DUT directory, keep as absolute path
                    if rel_path.startswith(".."):
                        if "error-logs" in path:
                            result_paths.add(path)
                        else:
                            result_paths.add(str(Path(path).parent))
                    else:
                        # For paths within DUT directory, get parent directory
                        if "error-logs" in path:
                            result_paths.add(path)
                        else:
                            parent_dir = str(Path(rel_path).parent)
                            if parent_dir and parent_dir != ".":
                                result_paths.add(parent_dir)
                            else:
                                result_paths.add(rel_path)
                except ValueError:
                    # If paths are on different drives, use absolute path
                    if "error-logs" in path:
                        result_paths.add(path)
                    else:
                        result_paths.add(str(Path(path).parent))

        # Return unique paths
        result = list(result_paths) if result_paths else cleaned_paths
        return result if result else [""]

    def _discover_files_in_paths(
        self, log_paths: List[str], dut_id: str
    ) -> Dict[str, List[str]]:
        """
        Discover files in paths.

        The implementation uses ``log_paths`` and ``dut_id`` to discover files
        in paths. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle.

        Args:
            log_paths: Filesystem locations processed in caller-provided order.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing discover files in paths.
        """
        dut_log_dir = self.log_dir / dut_id
        try:
            dut_log_root = dut_log_dir.resolve()
        except (OSError, RuntimeError):
            return {}
        discovered_files = {}

        for path in log_paths:
            if not path or path == "":
                continue

            # Convert to absolute path if needed
            if os.path.isabs(path):
                abs_path = Path(path)
            else:
                abs_path = dut_log_dir / path

            # Skip if path doesn't exist
            if not abs_path.exists():
                continue

            # Handle individual files (like error logs)
            if abs_path.is_file():
                try:
                    # Make path relative to DUT log directory
                    rel_file_path = os.path.relpath(abs_path, dut_log_dir)
                    # Use the parent directory as the key for consistency
                    parent_dir = str(Path(rel_file_path).parent)
                    if parent_dir == ".":
                        parent_dir = (
                            rel_file_path  # If file is in root, use file path as key
                        )

                    if parent_dir not in discovered_files:
                        discovered_files[parent_dir] = []
                    discovered_files[parent_dir].append(rel_file_path)

                except ValueError:
                    # If paths are on different drives, use absolute path
                    parent_dir = str(abs_path.parent)
                    if parent_dir not in discovered_files:
                        discovered_files[parent_dir] = []
                    discovered_files[parent_dir].append(str(abs_path))
                continue

            # Handle directories
            if not abs_path.is_dir():
                continue

            # Collection inventories are authoritative and therefore remain
            # uncapped inside the DUT tree.  Do not recursively enumerate an
            # arbitrary absolute directory supplied as a log path, though.
            try:
                abs_path = abs_path.resolve()
            except (OSError, RuntimeError):
                continue
            if not abs_path.is_relative_to(dut_log_root):
                continue

            # ``Path.rglob`` yields entries incrementally.  Retain one relative
            # path per file because this inventory is authoritative input to
            # the execution summary and report artifact links; an implicit
            # count limit would silently make a successful collection look
            # incomplete.
            files_in_folder = []
            try:
                for file_path in abs_path.rglob("*"):
                    if file_path.is_file():
                        # Make path relative to DUT log directory
                        try:
                            rel_file_path = os.path.relpath(file_path, dut_log_dir)
                            files_in_folder.append(rel_file_path)
                        except ValueError:
                            # If paths are on different drives, use absolute path
                            files_in_folder.append(str(file_path))

                # Sort files for consistent output
                files_in_folder.sort()

                if files_in_folder:
                    discovered_files[path] = files_in_folder

            except (OSError, PermissionError):
                # Skip directories that can't be accessed
                continue

        return discovered_files

    def _update_collector_metadata_with_files(
        self, dut_id: str, entry: Dict[str, Any]
    ) -> None:
        """
        Update collector metadata with discovered files.

        Store discovered files for later integration This avoids race conditions
        by not calling _update_collector_status here.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            entry: Mapping supplying fields for update collector metadata with
                discovered files.
        """
        try:
            collector_id = entry.get("collector_id")
            discovered_files = entry.get("discovered_files", {})

            if not collector_id or not discovered_files:
                return

            # Store discovered files for later integration
            # This avoids race conditions by not calling _update_collector_status here
            if not hasattr(self, "_pending_file_updates"):
                self._pending_file_updates = {}

            key = f"{dut_id}:{collector_id}"
            self._pending_file_updates[key] = discovered_files

        except Exception:
            # Silently fail if metadata update fails
            pass

    @staticmethod
    def _sanitize_summary_cell(value: Any) -> str:
        """
        Return a single-line, tab-safe value for the TSV summary.

        After applying local validation, the function forwards ``value`` to
        ``strip`` and preserves its return and exception contract.

        Args:
            value: Value evaluated while performing single-line, tab-safe value
                for the TSV summary.

        Returns:
            The canonical summary cell text.
        """
        return re.sub(r"[\t\r\n]+", " ", str(value or "")).strip()

    @classmethod
    def _summary_header(cls) -> str:
        """
        Keep the original four columns first, then append richer fields.

        The implementation uses current instance state to keep the original four
        columns first, then append richer fields.

        Returns:
            The canonical summary header text.
        """
        return (
            f"{cls._SUMMARY_HEADERS[0]:<35} \t "
            f"{cls._SUMMARY_HEADERS[1]:<8} \t "
            f"{cls._SUMMARY_HEADERS[2]:<16} \t "
            + " \t ".join(cls._SUMMARY_HEADERS[3:])
            + "\n"
        )

    def _normalize_output_path(self, raw_path: Any, dut_id: str) -> str:
        """
        Normalize an output path relative to the DUT directory when possible.

        The implementation uses ``raw_path`` and ``dut_id`` to normalize an
        output path relative to the DUT directory when possible. The source
        value keeps its ownership while the normalized representation is
        returned separately. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            raw_path: filesystem location used as the raw path for this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The canonical output path.
        """
        if not raw_path:
            return ""

        path = Path(str(raw_path))
        dut_dir = (self.log_dir / dut_id).resolve(strict=False)
        if path.is_absolute():
            try:
                path = path.resolve(strict=False).relative_to(dut_dir)
            except (OSError, ValueError):
                return str(path).replace("\\", "/")
        else:
            parts = path.parts
            if parts and parts[0] == dut_id:
                path = Path(*parts[1:])
        return str(path).replace("\\", "/")

    @staticmethod
    def _is_diagnostic_output_path(path: str) -> bool:
        """
        Classify request/response captures and error logs as diagnostics.

        The implementation uses ``path`` to classify request/response captures
        and error logs as diagnostics.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            Whether the classify request/response captures and error logs as
            diagnostics operation succeeds.
        """
        parts = [part.lower() for part in Path(path).parts]
        if not parts:
            return False
        if "error-logs" in parts[:-1] or "diagnostic" in parts[:-1]:
            return True
        return parts[-1].startswith(
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
        )

    @staticmethod
    def _is_collector_status_envelope(path: str, collector_id: Optional[str]) -> bool:
        """
        Identify only the logger-created status envelope at collector root.

        Logger envelopes have the exact DUT-relative shape
        <group>/<collector-directory>/status.json. A collected nested file named
        status.json remains a legitimate artifact, even when its parent
        directory happens to contain the collector ID.

        Args:
            path: filesystem location used as the path for this operation.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            Whether the identify only the logger-created status envelope at
            collector root operation succeeds.
        """
        candidate = Path(path)
        if candidate.name.lower() != "status.json" or not collector_id:
            return False
        # Logger envelopes have the exact DUT-relative shape
        # <group>/<collector-directory>/status.json. A collected nested file
        # named status.json remains a legitimate artifact, even when its parent
        # directory happens to contain the collector ID.
        if candidate.is_absolute() or len(candidate.parts) != 3:
            return False
        parent_name = candidate.parent.name
        return bool(
            re.search(
                rf"(?:^|_){re.escape(str(collector_id))}(?:_|$)",
                parent_name,
                re.IGNORECASE,
            )
        )

    def _normalize_inventory_paths(
        self,
        dut_id: str,
        collector_id: Optional[str],
        paths: Any,
    ) -> set[str]:
        """
        Normalize an authoritative inventory category without reclassifying it.

        The implementation uses ``dut_id``, ``collector_id``, and ``paths`` to
        normalize an authoritative inventory category without reclassifying it.
        The source value keeps its ownership while the normalized representation
        is returned separately.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            paths: Filesystem locations processed in caller-provided order.

        Returns:
            The validated ``normalized_paths``.
        """
        normalized_paths = set()
        for path in paths if isinstance(paths, (list, tuple, set)) else []:
            normalized = self._normalize_output_path(path, dut_id)
            if normalized and not self._is_collector_status_envelope(
                normalized, collector_id
            ):
                normalized_paths.add(normalized)
        return normalized_paths

    @staticmethod
    def _is_preexecution_exclusion_record(collector_info: Dict[str, Any]) -> bool:
        """
        Recognize explicit and legacy applicability/config exclusions.

        The implementation uses ``collector_info`` to recognize explicit and
        legacy applicability/config exclusions.

        Args:
            collector_info: Mapping supplying fields for recognize explicit and
                legacy applicability/config exclusions.

        Returns:
            Whether the recognize explicit and legacy applicability/config
            exclusions operation succeeds.
        """
        if collector_info.get("exclusion_type"):
            return True
        reason = str(collector_info.get("reason") or "").lower()
        return "filtered out before execution" in reason or (
            "baseboardconstraint" in reason and "not applicable" in reason
        )

    def _classify_output_paths(
        self,
        dut_id: str,
        log_paths: List[str],
        discovered_files: Optional[Dict[str, List[str]]] = None,
        collector_id: Optional[str] = None,
    ) -> tuple[List[str], List[str]]:
        """
        Return deterministic physical artifact and diagnostic file paths.

        Re-scan the legacy log paths at finalization time because CSV exports,
        task-polling captures, and partial-collector error logs may be created
        after the initial execution-summary entry was recorded.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            log_paths: Filesystem locations processed in caller-provided order.
            discovered_files: Optional discovered files; ``None`` selects the
                function's default behavior.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A tuple containing ``sorted`` and ``sorted`` in that order.
        """
        try:
            refreshed = self._discover_files_in_paths(log_paths or [], dut_id)
        except Exception:
            refreshed = {}

        artifacts = set()
        diagnostics = set()
        # Iterate the initial and refreshed inventories without flattening a
        # second, potentially large list in memory.  The sets are the final
        # deduplicated report membership and therefore cannot be bounded
        # without dropping artifact links.
        for inventory in (discovered_files or {}, refreshed):
            for paths in inventory.values():
                if not isinstance(paths, list):
                    continue
                for candidate in paths:
                    normalized = self._normalize_output_path(candidate, dut_id)
                    if not normalized or self._is_collector_status_envelope(
                        normalized, collector_id
                    ):
                        continue
                    if self._is_diagnostic_output_path(normalized):
                        diagnostics.add(normalized)
                    else:
                        artifacts.add(normalized)

        return sorted(artifacts), sorted(diagnostics)

    def _format_summary_entry(self, entry: Dict[str, Any]) -> str:
        """
        Serialize one enhanced summary row while preserving four-column order.

        The implementation uses ``entry`` to serialize one enhanced summary row
        while preserving four-column order.

        Args:
            entry: Mapping supplying fields for serialize one enhanced summary
                row while preserving four-column order.

        Returns:
            The canonical summary entry text.
        """
        duration = entry.get("duration_seconds")
        try:
            duration_text = f"{max(0.0, float(duration)):.6f}"
        except (TypeError, ValueError, OverflowError):
            duration_text = ""

        log_paths = sorted(
            {
                self._sanitize_summary_cell(path)
                for path in entry.get("log_paths", [])
                if path
            }
        )
        artifact_paths = sorted(
            {
                self._sanitize_summary_cell(path)
                for path in entry.get("artifact_paths", [])
                if path
            }
        )
        diagnostic_paths = sorted(
            {
                self._sanitize_summary_cell(path)
                for path in entry.get("diagnostic_paths", [])
                if path
            }
        )

        return (
            f"{self._sanitize_summary_cell(entry.get('collection_name')):<35} \t "
            f"{self._sanitize_summary_cell(entry.get('collector_id') or 'N/A'):<8} \t "
            f"{self._sanitize_summary_cell(entry.get('status') or 'Unknown'):<16} \t "
            f"{', '.join(log_paths)} \t "
            f"{duration_text} \t "
            f"{self._sanitize_summary_cell(entry.get('reason'))} \t "
            f"{', '.join(artifact_paths)} \t "
            f"{', '.join(diagnostic_paths)} \t "
            f"{self._sanitize_summary_cell(entry.get('failure_category'))}\n"
        )

    @staticmethod
    def _parse_summary_entry(line: str) -> Optional[Dict[str, Any]]:
        """
        Parse both the historical four-column and enhanced summary rows.

        The implementation uses ``line`` to parse both the historical
        four-column and enhanced summary rows. Parsing or I/O must finish before
        the validated representation is made available to the caller.

        Args:
            line: Text supplied as line in the format accepted by this function.

        Returns:
            The validated ``entry``, or ``None`` when no value qualifies.
        """
        parts = [part.strip() for part in line.rstrip("\r\n").split("\t")]
        if len(parts) < 3:
            return None
        parts += [""] * (9 - len(parts))

        try:
            duration = float(parts[4].removesuffix("s")) if parts[4] else None
        except (TypeError, ValueError, OverflowError):
            duration = None

        def split_paths(value: str) -> List[str]:
            """
            Return the split paths.

            The implementation uses ``value`` to produce the split paths.

            Args:
                value: Text supplied as value in the format accepted by this
                    function.

            Returns:
                The split paths returned in operation-defined order.
            """
            return [path.strip() for path in value.split(",") if path.strip()]

        failure_category = normalize_collector_failure_category(parts[2], parts[8])
        entry = {
            "collection_name": parts[0],
            "collector_id": parts[1] or "N/A",
            "status": parts[2] or "Unknown",
            "log_paths": split_paths(parts[3]),
            "duration_seconds": duration,
            "reason": parts[5],
            "artifact_paths": split_paths(parts[6]),
            "diagnostic_paths": split_paths(parts[7]),
            "discovered_files": {},
        }
        if failure_category is not None:
            entry["failure_category"] = failure_category
        return entry

    async def _publish_summary(
        self, dut_id: str, writer: Callable[..., None], payload: Any
    ) -> None:
        """
        Acquire publication ownership before admitting a summary writer.

        Waiting for another process uses the asynchronous directory lock and
        consumes no filesystem worker. Cancellation retains the directory lock
        until the admitted write has been joined.

        Args:
            dut_id: DUT whose summary directory is pinned and locked.
            writer: Synchronous append or correction receiving the DUT, payload,
                and acquired publication lock.
            payload: Summary entry or authoritative entry list for the writer.

        Raises:
            OSError: If the directory cannot be pinned or publication fails.
        """

        directory = self.summary_files[dut_id].parent
        await run_managed_filesystem_operation(directory.mkdir, 0o777, True, True)
        async with async_report_publication_lock(directory) as publication_lock:
            await run_managed_filesystem_operation(
                writer, dut_id, payload, publication_lock
            )

    @contextmanager
    def _open_summary_for_update(
        self,
        dut_id: str,
        publication_lock: Optional[PinnedDirectoryLock] = None,
        *,
        read_only: bool = False,
    ) -> Iterator[TextIO]:
        """
        Open a regular summary through its locked, pinned DUT directory.

        Direct synchronous callers acquire the same bounded directory lock.
        Asynchronous callers pass their existing lock so worker admission never
        precedes lock acquisition. No regular-file advisory lock is requested;
        on NFS that request would depend on the server's lock service. Directory
        locking serializes cooperating processes on this client, following the
        same ownership scope as report and archive publication.

        Args:
            dut_id: DUT owning the summary file in ``summary_files``.
            publication_lock: Lock retained by the asynchronous caller, or
                ``None`` to acquire publication ownership synchronously.
            read_only: Read an existing summary for atomic reconciliation without
                creating an empty leaf if it disappeared while acquiring ownership.

        Yields:
            An append/update or read-only stream while the directory remains locked.

        Raises:
            OSError: If the directory changes or the summary is not a regular
                file reached without following its final component.
            TimeoutError: If a synchronous caller cannot acquire the lock.
        """

        path = self.summary_files[dut_id]
        if publication_lock is None:
            path.parent.mkdir(parents=True, exist_ok=True)
            with report_publication_lock(path.parent) as acquired:
                with self._open_summary_for_update(
                    dut_id, acquired, read_only=read_only
                ) as stream:
                    yield stream
            return

        directory_fd = publication_lock.duplicate_descriptor()
        try:
            descriptor = os.open(
                path.name,
                (os.O_RDONLY if read_only else os.O_RDWR | os.O_CREAT | os.O_APPEND)
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | os.O_CLOEXEC,
                0o666,
                dir_fd=directory_fd,
            )
            with os.fdopen(
                descriptor, "r" if read_only else "a+", encoding="utf-8"
            ) as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise OSError("Execution summary is not a regular file")
                yield stream
                publication_lock.require_current()
        finally:
            os.close(directory_fd)

    def _write_entry_to_file(
        self,
        dut_id: str,
        entry: Dict[str, Any],
        publication_lock: Optional[PinnedDirectoryLock] = None,
    ) -> None:
        """
        Write a single entry to the DUT-specific summary file.

        Append under directory publication ownership, creating the header only
        for an empty file. A failed write propagates to the lifecycle owner.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            entry: Mapping supplying fields for single entry to the DUT-specific
                summary file.
            publication_lock: Already acquired directory lock, or ``None`` for
                a direct synchronous writer.
        """
        entry_line = self._format_entry_for_file(dut_id, entry)
        with self._open_summary_for_update(dut_id, publication_lock) as summary_file:
            if os.fstat(summary_file.fileno()).st_size == 0:
                summary_file.write(self._summary_header())
            summary_file.write(entry_line)
            summary_file.flush()

    def _format_entry_for_file(self, dut_id: str, entry: Dict[str, Any]) -> str:
        """
        Render one in-memory summary entry with classified artifact paths.

        Classification is recomputed at the write boundary so both ordinary
        appends and authoritative lifecycle corrections serialize the same
        artifact/diagnostic contract.

        Args:
            dut_id: Stable DUT identifier used to normalize artifact paths.
            entry: In-memory execution-summary entry to render.

        Returns:
            The canonical tab-separated summary row.
        """

        artifacts, diagnostics = self._classify_output_paths(
            dut_id,
            entry.get("log_paths", []),
            entry.get("discovered_files", {}),
            entry.get("collector_id"),
        )
        enriched_entry = {
            **entry,
            "collector_id": entry.get("collector_id") or "N/A",
            "collection_name": entry.get("collection_name") or "Unknown",
            "status": entry.get("status") or "Unknown",
            "artifact_paths": artifacts,
            "diagnostic_paths": diagnostics,
        }
        return self._format_summary_entry(enriched_entry)

    def _rewrite_entries_to_file(
        self,
        dut_id: str,
        entries: List[Dict[str, Any]],
        publication_lock: Optional[PinnedDirectoryLock] = None,
    ) -> None:
        """
        Rewrite one DUT summary from an authoritative in-memory entry set.

        The directory publication lock serializes this correction with ordinary
        append writers. Complete bytes are staged privately and atomically
        renamed, so an unlocked reader or process interruption cannot observe
        a truncate-then-write window at the published pathname.

        Args:
            dut_id: Stable DUT identifier selecting the summary file.
            entries: Authoritative entries retained for that DUT.
            publication_lock: Already acquired directory lock, or ``None`` for
                a direct synchronous correction.

        Side Effects:
            Replaces the DUT execution-summary file contents under an exclusive
            directory lock.
        """

        payload = self._summary_header() + "".join(
            self._format_entry_for_file(dut_id, entry) for entry in entries
        )
        self._replace_summary_bytes(dut_id, payload.encode("utf-8"), publication_lock)

    def _replace_summary_bytes(
        self,
        dut_id: str,
        payload: bytes,
        publication_lock: Optional[PinnedDirectoryLock] = None,
    ) -> None:
        """
        Publish a complete summary through the shared atomic byte publisher.

        Direct callers acquire directory ownership here; asynchronous callers
        pass the lock they acquired before worker admission. Both paths publish
        through a pinned descriptor on the selected destination filesystem.

        Args:
            dut_id: DUT whose declared summary path is selected.
            payload: Complete formatted summary bytes, including any final footer.
            publication_lock: Existing directory ownership, or ``None`` for a
                synchronous caller that must acquire the bounded lock itself.

        Raises:
            OSError: If staging, directory validation or replacement fails.
            TimeoutError: If a synchronous caller cannot acquire publication ownership.

        Side Effects:
            Preserves the old complete file until a private staging file is ready.
        """
        path = self.summary_files[dut_id]
        if publication_lock is None:
            path.parent.mkdir(parents=True, exist_ok=True)
            with report_publication_lock(path.parent) as acquired:
                self._replace_summary_bytes(dut_id, payload, acquired)
            return
        atomic_publish_locked_bytes(publication_lock, path.name, payload)

    @staticmethod
    def _write_all(fd: int, payload: bytes | memoryview) -> None:
        """
        Write all.

        The implementation uses ``fd`` and ``payload`` to write all. Success is
        reported only after the owning output boundary has completed its
        required write or publication step. If the function cannot write all,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            fd: Numeric fd used while the operation performs bounded accounting.
            payload: Bounded byte sequence supplied as payload.

        Raises:
            OSError: If execution summary write made no progress.
        """
        remaining = memoryview(payload)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError("execution summary write made no progress")
            remaining = remaining[written:]

    def _publish_zero_summary(self, dut_fd: int, payload: bytes) -> None:
        """
        Publish zero summary.

        The implementation uses ``dut_fd`` and ``payload`` to publish zero
        summary. Success is reported only after the owning output boundary has
        completed its required write or publication step. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            dut_fd: Numeric DUT fd used while the operation performs bounded
                accounting.
            payload: Bounded byte sequence supplied as payload.
        """
        temp_name = f".{self.summary_file}.{secrets.token_hex(16)}.tmp"
        temp_fd = None
        try:
            temp_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=dut_fd,
            )
            self._write_all(temp_fd, payload)
            os.fchmod(temp_fd, 0o644)
            os.fsync(temp_fd)
            try:
                os.link(
                    temp_name,
                    self.summary_file,
                    src_dir_fd=dut_fd,
                    dst_dir_fd=dut_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                return
            os.unlink(temp_name, dir_fd=dut_fd)
            temp_name = ""
            os.fsync(dut_fd)
        finally:
            try:
                if temp_name:
                    try:
                        os.unlink(temp_name, dir_fd=dut_fd)
                    except FileNotFoundError:
                        pass
            finally:
                if temp_fd is not None:
                    os.close(temp_fd)

    def _complete_zero_summary(self, summary_fd: int, payload: bytes) -> None:
        """
        Complete an empty summary without overwriting divergent bytes.

        The implementation uses ``summary_fd`` and ``payload`` to complete an
        empty summary without overwriting divergent bytes. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle.

        Args:
            summary_fd: Numeric summary fd used while the operation performs
                bounded accounting.
            payload: Bounded byte sequence supplied as payload.
        """
        size = os.fstat(summary_fd).st_size
        if size > len(payload):
            return
        os.lseek(summary_fd, 0, os.SEEK_SET)
        prior = b""
        while len(prior) < size:
            chunk = os.read(summary_fd, size - len(prior))
            if not chunk:
                return
            prior += chunk
        if prior == payload or not payload.startswith(prior):
            return

        try:
            os.lseek(summary_fd, len(prior), os.SEEK_SET)
            self._write_all(summary_fd, payload[len(prior) :])
            os.fsync(summary_fd)
        except BaseException:
            os.ftruncate(summary_fd, 0)
            os.lseek(summary_fd, 0, os.SEEK_SET)
            self._write_all(summary_fd, prior)
            os.fsync(summary_fd)
            raise

    def ensure_zero_execution_summary(self, dut_id: str) -> None:
        """
        Publish the canonical report when a trusted DUT ran no collectors.

        The implementation uses ``dut_id`` to publish the canonical report when
        a trusted DUT ran no collectors. Success is reported only after the
        owning output boundary has completed its required write or publication
        step. If the function cannot publish the canonical report when a trusted
        DUT ran no collectors, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Raises:
            RuntimeError: If execution-summary DUT is absent from the receipt;
                or DUT ``dut_id`` does not own a regular execution summary.
            ValueError: If the dut id is not one direct path component.
        """
        if (
            self._terminal_dut_roster is not None
            and dut_id not in self._terminal_dut_roster
        ):
            raise RuntimeError("Execution-summary DUT is absent from the receipt")
        if (
            not isinstance(dut_id, str)
            or not dut_id
            or dut_id in {".", ".."}
            or os.path.basename(dut_id) != dut_id
            or "\x00" in dut_id
        ):
            raise ValueError("DUT ID must be one direct path component")
        if dut_id in self.summary_files:
            return

        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        summary_flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        payload = (
            self._summary_header() + "\nTotal execution time: 0.000000s\n"
        ).encode("utf-8")
        root_fd = os.open(os.fspath(self.log_dir), directory_flags)
        dut_fd = summary_fd = None
        try:
            dut_fd = os.open(dut_id, directory_flags, dir_fd=root_fd)
            # Match ordinary summary writers without contacting the NFS
            # regular-file lock service, including the empty-file repair path.
            fcntl.flock(dut_fd, fcntl.LOCK_EX)
            try:
                summary_fd = os.open(
                    self.summary_file,
                    summary_flags,
                    dir_fd=dut_fd,
                )
            except FileNotFoundError:
                self._publish_zero_summary(dut_fd, payload)
                return

            summary_stat = os.fstat(summary_fd)
            if not stat.S_ISREG(summary_stat.st_mode):
                raise RuntimeError(
                    f"DUT {dut_id} does not own a regular execution summary"
                )
            self._complete_zero_summary(summary_fd, payload)
        finally:
            if summary_fd is not None:
                os.close(summary_fd)
            if dut_fd is not None:
                os.close(dut_fd)
            os.close(root_fd)

    def finalize(self) -> None:
        """
        Finalize each DUT summary under its directory publication lock.

        Read, reconcile and replace each summary while retaining ownership so a
        cooperating append cannot be lost between the read and atomic commit.
        Asynchronous workflow callers run this synchronous method in an owned worker.

        Raises:
            OSError: If a summary cannot be read or atomically published.
            TimeoutError: If another publisher holds the directory beyond its budget.
        """
        for dut_id, summary_file_path in self.summary_files.items():
            if not summary_file_path.exists():
                continue
            with report_publication_lock(summary_file_path.parent) as publication_lock:
                self._finalize_dut_summary(dut_id, publication_lock)

    def _finalize_dut_summary(
        self, dut_id: str, publication_lock: PinnedDirectoryLock
    ) -> None:
        """
        Reconcile and format one summary while retaining its directory ownership.

        Use the existing authority, status priority and timing reconciliation
        rules. Holding ownership across that work prevents a concurrent append
        from landing between the initial read and the replacement commit.

        Args:
            dut_id: Declared DUT whose authoritative collector records are loaded.
            publication_lock: Directory lock held from the initial read through commit.

        Raises:
            OSError: If reading, validation or replacement fails.

        Side Effects:
            Publishes sorted authoritative entries and their completion footer
            without exposing an empty or partially rewritten final pathname.
        """
        # Read all entries
        with self._open_summary_for_update(
            dut_id, publication_lock, read_only=True
        ) as summary_file:
            summary_file.seek(0)
            lines = summary_file.readlines()
        if not lines:
            return

        entries: List[Dict[str, Any]] = []

        # Process lines, skipping empty lines and handling header
        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:  # Skip empty lines
                continue
            if "Collection Name" in line_stripped:  # Skip header lines
                continue
            if "\t" not in line and self._EXECUTION_TIME_LINE_RE.match(line_stripped):
                continue
            parsed_entry = self._parse_summary_entry(line)
            if parsed_entry is not None:
                entries.append(parsed_entry)

        # Merge entries for the same collector, combining paths and using most severe status
        collector_entries = {}
        final_collector_records = self._load_final_collector_records(dut_id)
        # Handle case-insensitive status matching
        status_priority = {
            "error": 5,
            "Error": 5,
            "ERROR": 5,
            "partial": 4,
            "Partial": 4,
            "PARTIAL": 4,
            "degraded": 3,
            "Degraded": 3,
            "DEGRADED": 3,
            "complete": 2,
            "Complete": 2,
            "COMPLETE": 2,
            "success": 2,
            "Success": 2,
            "skipped": 1,
            "Skipped": 1,
            "SKIPPED": 1,
            "unknown": 0,
            "Unknown": 0,
            "UNKNOWN": 0,
        }

        for entry in entries:
            collector_id = entry["collector_id"]
            collection_name = entry["collection_name"]
            unique_key = (
                collector_id.upper() if collector_id != "N/A" else collection_name
            )

            if unique_key not in collector_entries:
                collector_entries[unique_key] = entry
                continue

            existing = collector_entries[unique_key]
            current_priority = status_priority.get(entry["status"], 0)
            existing_priority = status_priority.get(existing["status"], 0)
            if current_priority > existing_priority:
                existing["status"] = entry["status"]
                if entry.get("reason"):
                    existing["reason"] = entry["reason"]
                existing.pop("failure_category", None)
                if entry.get("failure_category"):
                    existing["failure_category"] = entry["failure_category"]
            elif not existing.get("reason") and entry.get("reason"):
                existing["reason"] = entry["reason"]
            if (
                current_priority == existing_priority
                and not existing.get("failure_category")
                and entry.get("failure_category")
            ):
                existing["failure_category"] = entry["failure_category"]

            durations = [
                duration
                for duration in (
                    existing.get("duration_seconds"),
                    entry.get("duration_seconds"),
                )
                if duration is not None
            ]
            existing["duration_seconds"] = max(durations) if durations else None
            for field in ("log_paths", "artifact_paths", "diagnostic_paths"):
                existing[field] = sorted(
                    set(existing.get(field, [])) | set(entry.get(field, []))
                )

        # Merge discovered files from in-memory entries if available
        if dut_id in self.entries:
            for memory_entry in self.entries[dut_id]:
                collector_id = memory_entry.get("collector_id", "N/A")
                collection_name = memory_entry.get("collection_name", "Unknown")
                unique_key = (
                    str(collector_id).upper()
                    if collector_id != "N/A"
                    else collection_name
                )

                if unique_key in collector_entries:
                    discovered_files = memory_entry.get("discovered_files", {})
                    if discovered_files:
                        # Merge discovered files
                        existing_discovered = collector_entries[unique_key][
                            "discovered_files"
                        ]
                        for path, files in discovered_files.items():
                            if path not in existing_discovered:
                                existing_discovered[path] = files
                            else:
                                # Merge file lists, avoiding duplicates
                                existing_files = set(existing_discovered[path])
                                new_files = set(files)
                                existing_discovered[path] = list(
                                    existing_files | new_files
                                )

                    if not collector_entries[unique_key].get("reason"):
                        collector_entries[unique_key]["reason"] = (
                            memory_entry.get("reason") or ""
                        )
                    if memory_entry.get("failure_category"):
                        collector_entries[unique_key]["failure_category"] = (
                            memory_entry["failure_category"]
                        )

        # Convert back to entries format
        final_entries: List[Dict[str, Any]] = []
        for unique_key in collector_entries:
            entry_data = collector_entries[unique_key]
            record = final_collector_records.get(
                str(entry_data["collector_id"]).upper()
            )
            if (
                record
                and record.get("excluded")
                and bool(
                    entry_data.get("log_paths")
                    or entry_data.get("artifact_paths")
                    or entry_data.get("diagnostic_paths")
                    or entry_data.get("duration_seconds") not in (None, 0, 0.0)
                )
            ):
                # Exclusion rows may describe why explicitly requested work
                # did not run, but they must never claim execution evidence.
                # Drop a contradictory provisional row rather than publishing
                # artifacts or duration for work the tracker proves excluded.
                continue
            authoritative_diagnostics: set[str] = set()
            authoritative_artifacts: set[str] = set()
            if record:
                if record.get("status"):
                    entry_data["status"] = record["status"]
                if record.get("collector_name"):
                    entry_data["collection_name"] = record["collector_name"]
                if record.get("reason") is not None:
                    entry_data["reason"] = record["reason"]
                entry_data.pop("failure_category", None)
                if record.get("failure_category") is not None:
                    entry_data["failure_category"] = record["failure_category"]
                if record.get("duration_seconds") is not None:
                    entry_data["duration_seconds"] = record["duration_seconds"]

            artifacts, diagnostics = self._classify_output_paths(
                dut_id,
                entry_data.get("log_paths", []),
                {
                    **entry_data.get("discovered_files", {}),
                    "__final_status_inventory__": (
                        list(record.get("output_files", []))
                        + list(record.get("diagnostic_files", []))
                        + list(record.get("error_files", []))
                        + list(record.get("all_files", []))
                        if record
                        else []
                    ),
                    **(
                        record.get("discovered_files", {})
                        if record and isinstance(record.get("discovered_files"), dict)
                        else {}
                    ),
                },
                entry_data.get("collector_id"),
            )
            if record:
                authoritative_diagnostics = self._normalize_inventory_paths(
                    dut_id,
                    entry_data.get("collector_id"),
                    list(record.get("diagnostic_files", []))
                    + list(record.get("error_files", [])),
                )
                authoritative_artifacts = (
                    self._normalize_inventory_paths(
                        dut_id,
                        entry_data.get("collector_id"),
                        record.get("output_files", []),
                    )
                    - authoritative_diagnostics
                )
                # Explicit final categories override filename heuristics.
                artifacts = sorted(
                    (set(artifacts) | authoritative_artifacts)
                    - authoritative_diagnostics
                )
                diagnostics = sorted(
                    (set(diagnostics) - authoritative_artifacts)
                    | authoritative_diagnostics
                )
            entry_data["log_paths"] = sorted(
                {path for path in entry_data.get("log_paths", []) if path}
            )
            final_diagnostics = (
                set(entry_data.get("diagnostic_paths", []))
                | set(diagnostics)
                | authoritative_diagnostics
            ) - authoritative_artifacts
            final_artifacts = (
                set(entry_data.get("artifact_paths", []))
                | set(artifacts)
                | authoritative_artifacts
            ) - final_diagnostics
            entry_data["artifact_paths"] = sorted(final_artifacts)
            entry_data["diagnostic_paths"] = sorted(final_diagnostics)
            final_entries.append(entry_data)

        # Get actual execution time - prioritize DUT total time over individual collector times
        execution_time_str = "Total execution time: 0.000000s"  # Default fallback

        # Method 1: Try to get total DUT execution time from runtime log timestamps
        # (This is per-DUT timing, which is what users expect in per-DUT reports)
        total_dut_time = self._get_total_dut_execution_time(dut_id)
        if total_dut_time > 0:
            execution_time_str = f"Total execution time: {total_dut_time:.6f}s"
        else:
            # Method 2: Try to get total tool execution time from stdout log
            # (Fallback for single-DUT scenarios where tool time ≈ DUT time)
            total_tool_time = self._get_total_tool_execution_time()
            if total_tool_time > 0:
                execution_time_str = f"Total execution time: {total_tool_time:.6f}s"
            else:
                # Method 3: Try to read the actual execution time from the runtime log
                runtime_log_path = self.log_dir / dut_id / "nvdebug_runtime_output.txt"
                if runtime_log_path.exists():
                    try:
                        with runtime_log_path.open("r", encoding="utf-8") as f:
                            content = f.read()
                        # Look for "Total execution time: X.XX seconds" in the runtime log
                        runtime_match = re.search(
                            r"Total execution time:\s*[^(]*\((\d+(?:\.\d+)?)\s*seconds\)",
                            content,
                        )
                        if runtime_match:
                            actual_execution_time = float(runtime_match.group(1))
                            execution_time_str = (
                                f"Total execution time: {actual_execution_time:.6f}s"
                            )
                        else:
                            # Method 3: Try to get execution time from metadata JSON files (individual collector times)
                            max_time = self._get_execution_time_from_metadata(dut_id)
                            if max_time > 0:
                                execution_time_str = (
                                    f"Total execution time: {max_time:.6f}s"
                                )
                            else:
                                # Method 4: Try to extract execution time from individual collector results in runtime log
                                collector_time_matches = re.findall(
                                    r"Time:\s*(\d+(?:\.\d+)?)s|(\d+(?:\.\d+)?)s\s*$",
                                    content,
                                    re.MULTILINE,
                                )
                                if collector_time_matches:
                                    # Get the maximum execution time from all collectors
                                    max_time = 0.0
                                    for match in collector_time_matches:
                                        # match is a tuple, get the non-empty value
                                        time_str = match[0] if match[0] else match[1]
                                        if time_str:
                                            try:
                                                time_val = float(time_str)
                                                max_time = max(max_time, time_val)
                                            except ValueError:
                                                continue
                                    if max_time > 0:
                                        execution_time_str = (
                                            f"Total execution time: {max_time:.6f}s"
                                        )
                    except Exception:
                        # If reading runtime log fails, fall back to wall-clock calculation
                        end_time = datetime.now()
                        dut_start_time = self.dut_start_times.get(
                            dut_id, self.start_time
                        )
                        execution_time = end_time - dut_start_time
                        execution_time_str = f"Total execution time: {execution_time.total_seconds():.6f}s"
                else:
                    # If no runtime log, fall back to wall-clock calculation
                    end_time = datetime.now()
                    dut_start_time = self.dut_start_times.get(dut_id, self.start_time)
                    execution_time = end_time - dut_start_time
                    execution_time_str = (
                        f"Total execution time: {execution_time.total_seconds():.6f}s"
                    )

        payload = (
            self._summary_header()
            + "".join(
                self._format_summary_entry(entry)
                for entry in sorted(
                    final_entries,
                    key=lambda item: (
                        str(item["collection_name"]).lower(),
                        str(item.get("collector_id") or "").lower(),
                    ),
                )
            )
            + f"\n{execution_time_str}\n"
        )
        self._replace_summary_bytes(dut_id, payload.encode("utf-8"), publication_lock)

    def _get_total_tool_execution_time(self) -> float:
        """
        Get total tool execution time from stdout log.

        Look for "Total execution time: Xm Y.ZZs (Z.ZZ seconds)".

        Returns:
            The numeric total tool execution time value.
        """
        try:
            stdout_log_path = self.log_dir / ".nvdebug_stdout.log"
            if not stdout_log_path.exists():
                return 0.0

            with stdout_log_path.open("r", encoding="utf-8") as f:
                content = f.read()

            # Look for "Total execution time: Xm Y.ZZs (Z.ZZ seconds)"
            tool_time_match = re.search(
                r"Total execution time:\s*\d+m\s*\d+\.\d+s\s*\((\d+(?:\.\d+)?)\s*seconds\)",
                content,
            )

            if tool_time_match:
                return float(tool_time_match.group(1))

            return 0.0
        except Exception:
            return 0.0

    def _load_final_collector_statuses(self, dut_id: str) -> Dict[str, str]:
        """
        Backward-compatible status-only view of final collector records.

        The implementation uses ``dut_id`` to backward-compatible status-only
        view of final collector records.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing final collector statuses.
        """
        return {
            collector_id: record["status"]
            for collector_id, record in self._load_final_collector_records(
                dut_id
            ).items()
            if record.get("status")
        }

    def _load_final_collector_records(self, dut_id: str) -> Dict[str, Dict[str, Any]]:
        """
        Load authoritative status/reason and measured collector duration.

        Final collection-status metadata owns status, reason, collector
        identity, and exclusion semantics. TimingManager (or its persisted
        timing.json) owns the measured collector wall clock.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``final_records``.

        Raises:
            SnapshotConsistencyError: If execution-summary DUT is absent from
                the receipt; or could not read status snapshot artifact.
        """
        if (
            self._terminal_dut_roster is not None
            and dut_id not in self._terminal_dut_roster
        ):
            raise SnapshotConsistencyError(
                "Execution-summary DUT is absent from the receipt"
            )
        snapshot_generation = self._status_snapshot_generation()
        status_sources = (dut_id, None)

        final_records: Dict[str, Dict[str, Any]] = {}
        for status_dut_id in status_sources:
            try:
                status_data = read_snapshot_status(
                    self.log_dir,
                    dut_id=status_dut_id,
                    expected_generation=snapshot_generation,
                    required=snapshot_generation is not None,
                )
            except SnapshotArtifactFormatError:
                if snapshot_generation is not None:
                    raise
                continue
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                if snapshot_generation is not None:
                    raise SnapshotConsistencyError(
                        "Could not read status snapshot artifact"
                    ) from error
                continue
            if status_data is None:
                continue

            collectors = status_data.get("collectors", {})
            if not isinstance(collectors, dict):
                continue

            for key, collector_info in collectors.items():
                if not isinstance(collector_info, dict):
                    continue

                key_dut_id = key.split(":", 1)[0] if ":" in key else None
                info_dut_id = collector_info.get("dut_id")
                if info_dut_id and info_dut_id != dut_id:
                    continue
                if not info_dut_id and key_dut_id and key_dut_id != dut_id:
                    continue

                collector_id = collector_info.get("collector_id")
                if not collector_id and ":" in key:
                    collector_id = key.split(":", 1)[1]
                if not collector_id:
                    continue

                normalized_status = self._normalize_final_metadata_status(
                    collector_info.get("status")
                )
                try:
                    duration = max(0.0, float(collector_info.get("execution_time")))
                except (TypeError, ValueError, OverflowError):
                    duration = None
                final_records[str(collector_id).upper()] = {
                    "status": normalized_status,
                    "reason": collector_info.get("reason"),
                    "failure_category": normalize_collector_failure_category(
                        normalized_status,
                        collector_info.get("failure_category"),
                    ),
                    "collector_name": collector_info.get("collector_name"),
                    "duration_seconds": duration,
                    "excluded": self._is_preexecution_exclusion_record(collector_info),
                    "output_files": self._normalize_inventory_list(
                        collector_info.get("output_files")
                    ),
                    "diagnostic_files": self._normalize_inventory_list(
                        collector_info.get("diagnostic_files")
                    ),
                    "error_files": self._normalize_inventory_list(
                        collector_info.get("error_files")
                    ),
                    "all_files": self._normalize_inventory_list(
                        collector_info.get("all_files")
                    ),
                    "discovered_files": (
                        collector_info.get("discovered_files", {})
                        if isinstance(collector_info.get("discovered_files"), dict)
                        else {}
                    ),
                }

            if final_records:
                break

        # Prefer live monotonic timing while the run is still finalizing.
        live_timing_ids = set()
        timing_manager = getattr(
            getattr(getattr(self, "logger", None), "orchestrator", None),
            "timing_manager",
            None,
        )
        if timing_manager and hasattr(timing_manager, "get_collector_timing"):
            for collector_id, record in final_records.items():
                try:
                    timing = timing_manager.get_collector_timing(dut_id, collector_id)
                    duration = timing.get("wall_clock_duration_seconds")
                    if duration is not None:
                        record["duration_seconds"] = max(0.0, float(duration))
                        live_timing_ids.add(collector_id)
                except (AttributeError, TypeError, ValueError, OverflowError):
                    pass

        # Persisted timing is also useful when finalizing a pre-existing legacy
        # four-column summary without a live orchestrator.
        try:
            timing_data = read_snapshot_timing(
                self.log_dir,
                dut_id,
                expected_generation=snapshot_generation,
                required=snapshot_generation is not None,
            )
            if timing_data is not None:
                collector_timings = timing_data.get("collectors", {})
                if isinstance(collector_timings, dict):
                    for collector_id, timing in collector_timings.items():
                        if not isinstance(timing, dict):
                            continue
                        normalized_id = str(collector_id).upper()
                        record = final_records.setdefault(
                            normalized_id,
                            {
                                "status": self._normalize_final_metadata_status(
                                    timing.get("status")
                                ),
                                "reason": timing.get("reason"),
                                "collector_name": timing.get("collector_name"),
                                "duration_seconds": None,
                                "excluded": False,
                                "output_files": [],
                                "diagnostic_files": [],
                                "error_files": [],
                                "all_files": [],
                                "discovered_files": {},
                            },
                        )
                        if normalized_id in live_timing_ids:
                            continue
                        duration = timing.get(
                            "duration_seconds",
                            timing.get("wall_clock_duration_seconds"),
                        )
                        if duration is not None:
                            record["duration_seconds"] = max(0.0, float(duration))
        except SnapshotArtifactFormatError:
            if snapshot_generation is not None:
                raise
        except (
            json.JSONDecodeError,
            OSError,
            TypeError,
            ValueError,
            OverflowError,
        ):
            pass

        return final_records

    @staticmethod
    def _normalize_inventory_list(value: Any) -> List[str]:
        """
        Normalize one optional status-inventory field to a path list.

        The implementation uses ``value`` to normalize one optional
        status-inventory field to a path list. The source value keeps its
        ownership while the normalized representation is returned separately.

        Args:
            value: Value evaluated while performing one optional
                status-inventory field to a path list.

        Returns:
            The inventory list returned in operation-defined order.
        """
        if isinstance(value, (list, tuple, set)):
            return [str(path) for path in value if path]
        if value:
            return [str(value)]
        return []

    def _normalize_final_metadata_status(self, status: Any) -> Optional[str]:
        """
        Normalize final collection metadata status for execution summaries.

        After applying local validation, the function forwards ``status`` to
        ``self._normalize_status`` and preserves its return and exception
        contract. The source value keeps its ownership while the normalized
        representation is returned separately.

        Args:
            status: Status object whose ``strip`` state is read while performing
                final collection metadata status for execution summaries.

        Returns:
            The canonical final metadata status, or ``None`` when the requested
            value is unavailable.
        """
        if status is None:
            return None
        if isinstance(status, str):
            status_key = status.strip().lower()
        else:
            status_key = status

        final_statuses = {
            "success",
            "pass",
            "complete",
            "completed",
            "degraded",
            "partial",
            "error",
            "fail",
            "skipped",
            "not_ran",
            "cancelled",
            "canceled",
            True,
            False,
        }
        if status_key not in final_statuses:
            return None
        normalized_aliases = {
            "complete": "success",
            "completed": "success",
        }
        return self._normalize_status(normalized_aliases.get(status_key, status_key))

    def _get_total_dut_execution_time(self, dut_id: str) -> float:
        """
        Return total DUT execution time.

        Method 1: Try to get wall-clock time from timing.json (most accurate).

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The numeric total DUT execution time value.

        Raises:
            SnapshotConsistencyError: If execution-summary DUT is absent from
                the receipt.
        """
        snapshot_generation: Optional[str] = None
        try:
            # Method 1: Try to get wall-clock time from timing.json (most accurate)
            if (
                self._terminal_dut_roster is not None
                and dut_id not in self._terminal_dut_roster
            ):
                raise SnapshotConsistencyError(
                    "Execution-summary DUT is absent from the receipt"
                )
            snapshot_generation = self._status_snapshot_generation()
            timing_data = read_snapshot_timing(
                self.log_dir,
                dut_id,
                expected_generation=snapshot_generation,
                required=snapshot_generation is not None,
            )
            if timing_data is not None:
                wall_clock_duration = timing_data.get("overall", {}).get(
                    "wall_clock_duration_seconds", 0.0
                )
                if wall_clock_duration > 0:
                    return wall_clock_duration

            # Method 2: Fallback to runtime log timestamps (includes initialization overhead)
            runtime_log_path = self.log_dir / dut_id / "nvdebug_runtime_output.txt"
            if not runtime_log_path.exists():
                return 0.0

            with runtime_log_path.open("r", encoding="utf-8") as f:
                content = f.read()

            # Look for start and end timestamps
            # Start: "Started at: 2025-09-08T23:43:58.119244"
            start_match = re.search(
                r"Started at:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)", content
            )
            # End: "Completed at: 2025-09-08T23:46:07.411536"
            end_match = re.search(
                r"Completed at:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)", content
            )

            if start_match and end_match:
                from datetime import datetime

                start_time = datetime.fromisoformat(start_match.group(1))
                end_time = datetime.fromisoformat(end_match.group(1))
                execution_time = (end_time - start_time).total_seconds()
                return execution_time

            return 0.0
        except SnapshotArtifactFormatError:
            if snapshot_generation is not None:
                raise
            return 0.0
        except SnapshotConsistencyError:
            raise
        except Exception:
            return 0.0

    def _get_execution_time_from_metadata(self, dut_id: str) -> float:
        """
        Get execution time from metadata JSON files as a backup method.

        The implementation uses ``dut_id`` to get execution time from metadata
        JSON files as a backup method. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The numeric execution time from metadata value.
        """
        try:
            import json

            # Check all metadata files for execution times
            metadata_files = [
                "redfish.json",
                "ssh.json",
                "ipmi.json",
                "host.json",
                "health_check.json",
            ]
            max_time = 0.0

            for metadata_file in metadata_files:
                metadata_path = self.log_dir / dut_id / ".metadata" / metadata_file
                if metadata_path.exists():
                    try:
                        with metadata_path.open("r", encoding="utf-8") as f:
                            metadata = json.load(f)

                        collectors = metadata.get("collectors", {})
                        for collector_id, collector_info in collectors.items():
                            if isinstance(collector_info, dict):
                                execution_time = collector_info.get(
                                    "execution_time", ""
                                )
                                if execution_time and execution_time != "":
                                    try:
                                        if isinstance(execution_time, (int, float)):
                                            time_val = float(execution_time)
                                        else:
                                            time_val = float(execution_time)
                                        max_time = max(max_time, time_val)
                                    except (ValueError, TypeError):
                                        continue
                    except Exception:
                        # Skip this metadata file if there's an error
                        continue

            return max_time
        except Exception:
            return 0.0

    def get_summary_file_paths(self) -> Dict[str, Path]:
        """
        Get the paths to all summary files.

        The implementation uses current instance state to get the paths to all
        summary files.

        Returns:
            A mapping containing summary file paths.
        """
        return self.summary_files
