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
ManifestService: Generates manifest.json for the SPA report viewer.

Replaces HTML report generation with a lightweight JSON manifest that the Vue
SPA consumes to render reports client-side.
"""

import asyncio
import base64
import gzip
import hashlib
import json
import logging
import math
import os
import re
import shutil
import stat
import threading
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.collector_outcome import (
    normalize_collector_failure_category,
    project_collector_outcome_details,
    sanitize_terminal_collector_reason,
)
from ..core.finalization_receipt import (
    FinalizationReceipt,
    validate_consumable_finalization_receipt,
)
from ..core.run_result import (
    EXPLICIT_SELECTION_EVIDENCE_PATH,
    EXPLICIT_SELECTION_FAILURE_TYPES,
    RunResult,
    project_legacy_run_outcome,
    validate_run_result_document,
)
from ..utils.artifact_paths import (
    bundle_relative_artifact_path,
    normalize_artifact_file_list,
    normalize_artifact_timings,
    normalize_timing_artifact_paths,
)
from ..utils.managed_filesystem import run_managed_filesystem_operation
from ..utils.report_publication_lock import (
    PinnedDirectoryLock,
    async_report_publication_lock,
)
from ..utils.report_roles import (
    ReportRoleSnapshotChangedError,
    report_role_artifact_paths,
    report_role_snapshot,
)
from ..utils.status_snapshot import (
    MAX_TIMING_BYTES,
    RECEIPTLESS_SNAPSHOT_COMPATIBILITY_VERSION,
    SnapshotArtifactFormatError,
    SnapshotConsistencyError,
    TerminalSnapshotBinding,
    read_snapshot_status,
    read_snapshot_timing,
    validate_committed_terminal_snapshot,
)
from ..utils.trusted_extensions import legacy_extension_results
from ..version import __version__
from .openbmc_coredump_manifest import OpenBMCCoreDumpManifestService

logger = logging.getLogger(__name__)


def _log_report_publication_wait(elapsed_seconds: float) -> None:
    """
    Emit value-free liveness while another report publisher owns the lock.

    The implementation uses ``elapsed_seconds`` to emit value-free liveness
    while another report publisher owns the lock.

    Args:
        elapsed_seconds: Maximum duration in seconds allowed for elapsed
            seconds.
    """

    logger.info(
        "Waiting for another report publication to finish (%.1f seconds elapsed)",
        elapsed_seconds,
    )


LOG_VIEWER_FILES = {
    "nvdebug_runtime_output.txt",
    "nvdebug_runtime_output_structured.txt",
}

EXT_TYPE_MAP = {
    ".json": "json",
    ".txt": "text",
    ".log": "log",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
}

EXCLUDED_DIRS = {".metadata", "__pycache__", ".git"}

METADATA_SKIP_FILES = {
    "metadata.json",
    "preflight.json",
    "dependency_check.json",
    "collection_status.json",
    "timing.json",
    "system_info.json",
}

MANIFEST_PLACEHOLDER = "<!-- __NVDEBUG_MANIFEST_PLACEHOLDER__ -->"
INLINE_MANIFEST_ELEMENT_ID = "__NVDEBUG_MANIFEST_GZIP__"
_BASE64_STREAM_CHUNK_BYTES = 57 * 1024
MAX_MANIFEST_DOCUMENT_BYTES = 128 * 1024 * 1024
MAX_COMPRESSED_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_REPORT_INDEX_BYTES = 128 * 1024 * 1024
MAX_REPORT_DOCUMENT_BYTES = 192 * 1024 * 1024
MAX_BACKEND_TIMING_CACHE_BYTES = 32 * 1024 * 1024
MAX_BACKEND_TIMING_CACHE_ENTRIES = 8
MAX_SPA_ASSET_ENTRIES = 10_000
MAX_SPA_ASSET_BYTES = 256 * 1024 * 1024
MAX_AUXILIARY_JSON_FILE_BYTES = 8 * 1024 * 1024
MAX_AUXILIARY_JSON_TOTAL_BYTES = 256 * 1024 * 1024
MAX_SYSTEM_INFO_PARSE_BODY_CHARS = 256 * 1024
MAX_SYSTEM_INFO_PARSE_LINE_CHARS = 4096
MAX_SYSTEM_INFO_PARSE_LINES = 512
# Rack-scale L3 bundles can contain several thousand collector JSON artifacts.
# File admission remains bounded by this count, the aggregate byte ceiling,
# and the independent path-node ceiling.
HARD_MAX_AUXILIARY_JSON_FILES = 100_000
MAX_AUXILIARY_JSON_NODES = 250_000
MAX_AUXILIARY_JSON_DEPTH = 64
MAX_AUXILIARY_RESULT_ITEMS = 100_000
MAX_AUXILIARY_PATH_NODES = 100_000
REPORT_STAGE_CANCELLATION_GRACE_SECONDS = 1.0
_INLINE_MANIFEST_PATTERN = re.compile(
    rf'<script\b(?=[^>]*\bid=["\']{re.escape(INLINE_MANIFEST_ELEMENT_ID)}["\'])'
    r"[^>]*>.*?</script>",
    flags=re.DOTALL | re.IGNORECASE,
)
_INLINE_MANIFEST_OPEN_PATTERN = re.compile(
    rf'<script\b(?=[^>]*\bid=["\']{re.escape(INLINE_MANIFEST_ELEMENT_ID)}["\'])'
    r"[^>]*>",
    flags=re.DOTALL | re.IGNORECASE,
)
_LEGACY_MANIFEST_PATTERN = re.compile(
    r"<script\b[^>]*>\s*window\.__MANIFEST__\s*=.*?</script>",
    flags=re.DOTALL | re.IGNORECASE,
)
_LEGACY_MANIFEST_OPEN_PATTERN = re.compile(
    r"<script\b[^>]*>\s*window\.__MANIFEST__\s*=",
    flags=re.DOTALL | re.IGNORECASE,
)
_OWNED_MANIFEST_PATTERN = re.compile(
    rf"(?:{_INLINE_MANIFEST_PATTERN.pattern})|(?:{_LEGACY_MANIFEST_PATTERN.pattern})",
    flags=re.DOTALL | re.IGNORECASE,
)


def _strip_owned_manifest_fallbacks(html: str) -> str:
    """
    Remove every complete owned fallback and reject malformed remnants.

    The implementation uses ``html`` to remove every complete owned fallback and
    reject malformed remnants. If the function cannot remove every complete
    owned fallback and reject malformed remnants, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        html: Text supplied as HTML in the format accepted by this function.

    Returns:
        The validated ``cleaned``.

    Raises:
        ValueError: If could not safely replace an existing manifest fallback.
    """

    cleaned = _OWNED_MANIFEST_PATTERN.sub("", html)
    if _INLINE_MANIFEST_OPEN_PATTERN.search(
        cleaned
    ) or _LEGACY_MANIFEST_OPEN_PATTERN.search(cleaned):
        raise ValueError("Could not safely replace an existing manifest fallback")
    return cleaned


class _BoundedBinarySink:
    """
    File wrapper that rejects a stream before its byte budget is crossed.

    The type coordinates ``write``, ``flush``, and ``tell`` and retains the
    state those operations share between calls. Resource ownership remains
    inside the instance until the matching close, exit, or cleanup operation
    completes.
    """

    def __init__(self, output: Any, maximum_bytes: int):
        """
        Initialize a ``_BoundedBinarySink`` instance.

        The initializer records ``bytes_written``, ``maximum_bytes``, and
        ``output`` for later operations and establishes the instance invariants
        before any public method runs.

        Args:
            output: Output consumed while the function attempts to initialize a
                ``_BoundedBinarySink`` instance.
            maximum_bytes: Upper bound enforced for bytes; the consuming
                boundary rejects or truncates values that exceed it.
        """
        self.output = output
        self.maximum_bytes = maximum_bytes
        self.bytes_written = 0

    def write(self, payload: bytes) -> int:
        """
        Write the supplied data to the owned destination.

        The implementation uses ``payload`` to write the supplied data to the
        owned destination. Success is reported only after the owning output
        boundary has completed its required write or publication step. It
        updates ``bytes_written`` on the instance as part of that state
        transition. If the function cannot write the supplied data to the owned
        destination, its exception reaches the caller instead of being converted
        into a successful result.

        Args:
            payload: Bounded byte sequence supplied as payload.

        Returns:
            The validated ``written``.

        Raises:
            ValueError: If compressed report manifest exceeds its safety limit.
        """
        next_size = self.bytes_written + len(payload)
        if next_size > self.maximum_bytes:
            raise ValueError("Compressed report manifest exceeds its safety limit")
        written = self.output.write(payload)
        self.bytes_written += written
        return written

    def flush(self) -> None:
        """
        Flush buffered data through the owned destination.

        The implementation uses current instance state to flush buffered data
        through the owned destination.
        """
        self.output.flush()

    def tell(self) -> int:
        """
        Return the current stream position.

        After applying local validation, the function forwards current instance
        state to ``self.output.tell`` and preserves its return and exception
        contract.

        Returns:
            The numeric tell value.
        """
        return self.output.tell()


def _read_regular_file_bounded(path: Path, maximum_bytes: int) -> bytes:
    """
    Read one stable regular file without following its final component.

    After applying local validation, the function forwards ``path`` and
    ``maximum_bytes`` to ``join`` and preserves its return and exception
    contract. Parsing or I/O must finish before the validated representation is
    made available to the caller. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The regular file bounded bytes.

    Raises:
        OSError: If metadata source is not a regular file; metadata source
            exceeds its byte limit; metadata source changed before it was
            opened; or metadata source changed while it was read.
    """
    before = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise OSError("metadata source is not a regular file")
    if before.st_size < 0 or before.st_size > maximum_bytes:
        raise OSError("metadata source exceeds its byte limit")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        identity_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(opened, field) != getattr(before, field)
            for field in identity_fields
        ):
            raise OSError("metadata source changed before it was opened")
        chunks: List[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise OSError("metadata source exceeds its byte limit")
        after = os.fstat(descriptor)
        path_after = path.lstat()
        if observed != before.st_size or any(
            getattr(after, field) != getattr(before, field)
            or getattr(path_after, field) != getattr(before, field)
            for field in identity_fields
        ):
            raise OSError("metadata source changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_bounded_json_shape(document: Any) -> None:
    """
    Reject deeply nested or node-heavy auxiliary JSON iteratively.

    The implementation uses ``document`` to reject deeply nested or node-heavy
    auxiliary JSON iteratively. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        document: Document consumed while the function attempts to reject deeply
            nested or node-heavy auxiliary JSON iteratively.

    Raises:
        ValueError: If auxiliary JSON exceeds its node limit; or auxiliary JSON
            exceeds its depth limit.
    """

    stack: List[Tuple[Any, int]] = [(document, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_AUXILIARY_JSON_NODES:
            raise ValueError("auxiliary JSON exceeds its node limit")
        if depth > MAX_AUXILIARY_JSON_DEPTH:
            raise ValueError("auxiliary JSON exceeds its depth limit")
        if isinstance(value, dict):
            nodes += len(value)
            if nodes > MAX_AUXILIARY_JSON_NODES:
                raise ValueError("auxiliary JSON exceeds its node limit")
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)


def _finish_worker_heartbeat(heartbeat: "asyncio.Future[None]") -> None:
    """
    Resolve a worker-observation heartbeat unless its owner already cancelled it.

    A timer can become ready before cancellation resumes the observing coroutine
    and runs its timer cleanup. Preserve that cancellation without emitting an
    InvalidStateError from the already-ready callback.

    Args:
        heartbeat: Loop-owned future whose pending state may be completed.
    """
    if not heartbeat.done():
        heartbeat.set_result(None)


async def _await_executor_future(future: "asyncio.Future[Any]") -> Any:
    """
    Observe filesystem-worker completion with a bounded loop heartbeat.

    After applying local validation, the function forwards ``future`` to
    ``future.result`` and preserves its return and exception contract. Owned
    asynchronous work is awaited before return, so completion does not leave an
    unobserved task behind. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        future: Future object whose ``done`` and ``result`` state is read while
            performing observe filesystem-worker completion with a bounded loop
            heartbeat.

    Returns:
        The await executor future value selected by the operation.
    """
    while not future.done():
        loop = asyncio.get_running_loop()
        heartbeat = loop.create_future()
        timer = loop.call_later(0.01, _finish_worker_heartbeat, heartbeat)
        try:
            await heartbeat
        finally:
            timer.cancel()
    return future.result()


class ManifestService:
    """
    Generates a manifest.json from collected log data.

    The type coordinates ``_read_auxiliary_json``,
    ``_bounded_descendant_json_paths``, ``_bounded_descendant_regular_paths``,
    ``generate_manifest``, and ``_generate_manifest_from_bound_root`` and
    retains the state those operations share between calls. Resource ownership
    remains inside the instance until the matching close, exit, or cleanup
    operation completes.
    """

    def __init__(
        self,
        log_dir: Path,
        spa_dist_dir: Optional[Path] = None,
        *,
        finalization_receipt: Optional[FinalizationReceipt] = None,
        enforce_snapshot_consistency: bool = True,
        max_auxiliary_json_files: int = HARD_MAX_AUXILIARY_JSON_FILES,
    ):
        """
        Initialize a ``ManifestService`` instance.

        The initializer records ``_auxiliary_json_bytes``,
        ``_auxiliary_json_paths``, ``_bound_dut_directories``,
        ``_collector_catalog_by_id``, and ``_enforce_snapshot_consistency`` for
        later operations and establishes the instance invariants before any
        public method runs.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            spa_dist_dir: Optional filesystem location used as the spa dist dir
                for this operation.
            finalization_receipt: Optional finalization receipt; ``None``
                selects the function's default behavior.
            enforce_snapshot_consistency: Whether enforce snapshot consistency
                is enabled or required for this operation.
            max_auxiliary_json_files: Catalog-resolved file-count work budget.

        Raises:
            ValueError: If the selected count is outside the code-owned hard
                safety range.
        """
        if (
            isinstance(max_auxiliary_json_files, bool)
            or not isinstance(max_auxiliary_json_files, int)
            or not 1 <= max_auxiliary_json_files <= HARD_MAX_AUXILIARY_JSON_FILES
        ):
            raise ValueError("invalid auxiliary JSON file limit")
        self.log_dir = Path(log_dir)
        self.spa_dist_dir = spa_dist_dir
        self._finalization_receipt = finalization_receipt
        self._enforce_snapshot_consistency = enforce_snapshot_consistency
        self._collector_catalog_by_id: Dict[str, Dict[str, Any]] = {}
        self._terminal_snapshot_generation: Optional[str] = None
        self._terminal_dut_roster: Optional[Tuple[str, ...]] = None
        self._bound_dut_directories: Optional[Tuple[Path, ...]] = None
        self._snapshot_binding: Optional[TerminalSnapshotBinding] = None
        self._timing_cache: OrderedDict[str, Optional[Dict[str, Any]]] = OrderedDict()
        self._metadata_timing_cache: OrderedDict[str, Optional[Dict[str, Any]]] = (
            OrderedDict()
        )
        self._timing_cache_sizes: Dict[str, int] = {}
        self._metadata_timing_cache_sizes: Dict[str, int] = {}
        self._timing_cache_bytes = 0
        self._metadata_timing_cache_bytes = 0
        self._timing_sources: Dict[str, str] = {}
        self._timing_bindings: Dict[str, Dict[str, Any]] = {}
        self._auxiliary_json_paths: set[Path] = set()
        self._auxiliary_json_bytes = 0
        self._max_auxiliary_json_files = max_auxiliary_json_files

    def _read_auxiliary_json(
        self,
        path: Path,
        *,
        maximum_bytes: int = MAX_AUXILIARY_JSON_FILE_BYTES,
    ) -> Any:
        """
        Read one bounded JSON file under a run-wide aggregate budget.

        The implementation uses ``path`` and ``maximum_bytes`` to read one
        bounded JSON file under a run-wide aggregate budget. Parsing or I/O must
        finish before the validated representation is made available to the
        caller. It updates ``_auxiliary_json_bytes`` on the instance as part of
        that state transition. If the function cannot read one bounded JSON file
        under a run-wide aggregate budget, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            path: filesystem location used as the path for this operation.
            maximum_bytes: Upper bound enforced for bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            The validated ``document``.

        Raises:
            ValueError: If auxiliary JSON file limit exceeded; or auxiliary JSON
                aggregate byte limit exceeded.
        """

        normalized = Path(os.path.abspath(os.fspath(path)))
        raw = _read_regular_file_bounded(normalized, maximum_bytes)
        if normalized not in self._auxiliary_json_paths:
            if len(self._auxiliary_json_paths) >= self._max_auxiliary_json_files:
                raise ValueError("auxiliary JSON file limit exceeded")
            if self._auxiliary_json_bytes + len(raw) > MAX_AUXILIARY_JSON_TOTAL_BYTES:
                raise ValueError("auxiliary JSON aggregate byte limit exceeded")
            self._auxiliary_json_paths.add(normalized)
            self._auxiliary_json_bytes += len(raw)
        document = json.loads(raw.decode("utf-8"))
        _validate_bounded_json_shape(document)
        return document

    @staticmethod
    def _bounded_descendant_json_paths(
        root: Path,
        *,
        name_pattern: re.Pattern[str] | None = None,
        maximum_paths: int = HARD_MAX_AUXILIARY_JSON_FILES,
    ) -> List[Path]:
        """
        Enumerate regular JSON descendants without following directory links.

        The implementation uses ``root`` and ``name_pattern`` to enumerate
        regular JSON descendants without following directory links. If the
        function cannot enumerate regular JSON descendants without following
        directory links, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            root: filesystem location used as the root for this operation.
            name_pattern: Optional name pattern; ``None`` selects the function's
                default behavior.
            maximum_paths: Maximum regular JSON paths admitted by this scan.

        Returns:
            The bounded descendant JSON paths returned in operation-defined
            order.

        Raises:
            ValueError: If auxiliary metadata path limit exceeded; or auxiliary
                JSON path limit exceeded.
        """

        if root.is_symlink() or not root.is_dir():
            return []
        paths: List[Path] = []
        stack = [root]
        visited = 0
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    visited += 1
                    if visited > MAX_AUXILIARY_PATH_NODES:
                        raise ValueError("auxiliary metadata path limit exceeded")
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    elif (
                        entry.is_file(follow_symlinks=False)
                        and entry.name.endswith(".json")
                        and (
                            name_pattern is None
                            or name_pattern.search(entry.name) is not None
                        )
                    ):
                        paths.append(Path(entry.path))
                        if len(paths) > maximum_paths:
                            raise ValueError("auxiliary JSON path limit exceeded")
        return sorted(paths, key=lambda path: str(path).casefold())

    @staticmethod
    def _bounded_descendant_regular_paths(
        root: Path,
        *,
        suffixes: Optional[set[str]] = None,
        maximum_paths: int = HARD_MAX_AUXILIARY_JSON_FILES,
    ) -> List[Path]:
        """
        Enumerate regular descendants without following links or growing forever.

        The implementation uses ``root`` and ``suffixes`` to enumerate regular
        descendants without following links or growing forever. If the function
        cannot enumerate regular descendants without following links or growing
        forever, its exception reaches the caller instead of being converted
        into a successful result.

        Args:
            root: filesystem location used as the root for this operation.
            suffixes: Optional suffixes; ``None`` selects the function's default
                behavior.
            maximum_paths: Maximum regular paths admitted by this scan.

        Returns:
            The bounded descendant regular paths returned in operation-defined
            order.

        Raises:
            ValueError: If auxiliary metadata path limit exceeded; or auxiliary
                metadata file limit exceeded.
        """

        if root.is_symlink() or not root.is_dir():
            return []
        normalized_suffixes = (
            {suffix.casefold() for suffix in suffixes} if suffixes is not None else None
        )
        paths: List[Path] = []
        stack = [root]
        visited = 0
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    visited += 1
                    if visited > MAX_AUXILIARY_PATH_NODES:
                        raise ValueError("auxiliary metadata path limit exceeded")
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        path = Path(entry.path)
                        if (
                            normalized_suffixes is not None
                            and path.suffix.casefold() not in normalized_suffixes
                        ):
                            continue
                        paths.append(path)
                        if len(paths) > maximum_paths:
                            raise ValueError("auxiliary metadata file limit exceeded")
        return sorted(paths, key=lambda path: str(path).casefold())

    async def generate_manifest(self) -> Dict[str, Any]:
        """
        Build the complete manifest dict from the log directory.

        The implementation uses current instance state to build the complete
        manifest dict from the log directory. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        It updates ``_bound_dut_directories``, ``_snapshot_binding``,
        ``_terminal_dut_roster``, ``_terminal_snapshot_generation``, and
        ``log_dir`` on the instance as part of that state transition. Cleanup in
        the ``finally`` path runs for successful, failed, and cancelled
        execution.

        Returns:
            A mapping containing generate manifest.
        """
        if not self._enforce_snapshot_consistency:
            self._terminal_snapshot_generation = None
            self._terminal_dut_roster = None
            return await self._generate_manifest_from_bound_root()
        if self._finalization_receipt is not None:
            (
                self._terminal_snapshot_generation,
                self._terminal_dut_roster,
            ) = validate_consumable_finalization_receipt(self._finalization_receipt)
            original_log_dir = self.log_dir
            with TerminalSnapshotBinding(
                self.log_dir,
                self._terminal_dut_roster,
                expected_generation=self._terminal_snapshot_generation,
                expected_leaf_digests=(
                    self._finalization_receipt.snapshot_leaf_digests
                ),
            ) as binding:
                self.log_dir = binding.root_path
                self._bound_dut_directories = binding.dut_directories
                self._snapshot_binding = binding
                try:
                    return await self._generate_manifest_from_bound_root()
                finally:
                    self.log_dir = original_log_dir
                    self._bound_dut_directories = None
                    self._snapshot_binding = None

        # Explicitly receipt-less instances are offline/legacy readers.
        self._terminal_snapshot_generation = validate_committed_terminal_snapshot(
            self.log_dir,
            compatibility_version=RECEIPTLESS_SNAPSHOT_COMPATIBILITY_VERSION,
        )
        return await self._generate_manifest_from_bound_root()

    async def _generate_manifest_from_bound_root(self) -> Dict[str, Any]:
        """
        Build a manifest while current-run paths remain descriptor-bound.

        The implementation uses current instance state to build a manifest while
        current-run paths remain descriptor-bound. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. It updates ``_auxiliary_json_bytes``,
        ``_collector_catalog_by_id``, ``_metadata_timing_cache_bytes``, and
        ``_timing_cache_bytes`` on the instance as part of that state
        transition.

        Returns:
            The validated ``manifest``.
        """

        self._timing_cache.clear()
        self._metadata_timing_cache.clear()
        self._timing_cache_sizes.clear()
        self._metadata_timing_cache_sizes.clear()
        self._timing_cache_bytes = 0
        self._metadata_timing_cache_bytes = 0
        self._timing_sources.clear()
        self._timing_bindings.clear()
        self._auxiliary_json_paths.clear()
        self._auxiliary_json_bytes = 0

        collector_catalog = self._read_collector_catalog()
        self._collector_catalog_by_id = self._index_collector_catalog(collector_catalog)
        manifest: Dict[str, Any] = {
            "schema_version": "2.0",
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool_version": __version__,
            "tool_config": self._read_tool_config(),
            "duts": [],
            "collector_catalog": collector_catalog,
            "timing": {},
            "file_index": [],
            "errors": [],
            "preflight": {"per_dut": []},
            "dependency_check": {"per_dut": []},
            "extensions": {"per_dut": []},
            "collection_summary": {},
            "run_result": None,
            "openbmc_coredumps": {},
        }

        dut_dirs = self._find_dut_directories()
        logger.info("Found %d DUT directories in %s", len(dut_dirs), self.log_dir)

        for dut_dir in dut_dirs:
            dut_id = dut_dir.name
            try:
                dut = await self._process_dut(dut_dir)
                manifest["duts"].append(dut)
            except SnapshotConsistencyError:
                raise
            except Exception as e:
                logger.error("Failed to process DUT %s: %s", dut_id, e, exc_info=True)
                manifest["errors"].append(
                    {
                        "dut_id": dut_id,
                        "collector_id": "",
                        "collector_name": "",
                        "collector_group": "",
                        "message": f"Failed to process DUT directory: {e}",
                        "timestamp": None,
                    }
                )
                continue

            dut_files = self._build_file_index(dut_dir, dut_id)
            self._enrich_file_index(dut_files, dut)
            manifest["file_index"].extend(dut_files)

            dut_errors = self._extract_errors(dut_dir, dut_id)
            manifest["errors"].extend(dut_errors)

            preflight = self._read_preflight(dut_dir, dut_id)
            if preflight:
                manifest["preflight"]["per_dut"].append(preflight)

            dependency = self._read_dependency_check(dut_dir, dut_id)
            if dependency:
                manifest["dependency_check"]["per_dut"].append(dependency)

            extension_results = self._read_extension_results(dut_dir, dut_id)
            if extension_results:
                manifest["extensions"]["per_dut"].extend(extension_results)
                dut["extensions"] = extension_results

        manifest["timing"] = self._build_timing_data()
        run_result = self._read_run_result()
        if run_result is not None:
            run_result_document = run_result.to_dict()
            manifest["run_result"] = run_result_document
            if run_result.run_identity is not None:
                identity_document = run_result.run_identity.to_dict()
                manifest["run_identity"] = identity_document
                manifest["tool_version"] = run_result.run_identity.tool_version
                tool_config = manifest.get("tool_config")
                if not isinstance(tool_config, dict):
                    tool_config = {}
                    manifest["tool_config"] = tool_config
                tool_config["collection_level"] = run_result.run_identity.resolved_level
                tool_config["collection_profile"] = (
                    run_result.run_identity.resolved_profile
                )
        self._apply_explicit_selection_dut_statuses(
            manifest,
            self._read_run_outcome(),
        )
        manifest["collection_summary"] = self._compute_summary(manifest)
        coredump_service = OpenBMCCoreDumpManifestService(self.log_dir)

        def load_or_generate_coredump_handoff() -> Dict[str, Any]:
            """
            Read the existing handoff or scan the bounded report file index.

            The complete blocking decision stays on one worker so the existing
            artifact cannot change between the read attempt and the fallback
            scan. The service's finite archive and record budgets remain
            authoritative for generated data.

            Returns:
                The validated existing or newly generated handoff document.
            """

            return coredump_service.read_existing() or coredump_service.generate(
                manifest["file_index"]
            )

        try:
            manifest["openbmc_coredumps"] = await run_managed_filesystem_operation(
                load_or_generate_coredump_handoff
            )
        except Exception as exc:
            # Optional metadata enrichment must never prevent report/archive
            # creation or affect the status of already-collected artifacts.
            logger.warning(
                "OpenBMC core-dump handoff discovery unavailable; collected "
                "artifacts remain unchanged: %s",
                exc,
                exc_info=True,
            )
            manifest["openbmc_coredumps"] = coredump_service.unavailable_payload(
                f"{type(exc).__name__}: {exc}"
            )

        logger.info(
            "Manifest generated: %d DUTs, %d files, %d errors",
            len(manifest["duts"]),
            len(manifest["file_index"]),
            len(manifest["errors"]),
        )

        return manifest

    def _read_extension_results(
        self, dut_dir: Path, dut_id: str
    ) -> List[Dict[str, Any]]:
        """
        Read every versioned trusted-extension result without a fixed registry.

        The implementation uses ``dut_dir`` and ``dut_id`` to read every
        versioned trusted-extension result without a fixed registry. Parsing or
        I/O must finish before the validated representation is made available to
        the caller.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The extension results returned in operation-defined order.
        """

        results: List[Dict[str, Any]] = []
        for metadata_name in (".metadata", "metadata"):
            extension_dir = dut_dir / metadata_name / "extensions"
            if not extension_dir.is_dir() or extension_dir.is_symlink():
                continue
            try:
                extension_paths = []
                with os.scandir(extension_dir) as entries:
                    for entry in entries:
                        if not entry.name.endswith(".json") or not entry.is_file(
                            follow_symlinks=False
                        ):
                            continue
                        if len(extension_paths) >= self._max_auxiliary_json_files:
                            logger.warning(
                                "Extension result file limit reached for %s", dut_id
                            )
                            break
                        extension_paths.append(Path(entry.path))
                extension_paths.sort(key=lambda path: path.name.casefold())
            except OSError:
                extension_paths = []
            for path in extension_paths:
                namespace = path.stem
                invalid_reason: Optional[str] = None
                payload: Any = None
                if path.is_symlink() or not path.is_file():
                    invalid_reason = "extension result is not a regular file"
                else:
                    try:
                        payload = self._read_auxiliary_json(path)
                    except (
                        OSError,
                        UnicodeError,
                        ValueError,
                        json.JSONDecodeError,
                        RecursionError,
                    ):
                        invalid_reason = "extension result is unreadable or malformed"
                if isinstance(payload, dict):
                    declared_namespace = payload.get("namespace")
                    declared_dut = payload.get("dut_id")
                    if declared_namespace != namespace:
                        invalid_reason = "extension namespace does not match its file"
                    elif declared_dut != dut_id:
                        invalid_reason = "extension DUT does not match its directory"
                    elif not all(
                        isinstance(payload.get(key), str) and payload[key].strip()
                        for key in ("schema_version", "phase", "outcome")
                    ):
                        invalid_reason = "extension result is missing required fields"
                    elif not all(
                        isinstance(payload.get(key), list)
                        for key in ("capabilities", "errors", "warnings")
                    ):
                        invalid_reason = "extension result has invalid list fields"
                    else:
                        results.append(payload)
                        continue
                elif invalid_reason is None:
                    invalid_reason = "extension result must be a JSON object"
                logger.warning(
                    "Failed to read extension result %s for %s: %s",
                    namespace,
                    dut_id,
                    invalid_reason,
                )
                results.append(
                    {
                        "schema_version": "1.0",
                        "namespace": namespace,
                        "dut_id": dut_id,
                        "phase": "manifest",
                        "outcome": "failed",
                        "capabilities": [],
                        "warnings": [],
                        "errors": [
                            {
                                "code": "invalid_extension_result",
                                "message": invalid_reason,
                            }
                        ],
                    }
                )
            if results:
                break
        if results:
            return results
        return list(legacy_extension_results(dut_dir, dut_id))

    async def generate_report(self, report_dir: Path) -> Path:
        """
        Generate manifest and create the report directory with SPA assets.

        Assets, standalone JSON, and the offline fallback are one publication
        generation. The lock begins before staging because source-mode staging
        can reuse the currently published index. A concurrent refresher must
        therefore observe either complete generation, never stale inputs
        followed by a newer overwrite.

        Args:
            report_dir: filesystem location used as the report dir for this
                operation.

        Returns:
            The validated generate report filesystem path.
        """
        report_dir = Path(report_dir)
        report_dir.parent.mkdir(parents=True, exist_ok=True)

        manifest = await self.generate_manifest()

        # Assets, standalone JSON, and the offline fallback are one publication
        # generation. The lock begins before staging because source-mode staging
        # can reuse the currently published index. A concurrent refresher must
        # therefore observe either complete generation, never stale inputs
        # followed by a newer overwrite.
        report_dir.mkdir(parents=True, exist_ok=True)
        async with async_report_publication_lock(
            report_dir,
            on_wait=_log_report_publication_wait,
        ) as publication_lock:
            pinned_report_dir = publication_lock.pinned_path
            pinned_parent_dir = publication_lock.pinned_parent_path
            staged_root: Optional[Path] = None
            try:
                staged_root = await self._stage_report_tree_owned(
                    pinned_report_dir,
                    manifest,
                    staging_parent=pinned_parent_dir,
                    report_name=report_dir.name,
                )
            except BaseException:
                if staged_root is not None:
                    self._cleanup_report_tree(staged_root)
                raise

            try:
                self._publish_report_tree(
                    staged_root,
                    pinned_report_dir,
                    publication_lock,
                    backup_parent=pinned_parent_dir,
                    report_name=report_dir.name,
                )
            finally:
                self._cleanup_report_tree(staged_root)

            # Persist the canonical handoff under the collection's hidden
            # metadata directory before releasing this generation's lock. The
            # SPA uses the embedded copy in reports/manifest.json; serializing
            # this side effect prevents an older concurrent producer from
            # overwriting the handoff after a newer report is published.
            try:
                handoff_root = (
                    pinned_parent_dir
                    if self.log_dir.absolute() == report_dir.parent.absolute()
                    else self.log_dir
                )
                OpenBMCCoreDumpManifestService(handoff_root).write(
                    payload=manifest["openbmc_coredumps"]
                )
            except Exception as exc:
                # reports/manifest.json still carries the handoff. Failure to
                # write the canonical metadata file must not discard the report
                # or cores.
                logger.warning(
                    "Unable to write OpenBMC core-dump handoff metadata: %s",
                    exc,
                    exc_info=True,
                )
            publication_lock.require_current()

        manifest_path = report_dir / "manifest.json"
        index_html = report_dir / "index.html"

        return index_html if index_html.exists() else manifest_path

    async def _stage_report_tree_owned(
        self,
        report_dir: Path,
        manifest: Dict[str, Any],
        *,
        staging_parent: Optional[Path] = None,
        report_name: Optional[str] = None,
    ) -> Path:
        """
        Own a private complete report generation through cancellation.

        A second cancellation may interrupt the bounded grace period. Install
        the worker-owned cleanup before awaiting anything so the private
        generation is still reclaimed in that case.

        Args:
            report_dir: filesystem location used as the report dir for this
                operation.
            manifest: Mapping supplying fields for own a private complete report
                generation through cancellation.
            staging_parent: Optional filesystem location used as the staging
                parent for this operation.
            report_name: Stable report name used for lookup and operator-facing
                diagnostics.

        Returns:
            The validated stage report tree owned filesystem path.
        """
        executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="nvdebug-report-stage"
        )
        concurrent_future = executor.submit(
            self._stage_report_tree,
            report_dir,
            manifest,
            staging_parent=staging_parent,
            report_name=report_name,
        )
        future = asyncio.wrap_future(concurrent_future)
        cleanup_deferred = False
        try:
            return await _await_executor_future(future)
        except asyncio.CancelledError:
            # A second cancellation may interrupt the bounded grace period.
            # Install the worker-owned cleanup before awaiting anything so the
            # private generation is still reclaimed in that case.
            cleanup_deferred = True
            cleanup_complete = threading.Event()
            future.cancel()

            def cleanup_after_worker(completed: Any) -> None:
                """
                Clean up after worker.

                The implementation uses ``completed`` to clean up after worker.
                Cleanup in the ``finally`` path runs for successful, failed, and
                cancelled execution.

                Args:
                    completed: Completed object whose ``result`` state is read
                        while performing clean up after worker.
                """
                try:
                    staged_root = completed.result()
                except BaseException:
                    pass
                else:
                    self._cleanup_report_tree(staged_root)
                finally:
                    executor.shutdown(wait=False, cancel_futures=True)
                    cleanup_complete.set()

            concurrent_future.add_done_callback(cleanup_after_worker)
            loop = asyncio.get_running_loop()
            deadline = loop.time() + REPORT_STAGE_CANCELLATION_GRACE_SECONDS
            while not cleanup_complete.is_set() and loop.time() < deadline:
                heartbeat = loop.create_future()
                timer = loop.call_later(0.01, _finish_worker_heartbeat, heartbeat)
                try:
                    await heartbeat
                finally:
                    timer.cancel()
            raise
        finally:
            if not cleanup_deferred:
                executor.shutdown(wait=False, cancel_futures=True)

    def _stage_report_tree(
        self,
        report_dir: Path,
        manifest: Dict[str, Any],
        *,
        staging_parent: Optional[Path] = None,
        report_name: Optional[str] = None,
    ) -> Path:
        """
        Build a private tree containing every owned report file.

        The implementation uses ``report_dir``, ``manifest``,
        ``staging_parent``, and ``report_name`` to build a private tree
        containing every owned report file. Filesystem effects remain confined
        to the caller-selected paths and the owning resource lifecycle.

        Args:
            report_dir: filesystem location used as the report dir for this
                operation.
            manifest: Mapping supplying fields for private tree containing every
                owned report file.
            staging_parent: Optional filesystem location used as the staging
                parent for this operation.
            report_name: Stable report name used for lookup and operator-facing
                diagnostics.

        Returns:
            The validated ``stage_root``.
        """
        stage_parent = staging_parent or report_dir.parent
        stage_prefix = report_name or report_dir.name
        stage_root = stage_parent / (
            f".{stage_prefix}.nvdebug-stage-{uuid.uuid4().hex}"
        )
        stage_root.mkdir(mode=0o700)
        try:
            if self.spa_dist_dir and self.spa_dist_dir.exists():
                self._copy_spa_assets(stage_root)
            else:
                existing_index = report_dir / "index.html"
                if existing_index.exists():
                    raw_index = _read_regular_file_bounded(
                        existing_index, MAX_MANIFEST_DOCUMENT_BYTES
                    )
                    (stage_root / "index.html").write_bytes(raw_index)
            staged_manifest, staged_index = self._stage_report_documents(
                stage_root, manifest
            )
            os.replace(staged_manifest, stage_root / "manifest.json")
            if staged_index is not None:
                os.replace(staged_index, stage_root / "index.html")
            return stage_root
        except BaseException:
            self._cleanup_report_tree(stage_root)
            raise

    @staticmethod
    def _cleanup_report_tree(stage_root: Path) -> None:
        """
        Remove one exact private generation path.

        The implementation uses ``stage_root`` to remove one exact private
        generation path.

        Args:
            stage_root: filesystem location used as the stage root for this
                operation.
        """
        try:
            shutil.rmtree(stage_root)
        except FileNotFoundError:
            pass
        except OSError:
            logger.warning("Unable to remove private report staging tree")

    @staticmethod
    def _publish_report_tree(
        stage_root: Path,
        report_dir: Path,
        publication_lock: PinnedDirectoryLock,
        *,
        backup_parent: Optional[Path] = None,
        report_name: Optional[str] = None,
    ) -> None:
        """
        Commit owned files with rollback while preserving unrelated files.

        The implementation uses ``stage_root``, ``report_dir``,
        ``publication_lock``, ``backup_parent``, and ``report_name`` to commit
        owned files with rollback while preserving unrelated files. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle. If the function cannot commit owned files with
        rollback while preserving unrelated files, its exception reaches the
        caller instead of being converted into a successful result. Cleanup in
        the ``finally`` path runs for successful, failed, and cancelled
        execution.

        Args:
            stage_root: filesystem location used as the stage root for this
                operation.
            report_dir: filesystem location used as the report dir for this
                operation.
            publication_lock: Publication lock object whose
                ``duplicate_descriptor``, ``duplicate_parent_descriptor``, and
                ``require_current`` state is read while performing commit owned
                files with rollback while preserving unrelated files.
            backup_parent: Optional filesystem location used as the backup
                parent for this operation.
            report_name: Stable report name used for lookup and operator-facing
                diagnostics.

        Raises:
            OSError: If staged report contains a non-regular entry; staged
                report source is not a regular file; report destination is not a
                regular file; or report backup identity changed; or another
                input invariant is violated.
            RuntimeError: If the function cannot commit owned files with
                rollback while preserving unrelated files safely.
        """
        publication_lock.require_current()
        backup_parent = backup_parent or report_dir.parent
        backup_prefix = report_name or report_dir.name
        backup_name = f".{backup_prefix}.nvdebug-backup-{uuid.uuid4().hex}"
        backup_root = backup_parent / backup_name
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        report_descriptor = -1
        parent_descriptor = -1
        stage_descriptor = -1
        backup_descriptor = -1
        report_directories: Dict[Path, int] = {}
        stage_directories: Dict[Path, int] = {}
        backup_directories: Dict[Path, int] = {}
        published: List[Path] = []
        backed_up: Dict[Path, os.stat_result] = {}
        created_directories: List[Tuple[Path, Tuple[int, int]]] = []
        remove_backup = True

        def open_directory(
            cache: Dict[Path, int],
            root_descriptor: int,
            relative: Path,
            *,
            create: bool = False,
            record_created: bool = False,
        ) -> int:
            """
            Open directory.

            The implementation uses ``cache``, ``root_descriptor``,
            ``relative``, ``create``, and ``record_created`` to open directory.
            If the function cannot open directory, its exception reaches the
            caller instead of being converted into a successful result. Cleanup
            in the ``finally`` path runs for successful, failed, and cancelled
            execution.

            Args:
                cache: filesystem location used as the cache for this operation.
                root_descriptor: Numeric root descriptor used while the
                    operation performs bounded accounting.
                relative: filesystem location used as the relative for this
                    operation.
                create: Whether create is enabled or required for this
                    operation.
                record_created: Whether record created is enabled or required
                    for this operation.

            Returns:
                The numeric open directory value.

            Raises:
                OSError: If report publication path is not a safe relative path.
            """
            relative = Path(*relative.parts)
            if relative.is_absolute() or any(
                part in {"", ".", ".."} for part in relative.parts
            ):
                raise OSError("report publication path is not a safe relative path")
            if relative in cache:
                return cache[relative]

            descriptor = os.dup(root_descriptor)
            walked = Path()
            try:
                for component in relative.parts:
                    walked /= component
                    cached = cache.get(walked)
                    if cached is not None:
                        os.close(descriptor)
                        descriptor = os.dup(cached)
                        continue
                    try:
                        child = os.open(
                            component,
                            directory_flags,
                            dir_fd=descriptor,
                        )
                    except FileNotFoundError:
                        if not create:
                            raise
                        os.mkdir(component, mode=0o755, dir_fd=descriptor)
                        created_metadata = os.stat(
                            component,
                            dir_fd=descriptor,
                            follow_symlinks=False,
                        )
                        if record_created:
                            created_directories.append(
                                (
                                    walked,
                                    (
                                        created_metadata.st_dev,
                                        created_metadata.st_ino,
                                    ),
                                )
                            )
                        child = os.open(
                            component,
                            directory_flags,
                            dir_fd=descriptor,
                        )
                    os.close(descriptor)
                    descriptor = child
                    cache[walked] = os.dup(descriptor)
                cache[relative] = os.dup(descriptor)
                return cache[relative]
            finally:
                os.close(descriptor)

        def require_directory_current(relative: Path, expected: int) -> None:
            """
            Require directory current.

            The implementation uses ``relative`` and ``expected`` to require
            directory current. Every required invariant is checked before a
            successful value is returned; invalid input follows the function's
            explicit exception path. Cleanup in the ``finally`` path runs for
            successful, failed, and cancelled execution.

            Args:
                relative: filesystem location used as the relative for this
                    operation.
                expected: Numeric expected used while the operation performs
                    bounded accounting.

            Raises:
                OSError: If report destination directory changed.
            """
            observed_cache: Dict[Path, int] = {}
            try:
                try:
                    observed = open_directory(
                        observed_cache,
                        report_descriptor,
                        relative,
                    )
                except OSError:
                    raise OSError("report destination directory changed") from None
                expected_metadata = os.fstat(expected)
                observed_metadata = os.fstat(observed)
                if (
                    not stat.S_ISDIR(expected_metadata.st_mode)
                    or not stat.S_ISDIR(observed_metadata.st_mode)
                    or expected_metadata.st_dev != observed_metadata.st_dev
                    or expected_metadata.st_ino != observed_metadata.st_ino
                ):
                    raise OSError("report destination directory changed")
            finally:
                for descriptor in set(observed_cache.values()):
                    os.close(descriptor)

        def original_identity_is_restored(
            relative: Path, original: os.stat_result
        ) -> bool:
            """
            Return the original identity is restored.

            The implementation uses ``relative`` and ``original`` to produce the
            original identity is restored. Filesystem effects remain confined to
            the caller-selected paths and the owning resource lifecycle.

            Args:
                relative: filesystem location used as the relative for this
                    operation.
                original: Original consumed while the function attempts to
                    produce the original identity is restored.

            Returns:
                Whether the original identity is restored operation succeeds.
            """
            try:
                destination_parent = open_directory(
                    report_directories,
                    report_descriptor,
                    relative.parent,
                )
                observed = os.stat(
                    relative.name,
                    dir_fd=destination_parent,
                    follow_symlinks=False,
                )
            except OSError:
                return False
            return regular_file_identity_matches(observed, original)

        def regular_file_identity_matches(
            observed: os.stat_result,
            expected: os.stat_result,
        ) -> bool:
            """
            Return the regular file identity matches.

            The implementation uses ``observed`` and ``expected`` to produce the
            regular file identity matches.

            Args:
                observed: Observed object whose ``st_dev``, ``st_ino``,
                    ``st_mode``, ``st_mtime_ns``, and ``st_size`` state is read
                    while performing regular file identity matches.
                expected: Expected object whose ``st_dev``, ``st_ino``,
                    ``st_mode``, ``st_mtime_ns``, and ``st_size`` state is read
                    while performing regular file identity matches.

            Returns:
                Whether the regular file identity matches operation succeeds.
            """
            return (
                stat.S_ISREG(observed.st_mode)
                and observed.st_dev == expected.st_dev
                and observed.st_ino == expected.st_ino
                and observed.st_mode == expected.st_mode
                and observed.st_size == expected.st_size
                and observed.st_mtime_ns == expected.st_mtime_ns
            )

        def backup_identity_is_recoverable(
            relative: Path,
            original: os.stat_result,
        ) -> bool:
            """
            Return the backup identity is recoverable.

            The implementation uses ``relative`` and ``original`` to produce the
            backup identity is recoverable. Filesystem effects remain confined
            to the caller-selected paths and the owning resource lifecycle.

            Args:
                relative: filesystem location used as the relative for this
                    operation.
                original: Original consumed while the function attempts to
                    produce the backup identity is recoverable.

            Returns:
                Whether the backup identity is recoverable operation succeeds.
            """
            try:
                backup_file_parent = open_directory(
                    backup_directories,
                    backup_descriptor,
                    relative.parent,
                )
                observed = os.stat(
                    relative.name,
                    dir_fd=backup_file_parent,
                    follow_symlinks=False,
                )
            except OSError:
                return False
            return regular_file_identity_matches(observed, original)

        try:
            report_descriptor = publication_lock.duplicate_descriptor()
            parent_descriptor = publication_lock.duplicate_parent_descriptor()
            report_directories[Path()] = os.dup(report_descriptor)
            os.mkdir(backup_name, mode=0o700, dir_fd=parent_descriptor)
            backup_descriptor = os.open(
                backup_name,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            stage_descriptor = os.open(
                stage_root.name,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            stage_directories[Path()] = os.dup(stage_descriptor)
            backup_directories[Path()] = os.dup(backup_descriptor)

            staged_files: List[Path] = []
            for relative in sorted(
                (path.relative_to(stage_root) for path in stage_root.rglob("*")),
                key=Path.as_posix,
            ):
                source_parent = open_directory(
                    stage_directories,
                    stage_descriptor,
                    relative.parent,
                )
                source_metadata = os.stat(
                    relative.name,
                    dir_fd=source_parent,
                    follow_symlinks=False,
                )
                if stat.S_ISREG(source_metadata.st_mode):
                    staged_files.append(relative)
                elif not stat.S_ISDIR(source_metadata.st_mode):
                    raise OSError("staged report contains a non-regular entry")
            for relative in staged_files:
                publication_lock.require_current()
                source_parent = open_directory(
                    stage_directories,
                    stage_descriptor,
                    relative.parent,
                )
                source_metadata = os.stat(
                    relative.name,
                    dir_fd=source_parent,
                    follow_symlinks=False,
                )
                if not stat.S_ISREG(source_metadata.st_mode):
                    raise OSError("staged report source is not a regular file")
                destination_parent = open_directory(
                    report_directories,
                    report_descriptor,
                    relative.parent,
                    create=True,
                    record_created=True,
                )
                require_directory_current(relative.parent, destination_parent)
                try:
                    metadata = os.stat(
                        relative.name,
                        dir_fd=destination_parent,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    metadata = None
                if metadata is not None:
                    if not stat.S_ISREG(metadata.st_mode):
                        raise OSError("report destination is not a regular file")
                    backup_file_parent = open_directory(
                        backup_directories,
                        backup_descriptor,
                        relative.parent,
                        create=True,
                    )
                    # Register the original before the syscall so an error
                    # reported after an effective rename still enters the
                    # identity-checked restore path.
                    backed_up[relative] = metadata
                    os.replace(
                        relative.name,
                        relative.name,
                        src_dir_fd=destination_parent,
                        dst_dir_fd=backup_file_parent,
                    )
                    if not backup_identity_is_recoverable(relative, metadata):
                        raise OSError("report backup identity changed")
                    publication_lock.require_current()
                    require_directory_current(relative.parent, destination_parent)
                os.replace(
                    relative.name,
                    relative.name,
                    src_dir_fd=source_parent,
                    dst_dir_fd=destination_parent,
                )
                published.append(relative)
                publication_lock.require_current()
                require_directory_current(relative.parent, destination_parent)
            publication_lock.require_current()
        except BaseException as publication_error:
            unresolved_restores: List[Tuple[Path, Path, BaseException]] = []
            residual_new_only: List[Tuple[str, Path, BaseException]] = []
            resolved_transient_cleanup: List[Tuple[str, Path, BaseException]] = []

            # A backup restore atomically replaces the staged generation. Do not
            # unlink those destinations first: the backup remains the recovery
            # source until the exact original identity is back in place.
            for relative, original in reversed(backed_up.items()):
                destination = report_dir / relative
                backup = backup_root / relative
                try:
                    destination_parent = open_directory(
                        report_directories,
                        report_descriptor,
                        relative.parent,
                    )
                    backup_file_parent = open_directory(
                        backup_directories,
                        backup_descriptor,
                        relative.parent,
                    )
                    if not backup_identity_is_recoverable(relative, original):
                        raise OSError("report backup identity changed")
                    os.replace(
                        relative.name,
                        relative.name,
                        src_dir_fd=backup_file_parent,
                        dst_dir_fd=destination_parent,
                    )
                except OSError as error:
                    if original_identity_is_restored(relative, original):
                        resolved_transient_cleanup.append(
                            ("restore", destination, error)
                        )
                    else:
                        unresolved_restores.append((destination, backup, error))
                else:
                    if not original_identity_is_restored(relative, original):
                        unresolved_restores.append(
                            (
                                destination,
                                backup,
                                OSError(
                                    "restored report destination identity did not "
                                    "match its backup"
                                ),
                            )
                        )

            backed_destinations = set(backed_up)
            for relative in reversed(published):
                if relative in backed_destinations:
                    continue
                destination = report_dir / relative
                destination_parent: Optional[int] = None
                try:
                    destination_parent = open_directory(
                        report_directories,
                        report_descriptor,
                        relative.parent,
                    )
                    os.unlink(relative.name, dir_fd=destination_parent)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    if destination_parent is None:
                        residual_new_only.append(("remove", destination, error))
                        continue
                    try:
                        os.stat(
                            relative.name,
                            dir_fd=destination_parent,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        resolved_transient_cleanup.append(
                            ("remove", destination, error)
                        )
                    else:
                        residual_new_only.append(("remove", destination, error))
                else:
                    try:
                        os.stat(
                            relative.name,
                            dir_fd=destination_parent,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        residual_new_only.append(
                            (
                                "remove",
                                destination,
                                OSError("new report destination remains after removal"),
                            )
                        )
            for relative, expected_identity in reversed(created_directories):
                directory = report_dir / relative
                parent: Optional[int] = None
                try:
                    parent = open_directory(
                        report_directories,
                        report_descriptor,
                        relative.parent,
                    )
                    observed = os.stat(
                        relative.name,
                        dir_fd=parent,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISDIR(observed.st_mode)
                        or (observed.st_dev, observed.st_ino) != expected_identity
                    ):
                        raise OSError("new report directory identity changed")
                    os.rmdir(relative.name, dir_fd=parent)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    if parent is None:
                        residual_new_only.append(("remove_directory", directory, error))
                        continue
                    try:
                        os.stat(
                            relative.name,
                            dir_fd=parent,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        resolved_transient_cleanup.append(
                            ("remove_directory", directory, error)
                        )
                    else:
                        residual_new_only.append(("remove_directory", directory, error))
                else:
                    try:
                        os.stat(
                            relative.name,
                            dir_fd=parent,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        residual_new_only.append(
                            (
                                "remove_directory",
                                directory,
                                OSError("new report directory remains after removal"),
                            )
                        )

            if resolved_transient_cleanup:
                logger.debug(
                    "Report rollback resolved %d transient cleanup failures",
                    len(resolved_transient_cleanup),
                )

            backup_has_recovery_files = any(
                backup_identity_is_recoverable(relative, original)
                for relative, original in backed_up.items()
            )
            if unresolved_restores or residual_new_only:
                # Retain the backup root only when it still contains an exact
                # recoverable prior-generation file. Residual new-only paths are
                # a separate incomplete-cleanup class and must not manufacture a
                # false recoverable-backup claim.
                remove_backup = not backup_has_recovery_files
                failure_kinds = [
                    f"restore:{destination.relative_to(report_dir)}"
                    for destination, _backup, _error in unresolved_restores
                ]
                failure_kinds.extend(
                    f"{operation}:{path.relative_to(report_dir)}"
                    for operation, path, _error in residual_new_only
                )
                recovery = (
                    "; recoverable backups remain in the report parent"
                    if backup_has_recovery_files
                    else "; no recoverable backup remains"
                )
                raise RuntimeError(
                    "Report publication failed and rollback was incomplete"
                    f"{recovery} ({', '.join(failure_kinds)})"
                ) from publication_error
            raise
        finally:
            if remove_backup:
                shutil.rmtree(backup_root, ignore_errors=True)
            for cache in (
                report_directories,
                stage_directories,
                backup_directories,
            ):
                for descriptor in set(cache.values()):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            for descriptor in (
                stage_descriptor,
                backup_descriptor,
                report_descriptor,
                parent_descriptor,
            ):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    @staticmethod
    def _manifest_insertion_parts(html: str) -> Tuple[str, str]:
        """
        Split a clean SPA bundle around the manifest insertion point.

        The implementation uses ``html`` to split a clean SPA bundle around the
        manifest insertion point. If the function cannot split a clean SPA
        bundle around the manifest insertion point, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            html: Text supplied as HTML in the format accepted by this function.

        Returns:
            A tuple containing the HTML before the insertion point and the HTML
            after it, with the insertion marker itself removed.

        Raises:
            ValueError: If could not embed manifest: no placeholder or
                </head>/</body> found.
        """
        # A report regenerated without a configured SPA distribution reuses
        # its already-published index as the bundle source. Remove every prior
        # owned fallback first so the new standalone manifest and file:// copy
        # remain one generation instead of accumulating stale script elements.
        html = _strip_owned_manifest_fallbacks(html)
        if MANIFEST_PLACEHOLDER in html:
            prefix, suffix = html.split(MANIFEST_PLACEHOLDER, 1)
            return prefix, suffix
        for marker in ("</head>", "</body>"):
            marker_index = html.find(marker)
            if marker_index >= 0:
                return html[:marker_index], html[marker_index:]
        raise ValueError(
            "Could not embed manifest: no placeholder or </head>/</body> found"
        )

    @staticmethod
    def _inline_manifest_opening_tag(
        uncompressed_bytes: int, compressed_bytes: int
    ) -> str:
        """
        Return the inline manifest opening tag.

        The implementation uses ``uncompressed_bytes`` and ``compressed_bytes``
        to produce the inline manifest opening tag.

        Args:
            uncompressed_bytes: Numeric uncompressed bytes used while the
                operation performs bounded accounting.
            compressed_bytes: Numeric compressed bytes used while the operation
                performs bounded accounting.

        Returns:
            The canonical inline manifest opening tag text.
        """
        return (
            f'<script id="{INLINE_MANIFEST_ELEMENT_ID}" '
            'type="application/octet-stream" data-encoding="gzip+base64" '
            f'data-uncompressed-bytes="{uncompressed_bytes}" '
            f'data-compressed-bytes="{compressed_bytes}">'
        )

    def _stage_report_documents(
        self,
        report_dir: Path,
        manifest: Dict[str, Any],
    ) -> Tuple[Path, Optional[Path]]:
        """
        Stage standalone JSON and a compressed file:// fallback atomically.

        The implementation uses ``report_dir`` and ``manifest`` to stage
        standalone JSON and a compressed file:// fallback atomically. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle. If the function cannot stage standalone JSON and a
        compressed file:// fallback atomically, its exception reaches the caller
        instead of being converted into a successful result. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            report_dir: filesystem location used as the report dir for this
                operation.
            manifest: Mapping supplying fields for stage standalone JSON and a
                compressed file:// fallback atomically.

        Returns:
            A tuple containing ``manifest temp`` and ``staged index`` in that
            order.

        Raises:
            ValueError: If report manifest exceeds the 128 MiB safety limit.
        """
        token = uuid.uuid4().hex
        manifest_temp = report_dir / f".manifest.json.{token}.tmp"
        compressed_temp = report_dir / f".manifest.json.{token}.gz.tmp"
        index_path = report_dir / "index.html"
        index_temp = report_dir / f".index.html.{token}.tmp"
        staged_index: Optional[Path] = None
        try:
            with manifest_temp.open("x", encoding="utf-8", newline="\n") as output:
                encoder = json.JSONEncoder(
                    indent=2,
                    default=str,
                    allow_nan=False,
                )
                manifest_bytes = 0
                for chunk in encoder.iterencode(manifest):
                    chunk_bytes = len(chunk.encode("utf-8"))
                    if manifest_bytes + chunk_bytes > MAX_MANIFEST_DOCUMENT_BYTES:
                        raise ValueError(
                            "Report manifest exceeds the 128 MiB safety limit"
                        )
                    output.write(chunk)
                    manifest_bytes += chunk_bytes
                if manifest_bytes + 1 > MAX_MANIFEST_DOCUMENT_BYTES:
                    raise ValueError("Report manifest exceeds the 128 MiB safety limit")
                output.write("\n")
                manifest_bytes += 1
                output.flush()
                os.fsync(output.fileno())

            with manifest_temp.open("rb") as source, compressed_temp.open("xb") as raw:
                bounded_raw = _BoundedBinarySink(raw, MAX_COMPRESSED_MANIFEST_BYTES)
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    fileobj=bounded_raw,
                    mtime=0,
                ) as compressed:
                    shutil.copyfileobj(source, compressed, length=1024 * 1024)
                raw.flush()
                os.fsync(raw.fileno())

            if index_path.exists():
                bundle_html = _read_regular_file_bounded(
                    index_path, MAX_REPORT_INDEX_BYTES
                ).decode("utf-8")
                prefix, suffix = self._manifest_insertion_parts(bundle_html)
                uncompressed_size = manifest_bytes
                compressed_size = compressed_temp.stat().st_size
                with index_temp.open("x", encoding="utf-8", newline="\n") as output:
                    index_bytes = 0
                    index_limit = min(
                        MAX_REPORT_INDEX_BYTES,
                        MAX_REPORT_DOCUMENT_BYTES - manifest_bytes,
                    )

                    def write_index(value: str) -> None:
                        """
                        Write index.

                        The implementation uses ``value`` to write index.
                        Success is reported only after the owning output
                        boundary has completed its required write or publication
                        step. If the function cannot write index, its exception
                        reaches the caller instead of being converted into a
                        successful result.

                        Args:
                            value: Text supplied as value in the format accepted
                                by this function.

                        Raises:
                            ValueError: If offline report documents exceed their
                                aggregate limit.
                        """
                        nonlocal index_bytes
                        encoded_size = len(value.encode("utf-8"))
                        if index_bytes + encoded_size > index_limit:
                            raise ValueError(
                                "Offline report documents exceed their aggregate limit"
                            )
                        output.write(value)
                        index_bytes += encoded_size

                    write_index(prefix)
                    write_index(
                        self._inline_manifest_opening_tag(
                            uncompressed_size, compressed_size
                        )
                    )
                    with compressed_temp.open("rb") as compressed:
                        while True:
                            chunk = compressed.read(_BASE64_STREAM_CHUNK_BYTES)
                            if not chunk:
                                break
                            write_index(base64.b64encode(chunk).decode("ascii"))
                    write_index("</script>")
                    write_index(suffix)
                    output.flush()
                    os.fsync(output.fileno())
                staged_index = index_temp
            return manifest_temp, staged_index
        except BaseException:
            for path in (manifest_temp, compressed_temp, index_temp):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
        finally:
            try:
                compressed_temp.unlink(missing_ok=True)
            except OSError:
                pass

    def _find_dut_directories(self) -> List[Path]:
        """
        Find DUT directories.

        A DUT directory has either an execution summary or metadata.

        Returns:
            The DUT directories returned in operation-defined order.
        """
        if self._bound_dut_directories is not None:
            return list(self._bound_dut_directories)

        dut_dirs = []
        if not self.log_dir.exists():
            return dut_dirs

        for entry in sorted(self.log_dir.iterdir()):
            if not entry.is_dir():
                continue
            if entry.name.startswith(".") or entry.name == "reports":
                continue
            # A DUT directory has either an execution summary or metadata
            has_summary = (entry / "Execution_Summary_Report.txt").exists()
            has_metadata = (entry / ".metadata").is_dir() or (
                entry / "metadata"
            ).is_dir()
            if has_summary or has_metadata:
                dut_dirs.append(entry)

        return dut_dirs

    @staticmethod
    def _apply_explicit_selection_dut_statuses(
        manifest: Dict[str, Any],
        run_outcome: Dict[str, Any],
    ) -> None:
        """
        Mark DUTs affected by an explicit selection failure as errors.

        Collector status summaries remain unchanged because a collector blocked
        by preflight is truthfully skipped. The DUT-level outcome is nevertheless
        an error when the operator explicitly selected that work and the
        receipt-bound run outcome identifies the affected DUT.

        Args:
            manifest: In-progress report manifest whose DUT entries are updated
                in place.
            run_outcome: Canonically projected legacy outcome read from the
                terminal snapshot.

        Side Effects:
            Changes only ``overall_status`` on affected manifest DUT entries.
        """

        if not (
            isinstance(run_outcome, dict)
            and run_outcome.get("status") == "domain_failed"
            and run_outcome.get("failure_type") in EXPLICIT_SELECTION_FAILURE_TYPES
            and run_outcome.get("evidence") == EXPLICIT_SELECTION_EVIDENCE_PATH
        ):
            return
        affected = run_outcome.get("affected_duts")
        if not (
            isinstance(affected, list)
            and bool(affected)
            and all(type(dut_id) is str for dut_id in affected)
            and len(affected) == len(set(affected))
        ):
            return
        affected_duts = set(affected)
        duts = manifest.get("duts")
        if not isinstance(duts, list):
            return
        for dut in duts:
            if isinstance(dut, dict) and dut.get("id") in affected_duts:
                dut["overall_status"] = "error"

    async def _process_dut(self, dut_dir: Path) -> Dict[str, Any]:
        """
        Process a single DUT directory into a DUT manifest entry.

        Read collector groups from metadata and enrich collector entries with
        timing_data captured in .metadata/metadata.json.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            A mapping containing the ``id``, ``baseboard``, ``node_type``,
            ``bmc_ip``, and ``platform_identity`` fields.
        """
        dut_id = dut_dir.name
        metadata_dir = dut_dir / ".metadata"
        if not metadata_dir.exists():
            metadata_dir = dut_dir / "metadata"

        system_info = await run_managed_filesystem_operation(
            self._extract_system_info_from_snapshot, metadata_dir, dut_dir
        )

        # Read collector groups from metadata and enrich collector entries with
        # timing_data captured in .metadata/metadata.json.
        timing_lookup = self._build_collector_timing_lookup(dut_dir)
        collector_groups = self._build_collector_groups(
            metadata_dir, dut_dir, timing_lookup
        )

        # Compute status summary
        status_counts = {
            "success": 0,
            "error": 0,
            "degraded": 0,
            "partial": 0,
            "skipped": 0,
            "cancelled": 0,
            "not_ran": 0,
            "running": 0,
            "pending": 0,
        }
        for group in collector_groups:
            for collector in group.get("collectors", []):
                status = collector.get("status", "unknown")
                if status in status_counts:
                    status_counts[status] += 1

        tracker_status_counts = self._read_status_summary_from_tracker(
            metadata_dir,
            dut_id,
        )
        if tracker_status_counts is not None:
            status_counts = tracker_status_counts

        # Determine overall status
        if status_counts["error"] > 0:
            overall_status = "error"
        elif status_counts["partial"] > 0:
            overall_status = "partial"
        elif status_counts["cancelled"] > 0:
            overall_status = "interrupted"
        elif status_counts["running"] > 0 or status_counts["pending"] > 0:
            overall_status = "incomplete"
        elif status_counts["degraded"] > 0:
            overall_status = "degraded"
        elif status_counts["success"] > 0:
            overall_status = "success"
        elif status_counts["skipped"] > 0:
            overall_status = "skipped"
        else:
            overall_status = "unknown"

        # Read execution time from timing
        execution_time = self._get_dut_execution_time(metadata_dir, dut_dir)

        # Calculate log size
        log_size = self._calculate_dir_size(dut_dir)

        baseboard = self._get_baseboard(dut_dir)
        node_type = self._get_node_type(dut_dir)
        security_mode = self._read_security_mode(dut_dir)

        return {
            "id": dut_id,
            # Legacy top-level fields remain authoritative for existing report
            # consumers.  The additive object gives newer report
            # readers one stable platform-identity shape.
            "baseboard": baseboard,
            "node_type": node_type,
            "bmc_ip": self._get_bmc_ip(dut_dir),
            "platform_identity": {
                "baseboard": baseboard,
                "node_type": node_type,
                "model": system_info.get("model"),
                "part_number": system_info.get("part_number"),
                "serial_number": system_info.get("serial_number"),
            },
            "security_mode": security_mode,
            "collector_groups": collector_groups,
            "status_summary": status_counts,
            "filtered_out": self._read_filtered_out(metadata_dir, dut_id),
            "overall_status": overall_status,
            "execution_time": execution_time,
            "log_size": log_size,
            "system_info": system_info,
        }

    def _read_filtered_out(
        self, metadata_dir: Path, dut_id: Optional[str] = None
    ) -> int:
        """
        Read filtered out.

        The implementation uses ``metadata_dir`` and ``dut_id`` to read filtered
        out. Parsing or I/O must finish before the validated representation is
        made available to the caller.

        Args:
            metadata_dir: filesystem location used as the metadata dir for this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The numeric filtered out value.
        """
        try:
            if dut_id is None and metadata_dir.parent != self.log_dir:
                dut_id = metadata_dir.parent.name
            document = self._read_terminal_status(dut_id)
            if document is None:
                return 0
            meta = document.get("metadata", {})
            return int(
                meta.get(
                    "filtered_out",
                    meta.get("stats", {}).get("filtered_out", 0),
                )
            )
        except SnapshotArtifactFormatError:
            if self._terminal_snapshot_generation is not None:
                raise
            return 0
        except (json.JSONDecodeError, OSError, ValueError, TypeError):
            return 0

    def _read_status_summary_from_tracker(
        self,
        metadata_dir: Path,
        dut_id: Optional[str] = None,
    ) -> Optional[Dict[str, int]]:
        """
        Read per-DUT run status counts from collection_status.json.

        Service metadata can represent pre-execution filtered collectors as
        ``not_ran`` while the tracker keeps the actual run map. Prefer the
        tracker when present so manifest percentages match root metadata and do
        not double-count filtered collectors.

        Args:
            metadata_dir: filesystem location used as the metadata dir for this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``counts``, or ``None`` when no value qualifies.
        """
        try:
            if dut_id is None and metadata_dir.parent != self.log_dir:
                dut_id = metadata_dir.parent.name
            data = self._read_terminal_status(dut_id)
        except SnapshotArtifactFormatError:
            if self._terminal_snapshot_generation is not None:
                raise
            return None
        except (json.JSONDecodeError, OSError):
            return None
        if data is None:
            return None

        collectors = data.get("collectors", {}) if isinstance(data, dict) else {}
        if not isinstance(collectors, dict) or not collectors:
            return None

        counts = {
            "success": 0,
            "error": 0,
            "degraded": 0,
            "partial": 0,
            "skipped": 0,
            "cancelled": 0,
            "not_ran": 0,
            "running": 0,
            "pending": 0,
        }
        status_map = {
            "complete": "success",
            "completed": "success",
            "passed": "success",
            "pass": "success",
            "success": "success",
            "error": "error",
            "failed": "error",
            "fail": "error",
            "degraded": "degraded",
            "partial": "partial",
            "skipped": "skipped",
            "cancelled": "cancelled",
            "canceled": "cancelled",
            "not_ran": "not_ran",
            "notran": "not_ran",
            "running": "running",
            "pending": "pending",
        }

        for collector_data in collectors.values():
            if not isinstance(collector_data, dict):
                continue
            if self._is_preexecution_filtered_entry(collector_data):
                # Applicability/config exclusions are accounting metadata, not
                # collector outcomes.  They are represented by ``filtered_out``
                # and must not inflate any status bucket in the run report.
                continue
            raw_status = str(collector_data.get("status", "not_ran")).lower()
            status = status_map.get(raw_status, "not_ran")
            counts[status] += 1

        return counts

    def _read_terminal_status(
        self,
        dut_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Read status through the active receipt binding when present.

        The implementation uses ``dut_id`` to read status through the active
        receipt binding when present. Parsing or I/O must finish before the
        validated representation is made available to the caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing terminal status, or ``None`` when the requested
            value is unavailable.
        """

        if self._snapshot_binding is not None:
            return self._snapshot_binding.read_status(dut_id)
        return read_snapshot_status(
            self.log_dir,
            dut_id=dut_id,
            expected_generation=self._terminal_snapshot_generation,
            required=self._terminal_snapshot_generation is not None,
        )

    def _read_terminal_timing(self, dut_id: str) -> Optional[Dict[str, Any]]:
        """
        Read timing through the active receipt binding when present.

        The implementation uses ``dut_id`` to read timing through the active
        receipt binding when present. Parsing or I/O must finish before the
        validated representation is made available to the caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing terminal timing, or ``None`` when the requested
            value is unavailable.
        """

        if self._snapshot_binding is not None:
            return self._snapshot_binding.read_timing(dut_id)
        return read_snapshot_timing(
            self.log_dir,
            dut_id,
            expected_generation=self._terminal_snapshot_generation,
            required=self._terminal_snapshot_generation is not None,
        )

    @staticmethod
    def _is_preexecution_filtered_reason(reason: Any) -> bool:
        """
        Return whether ``reason`` is preexecution filtered reason.

        The implementation uses ``reason`` to determine whether ``reason`` is
        preexecution filtered reason.

        Args:
            reason: Reason object whose ``lower`` state is read while performing
                ``reason`` is preexecution filtered reason.

        Returns:
            Whether ``reason`` is preexecution filtered reason.
        """
        if not isinstance(reason, str) or not reason:
            return False
        reason_lower = reason.lower()

        # Canonical marker used by newer filtering paths.
        if "filtered out" in reason_lower and (
            "before execution" in reason_lower or "not executed" in reason_lower
        ):
            return True

        # Production baseboard filtering reasons predate the canonical marker.
        if "baseboardconstraint" in reason_lower:
            return True
        if (
            "not applicable" in reason_lower
            and "baseboard" in reason_lower
            and "tags:" in reason_lower
        ):
            return True

        # Live ActionInfo capability gating also occurs before collector
        # execution and therefore belongs in filtered-out accounting.
        if "skipped because" in reason_lower and (
            "system dump actioninfo capability data is unavailable" in reason_lower
            or (
                "live system dump actioninfo" in reason_lower
                and "does not advertise" in reason_lower
            )
        ):
            return True

        # Explicit include/exclude lists, service skip flags, and streaming-only
        # selection are configuration filters rather than runtime collector skips.
        config_markers = (
            " not in dut ",
            " in dut ",
            " in tool skip list",
            " in tool collector_to_skip list",
            "skipped due to skip_",
            "not a streaming candidate (--streaming-only mode)",
        )
        if reason_lower.startswith("collector ") and any(
            marker in reason_lower for marker in config_markers
        ):
            if any(
                token in reason_lower
                for token in (
                    "include list",
                    "skip list",
                    "collector_to_skip list",
                    "skipped due to skip_",
                    "streaming-only mode",
                )
            ):
                return True

        return False

    @classmethod
    def _is_preexecution_filtered_entry(cls, collector_data: Any) -> bool:
        """
        Prefer explicit exclusion metadata, with legacy reason fallback.

        The implementation uses ``collector_data`` to prefer explicit exclusion
        metadata, with legacy reason fallback.

        Args:
            collector_data: Collector data object whose ``get`` state is read
                while performing prefer explicit exclusion metadata, with legacy
                reason fallback.

        Returns:
            Whether the prefer explicit exclusion metadata, with legacy reason
            fallback operation succeeds.
        """
        if not isinstance(collector_data, dict):
            return False
        exclusion_type = collector_data.get("exclusion_type")
        if isinstance(exclusion_type, str) and exclusion_type.strip():
            return True
        return cls._is_preexecution_filtered_reason(collector_data.get("reason", ""))

    def _build_collector_groups(
        self,
        metadata_dir: Path,
        dut_dir: Path,
        timing_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[Dict]:
        """
        Build collector groups from metadata JSON files.

        Each service metadata file (redfish.json, host.json, etc.) contains
        collector results.

        Args:
            metadata_dir: filesystem location used as the metadata dir for this
                operation.
            dut_dir: filesystem location used as the DUT dir for this operation.
            timing_lookup: Optional timing lookup; ``None`` selects the
                function's default behavior.

        Returns:
            The collector groups returned in operation-defined order.
        """
        groups = []
        if not metadata_dir.exists():
            return groups
        timing_lookup = timing_lookup or {}

        # Each service metadata file (redfish.json, host.json, etc.) contains collector results
        service_files = {
            "redfish.json": "redfish",
            "host.json": "host",
            "ipmi.json": "ipmi",
            "ssh.json": "ssh",
            "bmc_ssh.json": "ssh",
            "health_check.json": "health_check",
            "healthcheck.json": "health_check",
        }

        for filename, service_type in service_files.items():
            meta_path = metadata_dir / filename
            if not meta_path.exists():
                continue

            try:
                meta = self._read_auxiliary_json(meta_path)
            except (
                json.JSONDecodeError,
                OSError,
                UnicodeError,
                ValueError,
                RecursionError,
            ):
                continue

            collectors = []
            if isinstance(meta, dict):
                # The metadata JSON has a "collectors" key containing the actual
                # collector results. Top-level keys like "metadata", "status_fields",
                # "summary" are not collectors.
                collector_dict = meta.get("collectors", {})
                if not isinstance(collector_dict, dict):
                    collector_dict = {}
                # Fallback: if no "collectors" key, check if top-level keys look
                # like collector IDs (e.g., "R1", "H2") — older format
                if not collector_dict:
                    for key, val in meta.items():
                        if (
                            isinstance(val, dict)
                            and key not in ("metadata", "status_fields", "summary")
                            and (
                                val.get("id")
                                or val.get("status")
                                or val.get("files")
                                or val.get("log_paths")
                            )
                        ):
                            collector_dict[key] = val
                for collector_id, collector_data in collector_dict.items():
                    if not isinstance(collector_data, dict):
                        continue
                    raw_status = str(collector_data.get("status", "")).lower()
                    if raw_status in ("not_ran", "notran"):
                        # Service metadata contains catalog placeholders for
                        # collectors that were not part of this run. They are
                        # not collector outcomes and must not create report rows.
                        continue
                    if self._is_preexecution_filtered_entry(collector_data):
                        # Keep the exclusion in collection_status.json for audit
                        # and filtered-out counts, but do not manufacture a
                        # collector row for work that was never attempted.
                        continue
                    collectors.append(
                        self._parse_collector(
                            collector_id, collector_data, dut_dir, service_type
                        )
                    )

            for collector in collectors:
                self._apply_timing_to_collector(
                    collector,
                    timing_lookup,
                    dut_dir.name,
                )
            total_time = sum(c.get("execution_time", 0) for c in collectors)

            if collectors:
                component_labels = sorted(
                    {
                        str(collector.get("component_label"))
                        for collector in collectors
                        if collector.get("component_label")
                    }
                )
                groups.append(
                    {
                        "name": service_type,
                        "service_type": service_type,
                        "access_path": self._canonical_access_path(service_type),
                        "component_labels": component_labels,
                        "collectors": collectors,
                        "total_execution_time": total_time,
                    }
                )

        return groups

    def _build_collector_timing_lookup(
        self, dut_dir: Path
    ) -> Dict[str, Dict[str, Any]]:
        """
        Build an uppercase collector-id to timing payload lookup.

        The implementation uses ``dut_dir`` to build an uppercase collector-id
        to timing payload lookup.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            The validated ``lookup``.
        """
        lookup: Dict[str, Dict[str, Any]] = {}
        for timing_source in (
            self._read_metadata_timing(dut_dir),
            self._read_timing_json(dut_dir),
        ):
            if not timing_source:
                continue
            collectors = self._select_timing_collectors(timing_source, dut_dir.name)
            for collector_id, timing_data in collectors.items():
                if isinstance(timing_data, dict):
                    key = str(collector_id).upper()
                    existing = lookup.get(key, {})
                    merged = {**existing, **timing_data}
                    existing_stages = existing.get("stage_timing") or existing.get(
                        "stages"
                    )
                    new_stages = timing_data.get("stage_timing") or timing_data.get(
                        "stages"
                    )
                    if isinstance(existing_stages, dict) and existing_stages:
                        if not isinstance(new_stages, dict) or not new_stages:
                            merged["stages"] = existing_stages
                    lookup[key] = merged
        return lookup

    @staticmethod
    def _select_timing_collectors(
        timing_source: Dict[str, Any], dut_id: str
    ) -> Dict[str, Any]:
        """
        Select timing records for one DUT, with legacy global fallback.

        The implementation uses ``timing_source`` and ``dut_id`` to select
        timing records for one DUT, with legacy global fallback.

        Args:
            timing_source: Mapping supplying fields for timing records for one
                DUT, with legacy global fallback.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing timing collectors.
        """
        collectors_by_dut = timing_source.get("collectors_by_dut")
        if isinstance(collectors_by_dut, dict) and dut_id in collectors_by_dut:
            dut_collectors = collectors_by_dut[dut_id]
            return dut_collectors if isinstance(dut_collectors, dict) else {}

        collectors = timing_source.get("collectors", {})
        return collectors if isinstance(collectors, dict) else {}

    def _apply_timing_to_collector(
        self,
        collector: Dict[str, Any],
        timing_lookup: Dict[str, Dict[str, Any]],
        dut_id: str,
    ) -> None:
        """
        Overlay canonical collector timing metadata onto the manifest entry.

        Detailed operation/artifact timing remains canonical in the DUT's
        timing.json. The SPA resolves this reference only on demand.

        Args:
            collector: Mapping supplying fields for overlay canonical collector
                timing metadata onto the manifest entry.
            timing_lookup: Mapping supplying fields for overlay canonical
                collector timing metadata onto the manifest entry.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        timing_data = timing_lookup.get(str(collector.get("id", "")).upper())
        if not timing_data:
            return

        duration = timing_data.get(
            "duration_seconds",
            timing_data.get("duration", timing_data.get("total_time")),
        )
        if duration is not None:
            collector["execution_time"] = float(duration or 0)

        granular_timing = timing_data.get("timing")
        if isinstance(granular_timing, dict):
            # The per-collector status snapshot can precede the final timing
            # snapshot, so its FileRef overlay may be incomplete. Reconcile
            # files from the canonical per-DUT timing document before emitting
            # the manifest. Detailed timing remains external through
            # ``timing_ref``; this copies only the bounded selection fields
            # needed to identify the exact timing row.
            self._apply_artifact_timing_to_files(
                collector.get("files", []),
                normalize_artifact_timings(
                    granular_timing.get("artifact_timings", []),
                    self.log_dir,
                    dut_id=dut_id,
                ),
            )
        timing_reference = self._timing_reference(dut_id, str(collector.get("id", "")))
        if timing_reference is not None:
            # Detailed operation/artifact timing remains canonical in the DUT's
            # timing.json. The SPA resolves this reference only on demand.
            collector["timing_ref"] = timing_reference
            collector.pop("timing", None)
        elif isinstance(granular_timing, dict) and granular_timing:
            # Legacy bundles without a standalone timing document retain their
            # historical inline representation.
            collector["timing"] = normalize_timing_artifact_paths(
                granular_timing,
                self.log_dir,
                dut_id=dut_id,
            )

        start_time = timing_data.get("start_time")
        end_time = timing_data.get("end_time")
        if isinstance(granular_timing, dict):
            start_time = start_time or granular_timing.get("collector_started_at")
            end_time = end_time or granular_timing.get("collector_ended_at")
        if start_time:
            collector["start_time"] = start_time
        if end_time:
            collector["end_time"] = end_time

        collection_level = timing_data.get("collection_level") or timing_data.get(
            "level"
        )
        if collection_level:
            collector["collection_level"] = collection_level

        stages = self._collector_stage_timing(timing_data)

        stage_timing = collector.setdefault(
            "stage_timing",
            {
                "validation": None,
                "discovery": None,
                "execution": None,
                "post_processing": None,
            },
        )
        for stage_name in (
            "validation",
            "discovery",
            "execution",
            "post_processing",
        ):
            if stages[stage_name] is not None:
                stage_timing[stage_name] = stages[stage_name]

    def _parse_collector(
        self, collector_id: str, data: Dict, dut_dir: Path, service_type: str
    ) -> Dict:
        """
        Parse a single collector entry from metadata.

        The implementation uses ``collector_id``, ``data``, ``dut_dir``, and
        ``service_type`` to parse a single collector entry from metadata.
        Parsing or I/O must finish before the validated representation is made
        available to the caller.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            data: Mapping supplying fields for single collector entry from
                metadata.
            dut_dir: filesystem location used as the DUT dir for this operation.
            service_type: Text supplied as service type in the format accepted
                by this function.

        Returns:
            The validated ``parsed_collector``.
        """
        collector_id = str(collector_id).upper()

        # Normalize status
        raw_status = str(data.get("status", "unknown")).lower()
        status_map = {
            "complete": "success",
            "completed": "success",
            "passed": "success",
            "pass": "success",
            "success": "success",
            "error": "error",
            "failed": "error",
            "fail": "error",
            "degraded": "degraded",
            "partial": "partial",
            "skipped": "skipped",
            "cancelled": "cancelled",
            "canceled": "cancelled",
            "not_ran": "not_ran",
            "notran": "not_ran",
            "running": "running",
            "pending": "pending",
        }
        status = status_map.get(raw_status, "not_ran")

        # Collectors filtered out before execution (baseboard not applicable,
        # config skip, etc.) never ran. Classify them as "not_ran" so the report
        # hides them from the main table by default and folds them into the
        # existing "Show not executed" toggle, instead of showing them as
        # "Skipped". Preflight-failure skips are not matched and stay visible.
        if self._is_preexecution_filtered_entry(data):
            status = "not_ran"

        # Extract files
        files = []
        seen_paths = set()
        for file_path in data.get("files", data.get("log_paths", [])):
            if isinstance(file_path, str):
                rel_path = bundle_relative_artifact_path(
                    self.log_dir,
                    file_path,
                    dut_id=dut_dir.name,
                )
                if rel_path is None:
                    continue
                abs_path = self.log_dir / rel_path
                # Collector results can include a working/output directory as
                # well as the files created beneath it.  A directory is not a
                # viewable artifact and must never become a FileRef.
                if abs_path.is_file():
                    norm_rel_path = rel_path
                    if norm_rel_path not in seen_paths:
                        files.append(
                            self._make_file_ref(norm_rel_path, abs_path, collector_id)
                        )
                        seen_paths.add(norm_rel_path)

        status_data = self._append_status_artifacts(
            files, seen_paths, collector_id, dut_dir, service_type
        )
        status_data = status_data if isinstance(status_data, dict) else {}
        # The collector-root envelope is the final service projection. Prefer
        # its corrected terminal state over group metadata captured earlier.
        if "status" in status_data:
            authoritative_status = str(status_data.get("status", "unknown")).lower()
            status = status_map.get(authoritative_status, "not_ran")
            if self._is_preexecution_filtered_entry(data):
                status = "not_ran"
        status_timing = status_data.get("timing", {})
        status_timing = normalize_timing_artifact_paths(
            status_timing,
            self.log_dir,
            dut_id=dut_dir.name,
        )
        self._apply_artifact_timing_to_files(
            files,
            normalize_artifact_timings(
                status_data.get("artifact_timings", []),
                self.log_dir,
                dut_id=dut_dir.name,
            ),
        )

        catalog_metadata = self._collector_catalog_by_id.get(collector_id, {})
        report_roles = data.get("report_role") or catalog_metadata.get("report_role")
        if not isinstance(report_roles, list):
            report_roles = [report_roles]
        report_roles = [
            self._metadata_text(role).lower()
            for role in report_roles[:16]
            if isinstance(role, str) and role.strip()
        ]
        component_label = self._metadata_text(
            catalog_metadata.get("component")
            or catalog_metadata.get("component_label")
            or service_type
        )

        outcome_details = project_collector_outcome_details(
            status_data.get("outcome_details")
        )
        category_source = (
            status_data.get("failure_category")
            if status_data
            else data.get("failure_category")
        )
        if category_source is None and outcome_details is not None:
            category_source = outcome_details["category"]
        failure_category = normalize_collector_failure_category(
            status,
            category_source,
        )
        reason = sanitize_terminal_collector_reason(
            status,
            status_data.get(
                "reason",
                data.get("reason", data.get("error", "")),
            ),
        )
        parsed_collector = {
            "id": collector_id,
            "name": data.get("name", collector_id),
            "component_label": component_label,
            "report_role": report_roles,
            "access_path": self._canonical_access_path(service_type),
            "status": status,
            "failure_category": failure_category,
            "execution_time": float(
                data.get("execution_time", data.get("duration", 0)) or 0
            ),
            "start_time": data.get("start_time")
            or status_timing.get("collector_started_at"),
            "end_time": data.get("end_time") or status_timing.get("collector_ended_at"),
            "reason": reason,
            "dependencies": data.get("dependencies", []),
            "collection_level": data.get("collection_level")
            or data.get("level")
            or status_data.get("collection_level", ""),
            "files": files,
            "stage_timing": {
                "validation": self._normalize_stage_value(
                    data.get("stage_timing", {}).get("validation")
                ),
                "discovery": self._normalize_stage_value(
                    data.get("stage_timing", {}).get("discovery")
                ),
                "execution": self._normalize_stage_value(
                    data.get("stage_timing", {}).get("execution")
                ),
                "post_processing": self._normalize_stage_value(
                    data.get("stage_timing", {}).get("post_processing")
                ),
            },
        }
        if status in {"degraded", "partial", "error"} and outcome_details is not None:
            parsed_collector["outcome_details"] = outcome_details
        timing_reference = self._timing_reference(dut_dir.name, collector_id)
        if timing_reference is not None:
            parsed_collector["timing_ref"] = timing_reference
        elif status_timing:
            parsed_collector["timing"] = status_timing
        return parsed_collector

    def _timing_reference(
        self, dut_id: str, collector_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Return a portable reference to a canonical per-DUT timing document.

        The implementation uses ``dut_id`` and ``collector_id`` to produce a
        portable reference to a canonical per-DUT timing document.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A mapping containing the ``schema_version``, ``scope``, ``source``,
            ``collector_id``, and ``size_bytes`` fields.
        """
        normalized_dut_id = str(dut_id)
        binding = self._timing_bindings.get(normalized_dut_id)
        if not isinstance(binding, dict):
            return None
        normalized_collector_id = str(collector_id).upper()
        if normalized_collector_id not in binding.get("collector_ids", ()):
            return None
        return {
            "schema_version": "2.0",
            "scope": "dut",
            "source": f"{dut_id}/{binding['source']}/timing.json",
            "collector_id": normalized_collector_id,
            "size_bytes": binding["size_bytes"],
            "sha256": binding["sha256"],
            "snapshot_generation": binding["snapshot_generation"],
        }

    def _append_status_artifacts(
        self,
        files: List[Dict],
        seen_paths: set,
        collector_id: str,
        dut_dir: Path,
        service_type: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Backfill artifacts referenced from per-collector status.json.

        The implementation uses ``files``, ``seen_paths``, ``collector_id``,
        ``dut_dir``, and ``service_type`` to backfill artifacts referenced from
        per-collector status.json. The operation mutates ``files`` and
        ``seen_paths`` in place; ownership of those objects remains with the
        caller.

        Args:
            files: Filesystem locations processed in caller-provided order.
            seen_paths: Filesystem locations processed in caller-provided order.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_dir: filesystem location used as the DUT dir for this operation.
            service_type: Text supplied as service type in the format accepted
                by this function.

        Returns:
            The validated ``status_data``, or ``None`` when no value qualifies.
        """
        status_path = self._find_collector_status_file(
            collector_id, files, dut_dir, service_type
        )
        if not status_path or not status_path.exists():
            return None

        try:
            status_data = self._read_auxiliary_json(status_path)
        except (
            json.JSONDecodeError,
            OSError,
            UnicodeError,
            ValueError,
            RecursionError,
        ):
            return None
        if not isinstance(status_data, dict):
            return None

        artifact_names = normalize_artifact_file_list(
            status_data.get("output_files"),
            self.log_dir,
            dut_id=dut_dir.name,
        )
        for artifact_key in ("command_execution", "request_response_capture"):
            artifact_name = (status_data.get(artifact_key, {}) or {}).get("artifact")
            if artifact_name:
                artifact_names.append(artifact_name)

        for artifact_name in artifact_names:
            rel_path = bundle_relative_artifact_path(
                self.log_dir,
                artifact_name,
                dut_id=dut_dir.name,
            )
            # Legacy status files stored these references relative to the
            # collector directory rather than to the bundle root.
            if rel_path is None:
                rel_path = bundle_relative_artifact_path(
                    self.log_dir,
                    status_path.parent / str(artifact_name),
                    dut_id=dut_dir.name,
                )
            if rel_path is None:
                continue
            artifact_path = self.log_dir / rel_path

            if rel_path in seen_paths:
                continue

            files.append(self._make_file_ref(rel_path, artifact_path, collector_id))
            seen_paths.add(rel_path)

        # Task polling, snapshots, and diagnostic error/response arrays are not
        # always returned as primary collector outputs. Backfill every physical
        # diagnostic file so CollectorDetail can display the complete section.
        diagnostic_dir = status_path.parent / "diagnostic"
        try:
            diagnostic_paths = self._bounded_descendant_regular_paths(
                diagnostic_dir,
                maximum_paths=self._max_auxiliary_json_files,
            )
        except (OSError, ValueError):
            diagnostic_paths = []
        for diagnostic_path in diagnostic_paths:
            rel_path = bundle_relative_artifact_path(
                self.log_dir,
                diagnostic_path,
                dut_id=dut_dir.name,
            )
            if rel_path is None:
                continue
            if rel_path in seen_paths:
                continue
            files.append(self._make_file_ref(rel_path, diagnostic_path, collector_id))
            seen_paths.add(rel_path)
        return status_data

    def _apply_artifact_timing_to_files(
        self, files: List[Dict[str, Any]], artifact_timings: Any
    ) -> None:
        """
        Overlay measured per-artifact timing onto manifest FileRef entries.

        The implementation uses ``files`` and ``artifact_timings`` to overlay
        measured per-artifact timing onto manifest FileRef entries. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            files: Filesystem locations processed in caller-provided order.
            artifact_timings: Entries supplied as ``artifact_timings`` and
                processed in caller-provided order.
        """
        if not isinstance(artifact_timings, list):
            return

        timing_by_path: Dict[str, Dict[str, Any]] = {}
        for timing in artifact_timings:
            if not isinstance(timing, dict) or not timing.get("path"):
                continue
            raw_path = Path(str(timing["path"]))
            absolute_path = (
                raw_path if raw_path.is_absolute() else self.log_dir / raw_path
            )
            try:
                key = str(absolute_path.resolve(strict=False))
            except OSError:
                key = str(absolute_path.absolute())
            existing = timing_by_path.get(key)
            priority = {
                "not_instrumented": 0,
                "artifact_persistence": 1,
                "hook_acquisition": 2,
                "host_command_acquisition": 2,
                "host_command": 2,
                "bmc_ssh_command": 2,
                "ipmi_command": 2,
                "host_file_acquisition": 2,
                "bmc_file_acquisition": 2,
                "redfish_file_acquisition": 2,
                "redfish_request": 2,
                "bmc_ssh_command_duration": 3,
                "bmc_ssh_command_duration_estimated": 3,
            }
            if existing is None or priority.get(
                str(timing.get("measurement")), 1
            ) >= priority.get(str(existing.get("measurement")), 1):
                timing_by_path[key] = timing

        for file_ref in files:
            raw_path = Path(str(file_ref.get("path", "")))
            absolute_path = (
                raw_path if raw_path.is_absolute() else self.log_dir / raw_path
            )
            try:
                key = str(absolute_path.resolve(strict=False))
            except OSError:
                key = str(absolute_path.absolute())
            timing = timing_by_path.get(key)
            if timing is None:
                continue
            file_ref.update(
                {
                    "produced_by_operation_id": timing.get("operation_id"),
                    "measurement": timing.get("measurement"),
                    "measurement_quality": timing.get("measurement_quality"),
                    "measurement_scope": timing.get("measurement_scope"),
                    "shared_operation_artifact_count": timing.get(
                        "shared_operation_artifact_count"
                    ),
                    "shared_request_operation_count": timing.get(
                        "shared_request_operation_count"
                    ),
                    "started_at": timing.get("started_at"),
                    "ended_at": timing.get("ended_at"),
                    "duration_seconds": timing.get("duration_seconds"),
                    "status": timing.get("status"),
                }
            )

    def _find_collector_status_file(
        self,
        collector_id: str,
        files: List[Dict],
        dut_dir: Path,
        service_type: str,
    ) -> Optional[Path]:
        """
        Locate a collector's status.json file.

        The implementation uses ``collector_id``, ``files``, ``dut_dir``, and
        ``service_type`` to locate a collector's status.json file. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            files: Filesystem locations processed in caller-provided order.
            dut_dir: filesystem location used as the DUT dir for this operation.
            service_type: Text supplied as service type in the format accepted
                by this function.

        Returns:
            The validated collector status file filesystem path, or ``None``
            when the requested value is unavailable.
        """
        for file_ref in files:
            file_path = self.log_dir / file_ref["path"]
            status_path = file_path.parent / "status.json"
            if status_path.exists():
                return status_path

        group_dir = dut_dir / service_type
        if not group_dir.exists():
            return None

        service_prefix = service_type.capitalize()
        expected_prefix = f"{service_prefix}_{collector_id}_".casefold()
        matches: List[Path] = []
        try:
            with os.scandir(group_dir) as entries:
                for index, entry in enumerate(entries):
                    if index >= MAX_AUXILIARY_PATH_NODES:
                        return None
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if not entry.name.casefold().startswith(expected_prefix):
                        continue
                    status_path = Path(entry.path) / "status.json"
                    try:
                        metadata = status_path.lstat()
                    except OSError:
                        continue
                    if stat.S_ISREG(metadata.st_mode):
                        matches.append(status_path)
                        if len(matches) > self._max_auxiliary_json_files:
                            return None
        except OSError:
            return None
        matches.sort(key=lambda path: str(path).casefold())
        if matches:
            return matches[0]

        return None

    @staticmethod
    def _normalize_stage_value(val: Any) -> Optional[float]:
        """
        Normalize a stage_timing value to float or None.

        Accept explicit finite, nonnegative measurements, including zero and
        legacy nested duration records. Missing or malformed measurements stay
        absent instead of being converted into a fabricated zero duration.

        Args:
            val: Measured seconds or a legacy record containing an explicit
                ``total_time``, ``duration``, or ``duration_seconds`` value.

        Returns:
            The numeric stage value, or ``None`` when the requested value is
            unavailable.
        """
        if isinstance(val, dict):
            val = val.get(
                "total_time", val.get("duration", val.get("duration_seconds"))
            )
        if isinstance(val, (int, float)) and not isinstance(val, bool) and val >= 0:
            try:
                seconds = float(val)
            except OverflowError:
                return None
            return seconds if math.isfinite(seconds) else None
        return None

    def _collector_stage_timing(
        self, record: Dict[str, Any]
    ) -> Dict[str, Optional[float]]:
        """
        Resolve compact stage measurements from summaries or canonical spans.

        A canonical timing document can contain only operation spans when its
        legacy metadata index is absent. Use stage scopes from that document
        without summing their nested hooks, requests, or artifact durations.
        Accept operations at the record root or under its timing mapping.
        Explicit summary measurements take precedence, including zero.

        Args:
            record: One collector's timing record from bounded report metadata.

        Returns:
            Canonical stage names mapped to measured seconds or ``None`` when
            the report contains no valid measurement for that stage.
        """

        stages: Dict[str, Optional[float]] = dict.fromkeys(
            ("validation", "discovery", "execution", "post_processing")
        )
        for source in (record.get("stage_timing"), record.get("stages")):
            if not isinstance(source, dict):
                continue
            for stage in stages:
                if stages[stage] is None:
                    stages[stage] = self._normalize_stage_value(source.get(stage))
        timing = record.get("timing")
        if not isinstance(timing, dict):
            timing = record
        operations = timing.get("operations", [])
        if not isinstance(operations, list):
            return stages
        stage_ids = {
            operation.get("operation_id")
            for operation in operations
            if isinstance(operation, dict)
            and operation.get("operation_type") == "stage"
            and isinstance(operation.get("operation_id"), str)
        }
        measured: Dict[str, float] = {}
        for operation in operations:
            if (
                not isinstance(operation, dict)
                or operation.get("operation_type") != "stage"
            ):
                continue
            parent = operation.get("parent_id")
            if isinstance(parent, str) and parent in stage_ids:
                continue
            stage = operation.get("name")
            duration = self._normalize_stage_value(operation.get("duration_seconds"))
            if isinstance(stage, str) and stage in stages and duration is not None:
                measured[stage] = measured.get(stage, 0.0) + duration
        for stage, duration in measured.items():
            if stages[stage] is None and math.isfinite(duration):
                stages[stage] = duration
        return stages

    def _make_file_ref(self, rel_path: str, abs_path: Path, collector_id: str) -> Dict:
        """
        Create a FileRef dict for a file.

        The implementation uses ``rel_path``, ``abs_path``, and ``collector_id``
        to create a FileRef dict for a file. Filesystem effects remain confined
        to the caller-selected paths and the owning resource lifecycle.

        Args:
            rel_path: filesystem location used as the rel path for this
                operation.
            abs_path: filesystem location used as the abs path for this
                operation.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The validated ``ref``.
        """
        ext = abs_path.suffix.lower()
        file_type = EXT_TYPE_MAP.get(ext, "binary")

        ref = {
            "path": rel_path.replace("\\", "/"),
            "size": abs_path.stat().st_size if abs_path.exists() else 0,
            "type": file_type,
            "collector_id": collector_id,
        }

        # Set viewer_hint for known log files
        name = abs_path.name
        if name in LOG_VIEWER_FILES or name.endswith("_stdout.log"):
            ref["viewer_hint"] = "log-viewer"

        return ref

    def _build_file_index(self, dut_dir: Path, dut_id: str) -> List[Dict]:
        """
        Walk a DUT directory and build the file index.

        Receipt-bound snapshots expose the pinned DUT directory through
        ``/proc/self/fd``. ``os.walk`` does not descend through that symlink, so
        use descriptor-relative traversal instead. The same traversal also
        prevents a bundle-owned symlink from escaping the pinned DUT root.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The file index returned in operation-defined order.
        """

        files: List[Dict[str, Any]] = []
        open_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        open_flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            dut_fd = os.open(dut_dir, open_flags)
        except OSError as error:
            logger.warning("Unable to index DUT directory %s: %s", dut_dir, error)
            return files

        try:
            for relative_root, dirs, filenames, root_fd in os.fwalk(
                ".",
                topdown=True,
                follow_symlinks=False,
                dir_fd=dut_fd,
            ):
                retained_dirs = []
                for dirname in sorted(dirs):
                    if dirname in EXCLUDED_DIRS:
                        continue
                    try:
                        metadata = os.stat(
                            dirname,
                            dir_fd=root_fd,
                            follow_symlinks=False,
                        )
                    except OSError:
                        continue
                    if stat.S_ISDIR(metadata.st_mode):
                        retained_dirs.append(dirname)
                dirs[:] = retained_dirs

                root_parts = Path(relative_root).parts
                for filename in sorted(filenames):
                    try:
                        metadata = os.stat(
                            filename,
                            dir_fd=root_fd,
                            follow_symlinks=False,
                        )
                    except OSError:
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        continue

                    relative_parts = (*root_parts, filename)
                    rel_path = "/".join((dut_id, *relative_parts))
                    ext = Path(filename).suffix.lower()
                    entry = {
                        "path": rel_path,
                        "size": metadata.st_size,
                        "type": EXT_TYPE_MAP.get(ext, "binary"),
                        "collector_id": "",  # Enriched if matched to a collector.
                        "dut_id": dut_id,
                        "collector_group": root_parts[0] if root_parts else "",
                        "collector_name": "",
                    }

                    if filename in LOG_VIEWER_FILES or filename.endswith("_stdout.log"):
                        entry["viewer_hint"] = "log-viewer"

                    files.append(entry)
        finally:
            os.close(dut_fd)

        return files

    @staticmethod
    def _enrich_file_index(file_entries: List[Dict], dut: Dict[str, Any]) -> None:
        """
        Enrich file-index entries with stable collector report metadata.

        The implementation uses ``file_entries`` and ``dut`` to enrich
        file-index entries with stable collector report metadata. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            file_entries: Mapping supplying fields for enrich file-index entries
                with stable collector report metadata.
            dut: Stable DUT used to correlate configuration, logs, and results.
        """
        path_to_collector: Dict[str, tuple] = {}
        for group in dut.get("collector_groups", []):
            for collector in group.get("collectors", []):
                cid = collector.get("id", "")
                cname = collector.get("name", "")
                component_label = collector.get("component_label", "")
                access_path = collector.get("access_path", "")
                for fref in collector.get("files", []):
                    p = fref.get("path", "")
                    if p:
                        path_to_collector[p.replace("\\", "/")] = (
                            cid,
                            cname,
                            component_label,
                            access_path,
                        )

        for entry in file_entries:
            key = entry.get("path", "").replace("\\", "/")
            if key in path_to_collector:
                entry["collector_id"] = path_to_collector[key][0]
                entry["collector_name"] = path_to_collector[key][1]
                entry["component_label"] = path_to_collector[key][2]
                entry["access_path"] = path_to_collector[key][3]

    def _infer_group(self, file_dir: Path, dut_dir: Path) -> str:
        """
        Infer collector group from directory path.

        The implementation uses ``file_dir`` and ``dut_dir`` to infer collector
        group from directory path.

        Args:
            file_dir: filesystem location used as the file dir for this
                operation.
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            The canonical infer group text.
        """
        try:
            rel = file_dir.relative_to(dut_dir)
            parts = rel.parts
            if parts:
                return parts[0]
        except ValueError:
            pass
        return ""

    def _extract_errors(self, dut_dir: Path, dut_id: str) -> List[Dict]:
        """
        Extract errors from metadata files.

        The implementation uses ``dut_dir`` and ``dut_id`` to extract errors
        from metadata files.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The errors returned in operation-defined order.
        """
        errors_by_collector: Dict[Tuple[str, str], Dict[str, Any]] = {}
        metadata_dir = dut_dir / ".metadata"
        if not metadata_dir.exists():
            metadata_dir = dut_dir / "metadata"
        if not metadata_dir.exists():
            return []

        try:
            metadata_paths = []
            with os.scandir(metadata_dir) as entries:
                for entry in entries:
                    if not entry.name.endswith(".json") or not entry.is_file(
                        follow_symlinks=False
                    ):
                        continue
                    if len(metadata_paths) >= self._max_auxiliary_json_files:
                        break
                    metadata_paths.append(Path(entry.path))
            metadata_paths.sort(key=lambda path: path.name.casefold())
        except OSError:
            metadata_paths = []
        for meta_file in metadata_paths:
            if meta_file.name in ("timing.json", "preflight.json"):
                continue
            try:
                meta = self._read_auxiliary_json(meta_file)
            except (
                json.JSONDecodeError,
                OSError,
                UnicodeError,
                ValueError,
                RecursionError,
            ):
                continue

            if isinstance(meta, dict):
                # Extract collectors dict (same logic as _build_collector_groups)
                collector_dict = meta.get("collectors", {})
                if not isinstance(collector_dict, dict):
                    collector_dict = {}
                if not collector_dict:
                    for key, val in meta.items():
                        if (
                            isinstance(val, dict)
                            and key not in ("metadata", "status_fields", "summary")
                            and (
                                val.get("id")
                                or val.get("status")
                                or val.get("files")
                                or val.get("log_paths")
                            )
                        ):
                            collector_dict[key] = val
                for collector_id, data in collector_dict.items():
                    if not isinstance(data, dict):
                        continue
                    status = str(data.get("status", "")).lower()
                    if status in ("degraded", "error", "failed", "partial"):
                        identity = str(data.get("id") or collector_id)
                        dut_prefix = f"{dut_id}:"
                        if identity.casefold().startswith(dut_prefix.casefold()):
                            identity = identity[len(dut_prefix) :]
                        dedupe_key = (dut_id.casefold(), identity.casefold())
                        message = sanitize_terminal_collector_reason(
                            status,
                            data.get(
                                "reason",
                                data.get("error", "Unknown error"),
                            ),
                        )
                        error = {
                            "dut_id": dut_id,
                            "collector_id": collector_id,
                            "collector_name": data.get("name", collector_id),
                            "collector_group": meta_file.stem,
                            "message": message,
                            "timestamp": data.get("start_time"),
                        }
                        existing = errors_by_collector.get(dedupe_key)
                        if existing is None or (
                            existing.get("collector_group") == "collection_status"
                            and meta_file.stem != "collection_status"
                        ):
                            # Service metadata has the collector name, group and
                            # full reason; collection_status is only a fallback.
                            errors_by_collector[dedupe_key] = error

        return list(errors_by_collector.values())

    def _read_preflight(self, dut_dir: Path, dut_id: str) -> Optional[Dict]:
        """
        Read preflight check data from .metadata/preflight.json.

        The preflight file structure has a nested 'preflights' dict:
        {"preflights": {"HOST": {"status": "...", "reason": "..."}, ...}}

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing preflight, or ``None`` when the requested value
            is unavailable.
        """
        for metadata_name in (".metadata", "metadata"):
            preflight_path = dut_dir / metadata_name / "preflight.json"
            if preflight_path.exists():
                break
        else:
            logger.debug("No preflight.json found for DUT %s", dut_id)
            return None

        try:
            data = self._read_auxiliary_json(preflight_path)
        except (
            json.JSONDecodeError,
            OSError,
            UnicodeError,
            ValueError,
            RecursionError,
        ) as e:
            logger.warning("Failed to read preflight.json for DUT %s: %s", dut_id, e)
            return None

        checks = []
        if isinstance(data, dict):
            preflights = data.get("preflights", {})
            if not isinstance(preflights, dict) or not preflights:
                preflights = {
                    k: v
                    for k, v in data.items()
                    if isinstance(v, dict) and k != "metadata"
                }

            for check_name, check_data in preflights.items():
                if not isinstance(check_data, dict):
                    continue
                checks.append(
                    {
                        "name": check_name,
                        "group": check_data.get("group", check_name.lower()),
                        "status": str(check_data.get("status", "na")).lower(),
                        "details": str(
                            check_data.get(
                                "reason",
                                check_data.get(
                                    "details", check_data.get("message", "")
                                ),
                            )
                            or ""
                        ),
                    }
                )

        if checks:
            logger.debug("Read %d preflight checks for DUT %s", len(checks), dut_id)
        return {"dut_id": dut_id, "checks": checks} if checks else None

    def _read_tool_config(self) -> Dict:
        """
        Read tool config from any DUT's config.json.

        The implementation uses current instance state to read tool config from
        any DUT's config.json. Parsing or I/O must finish before the validated
        representation is made available to the caller.

        Returns:
            A mapping containing tool config.
        """
        for dut_dir in self._find_dut_directories():
            config_path = dut_dir / "config.json"
            if config_path.exists():
                try:
                    document = self._read_auxiliary_json(config_path)
                    if isinstance(document, dict):
                        return document
                except (
                    json.JSONDecodeError,
                    OSError,
                    UnicodeError,
                    ValueError,
                    RecursionError,
                ):
                    pass
        return {
            "collection_level": "unknown",
            "execution_mode": "unknown",
            "baseboard": "unknown",
        }

    def _read_collector_catalog(self) -> List[Dict]:
        """
        Read collector catalog from root-level file.

        The implementation uses current instance state to read collector catalog
        from root-level file. Parsing or I/O must finish before the validated
        representation is made available to the caller.

        Returns:
            The collector catalog returned in operation-defined order.
        """
        catalog_path = self.log_dir / "collector_catalog.json"
        if not catalog_path.exists():
            return []
        try:
            data = self._read_auxiliary_json(catalog_path)
            return data if isinstance(data, list) else []
        except (
            json.JSONDecodeError,
            OSError,
            UnicodeError,
            ValueError,
            RecursionError,
        ):
            return []

    @staticmethod
    def _index_collector_catalog(catalog: Any) -> Dict[str, Dict[str, Any]]:
        """
        Index additive catalog metadata without assuming one producer shape.

        The implementation uses ``catalog`` to index additive catalog metadata
        without assuming one producer shape.

        Args:
            catalog: Entries supplied as ``catalog`` and processed in
                caller-provided order.

        Returns:
            A mapping containing index collector catalog.
        """
        indexed: Dict[str, Dict[str, Any]] = {}
        if not isinstance(catalog, list):
            return indexed
        for item in catalog:
            if not isinstance(item, dict):
                continue
            collector_id = item.get("id") or item.get("ID") or item.get("collector_id")
            if isinstance(collector_id, str) and collector_id.strip():
                indexed[collector_id.strip().upper()] = item
        return indexed

    @staticmethod
    def _canonical_access_path(service_type: Any) -> str:
        """
        Return a credential-free, stable transport label for reports.

        After applying local validation, the function forwards ``service_type``
        to ``get`` and preserves its return and exception contract.

        Args:
            service_type: Service type consumed while the function attempts to
                produce a credential-free, stable transport label for reports.

        Returns:
            The canonical access path.
        """
        return {
            "redfish": "redfish",
            "host": "host_ssh",
            "ssh": "bmc_ssh",
            "bmc_ssh": "bmc_ssh",
            "ipmi": "ipmi",
            "health_check": "composite",
        }.get(str(service_type or "").strip().lower(), "unknown")

    @staticmethod
    def _metadata_text(value: Any, *, limit: int = 128) -> str:
        """
        Bound one display-only metadata value and remove control bytes.

        The implementation uses ``value`` and ``limit`` to bound one
        display-only metadata value and remove control bytes.

        Args:
            value: Value evaluated while performing bound one display-only
                metadata value and remove control bytes.
            limit: Numeric limit used while the operation performs bounded
                accounting.

        Returns:
            The canonical metadata text.
        """
        text = "" if value is None else str(value)
        text = "".join(character for character in text if character.isprintable())
        return text.strip()[:limit]

    def _read_security_mode(self, dut_dir: Path) -> Dict[str, Any]:
        """
        Read only an explicitly recorded hardware security mode.

        Transport TLS settings and NVDebug's diagnostic ``debug`` flag are not
        hardware security-mode evidence. When the DUT config does not carry a
        recognized field, publish an explicit unknown rather than infer one.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            A mapping containing the ``status``, ``value``, and ``source``
            fields.
        """
        config_path = dut_dir / "dut_config.json"
        try:
            document = self._read_auxiliary_json(config_path)
        except (
            OSError,
            UnicodeError,
            ValueError,
            json.JSONDecodeError,
            RecursionError,
        ):
            document = {}
        if not isinstance(document, dict):
            document = {}

        for field in ("security_mode", "SECURITY_MODE", "SecurityMode"):
            value = document.get(field)
            if isinstance(value, str):
                value = self._metadata_text(value)
                if not value:
                    continue
            elif not isinstance(value, (bool, int)):
                continue
            return {
                "status": "reported",
                "value": value,
                "source": f"dut_config.{field}",
            }
        return {"status": "unknown", "value": None, "source": None}

    def _build_timing_data(self) -> Dict:
        """
        Build timing data from DUT timing.json and metadata.json files.

        timing.json structure: {"overall": {"wall_clock_duration_seconds": N},
        "collectors": {ID: {...}}, "by_service": {...}} metadata.json timing:
        {"payload": {"timing_data": {"collectors": {ID: {"total_time": N,
        "stages": {...}}}}}}

        Returns:
            The validated ``timing``.
        """
        timing: Dict[str, Any] = {
            "total_duration": 0,
            "component_timing": {
                "tool_init": None,
                "config_load": None,
                "dut_init": None,
                "preflight": None,
                "collection": None,
                "report_generation": None,
                "metadata_write": None,
                "cleanup": None,
            },
            "per_dut": [],
            "per_service": [],
        }

        service_totals: Dict[str, Dict] = {}

        for dut_dir in self._find_dut_directories():
            dut_id = dut_dir.name
            dut_timing = self._read_timing_json(dut_dir)
            metadata_timing = self._read_metadata_timing(dut_dir)

            if not dut_timing and not metadata_timing:
                continue

            overall = dut_timing.get("overall", {}) if dut_timing else {}
            duration = float(
                overall.get(
                    "wall_clock_duration_seconds",
                    overall.get(
                        "duration_seconds",
                        (
                            dut_timing.get(
                                "total_duration", dut_timing.get("duration", 0)
                            )
                            if dut_timing
                            else 0
                        ),
                    ),
                )
                or 0
            )
            timing["total_duration"] = max(timing["total_duration"], duration)

            if (
                dut_timing
                and dut_timing.get("component_timing")
                and all(v is None for v in timing["component_timing"].values())
            ):
                timing["component_timing"] = dut_timing["component_timing"]

            collectors = self._parse_timing_collectors(
                dut_id, dut_timing, metadata_timing, service_totals
            )

            timing["per_dut"].append(
                {
                    "dut_id": dut_id,
                    "duration": duration,
                    "collectors": collectors,
                }
            )

        timing["per_service"] = [
            {"service": svc, **totals} for svc, totals in sorted(service_totals.items())
        ]

        return timing

    def _read_timing_json(self, dut_dir: Path) -> Optional[Dict]:
        """
        Read timing.json from a DUT's metadata directory.

        The implementation uses ``dut_dir`` to read timing.json from a DUT's
        metadata directory. Parsing or I/O must finish before the validated
        representation is made available to the caller.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            A mapping containing timing JSON, or ``None`` when the requested
            value is unavailable.
        """
        dut_id = dut_dir.name
        if dut_id in self._timing_cache:
            self._timing_cache.move_to_end(dut_id)
            return self._timing_cache[dut_id]
        for metadata_name in (".metadata", "metadata"):
            timing_path = dut_dir / metadata_name / "timing.json"
            if metadata_name == ".metadata":
                try:
                    data = self._read_terminal_timing(dut_dir.name)
                except SnapshotArtifactFormatError:
                    if self._terminal_snapshot_generation is not None:
                        raise
                    data = None
                if data is not None:
                    binding = self._timing_source_binding(
                        dut_id,
                        metadata_name,
                        timing_path,
                        data,
                    )
                    if binding is not None:
                        self._timing_bindings[dut_id] = binding
                    self._timing_sources[dut_id] = metadata_name
                    self._put_timing_cache(dut_id, data, binding=binding)
                    return data
                continue
            if timing_path.exists():
                try:
                    raw = _read_regular_file_bounded(timing_path, MAX_TIMING_BYTES)
                    data = json.loads(raw.decode("utf-8"))
                    normalized = data if isinstance(data, dict) else None
                    if normalized is not None:
                        self._timing_sources[dut_id] = metadata_name
                    self._put_timing_cache(
                        dut_id,
                        normalized,
                        serialized_bytes=len(raw),
                    )
                    return normalized
                except (json.JSONDecodeError, OSError, UnicodeError) as e:
                    logger.warning(
                        "Failed to read timing.json for %s: %s",
                        dut_dir.name,
                        e,
                    )
        self._put_timing_cache(dut_id, None, serialized_bytes=0)
        return None

    @staticmethod
    def _cache_document_size(value: Optional[Dict[str, Any]]) -> int:
        """
        Return the cache document size.

        The implementation uses ``value`` to produce the cache document size.

        Args:
            value: Mapping supplying fields for cache document size.

        Returns:
            The numeric cache document size.
        """
        if value is None:
            return 0
        return len(
            json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
                default=str,
            ).encode("utf-8")
        )

    def _put_bounded_cache(
        self,
        cache: "OrderedDict[str, Optional[Dict[str, Any]]]",
        sizes: Dict[str, int],
        dut_id: str,
        value: Optional[Dict[str, Any]],
        *,
        serialized_bytes: Optional[int],
        timing_cache: bool,
    ) -> None:
        """
        Store bounded cache.

        The implementation uses ``cache``, ``sizes``, ``dut_id``, ``value``, and
        ``serialized_bytes`` to store bounded cache. It updates
        ``_metadata_timing_cache_bytes`` and ``_timing_cache_bytes`` on the
        instance as part of that state transition. The operation mutates
        ``sizes`` in place; ownership of those objects remains with the caller.

        Args:
            cache: Mapping supplying fields for store bounded cache.
            sizes: Mapping supplying fields for store bounded cache.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            value: Mapping supplying fields for store bounded cache.
            serialized_bytes: Numeric serialized bytes used while the operation
                performs bounded accounting.
            timing_cache: Whether timing cache is enabled or required for this
                operation.
        """
        size = (
            self._cache_document_size(value)
            if serialized_bytes is None
            else max(0, int(serialized_bytes))
        )
        current_total = (
            self._timing_cache_bytes
            if timing_cache
            else self._metadata_timing_cache_bytes
        )
        if dut_id in cache:
            current_total -= sizes.pop(dut_id, 0)
            del cache[dut_id]
        per_cache_limit = MAX_BACKEND_TIMING_CACHE_BYTES // 2
        while cache and (
            len(cache) >= MAX_BACKEND_TIMING_CACHE_ENTRIES
            or current_total + size > per_cache_limit
        ):
            evicted_dut, _ = cache.popitem(last=False)
            current_total -= sizes.pop(evicted_dut, 0)
        if size <= per_cache_limit:
            cache[dut_id] = value
            sizes[dut_id] = size
            current_total += size
        if timing_cache:
            self._timing_cache_bytes = current_total
        else:
            self._metadata_timing_cache_bytes = current_total

    def _put_timing_cache(
        self,
        dut_id: str,
        value: Optional[Dict[str, Any]],
        *,
        serialized_bytes: Optional[int] = None,
        binding: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Store timing cache.

        The implementation uses ``dut_id``, ``value``, ``serialized_bytes``, and
        ``binding`` to store timing cache.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            value: Mapping supplying fields for store timing cache.
            serialized_bytes: Optional serialized bytes; ``None`` selects the
                function's default behavior.
            binding: Optional binding; ``None`` selects the function's default
                behavior.
        """
        if binding is not None:
            serialized_bytes = int(binding["size_bytes"])
        self._put_bounded_cache(
            self._timing_cache,
            self._timing_cache_sizes,
            dut_id,
            value,
            serialized_bytes=serialized_bytes,
            timing_cache=True,
        )

    def _timing_source_binding(
        self,
        dut_id: str,
        metadata_name: str,
        timing_path: Path,
        document: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Bind a timing document to exact bytes, generation, and collectors.

        The implementation uses ``dut_id``, ``metadata_name``, ``timing_path``,
        and ``document`` to bind a timing document to exact bytes, generation,
        and collectors.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            metadata_name: Stable metadata name used for lookup and
                operator-facing diagnostics.
            timing_path: filesystem location used as the timing path for this
                operation.
            document: Mapping supplying fields for bind a timing document to
                exact bytes, generation, and collectors.

        Returns:
            A mapping containing the ``source``, ``size_bytes``, ``sha256``,
            ``snapshot_generation``, and ``collector_ids`` fields.
        """
        generation = document.get("snapshot_generation")
        if not isinstance(generation, str) or not generation:
            return None
        if (
            self._terminal_snapshot_generation is not None
            and generation != self._terminal_snapshot_generation
        ):
            return None
        relative = f"{dut_id}/{metadata_name}/timing.json"
        size_bytes: Optional[int] = None
        sha256: Optional[str] = None
        if self._snapshot_binding is not None:
            for (
                leaf_path,
                leaf_size,
                leaf_digest,
            ) in self._snapshot_binding.leaf_digests:
                if leaf_path == relative:
                    size_bytes = leaf_size
                    sha256 = leaf_digest
                    break
        if size_bytes is None or sha256 is None:
            try:
                raw = _read_regular_file_bounded(timing_path, MAX_TIMING_BYTES)
            except OSError:
                return None
            size_bytes = len(raw)
            sha256 = hashlib.sha256(raw).hexdigest()
            try:
                confirmation = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                return None
            if confirmation != document:
                return None
        collectors = self._select_timing_collectors(document, dut_id)
        referenceable_collectors: List[str] = []
        for key, value in collectors.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            detailed_timing = value.get("timing", value)
            if (
                isinstance(detailed_timing, dict)
                and isinstance(detailed_timing.get("operations"), list)
                and isinstance(detailed_timing.get("artifact_timings"), list)
            ):
                referenceable_collectors.append(key.upper())
        collector_ids = tuple(sorted(referenceable_collectors))
        return {
            "source": metadata_name,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "snapshot_generation": generation,
            "collector_ids": collector_ids,
        }

    def _read_metadata_timing(self, dut_dir: Path) -> Optional[Dict]:
        """
        Read timing_data from metadata.json payload.

        The implementation uses ``dut_dir`` to read timing_data from
        metadata.json payload. Parsing or I/O must finish before the validated
        representation is made available to the caller. If the function cannot
        read timing_data from metadata.json payload, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            A mapping containing metadata timing, or ``None`` when the requested
            value is unavailable.

        Raises:
            ValueError: If metadata.json is not an object.
        """
        dut_id = dut_dir.name
        if dut_id in self._metadata_timing_cache:
            self._metadata_timing_cache.move_to_end(dut_id)
            return self._metadata_timing_cache[dut_id]
        for metadata_name in (".metadata", "metadata"):
            meta_path = dut_dir / metadata_name / "metadata.json"
            if meta_path.exists():
                try:
                    raw = _read_regular_file_bounded(
                        meta_path,
                        MAX_BACKEND_TIMING_CACHE_BYTES // 2,
                    )
                    data = json.loads(raw.decode("utf-8"))
                    if not isinstance(data, dict):
                        raise ValueError("metadata.json is not an object")
                    timing_data = data.get("payload", {}).get("timing_data", {})
                    normalized = (
                        timing_data
                        if isinstance(timing_data, dict) and timing_data
                        else None
                    )
                    self._put_bounded_cache(
                        self._metadata_timing_cache,
                        self._metadata_timing_cache_sizes,
                        dut_id,
                        normalized,
                        serialized_bytes=(
                            self._cache_document_size(normalized)
                            if normalized is not None
                            else 0
                        ),
                        timing_cache=False,
                    )
                    return normalized
                except (json.JSONDecodeError, OSError, UnicodeError, ValueError):
                    pass
        self._put_bounded_cache(
            self._metadata_timing_cache,
            self._metadata_timing_cache_sizes,
            dut_id,
            None,
            serialized_bytes=0,
            timing_cache=False,
        )
        return None

    def _parse_timing_collectors(
        self,
        dut_id: str,
        dut_timing: Optional[Dict],
        metadata_timing: Optional[Dict],
        service_totals: Dict[str, Dict],
    ) -> List[Dict]:
        """
        Parse collector timing from timing.json (dict format) and metadata.json.

        Canonical stage measurements take precedence over legacy metadata,
        which only fills absent stages. Normalize both sources so missing or
        invalid measurements remain unknown. Accumulate collector counts and
        durations into the caller's service totals.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut_timing: Mapping supplying fields for collector timing from
                timing.json (dict format) and metadata.json.
            metadata_timing: Mapping supplying fields for collector timing from
                timing.json (dict format) and metadata.json.
            service_totals: Mapping supplying fields for collector timing from
                timing.json (dict format) and metadata.json.

        Returns:
            The validated ``collectors``.
        """
        collectors: List[Dict] = []
        seen_ids: set = set()

        if dut_timing:
            raw_collectors = dut_timing.get("collectors", {})
            if isinstance(raw_collectors, dict):
                items = raw_collectors.items()
            elif isinstance(raw_collectors, list):
                items = (
                    (c.get("id", ""), c) for c in raw_collectors if isinstance(c, dict)
                )
            else:
                items = iter([])

            for coll_id, coll in items:
                if not isinstance(coll, dict):
                    continue
                seen_ids.add(coll_id)
                group = coll.get("group", coll.get("service", ""))
                dur = float(
                    coll.get(
                        "duration_seconds",
                        coll.get("duration", coll.get("total_time", 0)),
                    )
                    or 0
                )

                normalized_stages = self._collector_stage_timing(coll)

                timing_reference = self._timing_reference(
                    dut_id, str(coll_id or coll.get("id", ""))
                )
                if timing_reference is not None:
                    timing_fields = {"timing_ref": timing_reference}
                else:
                    timing_fields = {
                        "timing": (
                            normalize_timing_artifact_paths(
                                coll.get("timing", {}),
                                self.log_dir,
                                dut_id=dut_id,
                            )
                            if isinstance(coll.get("timing"), dict)
                            else {}
                        ),
                        "artifact_timings": normalize_artifact_timings(
                            coll.get("artifact_timings", []),
                            self.log_dir,
                            dut_id=dut_id,
                        ),
                    }

                collectors.append(
                    {
                        "id": coll_id or coll.get("id", ""),
                        "name": coll.get("name", coll_id),
                        "group": group,
                        "duration": dur,
                        "start_time": coll.get("start_time"),
                        "end_time": coll.get("end_time"),
                        "status": coll.get("status", ""),
                        **timing_fields,
                        "stage_timing": {
                            "validation": normalized_stages.get("validation"),
                            "discovery": normalized_stages.get("discovery"),
                            "execution": normalized_stages.get("execution"),
                            "post_processing": normalized_stages.get("post_processing"),
                        },
                    }
                )

                if group and group not in service_totals:
                    service_totals[group] = {
                        "total_collectors": 0,
                        "total_duration": 0,
                    }
                if group:
                    service_totals[group]["total_collectors"] += 1
                    service_totals[group]["total_duration"] += dur

        if metadata_timing:
            meta_collectors = self._select_timing_collectors(metadata_timing, dut_id)
            for coll_id, coll in meta_collectors.items():
                if not isinstance(coll, dict):
                    continue
                if coll_id in seen_ids:
                    legacy_stages = self._collector_stage_timing(coll)
                    if any(value is not None for value in legacy_stages.values()):
                        for existing in collectors:
                            if existing["id"] == coll_id:
                                for stage, value in legacy_stages.items():
                                    if existing["stage_timing"][stage] is None:
                                        existing["stage_timing"][stage] = value
                                break
                    continue
                dur = float(coll.get("total_time", 0) or 0)
                normalized_stages = self._collector_stage_timing(coll)
                group = coll.get("group", coll.get("service", ""))
                timing_reference = self._timing_reference(dut_id, str(coll_id))
                if timing_reference is not None:
                    timing_fields = {"timing_ref": timing_reference}
                else:
                    timing_fields = {
                        "timing": (
                            normalize_timing_artifact_paths(
                                coll.get("timing", {}),
                                self.log_dir,
                                dut_id=dut_id,
                            )
                            if isinstance(coll.get("timing"), dict)
                            else {}
                        ),
                        "artifact_timings": normalize_artifact_timings(
                            coll.get("artifact_timings", []),
                            self.log_dir,
                            dut_id=dut_id,
                        ),
                    }
                collectors.append(
                    {
                        "id": coll_id,
                        "name": coll.get("name", coll_id),
                        "group": group,
                        "duration": dur,
                        "start_time": coll.get("start_time"),
                        "end_time": coll.get("end_time"),
                        "status": coll.get("status", ""),
                        **timing_fields,
                        "stage_timing": {
                            "validation": normalized_stages.get("validation"),
                            "discovery": normalized_stages.get("discovery"),
                            "execution": normalized_stages.get("execution"),
                            "post_processing": normalized_stages.get("post_processing"),
                        },
                    }
                )
                if group and group not in service_totals:
                    service_totals[group] = {
                        "total_collectors": 0,
                        "total_duration": 0,
                    }
                if group:
                    service_totals[group]["total_collectors"] += 1
                    service_totals[group]["total_duration"] += dur

        return collectors

    def _extract_system_info_from_snapshot(
        self, metadata_dir: Path, dut_dir: Path
    ) -> Dict:
        """
        Project system fields from one bounded, verified set of role sources.

        The caller owns the filesystem worker until this synchronous scope exits.
        Repeated dashboard fields reuse role metadata and artifact resolutions;
        source identity drift invalidates the projection before publication.

        Args:
            metadata_dir: Selected current or legacy DUT metadata directory.
            dut_dir: Descriptor-bound DUT root or explicit offline input root.

        Returns:
            The existing system-information projection with identical field rules.

        Raises:
            SnapshotConsistencyError: If cached source metadata changes.
        """

        try:
            with report_role_snapshot(dut_dir):
                return self._extract_system_info(metadata_dir, dut_dir)
        except ReportRoleSnapshotChangedError as error:
            raise SnapshotConsistencyError(str(error)) from error

    def _extract_system_info(self, metadata_dir: Path, dut_dir: Path) -> Dict:
        """
        Extract optional system identity and dashboard data from collected files.

        Nullable or non-text identity fields in ``metadata.json`` are treated as
        unavailable instead of making report generation emit a failure warning.
        When metadata does not provide a model, the per-DUT runtime output is
        inspected as a compatibility fallback. The method reads only bounded
        files beneath the supplied directories and records diagnostics for
        malformed or unreadable inputs.

        Args:
            metadata_dir: filesystem location used as the metadata dir for this
                operation.
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            A mapping containing optional identity fields, firmware inventory,
            and the compact system view used by the report application.
        """
        info: Dict[str, Any] = {
            "model": None,
            "part_number": None,
            "serial_number": None,
            "firmware": [],
        }

        if metadata_dir.exists():
            meta_path = metadata_dir / "metadata.json"
            if meta_path.exists():
                try:
                    data = self._read_auxiliary_json(meta_path)
                    payload = data.get("payload", {}) if isinstance(data, dict) else {}
                    if isinstance(payload, dict):
                        for info_key, payload_key in (
                            ("model", "PlatformModel"),
                            ("part_number", "PartNumber"),
                            ("serial_number", "SerialNumber"),
                        ):
                            value = payload.get(payload_key)
                            info[info_key] = (
                                value.strip() or None
                                if isinstance(value, str)
                                else None
                            )
                        logger.debug(
                            "System info from metadata.json: model=%s part=%s serial=%s",
                            info["model"],
                            info["part_number"],
                            info["serial_number"],
                        )
                except (
                    json.JSONDecodeError,
                    OSError,
                    UnicodeError,
                    ValueError,
                    RecursionError,
                ) as e:
                    logger.warning(
                        "Failed to read metadata.json in %s: %s",
                        metadata_dir,
                        e,
                    )

        if not info["model"]:
            runtime_path = dut_dir / "nvdebug_runtime_output.txt"
            if runtime_path.exists():
                try:
                    text = _read_regular_file_bounded(
                        runtime_path,
                        MAX_AUXILIARY_JSON_FILE_BYTES,
                    ).decode("utf-8", errors="replace")
                    model_match = re.search(r"Platform Model:\s*(.+)", text)
                    part_match = re.search(r"Part Number:\s*(.+)", text)
                    serial_match = re.search(r"Serial Number:\s*(.+)", text)
                    if model_match:
                        info["model"] = model_match.group(1).strip() or None
                    if part_match:
                        info["part_number"] = part_match.group(1).strip() or None
                    if serial_match:
                        info["serial_number"] = serial_match.group(1).strip() or None

                    if not info["model"]:
                        legacy_match = re.search(
                            r"Identified system as Model:\s*(?P<model>[^,]+)"
                            r",\s*Partno:\s*(?P<part>[^,]+)"
                            r",\s*Serialno:\s*(?P<ser>\S+)",
                            text,
                        )
                        if legacy_match:
                            info["model"] = legacy_match.group("model").strip() or None
                            info["part_number"] = (
                                legacy_match.group("part").strip() or None
                            )
                            info["serial_number"] = (
                                legacy_match.group("ser").strip() or None
                            )

                    logger.debug(
                        "System info from runtime output fallback: %s",
                        info["model"],
                    )
                except OSError as e:
                    logger.warning(
                        "Failed to read runtime output in %s: %s", dut_dir, e
                    )

        info["firmware"] = self._extract_firmware_from_redfish(dut_dir)
        info["system_view"] = self._extract_system_view(dut_dir, info)

        return info

    def _extract_system_view(
        self, dut_dir: Path, system_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract the compact system view used by the dashboard modal.

        The report is generated from collected logs, so every field is optional
        and depends on which collectors were run. Parsers intentionally accept
        both the current collector output names and older command-wrapper files.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            system_info: Mapping supplying fields for extract the compact system
                view used by the dashboard modal.

        Returns:
            A mapping containing the ``bmc``, ``host``, and ``software`` fields.
        """
        firmware = system_info.get("firmware", [])

        host_os_text = self._read_report_role_command_output(
            dut_dir,
            "host_system_snapshot",
            r"\bcat\s+/etc/os-release\b",
            legacy_subdir="host",
        ) or self._read_first_matching_text(dut_dir, ["host/**/*os_release*.txt"])
        host_uname_text = self._read_report_role_command_output(
            dut_dir,
            "host_system_snapshot",
            r"\buname\s+-a\b",
            legacy_subdir="host",
        ) or self._read_first_matching_text(dut_dir, ["host/**/*uname_-a.txt"])
        host_uptime_text = self._read_report_role_command_output(
            dut_dir,
            "host_system_snapshot",
            r"\buptime\b",
            legacy_subdir="host",
        ) or self._read_first_matching_text(dut_dir, ["host/**/*uptime.txt"])
        host_top_text = self._read_report_role_command_output(
            dut_dir,
            "host_system_snapshot",
            r"\btop\b",
            legacy_subdir="host",
        ) or self._read_first_matching_text(dut_dir, ["host/**/*top_-bn1.txt"])
        host_free_text = (
            self._read_report_role_command_output(
                dut_dir,
                "host_system_snapshot",
                r"\bfree\s+-m\b",
                legacy_subdir="host",
            )
            or self._read_report_role_command_output(
                dut_dir,
                "host_memory_snapshot",
                r"\bfree\s+-m\b",
                legacy_subdir="host",
            )
            or self._read_first_matching_text(
                dut_dir,
                ["host/**/*free_-m.txt", "host/**/*free_m.txt"],
            )
        )
        host_meminfo_text = self._read_report_role_command_output(
            dut_dir,
            "host_memory_snapshot",
            r"/proc/meminfo\b",
            legacy_subdir="host",
        ) or self._read_first_matching_text(dut_dir, ["host/**/*meminfo.txt"])
        host_df_text = self._read_report_role_command_output(
            dut_dir,
            "host_system_snapshot",
            r"\bdf\s+-kh\b",
            legacy_subdir="host",
        ) or self._read_first_matching_text(dut_dir, ["host/**/*df_-kh.txt"])
        nvidia_smi_text = (
            self._read_report_role_command_output(
                dut_dir,
                "host_gpu_runtime",
                r"\bnvidia-smi\s+-q\b",
                legacy_subdir="host",
            )
            or self._read_report_role_command_output(
                dut_dir,
                "host_gpu_runtime",
                r"\bnvidia-smi\s*$",
                legacy_subdir="host",
            )
            or self._read_first_matching_text(
                dut_dir,
                ["host/**/*nvidia-smi*.txt", "host/**/*nvidia_smi*.txt"],
            )
        )
        dcgmi_text = self._read_report_role_command_output(
            dut_dir,
            "host_gpu_runtime",
            r"\bdcgmi\s+--version\b",
            legacy_subdir="host",
        ) or self._read_first_matching_text(dut_dir, ["host/**/*dcgmi*.txt"])
        dmidecode_text = self._read_report_role_command_output(
            dut_dir,
            "host_smbios",
            r"\bdmidecode\s*$",
            legacy_subdir="host",
        ) or self._read_first_matching_text(dut_dir, ["host/**/*dmidecode.txt"])

        bmc_os_text = self._read_report_role_command_output(
            dut_dir, "bmc_os_identity", r"\bcat\s+\S*os-release\b"
        ) or self._read_first_matching_text(
            dut_dir,
            ["ssh/**/*bmc_stack_info.txt", "ssh/**/*os-release*.txt"],
        )
        bmc_uname_text = self._read_report_role_command_output(
            dut_dir, "bmc_resource_snapshot", r"\buname\s+-a\b"
        ) or self._read_first_matching_text(dut_dir, ["ssh/**/*uname*.txt"])
        bmc_uptime_text = self._read_report_role_command_output(
            dut_dir, "bmc_uptime", r"\buptime\b"
        ) or self._read_first_matching_text(dut_dir, ["ssh/**/*uptime*.txt"])
        bmc_top_text = self._read_report_role_command_output(
            dut_dir, "bmc_resource_snapshot", r"\btop\b"
        ) or self._read_first_matching_text(dut_dir, ["ssh/**/*top*.txt"])
        bmc_proc_stat_text = self._read_first_matching_text(
            dut_dir,
            [
                "ssh/**/*proc_stat_cpu_sample*.txt",
            ],
        ) or self._read_report_role_command_output(
            dut_dir, "bmc_resource_snapshot", r"/proc/stat"
        )
        bmc_meminfo_text = self._read_report_role_command_output(
            dut_dir, "bmc_resource_snapshot", r"/proc/meminfo"
        ) or self._read_first_matching_text(dut_dir, ["ssh/**/*meminfo*.txt"])
        bmc_df_text = self._read_report_role_command_output(
            dut_dir, "bmc_resource_snapshot", r"\bdf\s+-kh\b"
        ) or self._read_first_matching_text(dut_dir, ["ssh/**/*df*.txt"])

        host_os = self._parse_os_release_name(host_os_text)
        host_kernel = self._parse_uname_kernel(host_uname_text)
        bmc_version = self._extract_bmc_version(dut_dir, firmware, bmc_os_text)

        return {
            "bmc": {
                "version": bmc_version,
                "os": self._parse_os_release_name(bmc_os_text),
                "kernel": self._parse_uname_kernel(bmc_uname_text),
                "uptime": self._parse_uptime(bmc_uptime_text),
                "utilization": self._parse_utilization(
                    top_text=bmc_top_text,
                    proc_stat_text=bmc_proc_stat_text,
                    free_text=None,
                    meminfo_text=bmc_meminfo_text,
                    df_text=bmc_df_text,
                ),
            },
            "host": {
                "os": host_os,
                "kernel": host_kernel,
                "uptime": self._parse_uptime(host_uptime_text),
                "utilization": self._parse_utilization(
                    top_text=host_top_text,
                    free_text=host_free_text,
                    meminfo_text=host_meminfo_text,
                    df_text=host_df_text,
                ),
            },
            "software": {
                "host_os": host_os,
                "kernel_version": host_kernel,
                "bmc_version": bmc_version,
                "sbios": self._parse_bios_version(dmidecode_text),
                "rm_driver_version": self._parse_nvidia_field(
                    nvidia_smi_text, "driver"
                ),
                "cuda_driver_version": self._parse_nvidia_field(
                    nvidia_smi_text, "cuda"
                ),
                "dcgm_version": self._parse_dcgm_version(dcgmi_text),
            },
        }

    def _read_text_file(self, path: Path) -> Optional[str]:
        """
        Read text file.

        After applying local validation, the function forwards ``path`` to
        ``decode`` and preserves its return and exception contract. Parsing or
        I/O must finish before the validated representation is made available to
        the caller.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The canonical text file text, or ``None`` when the requested value
            is unavailable.
        """
        try:
            return _read_regular_file_bounded(
                path,
                MAX_AUXILIARY_JSON_FILE_BYTES,
            ).decode("utf-8", errors="replace")
        except (OSError, ValueError):
            return None

    def _read_first_matching_text(
        self, dut_dir: Path, patterns: List[str]
    ) -> Optional[str]:
        """
        Read first matching text.

        The implementation uses ``dut_dir`` and ``patterns`` to read first
        matching text. Parsing or I/O must finish before the validated
        representation is made available to the caller.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            patterns: Entries supplied as ``patterns`` without transferring
                container ownership.

        Returns:
            The validated ``text``, or ``None`` when no value qualifies.
        """
        for pattern in patterns:
            if "/**/" in pattern:
                root_name, name_pattern = pattern.split("/**/", 1)
                root = dut_dir / root_name
                try:
                    candidates = self._bounded_descendant_regular_paths(
                        root,
                        suffixes={".txt"},
                        maximum_paths=self._max_auxiliary_json_files,
                    )
                except (OSError, ValueError):
                    return None
                candidates = [
                    path for path in candidates if Path(path.name).match(name_pattern)
                ]
            else:
                try:
                    candidates = self._bounded_descendant_regular_paths(
                        dut_dir,
                        suffixes={".txt"},
                        maximum_paths=self._max_auxiliary_json_files,
                    )
                except (OSError, ValueError):
                    return None
                candidates = [
                    path
                    for path in candidates
                    if path.relative_to(dut_dir).match(pattern)
                ]
            for path in candidates:
                text = self._read_text_file(path)
                if text:
                    return text
        return None

    def _read_report_role_command_output(
        self,
        dut_dir: Path,
        report_role: str,
        command_pattern: str,
        *,
        legacy_subdir: str = "ssh",
    ) -> Optional[str]:
        """
        Read command output from the collector assigned to a report role.

        Legacy bundles predate report_role metadata. Command headers are
        semantic evidence and avoid coupling the report to an old ID.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            report_role: Text supplied as report role in the format accepted by
                this function.
            command_pattern: Text supplied as command pattern in the format
                accepted by this function.
            legacy_subdir: Text supplied as legacy subdir in the format accepted
                by this function.

        Returns:
            The validated ``text``, or ``None`` when no value qualifies.
        """
        command_re = re.compile(command_pattern)
        role_paths = report_role_artifact_paths(
            dut_dir,
            report_role,
            suffixes={".txt", ".log"},
        )
        candidates = role_paths
        if not candidates:
            # Legacy bundles predate report_role metadata. Command headers are
            # semantic evidence and avoid coupling the report to an old ID.
            service_dir = dut_dir / legacy_subdir
            try:
                candidates = self._bounded_descendant_regular_paths(
                    service_dir,
                    suffixes={".txt"},
                    maximum_paths=self._max_auxiliary_json_files,
                )
            except (OSError, ValueError):
                candidates = []
        for path in candidates:
            text = self._read_text_file(path)
            if not text:
                continue
            command_match = re.search(r"^Command:\s*(.+)$", text, re.MULTILINE)
            if command_match and command_re.search(command_match.group(1)):
                return text
        return None

    def _command_output_body(self, text: Optional[str]) -> str:
        """
        Return the command output body.

        The implementation uses ``text`` to produce the command output body.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical command output body text.
        """
        if not text:
            return ""
        output_marker = "\nOutput:\n"
        if output_marker in text:
            body = text.split(output_marker, 1)[1]
            if "\nError:\n" in body:
                body = body.split("\nError:\n", 1)[0]
            return body.strip()
        return text.strip()

    def _bounded_system_info_lines(self, text: Optional[str]) -> List[str]:
        """
        Return bounded lines for human-readable system-info parsers.

        Collector output is untrusted and may contain one multi-megabyte line.
        Keeping a shared character, line-length, and line-count envelope makes
        every downstream parser deterministic even when a device emits hostile
        input.

        Args:
            text: Optional collector output containing human-readable system
                information.

        Returns:
            Bounded output lines suitable for the system-information parsers.
        """

        body = self._command_output_body(text)[:MAX_SYSTEM_INFO_PARSE_BODY_CHARS]
        return [
            line[:MAX_SYSTEM_INFO_PARSE_LINE_CHARS]
            for line in body.splitlines()[:MAX_SYSTEM_INFO_PARSE_LINES]
        ]

    def _parse_os_release_name(self, text: Optional[str]) -> Optional[str]:
        """
        Parse os release name.

        The implementation uses ``text`` to parse os release name. Parsing or
        I/O must finish before the validated representation is made available to
        the caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            Whether the os release name operation succeeds.
        """
        values = self._parse_key_value_text(self._command_output_body(text))
        return (
            values.get("PRETTY_NAME")
            or values.get("NAME")
            or values.get("VERSION")
            or values.get("VERSION_ID")
        )

    def _parse_key_value_text(self, text: str) -> Dict[str, str]:
        """
        Parse key value text.

        The implementation uses ``text`` to parse key value text. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The validated ``values``.
        """
        values: Dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
        return values

    def _parse_uname_kernel(self, text: Optional[str]) -> Optional[str]:
        """
        Parse uname kernel.

        The implementation uses ``text`` to parse uname kernel. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical uname kernel text, or ``None`` when the requested
            value is unavailable.
        """
        for line in self._bounded_system_info_lines(text):
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[0].lower() == "linux":
                return f"{parts[0]} {parts[2]}"
            return line
        return None

    def _parse_uptime(self, text: Optional[str]) -> Optional[str]:
        """
        Parse uptime.

        The implementation uses ``text`` to parse uptime. Parsing or I/O must
        finish before the validated representation is made available to the
        caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical uptime text, or ``None`` when the requested value is
            unavailable.
        """
        for line in self._bounded_system_info_lines(text):
            line = line.strip()
            if not line:
                continue
            lower = line.casefold()
            marker = " up "
            marker_index = lower.find(marker)
            if marker_index >= 0:
                uptime_text = line[marker_index + len(marker) :]
            elif lower.startswith("up "):
                uptime_text = line[3:]
            else:
                return line
            fragments = [fragment.strip() for fragment in uptime_text.split(",")]
            for index, fragment in enumerate(fragments):
                words = fragment.casefold().split()
                is_user_count = (
                    len(words) == 2
                    and words[0].isdigit()
                    and words[1] in {"user", "users"}
                )
                if is_user_count or fragment.casefold().startswith("load average"):
                    parsed = ", ".join(fragments[:index]).strip()
                    return parsed or None
            return line
        return None

    def _parse_utilization(
        self,
        *,
        top_text: Optional[str],
        proc_stat_text: Optional[str] = None,
        free_text: Optional[str],
        meminfo_text: Optional[str],
        df_text: Optional[str],
    ) -> Dict[str, Optional[str]]:
        """
        Parse utilization.

        The implementation uses ``top_text``, ``proc_stat_text``, ``free_text``,
        ``meminfo_text``, and ``df_text`` to parse utilization. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            top_text: Text supplied as top text in the format accepted by this
                function.
            proc_stat_text: Optional proc stat text; ``None`` selects the
                function's default behavior.
            free_text: Text supplied as free text in the format accepted by this
                function.
            meminfo_text: Text supplied as meminfo text in the format accepted
                by this function.
            df_text: Text supplied as df text in the format accepted by this
                function.

        Returns:
            A mapping containing the ``cpu``, ``memory``, and ``disk`` fields.
        """
        return {
            "cpu": self._parse_cpu_from_proc_stat(proc_stat_text)
            or self._parse_cpu_from_top(top_text),
            "memory": self._parse_memory_from_free(free_text)
            or self._parse_memory_from_meminfo(meminfo_text),
            "disk": self._parse_disk_from_df(df_text),
        }

    def _parse_cpu_from_proc_stat(self, text: Optional[str]) -> Optional[str]:
        """
        Parse CPU from proc stat.

        The implementation uses ``text`` to parse CPU from proc stat. Parsing or
        I/O must finish before the validated representation is made available to
        the caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical CPU from proc stat text, or ``None`` when the
            requested value is unavailable.
        """
        body = "\n".join(self._bounded_system_info_lines(text))
        samples: List[Tuple[float, float]] = []

        for line in body.splitlines():
            parts = line.strip().split()
            if len(parts) < 5 or parts[0] != "cpu":
                continue
            try:
                values = [float(part) for part in parts[1:]]
            except ValueError:
                continue
            idle = values[3] + (values[4] if len(values) > 4 else 0.0)
            total = sum(values)
            samples.append((idle, total))

        if len(samples) < 2:
            return None

        first_idle, first_total = samples[0]
        last_idle, last_total = samples[-1]
        total_delta = last_total - first_total
        idle_delta = last_idle - first_idle
        if total_delta <= 0 or idle_delta < 0:
            return None

        used = (total_delta - idle_delta) / total_delta * 100.0
        used = min(100.0, max(0.0, used))
        return f"{used:.1f}%"

    def _parse_cpu_from_top(self, text: Optional[str]) -> Optional[str]:
        """
        Parse CPU from top.

        The implementation uses ``text`` to parse CPU from top. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical CPU from top text, or ``None`` when the requested
            value is unavailable.
        """
        for line in self._bounded_system_info_lines(text):
            stripped = line.strip()
            lower = stripped.lower()
            if "%cpu" not in lower and not lower.startswith("cpu:"):
                continue

            percentages: Dict[str, float] = {}
            for match in re.finditer(
                r"(?<![\d.])(\d{1,3}(?:\.\d{1,6})?)\s*%?\s*" r"(idle|id|usr|sys)\b",
                lower,
            ):
                value = float(match.group(1))
                if value <= 100.0:
                    label = "idle" if match.group(2) == "id" else match.group(2)
                    percentages.setdefault(label, value)

            if "idle" in percentages:
                used = max(0.0, 100.0 - percentages["idle"])
                return f"{used:.1f}%"

            if "usr" in percentages or "sys" in percentages:
                used = percentages.get("usr", 0.0) + percentages.get("sys", 0.0)
                return f"{used:.1f}%"
        return None

    def _parse_memory_from_free(self, text: Optional[str]) -> Optional[str]:
        """
        Parse memory from free.

        The implementation uses ``text`` to parse memory from free. Parsing or
        I/O must finish before the validated representation is made available to
        the caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical memory from free text, or ``None`` when the requested
            value is unavailable.
        """
        body = self._command_output_body(text)
        for line in body.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0].rstrip(":").lower() == "mem":
                try:
                    total = float(parts[1])
                    used = float(parts[2])
                except ValueError:
                    return None
                if total <= 0:
                    return None
                return f"{used / total * 100:.1f}% ({used:.0f}/{total:.0f} MB)"
        return None

    def _parse_memory_from_meminfo(self, text: Optional[str]) -> Optional[str]:
        """
        Parse memory from meminfo.

        The implementation uses ``text`` to parse memory from meminfo. Parsing
        or I/O must finish before the validated representation is made available
        to the caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical memory from meminfo text, or ``None`` when the
            requested value is unavailable.
        """
        body = self._command_output_body(text)
        values: Dict[str, float] = {}
        for line in body.splitlines():
            match = re.match(r"^(MemTotal|MemAvailable|MemFree):\s+(\d+)\s+kB", line)
            if match:
                values[match.group(1)] = float(match.group(2))
        total = values.get("MemTotal")
        available = values.get("MemAvailable", values.get("MemFree"))
        if not total or available is None or total <= 0:
            return None
        used = max(0.0, total - available)
        return f"{used / total * 100:.1f}% ({self._format_kib(used)}/{self._format_kib(total)})"

    def _parse_disk_from_df(self, text: Optional[str]) -> Optional[str]:
        """
        Parse disk from df.

        The implementation uses ``text`` to parse disk from df. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical disk from df text, or ``None`` when the requested
            value is unavailable.
        """
        body = self._command_output_body(text)
        candidates: List[Tuple[int, str]] = []
        for line in body.splitlines():
            parts = line.split()
            if len(parts) < 6 or not parts[-2].endswith("%"):
                continue
            try:
                used_pct = int(parts[-2].rstrip("%"))
            except ValueError:
                continue
            mount = parts[-1]
            if mount == "/":
                return f"{used_pct}% (/)"
            candidates.append((used_pct, mount))
        if candidates:
            used_pct, mount = max(candidates, key=lambda item: item[0])
            return f"{used_pct}% ({mount})"
        return None

    def _format_kib(self, value: float) -> str:
        """
        Format kib.

        The implementation uses ``value`` to format kib. The source value keeps
        its ownership while the normalized representation is returned
        separately.

        Args:
            value: Numeric value used while the operation performs bounded
                accounting.

        Returns:
            The canonical kib text.
        """
        mib = value / 1024
        if mib >= 1024:
            return f"{mib / 1024:.1f} GB"
        return f"{mib:.0f} MB"

    def _parse_bios_version(self, text: Optional[str]) -> Optional[str]:
        """
        Parse bios version.

        The implementation uses ``text`` to parse bios version. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical bios version text, or ``None`` when the requested
            value is unavailable.
        """
        in_bios_section = False
        fallback = None
        for line in self._bounded_system_info_lines(text):
            stripped = line.strip()
            if "BIOS Information" in stripped:
                in_bios_section = True
                continue
            if not stripped.startswith("Version:"):
                continue
            version = stripped.partition(":")[2].strip()
            if not version:
                continue
            if in_bios_section:
                return version
            if fallback is None:
                fallback = version
        return fallback

    def _parse_nvidia_field(self, text: Optional[str], field: str) -> Optional[str]:
        """
        Parse nvidia field.

        After applying local validation, the function forwards ``text`` and
        ``field`` to ``strip`` and preserves its return and exception contract.
        Parsing or I/O must finish before the validated representation is made
        available to the caller.

        Args:
            text: Text supplied as text in the format accepted by this function.
            field: Text supplied as field in the format accepted by this
                function.

        Returns:
            The canonical nvidia field text, or ``None`` when the requested
            value is unavailable.
        """
        body = self._command_output_body(text)
        if not body:
            return None
        if field == "driver":
            patterns = [
                r"Driver Version\s*:\s*([^\n|]+)",
                r"Driver Version:\s*([^\s|]+)",
            ]
        else:
            patterns = [
                r"CUDA Version\s*:\s*([^\n|]+)",
                r"CUDA Version:\s*([^\s|]+)",
            ]
        for pattern in patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(1).strip()
        return None

    def _parse_dcgm_version(self, text: Optional[str]) -> Optional[str]:
        """
        Parse dcgm version.

        The implementation uses ``text`` to parse dcgm version. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical dcgm version text, or ``None`` when the requested
            value is unavailable.
        """
        body = self._command_output_body(text)
        if not body:
            return None
        if re.search(r"not found|not installed|No such file", body, re.IGNORECASE):
            return "DCGM not installed and/or enabled"
        for pattern in (
            r"DCGM\s+Version\s*:?\s*([^\n]+)",
            r"dcgmi\s+version\s*:?\s*([^\n]+)",
            r"version\s*:?\s*([^\n]+)",
        ):
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return body.splitlines()[0].strip() if body.splitlines() else None

    def _extract_bmc_version(
        self,
        dut_dir: Path,
        firmware: List[Dict[str, Any]],
        bmc_os_text: Optional[str],
    ) -> Optional[str]:
        """
        Extract BMC version.

        The implementation uses ``dut_dir``, ``firmware``, and ``bmc_os_text``
        to extract BMC version.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            firmware: Mapping supplying fields for extract BMC version.
            bmc_os_text: Text supplied as BMC os text in the format accepted by
                this function.

        Returns:
            The canonical BMC version text, or ``None`` when the requested value
            is unavailable.
        """
        manager_version = self._extract_manager_firmware_version(dut_dir)
        if manager_version:
            return manager_version

        for item in firmware:
            name = " ".join(
                str(item.get(key, "")) for key in ("component", "name", "id")
            )
            if re.search(r"\bbmc\b", name, re.IGNORECASE) and item.get("version"):
                return str(item["version"])

        os_values = self._parse_key_value_text(self._command_output_body(bmc_os_text))
        return (
            os_values.get("IMAGE_VERSION")
            or os_values.get("VERSION_ID")
            or os_values.get("VERSION")
        )

    def _extract_manager_firmware_version(self, dut_dir: Path) -> Optional[str]:
        """
        Extract manager firmware version.

        Legacy bundles predate report roles; retain compatibility through
        semantic artifact names rather than the collector IDs of the day.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            The canonical manager firmware version text, or ``None`` when the
            requested value is unavailable.
        """
        paths = report_role_artifact_paths(
            dut_dir,
            "manager_inventory",
            suffixes={".json"},
        )
        if not paths:
            # Legacy bundles predate report roles; retain compatibility through
            # semantic artifact names rather than the collector IDs of the day.
            redfish_dir = dut_dir / "redfish"
            try:
                paths = self._bounded_descendant_json_paths(
                    redfish_dir,
                    name_pattern=re.compile(
                        r"(?:manager_(?:info|expand_query)|(?:^|_)expand_query)",
                        re.IGNORECASE,
                    ),
                    maximum_paths=self._max_auxiliary_json_files,
                )
            except (OSError, ValueError):
                paths = []
        for path in paths:
            try:
                data = self._read_auxiliary_json(path)
            except (
                json.JSONDecodeError,
                OSError,
                UnicodeError,
                ValueError,
                RecursionError,
            ):
                continue
            for item in self._walk_json_dicts(data):
                version = item.get("FirmwareVersion")
                if not version:
                    continue
                name = " ".join(str(item.get(key, "")) for key in ("Id", "Name"))
                if not name or re.search(r"\bbmc\b|manager", name, re.IGNORECASE):
                    return str(version)
        return None

    def _walk_json_dicts(self, value: Any):
        """
        Walk JSON dicts.

        The implementation uses ``value`` to walk JSON dicts.

        Args:
            value: Value evaluated while performing walk JSON dicts.

        Yields:
            Each walk JSON dicts admitted by the operation, in deterministic
            iteration order.
        """
        stack: List[Tuple[Any, int]] = [(value, 0)]
        visited = 0
        while stack:
            current, depth = stack.pop()
            visited += 1
            if visited > MAX_AUXILIARY_JSON_NODES or depth > MAX_AUXILIARY_JSON_DEPTH:
                return
            if isinstance(current, dict):
                yield current
                stack.extend((child, depth + 1) for child in current.values())
            elif isinstance(current, list):
                stack.extend((child, depth + 1) for child in current)

    def _extract_firmware_from_redfish(
        self, dut_dir: Path, collector_definitions: Any = None
    ) -> List[Dict]:
        """
        Extract firmware from Redfish.

        Old bundles have no report_role metadata. Restrict the fallback to
        semantically named firmware-inventory artifacts, then detect format from
        JSON content instead of collector IDs.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            collector_definitions: Optional collector definitions; ``None``
                selects the function's default behavior.

        Returns:
            The firmware from Redfish returned in operation-defined order.
        """
        role_parsers = (
            ("firmware_inventory_table", self._parse_firmware_table),
            ("firmware_inventory_expanded", self._parse_firmware_members),
            ("firmware_inventory_references", self._parse_firmware_references),
        )
        for report_role, parser in role_parsers:
            role_paths = report_role_artifact_paths(
                dut_dir,
                report_role,
                collector_definitions=collector_definitions,
                suffixes={".json"},
            )
            firmware_items = self._parse_firmware_paths(role_paths, parser)
            if firmware_items:
                logger.debug(
                    "Read %d firmware items from report role %s",
                    len(firmware_items),
                    report_role,
                )
                return firmware_items

        # Old bundles have no report_role metadata. Restrict the fallback to
        # semantically named firmware-inventory artifacts, then detect format
        # from JSON content instead of collector IDs.
        redfish_dir = dut_dir / "redfish"
        try:
            legacy_paths = self._bounded_descendant_json_paths(
                redfish_dir,
                name_pattern=re.compile(r"firmware_inventory", re.IGNORECASE),
                maximum_paths=self._max_auxiliary_json_files,
            )
        except (OSError, ValueError):
            legacy_paths = []
        for _, parser in role_parsers:
            firmware_items = self._parse_firmware_paths(legacy_paths, parser)
            if firmware_items:
                return firmware_items
        return []

    def _parse_firmware_paths(self, paths, parser) -> List[Dict[str, Any]]:
        """
        Parse firmware paths.

        The implementation uses ``paths`` and ``parser`` to parse firmware
        paths. Parsing or I/O must finish before the validated representation is
        made available to the caller.

        Args:
            paths: Filesystem locations processed in caller-provided order.
            parser: Parser consumed while the function attempts to parse
                firmware paths.

        Returns:
            The validated ``items``.
        """
        items: List[Dict[str, Any]] = []
        for path_index, path in enumerate(paths):
            if path_index >= self._max_auxiliary_json_files:
                break
            try:
                payload = self._read_auxiliary_json(path)
            except (
                json.JSONDecodeError,
                OSError,
                UnicodeError,
                ValueError,
                RecursionError,
            ) as exc:
                logger.warning("Error reading firmware data from %s: %s", path, exc)
                continue
            parsed = parser(payload)
            remaining = MAX_AUXILIARY_RESULT_ITEMS - len(items)
            if remaining <= 0:
                break
            items.extend(parsed[:remaining])
        return items

    @staticmethod
    def _parse_firmware_table(payload: Any) -> List[Dict[str, Any]]:
        """
        Parse firmware table.

        The implementation uses ``payload`` to parse firmware table. Parsing or
        I/O must finish before the validated representation is made available to
        the caller.

        Args:
            payload: Entries supplied as ``payload`` and processed in
                caller-provided order.

        Returns:
            The firmware table returned in operation-defined order.
        """
        if not isinstance(payload, list):
            return []
        items = []
        for item in payload:
            if not isinstance(item, dict) or not item.get("Id"):
                continue
            normalized = {
                "id": item.get("Id", ""),
                "name": item.get("Name", item.get("Id", "")),
                "version": item.get("Version", ""),
            }
            for source, target in (
                ("Description", "description"),
                ("Manufacturer", "manufacturer"),
                ("Status", "status"),
            ):
                if source in item:
                    normalized[target] = item[source]
            items.append(normalized)
        return items

    @staticmethod
    def _parse_firmware_members(payload: Any) -> List[Dict[str, Any]]:
        """
        Parse firmware members.

        The implementation uses ``payload`` to parse firmware members. Parsing
        or I/O must finish before the validated representation is made available
        to the caller.

        Args:
            payload: Payload object whose ``get`` state is read while performing
                firmware members.

        Returns:
            The validated ``items``.
        """
        members = payload.get("Members", []) if isinstance(payload, dict) else []
        items = []
        for member in members:
            if not isinstance(member, dict) or not member.get("Id"):
                continue
            normalized = {
                "id": member.get("Id", ""),
                "name": member.get("Name", member.get("Id", "")),
                "version": member.get("Version", ""),
            }
            for source, target in (
                ("Description", "description"),
                ("Manufacturer", "manufacturer"),
                ("Status", "status"),
            ):
                if source in member:
                    normalized[target] = member[source]
            items.append(normalized)
        return items

    @staticmethod
    def _parse_firmware_references(payload: Any) -> List[Dict[str, Any]]:
        """
        Parse firmware references.

        The implementation uses ``payload`` to parse firmware references.
        Parsing or I/O must finish before the validated representation is made
        available to the caller.

        Args:
            payload: Payload object whose ``get`` state is read while performing
                firmware references.

        Returns:
            The validated ``items``.
        """
        members = payload.get("Members", []) if isinstance(payload, dict) else []
        items = []
        for member in members:
            if not isinstance(member, dict) or not member.get("@odata.id"):
                continue
            firmware_id = str(member["@odata.id"]).rstrip("/").split("/")[-1]
            items.append({"id": firmware_id, "name": firmware_id, "version": ""})
        return items

    def _read_dependency_check(self, dut_dir: Path, dut_id: str) -> Optional[Dict]:
        """
        Read dependency check data from .metadata/dependency_check.json.

        Structure: {"collectors": {"R1": {"name": "...", "dependencies": [...]},
        ...}}

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing dependency check, or ``None`` when the
            requested value is unavailable.
        """
        for metadata_name in (".metadata", "metadata"):
            dep_path = dut_dir / metadata_name / "dependency_check.json"
            if dep_path.exists():
                break
        else:
            return None

        try:
            data = self._read_auxiliary_json(dep_path)
        except (
            json.JSONDecodeError,
            OSError,
            UnicodeError,
            ValueError,
            RecursionError,
        ) as e:
            logger.warning(
                "Failed to read dependency_check.json for DUT %s: %s",
                dut_id,
                e,
            )
            return None

        collectors_data = data.get("collectors", {}) if isinstance(data, dict) else {}
        if not isinstance(collectors_data, dict) or not collectors_data:
            return None

        collectors = []
        for collector_id, cinfo in collectors_data.items():
            if not isinstance(cinfo, dict):
                continue
            deps = cinfo.get("dependencies", [])
            collectors.append(
                {
                    "collector_id": collector_id,
                    "name": cinfo.get("name", collector_id),
                    "dependencies": deps if isinstance(deps, list) else [],
                }
            )

        if collectors:
            logger.debug(
                "Read %d dependency checks for DUT %s", len(collectors), dut_id
            )
        return {"dut_id": dut_id, "collectors": collectors} if collectors else None

    def _get_dut_execution_time(self, metadata_dir: Path, dut_dir: Path) -> float:
        """
        Return DUT execution time.

        The implementation uses ``metadata_dir`` and ``dut_dir`` to produce DUT
        execution time.

        Args:
            metadata_dir: filesystem location used as the metadata dir for this
                operation.
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            The numeric DUT execution time value.
        """
        for metadata_name in (".metadata", "metadata"):
            timing_path = dut_dir / metadata_name / "timing.json"
            if metadata_name == ".metadata":
                try:
                    data = self._read_terminal_timing(dut_dir.name)
                except SnapshotArtifactFormatError:
                    if self._terminal_snapshot_generation is not None:
                        raise
                    data = None
                if data is None:
                    continue
                try:
                    overall = data.get("overall", {})
                    if isinstance(overall, dict) and overall:
                        return float(
                            overall.get(
                                "wall_clock_duration_seconds",
                                overall.get("duration_seconds", 0),
                            )
                            or 0
                        )
                    return float(
                        data.get("total_duration", data.get("duration", 0)) or 0
                    )
                except (TypeError, ValueError):
                    continue
            if not timing_path.exists():
                continue
            try:
                data = self._read_auxiliary_json(
                    timing_path,
                    maximum_bytes=MAX_TIMING_BYTES,
                )
                overall = data.get("overall", {}) if isinstance(data, dict) else {}
                if isinstance(overall, dict) and overall:
                    return float(
                        overall.get(
                            "wall_clock_duration_seconds",
                            overall.get("duration_seconds", 0),
                        )
                        or 0
                    )
                return float(data.get("total_duration", data.get("duration", 0)) or 0)
            except (
                json.JSONDecodeError,
                OSError,
                UnicodeError,
                ValueError,
                RecursionError,
                TypeError,
            ):
                pass

        summary_path = dut_dir / "Execution_Summary_Report.txt"
        if summary_path.exists():
            try:
                text = _read_regular_file_bounded(
                    summary_path,
                    MAX_AUXILIARY_JSON_FILE_BYTES,
                ).decode("utf-8")
                for line in text.splitlines():
                    stripped = line.strip()
                    if "\t" in line or not re.match(
                        r"^(?:Log collection took\b|Total execution time:)",
                        stripped,
                        re.IGNORECASE,
                    ):
                        continue
                    duration_matches = re.findall(
                        r"(\d+(?:\.\d+)?)\s*(?:seconds|s)\b",
                        stripped,
                        re.IGNORECASE,
                    )
                    if duration_matches:
                        # Parenthetical totals follow human-readable minute/hour
                        # forms, so the final seconds value is authoritative.
                        return float(duration_matches[-1])
            except OSError:
                pass

        return 0.0

    def _get_baseboard(self, dut_dir: Path) -> str:
        """
        Get baseboard from DUT config.

        After applying local validation, the function forwards ``dut_dir`` to
        ``self._read_dut_config_field`` and preserves its return and exception
        contract.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            The canonical baseboard text.
        """
        return self._read_dut_config_field(dut_dir, "baseboard", "")

    def _get_node_type(self, dut_dir: Path) -> str:
        """
        Get node type from DUT config.

        After applying local validation, the function forwards ``dut_dir`` to
        ``self._read_dut_config_field`` and preserves its return and exception
        contract.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            The canonical node type text.
        """
        return self._read_dut_config_field(dut_dir, "NodeType", "Compute")

    def _get_bmc_ip(self, dut_dir: Path) -> str:
        """
        Get BMC IP from DUT config.

        After applying local validation, the function forwards ``dut_dir`` to
        ``self._read_dut_config_field`` and preserves its return and exception
        contract.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            The canonical BMC IP text.
        """
        return self._read_dut_config_field(dut_dir, "BMC_IP", "")

    def _read_dut_config_field(self, dut_dir: Path, field: str, default: str) -> str:
        """
        Read a field from the DUT's dut_config.json.

        The implementation uses ``dut_dir``, ``field``, and ``default`` to read
        a field from the DUT's dut_config.json. Parsing or I/O must finish
        before the validated representation is made available to the caller.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.
            field: Text supplied as field in the format accepted by this
                function.
            default: Fallback used when the requested value is absent or
                invalid.

        Returns:
            The canonical DUT config field text.
        """
        config_path = dut_dir / "dut_config.json"
        if config_path.exists():
            try:
                data = self._read_auxiliary_json(config_path)
                if isinstance(data, dict):
                    return str(data.get(field, default))
            except (
                json.JSONDecodeError,
                OSError,
                UnicodeError,
                ValueError,
                RecursionError,
            ):
                pass
        return default

    def _has_runtime_failure_outcome(self) -> bool:
        """
        Whether the tracker records an authoritative runtime failure.

        The only result-less path is the explicitly versioned receipt-less
        compatibility reader. It may project a historical flat outcome but can
        never feed that value back into a canonical RunResult.

        Returns:
            Whether the whether the tracker records an authoritative runtime
            failure operation succeeds.
        """
        result = self._read_run_result()
        if result is not None:
            return result.runtime_status.value == "failed"
        # The only result-less path is the explicitly versioned receipt-less
        # compatibility reader. It may project a historical flat outcome but
        # can never feed that value back into a canonical RunResult.
        return self._read_run_outcome().get("status") == "runtime_failed"

    def _calculate_dir_size(self, directory: Path) -> int:
        """
        Calculate total size of files in a directory.

        The implementation uses ``directory`` to calculate total size of files
        in a directory. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            directory: filesystem location used as the directory for this
                operation.

        Returns:
            The validated ``total``.
        """
        total = 0
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            for f in files:
                try:
                    total += (Path(root) / f).stat().st_size
                except OSError:
                    pass
        return total

    def _read_run_outcome(self) -> Dict[str, Any]:
        """
        Return only a one-way compatibility adapter from canonical truth.

        Receipt-less readers may consume historical bundles that predate the
        canonical result. Current-run manifests never take this branch.

        Returns:
            A mapping containing run outcome.
        """

        result = self._read_run_result()
        if result is not None:
            document = self._read_terminal_status()
            metadata = (
                document.get("metadata", {}) if isinstance(document, dict) else {}
            )
            persisted = (
                metadata.get("run_outcome", {}) if isinstance(metadata, dict) else {}
            )
            return project_legacy_run_outcome(result, domain_hint=persisted)
        # Receipt-less readers may consume historical bundles that predate the
        # canonical result. Current-run manifests never take this branch.
        try:
            document = self._read_terminal_status()
        except SnapshotArtifactFormatError:
            if self._terminal_snapshot_generation is not None:
                raise
            return {}
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {}
        if document is None:
            return {}
        metadata = document.get("metadata", {}) if isinstance(document, dict) else {}
        outcome = metadata.get("run_outcome", {}) if isinstance(metadata, dict) else {}
        return dict(outcome) if isinstance(outcome, dict) else {}

    def _read_run_result(self) -> Optional[RunResult]:
        """
        Read and strictly reconstruct the receipt-bound canonical result.

        After applying local validation, the function forwards current instance
        state to ``validate_run_result_document`` and preserves its return and
        exception contract. Parsing or I/O must finish before the validated
        representation is made available to the caller.

        Returns:
            A ``RunResult`` representing run result, or ``None`` when the
            requested value is unavailable.

        Raises:
            SnapshotArtifactFormatError: If terminal status snapshot is missing
                canonical RunResult; or terminal status snapshot contains an
                invalid canonical RunResult.
        """

        try:
            document = self._read_terminal_status()
        except SnapshotArtifactFormatError:
            if self._terminal_snapshot_generation is not None:
                raise
            return None
        except (OSError, UnicodeError, json.JSONDecodeError):
            if self._terminal_snapshot_generation is not None:
                raise
            return None
        if document is None:
            return None
        metadata = document.get("metadata", {}) if isinstance(document, dict) else {}
        raw_result = metadata.get("run_result") if isinstance(metadata, dict) else None
        if raw_result is None:
            if self._terminal_snapshot_generation is not None:
                raise SnapshotArtifactFormatError(
                    "Terminal status snapshot is missing canonical RunResult"
                )
            return None
        try:
            return validate_run_result_document(raw_result)
        except (TypeError, ValueError) as error:
            raise SnapshotArtifactFormatError(
                "Terminal status snapshot contains an invalid canonical RunResult"
            ) from error

    def _compute_summary(self, manifest: Dict) -> Dict:
        """
        Compute collection summary from manifest data.

        Counts only the collectors that were part of the run map
        (success/degraded/error/partial/skipped/cancelled/running/pending).
        Catalog collectors that were never applicable to the baseboard surface
        as ``not_ran`` and are reported separately as ``not_applicable``.
        ``filtered_out`` (pre-execution exclusions) is read from the
        authoritative collection status tracker and removed from ``not_ran``
        before catalog accounting so it is not double-counted.

        Args:
            manifest: Mapping supplying fields for compute collection summary
                from manifest data.

        Returns:
            The validated ``summary``.
        """
        status_counts = {
            "success": 0,
            "error": 0,
            "degraded": 0,
            "partial": 0,
            "skipped": 0,
            "cancelled": 0,
        }
        running = 0
        pending = 0
        not_applicable = 0
        filtered_out = 0
        total_log_size = 0

        def _count(value: Any) -> int:
            """
            Return the count.

            The implementation uses ``value`` to produce the count.

            Args:
                value: Value evaluated while performing count.

            Returns:
                The numeric count.
            """
            try:
                return max(int(value or 0), 0)
            except (TypeError, ValueError):
                return 0

        for dut in manifest.get("duts", []):
            summary = dut.get("status_summary", {})
            for key in status_counts:
                status_counts[key] += _count(summary.get(key, 0))
            running += _count(summary.get("running", 0))
            pending += _count(summary.get("pending", 0))

            dut_filtered_out = _count(dut.get("filtered_out", 0))
            filtered_out += dut_filtered_out
            raw_not_ran = _count(summary.get("not_ran", 0))
            not_applicable += max(raw_not_ran - dut_filtered_out, 0)
            total_log_size += dut.get("log_size", 0)

        collectors_to_run = sum(status_counts.values()) + running + pending
        total_executed = collectors_to_run
        obtained = (
            status_counts["success"]
            + status_counts["degraded"]
            + status_counts["partial"]
        )
        collection_pct = (
            (obtained / collectors_to_run * 100) if collectors_to_run > 0 else 0
        )

        canonical_result = self._read_run_result()
        if status_counts["error"] > 0:
            overall_status = "Failed"
        elif status_counts["partial"] > 0:
            overall_status = "Partial"
        elif status_counts["cancelled"] > 0:
            overall_status = "Interrupted"
        elif running or pending:
            overall_status = "Incomplete"
        elif status_counts["degraded"] > 0:
            overall_status = "Degraded"
        else:
            overall_status = "Passed"

        summary = {
            "total_duts": len(manifest.get("duts", [])),
            "total_collectors_executed": total_executed,
            "total_collectors_in_catalog": (
                collectors_to_run + filtered_out + not_applicable
            ),
            "total_collectors_filtered_out": filtered_out,
            "total_collectors_not_applicable": not_applicable,
            "total_collectors_running": running,
            "total_collectors_pending": pending,
            "total_log_size": total_log_size,
            "total_runtime": manifest.get("timing", {}).get("total_duration", 0),
            "overall_collection_pct": round(collection_pct, 1),
            "overall_status": (
                "Failed" if self._has_runtime_failure_outcome() else overall_status
            ),
            # Keep the historical terminal counters and project the active
            # lifecycle buckets into the same canonical map consumed by the
            # report application.  The legacy aggregate fields above remain
            # unchanged for older consumers.
            "status_counts": {
                **status_counts,
                "running": running,
                "pending": pending,
            },
            # Receipt-less legacy/offline readers retain explicit nulls. A
            # current-run manifest always replaces these with the exact result.
            "run_result": None,
            "runtime_status": None,
            "collection_status": None,
            "collector_counts": None,
        }
        if canonical_result is not None:
            canonical_document = canonical_result.to_dict()
            canonical_counts = dict(canonical_result.collector_counts)
            # Per-DUT summaries already exclude pre-execution filtered work
            # using the terminal tracker records. Keep their selected skips:
            # canonical capability_excluded also includes timed runtime
            # applicability probes, which must remain visible in the report.
            canonical_status_counts = {
                "success": canonical_counts.get("completed_collectors", 0),
                "error": canonical_counts.get("failed_collectors", 0),
                "degraded": canonical_counts.get("degraded_collectors", 0),
                "partial": canonical_counts.get("partial_collectors", 0),
                "skipped": status_counts["skipped"],
                "cancelled": canonical_counts.get("cancelled_collectors", 0),
                "running": canonical_counts.get("running_collectors", 0),
                "pending": canonical_counts.get("pending_collectors", 0),
            }
            if canonical_result.runtime_status.value == "failed":
                canonical_overall_status = "Failed"
            elif canonical_result.runtime_status.value == "interrupted":
                canonical_overall_status = "Interrupted"
            elif canonical_status_counts["error"]:
                canonical_overall_status = "Failed"
            else:
                canonical_overall_status = {
                    "success": "Passed",
                    "degraded": "Degraded",
                    "partial": "Partial",
                    "failed": "Failed",
                    "interrupted": "Interrupted",
                    "incomplete": "Incomplete",
                }[canonical_result.collection_status.value]
            summary.update(
                {
                    "run_result": canonical_document,
                    "runtime_status": canonical_result.runtime_status.value,
                    "collection_status": canonical_result.collection_status.value,
                    "collector_counts": canonical_counts,
                    "status_counts": canonical_status_counts,
                    "overall_status": canonical_overall_status,
                }
            )
            if canonical_result.run_identity is not None:
                summary["run_identity"] = canonical_result.run_identity.to_dict()
        run_outcome = self._read_run_outcome()
        if run_outcome:
            summary["run_outcome"] = dict(run_outcome)
            outcome_status = run_outcome.get("status")
            if isinstance(outcome_status, str):
                summary["run_outcome_status"] = outcome_status
            if outcome_status in {"runtime_failed", "interrupted"}:
                summary["run_outcome_reason"] = run_outcome.get("reason", "")
                if outcome_status == "runtime_failed":
                    summary["run_outcome_failure_type"] = run_outcome.get(
                        "failure_type"
                    )
        if run_outcome.get("status") == "domain_failed":
            summary.update(
                {
                    "run_outcome_status": "domain_failed",
                    "domain_failure": True,
                    "domain_failure_type": run_outcome.get(
                        "failure_type", "collection_domain_failure"
                    ),
                    "domain_failure_reason": run_outcome.get("reason", ""),
                }
            )
            if canonical_result is None:
                summary["overall_status"] = (
                    "Partial"
                    if not status_counts["error"]
                    and (status_counts["degraded"] or status_counts["partial"])
                    else "Failed"
                )
            elif (
                run_outcome.get("failure_type") in EXPLICIT_SELECTION_FAILURE_TYPES
                and run_outcome.get("evidence") == EXPLICIT_SELECTION_EVIDENCE_PATH
            ):
                summary["overall_status"] = "Failed"
            if run_outcome.get("evidence"):
                summary["domain_failure_evidence"] = run_outcome["evidence"]
        return summary

    def _copy_spa_assets(self, report_dir: Path) -> None:
        """
        Copy one descriptor-bound SPA distribution into a private tree.

        The implementation uses ``report_dir`` to copy one descriptor-bound SPA
        distribution into a private tree. Filesystem effects remain confined to
        the caller-selected paths and the owning resource lifecycle. If the
        function cannot copy one descriptor-bound SPA distribution into a
        private tree, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            report_dir: filesystem location used as the report dir for this
                operation.

        Raises:
            OSError: If staged SPA distribution inventory changed during
                validation.
        """
        if not self.spa_dist_dir or not self.spa_dist_dir.exists():
            return
        source_root = Path(self.spa_dist_dir)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        destination_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        destination_flags |= getattr(os, "O_CLOEXEC", 0)
        destination_flags |= getattr(os, "O_NOFOLLOW", 0)
        stable_file_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        stable_directory_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        counters = {"entries": 0, "bytes": 0}
        expected_files: Dict[str, Tuple[int, str]] = {}
        expected_directories: set[str] = set()

        def same_identity(
            left: os.stat_result,
            right: os.stat_result,
            *,
            directory: bool,
        ) -> bool:
            """
            Return the same identity.

            After applying local validation, the function forwards ``left``,
            ``right``, and ``directory`` to ``all`` and preserves its return and
            exception contract.

            Args:
                left: Left consumed while the function attempts to produce the
                    same identity.
                right: Right consumed while the function attempts to produce the
                    same identity.
                directory: filesystem location used as the directory for this
                    operation.

            Returns:
                Whether the same identity operation succeeds.
            """
            fields = stable_directory_fields if directory else stable_file_fields
            return all(
                getattr(left, field) == getattr(right, field) for field in fields
            )

        def copy_file(
            source_directory: int,
            name: str,
            observed: os.stat_result,
            destination: Path,
            relative: str,
        ) -> None:
            """
            Copy file.

            The implementation uses ``source_directory``, ``name``,
            ``observed``, ``destination``, and ``relative`` to copy file.
            Filesystem effects remain confined to the caller-selected paths and
            the owning resource lifecycle. If the function cannot copy file, its
            exception reaches the caller instead of being converted into a
            successful result. Cleanup in the ``finally`` path runs for
            successful, failed, and cancelled execution.

            Args:
                source_directory: filesystem location used as the source for
                    this operation.
                name: Stable name used for lookup and operator-facing
                    diagnostics.
                observed: Observed consumed while the function attempts to copy
                    file.
                destination: filesystem location used as the destination for
                    this operation.
                relative: Text supplied as relative in the format accepted by
                    this function.

            Raises:
                OSError: If SPA distribution file changed or exceeds its bound;
                    SPA distribution file grew while being copied; staged SPA
                    asset write made no progress; or SPA distribution file
                    changed while being copied; or another input invariant is
                    violated.
            """
            source_descriptor = os.open(name, file_flags, dir_fd=source_directory)
            destination_descriptor: Optional[int] = None
            try:
                opened = os.fstat(source_descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or not same_identity(observed, opened, directory=False)
                    or opened.st_size < 0
                    or counters["bytes"] + opened.st_size > MAX_SPA_ASSET_BYTES
                ):
                    raise OSError("SPA distribution file changed or exceeds its bound")
                destination_descriptor = os.open(
                    destination,
                    destination_flags,
                    0o644,
                )
                digest = hashlib.sha256()
                copied = 0
                while True:
                    remaining_budget = MAX_SPA_ASSET_BYTES - counters["bytes"]
                    chunk = os.read(
                        source_descriptor,
                        min(64 * 1024, remaining_budget + 1),
                    )
                    if not chunk:
                        break
                    copied += len(chunk)
                    counters["bytes"] += len(chunk)
                    if (
                        copied > opened.st_size
                        or counters["bytes"] > MAX_SPA_ASSET_BYTES
                    ):
                        raise OSError("SPA distribution file grew while being copied")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(destination_descriptor, view)
                        if written <= 0:
                            raise OSError("Staged SPA asset write made no progress")
                        view = view[written:]
                after = os.fstat(source_descriptor)
                if copied != opened.st_size or not same_identity(
                    opened, after, directory=False
                ):
                    raise OSError("SPA distribution file changed while being copied")
                os.fchmod(destination_descriptor, 0o644)
                os.fsync(destination_descriptor)

                # Re-read the private output through its owned descriptor. This
                # catches short/partial writes before the generation can become
                # eligible for publication.
                destination_before = os.fstat(destination_descriptor)
                if not stat.S_ISREG(destination_before.st_mode):
                    raise OSError("Staged SPA asset is not a regular file")
                os.lseek(destination_descriptor, 0, os.SEEK_SET)
                staged_digest = hashlib.sha256()
                staged_bytes = 0
                while True:
                    chunk = os.read(
                        destination_descriptor,
                        min(64 * 1024, copied + 1 - staged_bytes),
                    )
                    if not chunk:
                        break
                    staged_bytes += len(chunk)
                    if staged_bytes > copied:
                        raise OSError("Staged SPA asset grew during verification")
                    staged_digest.update(chunk)
                destination_after = os.fstat(destination_descriptor)
                if (
                    staged_bytes != copied
                    or not same_identity(
                        destination_before, destination_after, directory=False
                    )
                    or staged_digest.digest() != digest.digest()
                ):
                    raise OSError("Staged SPA asset failed stable verification")
                expected_files[relative] = (copied, digest.hexdigest())
            finally:
                if destination_descriptor is not None:
                    os.close(destination_descriptor)
                os.close(source_descriptor)

        def copy_directory(
            source_descriptor: int,
            destination: Path,
            relative_parts: Tuple[str, ...],
        ) -> None:
            """
            Copy directory.

            The implementation uses ``source_descriptor``, ``destination``, and
            ``relative_parts`` to copy directory. Filesystem effects remain
            confined to the caller-selected paths and the owning resource
            lifecycle. If the function cannot copy directory, its exception
            reaches the caller instead of being converted into a successful
            result. Cleanup in the ``finally`` path runs for successful, failed,
            and cancelled execution.

            Args:
                source_descriptor: Numeric source descriptor used while the
                    operation performs bounded accounting.
                destination: filesystem location used as the destination for
                    this operation.
                relative_parts: Entries supplied as ``relative_parts`` without
                    transferring container ownership.

            Raises:
                OSError: If SPA distribution contains a non-directory entry; SPA
                    distribution exceeds its aggregate bound; SPA distribution
                    directory changed before it was opened; or SPA distribution
                    contains a non-regular entry; or another input invariant is
                    violated.
            """
            before = os.fstat(source_descriptor)
            if not stat.S_ISDIR(before.st_mode):
                raise OSError("SPA distribution contains a non-directory entry")
            with os.scandir(source_descriptor) as iterator:
                entries = []
                for entry in iterator:
                    counters["entries"] += 1
                    if counters["entries"] > MAX_SPA_ASSET_ENTRIES:
                        raise OSError("SPA distribution exceeds its aggregate bound")
                    entries.append((entry.name, entry.stat(follow_symlinks=False)))
            for name, observed in sorted(entries, key=lambda item: item[0]):
                relative_tuple = (*relative_parts, name)
                relative = Path(*relative_tuple).as_posix()
                target = destination / name
                if stat.S_ISDIR(observed.st_mode):
                    child_source = os.open(
                        name, directory_flags, dir_fd=source_descriptor
                    )
                    try:
                        opened = os.fstat(child_source)
                        if not same_identity(observed, opened, directory=True):
                            raise OSError(
                                "SPA distribution directory changed before it was opened"
                            )
                        target.mkdir()
                        expected_directories.add(relative)
                        copy_directory(child_source, target, relative_tuple)
                    finally:
                        os.close(child_source)
                elif stat.S_ISREG(observed.st_mode):
                    copy_file(
                        source_descriptor,
                        name,
                        observed,
                        target,
                        relative,
                    )
                else:
                    raise OSError("SPA distribution contains a non-regular entry")
            after = os.fstat(source_descriptor)
            if not same_identity(before, after, directory=True):
                raise OSError("SPA distribution directory changed while being copied")

        source_descriptor = os.open(source_root, directory_flags)
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
            copy_directory(source_descriptor, report_dir, ())
        finally:
            os.close(source_descriptor)

        # Walk the staged tree again through directory-relative, no-follow
        # descriptors. The exact set, byte sizes, and digests must match the
        # generation observed above; an injected entry or swap fails closed.
        seen_files: set[str] = set()
        seen_directories: set[str] = set()
        verified_entries = 0
        verified_bytes = 0

        def validate_directory(
            descriptor: int,
            relative_parts: Tuple[str, ...],
        ) -> None:
            """
            Validate directory.

            The implementation uses ``descriptor`` and ``relative_parts`` to
            validate directory. Every required invariant is checked before a
            successful value is returned; invalid input follows the function's
            explicit exception path. Filesystem effects remain confined to the
            caller-selected paths and the owning resource lifecycle. Cleanup in
            the ``finally`` path runs for successful, failed, and cancelled
            execution.

            Args:
                descriptor: Numeric descriptor used while the operation performs
                    bounded accounting.
                relative_parts: Entries supplied as ``relative_parts`` without
                    transferring container ownership.

            Raises:
                OSError: If staged SPA distribution contains a non-directory;
                    staged SPA distribution exceeds its entry bound; staged SPA
                    directory changed during validation; or staged SPA
                    distribution contains an unexpected entry; or another input
                    invariant is violated.
            """
            nonlocal verified_entries, verified_bytes
            before = os.fstat(descriptor)
            if not stat.S_ISDIR(before.st_mode):
                raise OSError("Staged SPA distribution contains a non-directory")
            with os.scandir(descriptor) as iterator:
                entries = sorted(
                    (
                        (entry.name, entry.stat(follow_symlinks=False))
                        for entry in iterator
                    ),
                    key=lambda item: item[0],
                )
            for name, observed in entries:
                verified_entries += 1
                if verified_entries > MAX_SPA_ASSET_ENTRIES:
                    raise OSError("Staged SPA distribution exceeds its entry bound")
                relative_tuple = (*relative_parts, name)
                relative = Path(*relative_tuple).as_posix()
                if stat.S_ISDIR(observed.st_mode):
                    child = os.open(name, directory_flags, dir_fd=descriptor)
                    try:
                        opened = os.fstat(child)
                        if not same_identity(observed, opened, directory=True):
                            raise OSError(
                                "Staged SPA directory changed during validation"
                            )
                        seen_directories.add(relative)
                        validate_directory(child, relative_tuple)
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(observed.st_mode) or relative not in expected_files:
                    raise OSError(
                        "Staged SPA distribution contains an unexpected entry"
                    )
                expected_size, expected_digest = expected_files[relative]
                child = os.open(name, file_flags, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if not same_identity(observed, opened, directory=False):
                        raise OSError("Staged SPA asset changed before validation")
                    digest = hashlib.sha256()
                    consumed = 0
                    while True:
                        chunk = os.read(
                            child, min(64 * 1024, expected_size + 1 - consumed)
                        )
                        if not chunk:
                            break
                        consumed += len(chunk)
                        verified_bytes += len(chunk)
                        if (
                            consumed > expected_size
                            or verified_bytes > MAX_SPA_ASSET_BYTES
                        ):
                            raise OSError("Staged SPA asset exceeds its byte bound")
                        digest.update(chunk)
                    after = os.fstat(child)
                    if (
                        consumed != expected_size
                        or digest.hexdigest() != expected_digest
                        or not same_identity(opened, after, directory=False)
                    ):
                        raise OSError("Staged SPA asset failed final validation")
                    seen_files.add(relative)
                finally:
                    os.close(child)
            after = os.fstat(descriptor)
            if not same_identity(before, after, directory=True):
                raise OSError("Staged SPA directory changed during final validation")

        staged_descriptor = os.open(report_dir, directory_flags)
        try:
            validate_directory(staged_descriptor, ())
        finally:
            os.close(staged_descriptor)
        if (
            seen_files != set(expected_files)
            or seen_directories != expected_directories
        ):
            raise OSError("Staged SPA distribution inventory changed during validation")

    def _embed_manifest(self, index_html: Path, manifest_json: str) -> None:
        """
        Inject a compressed offline fallback into an existing SPA bundle.

        Report generation uses the streaming staging path above. This retained
        helper supports callers that already hold JSON text without restoring a
        second raw JSON copy in the HTML.

        Args:
            index_html: filesystem location used as the index HTML for this
                operation.
            manifest_json: Text supplied as manifest JSON in the format accepted
                by this function.

        Raises:
            ValueError: If report manifest exceeds the 128 MiB safety limit;
                compressed report manifest exceeds the 64 MiB safety limit; or
                embedded report exceeds its document size limit.
            OSError: If report index is not a regular file; unable to write
                embedded report; or report index changed before embedded
                publication.
        """
        manifest_bytes = manifest_json.encode("utf-8")
        if len(manifest_bytes) > MAX_MANIFEST_DOCUMENT_BYTES:
            raise ValueError("Report manifest exceeds the 128 MiB safety limit")
        compressed = gzip.compress(manifest_bytes, mtime=0)
        if len(compressed) > MAX_COMPRESSED_MANIFEST_BYTES:
            raise ValueError(
                "Compressed report manifest exceeds the 64 MiB safety limit"
            )
        original = index_html.lstat()
        if not stat.S_ISREG(original.st_mode):
            raise OSError("Report index is not a regular file")
        html = _read_regular_file_bounded(
            index_html,
            MAX_REPORT_INDEX_BYTES,
        ).decode("utf-8")
        try:
            prefix, suffix = self._manifest_insertion_parts(html)
        except ValueError:
            logger.warning(
                "Could not embed manifest: no placeholder or </head>/</body> found in %s",
                index_html,
            )
            return
        script_tag = (
            self._inline_manifest_opening_tag(len(manifest_bytes), len(compressed))
            + base64.b64encode(compressed).decode("ascii")
            + "</script>"
        )
        html = prefix + script_tag + suffix
        encoded = html.encode("utf-8")
        if len(encoded) > MAX_REPORT_DOCUMENT_BYTES:
            raise ValueError("Embedded report exceeds its document size limit")

        temporary_path = index_html.parent / (
            f".{index_html.name}.embed-{uuid.uuid4().hex}"
        )
        descriptor = os.open(
            temporary_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            stat.S_IMODE(original.st_mode) or 0o600,
        )
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Unable to write embedded report")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            observed = index_html.lstat()
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_dev != original.st_dev
                or observed.st_ino != original.st_ino
                or observed.st_size != original.st_size
                or observed.st_mtime_ns != original.st_mtime_ns
                or observed.st_ctime_ns != original.st_ctime_ns
            ):
                raise OSError("Report index changed before embedded publication")
            os.replace(temporary_path, index_html)
        finally:
            temporary_path.unlink(missing_ok=True)
