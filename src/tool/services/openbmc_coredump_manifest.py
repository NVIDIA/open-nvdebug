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
Build a metadata-only handoff for OpenBMC core-dump analysis.

This handoff does not upload core files. It identifies controller-side core
artifacts and records the inputs an engineer needs for a manual analysis
session. The analysis destination is deployment configuration, not product
source or collection data.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .bounded_tar_scanner import (
    ARCHIVE_SCAN_SECONDS_LIMIT,
    XZ_MAX_DECODER_MEMORY_BYTES,
    ZSTD_MAX_WINDOW_BYTES,
    ArchiveLimitExceeded,
    ArchiveScanError,
    BoundedTarScanner,
    MemberReader,
    SafeTarMember,
    normalize_tar_member_path,
)

logger = logging.getLogger(__name__)

MANIFEST_FILENAME = "openbmc_coredump_analyzer_manifest.json"
MANIFEST_RELATIVE_PATH = Path(".metadata") / MANIFEST_FILENAME

# Directly compressed systemd core files are surfaced, but are not claimed to
# be analyzer-ready because the analyzer's compression contract is not public.
SUPPORTED_COMPRESSION_SUFFIXES = (
    ".zstd",
    ".zst",
    ".lz4",
    ".bz2",
    ".gz",
    ".xz",
)

CONTROLLER_GROUPS = {"ssh", "bmc", "hmc", "redfish"}
NON_CONTROLLER_GROUPS = {"host", "ipmi", "nvidia-smi"}
TEXT_METADATA_FILE_LIMIT = 2 * 1024 * 1024
TEXT_METADATA_TOTAL_LIMIT = 16 * 1024 * 1024
TEXT_METADATA_CANDIDATE_LIMIT = 200
DUT_METADATA_FILE_LIMIT = 2 * 1024 * 1024
METADATA_JSON_NODE_LIMIT = 100_000
METADATA_JSON_DEPTH_LIMIT = 64
ELF_VALIDATION_READ_LIMIT = 64 * 1024
ARCHIVE_CANDIDATE_LIMIT = 1024
ARCHIVE_INPUT_SIZE_LIMIT = 512 * 1024 * 1024
ARCHIVE_INPUT_TOTAL_LIMIT = 2 * 1024 * 1024 * 1024
ARCHIVE_DECOMPRESSED_SIZE_LIMIT = 2 * 1024 * 1024 * 1024
ARCHIVE_DECOMPRESSED_TOTAL_LIMIT = 4 * 1024 * 1024 * 1024
ARCHIVE_LOGICAL_SIZE_LIMIT = 2 * 1024 * 1024 * 1024
ARCHIVE_MEMBER_LIMIT = 4096
ARCHIVE_MEMBER_TOTAL_LIMIT = 65536
ARCHIVE_MEMBER_NAME_LIMIT = 4096
ARCHIVE_METADATA_TOTAL_LIMIT = 2 * 1024 * 1024
CORE_RECORD_LIMIT = 2048
HANDOFF_MANIFEST_SIZE_LIMIT = 64 * 1024 * 1024
UNINSPECTED_ARCHIVE_DETAIL_LIMIT = 256
SUPPORTED_ARCHIVE_SUFFIXES = (
    ".tar.bz2",
    ".tar.gz",
    ".tar.zstd",
    ".tar.zst",
    ".tar.xz",
    ".tbz2",
    ".tgz",
    ".tzst",
    ".tar",
    ".zip",
)
ELF_CORE_CANDIDATE_VALIDATIONS = {
    "validated_raw_elf_core",
    "elf_core_requires_manual_validation",
}

_SYSTEMD_FULL_NAME = re.compile(
    r"^core\.(?P<service>.+)\.(?P<uid>\d+)\."
    r"(?P<boot_id>[0-9a-fA-F-]+)\.(?P<pid>\d+)\.(?P<timestamp>\d+)$"
)
_SYSTEMD_SHORT_NAME = re.compile(r"^core\.(?P<service>.+)\.(?P<pid>\d+)$")
_CORE_UNDERSCORE_NAME = re.compile(
    r"^core_(?P<service>[A-Za-z0-9@:+-][A-Za-z0-9@:+._-]*)$"
)
_SERVICE_CORE_NAME = re.compile(
    r"^(?P<service>[A-Za-z0-9@:+-][A-Za-z0-9@:+._-]*)\.core$"
)
_COMMIT_VALUE = re.compile(r"^(?:g)?(?P<sha>[0-9a-fA-F]{7,40})$")
_COMMIT_ENV = re.compile(
    r"^\s*(?:VERSION_ID|EXTENDED_VERSION)\s*=\s*[\"']?"
    r"[^\r\n\"']*?-g(?P<sha>[0-9a-fA-F]{7,40})(?:[.\s\"']|$)",
    re.IGNORECASE | re.MULTILINE,
)
_COMMIT_IN_TEXT = re.compile(
    r"\b(?:openbmc|bmc)[ _-]*(?:git[ _-]*)?commit(?:[ _-]*hash)?\b"
    r"\s*[:=]\s*g?(?P<sha>[0-9a-fA-F]{7,40})\b",
    re.IGNORECASE,
)
_MACHINE_ENV = re.compile(
    r"^\s*OPENBMC_TARGET_MACHINE\s*=\s*[\"']?"
    r"(?P<machine>[a-z0-9][a-z0-9._-]+)[\"']?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_MACHINE_IN_TEXT = re.compile(
    r"\b(?:openbmc[ _-]*)?machine\b\s*[:=]\s*[\"']?"
    r"(?P<machine>[a-z0-9][a-z0-9._-]+)",
    re.IGNORECASE,
)

_COMMIT_KEYS = {
    "openbmccommit",
    "openbmccommithash",
    "bmccommit",
    "bmccommithash",
}
_MACHINE_KEYS = {
    "openbmcanalyzermachine",
    "openbmcmachine",
    "bmcmachine",
}


class CoreRecordLimitExceeded(ArchiveLimitExceeded):
    """
    The bounded handoff record budget was exhausted.

    The type gives the core record limit exceeded responsibility a stable
    runtime boundary. Callers use the declared Python protocol instead of
    depending on its representation.
    """


def _normalized_key(value: Any) -> str:
    """
    Return the normalized key.

    After applying local validation, the function forwards ``value`` to
    ``re.sub`` and preserves its return and exception contract.

    Args:
        value: Value evaluated while performing normalized key.

    Returns:
        The canonical normalized key text.
    """
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _first_nested_value(data: Any, accepted_keys: set[str]) -> Optional[str]:
    """
    Return the first non-empty scalar under an explicitly accepted key.

    The implementation uses ``data`` and ``accepted_keys`` to produce the first
    non-empty scalar under an explicitly accepted key.

    Args:
        data: Data consumed while the function attempts to produce the first
            non-empty scalar under an explicitly accepted key.
        accepted_keys: Entries supplied as ``accepted_keys`` without
            transferring container ownership.

    Returns:
        The validated ``candidate``, or ``None`` when no value qualifies.
    """
    stack: List[Tuple[Any, int]] = [(data, 0)]
    visited = 0
    while stack:
        value, depth = stack.pop()
        visited += 1
        if visited > METADATA_JSON_NODE_LIMIT or depth > METADATA_JSON_DEPTH_LIMIT:
            return None
        if isinstance(value, dict):
            for key, child in value.items():
                if _normalized_key(key) in accepted_keys and isinstance(
                    child, (str, int)
                ):
                    candidate = str(child).strip()
                    if candidate:
                        return candidate
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
    return None


def _read_regular_file_bounded(path: Path, maximum_bytes: int) -> bytes:
    """
    Read one stable regular metadata file without following its leaf.

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
        OSError: If metadata source is not a bounded regular file; metadata
            source lacks no-follow file access; metadata source changed before
            it was opened; or metadata source exceeded its byte limit; or
            another input invariant is violated.
    """

    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
        raise OSError("metadata source is not a bounded regular file")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise OSError("metadata source requires no-follow file access")
    descriptor = os.open(
        path,
        os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened = os.fstat(descriptor)

        def identity(item: os.stat_result) -> Tuple[int, ...]:
            """
            Return the identity.

            The implementation uses ``item`` to produce the identity.

            Args:
                item: Item object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
                    ``st_mode``, and ``st_mtime_ns`` state is read while
                    performing identity.

            Returns:
                A tuple containing ``st dev``, ``st ino``, ``st mode``, ``st
                size``, ``st mtime ns``, and ``st ctime ns`` in that order.
            """
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if identity(opened) != identity(before):
            raise OSError("metadata source changed before it was opened")
        chunks: List[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum_bytes:
                raise OSError("metadata source exceeded its byte limit")
            chunks.append(chunk)
        if identity(os.fstat(descriptor)) != identity(before) or identity(
            path.lstat()
        ) != identity(before):
            raise OSError("metadata source changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_metadata_json_shape(document: Any) -> None:
    """
    Validate metadata JSON shape.

    The implementation uses ``document`` to validate metadata JSON shape. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        document: Document consumed while the function attempts to validate
            metadata JSON shape.

    Raises:
        ValueError: If metadata JSON structure exceeds its safety limit.
    """
    stack: List[Tuple[Any, int]] = [(document, 0)]
    visited = 0
    while stack:
        value, depth = stack.pop()
        visited += 1
        if visited > METADATA_JSON_NODE_LIMIT or depth > METADATA_JSON_DEPTH_LIMIT:
            raise ValueError("metadata JSON structure exceeds its safety limit")
        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)


class OpenBMCCoreDumpManifestService:
    """
    Discover OpenBMC core dumps and describe a safe manual handoff.

    The type coordinates ``generate``, ``empty_payload``,
    ``unavailable_payload``, ``_build_payload``, and ``write`` and retains the
    state those operations share between calls. Resource ownership remains
    inside the instance until the matching close, exit, or cleanup operation
    completes.
    """

    def __init__(self, log_dir: Path):
        """
        Initialize an ``OpenBMCCoreDumpManifestService`` instance.

        The initializer records ``_archive_decompressed_bytes``,
        ``_archive_input_bytes``, ``_archive_members_inspected``,
        ``_archives_inspected``, and ``_metadata_cache`` for later operations
        and establishes the instance invariants before any public method runs.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
        """
        self.log_dir = Path(log_dir)
        self._metadata_cache: Dict[
            str, Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]
        ] = {}
        self._scan_warnings: List[str] = []
        self._uninspected_archives: List[Dict[str, Any]] = []
        self._archives_inspected = 0
        self._archive_input_bytes = 0
        self._archive_compressed_bytes_read = 0
        self._archive_decompressed_bytes = 0
        self._archive_members_inspected = 0
        self._record_limit_reached = False
        self._uninspected_archive_count = 0

    def generate(
        self, file_index: Optional[Iterable[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Build the handoff without copying, modifying, or uploading a core.

        The implementation uses ``file_index`` to build the handoff without
        copying, modifying, or uploading a core. It updates
        ``_archive_decompressed_bytes``, ``_archive_input_bytes``,
        ``_archive_members_inspected``, ``_archives_inspected``, and
        ``_metadata_cache`` on the instance as part of that state transition.

        Args:
            file_index: Numeric file index used by the operation's bounded
                accounting.

        Returns:
            The validated ``payload``.
        """
        entries = (
            file_index
            if isinstance(file_index, list)
            else list(file_index) if file_index is not None else self._walk_files()
        )
        records: List[Dict[str, Any]] = []
        self._metadata_cache = {}
        self._scan_warnings = []
        self._uninspected_archives = []
        self._archives_inspected = 0
        self._archive_input_bytes = 0
        self._archive_compressed_bytes_read = 0
        self._archive_decompressed_bytes = 0
        self._archive_members_inspected = 0
        self._record_limit_reached = False
        self._uninspected_archive_count = 0
        archive_count = 0
        archive_limit_reported = False
        record_limit_reported = False

        for entry in entries:
            if len(records) >= CORE_RECORD_LIMIT:
                self._record_limit_reached = True
                if not record_limit_reported:
                    self._scan_warnings.append(
                        "OpenBMC core-dump indexing stopped after "
                        f"{CORE_RECORD_LIMIT} records. Collected artifacts remain "
                        "unchanged and may contain additional cores."
                    )
                    record_limit_reported = True
                if self._is_archive_candidate(entry):
                    self._record_uninspected_archive(
                        entry,
                        "core_record_limit",
                        "skipped",
                    )
                continue

            record = self._build_record(entry, entries)
            if record is not None:
                records.append(record)
            if not self._is_archive_candidate(entry):
                continue
            archive_count += 1
            if archive_count > ARCHIVE_CANDIDATE_LIMIT:
                self._record_uninspected_archive(
                    entry,
                    "archive_candidate_limit",
                    "skipped",
                )
                if not archive_limit_reported:
                    self._scan_warnings.append(
                        "Controller archive scan stopped after "
                        f"{ARCHIVE_CANDIDATE_LIMIT} candidates; collected "
                        "archives remain unchanged."
                    )
                    archive_limit_reported = True
                continue
            archive_size = self._entry_file_size(entry)
            if archive_size > ARCHIVE_INPUT_SIZE_LIMIT:
                self._record_uninspected_archive(
                    entry,
                    "archive_input_size_limit",
                    "skipped",
                )
                self._scan_warnings.append(
                    f"Controller archive exceeds the per-archive input limit "
                    f"of {ARCHIVE_INPUT_SIZE_LIMIT} bytes and was not inspected."
                )
                continue
            if self._archive_input_bytes + archive_size > ARCHIVE_INPUT_TOTAL_LIMIT:
                self._record_uninspected_archive(
                    entry,
                    "archive_input_total_limit",
                    "skipped",
                )
                self._scan_warnings.append(
                    "Controller archive was not inspected because the global "
                    f"compressed-input budget of {ARCHIVE_INPUT_TOTAL_LIMIT} "
                    "bytes was reached."
                )
                continue
            try:
                records.extend(
                    self._scan_archive(
                        entry,
                        entries,
                        core_record_limit=CORE_RECORD_LIMIT - len(records),
                    )
                )
            except Exception as exc:
                relative = self._normalize_relative_path(entry.get("path"))
                archive_name = relative.as_posix() if relative else "<invalid path>"
                self._scan_warnings.append(
                    f"Unable to inspect controller archive {archive_name}: "
                    f"{type(exc).__name__}: {exc}"
                )
                self._record_uninspected_archive(
                    entry,
                    f"{type(exc).__name__}: {exc}",
                    "failed",
                )

        payload = self._build_payload(
            records,
            self._scan_warnings,
            scan_complete=(
                self._uninspected_archive_count == 0 and not self._record_limit_reached
            ),
            uninspected_archives=self._uninspected_archives,
            archives_inspected=self._archives_inspected,
            archive_input_bytes=self._archive_compressed_bytes_read,
            archive_decompressed_bytes=self._archive_decompressed_bytes,
            archive_members_inspected=self._archive_members_inspected,
            uninspected_archive_count=self._uninspected_archive_count,
        )
        self._require_payload_size(payload)
        return payload

    @staticmethod
    def empty_payload() -> Dict[str, Any]:
        """
        Return the complete schema when no controller core is present.

        After applying local validation, the function forwards current instance
        state to ``OpenBMCCoreDumpManifestService._build_payload`` and preserves
        its return and exception contract.

        Returns:
            A mapping containing empty payload.
        """
        return OpenBMCCoreDumpManifestService._build_payload([])

    @staticmethod
    def unavailable_payload(reason: str) -> Dict[str, Any]:
        """
        Return a truthful schema when discovery could not run.

        After applying local validation, the function forwards ``reason`` to
        ``OpenBMCCoreDumpManifestService._build_payload`` and preserves its
        return and exception contract.

        Args:
            reason: Text supplied as reason in the format accepted by this
                function.

        Returns:
            A mapping containing unavailable payload.
        """
        normalized_reason = str(reason or "unknown discovery failure")
        return OpenBMCCoreDumpManifestService._build_payload(
            [],
            [
                "OpenBMC core-dump discovery was unavailable; collected "
                "artifacts remain unchanged and may contain cores. "
                f"Reason: {normalized_reason}"
            ],
            scan_complete=False,
            uninspected_archives=[
                {
                    "artifact_path": "<discovery unavailable>",
                    "size_bytes": 0,
                    "status": "unavailable",
                    "reason": normalized_reason,
                }
            ],
        )

    @staticmethod
    def _build_payload(
        records: List[Dict[str, Any]],
        scan_warnings: Optional[List[str]] = None,
        *,
        scan_complete: bool = True,
        uninspected_archives: Optional[List[Dict[str, Any]]] = None,
        archives_inspected: int = 0,
        archive_input_bytes: int = 0,
        archive_decompressed_bytes: int = 0,
        archive_members_inspected: int = 0,
        uninspected_archive_count: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Build payload.

        The report build supplies an approved destination when one exists.
        Collection metadata is intentionally not trusted to choose where an
        engineer uploads a sensitive core file.

        Args:
            records: Mapping supplying fields for payload.
            scan_warnings: Optional scan warnings; ``None`` selects the
                function's default behavior.
            scan_complete: Whether scan complete is enabled or required for this
                operation.
            uninspected_archives: Optional uninspected archives; ``None``
                selects the function's default behavior.
            archives_inspected: Numeric archives inspected used while the
                operation performs bounded accounting.
            archive_input_bytes: Numeric archive input bytes used while the
                operation performs bounded accounting.
            archive_decompressed_bytes: Numeric archive decompressed bytes used
                while the operation performs bounded accounting.
            archive_members_inspected: Numeric archive members inspected used
                while the operation performs bounded accounting.
            uninspected_archive_count: Numeric uninspected archive count used by
                the operation's bounded accounting.

        Returns:
            A mapping containing the ``schema_version``, ``generated_at``,
            ``analyzer``, ``privacy``, and ``summary`` fields.
        """
        records.sort(key=lambda item: (item["source_dut"], item["artifact_path"]))
        ready_count = sum(bool(record["ready_for_analyzer"]) for record in records)
        return {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "analyzer": {
                "name": "OpenBMC Core Dump Analyzer",
                # The report build supplies an approved destination when one
                # exists. Collection metadata is intentionally not trusted to
                # choose where an engineer uploads a sensitive core file.
                "url": None,
                "integration_mode": "manual_handoff",
                "automatic_upload": False,
            },
            "privacy": {
                "classification": "sensitive_diagnostic_artifact",
                "notice": (
                    "Core dumps can contain process memory, credentials, and "
                    "customer data. This handoff never uploads them to the "
                    "analyzer. Review the selected file and use an approved "
                    "analysis destination only when authorized."
                ),
            },
            "summary": {
                "core_dump_count": len(records),
                "analyzer_ready_count": ready_count,
                "needs_metadata_count": len(records) - ready_count,
            },
            "scan_warnings": list(scan_warnings or []),
            "archive_scan": {
                "complete": scan_complete,
                "archives_inspected": archives_inspected,
                "compressed_bytes_inspected": archive_input_bytes,
                "decompressed_bytes_consumed": archive_decompressed_bytes,
                "members_inspected": archive_members_inspected,
                "uninspected_archive_count": (
                    len(uninspected_archives or [])
                    if uninspected_archive_count is None
                    else uninspected_archive_count
                ),
                "uninspected_archive_details_omitted": max(
                    0,
                    (
                        len(uninspected_archives or [])
                        if uninspected_archive_count is None
                        else uninspected_archive_count
                    )
                    - len(uninspected_archives or []),
                ),
                "uninspected_archives": list(uninspected_archives or []),
            },
            "core_dumps": records,
        }

    def write(
        self,
        destination: Optional[Path] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """
        Write a standalone metadata artifact below the collection root.

        Reject an outside destination before creating any of its directories.

        Args:
            destination: Optional filesystem location used as the destination
                for this operation.
            payload: Optional payload; ``None`` selects the function's default
                behavior.

        Returns:
            The validated ``output_path``.

        Raises:
            ValueError: If refusing non-regular manifest path: ``output_path``;
                or openBMC core-dump handoff exceeds the
                ``HANDOFF_MANIFEST_SIZE_LIMIT``-byte manifest limit.
        """
        self.log_dir.mkdir(parents=True, exist_ok=True)
        output_path = (
            Path(destination) if destination else self.log_dir / MANIFEST_RELATIVE_PATH
        )
        # Reject an outside destination before creating any of its directories.
        self._require_candidate_path_below_log_root(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        self._require_path_below_log_root(output_path)

        try:
            output_mode = output_path.lstat().st_mode
        except FileNotFoundError:
            output_mode = None
        if output_mode is not None and not stat.S_ISREG(output_mode):
            raise ValueError(f"Refusing non-regular manifest path: {output_path}")

        document = payload if payload is not None else self.generate()
        self._require_payload_size(document)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output_path.name}.", dir=output_path.parent
        )
        temporary_path = Path(temporary_name)
        descriptor_open = True
        try:
            os.fchmod(descriptor, 0o600)
            stream = os.fdopen(descriptor, "wb")
            descriptor_open = False
            with stream:
                written = 0
                for chunk in json.JSONEncoder(
                    indent=2,
                    sort_keys=True,
                ).iterencode(document):
                    encoded = chunk.encode("utf-8")
                    written += len(encoded)
                    if written + 1 > HANDOFF_MANIFEST_SIZE_LIMIT:
                        raise ValueError(
                            "OpenBMC core-dump handoff exceeds the "
                            f"{HANDOFF_MANIFEST_SIZE_LIMIT}-byte manifest limit"
                        )
                    stream.write(encoded)
                stream.write(b"\n")
            os.replace(temporary_path, output_path)
        finally:
            if descriptor_open:
                os.close(descriptor)
            temporary_path.unlink(missing_ok=True)
        return output_path

    @staticmethod
    def _require_payload_size(payload: Dict[str, Any]) -> None:
        """
        Reject a handoff that cannot safely be embedded in the SPA report.

        The implementation uses ``payload`` to reject a handoff that cannot
        safely be embedded in the SPA report. Every required invariant is
        checked before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            payload: Mapping supplying fields for handoff that cannot safely be
                embedded in the SPA report.

        Raises:
            ValueError: If openBMC core-dump handoff exceeds the
                ``HANDOFF_MANIFEST_SIZE_LIMIT``-byte manifest limit.
        """
        encoded_size = 1  # Trailing newline written by ``write``.
        for chunk in json.JSONEncoder(
            indent=2,
            sort_keys=True,
        ).iterencode(payload):
            encoded_size += len(chunk.encode("utf-8"))
            if encoded_size > HANDOFF_MANIFEST_SIZE_LIMIT:
                raise ValueError(
                    "OpenBMC core-dump handoff exceeds the "
                    f"{HANDOFF_MANIFEST_SIZE_LIMIT}-byte manifest limit"
                )

    def read_existing(self) -> Optional[Dict[str, Any]]:
        """
        Load a generated handoff to avoid rescanning manager archives.

        Prefer the canonical hidden metadata path. The collection-root lookup
        keeps report generation compatible with bundles produced by the draft
        layout of this feature.

        Returns:
            The validated ``payload``, or ``None`` when no value qualifies.
        """
        path = self._safe_regular_artifact(self.log_dir / MANIFEST_RELATIVE_PATH)
        if path is None:
            path = self._safe_regular_artifact(self.log_dir / MANIFEST_FILENAME)
        if path is None:
            return None
        size = self._file_size(path)
        if size <= 0 or size > HANDOFF_MANIFEST_SIZE_LIMIT:
            return None
        try:
            payload = json.loads(
                _read_regular_file_bounded(
                    path,
                    HANDOFF_MANIFEST_SIZE_LIMIT,
                ).decode("utf-8")
            )
            _validate_metadata_json_shape(payload)
        except (
            OSError,
            UnicodeError,
            ValueError,
            json.JSONDecodeError,
            RecursionError,
        ):
            return None
        if not isinstance(payload, dict):
            return None
        analyzer = payload.get("analyzer")
        archive_scan = payload.get("archive_scan")
        if (
            payload.get("schema_version") != "1.0"
            or not isinstance(payload.get("summary"), dict)
            or not isinstance(payload.get("core_dumps"), list)
            or not isinstance(payload.get("scan_warnings"), list)
            or not isinstance(archive_scan, dict)
            or not isinstance(analyzer, dict)
            or analyzer.get("automatic_upload") is not False
        ):
            return None
        for record in payload["core_dumps"]:
            if not isinstance(record, dict):
                return None
            relative = self._normalize_relative_path(record.get("artifact_path"))
            if (
                relative is None
                or self._safe_regular_artifact(self.log_dir / relative) is None
            ):
                return None
            member_value = record.get("archive_member_path")
            if (
                member_value is not None
                and self._normalize_archive_member_path(member_value) is None
            ):
                return None
            handoff = record.get("handoff")
            if (
                not isinstance(handoff, dict)
                or handoff.get("upload_performed") is not False
            ):
                return None
            # Legacy draft manifests carried a destination selected by the
            # collection data. Retain the handoff record but remove that
            # untrusted upload target before embedding it in a new report.
            handoff["analyzer_url"] = None
        analyzer["url"] = None
        return payload

    def _walk_files(self) -> List[Dict[str, Any]]:
        """
        Walk files.

        The implementation uses current instance state to walk files. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Returns:
            The walk files returned in operation-defined order.
        """
        entries: List[Dict[str, Any]] = []
        if not self.log_dir.is_dir():
            return entries

        for root, dirs, filenames in os.walk(self.log_dir, followlinks=False):
            dirs[:] = [
                name
                for name in dirs
                if name not in {"reports", ".metadata", "metadata", "__pycache__"}
                and not (Path(root) / name).is_symlink()
            ]
            root_path = Path(root)
            for filename in sorted(filenames):
                path = root_path / filename
                safe_path = self._safe_regular_artifact(path)
                if safe_path is None:
                    continue
                relative = safe_path.relative_to(self.log_dir.resolve())
                if len(relative.parts) < 2:
                    continue
                entries.append(
                    {
                        "path": relative.as_posix(),
                        "size": self._file_size(safe_path),
                        "dut_id": relative.parts[0],
                        "collector_id": "",
                        "collector_group": (
                            relative.parts[1] if len(relative.parts) > 2 else ""
                        ),
                        "collector_name": "",
                    }
                )
        return entries

    def _build_record(
        self, entry: Dict[str, Any], all_entries: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Build record.

        The normalized artifact path is authoritative. A caller-supplied
        file-index DUT ID must not redirect metadata lookup outside that DUT.

        Args:
            entry: Mapping supplying fields for record.
            all_entries: Mapping supplying fields for record.

        Returns:
            A mapping containing the ``artifact_path``, ``archive_member_path``,
            ``filename``, ``size_bytes``, and ``source_dut`` fields.
        """
        relative_path = self._normalize_relative_path(entry.get("path"))
        if relative_path is None or not self._is_controller_artifact(
            entry, relative_path
        ):
            return None

        artifact_path = self._safe_regular_artifact(self.log_dir / relative_path)
        if artifact_path is None:
            return None

        base_name, compression = self._strip_compression(artifact_path.name)
        parsed, filename_identifies_core = self._parse_filename(base_name)
        validation = self._validate_artifact(artifact_path, compression)
        if (
            validation not in ELF_CORE_CANDIDATE_VALIDATIONS
            and not filename_identifies_core
        ):
            return None

        # The normalized artifact path is authoritative. A caller-supplied
        # file-index DUT ID must not redirect metadata lookup outside that DUT.
        dut_id = relative_path.parts[0]
        dut_dir = self.log_dir / dut_id
        dut_metadata = self._read_dut_metadata(dut_dir)
        baseboard = str(
            dut_metadata.get("baseboard") or dut_metadata.get("TargetBaseboard") or ""
        )

        commit, commit_source, machine, machine_source = (
            self._resolve_analyzer_metadata(dut_id, dut_metadata, all_entries)
        )

        missing_required = []
        preparation_required = []
        if not commit:
            missing_required.append("openbmc_commit")
        if not machine:
            missing_required.append("machine")
        if validation == "compressed_core_not_inspected":
            preparation_required.append(
                "Decompress a copy of the core before analyzer upload; preserve "
                "the collected artifact unchanged."
            )
        elif validation == "elf_core_requires_manual_validation":
            missing_required.append("valid_core_dump")
            preparation_required.append(
                "Validate the complete ELF core structure before analyzer upload."
            )
        elif validation != "validated_raw_elf_core":
            missing_required.append("valid_core_dump")

        warnings = []
        if not parsed.get("service"):
            warnings.append(
                "Service was not present in the filename; use analyzer "
                "auto-detection or provide it manually."
            )
        if not parsed.get("timestamp"):
            warnings.append("Crash timestamp was inferred from collected file mtime.")

        timestamp = parsed.get("timestamp") or self._mtime(artifact_path)
        collector_path = relative_path.parent.as_posix()
        ready = not missing_required and not preparation_required
        return {
            "artifact_path": relative_path.as_posix(),
            "archive_member_path": None,
            "filename": artifact_path.name,
            # The collected artifact is authoritative; file-index size is
            # descriptive input and may be stale or malformed.
            "size_bytes": self._file_size(artifact_path),
            "source_dut": dut_id,
            "collector": {
                "id": str(entry.get("collector_id") or ""),
                "name": str(entry.get("collector_name") or ""),
                "group": str(entry.get("collector_group") or ""),
                "path": collector_path,
            },
            "openbmc_commit": commit,
            "machine": machine,
            "baseboard": baseboard or None,
            "service": parsed.get("service"),
            "pid": parsed.get("pid"),
            "timestamp": timestamp,
            "compression": compression or "raw",
            "validation": validation,
            "metadata_sources": {
                "openbmc_commit": commit_source,
                "machine": machine_source,
                "service": "filename" if parsed.get("service") else None,
                "timestamp": "filename" if parsed.get("timestamp") else "file_mtime",
            },
            "ready_for_analyzer": ready,
            "missing_required_metadata": missing_required,
            "preparation_required": preparation_required,
            "warnings": warnings,
            "handoff": {
                "action": "manual_upload",
                "analyzer_url": None,
                "upload_performed": False,
            },
        }

    def _is_archive_candidate(self, entry: Dict[str, Any]) -> bool:
        """
        Return whether ``entry`` is archive candidate.

        The implementation uses ``entry`` to determine whether ``entry`` is
        archive candidate.

        Args:
            entry: Mapping supplying fields for ``entry`` is archive candidate.

        Returns:
            Whether ``entry`` is archive candidate.
        """
        relative = self._normalize_relative_path(entry.get("path"))
        if relative is None or not self._is_controller_artifact(entry, relative):
            return False
        lowered = relative.name.lower()
        return any(lowered.endswith(suffix) for suffix in SUPPORTED_ARCHIVE_SUFFIXES)

    def _entry_file_size(self, entry: Dict[str, Any]) -> int:
        """
        Return the entry file size.

        The implementation uses ``entry`` to produce the entry file size.

        Args:
            entry: Mapping supplying fields for entry file size.

        Returns:
            The numeric entry file size.
        """
        relative = self._normalize_relative_path(entry.get("path"))
        if relative is None:
            return 0
        path = self._safe_regular_artifact(self.log_dir / relative)
        return self._file_size(path) if path is not None else 0

    def _record_uninspected_archive(
        self,
        entry: Dict[str, Any],
        reason: str,
        status: str,
    ) -> None:
        """
        Record uninspected archive.

        The implementation uses ``entry``, ``reason``, and ``status`` to record
        uninspected archive. It updates ``_uninspected_archive_count`` on the
        instance as part of that state transition.

        Args:
            entry: Mapping supplying fields for record uninspected archive.
            reason: Text supplied as reason in the format accepted by this
                function.
            status: Text supplied as status in the format accepted by this
                function.
        """
        self._uninspected_archive_count += 1
        if len(self._uninspected_archives) >= UNINSPECTED_ARCHIVE_DETAIL_LIMIT:
            return
        relative = self._normalize_relative_path(entry.get("path"))
        self._uninspected_archives.append(
            {
                "artifact_path": (
                    relative.as_posix() if relative is not None else "<invalid path>"
                ),
                "size_bytes": self._entry_file_size(entry),
                "status": status,
                "reason": reason,
            }
        )

    def _scan_archive(
        self,
        entry: Dict[str, Any],
        all_entries: List[Dict[str, Any]],
        *,
        core_record_limit: int,
    ) -> List[Dict[str, Any]]:
        """
        Index core members without extracting or modifying an archive.

        The implementation uses ``entry``, ``all_entries``, and
        ``core_record_limit`` to index core members without extracting or
        modifying an archive. It updates ``_archive_decompressed_bytes``,
        ``_archive_input_bytes``, ``_archive_members_inspected``,
        ``_archives_inspected``, and ``_record_limit_reached`` on the instance
        as part of that state transition. If the function cannot index core
        members without extracting or modifying an archive, its exception
        reaches the caller instead of being converted into a successful result.
        Cleanup in the ``finally`` path runs for successful, failed, and
        cancelled execution.

        Args:
            entry: Mapping supplying fields for index core members without
                extracting or modifying an archive.
            all_entries: Mapping supplying fields for index core members without
                extracting or modifying an archive.
            core_record_limit: Upper bound enforced for core record limit; the
                consuming boundary rejects or truncates values that exceed it.

        Returns:
            The scan archive returned in operation-defined order.

        Raises:
            ValueError: If archive path is missing, unsafe, or non-regular; or
                archive is empty.
            ArchiveLimitExceeded: If compressed archive exceeds
                ``ARCHIVE_INPUT_SIZE_LIMIT`` bytes.
        """
        relative = self._normalize_relative_path(entry.get("path"))
        if relative is None or not self._is_controller_artifact(entry, relative):
            return []
        archive_path = self._safe_regular_artifact(self.log_dir / relative)
        if archive_path is None:
            raise ValueError("archive path is missing, unsafe, or non-regular")

        archive_size = self._file_size(archive_path)
        if archive_size <= 0:
            raise ValueError("archive is empty")
        if archive_size > ARCHIVE_INPUT_SIZE_LIMIT:
            raise ArchiveLimitExceeded(
                f"compressed archive exceeds {ARCHIVE_INPUT_SIZE_LIMIT} bytes"
            )
        if relative.name.lower().endswith(".zip"):
            self._record_uninspected_archive(
                entry,
                "zip_archive_not_inspected",
                "unsupported",
            )
            self._scan_warnings.append(
                f"Controller ZIP archive {relative.as_posix()} was preserved "
                "but not inspected by the bounded tar scanner."
            )
            return []
        if core_record_limit <= 0:
            self._record_limit_reached = True
            self._record_uninspected_archive(
                entry,
                "core_record_limit",
                "skipped",
            )
            return []

        core_members: List[Dict[str, Any]] = []
        archive_commit: Optional[str] = None
        archive_commit_source: Optional[str] = None
        archive_commit_priority = 100
        archive_machine: Optional[str] = None
        archive_machine_source: Optional[str] = None
        archive_machine_priority = 100
        metadata_bytes = 0
        metadata_limit_reached = False
        partial_reason: Optional[str] = None

        remaining_global_decompressed = (
            ARCHIVE_DECOMPRESSED_TOTAL_LIMIT - self._archive_decompressed_bytes
        )
        if remaining_global_decompressed <= 0:
            self._record_uninspected_archive(
                entry,
                "archive_decompressed_total_limit",
                "skipped",
            )
            self._scan_warnings.append(
                "Controller archive was not inspected because the global "
                f"decompressed-input budget of "
                f"{ARCHIVE_DECOMPRESSED_TOTAL_LIMIT} bytes was reached."
            )
            return []
        remaining_global_members = (
            ARCHIVE_MEMBER_TOTAL_LIMIT - self._archive_members_inspected
        )
        if remaining_global_members <= 0:
            self._record_uninspected_archive(
                entry,
                "archive_member_total_limit",
                "skipped",
            )
            self._scan_warnings.append(
                "Controller archive was not inspected because the global "
                f"member budget of {ARCHIVE_MEMBER_TOTAL_LIMIT} was reached."
            )
            return []
        decompressed_limit = min(
            ARCHIVE_DECOMPRESSED_SIZE_LIMIT,
            remaining_global_decompressed,
        )
        self._archive_input_bytes += archive_size

        scanner = BoundedTarScanner(
            archive_path,
            decompressed_limit=decompressed_limit,
            logical_size_limit=ARCHIVE_LOGICAL_SIZE_LIMIT,
            member_limit=min(
                ARCHIVE_MEMBER_LIMIT,
                remaining_global_members,
            ),
            member_name_limit=ARCHIVE_MEMBER_NAME_LIMIT,
            max_zstd_window_bytes=ZSTD_MAX_WINDOW_BYTES,
            max_xz_decoder_memory_bytes=XZ_MAX_DECODER_MEMORY_BYTES,
            compressed_size_limit=ARCHIVE_INPUT_SIZE_LIMIT,
            max_seconds=ARCHIVE_SCAN_SECONDS_LIMIT,
            max_zstd_frames=ARCHIVE_MEMBER_LIMIT,
        )

        def inspect_member(
            member: SafeTarMember,
            read_member: MemberReader,
        ) -> None:
            """
            Inspect member.

            The implementation uses ``member`` and ``read_member`` to inspect
            member. If the function cannot inspect member, its exception reaches
            the caller instead of being converted into a successful result.

            Args:
                member: Member object whose ``mtime``, ``path``, and ``size``
                    state is read while performing inspect member.
                read_member: Read member consumed while the function attempts to
                    inspect member.

            Raises:
                CoreRecordLimitExceeded: If core record limit of
                    ``CORE_RECORD_LIMIT`` reached.
            """
            nonlocal archive_commit
            nonlocal archive_commit_priority
            nonlocal archive_commit_source
            nonlocal archive_machine
            nonlocal archive_machine_priority
            nonlocal archive_machine_source
            nonlocal metadata_bytes
            nonlocal metadata_limit_reached

            member_path = member.path
            metadata_priority = self._archive_metadata_priority(member_path)
            member_data: Optional[bytes] = None
            if metadata_priority is not None:
                remaining_metadata = ARCHIVE_METADATA_TOTAL_LIMIT - metadata_bytes
                if (
                    member.size <= TEXT_METADATA_FILE_LIMIT
                    and member.size <= remaining_metadata
                ):
                    member_data = read_member(member.size)
                    metadata_bytes += len(member_data)
                    text = member_data.decode("utf-8", errors="replace")
                    commit, machine = self._metadata_from_text(text)
                    source = f"{relative.as_posix()}::{member_path.as_posix()}"
                    if commit and metadata_priority < archive_commit_priority:
                        archive_commit = commit
                        archive_commit_source = source
                        archive_commit_priority = metadata_priority
                    if machine and metadata_priority < archive_machine_priority:
                        archive_machine = machine
                        archive_machine_source = source
                        archive_machine_priority = metadata_priority
                else:
                    metadata_limit_reached = True

            base_name, compression = self._strip_compression(member_path.name)
            parsed, filename_identifies_core = self._parse_filename(base_name)
            if compression and filename_identifies_core:
                validation = "compressed_archive_member_not_inspected"
            else:
                header = (
                    member_data[:ELF_VALIDATION_READ_LIMIT]
                    if member_data is not None
                    else read_member(min(member.size, ELF_VALIDATION_READ_LIMIT))
                )
                validation = self._validate_elf_header(
                    header,
                    member.size,
                )
                if (
                    validation not in ELF_CORE_CANDIDATE_VALIDATIONS
                    and not filename_identifies_core
                ):
                    return

            if len(core_members) >= core_record_limit:
                raise CoreRecordLimitExceeded(
                    f"core record limit of {CORE_RECORD_LIMIT} reached"
                )
            core_members.append(
                {
                    "member_path": member_path.as_posix(),
                    "size": member.size,
                    "parsed": parsed,
                    "compression": compression,
                    "validation": validation,
                    "mtime": member.mtime,
                }
            )

        try:
            scanner.scan(inspect_member)
        except CoreRecordLimitExceeded:
            self._record_limit_reached = True
            partial_reason = "core_record_limit"
            self._scan_warnings.append(
                f"Controller archive {relative.as_posix()} contains more core "
                f"records than the global limit of {CORE_RECORD_LIMIT}; "
                "collected artifacts remain unchanged."
            )
        except (
            ArchiveLimitExceeded,
            ArchiveScanError,
        ) as exc:
            partial_reason = f"{type(exc).__name__}: {exc}"
            self._scan_warnings.append(
                f"Controller archive {relative.as_posix()} could not be fully "
                f"inspected: {partial_reason}"
            )
        finally:
            self._archive_compressed_bytes_read += scanner.compressed_bytes
            if scanner.compressed_bytes >= archive_size:
                self._archives_inspected += 1
            self._archive_decompressed_bytes += scanner.decompressed_bytes
            self._archive_members_inspected += scanner.members_visited

        if scanner.member_limit_reached:
            reached_global_member_limit = (
                self._archive_members_inspected >= ARCHIVE_MEMBER_TOTAL_LIMIT
            )
            partial_reason = (
                "archive_member_total_limit"
                if reached_global_member_limit
                else "archive_member_limit"
            )
            limit = (
                ARCHIVE_MEMBER_TOTAL_LIMIT
                if reached_global_member_limit
                else ARCHIVE_MEMBER_LIMIT
            )
            self._scan_warnings.append(
                f"Controller archive {relative.as_posix()} scan stopped after "
                f"{limit} {'total ' if reached_global_member_limit else ''}members."
            )
        if metadata_limit_reached:
            partial_reason = partial_reason or "archive_metadata_total_limit"
            self._scan_warnings.append(
                f"Controller archive {relative.as_posix()} metadata scan was "
                f"limited to {ARCHIVE_METADATA_TOTAL_LIMIT} bytes."
            )
        if scanner.rejected_members:
            partial_reason = partial_reason or "unsafe_or_non_regular_members"
            self._scan_warnings.append(
                f"Controller archive {relative.as_posix()} ignored "
                f"{scanner.rejected_members} unsafe or non-regular member(s)."
            )
        if partial_reason:
            self._record_uninspected_archive(
                entry,
                partial_reason,
                "partial",
            )

        dut_id = relative.parts[0]
        dut_dir = self.log_dir / dut_id
        dut_metadata = self._read_dut_metadata(dut_dir)
        baseboard = str(
            dut_metadata.get("baseboard") or dut_metadata.get("TargetBaseboard") or ""
        )
        (
            fallback_commit,
            fallback_commit_source,
            fallback_machine,
            fallback_machine_source,
        ) = self._resolve_analyzer_metadata(dut_id, dut_metadata, all_entries)
        commit = archive_commit or fallback_commit
        commit_source = archive_commit_source or fallback_commit_source
        machine = archive_machine or fallback_machine
        machine_source = archive_machine_source or fallback_machine_source

        return [
            self._build_archive_record(
                entry=entry,
                relative=relative,
                archive_size=archive_size,
                core_member=core_member,
                baseboard=baseboard,
                commit=commit,
                commit_source=commit_source,
                machine=machine,
                machine_source=machine_source,
            )
            for core_member in core_members
        ]

    @staticmethod
    def _normalize_archive_member_path(value: Any) -> Optional[PurePosixPath]:
        """
        Normalize archive member path.

        After applying local validation, the function forwards ``value`` to
        ``normalize_tar_member_path`` and preserves its return and exception
        contract. The source value keeps its ownership while the normalized
        representation is returned separately.

        Args:
            value: Value evaluated while performing archive member path.

        Returns:
            The validated archive member path filesystem path, or ``None`` when
            the requested value is unavailable.
        """
        return normalize_tar_member_path(value)

    @staticmethod
    def _archive_metadata_priority(path: PurePosixPath) -> Optional[int]:
        """
        Archive metadata priority.

        The implementation uses ``path`` to archive metadata priority. Success
        is reported only after the owning output boundary has completed its
        required write or publication step.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The numeric archive metadata priority value, or ``None`` when the
            requested value is unavailable.
        """
        name = path.name.lower()
        if name == "os-release" or "bmc_stack_info" in name:
            return 0
        if name in {"bmc_version.txt", "openbmc_version.txt"}:
            return 1
        if ("version" in name or "release" in name) and path.suffix.lower() in {
            "",
            ".txt",
            ".log",
            ".conf",
        }:
            return 2
        return None

    def _build_archive_record(
        self,
        *,
        entry: Dict[str, Any],
        relative: PurePosixPath,
        archive_size: int,
        core_member: Dict[str, Any],
        baseboard: str,
        commit: Optional[str],
        commit_source: Optional[str],
        machine: Optional[str],
        machine_source: Optional[str],
    ) -> Dict[str, Any]:
        """
        Build archive record.

        The implementation uses ``entry``, ``relative``, ``archive_size``,
        ``core_member``, and ``baseboard`` to build archive record.

        Args:
            entry: Mapping supplying fields for archive record.
            relative: filesystem location used as the relative for this
                operation.
            archive_size: Numeric archive size used by the operation's bounded
                accounting.
            core_member: Mapping supplying fields for archive record.
            baseboard: Text supplied as baseboard in the format accepted by this
                function.
            commit: Text supplied as commit in the format accepted by this
                function.
            commit_source: Text supplied as commit source in the format accepted
                by this function.
            machine: Text supplied as machine in the format accepted by this
                function.
            machine_source: Text supplied as machine source in the format
                accepted by this function.

        Returns:
            A mapping containing the ``artifact_path``, ``archive_member_path``,
            ``filename``, ``size_bytes``, and ``outer_archive_size_bytes``
            fields.
        """
        member_path = PurePosixPath(core_member["member_path"])
        parsed = core_member["parsed"]
        validation = core_member["validation"]
        compression = core_member["compression"]
        missing_required = []
        if not commit:
            missing_required.append("openbmc_commit")
        if not machine:
            missing_required.append("machine")
        if validation not in {
            "validated_raw_elf_core",
            "compressed_archive_member_not_inspected",
        }:
            missing_required.append("valid_core_dump")

        preparation_required = [
            "Extract the recorded archive member from a copy of the manager "
            "dump; preserve the collected archive unchanged."
        ]
        if compression:
            preparation_required.append(
                "Decompress the extracted core copy before analyzer upload; "
                "preserve the collected archive and member unchanged."
            )
        if validation == "elf_core_requires_manual_validation":
            preparation_required.append(
                "Validate the complete ELF core structure before analyzer upload."
            )

        warnings = []
        if not parsed.get("service"):
            warnings.append(
                "Service was not present in the member filename; use analyzer "
                "auto-detection or provide it manually."
            )
        if not parsed.get("timestamp"):
            warnings.append(
                "Crash timestamp was inferred from the archive member mtime."
            )

        member_mtime = core_member.get("mtime")
        timestamp = parsed.get("timestamp")
        if timestamp is None and isinstance(member_mtime, (int, float)):
            timestamp = self._epoch_to_iso(int(member_mtime))
        dut_id = relative.parts[0]
        return {
            "artifact_path": relative.as_posix(),
            "archive_member_path": member_path.as_posix(),
            "filename": member_path.name,
            "size_bytes": int(core_member["size"]),
            "outer_archive_size_bytes": archive_size,
            "source_dut": dut_id,
            "collector": {
                "id": str(entry.get("collector_id") or ""),
                "name": str(entry.get("collector_name") or ""),
                "group": str(entry.get("collector_group") or ""),
                "path": relative.parent.as_posix(),
            },
            "openbmc_commit": commit,
            "machine": machine,
            "baseboard": baseboard or None,
            "service": parsed.get("service"),
            "pid": parsed.get("pid"),
            "timestamp": timestamp,
            "compression": compression or "raw",
            "validation": validation,
            "metadata_sources": {
                "openbmc_commit": commit_source,
                "machine": machine_source,
                "service": "archive_member_filename" if parsed.get("service") else None,
                "timestamp": (
                    "archive_member_filename"
                    if parsed.get("timestamp")
                    else "archive_member_mtime"
                ),
            },
            "ready_for_analyzer": False,
            "missing_required_metadata": missing_required,
            "preparation_required": preparation_required,
            "warnings": warnings,
            "handoff": {
                "action": "manual_upload",
                "analyzer_url": None,
                "upload_performed": False,
            },
        }

    def _resolve_analyzer_metadata(
        self,
        dut_id: str,
        dut_metadata: Dict[str, Any],
        all_entries: List[Dict[str, Any]],
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Resolve analyzer metadata.

        The implementation uses ``dut_id``, ``dut_metadata``, and
        ``all_entries`` to resolve analyzer metadata.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut_metadata: Mapping supplying fields for analyzer metadata.
            all_entries: Mapping supplying fields for analyzer metadata.

        Returns:
            A tuple containing the fields that represent analyzer metadata, or
            ``None`` when the requested value is unavailable.
        """
        if dut_id in self._metadata_cache:
            return self._metadata_cache[dut_id]

        commit, commit_source, machine, machine_source = (
            self._search_collected_controller_text(dut_id, all_entries)
        )

        if not commit:
            configured_commit = _first_nested_value(dut_metadata, _COMMIT_KEYS)
            if configured_commit:
                match = _COMMIT_VALUE.fullmatch(configured_commit)
                if match:
                    commit = match.group("sha").lower()
                    commit_source = "dut_config.json"

        if not machine:
            configured_machine = _first_nested_value(dut_metadata, _MACHINE_KEYS)
            if configured_machine:
                machine = configured_machine.lower()
                machine_source = "dut_config.json"

        result = (commit, commit_source, machine, machine_source)
        self._metadata_cache[dut_id] = result
        return result

    def _search_collected_controller_text(
        self, dut_id: str, entries: List[Dict[str, Any]]
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Return the search collected controller text.

        The implementation uses ``dut_id`` and ``entries`` to produce the search
        collected controller text.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            entries: Mapping supplying fields for search collected controller
                text.

        Returns:
            A tuple containing ``commit``, ``commit source``, ``machine``, and
            ``machine source`` in that order.
        """
        candidates: List[Tuple[int, str, Path, int]] = []
        for entry in entries:
            relative = self._normalize_relative_path(entry.get("path"))
            if (
                relative is None
                or relative.parts[0] != dut_id
                or not self._is_controller_artifact(entry, relative)
            ):
                continue
            suffix = relative.suffix.lower()
            if suffix not in {"", ".txt", ".log", ".conf"}:
                continue
            path = self._safe_regular_artifact(self.log_dir / relative)
            if path is None:
                continue
            size = self._file_size(path)
            if size <= 0 or size > TEXT_METADATA_FILE_LIMIT:
                continue
            base_name, compression = self._strip_compression(path.name)
            _, filename_identifies_core = self._parse_filename(base_name)
            if (
                filename_identifies_core
                or self._validate_artifact(path, compression)
                in ELF_CORE_CANDIDATE_VALIDATIONS
            ):
                # Do not mine process memory for build metadata. Besides being
                # untrusted provenance, a small raw systemd core has no suffix
                # and otherwise looks like a text-metadata candidate.
                continue
            lowered = path.name.lower()
            priority = (
                0
                if "bmc_stack_info" in lowered or "os-release" in lowered
                else 1 if "version" in lowered or "release" in lowered else 2
            )
            candidates.append((priority, relative.as_posix(), path, size))

        commit: Optional[str] = None
        commit_source: Optional[str] = None
        machine: Optional[str] = None
        machine_source: Optional[str] = None
        consumed = 0
        for _, relative_text_path, path, size in sorted(candidates)[
            :TEXT_METADATA_CANDIDATE_LIMIT
        ]:
            if consumed + size > TEXT_METADATA_TOTAL_LIMIT:
                break
            consumed += size
            try:
                text = _read_regular_file_bounded(
                    path,
                    TEXT_METADATA_FILE_LIMIT,
                ).decode("utf-8", errors="replace")
            except (OSError, ValueError):
                continue

            parsed_commit, parsed_machine = self._metadata_from_text(text)
            if not commit and parsed_commit:
                commit = parsed_commit
                commit_source = relative_text_path
            if not machine and parsed_machine:
                machine = parsed_machine
                machine_source = relative_text_path
            if commit and machine:
                break
        return commit, commit_source, machine, machine_source

    @staticmethod
    def _metadata_from_text(
        text: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Return the metadata from text.

        The implementation uses ``text`` to produce the metadata from text.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            A tuple containing ``commit`` and ``machine`` in that order.
        """
        commit_match = _COMMIT_ENV.search(text) or _COMMIT_IN_TEXT.search(text)
        machine_match = _MACHINE_ENV.search(text) or _MACHINE_IN_TEXT.search(text)
        commit = commit_match.group("sha").lower() if commit_match is not None else None
        machine = (
            machine_match.group("machine").lower()
            if machine_match is not None
            else None
        )
        return commit, machine

    def _read_dut_metadata(self, dut_dir: Path) -> Dict[str, Any]:
        """
        Read DUT metadata.

        The implementation uses ``dut_dir`` to read DUT metadata. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            dut_dir: filesystem location used as the DUT dir for this operation.

        Returns:
            The validated ``merged``.
        """
        merged: Dict[str, Any] = {}
        for path in (
            dut_dir / "dut_config.json",
            dut_dir / ".metadata" / "openbmc_coredump.json",
            dut_dir / "metadata" / "openbmc_coredump.json",
        ):
            safe_path = self._safe_regular_artifact(path)
            if safe_path is None:
                continue
            try:
                data = json.loads(
                    _read_regular_file_bounded(
                        safe_path,
                        DUT_METADATA_FILE_LIMIT,
                    ).decode("utf-8")
                )
                _validate_metadata_json_shape(data)
            except (
                OSError,
                UnicodeError,
                ValueError,
                json.JSONDecodeError,
                RecursionError,
            ):
                continue
            if isinstance(data, dict):
                merged.update(data)
        return merged

    @staticmethod
    def _strip_compression(filename: str) -> Tuple[str, Optional[str]]:
        """
        Return the strip compression.

        The implementation uses ``filename`` to produce the strip compression.

        Args:
            filename: Text supplied as filename in the format accepted by this
                function.

        Returns:
            A tuple containing the filename without a recognized compression
            suffix and that suffix, or ``None`` when the name is uncompressed.
        """
        lowered = filename.lower()
        for suffix in SUPPORTED_COMPRESSION_SUFFIXES:
            if lowered.endswith(suffix):
                return filename[: -len(suffix)], suffix
        return filename, None

    @staticmethod
    def _parse_filename(base_name: str) -> Tuple[Dict[str, Any], bool]:
        """
        Parse filename.

        The implementation uses ``base_name`` to parse filename. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            base_name: Stable base name used for lookup and operator-facing
                diagnostics.

        Returns:
            A tuple containing ``metadata mapping`` and ``success flag`` in that
            order.
        """
        for pattern in (
            _SYSTEMD_FULL_NAME,
            _SYSTEMD_SHORT_NAME,
            _CORE_UNDERSCORE_NAME,
            _SERVICE_CORE_NAME,
        ):
            match = pattern.fullmatch(base_name)
            if not match:
                continue
            values: Dict[str, Any] = match.groupdict()
            if values.get("pid"):
                values["pid"] = int(values["pid"])
            if values.get("timestamp"):
                values["timestamp"] = OpenBMCCoreDumpManifestService._epoch_to_iso(
                    int(values["timestamp"])
                )
            return values, True
        return {}, False

    @staticmethod
    def _epoch_to_iso(value: int) -> Optional[str]:
        # systemd commonly puts microseconds since epoch in the core filename.
        """
        Return the epoch to iso.

        After applying local validation, the function forwards ``value`` to
        ``isoformat`` and preserves its return and exception contract.

        Args:
            value: Numeric value used while the operation performs bounded
                accounting.

        Returns:
            The canonical epoch to iso text, or ``None`` when the requested
            value is unavailable.
        """
        seconds = value / 1_000_000 if value > 10_000_000_000 else value
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None

    @staticmethod
    def _validate_artifact(path: Path, compression: Optional[str]) -> str:
        """
        Validate artifact.

        The implementation uses ``path`` and ``compression`` to validate
        artifact. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path. Filesystem effects remain confined to the caller-selected paths
        and the owning resource lifecycle.

        Args:
            path: filesystem location used as the path for this operation.
            compression: Text supplied as compression in the format accepted by
                this function.

        Returns:
            The canonical artifact text.
        """
        if compression:
            return "compressed_core_not_inspected"
        try:
            file_size = path.stat().st_size
            with path.open("rb") as stream:
                header = stream.read(ELF_VALIDATION_READ_LIMIT)
        except OSError:
            return "unreadable"
        return OpenBMCCoreDumpManifestService._validate_elf_header(
            header,
            file_size,
        )

    @staticmethod
    def _validate_elf_header(header: bytes, file_size: int) -> str:
        """
        Validate enough ELF structure to call an artifact a usable core.

        The implementation uses ``header`` and ``file_size`` to validate enough
        ELF structure to call an artifact a usable core. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path.

        Args:
            header: Bounded byte sequence supplied as header.
            file_size: Numeric file size used by the operation's bounded
                accounting.

        Returns:
            The canonical elf header text.
        """
        if len(header) < 20 or header[:4] != b"\x7fELF":
            return "invalid_raw_elf_core"
        elf_class = header[4]
        byte_order = {1: "little", 2: "big"}.get(header[5])
        if byte_order is None or header[6] != 1:
            return "invalid_raw_elf_core"
        if int.from_bytes(header[16:18], byte_order) != 4:
            return "invalid_raw_elf_core"
        if int.from_bytes(header[20:24], byte_order) != 1:
            return "invalid_raw_elf_core"

        if elf_class == 1:
            expected_header_size = 52
            expected_program_header_size = 32
            offsets = {
                "program_header": (28, 32),
                "header_size": (40, 42),
                "entry_size": (42, 44),
                "entry_count": (44, 46),
            }
            segment_offsets = {
                "file_offset": (4, 8),
                "file_size": (16, 20),
                "memory_size": (20, 24),
            }
        elif elf_class == 2:
            expected_header_size = 64
            expected_program_header_size = 56
            offsets = {
                "program_header": (32, 40),
                "header_size": (52, 54),
                "entry_size": (54, 56),
                "entry_count": (56, 58),
            }
            segment_offsets = {
                "file_offset": (8, 16),
                "file_size": (32, 40),
                "memory_size": (40, 48),
            }
        else:
            return "invalid_raw_elf_core"

        if len(header) < expected_header_size:
            return "invalid_raw_elf_core"

        def read_field(name: str) -> int:
            """
            Read field.

            After applying local validation, the function forwards ``name`` to
            ``int.from_bytes`` and preserves its return and exception contract.
            Parsing or I/O must finish before the validated representation is
            made available to the caller.

            Args:
                name: Stable name used for lookup and operator-facing
                    diagnostics.

            Returns:
                The numeric field value.
            """
            start, end = offsets[name]
            return int.from_bytes(header[start:end], byte_order)

        program_header_offset = read_field("program_header")
        header_size = read_field("header_size")
        entry_size = read_field("entry_size")
        entry_count = read_field("entry_count")
        if (
            header_size != expected_header_size
            or entry_size < expected_program_header_size
            or entry_size > 4096
            or entry_count <= 0
            or entry_count == 0xFFFF
            or program_header_offset < header_size
        ):
            return "invalid_raw_elf_core"

        table_end = program_header_offset + entry_size * entry_count
        if table_end > file_size:
            return "invalid_raw_elf_core"
        if table_end > len(header):
            return "elf_core_requires_manual_validation"

        usable_core_segment = False
        for index in range(entry_count):
            entry_offset = program_header_offset + index * entry_size

            def read_segment_field(name: str) -> int:
                """
                Read segment field.

                After applying local validation, the function forwards ``name``
                to ``int.from_bytes`` and preserves its return and exception
                contract. Parsing or I/O must finish before the validated
                representation is made available to the caller.

                Args:
                    name: Stable name used for lookup and operator-facing
                        diagnostics.

                Returns:
                    The numeric segment field value.
                """
                start, end = segment_offsets[name]
                return int.from_bytes(
                    header[entry_offset + start : entry_offset + end],
                    byte_order,
                )

            program_type = int.from_bytes(
                header[entry_offset : entry_offset + 4],
                byte_order,
            )
            segment_file_offset = read_segment_field("file_offset")
            segment_file_size = read_segment_field("file_size")
            segment_memory_size = read_segment_field("memory_size")
            if segment_file_size:
                if (
                    segment_file_offset > file_size
                    or segment_file_size > file_size - segment_file_offset
                ):
                    return "invalid_raw_elf_core"
                if program_type == 1 and segment_file_size > segment_memory_size:
                    return "invalid_raw_elf_core"
                if program_type in {1, 4}:
                    usable_core_segment = True
        if not usable_core_segment:
            return "invalid_raw_elf_core"
        return "validated_raw_elf_core"

    @staticmethod
    def _is_controller_artifact(
        entry: Dict[str, Any], relative_path: PurePosixPath
    ) -> bool:
        # The collection directory is authoritative when it names a known
        # domain. File-index metadata must not relabel a host core as a BMC one.
        """
        Return whether ``entry`` is controller artifact.

        The implementation uses ``entry`` and ``relative_path`` to determine
        whether ``entry`` is controller artifact.

        Args:
            entry: Mapping supplying fields for ``entry`` is controller
                artifact.
            relative_path: filesystem location used as the relative path for
                this operation.

        Returns:
            Whether ``entry`` is controller artifact.
        """
        path_group = (
            relative_path.parts[1].lower() if len(relative_path.parts) > 1 else ""
        )
        if path_group in NON_CONTROLLER_GROUPS:
            return False
        if path_group in CONTROLLER_GROUPS:
            return True

        group = str(entry.get("collector_group") or "").strip().lower()
        if group in NON_CONTROLLER_GROUPS:
            return False
        if group in CONTROLLER_GROUPS:
            return True
        return any(
            part.lower() in CONTROLLER_GROUPS for part in relative_path.parts[1:3]
        )

    @staticmethod
    def _normalize_relative_path(value: Any) -> Optional[PurePosixPath]:
        """
        Normalize relative path.

        The implementation uses ``value`` to normalize relative path. The source
        value keeps its ownership while the normalized representation is
        returned separately. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            value: Value evaluated while performing relative path.

        Returns:
            The validated ``path``, or ``None`` when no value qualifies.
        """
        raw = str(value or "").replace("\\", "/")
        if not raw or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in raw
        ):
            return None
        path = PurePosixPath(raw)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            return None
        return path

    def _safe_regular_artifact(self, path: Path) -> Optional[Path]:
        """
        Return the safe regular artifact.

        The implementation uses ``path`` to produce the safe regular artifact.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The validated ``resolved``, or ``None`` when no value qualifies.
        """
        try:
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                return None
            resolved = path.resolve(strict=True)
            root = self.log_dir.resolve(strict=True)
            resolved.relative_to(root)
        except (FileNotFoundError, OSError, RuntimeError, ValueError):
            return None
        return resolved

    def _require_path_below_log_root(self, path: Path) -> None:
        """
        Require path below log root.

        The implementation uses ``path`` to require path below log root. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            path: filesystem location used as the path for this operation.

        Raises:
            ValueError: If manifest path must remain below collection root:
                ``path``.
        """
        try:
            root = self.log_dir.resolve(strict=True)
            parent = path.parent.resolve(strict=True)
            parent.relative_to(root)
        except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
            raise ValueError(
                f"Manifest path must remain below collection root: {path}"
            ) from exc

    def _require_candidate_path_below_log_root(self, path: Path) -> None:
        """
        Validate a not-yet-created output parent without mutating it.

        The implementation uses ``path`` to validate a not-yet-created output
        parent without mutating it. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            path: filesystem location used as the path for this operation.

        Raises:
            ValueError: If manifest path must remain below collection root:
                ``path``.
        """
        try:
            root = self.log_dir.resolve(strict=True)
            parent = path.parent.resolve(strict=False)
            parent.relative_to(root)
        except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
            raise ValueError(
                f"Manifest path must remain below collection root: {path}"
            ) from exc

    @staticmethod
    def _mtime(path: Path) -> Optional[str]:
        """
        Return the mtime.

        After applying local validation, the function forwards ``path`` to
        ``isoformat`` and preserves its return and exception contract.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The canonical mtime text, or ``None`` when the requested value is
            unavailable.
        """
        try:
            return datetime.fromtimestamp(
                path.stat().st_mtime, tz=timezone.utc
            ).isoformat()
        except OSError:
            return None

    @staticmethod
    def _file_size(path: Path) -> int:
        """
        Return the file size.

        The implementation uses ``path`` to produce the file size. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The numeric file size.
        """
        try:
            return path.stat().st_size
        except OSError:
            return 0
