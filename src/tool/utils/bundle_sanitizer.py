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
Sanitize textual artifacts in a completed nvdebug bundle.

Collector implementations are intentionally allowed to persist opaque binary
artifacts. Text, on the other hand, must pass through the run sanitizer before
the bundle is handed to a user. This module supplies the finalization backstop
for writers which do not use :class:`AsyncSafeLogger` directly, including text
members inside common nested archive formats.

The sanitizer never rewrites a payload unless it can classify it as text or as a
supported archive containing changed text. In particular, arbitrary binary
collector output is preserved byte-for-byte.
"""

from __future__ import annotations

import bz2
import copy
import datetime
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import stat
import tarfile
import tempfile
import time
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

import yaml

from .archive_member_policy import (
    has_unsafe_member_characters,
    is_unsafe_portable_component,
)
from .archive_validation import (
    ARCHIVE_VALIDATION_PRIMARY_ROLE,
    ARCHIVE_VALIDATION_PRODUCER,
    ARCHIVE_VALIDATION_REFERENCE_ROLE,
    ARCHIVE_VALIDATION_SCHEMA,
    ARCHIVE_VALIDATION_SUPPORTED_SUFFIXES,
    archive_validation_is_sha256,
    archive_validation_load_json,
    archive_validation_path_sha256,
    archive_validation_receipt_id,
)
from .changed_file_transaction import (
    SnapshotDirectory,
    SnapshotFile,
    StagedReplacement,
    publish_changed_files,
    recover_changed_file_transaction,
    validate_unchanged_files,
)
from .run_limits import (
    MAX_COLLECTORS_PER_RUN,
    MAX_DUT_ID_BYTES,
    MAX_DUTS,
    MAX_TRACKED_COLLECTOR_RECORDS,
    is_printable_identity,
)
from .runtime_boundary_profile import (
    DEFAULT_RUNTIME_BOUNDARIES,
    resolve_runtime_boundaries,
)
from .strict_zstd import StrictZstdError, StrictZstdReader

try:
    import zstandard
except ImportError:  # pragma: no cover - exercised with an import-blocking test
    zstandard = None

_TEXT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".crt",
    ".csv",
    ".env",
    ".err",
    ".html",
    ".htm",
    ".ini",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".ndjson",
    ".out",
    ".pem",
    ".properties",
    ".py",
    ".sh",
    ".sql",
    ".toml",
    ".tsv",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
_BINARY_SUFFIXES = {
    ".7z",
    ".bin",
    ".bmp",
    ".der",
    ".elf",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".o",
    ".pdf",
    ".png",
    ".so",
    ".sqlite",
    ".sqlite3",
    ".wasm",
    ".webp",
    ".xlsx",
}
_ZIP_SUFFIXES = (".zip", ".jar")
_MAX_ZIP64_END_RECORD_BYTES = 1024 * 1024
_MAX_PORTABLE_ARCHIVE_PATH_BYTES = 4095
_SAFE_ZIP_EXTRA_FIELD_IDS = frozenset(
    {0x0001, 0x000A, 0x5455, 0x7075, 0x7875, 0xA220, 0xCAFE}
)
_TAR_SUFFIXES = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar.zst",
    ".tar.zstd",
    ".tzst",
)
_ZSTD_SUFFIXES = (".zst", ".zstd")
_ZSTD_FRAME_MAGIC = b"\x28\xb5\x2f\xfd"
_ZSTD_MAX_WINDOW_BYTES = 256 * 1024 * 1024
_ZSTD_MAX_FRAMES = 20_000
_PRINTABLE_ASCII_BYTES = bytes(range(0x20, 0x7F)) + b"\r\n\t"
_ARCHIVE_VALIDATION_RECORD_LIMIT = 4 * 1024 * 1024
_ARCHIVE_VALIDATION_ENTRY_LIMIT = 256
_ARCHIVE_VALIDATION_RECORD_COUNT_LIMIT = 10_000
_ARCHIVE_VALIDATION_ARTIFACT_SCAN_LIMIT = 20_000


@dataclass(frozen=True)
class _SanitizedArtifactRewrite:
    """
    Exact before/after identity for one sanitizer-owned loose-file rewrite.

    The immutable record keeps ``relative_path``, ``before_size``,
    ``before_sha256``, ``after_size``, and ``after_sha256`` together so
    consumers observe one sanitized artifact rewrite state. Consumers receive
    the fields as one unit instead of assembling partial state.

    Attributes:
        relative_path: Validated filesystem location associated with relative
            path.
        before_size: Numeric before size retained by this record.
        before_sha256: Lowercase SHA-256 digest binding the before content.
        after_size: Numeric after size retained by this record.
        after_sha256: Lowercase SHA-256 digest binding the after content.
    """

    relative_path: str
    before_size: int
    before_sha256: str
    after_size: int
    after_sha256: str


@dataclass(frozen=True)
class _StableFileIdentity:
    """
    Bounded content and inode identity captured through one open descriptor.

    The immutable record keeps ``size``, ``sha256``, ``device``, ``inode``, and
    ``links`` together so consumers observe one stable file identity state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        size: Cumulative byte count represented by this record.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        device: Numeric device retained by this record.
        inode: Numeric inode retained by this record.
        links: Number of links represented by this record.
        mode: Numeric mode retained by this record.
        mtime_ns: Number of mtime ns represented by this record.
        ctime_ns: Number of ctime ns represented by this record.
    """

    size: int
    sha256: str
    device: int
    inode: int
    links: int
    mode: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class _PinnedBundleEntry:
    """
    One lexically named object captured below the held bundle root.

    The immutable record keeps ``relative_path``, ``device``, ``inode``,
    ``links``, and ``mode`` together so consumers observe one pinned bundle
    entry state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        relative_path: Validated filesystem location associated with relative
            path.
        device: Numeric device retained by this record.
        inode: Numeric inode retained by this record.
        links: Number of links represented by this record.
        mode: Numeric mode retained by this record.
        size: Cumulative byte count represented by this record.
        mtime_ns: Number of mtime ns represented by this record.
        ctime_ns: Number of ctime ns represented by this record.
    """

    relative_path: str
    device: int
    inode: int
    links: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, relative_path: str, metadata: os.stat_result):
        """
        Build a _PinnedBundleEntry from stat.

        After applying local validation, the function forwards ``relative_path``
        and ``metadata`` to ``cls`` and preserves its return and exception
        contract.

        Args:
            relative_path: filesystem location used as the relative path for
                this operation.
            metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``,
                ``st_ino``, ``st_mode``, and ``st_mtime_ns`` state is read while
                performing _PinnedBundleEntry from stat.

        Returns:
            A pinned bundle entry populated from the path and filesystem
            identity fields.
        """
        return cls(
            relative_path=relative_path,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            links=metadata.st_nlink,
            mode=metadata.st_mode,
            size=metadata.st_size,
            mtime_ns=metadata.st_mtime_ns,
            ctime_ns=metadata.st_ctime_ns,
        )

    def matches(self, metadata: os.stat_result) -> bool:
        """
        Return whether metadata matches the configured pattern.

        The implementation uses ``metadata`` to determine whether metadata
        matches the configured pattern.

        Args:
            metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``,
                ``st_ino``, ``st_mode``, and ``st_mtime_ns`` state is read while
                performing metadata matches the configured pattern.

        Returns:
            Whether metadata matches the configured pattern.
        """
        return (
            self.device,
            self.inode,
            self.links,
            self.mode,
            self.size,
            self.mtime_ns,
            self.ctime_ns,
        ) == (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_nlink,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )


class _BundleEntryMissing(ValueError):
    """
    A lexical path was absent from the completed bounded namespace walk.

    Callers receive this exception when the bundle entry missing invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


@dataclass(frozen=True)
class _BoundArchiveReceipt:
    """
    One canonical Redfish archive receipt bound before bundle sanitization.

    The immutable record keeps ``record_index``, ``validation_id``,
    ``artifact_path``, ``artifact_relative_path``, and ``artifact_path_sha256``
    together so consumers observe one bound archive receipt state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        record_index: Numeric record index retained by this record.
        validation_id: Canonical text used as validation identifier.
        artifact_path: Validated filesystem location associated with artifact
            path.
        artifact_relative_path: Validated filesystem location associated with
            artifact relative path.
        artifact_path_sha256: Lowercase SHA-256 digest binding the artifact path
            content.
        status: Canonical status exposed to downstream status consumers.
        normalization: Normalization retained as part of the record's public
            state.
        original_size: Numeric original size retained by this record.
        original_sha256: Lowercase SHA-256 digest binding the original content.
        current_saved_size: Numeric current saved size retained by this record.
        current_saved_sha256: Lowercase SHA-256 digest binding the current saved
            content.
        producer_saved_size: Numeric producer saved size retained by this
            record.
        producer_saved_sha256: Lowercase SHA-256 digest binding the producer
            saved content.
        already_reconciled: Whether already reconciled applies to this record.
        initial_artifact_identity: Initial artifact identity retained as part of
            the record's public state.
    """

    record_index: int
    validation_id: str
    artifact_path: Path
    artifact_relative_path: str
    artifact_path_sha256: str
    status: str
    normalization: Any
    original_size: int
    original_sha256: str
    current_saved_size: int
    current_saved_sha256: str
    producer_saved_size: int
    producer_saved_sha256: str
    already_reconciled: bool
    initial_artifact_identity: _StableFileIdentity


@dataclass(frozen=True)
class _BoundValidationRecord:
    """
    Stable pre-sanitization bytes and canonical entries for one receipt file.

    The immutable record keeps ``path``, ``data``, ``identity``, ``receipts``,
    and ``has_invalid_receipts`` together so consumers observe one bound
    validation state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        data: Bounded byte sequence retained as data.
        identity: Identity retained as part of the record's public state.
        receipts: Collection of receipts entries retained by this record.
        has_invalid_receipts: Whether invalid receipts applies to this record.
    """

    path: Path
    data: bytes
    identity: _StableFileIdentity
    receipts: tuple[_BoundArchiveReceipt, ...]
    has_invalid_receipts: bool


@dataclass(frozen=True)
class _BoundReferenceRecord:
    """
    A diagnostic response whose archive reference must remain consistent.

    The immutable record keeps ``path``, ``data``, ``identity``, and
    ``references`` together so consumers observe one bound reference state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        path: Validated filesystem location associated with path.
        data: Bounded byte sequence retained as data.
        identity: Identity retained as part of the record's public state.
        references: Collection of references entries retained by this record.
    """

    path: Path
    data: bytes
    identity: _StableFileIdentity
    references: tuple["_BoundArchiveReference", ...]


@dataclass(frozen=True)
class _BoundArchiveReference:
    """
    Exact response-array slot and immutable fields for one reference.

    The immutable record keeps ``response_index``, ``validation_id``,
    ``status``, and ``normalization`` together so consumers observe one bound
    archive reference state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        response_index: Numeric response index retained by this record.
        validation_id: Canonical text used as validation identifier.
        status: Canonical status exposed to downstream status consumers.
        normalization: Normalization retained as part of the record's public
            state.
    """

    response_index: int
    validation_id: str
    status: str
    normalization: Any


@dataclass(frozen=True)
class _ArchiveValidationPlan:
    """
    All primary receipts and references captured before general sanitization.

    The immutable record keeps ``records``, ``references``,
    ``primary_summaries``, and ``bound_artifacts`` together so consumers observe
    one archive validation plan state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        records: Collection of records entries retained by this record.
        references: Collection of references entries retained by this record.
        primary_summaries: Mapping that retains the primary summaries fields for
            this record.
        bound_artifacts: Collection of bound artifacts entries retained by this
            record.
    """

    records: tuple[_BoundValidationRecord, ...]
    references: tuple[_BoundReferenceRecord, ...]
    primary_summaries: dict[str, tuple[str, Any]]
    bound_artifacts: frozenset[Path]


_STATUS_ARTIFACT_LIST_FIELDS = (
    "output_files",
    "diagnostic_files",
    "error_files",
    "all_files",
)
_COLLECTOR_STATUS_IDENTITY_FIELDS = (
    "dut_id",
    "collector_id",
    "collector_name",
    "collector_group",
    "collection_level",
)
_COLLECTION_STATUS_IDENTITY_FIELDS = (
    "dut_id",
    "collector_id",
    "collector_name",
    "group",
    "level",
)
_TIMING_STATUS_IDENTITY_FIELDS = (
    "collector_id",
    "collector_name",
    "group",
    "level",
)
_STATUS_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,255}")
_GENERATED_COMPONENT_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._ '\-]+")
_SNAPSHOT_GENERATION_RE = re.compile(r"[0-9a-f]{32}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_MAX_TRUSTED_STATUS_BYTES = 16 * 1024 * 1024
_StructuredPath = tuple[str | int, ...]
_StatusLeafDigest = tuple[str, int, str]


@dataclass
class BundleSanitizationReport:
    """
    Accounting for one bundle sanitization pass.

    The coherent record keeps ``scanned_files``, ``sanitized_files``,
    ``scanned_archives``, ``preserved_binary_files``, and
    ``reconciled_archive_validations`` together so consumers observe one bundle
    sanitization report state. Consumers receive the fields as one unit instead
    of assembling partial state.

    Attributes:
        scanned_files: Number of scanned files represented by this record.
        sanitized_files: Number of sanitized files represented by this record.
        scanned_archives: Number of scanned archives represented by this record.
        preserved_binary_files: Number of preserved binary files represented by
            this record.
        reconciled_archive_validations: Number of reconciled archive validations
            represented by this record.
        errors: Collection of errors entries retained by this record.
    """

    scanned_files: int = 0
    sanitized_files: int = 0
    scanned_archives: int = 0
    preserved_binary_files: int = 0
    reconciled_archive_validations: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def state(self) -> str:
        """
        Return the distributable-bundle outcome used by final metadata.

        Each access computes the value from ``errors`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            The canonical state text.
        """
        return "failed_safe" if self.errors else "complete"


@dataclass(frozen=True)
class BundleSanitizationLimits:
    """
    Resource ceilings for one complete bundle inspection.

    Defaults deliberately leave headroom above the largest grounded H14 NVOS
    archive (262 MiB compressed, 444 MiB of top-level members, 4,545 members,
    and a 59 MiB largest member) while making memory/CPU amplification finite.

    Attributes:
        max_top_level_bytes: Maximum top level bytes admitted by this record.
        max_archive_member_bytes: Maximum archive member bytes admitted by this
            record.
        max_archive_total_bytes: Maximum archive total bytes admitted by this
            record.
        max_archive_metadata_bytes: Maximum archive metadata bytes admitted by
            this record.
        max_archive_metadata_member_bytes: Maximum archive metadata member bytes
            admitted by this record.
        max_archive_pax_records: Maximum archive PAX records admitted by this
            record.
        max_archive_pax_records_per_header: Maximum archive PAX records per
            header admitted by this record.
        max_archive_global_pax_records: Maximum archive global PAX records
            admitted by this record.
        max_archive_extension_headers: Maximum archive extension headers
            admitted by this record.
        max_archive_extension_chain_depth: Maximum archive extension chain depth
            admitted by this record.
        max_archive_path_nodes: Maximum archive path nodes admitted by this
            record.
        max_archive_tracked_path_bytes: Maximum archive tracked path bytes
            admitted by this record.
        max_archive_path_depth: Maximum archive path depth admitted by this
            record.
        max_decompressed_stream_bytes: Maximum decompressed stream bytes
            admitted by this record.
        max_archive_members: Maximum archive members admitted by this record.
        max_cumulative_expanded_bytes: Maximum cumulative expanded bytes
            admitted by this record.
        max_cumulative_archive_members: Maximum cumulative archive members
            admitted by this record.
        max_resident_bytes: Maximum resident bytes admitted by this record.
        max_decompressor_memory_bytes: Maximum decompressor memory bytes
            admitted by this record.
        max_compression_ratio: Maximum compression ratio admitted by this
            record.
        max_seconds: Maximum seconds admitted by this record.
        max_yaml_nodes: Maximum YAML nodes admitted by this record.
        max_yaml_aliases: Maximum YAML aliases admitted by this record.
        max_yaml_depth: Maximum YAML depth admitted by this record.
        max_bundle_entries: Maximum bundle entries admitted by this record.
        max_bundle_path_bytes: Maximum bundle path bytes admitted by this
            record.
        max_bundle_path_length: Maximum bundle path length admitted by this
            record.
        max_bundle_path_depth: Maximum bundle path depth admitted by this
            record.
        max_bundle_total_bytes: Maximum bundle total bytes admitted by this
            record.
        max_bundle_rewrite_bytes: Maximum bundle rewrite bytes admitted by this
            record.
        max_bundle_rewrite_files: Maximum bundle rewrite files admitted by this
            record.
        max_archive_validation_total_bytes: Maximum archive validation total
            bytes admitted by this record.
        max_archive_validation_total_entries: Maximum archive validation total
            entries admitted by this record.
    """

    max_top_level_bytes: int = 512 * 1024 * 1024
    max_archive_member_bytes: int = 256 * 1024 * 1024
    max_archive_total_bytes: int = 768 * 1024 * 1024
    max_archive_metadata_bytes: int = 64 * 1024 * 1024
    max_archive_metadata_member_bytes: int = 8 * 1024 * 1024
    max_archive_pax_records: int = 20_000
    max_archive_pax_records_per_header: int = 4_096
    max_archive_global_pax_records: int = 256
    max_archive_extension_headers: int = 40_000
    max_archive_extension_chain_depth: int = 64
    max_archive_path_nodes: int = 250_000
    max_archive_tracked_path_bytes: int = 128 * 1024 * 1024
    max_archive_path_depth: int = 64
    max_decompressed_stream_bytes: int = 512 * 1024 * 1024
    max_archive_members: int = 20_000
    # The grounded H14 archive contains 424 individually compressed streams
    # whose expanded sizes total 4.2 GiB, though no single stream exceeds
    # 133 MiB. This is a work budget, not a simultaneous-memory allocation.
    max_cumulative_expanded_bytes: int = 8 * 1024 * 1024 * 1024
    max_cumulative_archive_members: int = 100_000
    max_resident_bytes: int = 2 * 1024 * 1024 * 1024
    max_decompressor_memory_bytes: int = 256 * 1024 * 1024
    max_compression_ratio: float = 1_000.0
    max_seconds: float = 900.0
    max_yaml_nodes: int = 100_000
    max_yaml_aliases: int = 10_000
    max_yaml_depth: int = 128
    max_bundle_entries: int = 100_000
    max_bundle_path_bytes: int = 64 * 1024 * 1024
    max_bundle_path_length: int = 4_096
    max_bundle_path_depth: int = 128
    max_bundle_total_bytes: int = 16 * 1024 * 1024 * 1024
    max_bundle_rewrite_bytes: int = 4 * 1024 * 1024 * 1024
    max_bundle_rewrite_files: int = 20_000
    max_archive_validation_total_bytes: int = 64 * 1024 * 1024
    max_archive_validation_total_entries: int = 20_000


STANDARD_BUNDLE_SANITIZATION_LIMITS = BundleSanitizationLimits()
_LIVE_BUNDLE_BOUNDARY_KEYS = {
    "max_archive_total_bytes": "finalization_sanitizer_max_archive_total_bytes",
    "max_archive_metadata_bytes": ("finalization_sanitizer_max_archive_metadata_bytes"),
    "max_archive_metadata_member_bytes": (
        "finalization_sanitizer_max_archive_metadata_member_bytes"
    ),
    "max_archive_pax_records": "finalization_sanitizer_max_archive_pax_records",
    "max_archive_extension_headers": (
        "finalization_sanitizer_max_archive_extension_headers"
    ),
    "max_archive_path_nodes": "finalization_sanitizer_max_archive_path_nodes",
    "max_archive_tracked_path_bytes": (
        "finalization_sanitizer_max_archive_tracked_path_bytes"
    ),
    "max_archive_members": "finalization_sanitizer_max_archive_members",
    "max_cumulative_expanded_bytes": (
        "finalization_sanitizer_max_cumulative_expanded_bytes"
    ),
    "max_cumulative_archive_members": (
        "finalization_sanitizer_max_cumulative_archive_members"
    ),
    "max_seconds": "finalization_sanitizer_max_seconds",
    "max_bundle_entries": "finalization_sanitizer_max_bundle_entries",
    "max_bundle_path_bytes": "finalization_sanitizer_max_bundle_path_bytes",
    "max_bundle_total_bytes": "finalization_sanitizer_max_bundle_total_bytes",
    "max_bundle_rewrite_bytes": "finalization_sanitizer_max_bundle_rewrite_bytes",
    "max_bundle_rewrite_files": "finalization_sanitizer_max_bundle_rewrite_files",
}


def _live_bundle_limits_from_resolved_boundaries(
    boundaries: Mapping[str, int],
) -> BundleSanitizationLimits:
    """
    Project resolved catalog values into live bundle sanitization limits.

    Per-payload, parser, and resident-memory controls remain at the stricter
    code-owned defaults; only catalog-governed aggregate work limits change.

    Args:
        boundaries: Complete validated runtime boundary mapping.

    Returns:
        The projected finite live bundle sanitization limits.
    """
    values = {
        field_name: boundaries[boundary_name]
        for field_name, boundary_name in _LIVE_BUNDLE_BOUNDARY_KEYS.items()
    }
    return replace(STANDARD_BUNDLE_SANITIZATION_LIMITS, **values)


HARD_LIVE_BUNDLE_SANITIZATION_LIMITS = _live_bundle_limits_from_resolved_boundaries(
    DEFAULT_RUNTIME_BOUNDARIES
)


def resolve_live_bundle_sanitization_limits(
    boundaries: Mapping[str, Any] | None = None,
) -> BundleSanitizationLimits:
    """
    Resolve finite work limits for a completed live collection bundle.

    Generic/offline sanitization retains :class:`BundleSanitizationLimits` as
    its deliberately smaller default. Live collection trees use the catalog
    values resolved across the participating baseboards. Only
    cumulative disk/work ceilings grow here; per-payload and resident-memory
    limits remain bounded to preserve fail-closed secret inspection.

    Args:
        boundaries: Optional partial or complete runtime boundary mapping.

    Returns:
        The finite sanitization limits selected for a live collection tree.
    """

    resolved = resolve_runtime_boundaries(
        None,
        boundaries if isinstance(boundaries, Mapping) else {},
    )
    return _live_bundle_limits_from_resolved_boundaries(resolved)


@dataclass(frozen=True)
class _StructuredDocumentContext:
    """
    Filesystem provenance for one top-level structured bundle artifact.

    The immutable record keeps ``bundle``, ``artifact_path``, ``artifact_size``,
    ``artifact_sha256``, and ``validated_status_leaf_digests`` together so
    consumers observe one structured document context state. Consumers receive
    the fields as one unit instead of assembling partial state.

    Attributes:
        bundle: Bundle retained as part of the record's public state.
        artifact_path: Validated filesystem location associated with artifact
            path.
        artifact_size: Numeric artifact size retained by this record.
        artifact_sha256: Lowercase SHA-256 digest binding the artifact content.
        validated_status_leaf_digests: Collection of validated status leaf
            digests entries retained by this record.
    """

    bundle: "_PinnedBundle"
    artifact_path: Path
    artifact_size: int
    artifact_sha256: str
    validated_status_leaf_digests: frozenset[_StatusLeafDigest] = frozenset()


@dataclass(frozen=True)
class _StructuredDocumentTrust:
    """
    Exact schema locations owned by one generated status document.

    The immutable record keeps ``value_paths`` and ``mapping_key_paths``
    together so consumers observe one structured document trust state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        value_paths: Collection of value paths entries retained by this record.
        mapping_key_paths: Collection of mapping key paths entries retained by
            this record.
    """

    value_paths: frozenset[_StructuredPath] = frozenset()
    mapping_key_paths: frozenset[_StructuredPath] = frozenset()


def _normalize_validated_status_leaf_digests(
    value: Any,
) -> frozenset[_StatusLeafDigest]:
    """
    Accept only bounded exact path/size/SHA-256 snapshot evidence.

    The implementation uses ``value`` to accept only bounded exact
    path/size/SHA-256 snapshot evidence.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.

    Returns:
        Accepted immutable digest records, or an empty set when the evidence is
        malformed.
    """

    if type(value) is not tuple or len(value) > (4 * MAX_DUTS) + 3:
        return frozenset()
    normalized: list[_StatusLeafDigest] = []
    paths: set[str] = set()
    for item in value:
        if (
            type(item) is not tuple
            or len(item) != 3
            or type(item[0]) is not str
            or not item[0]
            or len(item[0].encode("utf-8", errors="ignore")) > 4096
            or type(item[1]) is not int
            or item[1] < 0
            or type(item[2]) is not str
            or _SHA256_RE.fullmatch(item[2]) is None
            or item[0] in paths
        ):
            return frozenset()
        paths.add(item[0])
        normalized.append((item[0], item[1], item[2]))
    return frozenset(normalized)


def _status_leaf_bytes_match_receipt(
    context: _StructuredDocumentContext,
    relative: str,
    data: bytes,
) -> bool:
    """
    Return whether exact bytes match validated receipt leaf evidence.

    The implementation uses ``context``, ``relative``, and ``data`` to determine
    whether exact bytes match validated receipt leaf evidence.

    Args:
        context: Runtime context carrying state shared across this operation.
        relative: Text supplied as relative in the format accepted by this
            function.
        data: Bounded byte sequence supplied as data.

    Returns:
        Whether exact bytes match validated receipt leaf evidence.
    """

    return (
        relative,
        len(data),
        hashlib.sha256(data).hexdigest(),
    ) in context.validated_status_leaf_digests


def _current_status_leaf_matches_receipt(
    context: _StructuredDocumentContext,
    relative: str,
) -> bool:
    """
    Return whether the structured bytes being scanned are receipt-bound.

    The implementation uses ``context`` and ``relative`` to determine whether
    the structured bytes being scanned are receipt-bound.

    Args:
        context: Runtime context carrying state shared across this operation.
        relative: Text supplied as relative in the format accepted by this
            function.

    Returns:
        Whether the structured bytes being scanned are receipt-bound.
    """

    return (
        relative,
        context.artifact_size,
        context.artifact_sha256,
    ) in context.validated_status_leaf_digests


@dataclass
class _InspectionBudget:
    """
    Implement the inspection budget boundary used by the NVDebug runtime.

    The coherent record keeps ``expanded_bytes``, ``archive_members``,
    ``resident_bytes``, and ``deadline`` together so consumers observe one
    inspection budget state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        expanded_bytes: Byte count recorded for expanded.
        archive_members: Number of archive members represented by this record.
        resident_bytes: Byte count recorded for resident.
        deadline: Numeric deadline retained by this record.
    """

    expanded_bytes: int = 0
    archive_members: int = 0
    resident_bytes: int = 0
    deadline: float = float("inf")

    def check_deadline(self) -> None:
        """
        Check deadline.

        The implementation uses current instance state to check deadline. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Raises:
            ValueError: If bundle sanitization deadline exceeded.
        """
        if time.monotonic() > self.deadline:
            raise ValueError("bundle sanitization deadline exceeded")

    def hold_bytes(
        self,
        amount: int,
        *,
        label: str,
        limits: BundleSanitizationLimits,
    ) -> None:
        """
        Retain bytes.

        The implementation uses ``amount``, ``label``, and ``limits`` to retain
        bytes. It updates ``resident_bytes`` on the instance as part of that
        state transition. If the function cannot retain bytes, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            amount: Numeric amount used while the operation performs bounded
                accounting.
            label: Text supplied as label in the format accepted by this
                function.
            limits: Limits governing retain bytes.

        Raises:
            ValueError: If resident byte charge cannot be negative; or
                simultaneously resident inspection payload exceeds
                ``max_resident_bytes`` bytes while inspecting ``label``.
        """
        self.check_deadline()
        if amount < 0:
            raise ValueError("resident byte charge cannot be negative")
        projected = self.resident_bytes + amount
        if projected > limits.max_resident_bytes:
            raise ValueError(
                "simultaneously resident inspection payload exceeds "
                f"{limits.max_resident_bytes} bytes while inspecting {label}"
            )
        self.resident_bytes = projected

    def release_bytes(self, amount: int) -> None:
        """
        Release bytes.

        The implementation uses ``amount`` to release bytes. It updates
        ``resident_bytes`` on the instance as part of that state transition.

        Args:
            amount: Numeric amount used while the operation performs bounded
                accounting.
        """
        self.resident_bytes = max(0, self.resident_bytes - amount)

    @contextmanager
    def hold(
        self,
        amount: int,
        *,
        label: str,
        limits: BundleSanitizationLimits,
    ):
        """
        Retain hold.

        The implementation uses ``amount``, ``label``, and ``limits`` to retain
        hold. Cleanup in the ``finally`` path runs for successful, failed, and
        cancelled execution.

        Args:
            amount: Numeric amount used while the operation performs bounded
                accounting.
            label: Text supplied as label in the format accepted by this
                function.
            limits: Limits governing retain hold.

        Yields:
            Each hold admitted by the operation, in deterministic iteration
            order.
        """
        self.hold_bytes(amount, label=label, limits=limits)
        try:
            yield
        finally:
            self.release_bytes(amount)

    def charge_bytes(
        self, amount: int, *, label: str, limits: BundleSanitizationLimits
    ) -> None:
        """
        Charge bytes.

        The implementation uses ``amount``, ``label``, and ``limits`` to charge
        bytes. It updates ``expanded_bytes`` on the instance as part of that
        state transition. If the function cannot charge bytes, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            amount: Numeric amount used while the operation performs bounded
                accounting.
            label: Text supplied as label in the format accepted by this
                function.
            limits: Limits governing charge bytes.

        Raises:
            ValueError: If cumulative expanded payload exceeds
                ``max_cumulative_expanded_bytes`` bytes while inspecting
                ``label``.
        """
        self.check_deadline()
        self.expanded_bytes += amount
        if self.expanded_bytes > limits.max_cumulative_expanded_bytes:
            raise ValueError(
                "cumulative expanded payload exceeds "
                f"{limits.max_cumulative_expanded_bytes} bytes while inspecting {label}"
            )

    def charge_members(
        self, amount: int, *, label: str, limits: BundleSanitizationLimits
    ) -> None:
        """
        Charge members.

        The implementation uses ``amount``, ``label``, and ``limits`` to charge
        members. It updates ``archive_members`` on the instance as part of that
        state transition. If the function cannot charge members, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            amount: Numeric amount used while the operation performs bounded
                accounting.
            label: Text supplied as label in the format accepted by this
                function.
            limits: Limits governing charge members.

        Raises:
            ValueError: If cumulative archive member count exceeds
                ``max_cumulative_archive_members`` while inspecting ``label``.
        """
        self.check_deadline()
        self.archive_members += amount
        if self.archive_members > limits.max_cumulative_archive_members:
            raise ValueError(
                "cumulative archive member count exceeds "
                f"{limits.max_cumulative_archive_members} while inspecting {label}"
            )


def _generated_path_component(value: Any, fallback: str) -> str:
    """
    Mirror the logger's canonical single-component projection.

    The implementation uses ``value`` and ``fallback`` to mirror the logger's
    canonical single-component projection. Filesystem effects remain confined to
    the caller-selected paths and the owning resource lifecycle.

    Args:
        value: Value evaluated while performing mirror the logger's canonical
            single-component projection.
        fallback: Text supplied as fallback in the format accepted by this
            function.

    Returns:
        Whether the mirror the logger's canonical single-component projection
        operation succeeds.
    """

    text = str(value or "").strip()
    text = text.replace("/", "_").replace("\\", "_")
    text = _GENERATED_COMPONENT_UNSAFE_RE.sub("_", text).strip(" .")
    while ".." in text:
        text = text.replace("..", "_")
    return text or fallback


def _is_canonical_generated_component(value: Any, fallback: str) -> bool:
    """
    Return whether a source identity maps losslessly to one path component.

    The implementation uses ``value`` and ``fallback`` to determine whether a
    source identity maps losslessly to one path component.

    Args:
        value: Value evaluated while performing source identity maps losslessly
            to one path component.
        fallback: Text supplied as fallback in the format accepted by this
            function.

    Returns:
        Whether a source identity maps losslessly to one path component.
    """

    return isinstance(value, str) and value == _generated_path_component(
        value, fallback
    )


_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_REGULAR_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


class _PinnedBundle:
    """
    Bounded bundle namespace rooted at one held, no-follow directory fd.

    The type coordinates ``open``, ``close``, ``binding_matches``, ``entries``,
    and ``directory_snapshots`` and retains the state those operations share
    between calls. Resource ownership remains inside the instance until the
    matching close, exit, or cleanup operation completes.
    """

    def __init__(self, root_path: Path, root_fd: int) -> None:
        """
        Initialize a ``_PinnedBundle`` instance.

        The initializer records ``_entries``, ``_entry_map``, ``_root_entry``,
        ``_root_identity``, and ``root_fd`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            root_path: filesystem location used as the root path for this
                operation.
            root_fd: Numeric root fd used while the operation performs bounded
                accounting.
        """
        self.root_path = root_path
        self.root_fd = root_fd
        root_stat = os.fstat(root_fd)
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        self._root_entry: _PinnedBundleEntry | None = None
        self._entries: tuple[_PinnedBundleEntry, ...] | None = None
        self._entry_map: dict[str, _PinnedBundleEntry] = {}

    @classmethod
    def open(cls, root: Path) -> "_PinnedBundle":
        """
        Open the configured resource.

        After applying local validation, the function forwards ``root`` to
        ``cls`` and preserves its return and exception contract.

        Args:
            root: filesystem location used as the root for this operation.

        Returns:
            A ``_PinnedBundle`` representing open.
        """
        root_path = Path(os.path.abspath(os.fspath(root)))
        descriptor = os.open(os.sep, _DIRECTORY_OPEN_FLAGS)
        try:
            for part in root_path.parts[1:]:
                child = os.open(part, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return cls(root_path, descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def close(self) -> None:
        """
        Close the _PinnedBundle.

        The implementation uses current instance state to close the
        _PinnedBundle. It updates ``root_fd`` on the instance as part of that
        state transition.
        """
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1

    def binding_matches(self) -> bool:
        """
        Return the binding matches.

        The implementation uses current instance state to produce the binding
        matches. Filesystem effects remain confined to the caller-selected paths
        and the owning resource lifecycle. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Returns:
            Whether the binding matches operation succeeds.
        """
        try:
            current = self.open(self.root_path)
        except OSError:
            return False
        try:
            metadata = os.fstat(current.root_fd)
            return (metadata.st_dev, metadata.st_ino) == self._root_identity
        finally:
            current.close()

    @property
    def entries(self) -> tuple[_PinnedBundleEntry, ...]:
        """
        Return the entries.

        Each access computes the value from ``_entries`` on the current
        instance; the derived view is not stored as independent state. If the
        function cannot produce the entries, its exception reaches the caller
        instead of being converted into a successful result.

        Returns:
            The entries returned in operation-defined order.

        Raises:
            RuntimeError: If bundle namespace has not been enumerated.
        """
        if self._entries is None:
            raise RuntimeError("bundle namespace has not been enumerated")
        return self._entries

    def directory_snapshots(self) -> dict[str, SnapshotDirectory]:
        """
        Return the directory snapshots.

        The implementation uses current instance state to produce the directory
        snapshots. If the function cannot produce the directory snapshots, its
        exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            A mapping containing directory snapshots.

        Raises:
            RuntimeError: If bundle namespace has not been enumerated.
            ValueError: If bundle entry parent was not enumerated.
        """
        if self._entries is None or self._root_entry is None:
            raise RuntimeError("bundle namespace has not been enumerated")
        directories = {
            entry.relative_path: entry
            for entry in self._entries
            if stat.S_ISDIR(entry.mode)
        }
        directories["."] = self._root_entry
        children: dict[str, list[str]] = {relative: [] for relative in directories}
        for entry in self._entries:
            pure = PurePosixPath(entry.relative_path)
            parent = pure.parent.as_posix()
            if parent not in children:
                raise ValueError("bundle entry parent was not enumerated")
            children[parent].append(pure.name)
        return {
            relative: SnapshotDirectory(
                device=entry.device,
                inode=entry.inode,
                links=entry.links,
                mode=entry.mode,
                size=entry.size,
                mtime_ns=entry.mtime_ns,
                ctime_ns=entry.ctime_ns,
                children=tuple(sorted(children[relative])),
            )
            for relative, entry in directories.items()
        }

    def walk(self, limits: BundleSanitizationLimits) -> tuple[_PinnedBundleEntry, ...]:
        """
        Enumerate every entry once with strict count/path/depth ceilings.

        The implementation uses ``limits`` to enumerate every entry once with
        strict count/path/depth ceilings. It updates ``_entries``,
        ``_entry_map``, and ``_root_entry`` on the instance as part of that
        state transition. If the function cannot enumerate every entry once with
        strict count/path/depth ceilings, its exception reaches the caller
        instead of being converted into a successful result. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            limits: Limits governing enumerate every entry once with strict
                count/path/depth ceilings.

        Returns:
            The walk returned in operation-defined order.

        Raises:
            ValueError: If bundle root changed during enumeration; or bundle
                contains duplicate lexical paths.
        """

        entries: list[_PinnedBundleEntry] = []
        discovered_entries = 0
        total_path_bytes = 0
        root_before = os.fstat(self.root_fd)

        def visit(parent_parts: tuple[str, ...], parent_fd: int) -> None:
            """
            Visit the current syntax or data node.

            The implementation uses ``parent_parts`` and ``parent_fd`` to visit
            the current syntax or data node. Filesystem effects remain confined
            to the caller-selected paths and the owning resource lifecycle. If
            the function cannot visit the current syntax or data node, its
            exception reaches the caller instead of being converted into a
            successful result. Cleanup in the ``finally`` path runs for
            successful, failed, and cancelled execution.

            Args:
                parent_parts: Entries supplied as ``parent_parts`` without
                    transferring container ownership.
                parent_fd: Numeric parent fd used while the operation performs
                    bounded accounting.

            Raises:
                ValueError: If bundle entry count exceeds limit; bundle
                    directory changed during enumeration; bundle path depth
                    exceeds limit; or bundle path length exceeds limit; or
                    another input invariant is violated.
            """
            nonlocal discovered_entries, total_path_bytes
            before = os.fstat(parent_fd)
            names: list[str] = []
            with os.scandir(parent_fd) as iterator:
                for dir_entry in iterator:
                    discovered_entries += 1
                    if discovered_entries > limits.max_bundle_entries:
                        raise ValueError("bundle entry count exceeds limit")
                    names.append(dir_entry.name)
            after = os.fstat(parent_fd)
            if not _same_open_file(before, after):
                raise ValueError("bundle directory changed during enumeration")

            for name in sorted(names):
                parts = (*parent_parts, name)
                if len(parts) > limits.max_bundle_path_depth:
                    raise ValueError("bundle path depth exceeds limit")
                relative = "/".join(parts)
                path_size = len(relative.encode("utf-8", errors="surrogateescape"))
                if path_size > limits.max_bundle_path_length:
                    raise ValueError("bundle path length exceeds limit")
                total_path_bytes += path_size
                if total_path_bytes > limits.max_bundle_path_bytes:
                    raise ValueError("bundle path bytes exceed aggregate limit")

                metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                entry = _PinnedBundleEntry.from_stat(relative, metadata)
                entries.append(entry)
                if stat.S_ISDIR(metadata.st_mode):
                    child_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
                    try:
                        if not entry.matches(os.fstat(child_fd)):
                            raise ValueError(
                                "bundle directory changed during enumeration"
                            )
                        visit(parts, child_fd)
                    finally:
                        os.close(child_fd)

        visit((), self.root_fd)
        if not _same_open_file(root_before, os.fstat(self.root_fd)):
            raise ValueError("bundle root changed during enumeration")

        self._root_entry = _PinnedBundleEntry.from_stat(".", root_before)
        self._entries = tuple(sorted(entries, key=lambda item: item.relative_path))
        self._entry_map = {item.relative_path: item for item in self._entries}
        if len(self._entry_map) != len(self._entries):
            raise ValueError("bundle contains duplicate lexical paths")
        if not self.binding_matches():
            raise ValueError("bundle root changed during enumeration")
        return self._entries

    def path(self, relative_path: str) -> Path:
        """
        Return the path.

        After applying local validation, the function forwards ``relative_path``
        to ``self.root_path.joinpath`` and preserves its return and exception
        contract.

        Args:
            relative_path: filesystem location used as the relative path for
                this operation.

        Returns:
            The validated path filesystem path.
        """
        parts = _validated_relative_parts(relative_path)
        return self.root_path.joinpath(*parts)

    def relative(self, path: Path) -> str:
        """
        Return the relative.

        The implementation uses ``path`` to produce the relative. If the
        function cannot produce the relative, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The validated ``relative``.

        Raises:
            ValueError: If bundle path escapes its pinned root.
        """
        try:
            relative = Path(path).relative_to(self.root_path).as_posix()
        except ValueError as error:
            raise ValueError("bundle path escapes its pinned root") from error
        _validated_relative_parts(relative)
        return relative

    def entry(self, relative_path: str) -> _PinnedBundleEntry:
        """
        Return the entry.

        The implementation uses ``relative_path`` to produce the entry. If the
        function cannot produce the entry, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            relative_path: filesystem location used as the relative path for
                this operation.

        Returns:
            A ``_PinnedBundleEntry`` representing entry.

        Raises:
            _BundleEntryMissing: If bundle entry was not present in the bounded
                walk.
        """
        try:
            return self._entry_map[relative_path]
        except KeyError as error:
            raise _BundleEntryMissing(
                "bundle entry was not present in the bounded walk"
            ) from error

    def open_regular(self, relative_path: str) -> tuple[int, _PinnedBundleEntry]:
        """
        Open regular.

        The implementation uses ``relative_path`` to open regular. If the
        function cannot open regular, its exception reaches the caller instead
        of being converted into a successful result.

        Args:
            relative_path: filesystem location used as the relative path for
                this operation.

        Returns:
            A tuple containing ``descriptor`` and ``entry`` in that order.

        Raises:
            ValueError: If bundle entry changed after enumeration; or bundle
                artifact is not a regular file.
        """
        parts = _validated_relative_parts(relative_path)
        descriptor = os.dup(self.root_fd)
        try:
            for index, part in enumerate(parts):
                expected = self.entry("/".join(parts[: index + 1]))
                final = index == len(parts) - 1
                child = os.open(
                    part,
                    _REGULAR_OPEN_FLAGS if final else _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
                metadata = os.fstat(child)
                if not expected.matches(metadata):
                    os.close(child)
                    raise ValueError("bundle entry changed after enumeration")
                os.close(descriptor)
                descriptor = child
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("bundle artifact is not a regular file")
            return descriptor, self.entry(relative_path)
        except BaseException:
            os.close(descriptor)
            raise


def _validated_relative_parts(relative_path: str) -> tuple[str, ...]:
    """
    Return the validated relative parts.

    The implementation uses ``relative_path`` to produce the validated relative
    parts. If the function cannot produce the validated relative parts, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        relative_path: filesystem location used as the relative path for this
            operation.

    Returns:
        The validated ``parts``.

    Raises:
        ValueError: If bundle relative path is unsafe.
    """
    if not relative_path or "\\" in relative_path:
        raise ValueError("bundle relative path is unsafe")
    parts = tuple(relative_path.split("/"))
    if any(part in {"", ".", ".."} or "/" in part for part in parts):
        raise ValueError("bundle relative path is unsafe")
    return parts


def _read_bounded(
    stream: Any,
    limit: int,
    *,
    label: str,
    budget: _InspectionBudget | None = None,
    limits: BundleSanitizationLimits | None = None,
) -> bytes:
    """
    Read through EOF without ever accepting more than ``limit`` bytes.

    The read buffer and retained chunk coexist until this iteration exits, so
    charge both before retaining it.

    Args:
        stream: Stream object whose ``read`` state is read while performing
            through EOF without ever accepting more than ``limit`` bytes.
        limit: Numeric limit used while the operation performs bounded
            accounting.
        label: Text supplied as label in the format accepted by this function.
        budget: Optional budget; ``None`` selects the function's default
            behavior.
        limits: Optional Limits governing through EOF without ever accepting
            more than ``limit`` bytes.

    Returns:
        The bounded bytes.

    Raises:
        ValueError: If ``label`` exceeds ``limit`` bytes.
    """
    chunks: list[bytes] = []
    total = 0
    held = 0
    try:
        while True:
            requested = min(1024 * 1024, limit - total + 1)
            if budget is None or limits is None:
                chunk = stream.read(requested)
            else:
                with budget.hold(
                    requested, label=f"read buffer for {label}", limits=limits
                ):
                    chunk = stream.read(requested)
                    if chunk:
                        # The read buffer and retained chunk coexist until this
                        # iteration exits, so charge both before retaining it.
                        budget.hold_bytes(len(chunk), label=label, limits=limits)
                        held += len(chunk)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"{label} exceeds {limit} bytes")
            chunks.append(chunk)
        if budget is None or limits is None:
            return b"".join(chunks)
        with budget.hold(total, label=f"materialized {label}", limits=limits):
            return b"".join(chunks)
    finally:
        if budget is not None and held:
            budget.release_bytes(held)


def _stable_identity(
    metadata: os.stat_result,
    *,
    size: int,
    sha256: str,
) -> _StableFileIdentity:
    """
    Return the stable identity.

    After applying local validation, the function forwards ``metadata``,
    ``size``, and ``sha256`` to ``_StableFileIdentity`` and preserves its return
    and exception contract.

    Args:
        metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing
            stable identity.
        size: Numeric size used by the operation's bounded accounting.
        sha256: Text supplied as SHA-256 in the format accepted by this
            function.

    Returns:
        A ``_StableFileIdentity`` representing stable identity.
    """
    return _StableFileIdentity(
        size=size,
        sha256=sha256,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        links=metadata.st_nlink,
        mode=metadata.st_mode,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )


def _same_open_file(before: os.stat_result, after: os.stat_result) -> bool:
    """
    Return the same open file.

    The implementation uses ``before`` and ``after`` to produce the same open
    file.

    Args:
        before: Before object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing same
            open file.
        after: After object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing same
            open file.

    Returns:
        Whether the same open file operation succeeds.
    """
    return (
        before.st_dev,
        before.st_ino,
        before.st_nlink,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_nlink,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _read_regular_file_stable_bounded(
    bundle: _PinnedBundle,
    path: Path,
    limit: int,
) -> tuple[bytes, _StableFileIdentity]:
    """
    Read regular file stable bounded.

    The implementation uses ``bundle``, ``path``, and ``limit`` to read regular
    file stable bounded. Parsing or I/O must finish before the validated
    representation is made available to the caller. If the function cannot read
    regular file stable bounded, its exception reaches the caller instead of
    being converted into a successful result. Cleanup in the ``finally`` path
    runs for successful, failed, and cancelled execution.

    Args:
        bundle: Bundle object whose ``open_regular`` and ``relative`` state is
            read while performing regular file stable bounded.
        path: filesystem location used as the path for this operation.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        A tuple containing ``data`` and ``stable identity`` in that order.

    Raises:
        ValueError: If top-level artifact exceeds ``limit`` bytes: ``size``;
            top-level artifact exceeds ``limit`` bytes; or artifact changed
            while it was read.
    """
    fd, entry = bundle.open_regular(bundle.relative(path))
    try:
        before = os.fstat(fd)
        if entry.size > limit:
            raise ValueError(f"top-level artifact exceeds {limit} bytes: {entry.size}")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, min(1024 * 1024, limit - total + 1)):
            total += len(chunk)
            if total > limit:
                raise ValueError(f"top-level artifact exceeds {limit} bytes")
            chunks.append(chunk)
        after = os.fstat(fd)
        if not _same_open_file(before, after) or total != before.st_size:
            raise ValueError("artifact changed while it was read")
        data = b"".join(chunks)
        digest = hashlib.sha256(data).hexdigest()
        return data, _stable_identity(after, size=len(data), sha256=digest)
    finally:
        os.close(fd)


def _capture_regular_file_identity_bounded(
    bundle: _PinnedBundle,
    path: Path,
    limit: int,
) -> _StableFileIdentity:
    """
    Hash one regular file below the pinned bundle namespace.

    After applying local validation, the function forwards ``bundle``, ``path``,
    and ``limit`` to ``_stable_identity`` and preserves its return and exception
    contract. Filesystem effects remain confined to the caller-selected paths
    and the owning resource lifecycle. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        bundle: Bundle object whose ``open_regular`` and ``relative`` state is
            read while performing hash one regular file below the pinned bundle
            namespace.
        path: filesystem location used as the path for this operation.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        A ``_StableFileIdentity`` representing capture regular file identity
        bounded.

    Raises:
        ValueError: If top-level artifact exceeds ``limit`` bytes: ``size``;
            top-level artifact exceeds ``limit`` bytes; or artifact changed
            while its identity was captured.
    """

    fd, entry = bundle.open_regular(bundle.relative(path))
    try:
        before = os.fstat(fd)
        if entry.size > limit:
            raise ValueError(f"top-level artifact exceeds {limit} bytes: {entry.size}")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"top-level artifact exceeds {limit} bytes")
            digest.update(chunk)
        after = os.fstat(fd)
        if not _same_open_file(before, after) or total != before.st_size:
            raise ValueError("artifact changed while its identity was captured")
        return _stable_identity(after, size=total, sha256=digest.hexdigest())
    finally:
        os.close(fd)


def _capture_regular_file_identity_with_appended_digest(
    bundle: _PinnedBundle,
    path: Path,
    limit: int,
    suffix: bytes,
) -> tuple[_StableFileIdentity, str]:
    """
    Capture a stable file identity and hash its exact bytes plus ``suffix``.

    The implementation uses ``bundle``, ``path``, ``limit``, and ``suffix`` to
    capture a stable file identity and hash its exact bytes plus ``suffix``.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot capture a stable file
    identity and hash its exact bytes plus ``suffix``, its exception reaches the
    caller instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        bundle: Bundle object whose ``open_regular`` and ``relative`` state is
            read while performing capture a stable file identity and hash its
            exact bytes plus ``suffix``.
        path: filesystem location used as the path for this operation.
        limit: Numeric limit used while the operation performs bounded
            accounting.
        suffix: Bounded byte sequence supplied as suffix.

    Returns:
        A tuple containing ``stable identity`` and ``hexdigest`` in that order.

    Raises:
        ValueError: If archive artifact is not a bounded regular file; top-level
            artifact exceeds ``limit`` bytes; or artifact changed while its
            identity was captured.
    """

    fd, entry = bundle.open_regular(bundle.relative(path))
    try:
        before = os.fstat(fd)
        if entry.size > limit:
            raise ValueError("archive artifact is not a bounded regular file")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"top-level artifact exceeds {limit} bytes")
            digest.update(chunk)
        after = os.fstat(fd)
        if not _same_open_file(before, after) or total != before.st_size:
            raise ValueError("artifact changed while its identity was captured")
        saved_digest = digest.copy().hexdigest()
        digest.update(suffix)
        return (
            _stable_identity(after, size=total, sha256=saved_digest),
            digest.hexdigest(),
        )
    finally:
        os.close(fd)


def _append_bounded(
    chunks: list[bytes],
    chunk: bytes,
    total: int,
    limit: int,
    *,
    label: str,
) -> int:
    """
    Append one decoded chunk while enforcing the full-stream ceiling.

    The implementation uses ``chunks``, ``chunk``, ``total``, ``limit``, and
    ``label`` to append one decoded chunk while enforcing the full-stream
    ceiling. The operation mutates ``chunks`` in place; ownership of those
    objects remains with the caller. If the function cannot append one decoded
    chunk while enforcing the full-stream ceiling, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        chunks: Entries supplied as ``chunks`` without transferring container
            ownership.
        chunk: Bounded byte sequence supplied as chunk.
        total: Numeric total used while the operation performs bounded
            accounting.
        limit: Numeric limit used while the operation performs bounded
            accounting.
        label: Text supplied as label in the format accepted by this function.

    Returns:
        The validated ``total``.

    Raises:
        ValueError: If ``label`` exceeds ``limit`` bytes.
    """
    total += len(chunk)
    if total > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    chunks.append(chunk)
    return total


def _invalid_trailing_bytes(name: str, kind: str) -> ValueError:
    """
    Return the invalid trailing bytes.

    After applying local validation, the function forwards ``name`` and ``kind``
    to ``ValueError`` and preserves its return and exception contract.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.
        kind: Text supplied as kind in the format accepted by this function.

    Returns:
        A ``ValueError`` describing invalid trailing bytes.
    """
    return ValueError(f"invalid trailing bytes after {kind} stream {name!r}")


def _decompress_framed_stream_strict(
    data: bytes,
    name: str,
    kind: str,
    limit: int,
) -> bytes:
    """
    Decode every gzip/bzip2/xz frame and reject an unclaimed suffix.

    The high-level ``gzip``, ``bz2`` and ``lzma`` file wrappers differ in how
    they treat bytes following a valid frame. Walking the one-frame decoder APIs
    makes the policy uniform: another valid frame is accepted, anything else is
    a failed-safe inspection.

    Args:
        data: Bounded byte sequence supplied as data.
        name: Stable name used for lookup and operator-facing diagnostics.
        kind: Text supplied as kind in the format accepted by this function.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        The bounded decompress framed stream strict bytes.

    Raises:
        BaseException: If a delegated failure occurs while the function attempts
            to decode every gzip/bzip2/xz frame and reject an unclaimed suffix.
        ValueError: If invalid ``kind`` stream ``name``: ``__name__``: ``exc``;
            truncated ``kind`` stream ``name``; or empty ``kind`` stream
            ``name``.
    """
    chunks: list[bytes] = []
    total = 0
    remaining = data
    frame_count = 0
    signatures = {
        "gzip": b"\x1f\x8b",
        "bzip2": b"BZh",
        "xz": b"\xfd7zXZ\x00",
    }

    while remaining:
        if not remaining.startswith(signatures[kind]):
            raise _invalid_trailing_bytes(name, kind)

        frame_count += 1
        if kind == "gzip":
            decoder: Any = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif kind == "bzip2":
            decoder = bz2.BZ2Decompressor()
        else:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_AUTO)

        pending = remaining
        while True:
            try:
                decoded = decoder.decompress(pending, limit - total + 1)
            except (OSError, EOFError, lzma.LZMAError, zlib.error) as exc:
                if frame_count > 1:
                    raise _invalid_trailing_bytes(name, kind) from exc
                raise ValueError(
                    f"invalid {kind} stream {name!r}: {type(exc).__name__}: {exc}"
                ) from exc
            total = _append_bounded(
                chunks,
                decoded,
                total,
                limit,
                label=f"{kind} stream {name!r}",
            )

            if decoder.eof:
                remaining = decoder.unused_data
                break

            unconsumed = getattr(decoder, "unconsumed_tail", b"")
            if unconsumed:
                pending = unconsumed
                continue
            if getattr(decoder, "needs_input", True):
                raise ValueError(f"truncated {kind} stream {name!r}")
            pending = b""

    if frame_count == 0:
        raise ValueError(f"empty {kind} stream {name!r}")
    return b"".join(chunks)


def _decompress_stream_strict(
    data: bytes,
    name: str,
    kind: str,
    limit: int,
    *,
    max_frames: int = _ZSTD_MAX_FRAMES,
    check_deadline: Callable[[], None] | None = None,
) -> bytes:
    """
    Decode all supported frames without accepting trailing garbage.

    StrictZstdReader distinguishes truncated frames and non-frame suffixes
    internally. At the sanitizer boundary both mean the.

    Args:
        data: Bounded byte sequence supplied as data.
        name: Stable name used for lookup and operator-facing diagnostics.
        kind: Text supplied as kind in the format accepted by this function.
        limit: Numeric limit used while the operation performs bounded
            accounting.
        max_frames: Upper bound enforced for max frames; the consuming boundary
            rejects or truncates values that exceed it.
        check_deadline: Optional caller-owned deadline check for the surrounding
            sanitization budget.

    Returns:
        The bounded decompress stream strict bytes.

    Raises:
        RuntimeError: If zstandard payload inspection lacks the 'zstandard'
            package.
        ValueError: If zstd stream ``name`` exceeds ``limit`` bytes.
        BaseException: If a delegated failure occurs while the function attempts
            to decode all supported frames without accepting trailing garbage.
    """
    if kind in {"gzip", "bzip2", "xz"}:
        return _decompress_framed_stream_strict(data, name, kind, limit)

    if zstandard is None:
        raise RuntimeError(
            "Zstandard payload inspection requires the 'zstandard' package"
        )
    try:
        with StrictZstdReader(
            io.BytesIO(data),
            max_window_size=_ZSTD_MAX_WINDOW_BYTES,
            max_output_bytes=limit,
            max_input_bytes=max(1, len(data)),
            max_frames=max_frames,
            check_deadline=check_deadline,
        ) as reader:
            return _read_bounded(
                reader,
                limit,
                label=f"zstd stream {name!r}",
            )
    except StrictZstdError as exc:
        if exc.reason == "output_size_limit":
            raise ValueError(f"zstd stream {name!r} exceeds {limit} bytes") from exc
        if exc.reason == "time_limit":
            raise ValueError(
                f"zstd stream {name!r} exceeded its decode time budget"
            ) from exc
        # StrictZstdReader distinguishes truncated frames and non-frame
        # suffixes internally. At the sanitizer boundary both mean the
        # physical compressed stream contains invalid trailing bytes.
        raise _invalid_trailing_bytes(name, kind) from exc


def _compressed_stream_kind(data: bytes) -> str | None:
    """
    Return the compressed stream kind.

    The implementation uses ``data`` to produce the compressed stream kind.

    Args:
        data: Bounded byte sequence supplied as data.

    Returns:
        The canonical compressed stream kind text, or ``None`` when the
        requested value is unavailable.
    """
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"BZh"):
        return "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(_ZSTD_FRAME_MAGIC):
        return "zstd"
    return None


def _validate_tar_terminator(data: bytes, logical_end: int, *, name: str) -> None:
    """
    Require the two zero TAR end blocks and zero-only record padding.

    The implementation uses ``data``, ``logical_end``, and ``name`` to require
    the two zero TAR end blocks and zero-only record padding. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        data: Bounded byte sequence supplied as data.
        logical_end: Numeric logical end used while the operation performs
            bounded accounting.
        name: Stable name used for lookup and operator-facing diagnostics.

    Raises:
        ValueError: If invalid trailing bytes after TAR archive ``name``.
    """
    trailing = data[logical_end:]
    if len(trailing) < 1024 or any(trailing):
        raise ValueError(f"invalid trailing bytes after TAR archive {name!r}")


_TAR_EXTENSION_TYPES = frozenset(
    {
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
    }
)


def _tar_header_without_sanitizable_logical_fields(
    header: bytes,
    raw_member: tarfile.TarInfo,
    sanitizer: Any,
) -> tuple[bytes, bool]:
    """
    Mask only sensitive TAR strings that rebuilding the member removes.

    The raw framing scan must still inspect unused bytes after each NUL
    terminator, extension headers, numeric fields, and format-specific opaque
    metadata. Masking an entire fixed-width slot, or a logical string that the
    sanitizer does not actually change, would let ignored bytes bypass the
    privacy backstop. This helper therefore clears only a sensitive decoded
    prefix that is discarded when the parsed member is emitted again.

    Args:
        header: One exact 512-byte ordinary TAR member header.
        raw_member: Member parsed directly from ``header``, before any GNU or
            PAX extension overrides are applied.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.

    Returns:
        A same-length metadata view plus whether rebuilding is required to
        remove at least one sensitive logical string.

    Raises:
        ValueError: If a raw logical field or its sanitized replacement is not
            text.
    """

    if len(header) != tarfile.BLOCKSIZE:
        return header, False
    masked = bytearray(header)

    def mask_string(start: int, end: int, *, enabled: bool) -> None:
        """
        Clear one enabled logical prefix while retaining ignored field bytes.

        Bytes after the first NUL are not part of the parsed TAR value. They
        remain visible to the opaque scanner even when the logical prefix is
        known to be removed by rebuilding the member.

        Args:
            start: Inclusive byte offset of the fixed-width TAR field.
            end: Exclusive byte offset of the fixed-width TAR field.
            enabled: Whether the parsed logical value needs sanitization.

        Side Effects:
            Replaces the decoded logical prefix in ``masked`` with zero bytes.
        """

        if not enabled:
            return
        field = masked[start:end]
        terminator = field.find(0)
        logical_size = len(field) if terminator < 0 else terminator
        masked[start : start + logical_size] = b"\0" * logical_size

    changed_fields: dict[str, bool] = {}
    for field_name in ("name", "uname", "gname"):
        original = getattr(raw_member, field_name)
        if not isinstance(original, str):
            raise ValueError("invalid non-text TAR header metadata")
        replacement = sanitizer.sanitize(original) if original else original
        if not isinstance(replacement, str):
            raise ValueError("invalid sanitized TAR header metadata")
        changed_fields[field_name] = replacement != original

    mask_string(0, 100, enabled=changed_fields["name"])
    if header[257:262] == b"ustar":
        mask_string(265, 297, enabled=changed_fields["uname"])
        mask_string(297, 329, enabled=changed_fields["gname"])
        mask_string(345, 500, enabled=changed_fields["name"])
    return bytes(masked), any(changed_fields.values())


def _tar_extension_path_matches_member(
    value: str,
    member: tarfile.TarInfo,
) -> bool:
    """
    Return whether an extension path represents its effective TAR member.

    Python normalizes the conventional trailing slash away from directory names
    supplied by PAX or GNU long-name records. That single spelling difference
    carries no distinct extraction semantics; files and every other mismatch
    remain unequal.

    Args:
        value: Parsed value of one PAX or GNU path extension.
        member: Effective member produced from the extension.

    Returns:
        ``True`` for exact equality or the directory-only trailing-slash form.
    """

    return value == member.name or (
        member.isdir()
        and value.endswith("/")
        and value.rstrip("/") == member.name.rstrip("/")
    )


def _tar_pax_payload_without_sanitizable_path(
    payload: bytes,
    member: tarfile.TarInfo,
    sanitizer: Any,
) -> tuple[bytes, bool]:
    """
    Mask one rewriteable per-member PAX ``path`` value for raw scanning.

    A PAX ``path`` record is not opaque metadata when it exactly supplies the
    effective member name already exposed by ``TarInfo.name``. The archive
    rebuild rewrites that logical name and re-emits its PAX representation, so
    the original value may be masked from the raw-byte privacy backstop. Every
    other PAX key/value remains visible to that scan and therefore fail-closed.

    Args:
        payload: Exact unpadded payload bytes from one per-member PAX header.
        member: Effective parsed member governed by the PAX header.
        sanitizer: Sanitizer applied to the effective path before rebuild.

    Returns:
        A same-length metadata view and whether a sensitive mirrored path was
        masked because the rebuilt archive removes it.

    Raises:
        ValueError: If PAX framing is malformed, duplicated, non-UTF-8, or does
            not agree with the effective parsed member.
    """

    masked = bytearray(payload)
    position = 0
    changed = False
    seen_keys: set[str] = set()
    while position < len(payload):
        space = payload.find(b" ", position, min(position + 21, len(payload)))
        if space < 0 or not payload[position:space].isdigit():
            raise ValueError("invalid TAR PAX metadata framing")
        record_length = int(payload[position:space])
        record_end = position + record_length
        if (
            record_length < 5
            or record_end > len(payload)
            or payload[record_end - 1] != 0x0A
        ):
            raise ValueError("invalid TAR PAX metadata framing")
        equals = payload.find(b"=", space + 1, record_end - 1)
        if equals < 0:
            raise ValueError("invalid TAR PAX metadata framing")
        try:
            key = payload[space + 1 : equals].decode("utf-8")
            value = payload[equals + 1 : record_end - 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("invalid TAR PAX metadata encoding") from error
        if not key or key in seen_keys:
            raise ValueError("ambiguous duplicate TAR PAX field")
        seen_keys.add(key)
        if key == "path" and sanitizer.sanitize(value) != value:
            if member.pax_headers.get(
                "path"
            ) != value or not _tar_extension_path_matches_member(value, member):
                raise ValueError("ambiguous TAR PAX path metadata")
            masked[equals + 1 : record_end - 1] = b"\0" * (record_end - equals - 2)
            changed = True
        position = record_end
    if position != len(payload):
        raise ValueError("invalid TAR PAX metadata framing")
    return bytes(masked), changed


def _tar_gnu_longname_payload_without_sanitizable_path(
    payload: bytes,
    member: tarfile.TarInfo,
    sanitizer: Any,
) -> tuple[bytes, bool]:
    """
    Mask one rewriteable GNU long-name value for raw metadata scanning.

    GNU TAR stores a path that does not fit the ordinary header in a preceding
    ``L`` record. Python exposes that value as the following member's effective
    name, and rebuilding the member emits a fresh long-name record when one is
    still required. Only that exact relationship is admitted here. Bytes after
    the first NUL remain visible to the opaque scan, and GNU long-link targets
    use a separate record type that this helper never accepts.

    Args:
        payload: Exact unpadded payload bytes from one GNU long-name header.
        member: Effective member produced from that record.
        sanitizer: Sanitizer applied to the effective path before rebuild.

    Returns:
        A same-length metadata view and whether the logical path was masked.

    Raises:
        ValueError: If the encoded long name does not agree with the effective
            member.
    """

    terminator = payload.find(b"\0")
    logical_end = len(payload) if terminator < 0 else terminator
    value = payload[:logical_end].decode("utf-8", errors="surrogateescape")
    if sanitizer.sanitize(value) == value:
        return payload, False
    if not _tar_extension_path_matches_member(value, member):
        raise ValueError("ambiguous TAR GNU long-name metadata")
    masked = bytearray(payload)
    masked[:logical_end] = b"\0" * logical_end
    return bytes(masked), True


def _validate_tar_raw_framing(
    data: bytes,
    members: list[tarfile.TarInfo],
    logical_end: int,
    *,
    sanitizer: Any,
    name: str,
) -> bool:
    """
    Reject sensitive ignored header bytes and nonzero TAR block padding.

    The implementation uses ``data``, ``members``, ``logical_end``,
    ``sanitizer``, and ``name`` to reject sensitive ignored header bytes and
    nonzero TAR block padding. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        data: Bounded byte sequence supplied as data.
        members: Member values received from the source collection in their
            existing order.
        logical_end: Numeric logical end used while the operation performs
            bounded accounting.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        Whether sensitive logical bytes in an ordinary raw header require the
        archive to be rebuilt even when an extension overrides those bytes.

    Raises:
        ValueError: If invalid TAR member framing in ``name``; truncated TAR
            header in ``name``; premature TAR terminator in ``name``; or
            sensitive data in TAR header metadata: ``name``; or another input
            invariant is violated.
    """

    def scan_global_extension(position: int) -> int:
        """
        Scan global extension.

        The implementation uses ``position`` to scan global extension. If the
        function cannot scan global extension, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            position: Numeric position used while the operation performs bounded
                accounting.

        Returns:
            The validated ``padded_end``.

        Raises:
            ValueError: If truncated TAR global extension in ``name``; sensitive
                data in TAR header metadata: ``name``; invalid TAR global
                extension in ``name``; or invalid TAR member framing in
                ``name``; or another input invariant is violated.
        """
        header_end = position + tarfile.BLOCKSIZE
        if header_end > logical_end:
            raise ValueError(f"truncated TAR global extension in {name!r}")
        header = data[position:header_end]
        if _opaque_metadata_contains_sensitive_text(header, sanitizer):
            raise ValueError(f"sensitive data in TAR header metadata: {name!r}")
        try:
            raw_member = tarfile.TarInfo.frombuf(
                header,
                encoding="utf-8",
                errors="surrogateescape",
            )
        except tarfile.TarError as exc:
            raise ValueError(f"invalid TAR global extension in {name!r}") from exc
        if raw_member.type != tarfile.XGLTYPE:
            raise ValueError(f"invalid TAR member framing in {name!r}")
        extension_end = header_end + raw_member.size
        padded_end = (
            header_end
            + ((raw_member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE)
            * tarfile.BLOCKSIZE
        )
        if extension_end > logical_end or padded_end > logical_end:
            raise ValueError(f"truncated TAR global extension in {name!r}")
        if _opaque_metadata_contains_sensitive_text(
            data[header_end:extension_end], sanitizer
        ):
            raise ValueError(f"sensitive data in TAR extension metadata: {name!r}")
        if any(data[extension_end:padded_end]):
            raise ValueError(f"non-zero TAR extension padding in {name!r}")
        return padded_end

    expected_offset = 0
    logical_header_changed = False
    for index, member in enumerate(members):
        while expected_offset < member.offset:
            expected_offset = scan_global_extension(expected_offset)
        if member.offset != expected_offset or member.offset_data > logical_end:
            raise ValueError(f"invalid TAR member framing in {name!r}")
        position = member.offset
        while position < member.offset_data:
            header_end = position + tarfile.BLOCKSIZE
            if header_end > member.offset_data:
                raise ValueError(f"truncated TAR header in {name!r}")
            header = data[position:header_end]
            if not any(header):
                raise ValueError(f"premature TAR terminator in {name!r}")
            try:
                raw_member = tarfile.TarInfo.frombuf(
                    header,
                    encoding="utf-8",
                    errors="surrogateescape",
                )
            except tarfile.TarError as exc:
                raise ValueError(f"invalid TAR header framing in {name!r}") from exc
            metadata_view, raw_changed = _tar_header_without_sanitizable_logical_fields(
                header,
                raw_member,
                sanitizer,
            )
            logical_header_changed = logical_header_changed or raw_changed
            if _opaque_metadata_contains_sensitive_text(metadata_view, sanitizer):
                raise ValueError(f"sensitive data in TAR header metadata: {name!r}")
            if header_end == member.offset_data:
                position = header_end
                break
            if raw_member.type not in _TAR_EXTENSION_TYPES:
                raise ValueError(f"invalid TAR extension framing in {name!r}")
            extension_end = header_end + raw_member.size
            padded_end = (
                header_end
                + ((raw_member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE)
                * tarfile.BLOCKSIZE
            )
            if extension_end > member.offset_data or padded_end > member.offset_data:
                raise ValueError(f"truncated TAR extension framing in {name!r}")
            extension_view = data[header_end:extension_end]
            if raw_member.type in {tarfile.XHDTYPE, tarfile.SOLARIS_XHDTYPE}:
                extension_view, pax_path_changed = (
                    _tar_pax_payload_without_sanitizable_path(
                        extension_view,
                        member,
                        sanitizer,
                    )
                )
                logical_header_changed = logical_header_changed or pax_path_changed
            elif raw_member.type == tarfile.GNUTYPE_LONGNAME:
                extension_view, longname_changed = (
                    _tar_gnu_longname_payload_without_sanitizable_path(
                        extension_view,
                        member,
                        sanitizer,
                    )
                )
                logical_header_changed = logical_header_changed or longname_changed
            if _opaque_metadata_contains_sensitive_text(extension_view, sanitizer):
                raise ValueError(f"sensitive data in TAR extension metadata: {name!r}")
            if any(data[extension_end:padded_end]):
                raise ValueError(f"non-zero TAR extension padding in {name!r}")
            position = padded_end
        if position != member.offset_data:
            raise ValueError(f"invalid TAR member framing in {name!r}")
        data_end = member.offset_data + member.size
        padded_end = (
            member.offset_data
            + ((member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE)
            * tarfile.BLOCKSIZE
        )
        next_member_offset = (
            members[index + 1].offset if index + 1 < len(members) else logical_end
        )
        if data_end > padded_end or padded_end > next_member_offset:
            raise ValueError(f"invalid TAR member boundary in {name!r}")
        if any(data[data_end:padded_end]):
            raise ValueError(f"non-zero TAR member padding in {name!r}")
        expected_offset = padded_end
    while expected_offset < logical_end:
        expected_offset = scan_global_extension(expected_offset)
    if expected_offset != logical_end:
        raise ValueError(f"invalid TAR member framing in {name!r}")
    return logical_header_changed


def _sanitize_tar_logical_metadata(
    member: tarfile.TarInfo,
    sanitizer: Any,
) -> tuple[tarfile.TarInfo, bool]:
    """
    Rewrite unambiguous TAR identity strings and reject unsafe metadata.

    Member paths and the informational owner/group names can be validated and
    rewritten without changing file payload bytes. A per-member PAX ``path``
    that exactly mirrors the effective member name is the same rewriteable
    field and stays synchronized with it. Link targets and every other PAX
    record carry extraction or format semantics, so sensitive values in those
    fields remain fail-closed.

    Args:
        member: Parsed member whose logical metadata is inspected.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.

    Returns:
        A copied member carrying sanitized ``name``, ``uname``, and ``gname``
        fields, plus whether any of those fields changed.

    Raises:
        ValueError: If metadata is non-text, the sanitizer returns non-text, or
            sensitive link/PAX metadata cannot be rewritten safely.
    """

    values: list[Any] = [member.name, member.linkname, member.uname, member.gname]
    for key, value in member.pax_headers.items():
        values.extend((key, value))
    for value in values:
        if not isinstance(value, str):
            raise ValueError("invalid non-text TAR metadata")
    if member.linkname and sanitizer.sanitize(member.linkname) != member.linkname:
        raise ValueError("sensitive data in TAR logical metadata")
    sanitized = copy.copy(member)
    sanitized.pax_headers = dict(member.pax_headers)
    changed = False
    for field_name in ("name", "uname", "gname"):
        original = getattr(member, field_name)
        replacement = sanitizer.sanitize(original) if original else original
        if not isinstance(replacement, str):
            raise ValueError("invalid sanitized TAR logical metadata")
        setattr(sanitized, field_name, replacement)
        changed = changed or replacement != original
    for key, value in member.pax_headers.items():
        if key and sanitizer.sanitize(key) != key:
            raise ValueError("sensitive data in TAR logical metadata")
        replacement = sanitizer.sanitize(value) if value else value
        if replacement == value:
            continue
        if key != "path" or not _tar_extension_path_matches_member(value, member):
            raise ValueError("sensitive data in TAR logical metadata")
        sanitized.pax_headers[key] = sanitized.name + (
            "/" if member.isdir() and value.endswith("/") else ""
        )
        changed = True
    return sanitized, changed


def _validate_zip_terminator(data: bytes, *, name: str) -> int:
    """
    Require an EOCD record whose comment ends at the physical EOF.

    The implementation uses ``data`` and ``name`` to require an EOCD record
    whose comment ends at the physical EOF. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        data: Bounded byte sequence supplied as data.
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        The validated ``position``.

    Raises:
        ValueError: If invalid trailing bytes after ZIP archive ``name``.
    """
    signature = b"PK\x05\x06"
    minimum = 22
    search_start = max(0, len(data) - (minimum + 0xFFFF))
    position = data.rfind(signature, search_start)
    while position >= search_start:
        if position + minimum <= len(data):
            comment_size = int.from_bytes(data[position + 20 : position + 22], "little")
            if position + minimum + comment_size == len(data):
                return position
        position = data.rfind(signature, search_start, position)
    raise ValueError(f"invalid trailing bytes after ZIP archive {name!r}")


def _validate_zip_central_directory(
    data: bytes,
    *,
    limits: BundleSanitizationLimits,
    sanitizer: Any,
    classic_end_offset: int,
) -> int:
    """
    Bound and count central-directory records before ``ZipFile`` allocates.

    The implementation uses ``data``, ``limits``, ``sanitizer``, and
    ``classic_end_offset`` to bound and count central-directory records before
    ``ZipFile`` allocates. If the function cannot bound and count
    central-directory records before ``ZipFile`` allocates, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        data: Bounded byte sequence supplied as data.
        limits: Limits governing bound and count central-directory records
            before ``ZipFile`` allocates.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        classic_end_offset: Numeric classic end offset used by the operation's
            bounded accounting.

    Returns:
        The validated ``count``.

    Raises:
        ValueError: If invalid ZIP end-of-central-directory record; multi-disk
            ZIP archives are not distributable; archive member count exceeds
            ``max_archive_members``; or multi-disk ZIP64 archives are not
            distributable; or another input invariant is violated.
    """

    try:
        end_record = zipfile._EndRecData(io.BytesIO(data))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("invalid ZIP end-of-central-directory record") from exc
    if end_record is None:
        raise ValueError("invalid ZIP end-of-central-directory record")

    classic_disk = int.from_bytes(
        data[classic_end_offset + 4 : classic_end_offset + 6], "little"
    )
    classic_directory_disk = int.from_bytes(
        data[classic_end_offset + 6 : classic_end_offset + 8], "little"
    )
    classic_disk_count = int.from_bytes(
        data[classic_end_offset + 8 : classic_end_offset + 10], "little"
    )
    classic_total_count = int.from_bytes(
        data[classic_end_offset + 10 : classic_end_offset + 12], "little"
    )
    classic_directory_size = int.from_bytes(
        data[classic_end_offset + 12 : classic_end_offset + 16], "little"
    )
    classic_directory_offset = int.from_bytes(
        data[classic_end_offset + 16 : classic_end_offset + 20], "little"
    )
    if (
        classic_disk != 0
        or classic_directory_disk != 0
        or classic_disk_count != classic_total_count
        or int(end_record[zipfile._ECD_DISK_NUMBER]) != 0
        or int(end_record[zipfile._ECD_DISK_START]) != 0
        or int(end_record[zipfile._ECD_ENTRIES_THIS_DISK])
        != int(end_record[zipfile._ECD_ENTRIES_TOTAL])
    ):
        raise ValueError("multi-disk ZIP archives are not distributable")

    declared_count = int(end_record[zipfile._ECD_ENTRIES_TOTAL])
    directory_size = int(end_record[zipfile._ECD_SIZE])
    directory_offset = int(end_record[zipfile._ECD_OFFSET])
    end_record_offset = int(end_record[zipfile._ECD_LOCATION])
    if declared_count > limits.max_archive_members:
        raise ValueError(f"archive member count exceeds {limits.max_archive_members}")
    zip64_metadata_size = 0
    locator_offset = classic_end_offset - 20
    has_zip64_locator = locator_offset >= 0 and data.startswith(
        b"PK\x06\x07", locator_offset
    )
    if has_zip64_locator:
        locator_disk = int.from_bytes(
            data[locator_offset + 4 : locator_offset + 8], "little"
        )
        zip64_offset = int.from_bytes(
            data[locator_offset + 8 : locator_offset + 16], "little"
        )
        locator_disks = int.from_bytes(
            data[locator_offset + 16 : locator_offset + 20], "little"
        )
        if locator_disk != 0 or locator_disks != 1:
            raise ValueError("multi-disk ZIP64 archives are not distributable")
        if (
            zip64_offset < 0
            or zip64_offset + 56 > locator_offset
            or not data.startswith(b"PK\x06\x06", zip64_offset)
        ):
            raise ValueError("invalid ZIP64 end-of-central-directory record")
        zip64_payload_size = int.from_bytes(
            data[zip64_offset + 4 : zip64_offset + 12], "little"
        )
        zip64_metadata_size = 12 + zip64_payload_size
        if (
            zip64_payload_size < 44
            or zip64_metadata_size > _MAX_ZIP64_END_RECORD_BYTES
            or zip64_offset + zip64_metadata_size != locator_offset
        ):
            raise ValueError("invalid ZIP64 end-of-central-directory record")
        zip64_disk = int.from_bytes(
            data[zip64_offset + 16 : zip64_offset + 20], "little"
        )
        zip64_directory_disk = int.from_bytes(
            data[zip64_offset + 20 : zip64_offset + 24], "little"
        )
        zip64_disk_count = int.from_bytes(
            data[zip64_offset + 24 : zip64_offset + 32], "little"
        )
        zip64_total_count = int.from_bytes(
            data[zip64_offset + 32 : zip64_offset + 40], "little"
        )
        zip64_directory_size = int.from_bytes(
            data[zip64_offset + 40 : zip64_offset + 48], "little"
        )
        zip64_directory_offset = int.from_bytes(
            data[zip64_offset + 48 : zip64_offset + 56], "little"
        )
        if (
            zip64_disk != 0
            or zip64_directory_disk != 0
            or zip64_disk_count != zip64_total_count
            or zip64_total_count != declared_count
            or zip64_directory_size != directory_size
            or zip64_directory_offset != directory_offset
            or zip64_offset != end_record_offset
        ):
            raise ValueError("ZIP64 metadata disagrees with the central directory")
        if (
            classic_disk_count not in (0xFFFF, zip64_disk_count)
            or classic_total_count not in (0xFFFF, zip64_total_count)
            or classic_directory_size not in (0xFFFFFFFF, zip64_directory_size)
            or classic_directory_offset not in (0xFFFFFFFF, zip64_directory_offset)
        ):
            raise ValueError("classic ZIP metadata disagrees with ZIP64 metadata")
        if _opaque_metadata_contains_sensitive_text(
            data[zip64_offset + 56 : locator_offset], sanitizer
        ):
            raise ValueError("sensitive data in ZIP64 extensible metadata")
    else:
        if end_record_offset != classic_end_offset:
            raise ValueError("ZIP64 end record is missing its locator")
        if (
            classic_disk_count == 0xFFFF
            or classic_total_count == 0xFFFF
            or classic_directory_size == 0xFFFFFFFF
            or classic_directory_offset == 0xFFFFFFFF
        ):
            raise ValueError("ZIP64 sentinel metadata is missing its end record")

    if directory_size + zip64_metadata_size > limits.max_archive_metadata_bytes:
        raise ValueError(
            f"ZIP central directory exceeds {limits.max_archive_metadata_bytes} bytes"
        )
    concatenated_prefix = end_record_offset - directory_size - directory_offset
    if concatenated_prefix != 0:
        raise ValueError("prepended bytes before ZIP archive are not distributable")
    if declared_count == 0 and directory_offset != 0:
        raise ValueError("unindexed bytes precede an empty ZIP central directory")
    position = directory_offset + concatenated_prefix
    directory_end = position + directory_size
    if position < 0 or directory_end < position or directory_end > len(data):
        raise ValueError("invalid ZIP central-directory bounds")

    count = 0
    while position < directory_end:
        record_start = position
        fixed_size = 46
        if position + fixed_size > directory_end or not data.startswith(
            b"PK\x01\x02", position
        ):
            raise ValueError("invalid ZIP central-directory framing")
        filename_size = int.from_bytes(data[position + 28 : position + 30], "little")
        extra_size = int.from_bytes(data[position + 30 : position + 32], "little")
        comment_size = int.from_bytes(data[position + 32 : position + 34], "little")
        disk_start = int.from_bytes(data[position + 34 : position + 36], "little")
        if disk_start != 0:
            raise ValueError("multi-disk ZIP archives are not distributable")
        extra_start = position + fixed_size + filename_size
        extra_end = extra_start + extra_size
        if extra_end > directory_end:
            raise ValueError("invalid ZIP central-directory framing")
        _validate_zip64_central_extra(
            data[extra_start:extra_end],
            uncompressed_size=int.from_bytes(
                data[record_start + 24 : record_start + 28], "little"
            ),
            compressed_size=int.from_bytes(
                data[record_start + 20 : record_start + 24], "little"
            ),
            header_offset=int.from_bytes(
                data[record_start + 42 : record_start + 46], "little"
            ),
        )
        position += fixed_size + filename_size + extra_size + comment_size
        if position > directory_end:
            raise ValueError("invalid ZIP central-directory framing")
        count += 1
        if count > limits.max_archive_members:
            raise ValueError(
                f"archive member count exceeds {limits.max_archive_members}"
            )
    if position != directory_end or count != declared_count:
        raise ValueError("ZIP central-directory member count is inconsistent")
    return count


def _zip64_local_sizes(
    extra: bytes,
    *,
    compressed_size: int,
    uncompressed_size: int,
) -> tuple[int, int]:
    """
    Resolve ZIP64 local-header sentinels without allocating field payloads.

    The implementation uses ``extra``, ``compressed_size``, and
    ``uncompressed_size`` to resolve ZIP64 local-header sentinels without
    allocating field payloads. If the function cannot resolve ZIP64 local-header
    sentinels without allocating field payloads, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        extra: Bounded byte sequence supplied as extra.
        compressed_size: Numeric compressed size used by the operation's bounded
            accounting.
        uncompressed_size: Numeric uncompressed size used by the operation's
            bounded accounting.

    Returns:
        A tuple containing ``compressed size`` and ``uncompressed size`` in that
        order.

    Raises:
        ValueError: If extraneous ZIP64 local size metadata; or invalid ZIP64
            local size metadata.
    """

    needs_uncompressed = uncompressed_size == 0xFFFFFFFF
    needs_compressed = compressed_size == 0xFFFFFFFF
    zip64_values = _zip_extra_field_values(extra, 0x0001)
    if not needs_uncompressed and not needs_compressed:
        if zip64_values:
            raise ValueError("extraneous ZIP64 local size metadata")
        return compressed_size, uncompressed_size
    expected_size = 8 * (int(needs_uncompressed) + int(needs_compressed))
    if len(zip64_values) != 1 or len(zip64_values[0]) != expected_size:
        raise ValueError("invalid ZIP64 local size metadata")
    value = zip64_values[0]
    cursor = 0
    if needs_uncompressed:
        uncompressed_size = int.from_bytes(value[cursor : cursor + 8], "little")
        cursor += 8
    if needs_compressed:
        compressed_size = int.from_bytes(value[cursor : cursor + 8], "little")
    return compressed_size, uncompressed_size


def _validate_zip64_central_extra(
    extra: bytes,
    *,
    uncompressed_size: int,
    compressed_size: int,
    header_offset: int,
) -> None:
    """
    Require one exact ZIP64 central field only for sentinel-owned values.

    The implementation uses ``extra``, ``uncompressed_size``,
    ``compressed_size``, and ``header_offset`` to require one exact ZIP64
    central field only for sentinel-owned values. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        extra: Bounded byte sequence supplied as extra.
        uncompressed_size: Numeric uncompressed size used by the operation's
            bounded accounting.
        compressed_size: Numeric compressed size used by the operation's bounded
            accounting.
        header_offset: Numeric header offset used by the operation's bounded
            accounting.

    Raises:
        ValueError: If extraneous ZIP64 central metadata; or invalid ZIP64
            central metadata.
    """

    needs = (
        uncompressed_size == 0xFFFFFFFF,
        compressed_size == 0xFFFFFFFF,
        header_offset == 0xFFFFFFFF,
    )
    values = _zip_extra_field_values(extra, 0x0001)
    if not any(needs):
        if values:
            raise ValueError("extraneous ZIP64 central metadata")
        return
    if len(values) != 1 or len(values[0]) != 8 * sum(needs):
        raise ValueError("invalid ZIP64 central metadata")


def _zip_extra_fields(extra: bytes) -> tuple[tuple[int, bytes], ...]:
    """
    Return all exactly framed ZIP extra fields in source order.

    After applying local validation, the function forwards ``extra`` to
    ``tuple`` and preserves its return and exception contract.

    Args:
        extra: Bounded byte sequence supplied as extra.

    Returns:
        The ZIP extra fields returned in operation-defined order.

    Raises:
        ValueError: If invalid ZIP extra-field framing.
    """

    fields: list[tuple[int, bytes]] = []
    position = 0
    while position < len(extra):
        if position + 4 > len(extra):
            raise ValueError("invalid ZIP extra-field framing")
        current_id = int.from_bytes(extra[position : position + 2], "little")
        field_size = int.from_bytes(extra[position + 2 : position + 4], "little")
        field_start = position + 4
        field_end = field_start + field_size
        if field_end > len(extra):
            raise ValueError("invalid ZIP extra-field framing")
        fields.append((current_id, extra[field_start:field_end]))
        position = field_end
    return tuple(fields)


def _zip_extra_field_values(extra: bytes, field_id: int) -> tuple[bytes, ...]:
    """
    Return every exactly framed value for one ZIP extra-field identifier.

    After applying local validation, the function forwards ``extra`` and
    ``field_id`` to ``tuple`` and preserves its return and exception contract.

    Args:
        extra: Bounded byte sequence supplied as extra.
        field_id: Stable field identifier used to correlate configuration, logs,
            and results.

    Returns:
        The ZIP extra field values returned in operation-defined order.
    """

    return tuple(
        value
        for current_id, value in _zip_extra_fields(extra)
        if current_id == field_id
    )


def _validate_zip_unix_uid_gid_extra(value: bytes, *, label: str) -> None:
    """
    Validate the non-path-bearing Info-ZIP new Unix UID/GID field.

    The implementation uses ``value`` and ``label`` to validate the
    non-path-bearing Info-ZIP new Unix UID/GID field. Every required invariant
    is checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        value: Bounded byte sequence supplied as value.
        label: Text supplied as label in the format accepted by this function.

    Raises:
        ValueError: If invalid ZIP Unix UID/GID metadata: ``label``.
    """

    if len(value) < 4 or value[0] != 1:
        raise ValueError(f"invalid ZIP Unix UID/GID metadata: {label}")
    uid_size = value[1]
    gid_size_offset = 2 + uid_size
    if (
        not 1 <= uid_size <= 8
        or gid_size_offset >= len(value)
        or not 1 <= value[gid_size_offset] <= 8
        or gid_size_offset + 1 + value[gid_size_offset] != len(value)
    ):
        raise ValueError(f"invalid ZIP Unix UID/GID metadata: {label}")


def _validate_zip_microsoft_padding_extra(value: bytes, *, label: str) -> None:
    """
    Validate Microsoft's local-only, zero-filled ZIP alignment field.

    The implementation uses ``value`` and ``label`` to validate Microsoft's
    local-only, zero-filled ZIP alignment field. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        value: Bounded byte sequence supplied as value.
        label: Text supplied as label in the format accepted by this function.

    Raises:
        ValueError: If invalid ZIP Microsoft padding metadata: ``label``.
    """

    if (
        len(value) < 4
        or int.from_bytes(value[:2], "little") != 0xA028
        or int.from_bytes(value[2:4], "little") != len(value) - 4
        or any(value[4:])
    ):
        raise ValueError(f"invalid ZIP Microsoft padding metadata: {label}")


def _zip_extended_timestamp_mtime(
    value: bytes,
    *,
    label: str,
    central: bool,
) -> int | None:
    """
    Validate one Info-ZIP timestamp field and return its optional mtime.

    The implementation uses ``value``, ``label``, and ``central`` to validate
    one Info-ZIP timestamp field and return its optional mtime. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        value: Bounded byte sequence supplied as value.
        label: Text supplied as label in the format accepted by this function.
        central: Whether central is enabled or required for this operation.

    Returns:
        The numeric ZIP extended timestamp mtime value, or ``None`` when the
        requested value is unavailable.

    Raises:
        ValueError: If invalid ZIP extended timestamp metadata: ``label``.
    """

    if not value or value[0] & ~0x07:
        raise ValueError(f"invalid ZIP extended timestamp metadata: {label}")
    full_size = 1 + 4 * (value[0].bit_count())
    allowed_sizes = {full_size}
    if central:
        allowed_sizes.add(5 if value[0] & 0x01 else 1)
    if len(value) not in allowed_sizes:
        raise ValueError(f"invalid ZIP extended timestamp metadata: {label}")
    return int.from_bytes(value[1:5], "little") if value[0] & 0x01 else None


def _zip_ntfs_timestamps(value: bytes, *, label: str) -> tuple[int, int, int]:
    """
    Validate one canonical NTFS timestamp extra field.

    After applying local validation, the function forwards ``value`` and
    ``label`` to ``tuple`` and preserves its return and exception contract.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path.

    Args:
        value: Bounded byte sequence supplied as value.
        label: Text supplied as label in the format accepted by this function.

    Returns:
        A tuple containing the fields that represent ZIP ntfs timestamps.

    Raises:
        ValueError: If invalid ZIP NTFS timestamp metadata: ``label``.
    """

    if (
        len(value) != 32
        or value[:4] != b"\0" * 4
        or int.from_bytes(value[4:6], "little") != 0x0001
        or int.from_bytes(value[6:8], "little") != 24
    ):
        raise ValueError(f"invalid ZIP NTFS timestamp metadata: {label}")
    return tuple(
        int.from_bytes(value[offset : offset + 8], "little") for offset in (8, 16, 24)
    )


def _validate_zip_local_header(
    data: bytes,
    info: zipfile.ZipInfo,
    *,
    sanitizer: Any,
) -> tuple[int, int, tuple[Any, ...]]:
    """
    Require local-header sizes and descriptors to agree with the central entry.

    The implementation uses ``data``, ``info``, and ``sanitizer`` to require
    local-header sizes and descriptors to agree with the central entry. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        data: Bounded byte sequence supplied as data.
        info: Info object whose ``CRC``, ``compress_size``, ``compress_type``,
            ``date_time``, and ``encode`` state is read while performing
            local-header sizes and descriptors to agree with the central entry.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.

    Returns:
        A tuple containing ``payload start``, ``integer count``, and ``local
        metadata fingerprint`` in that order.

    Raises:
        ValueError: If invalid ZIP local header for ``label``; truncated ZIP
            local header for ``label``; invalid ZIP DOS timestamp metadata:
            ``label``; or ZIP local header disagrees with central directory:
            ``label``; or another input invariant is violated.
    """

    label = _archive_path_label(info.filename)
    header_offset = info.header_offset
    fixed_size = 30
    if (
        header_offset < 0
        or header_offset + fixed_size > len(data)
        or not data.startswith(b"PK\x03\x04", header_offset)
    ):
        raise ValueError(f"invalid ZIP local header for {label}")
    flags = int.from_bytes(data[header_offset + 6 : header_offset + 8], "little")
    compression = int.from_bytes(data[header_offset + 8 : header_offset + 10], "little")
    local_time = int.from_bytes(data[header_offset + 10 : header_offset + 12], "little")
    local_date = int.from_bytes(data[header_offset + 12 : header_offset + 14], "little")
    crc = int.from_bytes(data[header_offset + 14 : header_offset + 18], "little")
    compressed_size = int.from_bytes(
        data[header_offset + 18 : header_offset + 22], "little"
    )
    uncompressed_size = int.from_bytes(
        data[header_offset + 22 : header_offset + 26], "little"
    )
    filename_size = int.from_bytes(
        data[header_offset + 26 : header_offset + 28], "little"
    )
    extra_size = int.from_bytes(data[header_offset + 28 : header_offset + 30], "little")
    extra_start = header_offset + fixed_size + filename_size
    payload_start = extra_start + extra_size
    if payload_start > len(data):
        raise ValueError(f"truncated ZIP local header for {label}")
    year, month, day, hour, minute, second = info.date_time
    try:
        datetime.datetime(year, month, day, hour, minute, second)
    except ValueError as exc:
        raise ValueError(f"invalid ZIP DOS timestamp metadata: {label}") from exc
    central_time = (hour << 11) | (minute << 5) | (second // 2)
    central_date = ((year - 1980) << 9) | (month << 5) | day
    if (
        data[header_offset + 4] != info.extract_version
        or data[header_offset + 5] != info.reserved
        or flags != info.flag_bits
        or compression != info.compress_type
        or local_time != central_time
        or local_date != central_date
    ):
        raise ValueError(f"ZIP local header disagrees with central directory: {label}")
    local_extra = data[extra_start:payload_start]
    local_metadata_fingerprint = (
        flags,
        compression,
        local_time,
        local_date,
        crc,
        compressed_size,
        uncompressed_size,
        hashlib.sha256(local_extra).digest(),
    )
    raw_filename = data[
        header_offset + fixed_size : header_offset + fixed_size + filename_size
    ]
    filename_encoding = "utf-8" if flags & 0x800 else "cp437"
    try:
        central_raw_filename = info.orig_filename.encode(filename_encoding)
    except UnicodeEncodeError as exc:
        raise ValueError(f"invalid ZIP filename encoding: {label}") from exc
    if raw_filename != central_raw_filename:
        raise ValueError(f"ZIP filename metadata disagrees between headers: {label}")
    if _opaque_metadata_contains_sensitive_text(
        raw_filename, sanitizer
    ) or _opaque_metadata_contains_sensitive_text(central_raw_filename, sanitizer):
        raise ValueError("sensitive data in ZIP member path metadata")
    for metadata in (local_extra, info.extra):
        if any(
            _opaque_metadata_contains_sensitive_text(value, sanitizer)
            for _, value in _zip_extra_fields(metadata)
        ):
            raise ValueError(f"sensitive data in opaque ZIP extra metadata: {label}")
    local_unicode_paths = _zip_extra_field_values(local_extra, 0x7075)
    central_unicode_paths = _zip_extra_field_values(info.extra, 0x7075)
    if (
        len(local_unicode_paths) > 1
        or len(central_unicode_paths) > 1
        or local_unicode_paths != central_unicode_paths
    ):
        raise ValueError(
            f"ZIP Unicode path metadata disagrees between headers: {label}"
        )
    if local_unicode_paths:
        unicode_path = local_unicode_paths[0]
        if (
            len(unicode_path) < 6
            or unicode_path[0] != 1
            or int.from_bytes(unicode_path[1:5], "little") != zlib.crc32(raw_filename)
        ):
            raise ValueError(f"invalid ZIP Unicode path metadata: {label}")
        try:
            selected_unicode_path = unicode_path[5:].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"invalid ZIP Unicode path metadata: {label}") from exc
        if selected_unicode_path != info.filename:
            raise ValueError(f"ambiguous ZIP Unicode path metadata: {label}")
    local_zip64 = _zip_extra_field_values(local_extra, 0x0001)
    central_zip64 = _zip_extra_field_values(info.extra, 0x0001)
    if len(local_zip64) > 1 or len(central_zip64) > 1:
        raise ValueError(f"duplicate ZIP64 metadata is ambiguous: {label}")
    local_uid_gid = _zip_extra_field_values(local_extra, 0x7875)
    central_uid_gid = _zip_extra_field_values(info.extra, 0x7875)
    if (
        len(local_uid_gid) > 1
        or len(central_uid_gid) > 1
        or local_uid_gid != central_uid_gid
    ):
        raise ValueError(
            f"ZIP Unix UID/GID metadata disagrees between headers: {label}"
        )
    if local_uid_gid:
        _validate_zip_unix_uid_gid_extra(local_uid_gid[0], label=label)
    local_timestamps = _zip_extra_field_values(local_extra, 0x5455)
    central_timestamps = _zip_extra_field_values(info.extra, 0x5455)
    if (
        len(local_timestamps) > 1
        or len(central_timestamps) > 1
        or bool(local_timestamps) != bool(central_timestamps)
    ):
        raise ValueError(f"ZIP timestamp metadata disagrees between headers: {label}")
    if local_timestamps and (
        _zip_extended_timestamp_mtime(local_timestamps[0], label=label, central=False)
        != _zip_extended_timestamp_mtime(
            central_timestamps[0], label=label, central=True
        )
    ):
        raise ValueError(f"ZIP timestamp metadata disagrees between headers: {label}")
    if (
        central_timestamps
        and len(central_timestamps[0]) > 5
        and local_timestamps[0] != central_timestamps[0]
    ):
        raise ValueError(f"ZIP timestamp metadata disagrees between headers: {label}")
    local_ntfs = _zip_extra_field_values(local_extra, 0x000A)
    central_ntfs = _zip_extra_field_values(info.extra, 0x000A)
    if len(local_ntfs) > 1 or len(central_ntfs) > 1:
        raise ValueError(
            f"ZIP NTFS timestamp metadata disagrees between headers: {label}"
        )
    local_ntfs_times = (
        _zip_ntfs_timestamps(local_ntfs[0], label=label) if local_ntfs else None
    )
    central_ntfs_times = (
        _zip_ntfs_timestamps(central_ntfs[0], label=label) if central_ntfs else None
    )
    if (
        local_ntfs_times is not None
        and central_ntfs_times is not None
        and local_ntfs_times != central_ntfs_times
    ):
        raise ValueError(
            f"ZIP NTFS timestamp metadata disagrees between headers: {label}"
        )
    local_jar_markers = _zip_extra_field_values(local_extra, 0xCAFE)
    central_jar_markers = _zip_extra_field_values(info.extra, 0xCAFE)
    if (
        len(local_jar_markers) > 1
        or len(central_jar_markers) > 1
        or local_jar_markers != central_jar_markers
        or any(local_jar_markers)
    ):
        raise ValueError(f"invalid ZIP JAR marker metadata: {label}")
    local_microsoft_padding = _zip_extra_field_values(local_extra, 0xA220)
    central_microsoft_padding = _zip_extra_field_values(info.extra, 0xA220)
    if len(local_microsoft_padding) > 1 or central_microsoft_padding:
        raise ValueError(f"invalid ZIP Microsoft padding metadata: {label}")
    if local_microsoft_padding:
        _validate_zip_microsoft_padding_extra(local_microsoft_padding[0], label=label)
    for metadata in (local_extra, info.extra):
        fields = _zip_extra_fields(metadata)
        if len({field_id for field_id, _ in fields}) != len(fields):
            raise ValueError(f"duplicate ZIP extra metadata is ambiguous: {label}")
        if any(field_id not in _SAFE_ZIP_EXTRA_FIELD_IDS for field_id, _ in fields):
            raise ValueError(f"unsupported ZIP extra metadata is ambiguous: {label}")

    if not flags & 0x08:
        compressed_size, uncompressed_size = _zip64_local_sizes(
            data[extra_start:payload_start],
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
        )
        if (
            crc != info.CRC
            or compressed_size != info.compress_size
            or uncompressed_size != info.file_size
        ):
            raise ValueError(
                f"ZIP local header disagrees with central directory: {label}"
            )
        end_offset = getattr(info, "_end_offset", None)
        if (
            not isinstance(end_offset, int)
            or payload_start + compressed_size != end_offset
        ):
            raise ValueError(
                f"ZIP local member boundary disagrees with central directory: {label}"
            )
        return (
            payload_start,
            payload_start + compressed_size,
            local_metadata_fingerprint,
        )

    if (
        crc == 0
        and compressed_size == 0
        and uncompressed_size
        in (
            0,
            info.file_size,
        )
    ):
        if local_zip64:
            raise ValueError(f"invalid ZIP data-descriptor local metadata: {label}")
    elif crc == 0 and compressed_size == 0xFFFFFFFF and uncompressed_size == 0xFFFFFFFF:
        if len(local_zip64) != 1 or len(local_zip64[0]) != 16 or any(local_zip64[0]):
            raise ValueError(f"invalid ZIP data-descriptor local metadata: {label}")
    else:
        raise ValueError(f"invalid ZIP data-descriptor local metadata: {label}")

    descriptor_start = payload_start + info.compress_size
    end_offset = getattr(info, "_end_offset", None)
    if descriptor_start > len(data) or not isinstance(end_offset, int):
        raise ValueError(f"invalid ZIP data descriptor for {label}")
    if data.startswith(b"PK\x07\x08", descriptor_start):
        descriptor_start += 4
    for size_width in (4, 8):
        descriptor_end = descriptor_start + 4 + (2 * size_width)
        if descriptor_end != end_offset or descriptor_end > len(data):
            continue
        descriptor_crc = int.from_bytes(
            data[descriptor_start : descriptor_start + 4], "little"
        )
        descriptor_compressed = int.from_bytes(
            data[descriptor_start + 4 : descriptor_start + 4 + size_width],
            "little",
        )
        descriptor_uncompressed = int.from_bytes(
            data[descriptor_start + 4 + size_width : descriptor_end],
            "little",
        )
        if (
            descriptor_crc == info.CRC
            and descriptor_compressed == info.compress_size
            and descriptor_uncompressed == info.file_size
        ):
            return (
                payload_start,
                payload_start + info.compress_size,
                local_metadata_fingerprint,
            )
    raise ValueError(f"ZIP data descriptor disagrees with central directory: {label}")


def _validate_zip_compressed_payload(
    payload: bytes,
    info: zipfile.ZipInfo,
) -> None:
    """
    Require one ZIP member payload to contain exactly one compressed stream.

    The implementation uses ``payload`` and ``info`` to require one ZIP member
    payload to contain exactly one compressed stream. Every required invariant
    is checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        payload: Bounded byte sequence supplied as payload.
        info: Info object whose ``CRC``, ``compress_type``, ``file_size``, and
            ``filename`` state is read while performing one ZIP member payload
            to contain exactly one compressed stream.

    Raises:
        ValueError: If ZIP compression method does not provide bounded decoder
            allocations: ``label``; invalid or trailing ZIP compressed data:
            ``label``; or ZIP compressed data disagrees with metadata:
            ``label``.
        BaseException: If a delegated failure occurs while the function attempts
            to require one ZIP member payload to contain exactly one compressed
            stream.
    """

    label = _archive_path_label(info.filename)
    if info.compress_type in {zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}:
        raise ValueError(
            "ZIP compression method does not provide bounded decoder allocations: "
            f"{label}"
        )
    try:
        if info.compress_type == zipfile.ZIP_STORED:
            expanded = payload
        elif info.compress_type == zipfile.ZIP_DEFLATED:
            decompressor = zlib.decompressobj(-15)
            expanded = decompressor.decompress(payload, info.file_size + 1)
            if (
                not decompressor.eof
                or decompressor.unused_data
                or decompressor.unconsumed_tail
            ):
                raise ValueError
        else:
            raise ValueError
    except (EOFError, OSError, ValueError, lzma.LZMAError) as exc:
        raise ValueError(f"invalid or trailing ZIP compressed data: {label}") from exc
    if len(expanded) != info.file_size or zlib.crc32(expanded) != info.CRC:
        raise ValueError(f"ZIP compressed data disagrees with metadata: {label}")


def _zip_member_metadata_fingerprint(info: zipfile.ZipInfo) -> tuple[Any, ...]:
    """
    Return extraction-relevant metadata for duplicate-member comparison.

    The implementation uses ``info`` to produce extraction-relevant metadata for
    duplicate-member comparison.

    Args:
        info: Info object whose ``comment``, ``compress_type``,
            ``create_system``, ``create_version``, and ``date_time`` state is
            read while performing extraction-relevant metadata for
            duplicate-member comparison.

    Returns:
        A tuple containing ``date time``, ``compress type``, ``comment``,
        ``extra``, ``create system``, ``create version``, ``extract version``,
        ``reserved``, ``flag bits``, ``volume``, ``internal attr``, and
        ``external attr`` in that order.
    """

    return (
        info.date_time,
        info.compress_type,
        info.comment,
        info.extra,
        info.create_system,
        info.create_version,
        info.extract_version,
        info.reserved,
        info.flag_bits,
        info.volume,
        info.internal_attr,
        info.external_attr,
    )


# The Windows portability predicate now lives in the shared member-name
# policy so it no longer depends on this default-off sanitizer.  The alias
# keeps the established private spelling for this module's own call sites.
_is_unsafe_portable_component = is_unsafe_portable_component
_WINDOWS_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")
_PORTABLE_COMPONENT_ALIAS_MARKER = "~nvdebug~"
_WINDOWS_ILLEGAL_COMPONENT_CHARS = frozenset('<>:"|?*')


def _portable_component_alias(component: str) -> str:
    """
    Return a deterministic portable alias for one valid POSIX component.

    Core archive safety has already rejected traversal, separators, control
    characters, and non-printable text before this helper runs. This function
    handles only the narrower Windows-portability tier. A readable stem is
    retained, forbidden characters and terminal dot/space runs are neutralized,
    and a digest suffix prevents ordinary field names from collapsing together.
    The caller still performs archive-wide collision and case-fold checks.

    Args:
        component: One non-empty, non-dot POSIX member-name component.

    Returns:
        The original component when portable, otherwise a deterministic alias
        bounded to both 255 UTF-8 bytes and 255 UTF-16 code units.

    Raises:
        ValueError: If a portable bounded alias cannot be constructed.
    """

    if not _is_unsafe_portable_component(component):
        return component
    encoded = component.encode("utf-8", errors="surrogateescape")
    digest = hashlib.sha256(encoded).hexdigest()[:20]
    suffix = f"{_PORTABLE_COMPONENT_ALIAS_MARKER}{digest}"
    stem = "".join(
        "_" if character in _WINDOWS_ILLEGAL_COMPONENT_CHARS else character
        for character in component
    ).rstrip(" .")
    if not stem:
        stem = "member"
    maximum_units = 255 - len(suffix.encode("utf-16-le")) // 2
    maximum_bytes = 255 - len(suffix.encode("utf-8"))
    while stem and (
        len(stem.encode("utf-8", errors="surrogateescape")) > maximum_bytes
        or len(stem.encode("utf-16-le", errors="surrogatepass")) // 2 > maximum_units
    ):
        stem = stem[:-1]
    candidate = f"{stem or 'member'}{suffix}"
    if _is_unsafe_portable_component(candidate):
        candidate = f"nvdebug-{hashlib.sha256(encoded).hexdigest()}"
    if _is_unsafe_portable_component(candidate):
        raise ValueError("unsafe archive member path")
    return candidate


def _validate_member_name(
    name: str,
    *,
    directory: bool,
    max_path_depth: int,
    allow_root_directory: bool = False,
    canonicalize_portable: bool = False,
) -> str:
    """
    Validate member name.

    Bound allocation before splitting. PAX paths can be millions of tiny
    components even when their encoded header stays below the byte ceiling; at
    most ``max_path_depth + 1`` strings are created below.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.
        directory: filesystem location used as the directory for this operation.
        max_path_depth: Upper bound enforced for max path depth; the consuming
            boundary rejects or truncates values that exceed it.
        allow_root_directory: filesystem location used as the allow root
            directory for this operation.
        canonicalize_portable: Whether valid POSIX-only components are replaced
            by deterministic operator-facing aliases.

    Returns:
        The validated ``normalized``.

    Raises:
        ValueError: If unsafe archive member path.
    """
    stripped_name = name.rstrip("/")
    if (
        not name
        or name.startswith("/")
        or _WINDOWS_DRIVE_PREFIX_RE.match(stripped_name) is not None
        # Shared character policy: NUL, every other C0 control, DEL, any
        # non-printable such as a bidirectional override, and the literal
        # backslash.  Keeping this producer a superset of the extractor is
        # what stops a name admitted here from failing on extraction.
        or has_unsafe_member_characters(name)
        # Bound allocation before splitting.  PAX paths can be millions of
        # tiny components even when their encoded header stays below the byte
        # ceiling; at most ``max_path_depth + 1`` strings are created below.
        or name.count("/") > max_path_depth
        or (
            not directory
            and (
                name.endswith("/")
                or stripped_name == "."
                or stripped_name.endswith("/.")
            )
        )
    ):
        raise ValueError("unsafe archive member path")
    raw_parts = name.split("/")
    if any(part == ".." for part in raw_parts):
        raise ValueError("unsafe archive member path")
    meaningful_parts = [part for part in raw_parts if part not in ("", ".")]
    if (
        len([part for part in raw_parts if part]) > max_path_depth
        or len(meaningful_parts) > max_path_depth
        or (not meaningful_parts and (not directory or not allow_root_directory))
    ):
        raise ValueError("unsafe archive member path")
    if canonicalize_portable:
        meaningful_parts = [
            _portable_component_alias(part) for part in meaningful_parts
        ]
    elif any(_is_unsafe_portable_component(part) for part in meaningful_parts):
        raise ValueError("unsafe archive member path")
    normalized = (
        name
        if len(meaningful_parts) == 1 and meaningful_parts[0] == name
        else "/".join(meaningful_parts)
    )
    if (
        len(normalized.encode("utf-8", errors="surrogateescape"))
        > _MAX_PORTABLE_ARCHIVE_PATH_BYTES
    ):
        raise ValueError("unsafe archive member path")
    return normalized


_DISTRIBUTABLE_TAR_LINK_TYPES = frozenset({tarfile.SYMTYPE, tarfile.LNKTYPE})
_TAR_PAX_MAPPING_ENTRY_STATE_BYTES = 128
_TAR_PATH_NODE_STATE_BYTES = 768
_ZIP_PATH_NODE_STATE_BYTES = 768


def _archive_path_label(value: str) -> str:
    """
    Return a bounded error label for an adversary-controlled archive path.

    The implementation uses ``value`` to produce a bounded error label for an
    adversary-controlled archive path.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        The canonical archive path label.
    """

    if len(value) <= 160:
        return repr(value)
    return f"<archive path: {len(value)} characters>"


def _portable_path_key(value: str) -> str:
    """
    Return a Windows-case-insensitive collision key for a normalized path.

    After applying local validation, the function forwards ``value`` to ``join``
    and preserves its return and exception contract.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        The canonical portable path key text.
    """

    return "/".join(component.casefold() for component in value.split("/"))


@dataclass(frozen=True)
class _TarLinkSpec:
    """
    One normalized TAR link edge and its extraction semantics.

    The immutable record keeps ``target``, ``is_hardlink``, and
    ``requires_directory`` together so consumers observe one TAR link spec
    state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        target: Canonical text used as target.
        is_hardlink: Whether hardlink applies to this record.
        requires_directory: Whether requires directory applies to this record.
    """

    target: str
    is_hardlink: bool
    requires_directory: bool


@dataclass
class _TarPathNode:
    """
    One shared component in the normalized TAR member inventory.

    The coherent record keeps ``children`` and ``member_types`` together so
    consumers observe one TAR path node state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        children: Mapping that retains the children fields for this record.
        member_types: Collection of member types entries retained by this
            record.
    """

    children: dict[str, _TarPathNode] = field(default_factory=dict)
    member_types: set[str] = field(default_factory=set)

    @property
    def is_directory(self) -> bool:
        """
        Return whether ``the current value`` is directory.

        Each access computes the value from ``children`` and ``member_types`` on
        the current instance; the derived view is not stored as independent
        state.

        Returns:
            Whether ``the current value`` is directory.
        """
        return bool(self.children) or self.member_types == {"directory"}

    @property
    def is_link(self) -> bool:
        """
        Return whether ``the current value`` is link.

        Each access computes the value from ``member_types`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            Whether ``the current value`` is link.
        """
        return "link" in self.member_types


@dataclass
class _ZipPathNode:
    """
    One case-insensitive component in the ZIP extraction path graph.

    The coherent record keeps ``children`` and ``terminal_type`` together so
    consumers observe one ZIP path node state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        children: Mapping that retains the children fields for this record.
        terminal_type: Canonical text used as terminal type.
    """

    children: dict[str, _ZipPathNode] = field(default_factory=dict)
    terminal_type: str | None = None


def _register_zip_member_path(
    root: _ZipPathNode,
    normalized_name: str,
    *,
    directory: bool,
    path_nodes: int,
    tracked_path_bytes: int,
    limits: BundleSanitizationLimits,
) -> tuple[int, int]:
    """
    Register one ZIP path without allocating depth-many prefix strings.

    The implementation uses ``root``, ``normalized_name``, ``directory``,
    ``path_nodes``, and ``tracked_path_bytes`` to register one ZIP path without
    allocating depth-many prefix strings. If the function cannot register one
    ZIP path without allocating depth-many prefix strings, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        root: filesystem location used as the root for this operation.
        normalized_name: Stable normalized name used for lookup and
            operator-facing diagnostics.
        directory: filesystem location used as the directory for this operation.
        path_nodes: Numeric path nodes used while the operation performs bounded
            accounting.
        tracked_path_bytes: Numeric tracked path bytes used while the operation
            performs bounded accounting.
        limits: Limits governing register one ZIP path without allocating
            depth-many prefix strings.

    Returns:
        A tuple containing ``path nodes`` and ``tracked path bytes`` in that
        order.

    Raises:
        ValueError: If ZIP regular member conflicts with a descendant path:
            ``label``; archive path node count exceeds
            ``max_archive_path_nodes``; or archive tracked path metadata exceeds
            ``max_archive_tracked_path_bytes`` bytes.
    """

    label = _archive_path_label(normalized_name)
    node = root
    for component in normalized_name.split("/"):
        if node.terminal_type == "file":
            raise ValueError(
                f"ZIP regular member conflicts with a descendant path: {label}"
            )
        child = node.children.get(component)
        if child is None:
            path_nodes += 1
            if path_nodes > limits.max_archive_path_nodes:
                raise ValueError(
                    f"archive path node count exceeds {limits.max_archive_path_nodes}"
                )
            tracked_path_bytes += (
                3 * _encoded_metadata_size(component) + _ZIP_PATH_NODE_STATE_BYTES
            )
            if tracked_path_bytes > limits.max_archive_tracked_path_bytes:
                raise ValueError(
                    "archive tracked path metadata exceeds "
                    f"{limits.max_archive_tracked_path_bytes} bytes"
                )
            child = _ZipPathNode()
            node.children[component] = child
        node = child
    terminal_type = "directory" if directory else "file"
    if (terminal_type == "file" and node.children) or (
        node.terminal_type is not None and node.terminal_type != terminal_type
    ):
        raise ValueError(
            f"ZIP regular member conflicts with a descendant path: {label}"
        )
    node.terminal_type = terminal_type
    return path_nodes, tracked_path_bytes


def _encoded_metadata_size(value: str) -> int:
    """
    Return the encoded metadata size.

    After applying local validation, the function forwards ``value`` to ``len``
    and preserves its return and exception contract.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        The numeric encoded metadata size.
    """
    return len(value.encode("utf-8", errors="surrogateescape"))


def _tar_member_metadata_size(member: tarfile.TarInfo) -> int:
    """
    Account for parsed TAR metadata retained while validating the graph.

    Python copies the PAX mapping onto every TarInfo, including inherited global
    fields. Charge retained mapping state as well as string bytes so a small
    global header cannot multiply into hundreds of MiB of dicts.

    Args:
        member: Member object whose ``gname``, ``items``, ``linkname``,
            ``name``, and ``pax_headers`` state is read while performing account
            for parsed TAR metadata retained while validating the graph.

    Returns:
        The validated ``size``.
    """

    size = sum(
        _encoded_metadata_size(value)
        for value in (member.name, member.linkname, member.uname, member.gname)
    )
    for key, value in member.pax_headers.items():
        size += _encoded_metadata_size(key) + _encoded_metadata_size(value)
    # Python copies the PAX mapping onto every TarInfo, including inherited
    # global fields.  Charge retained mapping state as well as string bytes so
    # a small global header cannot multiply into hundreds of MiB of dicts.
    size += len(member.pax_headers) * _TAR_PAX_MAPPING_ENTRY_STATE_BYTES
    return size


def _bounded_sanitizer_tarinfo_type(
    limits: BundleSanitizationLimits,
) -> type[tarfile.TarInfo]:
    """
    Reject oversized extension headers before ``tarfile`` allocates them.

    The implementation uses ``limits`` to reject oversized extension headers
    before ``tarfile`` allocates them. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        limits: Limits governing oversized extension headers before ``tarfile``
            allocates them.

    Returns:
        The validated ``_BoundedSanitizerTarInfo``.
    """

    extension_metadata_size = 0
    extension_header_count = 0
    extension_chain_depth = 0
    extension_chain_fields: set[bytes] = set()
    pax_record_count = 0

    class _BoundedSanitizerTarInfo(tarfile.TarInfo):
        """
        Implement the bounded sanitizer TAR info boundary used by the NVDebug runtime.

        Implement the bounded sanitizer TAR info boundary used by the NVDebug
        runtime.

        The type coordinates ``_scan_pax_records``, ``_proc_pax``,
        ``_proc_member``, ``_proc_gnusparse_00``, and ``_proc_gnusparse_01`` and
        retains the state those operations share between calls. Resource
        ownership remains inside the instance until the matching close, exit, or
        cleanup operation completes.
        """

        def _scan_pax_records(
            self,
            archive: tarfile.TarFile,
        ) -> tuple[int, frozenset[bytes]]:
            """
            Validate framed PAX records before the stdlib parses them.

            The implementation uses ``archive`` to validate framed PAX records
            before the stdlib parses them. Every required invariant is checked
            before a successful value is returned; invalid input follows the
            function's explicit exception path. Filesystem effects remain
            confined to the caller-selected paths and the owning resource
            lifecycle.

            Args:
                archive: Archive object whose ``fileobj``, ``read``, ``seek``,
                    and ``tell`` state is read while performing framed PAX
                    records before the stdlib parses them.

            Returns:
                A tuple containing ``records`` and ``frozenset`` in that order.

            Raises:
                ValueError: If invalid TAR PAX metadata framing; GNU sparse TAR
                    metadata is not distributable; ambiguous duplicate TAR PAX
                    field; or archive PAX record count exceeds
                    ``max_archive_pax_records_per_header`` per header; or
                    another input invariant is violated.
            """

            start = archive.fileobj.tell()
            raw = archive.fileobj.read(self._block(self.size))
            archive.fileobj.seek(start)
            payload_size = min(self.size, len(raw))
            position = 0
            records = 0
            keywords: set[bytes] = set()
            while position < payload_size and raw[position] != 0:
                space = raw.find(b" ", position, min(position + 21, payload_size))
                if space < 0:
                    raise ValueError("invalid TAR PAX metadata framing")
                length_bytes = raw[position:space]
                if not length_bytes.isdigit():
                    raise ValueError("invalid TAR PAX metadata framing")
                length = int(length_bytes)
                record_end = position + length
                if (
                    length < 5
                    or record_end > payload_size
                    or raw[record_end - 1] != 0x0A
                ):
                    raise ValueError("invalid TAR PAX metadata framing")
                keyword_end = raw.find(b"=", space + 1, record_end - 1)
                if keyword_end < 0:
                    raise ValueError("invalid TAR PAX metadata framing")
                keyword = raw[space + 1 : keyword_end]
                if not keyword or keyword.startswith(b"GNU.sparse."):
                    raise ValueError("GNU sparse TAR metadata is not distributable")
                if keyword in keywords:
                    raise ValueError("ambiguous duplicate TAR PAX field")
                keywords.add(keyword)
                records += 1
                if records > limits.max_archive_pax_records_per_header:
                    raise ValueError(
                        "archive PAX record count exceeds "
                        f"{limits.max_archive_pax_records_per_header} per header"
                    )
                if self.type == tarfile.XGLTYPE and (
                    records > limits.max_archive_global_pax_records
                ):
                    raise ValueError(
                        "archive global PAX record count exceeds "
                        f"{limits.max_archive_global_pax_records}"
                    )
                if pax_record_count + records > limits.max_archive_pax_records:
                    raise ValueError(
                        "archive PAX record count exceeds "
                        f"{limits.max_archive_pax_records}"
                    )
                position = record_end
            return records, frozenset(keywords)

        def _proc_pax(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
            """
            Return the proc PAX.

            After applying local validation, the function forwards ``archive``
            to ``_proc_pax`` and preserves its return and exception contract.

            Args:
                archive: Archive consumed while the function attempts to produce
                    the proc PAX.

            Returns:
                A ``TarInfo`` representing proc PAX.

            Raises:
                ValueError: If archive PAX record count exceeds
                    ``max_archive_pax_records_per_header`` per header; archive
                    global PAX record count exceeds
                    ``max_archive_global_pax_records``; or archive PAX record
                    count exceeds ``max_archive_pax_records``.
            """
            nonlocal pax_record_count
            records, _ = self._scan_pax_records(archive)
            if records > limits.max_archive_pax_records_per_header:
                raise ValueError(
                    "archive PAX record count exceeds "
                    f"{limits.max_archive_pax_records_per_header} per header"
                )
            if self.type == tarfile.XGLTYPE and (
                records > limits.max_archive_global_pax_records
            ):
                raise ValueError(
                    "archive global PAX record count exceeds "
                    f"{limits.max_archive_global_pax_records}"
                )
            pax_record_count += records
            if pax_record_count > limits.max_archive_pax_records:
                raise ValueError(
                    f"archive PAX record count exceeds {limits.max_archive_pax_records}"
                )
            return super()._proc_pax(archive)

        def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
            """
            Process one archive member through the bounded parser.

            The implementation uses ``archive`` to process one archive member
            through the bounded parser. Terminal status is emitted only after
            one archive member through the bounded parser and its owned cleanup
            have completed. If the function cannot process one archive member
            through the bounded parser, its exception reaches the caller instead
            of being converted into a successful result. Cleanup in the
            ``finally`` path runs for successful, failed, and cancelled
            execution.

            Args:
                archive: Archive consumed while the function attempts to process
                    one archive member through the bounded parser.

            Returns:
                A ``TarInfo`` representing proc member.

            Raises:
                ValueError: If GNU sparse TAR members are not distributable;
                    archive extension header count exceeds
                    ``max_archive_extension_headers``; archive extension header
                    chain exceeds ``max_archive_extension_chain_depth``; or
                    archive extension metadata exceeds
                    ``max_archive_metadata_member_bytes`` bytes; or another
                    input invariant is violated.
            """
            nonlocal extension_chain_fields
            nonlocal extension_chain_depth
            nonlocal extension_header_count
            nonlocal extension_metadata_size
            if self.type == tarfile.GNUTYPE_SPARSE:
                raise ValueError("GNU sparse TAR members are not distributable")
            is_extension = self.type in {
                tarfile.GNUTYPE_LONGNAME,
                tarfile.GNUTYPE_LONGLINK,
                tarfile.XHDTYPE,
                tarfile.XGLTYPE,
                tarfile.SOLARIS_XHDTYPE,
            }
            if not is_extension:
                return super()._proc_member(archive)

            extension_header_count += 1
            if extension_header_count > limits.max_archive_extension_headers:
                raise ValueError(
                    "archive extension header count exceeds "
                    f"{limits.max_archive_extension_headers}"
                )
            extension_chain_depth += 1
            if extension_chain_depth > limits.max_archive_extension_chain_depth:
                raise ValueError(
                    "archive extension header chain exceeds "
                    f"{limits.max_archive_extension_chain_depth}"
                )
            fields = frozenset()
            registered_fields = False
            try:
                if (
                    self.size < 0
                    or self.size > limits.max_archive_metadata_member_bytes
                ):
                    raise ValueError(
                        "archive extension metadata exceeds "
                        f"{limits.max_archive_metadata_member_bytes} bytes"
                    )
                extension_metadata_size += self.size
                if extension_metadata_size > limits.max_archive_metadata_bytes:
                    raise ValueError(
                        "archive extension metadata exceeds "
                        f"{limits.max_archive_metadata_bytes} bytes"
                    )
                if self.type == tarfile.GNUTYPE_LONGNAME:
                    fields = frozenset({b"path"})
                elif self.type == tarfile.GNUTYPE_LONGLINK:
                    fields = frozenset({b"linkpath"})
                else:
                    _, fields = self._scan_pax_records(archive)
                if extension_chain_fields & fields:
                    raise ValueError("ambiguous TAR extension header chain")
                extension_chain_fields.update(fields)
                registered_fields = True
                return super()._proc_member(archive)
            finally:
                if registered_fields:
                    extension_chain_fields.difference_update(fields)
                extension_chain_depth -= 1

        def _proc_gnusparse_00(self, member: Any, raw_headers: Any) -> None:
            """
            Reject unsupported GNU sparse 0.0 metadata.

            The implementation uses ``member`` and ``raw_headers`` to reject
            unsupported GNU sparse 0.0 metadata. Every required invariant is
            checked before a successful value is returned; invalid input follows
            the function's explicit exception path.

            Args:
                member: Member consumed while the function attempts to reject
                    unsupported GNU sparse 0.0 metadata.
                raw_headers: Raw headers consumed while the function attempts to
                    reject unsupported GNU sparse 0.0 metadata.

            Raises:
                ValueError: If GNU sparse TAR metadata is not distributable.
            """
            raise ValueError("GNU sparse TAR metadata is not distributable")

        def _proc_gnusparse_01(self, member: Any, pax_headers: Any) -> None:
            """
            Reject unsupported GNU sparse 0.1 metadata.

            The implementation uses ``member`` and ``pax_headers`` to reject
            unsupported GNU sparse 0.1 metadata. Every required invariant is
            checked before a successful value is returned; invalid input follows
            the function's explicit exception path.

            Args:
                member: Member consumed while the function attempts to reject
                    unsupported GNU sparse 0.1 metadata.
                pax_headers: PAX headers consumed while the function attempts to
                    reject unsupported GNU sparse 0.1 metadata.

            Raises:
                ValueError: If GNU sparse TAR metadata is not distributable.
            """
            raise ValueError("GNU sparse TAR metadata is not distributable")

        def _proc_gnusparse_10(
            self,
            member: Any,
            pax_headers: Any,
            archive: tarfile.TarFile,
        ) -> None:
            """
            Reject unsupported GNU sparse 1.0 metadata.

            The implementation uses ``member``, ``pax_headers``, and ``archive``
            to reject unsupported GNU sparse 1.0 metadata. Every required
            invariant is checked before a successful value is returned; invalid
            input follows the function's explicit exception path.

            Args:
                member: Member consumed while the function attempts to reject
                    unsupported GNU sparse 1.0 metadata.
                pax_headers: PAX headers consumed while the function attempts to
                    reject unsupported GNU sparse 1.0 metadata.
                archive: Archive consumed while the function attempts to reject
                    unsupported GNU sparse 1.0 metadata.

            Raises:
                ValueError: If GNU sparse TAR metadata is not distributable.
            """
            raise ValueError("GNU sparse TAR metadata is not distributable")

    return _BoundedSanitizerTarInfo


def _tar_member_type(member: tarfile.TarInfo) -> str:
    """
    Return the TAR member type.

    The implementation uses ``member`` to produce the TAR member type.

    Args:
        member: Member object whose ``isdir``, ``isfile``, and ``type`` state is
            read while performing TAR member type.

    Returns:
        The canonical TAR member type text.
    """
    if member.type in _DISTRIBUTABLE_TAR_LINK_TYPES:
        return "link"
    if member.isfile():
        return "file"
    if member.isdir():
        return "directory"
    return "special"


def _build_tar_path_trie(
    normalized_members: list[tuple[tarfile.TarInfo, str]],
) -> _TarPathNode:
    """
    Build the bounded shared member inventory and reject path conflicts.

    The implementation uses ``normalized_members`` to build the bounded shared
    member inventory and reject path conflicts. If the function cannot build the
    bounded shared member inventory and reject path conflicts, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        normalized_members: Entries supplied as ``normalized_members`` without
            transferring container ownership.

    Returns:
        The validated ``root``.

    Raises:
        ValueError: If the supplied input cannot be used to build the bounded
            shared member inventory and reject path conflicts.
    """

    root = _TarPathNode()
    for member, normalized_name in normalized_members:
        node = root
        for component in normalized_name.split("/") if normalized_name else ():
            node = node.children.setdefault(component, _TarPathNode())
        node.member_types.add(_tar_member_type(member))

    pending: list[tuple[str, _TarPathNode]] = [("", root)]
    while pending:
        path, node = pending.pop()
        if len(node.member_types) > 1:
            raise ValueError(
                f"conflicting duplicate TAR member: {_archive_path_label(path)}"
            )
        if node.children and node.member_types - {"directory"}:
            if node.is_link:
                raise ValueError(
                    "TAR member is nested beneath a link member: "
                    f"{_archive_path_label(path)}"
                )
            raise ValueError(
                "TAR member is nested beneath a non-directory member: "
                f"{_archive_path_label(path)}"
            )
        for component, child in node.children.items():
            child_path = f"{path}/{component}" if path else component
            pending.append((child_path, child))
    return root


def _passes_through_link(normalized_name: str, path_trie: _TarPathNode) -> bool:
    """
    Return True when any ancestor of ``normalized_name`` is a declared link.

    A link member replaces a path component, so anything the archive later
    declares beneath that component is resolved through the link at extraction
    time rather than through the directory the name implies.

    Args:
        normalized_name: Stable normalized name used for lookup and
            operator-facing diagnostics.
        path_trie: filesystem location used as the path trie for this operation.

    Returns:
        Whether the true when any ancestor of ``normalized_name`` is a declared
        link operation succeeds.
    """

    if not normalized_name:
        return False
    node = path_trie
    for component in normalized_name.split("/")[:-1]:
        child = node.children.get(component)
        if child is None:
            return False
        node = child
        if node.is_link:
            return True
    return False


def _validate_link_target(
    member_name: str,
    link_target: str,
    *,
    is_symlink: bool,
    path_trie: _TarPathNode,
    max_path_depth: int,
) -> tuple[str, bool]:
    """
    Return the archive-relative target of a distributable TAR link member.

    Collector artifacts such as SOS reports legitimately contain links, so a
    link is not rejected merely for being a link. It is admitted only when the
    target provably stays inside the archive: a symbolic link resolves against
    its own directory, while a hard link names an archive-root-relative member.
    Absolute, traversing, drive-qualified, NUL-bearing, and empty targets stay
    non-distributable so no link chain can redirect extraction outside the root.

    Args:
        member_name: Stable member name used for lookup and operator-facing
            diagnostics.
        link_target: Text supplied as link target in the format accepted by this
            function.
        is_symlink: Whether is symlink is enabled or required for this
            operation.
        path_trie: filesystem location used as the path trie for this operation.
        max_path_depth: Upper bound enforced for max path depth; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        A tuple containing ``join`` and ``requires directory`` in that order.

    Raises:
        ValueError: If the supplied input cannot be used to produce the
            archive-relative target of a distributable TAR link member.
    """

    if not link_target:
        raise ValueError(
            f"TAR link member has no target: {_archive_path_label(member_name)}"
        )
    if link_target.startswith("/") or "\x00" in link_target or "\\" in link_target:
        raise ValueError(
            f"unsafe TAR link target for {_archive_path_label(member_name)}"
        )

    if link_target.count("/") > max_path_depth:
        raise ValueError(
            f"unsafe TAR link target for {_archive_path_label(member_name)}"
        )
    target_parts = link_target.split("/")
    stripped_target = link_target.rstrip("/")
    requires_directory = link_target.endswith("/") or (
        stripped_target == "." or stripped_target.endswith("/.")
    )
    meaningful_target_parts = [part for part in target_parts if part not in ("", ".")]
    if len([part for part in target_parts if part]) > max_path_depth or any(
        part != ".." and _is_unsafe_portable_component(part)
        for part in meaningful_target_parts
    ):
        raise ValueError(
            f"unsafe TAR link target for {_archive_path_label(member_name)}"
        )

    member_parts = member_name.split("/")
    resolved_parts = member_parts[:-1] if is_symlink else []
    trie_nodes: list[_TarPathNode | None] = []
    trie_node: _TarPathNode | None = path_trie
    for component in resolved_parts:
        trie_node = trie_node.children.get(component) if trie_node is not None else None
        trie_nodes.append(trie_node)
    remaining_components = sum(component not in ("", ".") for component in target_parts)
    for component in target_parts:
        if component in ("", "."):
            continue
        remaining_components -= 1
        if component == "..":
            if not resolved_parts:
                raise ValueError(
                    f"unsafe TAR link target for {_archive_path_label(member_name)}"
                )
            resolved_parts.pop()
            trie_nodes.pop()
            continue
        resolved_parts.append(component)
        parent_node = trie_nodes[-1] if trie_nodes else path_trie
        trie_node = (
            parent_node.children.get(component) if parent_node is not None else None
        )
        trie_nodes.append(trie_node)
        if trie_node is not None and trie_node.is_link and remaining_components:
            raise ValueError(
                f"unsafe TAR link target for {_archive_path_label(member_name)}"
            )
        if remaining_components and (trie_node is None or not trie_node.is_directory):
            raise ValueError(
                f"unresolvable TAR link target for {_archive_path_label(member_name)}"
            )
    if not resolved_parts or len(resolved_parts) > max_path_depth:
        raise ValueError(
            f"unsafe TAR link target for {_archive_path_label(member_name)}"
        )
    if (
        is_symlink
        and len(resolved_parts) < len(member_parts)
        and member_parts[: len(resolved_parts)] == resolved_parts
    ):
        raise ValueError(
            f"cyclic TAR directory link target for {_archive_path_label(member_name)}"
        )
    return "/".join(resolved_parts), requires_directory


def _validate_tar_link_graph(
    link_specs: dict[str, _TarLinkSpec],
    terminal_types: dict[str, set[str]],
) -> dict[str, tuple[str, str]]:
    """
    Require every TAR link to resolve to one safe archive-owned terminal.

    The implementation uses ``link_specs`` and ``terminal_types`` to require
    every TAR link to resolve to one safe archive-owned terminal. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        link_specs: Mapping supplying fields for every TAR link to resolve to
            one safe archive-owned terminal.
        terminal_types: Mapping supplying fields for every TAR link to resolve
            to one safe archive-owned terminal.

    Returns:
        The validated ``resolved``.

    Raises:
        ValueError: If the supplied input cannot be used to require every TAR
            link to resolve to one safe archive-owned terminal.
    """

    ambiguous_paths = link_specs.keys() & terminal_types.keys()
    if ambiguous_paths:
        path = min(ambiguous_paths)
        raise ValueError(
            f"conflicting duplicate TAR member: {_archive_path_label(path)}"
        )

    for source, spec in link_specs.items():
        if spec.is_hardlink and (
            spec.target in link_specs
            or (
                spec.target in terminal_types
                and terminal_types[spec.target] != {"file"}
            )
            or spec.requires_directory
        ):
            raise ValueError(
                "TAR hard link target is not a regular file: "
                f"{_archive_path_label(source)}"
            )

    resolved: dict[str, tuple[str, str]] = {}
    for source in link_specs:
        current = source
        trail: list[str] = []
        trail_positions: dict[str, int] = {}
        while current in link_specs and current not in resolved:
            if current in trail_positions:
                raise ValueError(
                    f"TAR link chain contains a cycle: {_archive_path_label(source)}"
                )
            trail_positions[current] = len(trail)
            trail.append(current)
            current = link_specs[current].target

        terminal = resolved.get(current)
        if terminal is None:
            types = terminal_types.get(current, set())
            if len(types) != 1 or "special" in types:
                if not types:
                    raise ValueError(
                        f"TAR link target is dangling: {_archive_path_label(source)}"
                    )
                raise ValueError(
                    "TAR link target has ambiguous member type: "
                    f"{_archive_path_label(source)}"
                )
            terminal = (current, next(iter(types)))

        for link_name in trail:
            if link_specs[link_name].requires_directory and terminal[1] != "directory":
                raise ValueError(
                    "TAR link target is not a directory: "
                    f"{_archive_path_label(link_name)}"
                )
            if link_specs[link_name].is_hardlink and terminal[1] != "file":
                raise ValueError(
                    "TAR hard link target is not a regular file: "
                    f"{_archive_path_label(link_name)}"
                )
            resolved[link_name] = terminal
    return resolved


def _validate_tar_directory_link_cycles(
    link_specs: dict[str, _TarLinkSpec],
    resolved: dict[str, tuple[str, str]],
) -> None:
    """
    Reject directory-link reachability cycles without filesystem traversal.

    The implementation uses ``link_specs`` and ``resolved`` to reject
    directory-link reachability cycles without filesystem traversal. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        link_specs: Mapping supplying fields for directory-link reachability
            cycles without filesystem traversal.
        resolved: Mapping supplying fields for directory-link reachability
            cycles without filesystem traversal.

    Raises:
        ValueError: If TAR directory link graph contains a cycle.
    """

    link_edges: list[tuple[str, str]] = []
    relevant_directories = {""}
    for source, spec in link_specs.items():
        terminal_path, terminal_type = resolved[source]
        if spec.is_hardlink or terminal_type != "directory":
            continue
        source_parent = source.rpartition("/")[0]
        link_edges.append((source_parent, terminal_path))
        relevant_directories.update((source_parent, terminal_path))

    adjacency: dict[str, set[str]] = {
        directory: set() for directory in relevant_directories
    }
    indegree = dict.fromkeys(relevant_directories, 0)
    for directory in relevant_directories - {""}:
        parts = directory.split("/")
        parent = ""
        for end in range(len(parts) - 1, 0, -1):
            candidate = "/".join(parts[:end])
            if candidate in relevant_directories:
                parent = candidate
                break
        if directory not in adjacency[parent]:
            adjacency[parent].add(directory)
            indegree[directory] += 1
    for parent, target in link_edges:
        if target not in adjacency[parent]:
            adjacency[parent].add(target)
            indegree[target] += 1

    ready = [node for node, degree in indegree.items() if degree == 0]
    visited = 0
    while ready:
        node = ready.pop()
        visited += 1
        for child in adjacency[node]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if visited != len(indegree):
        raise ValueError("TAR directory link graph contains a cycle")


def _check_compression_ratio(
    compressed_bytes: int,
    expanded_bytes: int,
    *,
    label: str,
    limits: BundleSanitizationLimits,
) -> None:
    """
    Check compression ratio.

    The implementation uses ``compressed_bytes``, ``expanded_bytes``, ``label``,
    and ``limits`` to check compression ratio. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        compressed_bytes: Numeric compressed bytes used while the operation
            performs bounded accounting.
        expanded_bytes: Numeric expanded bytes used while the operation performs
            bounded accounting.
        label: Text supplied as label in the format accepted by this function.
        limits: Limits governing compression ratio.

    Raises:
        ValueError: If ``label`` compression ratio ``ratio``:1 exceeds
            ``max_compression_ratio``:1.
    """
    ratio = expanded_bytes / max(compressed_bytes, 1)
    if ratio > limits.max_compression_ratio:
        raise ValueError(
            f"{label} compression ratio {ratio:.1f}:1 exceeds "
            f"{limits.max_compression_ratio:.1f}:1"
        )


def _enabled(sanitizer: Any) -> bool:
    """
    Return whether enabled for the current input and state.

    After applying local validation, the function forwards ``sanitizer`` to
    ``bool`` and preserves its return and exception contract.

    Args:
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.

    Returns:
        Whether enabled for the current input and state.
    """
    return bool(sanitizer and getattr(sanitizer, "enabled", True))


def _looks_like_text(data: bytes, name: str) -> bool:
    """
    Classify text conservatively while supporting extensionless logs.

    ``bytes.translate`` performs the common all-ASCII classification in C while
    preserving the exact policy below: printable ASCII plus the three log
    whitespace characters. Non-ASCII UTF-8 retains the full Unicode
    ``str.isprintable`` behavior.

    Args:
        data: Bounded byte sequence supplied as data.
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        Whether the classify text conservatively while supporting extensionless
        logs operation succeeds.
    """
    suffix = Path(name).suffix.lower()
    if suffix in _BINARY_SUFFIXES:
        return False
    if suffix in _TEXT_SUFFIXES:
        return True
    if not data:
        return False
    if b"\x00" in data:
        return False
    if data.isascii():
        # ``bytes.translate`` performs the common all-ASCII classification in
        # C while preserving the exact policy below: printable ASCII plus the
        # three log whitespace characters.  Non-ASCII UTF-8 retains the full
        # Unicode ``str.isprintable`` behavior.
        unprintable = len(data.translate(None, _PRINTABLE_ASCII_BYTES))
        printable = len(data) - unprintable
        return printable / len(data) >= 0.95
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False

    # Extensionless command output is common.  Require overwhelmingly printable
    # content before treating an unknown file type as text.
    printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
    return printable / max(len(text), 1) >= 0.95


def _sanitize_text_bytes(data: bytes, sanitizer: Any) -> tuple[bytes, bool]:
    """
    Sanitize text bytes.

    ``surrogateescape`` keeps undecodable octets exactly reversible. A mostly
    textual device log can therefore be sanitized without losing isolated vendor
    bytes or silently skipping an otherwise obvious log.

    Args:
        data: Bounded byte sequence supplied as data.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.

    Returns:
        A tuple containing ``byte sequence`` and ``success flag`` in that order.
    """
    encoding = "utf-8"
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encoding = "utf-32"
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    try:
        # ``surrogateescape`` keeps undecodable octets exactly reversible.  A
        # mostly textual device log can therefore be sanitized without losing
        # isolated vendor bytes or silently skipping an otherwise obvious log.
        text = data.decode(encoding, errors="surrogateescape")
    except UnicodeDecodeError:
        return data, False
    sanitized = sanitizer.sanitize(text)
    if sanitized == text:
        return data, False
    return sanitized.encode(encoding, errors="surrogateescape"), True


def _opaque_metadata_contains_sensitive_text(data: bytes, sanitizer: Any) -> bool:
    """
    Scan opaque metadata without treating framing bytes as an encoding BOM.

    The implementation uses ``data`` and ``sanitizer`` to scan opaque metadata
    without treating framing bytes as an encoding BOM.

    Args:
        data: Bounded byte sequence supplied as data.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.

    Returns:
        Whether the scan opaque metadata without treating framing bytes as an
        encoding BOM operation succeeds.
    """

    if not data:
        return False
    for encoding, errors in (
        ("utf-8", "surrogateescape"),
        ("cp437", "strict"),
        ("latin-1", "strict"),
        ("cp1252", "replace"),
    ):
        view = data.decode(encoding, errors=errors)
        if sanitizer.sanitize(view) != view:
            return True
    for width, encodings in (
        (2, ("utf-16-le", "utf-16-be")),
        (4, ("utf-32-le", "utf-32-be")),
    ):
        for offset in range(width):
            aligned_size = ((len(data) - offset) // width) * width
            if aligned_size <= 0:
                continue
            aligned = data[offset : offset + aligned_size]
            for encoding in encodings:
                view = aligned.decode(encoding, errors="replace")
                if sanitizer.sanitize(view) != view:
                    return True
    return False


def _sanitize_zip_comment(
    data: bytes,
    sanitizer: Any,
    *,
    label: str,
) -> tuple[bytes, bool]:
    """
    Sanitize a ZIP comment or fail closed on encoding ambiguity.

    The implementation uses ``data``, ``sanitizer``, and ``label`` to sanitize a
    ZIP comment or fail closed on encoding ambiguity. If the function cannot
    sanitize a ZIP comment or fail closed on encoding ambiguity, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        data: Bounded byte sequence supplied as data.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        label: Text supplied as label in the format accepted by this function.

    Returns:
        A tuple containing ``sanitized`` and ``changed`` in that order.

    Raises:
        ValueError: If sensitive data in ambiguously encoded ZIP ``label``
            comment.
    """

    sanitized, changed = _sanitize_text_bytes(data, sanitizer)
    if _opaque_metadata_contains_sensitive_text(sanitized, sanitizer):
        raise ValueError(f"sensitive data in ambiguously encoded ZIP {label} comment")
    return sanitized, changed


def _is_owned_bundle_reference(
    context: _StructuredDocumentContext,
    value: Any,
    *,
    directory: bool,
) -> bool:
    """
    Return whether ``value`` names one extant, symlink-free bundle object.

    The implementation uses ``context``, ``value``, and ``directory`` to
    determine whether ``value`` names one extant, symlink-free bundle object.

    Args:
        context: Runtime context carrying state shared across this operation.
        value: Value evaluated while performing ``value`` names one extant,
            symlink-free bundle object.
        directory: filesystem location used as the directory for this operation.

    Returns:
        Whether ``value`` names one extant, symlink-free bundle object.
    """

    if not isinstance(value, str) or not value or len(value) > 4096:
        return False
    if "\\" in value or "\x00" in value:
        return False

    relative = PurePosixPath(value)
    if relative.is_absolute() or relative.as_posix() != value:
        return False
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        return False

    try:
        entry = context.bundle.entry(value)
    except (OSError, RuntimeError, ValueError):
        return False
    return stat.S_ISDIR(entry.mode) if directory else stat.S_ISREG(entry.mode)


def _reference_is_below_directory(reference: str, directory: str) -> bool:
    """
    Return whether one canonical bundle reference is below ``directory``.

    The implementation uses ``reference`` and ``directory`` to determine whether
    one canonical bundle reference is below ``directory``.

    Args:
        reference: Text supplied as reference in the format accepted by this
            function.
        directory: filesystem location used as the directory for this operation.

    Returns:
        Whether one canonical bundle reference is below ``directory``.
    """

    try:
        PurePosixPath(reference).relative_to(PurePosixPath(directory))
    except ValueError:
        return False
    return reference != directory


def _reference_is_below_dut(reference: Any, dut_component: str) -> bool:
    """
    Return whether one canonical reference belongs to the owning DUT.

    The implementation uses ``reference`` and ``dut_component`` to determine
    whether one canonical reference belongs to the owning DUT.

    Args:
        reference: Reference consumed while the function attempts to determine
            whether one canonical reference belongs to the owning DUT.
        dut_component: Text supplied as DUT component in the format accepted by
            this function.

    Returns:
        Whether one canonical reference belongs to the owning DUT.
    """

    return (
        isinstance(reference, str)
        and bool(PurePosixPath(reference).parts)
        and PurePosixPath(reference).parts[0] == dut_component
    )


def _is_declared_dut_directory(
    context: _StructuredDocumentContext,
    value: Any,
) -> bool:
    """
    Mirror the tracker's bounded, direct DUT-directory invariant.

    The implementation uses ``context`` and ``value`` to mirror the tracker's
    bounded, direct DUT-directory invariant.

    Args:
        context: Runtime context carrying state shared across this operation.
        value: Value evaluated while performing mirror the tracker's bounded,
            direct DUT-directory invariant.

    Returns:
        Whether the mirror the tracker's bounded, direct DUT-directory invariant
        operation succeeds.
    """

    if not (
        is_printable_identity(value, maximum_bytes=MAX_DUT_ID_BYTES)
        and "\\" not in value
    ):
        return False
    component = PurePosixPath(value)
    return (
        not component.is_absolute()
        and component.parts == (value,)
        and component.as_posix() == value
        and value not in {".", "..", ".metadata"}
        and _is_owned_bundle_reference(context, value, directory=True)
    )


def _collector_status_path_matches(
    record: Any,
    relative_parts: tuple[str, ...],
) -> bool:
    """
    Bind one collector status document to the logger's producer path.

    The implementation uses ``record`` and ``relative_parts`` to bind one
    collector status document to the logger's producer path.

    Args:
        record: Record object whose ``get`` state is read while performing bind
            one collector status document to the logger's producer path.
        relative_parts: Entries supplied as ``relative_parts`` without
            transferring container ownership.

    Returns:
        Whether the bind one collector status document to the logger's producer
        path operation succeeds.
    """

    if not isinstance(record, dict) or len(relative_parts) != 4:
        return False
    dut_id = record.get("dut_id")
    collector_id = record.get("collector_id")
    collector_name = record.get("collector_name")
    group = record.get("collector_group")
    if (
        not all(
            (
                _is_canonical_generated_component(dut_id, "dut"),
                _is_canonical_generated_component(group, "collector"),
                _is_canonical_generated_component(collector_id, "collector"),
                _is_canonical_generated_component(collector_name, str(collector_id)),
            )
        )
        or group == ".metadata"
    ):
        return False
    group_directory = str(group).lower()
    expected_directory = f"{str(group).capitalize()}_{collector_id}_{collector_name}"
    return relative_parts == (
        dut_id,
        group_directory,
        expected_directory,
        "status.json",
    )


def _collection_record_producer_directory(
    record: Any,
    expected_dut: str,
) -> str | None:
    """
    Return the canonical logger directory declared by a collection record.

    After applying local validation, the function forwards ``record`` and
    ``expected_dut`` to ``as_posix`` and preserves its return and exception
    contract.

    Args:
        record: Record object whose ``get`` state is read while performing
            canonical logger directory declared by a collection record.
        expected_dut: Text supplied as expected DUT in the format accepted by
            this function.

    Returns:
        The canonical collection record producer directory text, or ``None``
        when the requested value is unavailable.
    """

    if not isinstance(record, dict) or record.get("dut_id") != expected_dut:
        return None
    collector_id = record.get("collector_id")
    collector_name = record.get("collector_name")
    group = record.get("group")
    if (
        not all(
            (
                _is_canonical_generated_component(expected_dut, "dut"),
                _is_canonical_generated_component(group, "collector"),
                _is_canonical_generated_component(collector_id, "collector"),
                _is_canonical_generated_component(
                    collector_name,
                    str(collector_id),
                ),
            )
        )
        or group == ".metadata"
    ):
        return None
    group_directory = str(group).lower()
    directory = f"{str(group).capitalize()}_{collector_id}_{collector_name}"
    return PurePosixPath(expected_dut, group_directory, directory).as_posix()


def _load_collector_status_authority(
    context: _StructuredDocumentContext,
    record: Any,
    expected_dut: str,
) -> tuple[dict[str, Any], str] | None:
    """
    Bind one collection row to its independent canonical status producer.

    The implementation uses ``context``, ``record``, and ``expected_dut`` to
    bind one collection row to its independent canonical status producer.

    Args:
        context: Runtime context carrying state shared across this operation.
        record: Record object whose ``get`` state is read while performing bind
            one collection row to its independent canonical status producer.
        expected_dut: Text supplied as expected DUT in the format accepted by
            this function.

    Returns:
        A tuple containing ``authority`` and ``producer directory`` in that
        order.
    """

    producer_directory = _collection_record_producer_directory(record, expected_dut)
    if producer_directory is None:
        return None
    relative = f"{producer_directory}/status.json"
    if not _is_owned_bundle_reference(context, relative, directory=False):
        return None
    try:
        data, _identity = _read_regular_file_stable_bounded(
            context.bundle,
            context.bundle.path(relative),
            _MAX_TRUSTED_STATUS_BYTES,
        )
        authority = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not (
        isinstance(authority, dict)
        and _collector_status_path_matches(
            authority,
            PurePosixPath(relative).parts,
        )
        and all(
            authority.get(status_field) == record.get(collection_field)
            for status_field, collection_field in (
                ("dut_id", "dut_id"),
                ("collector_id", "collector_id"),
                ("collector_name", "collector_name"),
                ("collector_group", "group"),
                ("collection_level", "level"),
            )
        )
    ):
        return None
    return authority, producer_directory


def _load_root_status_authority(
    context: _StructuredDocumentContext,
    record: Any,
    expected_dut: str,
    *,
    per_dut_metadata: Any = None,
    per_dut_receipt_bound: bool = False,
) -> tuple[dict[str, Any], str] | None:
    """
    Bind a per-DUT row to an exact receipt-authenticated snapshot.

    The implementation uses ``context``, ``record``, ``expected_dut``,
    ``per_dut_metadata``, and ``per_dut_receipt_bound`` to bind a per-DUT row to
    an exact receipt-authenticated snapshot.

    Args:
        context: Runtime context carrying state shared across this operation.
        record: Record evaluated while performing bind a per-DUT row to an exact
            receipt-authenticated snapshot.
        expected_dut: Text supplied as expected DUT in the format accepted by
            this function.
        per_dut_metadata: Optional per DUT metadata; ``None`` selects the
            function's default behavior.
        per_dut_receipt_bound: Whether per DUT receipt bound is enabled or
            required for this operation.

    Returns:
        A tuple containing ``record`` and ``producer directory`` in that order.
    """

    producer_directory = _collection_record_producer_directory(record, expected_dut)
    if producer_directory is None or not per_dut_receipt_bound:
        return None
    relative = ".metadata/collection_status.json"
    if not _is_owned_bundle_reference(context, relative, directory=False):
        return None
    try:
        data, _identity = _read_regular_file_stable_bounded(
            context.bundle,
            context.bundle.path(relative),
            _MAX_TRUSTED_STATUS_BYTES,
        )
        if not _status_leaf_bytes_match_receipt(context, relative, data):
            return None
        document = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(document, dict):
        return None
    metadata = document.get("metadata")
    collectors = document.get("collectors")
    if not (
        isinstance(metadata, dict)
        and metadata.get("terminal_finalized") is True
        and isinstance(metadata.get("snapshot_generation"), str)
        and _SNAPSHOT_GENERATION_RE.fullmatch(metadata["snapshot_generation"])
        and isinstance(metadata.get("dut_roster"), list)
        and expected_dut in metadata["dut_roster"]
        and len(metadata["dut_roster"]) <= MAX_DUTS
        and all(
            isinstance(dut_id, str) and _is_declared_dut_directory(context, dut_id)
            for dut_id in metadata["dut_roster"]
        )
        and len(metadata["dut_roster"]) == len(set(metadata["dut_roster"]))
        and isinstance(collectors, dict)
        and len(collectors) <= MAX_TRACKED_COLLECTOR_RECORDS
    ):
        return None
    delegated_per_dut_authority = (
        collectors == {}
        and metadata.get("collector_records_location") == "per_dut"
        and isinstance(per_dut_metadata, dict)
        and per_dut_metadata.get("dut_id") == expected_dut
        and per_dut_metadata.get("terminal_finalized") is True
        and per_dut_metadata.get("snapshot_generation")
        == metadata["snapshot_generation"]
        and all(
            per_dut_metadata.get(field_name) == metadata.get(field_name)
            for field_name in ("run_outcome", "run_result")
        )
    )
    if not delegated_per_dut_authority:
        return None
    return record, producer_directory


def _load_dut_status_records(
    context: _StructuredDocumentContext,
    expected_dut: str,
) -> dict[str, dict[str, Any]]:
    """
    Load exact sibling collector rows used to bind generated timing data.

    The implementation uses ``context`` and ``expected_dut`` to load exact
    sibling collector rows used to bind generated timing data. Parsing or I/O
    must finish before the validated representation is made available to the
    caller.

    Args:
        context: Runtime context carrying state shared across this operation.
        expected_dut: Text supplied as expected DUT in the format accepted by
            this function.

    Returns:
        A mapping containing DUT status records.
    """

    if not _is_declared_dut_directory(context, expected_dut):
        return {}
    relative = f"{expected_dut}/.metadata/collection_status.json"
    if not _is_owned_bundle_reference(context, relative, directory=False):
        return {}
    try:
        data, _identity = _read_regular_file_stable_bounded(
            context.bundle,
            context.bundle.path(relative),
            _MAX_TRUSTED_STATUS_BYTES,
        )
        per_dut_receipt_bound = _status_leaf_bytes_match_receipt(
            context,
            relative,
            data,
        )
        document = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    if not isinstance(document, dict):
        return {}
    metadata = document.get("metadata")
    collectors = document.get("collectors")
    if not (
        isinstance(metadata, dict)
        and metadata.get("dut_id") == expected_dut
        and isinstance(collectors, dict)
        and len(collectors) <= MAX_COLLECTORS_PER_RUN
    ):
        return {}

    validated: dict[str, dict[str, Any]] = {}
    for mapping_key, record in collectors.items():
        if not isinstance(mapping_key, str) or not isinstance(record, dict):
            continue
        collector_id = record.get("collector_id")
        if not (
            record.get("dut_id") == expected_dut
            and isinstance(collector_id, str)
            and mapping_key == f"{expected_dut}:{collector_id}"
        ):
            continue
        authority = _load_collector_status_authority(
            context,
            record,
            expected_dut,
        ) or _load_root_status_authority(
            context,
            record,
            expected_dut,
            per_dut_metadata=metadata,
            per_dut_receipt_bound=per_dut_receipt_bound,
        )
        if authority is not None:
            validated[collector_id] = record
    return validated


def _add_owned_file_value_path(
    value: Any,
    context: _StructuredDocumentContext,
    path: _StructuredPath,
    trusted_value_paths: set[_StructuredPath],
    *,
    dut_component: str,
    producer_directory: str,
    error_log_reference: str,
) -> bool:
    """
    Trust one file reference only at its generated schema location.

    The implementation uses ``value``, ``context``, ``path``,
    ``trusted_value_paths``, and ``dut_component`` to trust one file reference
    only at its generated schema location. The operation mutates
    ``trusted_value_paths`` in place; ownership of those objects remains with
    the caller.

    Args:
        value: Value evaluated while performing trust one file reference only at
            its generated schema location.
        context: Runtime context carrying state shared across this operation.
        path: filesystem location used as the path for this operation.
        trusted_value_paths: filesystem location used as the trusted value paths
            for this operation.
        dut_component: Text supplied as DUT component in the format accepted by
            this function.
        producer_directory: filesystem location used as the producer directory
            for this operation.
        error_log_reference: Text supplied as error log reference in the format
            accepted by this function.

    Returns:
        Whether the trust one file reference only at its generated schema
        location operation succeeds.
    """

    if not isinstance(value, str):
        return False
    reference_parent = PurePosixPath(value).parent.as_posix()
    allowed_parent_directories = {
        producer_directory,
        f"{producer_directory}/diagnostic",
    }
    if not (
        _reference_is_below_dut(value, dut_component)
        and (
            reference_parent in allowed_parent_directories
            or value == error_log_reference
        )
        and _is_owned_bundle_reference(context, value, directory=False)
    ):
        return False
    trusted_value_paths.add(path)
    return True


def _collect_timing_reference_paths(
    timing: Any,
    context: _StructuredDocumentContext,
    path: _StructuredPath,
    trusted_value_paths: set[_StructuredPath],
    *,
    dut_component: str,
    producer_directory: str,
    error_log_reference: str,
) -> None:
    """
    Collect generated artifact references from canonical timing fields.

    The implementation uses ``timing``, ``context``, ``path``,
    ``trusted_value_paths``, and ``dut_component`` to collect generated artifact
    references from canonical timing fields. Terminal status is emitted only
    after generated artifact references from canonical timing fields and its
    owned cleanup have completed.

    Args:
        timing: Timing object whose ``get`` state is read while performing
            generated artifact references from canonical timing fields.
        context: Runtime context carrying state shared across this operation.
        path: filesystem location used as the path for this operation.
        trusted_value_paths: filesystem location used as the trusted value paths
            for this operation.
        dut_component: Text supplied as DUT component in the format accepted by
            this function.
        producer_directory: filesystem location used as the producer directory
            for this operation.
        error_log_reference: Text supplied as error log reference in the format
            accepted by this function.
    """

    if not isinstance(timing, dict):
        return
    operations = timing.get("operations")
    if isinstance(operations, list):
        for operation_index, operation in enumerate(operations):
            if not isinstance(operation, dict):
                continue
            artifact_paths = operation.get("artifact_paths")
            if not isinstance(artifact_paths, list):
                continue
            for artifact_index, value in enumerate(artifact_paths):
                _add_owned_file_value_path(
                    value,
                    context,
                    path
                    + (
                        "operations",
                        operation_index,
                        "artifact_paths",
                        artifact_index,
                    ),
                    trusted_value_paths,
                    dut_component=dut_component,
                    producer_directory=producer_directory,
                    error_log_reference=error_log_reference,
                )

    artifact_timings = timing.get("artifact_timings")
    if isinstance(artifact_timings, list):
        for timing_index, item in enumerate(artifact_timings):
            if isinstance(item, dict):
                _add_owned_file_value_path(
                    item.get("path"),
                    context,
                    path + ("artifact_timings", timing_index, "path"),
                    trusted_value_paths,
                    dut_component=dut_component,
                    producer_directory=producer_directory,
                    error_log_reference=error_log_reference,
                )


def _collector_error_log_reference(record: Any, dut_component: str) -> str:
    """
    Mirror the logger's exact shared error-log filename for one collector.

    After applying local validation, the function forwards ``record`` and
    ``dut_component`` to ``as_posix`` and preserves its return and exception
    contract.

    Args:
        record: Record object whose ``get`` state is read while performing
            mirror the logger's exact shared error-log filename for one
            collector.
        dut_component: Text supplied as DUT component in the format accepted by
            this function.

    Returns:
        The canonical collector error log reference text.
    """

    collector_id = _generated_path_component(
        record.get("collector_id") if isinstance(record, dict) else None,
        "collector",
    )
    collector_name = _generated_path_component(
        record.get("collector_name") if isinstance(record, dict) else None,
        collector_id,
    )
    filename = (
        f"{collector_id}_{collector_name}_error.log"
        if collector_name != collector_id
        else f"{collector_id}_error.log"
    )
    return PurePosixPath(dut_component, "error-logs", filename).as_posix()


def _collect_status_record_trust(
    record: Any,
    context: _StructuredDocumentContext,
    *,
    record_path: _StructuredPath,
    mapping_key: str | None = None,
    expected_dut: str | None = None,
    allowed_duts: set[str] | None = None,
    dut_component: str,
    producer_directory: str,
    identity_fields: tuple[str, ...],
    authority_record: dict[str, Any] | None = None,
) -> tuple[set[_StructuredPath], set[_StructuredPath]]:
    """
    Collect exact source-owned identity and artifact references from a record.

    The implementation uses ``record``, ``context``, ``record_path``,
    ``mapping_key``, and ``expected_dut`` to collect exact source-owned identity
    and artifact references from a record. Terminal status is emitted only after
    exact source-owned identity and artifact references from a record and its
    owned cleanup have completed.

    Args:
        record: Record object whose ``get`` state is read while performing exact
            source-owned identity and artifact references from a record.
        context: Runtime context carrying state shared across this operation.
        record_path: filesystem location used as the record path for this
            operation.
        mapping_key: Stable mapping key used for lookup and operator-facing
            diagnostics.
        expected_dut: Optional expected DUT; ``None`` selects the function's
            default behavior.
        allowed_duts: Optional allowed duts; ``None`` selects the function's
            default behavior.
        dut_component: Text supplied as DUT component in the format accepted by
            this function.
        producer_directory: filesystem location used as the producer directory
            for this operation.
        identity_fields: Entries supplied as ``identity_fields`` without
            transferring container ownership.
        authority_record: Optional authority record; ``None`` selects the
            function's default behavior.

    Returns:
        A tuple containing ``filesystem path`` and ``filesystem path`` in that
        order.
    """

    if not isinstance(record, dict):
        return set(), set()
    dut_id = record.get("dut_id")
    collector_id = record.get("collector_id")
    if not all(
        isinstance(item, str) and _STATUS_IDENTITY_RE.fullmatch(item)
        for item in (dut_id, collector_id)
    ):
        return set(), set()
    if expected_dut is not None and dut_id != expected_dut:
        return set(), set()
    if allowed_duts is not None and dut_id not in allowed_duts:
        return set(), set()
    if mapping_key is not None and mapping_key != f"{dut_id}:{collector_id}":
        return set(), set()

    trusted_values: set[_StructuredPath] = set()
    trusted_keys: set[_StructuredPath] = (
        {record_path} if mapping_key is not None else set()
    )
    for field_name in identity_fields:
        value = record.get(field_name)
        if isinstance(value, str) and _STATUS_IDENTITY_RE.fullmatch(value):
            trusted_values.add(record_path + (field_name,))

    def matches_authority(field_name: str, value: Any) -> bool:
        """
        Return whether ``field_name`` matches authority.

        The implementation uses ``field_name`` and ``value`` to determine
        whether ``field_name`` matches authority.

        Args:
            field_name: Field label included in validation failures for the
                selected input.
            value: Value evaluated while performing ``field_name`` matches
                authority.

        Returns:
            Whether ``field_name`` matches authority.
        """
        return authority_record is None or authority_record.get(field_name) == value

    error_log_reference = _collector_error_log_reference(record, dut_component)

    def add_file_reference(value: Any, path: _StructuredPath) -> bool:
        """
        Add file reference.

        After applying local validation, the function forwards ``value`` and
        ``path`` to ``_add_owned_file_value_path`` and preserves its return and
        exception contract.

        Args:
            value: Value evaluated while performing add file reference.
            path: filesystem location used as the path for this operation.

        Returns:
            Whether the add file reference operation succeeds.
        """
        return _add_owned_file_value_path(
            value,
            context,
            path,
            trusted_values,
            dut_component=dut_component,
            producer_directory=producer_directory,
            error_log_reference=error_log_reference,
        )

    for field_name in _STATUS_ARTIFACT_LIST_FIELDS:
        values = record.get(field_name)
        if isinstance(values, list) and matches_authority(field_name, values):
            for index, value in enumerate(values):
                add_file_reference(value, record_path + (field_name, index))

    discovered = record.get("discovered_files")
    if isinstance(discovered, dict) and matches_authority(
        "discovered_files",
        discovered,
    ):
        for directory, values in discovered.items():
            allowed_directory = directory in {
                producer_directory,
                f"{producer_directory}/diagnostic",
            }
            error_directory = f"{dut_component}/error-logs"
            if not (
                isinstance(directory, str)
                and _reference_is_below_dut(directory, dut_component)
                and (allowed_directory or directory == error_directory)
                and _is_owned_bundle_reference(context, directory, directory=True)
                and isinstance(values, list)
                and values
            ):
                continue
            validated_values = [
                value
                for value in values
                if _is_owned_bundle_reference(context, value, directory=False)
                and _reference_is_below_dut(value, dut_component)
                and _reference_is_below_directory(value, directory)
                and (
                    (
                        allowed_directory
                        and PurePosixPath(value).parent.as_posix() == directory
                    )
                    or (directory == error_directory and value == error_log_reference)
                )
            ]
            if len(validated_values) == len(values):
                directory_path = record_path + ("discovered_files", directory)
                trusted_keys.add(directory_path)
                trusted_values.update(
                    directory_path + (index,) for index in range(len(values))
                )

    artifact_timings = record.get("artifact_timings")
    if isinstance(artifact_timings, list) and matches_authority(
        "artifact_timings",
        artifact_timings,
    ):
        for index, item in enumerate(artifact_timings):
            if isinstance(item, dict):
                add_file_reference(
                    item.get("path"),
                    record_path + ("artifact_timings", index, "path"),
                )

    capture = record.get("request_response_capture")
    if isinstance(capture, dict) and matches_authority(
        "request_response_capture",
        capture,
    ):
        add_file_reference(
            capture.get("artifact_path"),
            record_path + ("request_response_capture", "artifact_path"),
        )
    captures = record.get("request_response_logs")
    if isinstance(captures, dict) and matches_authority(
        "request_response_logs",
        captures,
    ):
        for capture_key, item in captures.items():
            if isinstance(item, dict):
                add_file_reference(
                    item.get("artifact_path"),
                    record_path
                    + ("request_response_logs", capture_key, "artifact_path"),
                )

    timing = record.get("timing")
    if matches_authority("timing", timing):
        _collect_timing_reference_paths(
            timing,
            context,
            record_path + ("timing",),
            trusted_values,
            dut_component=dut_component,
            producer_directory=producer_directory,
            error_log_reference=error_log_reference,
        )
    return trusted_values, trusted_keys


def _collect_roster_trust(
    metadata: Any,
    *,
    context: _StructuredDocumentContext,
    expected_dut: str | None,
) -> tuple[set[_StructuredPath], set[str]]:
    """
    Collect bounded run identities from generated collection metadata.

    The implementation uses ``metadata``, ``context``, and ``expected_dut`` to
    collect bounded run identities from generated collection metadata. Terminal
    status is emitted only after bounded run identities from generated
    collection metadata and its owned cleanup have completed.

    Args:
        metadata: Metadata object whose ``get`` state is read while performing
            bounded run identities from generated collection metadata.
        context: Runtime context carrying state shared across this operation.
        expected_dut: Optional expected DUT; ``None`` selects the function's
            default behavior.

    Returns:
        A tuple containing ``trusted paths`` and ``roster`` in that order.
    """

    trusted_paths: set[_StructuredPath] = set()
    roster: set[str] = set()
    if not isinstance(metadata, dict):
        return trusted_paths, roster

    if expected_dut is not None:
        if not (
            metadata.get("dut_id") == expected_dut
            and _is_declared_dut_directory(context, expected_dut)
        ):
            return trusted_paths, roster
        trusted_paths.add(("metadata", "dut_id"))
        roster.add(expected_dut)
    else:
        values = metadata.get("dut_roster")
        if (
            isinstance(values, list)
            and len(values) <= MAX_DUTS
            and all(isinstance(value, str) for value in values)
            and len(values) == len(set(values))
            and all(_is_declared_dut_directory(context, value) for value in values)
        ):
            roster.update(values)
            trusted_paths.update(
                ("metadata", "dut_roster", index) for index in range(len(values))
            )

    for result_field in ("run_outcome", "run_result"):
        result = metadata.get(result_field)
        affected_duts = (
            result.get("affected_duts") if isinstance(result, dict) else None
        )
        if (
            isinstance(affected_duts, list)
            and len(affected_duts) <= len(roster)
            and all(
                isinstance(value, str) and value in roster for value in affected_duts
            )
            and len(affected_duts) == len(set(affected_duts))
        ):
            trusted_paths.update(
                ("metadata", result_field, "affected_duts", index)
                for index in range(len(affected_duts))
            )
    return trusted_paths, roster


def _is_reserved_generated_status_document_path(parts: tuple[str, ...]) -> bool:
    """
    Return whether a bundle-relative path can carry generated status authority.

    The path check deliberately ignores whether the document later earns trust.
    Invalid or forged documents at reserved status locations must retain strict
    mapping-key rejection instead of falling back to ordinary artifact rewriting.

    Args:
        parts: Bundle-relative POSIX path components for one structured artifact.

    Returns:
        Whether the path is reserved for generated collection status or timing.
    """

    return (
        (len(parts) == 4 and parts[-1] == "status.json")
        or (
            len(parts) in {2, 3}
            and parts[-2:] == (".metadata", "collection_status.json")
        )
        or (len(parts) == 3 and parts[-2:] == (".metadata", "timing.json"))
    )


def _structured_mapping_key_rewrite_allowed(
    context: _StructuredDocumentContext | None,
) -> bool:
    """
    Permit collision-safe key rewriting only outside status authority documents.

    Nested archive members have no top-level status authority context and are
    ordinary collector payloads. A malformed top-level context remains strict so
    failure to resolve provenance can never weaken the generated-document boundary.

    Args:
        context: Optional provenance for the top-level structured bundle artifact.

    Returns:
        Whether redactable mapping keys may be rewritten after collision checks.
    """

    if context is None:
        return True
    try:
        relative = PurePosixPath(context.bundle.relative(context.artifact_path))
    except (OSError, RuntimeError, ValueError):
        return False
    return not _is_reserved_generated_status_document_path(relative.parts)


def _generated_status_document_trust(
    value: Any,
    context: _StructuredDocumentContext | None,
) -> _StructuredDocumentTrust:
    """
    Issue narrow trust only to generated status leaves at reserved paths.

    The implementation uses ``value`` and ``context`` to issue narrow trust only
    to generated status leaves at reserved paths.

    Args:
        value: Value object whose ``get`` state is read while performing issue
            narrow trust only to generated status leaves at reserved paths.
        context: Runtime context carrying state shared across this operation.

    Returns:
        A ``_StructuredDocumentTrust`` representing generated status document
        trust.
    """

    if context is None or not isinstance(value, dict):
        return _StructuredDocumentTrust()
    try:
        relative = PurePosixPath(context.bundle.relative(context.artifact_path))
    except (OSError, RuntimeError, ValueError):
        return _StructuredDocumentTrust()

    parts = relative.parts
    if not _is_reserved_generated_status_document_path(parts):
        return _StructuredDocumentTrust()
    if not _is_owned_bundle_reference(
        context,
        relative.as_posix(),
        directory=False,
    ):
        return _StructuredDocumentTrust()
    trusted_values: set[_StructuredPath] = set()
    trusted_keys: set[_StructuredPath] = set()
    if len(parts) == 4 and parts[-1] == "status.json":
        if not (
            _is_declared_dut_directory(context, parts[0])
            and _collector_status_path_matches(value, parts)
        ):
            return _StructuredDocumentTrust()
        values, keys = _collect_status_record_trust(
            value,
            context,
            record_path=(),
            expected_dut=parts[0],
            dut_component=parts[0],
            producer_directory=PurePosixPath(*parts[:-1]).as_posix(),
            identity_fields=_COLLECTOR_STATUS_IDENTITY_FIELDS,
        )
        trusted_values.update(values)
        trusted_keys.update(keys)
    elif len(parts) in {2, 3} and parts[-2:] == (
        ".metadata",
        "collection_status.json",
    ):
        expected_dut = parts[0] if len(parts) == 3 else None
        metadata = value.get("metadata")
        roster_paths, _roster = _collect_roster_trust(
            metadata,
            context=context,
            expected_dut=expected_dut,
        )
        if expected_dut is not None and not roster_paths:
            return _StructuredDocumentTrust()
        trusted_values.update(roster_paths)
        collectors = value.get("collectors")
        collector_limit = (
            MAX_COLLECTORS_PER_RUN
            if expected_dut is not None
            else MAX_TRACKED_COLLECTOR_RECORDS
        )
        if not isinstance(collectors, dict) or len(collectors) > collector_limit:
            return _StructuredDocumentTrust()
        per_dut_receipt_bound = bool(
            expected_dut is not None
            and _current_status_leaf_matches_receipt(
                context,
                relative.as_posix(),
            )
        )
        root_status_records: dict[str, dict[str, dict[str, Any]]] = {}
        for mapping_key, record in collectors.items():
            if not isinstance(mapping_key, str):
                continue
            record_dut = expected_dut
            if expected_dut is None:
                record_dut = record.get("dut_id") if isinstance(record, dict) else None
                collector_id = (
                    record.get("collector_id") if isinstance(record, dict) else None
                )
                if not (
                    isinstance(record_dut, str)
                    and record_dut in _roster
                    and isinstance(collector_id, str)
                ):
                    continue
                if record_dut not in root_status_records:
                    root_status_records[record_dut] = _load_dut_status_records(
                        context,
                        record_dut,
                    )
                status_records = root_status_records[record_dut]
                if status_records.get(collector_id) != record:
                    continue
            if not isinstance(record_dut, str):
                continue
            authority = _load_collector_status_authority(
                context,
                record,
                record_dut,
            )
            if authority is None and expected_dut is not None:
                authority = _load_root_status_authority(
                    context,
                    record,
                    record_dut,
                    per_dut_metadata=metadata,
                    per_dut_receipt_bound=per_dut_receipt_bound,
                )
            if authority is None:
                continue
            authority_record, producer_directory = authority
            values, keys = _collect_status_record_trust(
                record,
                context,
                record_path=("collectors", mapping_key),
                mapping_key=mapping_key,
                expected_dut=expected_dut,
                allowed_duts=_roster if expected_dut is None else None,
                dut_component=(
                    expected_dut
                    if expected_dut is not None
                    else str(record.get("dut_id", ""))
                ),
                producer_directory=producer_directory,
                identity_fields=_COLLECTION_STATUS_IDENTITY_FIELDS,
                authority_record=authority_record,
            )
            trusted_values.update(values)
            trusted_keys.update(keys)
    elif len(parts) == 3 and parts[-2:] == (".metadata", "timing.json"):
        expected_dut = parts[0]
        if not (
            value.get("dut_id") == expected_dut
            and _is_declared_dut_directory(context, expected_dut)
            and _current_status_leaf_matches_receipt(
                context,
                relative.as_posix(),
            )
        ):
            return _StructuredDocumentTrust()
        trusted_values.add(("dut_id",))
        collectors = value.get("collectors")
        if not isinstance(collectors, dict) or len(collectors) > MAX_COLLECTORS_PER_RUN:
            return _StructuredDocumentTrust()
        status_records = _load_dut_status_records(context, expected_dut)
        if not status_records:
            return _StructuredDocumentTrust()
        collector_groups: dict[str, str] = {}
        for mapping_key, record in collectors.items():
            if not isinstance(mapping_key, str) or not isinstance(record, dict):
                continue
            collector_id = record.get("collector_id")
            status_record = status_records.get(mapping_key)
            if not (
                isinstance(collector_id, str)
                and _STATUS_IDENTITY_RE.fullmatch(collector_id)
                and mapping_key == collector_id
                and isinstance(status_record, dict)
                and all(
                    record.get(field_name) == status_record.get(field_name)
                    for field_name in (
                        "collector_id",
                        "collector_name",
                        "group",
                        "level",
                    )
                )
            ):
                continue
            record_path = ("collectors", mapping_key)
            trusted_keys.add(record_path)
            for field_name in _TIMING_STATUS_IDENTITY_FIELDS:
                identity = record.get(field_name)
                if isinstance(identity, str) and _STATUS_IDENTITY_RE.fullmatch(
                    identity
                ):
                    trusted_values.add(record_path + (field_name,))
            group = record.get("group")
            if isinstance(group, str) and _STATUS_IDENTITY_RE.fullmatch(group):
                collector_groups[mapping_key] = group
            producer_directory = _collection_record_producer_directory(
                status_record,
                expected_dut,
            )
            if producer_directory is None:
                continue
            timing = record.get("timing")
            _collect_timing_reference_paths(
                timing,
                context,
                record_path + ("timing",),
                trusted_values,
                dut_component=expected_dut,
                producer_directory=producer_directory,
                error_log_reference=_collector_error_log_reference(
                    status_record,
                    expected_dut,
                ),
            )

        by_service = value.get("by_service")
        if isinstance(by_service, dict):
            expected_groups = set(collector_groups.values())
            for group, service_record in by_service.items():
                if group not in expected_groups or not isinstance(service_record, dict):
                    continue
                service_collectors = service_record.get("collectors")
                expected_collectors = [
                    collector_id
                    for collector_id, collector_group in collector_groups.items()
                    if collector_group == group
                ]
                if not (
                    isinstance(service_collectors, list)
                    and len(service_collectors) == len(expected_collectors)
                    and all(isinstance(item, str) for item in service_collectors)
                    and len(service_collectors) == len(set(service_collectors))
                    and set(service_collectors) == set(expected_collectors)
                ):
                    continue
                group_path = ("by_service", group)
                trusted_keys.add(group_path)
                trusted_values.update(
                    group_path + ("collectors", index)
                    for index in range(len(service_collectors))
                )

    return _StructuredDocumentTrust(
        value_paths=frozenset(trusted_values),
        mapping_key_paths=frozenset(trusted_keys),
    )


@dataclass
class _StructuredSanitizationState:
    """
    Memoized state for one parsed JSON/YAML document walk.

    The coherent record keeps ``memo`` and ``changed`` together so consumers
    observe one structured sanitization state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        memo: Whether memo applies to this record.
        changed: Whether changed applies to this record.
    """

    memo: dict[tuple[int, bool], Any] = field(default_factory=dict)
    changed: bool = False


def _structured_key_requires_redaction(sanitizer: Any, key: str) -> bool:
    """
    Return the structured key requires redaction.

    After applying local validation, the function forwards ``sanitizer`` and
    ``key`` to ``bool`` and preserves its return and exception contract.

    Args:
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        key: Stable key used for lookup and operator-facing diagnostics.

    Returns:
        Whether the structured key requires redaction operation succeeds.
    """
    checker = getattr(sanitizer, "is_sensitive_structured_key", None)
    return bool(checker and checker(key))


def _sanitize_structured_value(
    value: Any,
    sanitizer: Any,
    *,
    trust: _StructuredDocumentTrust | None = None,
    path: _StructuredPath = (),
    rewrite_mapping_keys: bool = False,
) -> tuple[Any, bool]:
    """
    Sanitize parsed data while retaining credential-key context and aliases.

    The implementation uses ``value``, ``sanitizer``, ``trust``, ``path``, and
    ``rewrite_mapping_keys`` to sanitize parsed data while retaining
    credential-key context and aliases.

    Args:
        value: Value evaluated while performing sanitize parsed data while
            retaining credential-key context and aliases.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        trust: Optional trust; ``None`` selects the function's default behavior.
        path: filesystem location used as the path for this operation.
        rewrite_mapping_keys: Whether non-trusted keys may be sanitized when all
            resulting sibling keys remain unique. The default retains strict
            rejection for callers that have not classified the document.

    Returns:
        A tuple containing ``sanitized`` and ``changed`` in that order.
    """

    active_trust = trust or _StructuredDocumentTrust()
    state = _StructuredSanitizationState()
    replacement = str(getattr(sanitizer, "replacement", "XXXX"))
    memoize = not active_trust.value_paths and not active_trust.mapping_key_paths

    def visit(current: Any, current_path: _StructuredPath, redact: bool) -> Any:
        """
        Visit the current syntax or data node.

        The implementation uses ``current``, ``current_path``, and ``redact`` to
        visit the current syntax or data node. If the function cannot visit the
        current syntax or data node, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            current: Current object whose ``items`` state is read while
                performing visit the current syntax or data node.
            current_path: filesystem location used as the current path for this
                operation.
            redact: Whether redact is enabled or required for this operation.

        Returns:
            The visit value selected by the operation.

        Raises:
            ValueError: If a structured mapping key requires forbidden rewriting
                or sanitized sibling keys would collide.
        """
        if isinstance(current, dict):
            identity = (id(current), redact)
            if memoize and identity in state.memo:
                return state.memo[identity]
            sanitized_mapping: dict[Any, Any] = {}
            if memoize:
                state.memo[identity] = sanitized_mapping
            claimed_output_keys: set[Any] = set()
            for key, child in current.items():
                child_path = current_path + (key,)
                output_key = key
                if (
                    isinstance(key, str)
                    and child_path not in active_trust.mapping_key_paths
                ):
                    sanitized_key = sanitizer.sanitize(key)
                    if sanitized_key != key:
                        if not rewrite_mapping_keys:
                            raise ValueError(
                                "structured mapping key requires sanitization"
                            )
                        output_key = sanitized_key
                        state.changed = True
                if output_key in claimed_output_keys:
                    raise ValueError("structured mapping key sanitization is ambiguous")
                claimed_output_keys.add(output_key)
                child_redact = child_path not in active_trust.value_paths and (
                    redact
                    or (
                        isinstance(key, str)
                        and _structured_key_requires_redaction(sanitizer, key)
                    )
                )
                sanitized_mapping[output_key] = visit(
                    child,
                    child_path,
                    child_redact,
                )
            return sanitized_mapping

        if isinstance(current, list):
            identity = (id(current), redact)
            if memoize and identity in state.memo:
                return state.memo[identity]
            sanitized_list: list[Any] = []
            if memoize:
                state.memo[identity] = sanitized_list
            for index, child in enumerate(current):
                child_path = current_path + (index,)
                sanitized_list.append(visit(child, child_path, redact))
            return sanitized_list

        if current_path in active_trust.value_paths:
            return current
        if redact and current is not None:
            if current != replacement:
                state.changed = True
            return replacement
        if isinstance(current, str):
            sanitized = sanitizer.sanitize(current)
            if sanitized != current:
                state.changed = True
            return sanitized
        return current

    sanitized = visit(value, path, False)
    return sanitized, state.changed


def _sanitize_json_bytes(
    data: bytes,
    name: str,
    sanitizer: Any,
    *,
    context: _StructuredDocumentContext | None = None,
) -> tuple[bytes, bool]:
    """
    Sanitize JSON bytes.

    The implementation uses ``data``, ``name``, ``sanitizer``, and ``context``
    to sanitize JSON bytes.

    Args:
        data: Bounded byte sequence supplied as data.
        name: Stable name used for lookup and operator-facing diagnostics.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        context: Runtime context carrying state shared across this operation.

    Returns:
        A tuple containing ``byte sequence`` and ``success flag`` in that order.
    """
    try:
        text = data.decode("utf-8")
        lowered = name.lower()
        if lowered.endswith((".jsonl", ".ndjson")):
            output_lines: list[str] = []
            changed = False
            for line in text.splitlines():
                if not line.strip():
                    output_lines.append(line)
                    continue
                value = json.loads(line)
                sanitized, line_changed = _sanitize_structured_value(
                    value,
                    sanitizer,
                    rewrite_mapping_keys=True,
                )
                output_lines.append(json.dumps(sanitized, ensure_ascii=False))
                changed = changed or line_changed
            if not changed:
                return data, False
            suffix = "\n" if text.endswith("\n") else ""
            return ("\n".join(output_lines) + suffix).encode("utf-8"), True

        value = json.loads(text)
        sanitized, changed = _sanitize_structured_value(
            value,
            sanitizer,
            trust=_generated_status_document_trust(value, context),
            rewrite_mapping_keys=_structured_mapping_key_rewrite_allowed(context),
        )
        if not changed:
            return data, False
        return (json.dumps(sanitized, indent=2, ensure_ascii=False) + "\n").encode(
            "utf-8"
        ), True
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Vendor archives frequently use a .json suffix for JSON-like command
        # output that is truncated or contains non-standard tokens. The suffix
        # still makes this a textual artifact: scan it losslessly instead of
        # failing cleanup solely because a structured parser rejects it.
        return _sanitize_text_bytes(data, sanitizer)


class _BoundedBundleYamlLoader(yaml.SafeLoader):
    """
    Safe single-document loader with parser-time work ceilings.

    The type coordinates ``compose_node`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        stream: str,
        *,
        limits: BundleSanitizationLimits,
        budget: _InspectionBudget,
    ) -> None:
        """
        Initialize a ``_BoundedBundleYamlLoader`` instance.

        The initializer records ``_alias_count``, ``_budget``,
        ``_compose_depth``, ``_limits``, and ``_node_count`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            stream: Text supplied as stream in the format accepted by this
                function.
            limits: Limits governing initialize a ``_BoundedBundleYamlLoader``
                instance.
            budget: Budget consumed while the function attempts to initialize a
                ``_BoundedBundleYamlLoader`` instance.
        """
        super().__init__(stream)
        self._limits = limits
        self._budget = budget
        self._node_count = 0
        self._alias_count = 0
        self._compose_depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        """
        Compose node.

        The implementation uses ``parent`` and ``index`` to compose node. It
        updates ``_alias_count``, ``_compose_depth``, and ``_node_count`` on the
        instance as part of that state transition. If the function cannot
        compose node, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            parent: Parent consumed while the function attempts to compose node.
            index: Zero-based position within the containing sequence.

        Returns:
            The compose node value selected by the operation.

        Raises:
            ValueError: If YAML alias count exceeds sanitization limit; YAML
                node count exceeds sanitization limit; or YAML nesting depth
                exceeds sanitization limit.
        """
        self._budget.check_deadline()
        if self.check_event(yaml.events.AliasEvent):
            self._alias_count += 1
            if self._alias_count > self._limits.max_yaml_aliases:
                raise ValueError("YAML alias count exceeds sanitization limit")
            return super().compose_node(parent, index)

        self._node_count += 1
        if self._node_count > self._limits.max_yaml_nodes:
            raise ValueError("YAML node count exceeds sanitization limit")
        self._compose_depth += 1
        if self._compose_depth > self._limits.max_yaml_depth:
            self._compose_depth -= 1
            raise ValueError("YAML nesting depth exceeds sanitization limit")
        try:
            return super().compose_node(parent, index)
        finally:
            self._compose_depth -= 1

    def get_single_data(self) -> Any:
        """
        Construct one document after bounding its expanded alias graph.

        Parser counters bound source syntax, while this second walk counts each
        logical alias occurrence and rejects recursive containers before YAML
        construction can expose them to the sanitizer.

        Returns:
            The single safely constructed YAML document, or ``None`` for an
            empty stream.

        Raises:
            ValueError: If aliases create a recursive graph or expand beyond
                the configured YAML node or depth limits.
        """

        node = self.get_single_node()
        if node is None:
            return None
        self._validate_expanded_node_graph(node)
        return self.construct_document(node)

    @staticmethod
    def _node_children(node: yaml.Node) -> list[yaml.Node]:
        """
        Return every logical child of one composed YAML node.

        Mapping keys participate in work and depth accounting just like their
        values. Scalars terminate the walk without allocating a child list
        beyond the empty result.

        Args:
            node: Composed mapping, sequence, or scalar node.

        Returns:
            Mapping keys and values, sequence entries, or an empty scalar list.
        """

        if isinstance(node, yaml.MappingNode):
            return [child for pair in node.value for child in pair]
        if isinstance(node, yaml.SequenceNode):
            return list(node.value)
        return []

    def _validate_expanded_node_graph(self, root: yaml.Node) -> None:
        """
        Bound logical alias expansion and reject recursive YAML graphs.

        Each alias occurrence is counted independently even when it references
        an already composed node. The active-path identity set distinguishes a
        harmless shared DAG from a recursive container while retaining the
        operator-resolved node, depth, and deadline policies.

        Args:
            root: Root node of the single composed YAML document.

        Raises:
            ValueError: If expanded nodes or nesting exceed operator-resolved
                limits, a recursive alias is found, or the inspection deadline
                expires.
        """

        expanded_nodes = 0
        active_nodes: set[int] = set()

        def visit(node: yaml.Node, depth: int) -> None:
            """
            Visit one logical alias occurrence under existing work limits.

            The recursive walk is safe because the configured YAML depth is
            checked before descending and is lower than Python's supported
            recursion depth in the governed runtime.

            Args:
                node: Current composed YAML node.
                depth: One-based logical nesting depth.

            Raises:
                ValueError: If graph size, depth, recursion, or time exceeds
                    the active sanitization policy.
            """

            nonlocal expanded_nodes
            self._budget.check_deadline()
            expanded_nodes += 1
            if expanded_nodes > self._limits.max_yaml_nodes:
                raise ValueError("expanded YAML node count exceeds sanitization limit")
            if depth > self._limits.max_yaml_depth:
                raise ValueError(
                    "expanded YAML nesting depth exceeds sanitization limit"
                )
            children = self._node_children(node)
            if not children:
                return
            identity = id(node)
            if identity in active_nodes:
                raise ValueError("recursive YAML aliases are not supported")
            active_nodes.add(identity)
            try:
                for child in children:
                    visit(child, depth + 1)
            finally:
                active_nodes.remove(identity)

        visit(root, 1)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        """
        Construct one YAML mapping only when explicit keys are unique.

        Merge keys are handled by ``SafeLoader`` and deliberately omitted from
        duplicate comparison; repeated explicit keys are ambiguous because a
        sanitized rewrite would otherwise erase a shadowed value.

        Args:
            node: Composed mapping node to validate and construct.
            deep: Whether PyYAML should recursively construct child objects.

        Returns:
            The mapping produced by ``SafeLoader`` after key validation.

        Raises:
            ValueError: If an explicit key is duplicated or unhashable.
        """

        seen: set[Any] = set()
        for key_node, _ in node.value:
            self._budget.check_deadline()
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
            except TypeError as error:
                raise ValueError("YAML mapping contains an unhashable key") from error
            if duplicate:
                raise ValueError(f"YAML mapping contains duplicate key {key!r}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _sanitize_yaml_bytes(
    data: bytes,
    sanitizer: Any,
    limits: BundleSanitizationLimits,
    budget: _InspectionBudget,
) -> tuple[bytes, bool]:
    """
    Sanitize YAML bytes.

    The implementation uses ``data``, ``sanitizer``, ``limits``, and ``budget``
    to sanitize YAML bytes. If the function cannot sanitize YAML bytes, its
    exception reaches the caller instead of being converted into a successful
    result. Cleanup in the ``finally`` path runs for successful, failed, and
    cancelled execution.

    Args:
        data: Bounded byte sequence supplied as data.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        limits: Limits governing sanitize YAML bytes.
        budget: Budget object whose ``check_deadline`` and ``hold`` state is
            read while performing sanitize YAML bytes.

    Returns:
        A tuple containing ``byte sequence`` and ``success flag`` in that order.

    Raises:
        ValueError: If multi-document YAML is not safely rewritable.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _sanitize_text_bytes(data, sanitizer)

    with budget.hold(
        len(data) * 4,
        label="decoded YAML text",
        limits=limits,
    ):
        loader = _BoundedBundleYamlLoader(text, limits=limits, budget=budget)
        try:
            value = loader.get_single_data()
        except yaml.composer.ComposerError as error:
            if "expected a single document" in str(error):
                raise ValueError(
                    "multi-document YAML is not safely rewritable"
                ) from None
            return _sanitize_text_bytes(data, sanitizer)
        except yaml.YAMLError:
            return _sanitize_text_bytes(data, sanitizer)
        finally:
            loader.dispose()

        budget.check_deadline()
        sanitized, changed = _sanitize_structured_value(
            value,
            sanitizer,
            rewrite_mapping_keys=True,
        )
        raw_text_changed = sanitizer.sanitize(text) != text
        if not changed and not raw_text_changed:
            return data, False
        rendered = yaml.safe_dump(sanitized, sort_keys=False).encode("utf-8")
        budget.check_deadline()
        return rendered, True


def _archive_kind(name: str, data: bytes) -> str | None:
    """
    Archive kind.

    The implementation uses ``name`` and ``data`` to archive kind. Success is
    reported only after the owning output boundary has completed its required
    write or publication step. If the function cannot archive kind, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.
        data: Bounded byte sequence supplied as data.

    Returns:
        The canonical archive kind text, or ``None`` when the requested value is
        unavailable.

    Raises:
        ValueError: If archive extension/signature mismatch for ``name``:
            ``extension_kind`` versus ``magic_kind``.
    """
    lowered = name.lower()
    extension_kind: str | None = None
    tar_container = False
    if lowered.endswith(_ZIP_SUFFIXES):
        extension_kind = "zip"
    elif lowered.endswith((".tar.gz", ".tgz")):
        extension_kind = "gzip"
        tar_container = True
    elif lowered.endswith((".tar.bz2", ".tbz", ".tbz2")):
        extension_kind = "bzip2"
        tar_container = True
    elif lowered.endswith((".tar.xz", ".txz")):
        extension_kind = "xz"
        tar_container = True
    elif lowered.endswith((".tar.zst", ".tar.zstd", ".tzst")):
        extension_kind = "zstd"
        tar_container = True
    elif lowered.endswith(".tar"):
        extension_kind = "tar"
    elif lowered.endswith(".gz"):
        extension_kind = "gzip"
    elif lowered.endswith((".bz2", ".bzip2")):
        extension_kind = "bzip2"
    elif lowered.endswith((".xz", ".lzma")):
        extension_kind = "xz"
    elif lowered.endswith(_ZSTD_SUFFIXES):
        extension_kind = "zstd"
    elif lowered.endswith((".7z", ".rar")):
        extension_kind = "unsupported"

    magic_kind: str | None = None
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        magic_kind = "zip"
    elif data.startswith(b"\x1f\x8b"):
        magic_kind = "gzip"
    elif data.startswith(b"BZh"):
        magic_kind = "bzip2"
    elif data.startswith(b"\xfd7zXZ\x00"):
        magic_kind = "xz"
    elif data.startswith(_ZSTD_FRAME_MAGIC):
        magic_kind = "zstd"
    elif len(data) > 262 and data[257:262] == b"ustar":
        magic_kind = "tar"
    elif data.startswith((b"7z\xbc\xaf'\x1c", b"Rar!\x1a\x07")):
        magic_kind = "unsupported"

    if extension_kind == "tar" and magic_kind in {"gzip", "bzip2", "xz", "zstd"}:
        return "tar"
    if extension_kind and magic_kind and extension_kind != magic_kind:
        raise ValueError(
            f"archive extension/signature mismatch for {name}: "
            f"{extension_kind} versus {magic_kind}"
        )
    if tar_container and extension_kind in {"gzip", "bzip2", "xz"}:
        return "tar"
    return extension_kind or magic_kind


def _tar_write_mode(name: str, compression_kind: str | None = None) -> str:
    """
    Return the TAR write mode.

    The implementation uses ``name`` and ``compression_kind`` to produce the TAR
    write mode.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.
        compression_kind: Optional compression kind; ``None`` selects the
            function's default behavior.

    Returns:
        The canonical TAR write mode text.
    """
    if compression_kind == "gzip":
        return "w:gz"
    if compression_kind == "bzip2":
        return "w:bz2"
    if compression_kind == "xz":
        return "w:xz"
    lowered = name.lower()
    if lowered.endswith((".tar.gz", ".tgz")):
        return "w:gz"
    if lowered.endswith((".tar.bz2", ".tbz", ".tbz2")):
        return "w:bz2"
    if lowered.endswith((".tar.xz", ".txz")):
        return "w:xz"
    return "w"


def _without_compression_suffix(name: str) -> str:
    """
    Return the without compression suffix.

    The implementation uses ``name`` to produce the without compression suffix.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        The canonical without compression suffix text.
    """
    lowered = name.lower()
    for suffix in (".bzip2", ".zstd", ".lzma", ".bz2", ".zst", ".gz", ".xz"):
        if lowered.endswith(suffix):
            return name[: -len(suffix)] or "payload"
    return name


def _raise_member_error(archive_name: str, member_name: str, exc: Exception) -> None:
    """
    Re-raise one nested failure with the exact archive/member chain.

    The implementation uses ``archive_name``, ``member_name``, and ``exc`` to
    re-raise one nested failure with the exact archive/member chain. If the
    function cannot re-raise one nested failure with the exact archive/member
    chain, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        archive_name: Stable archive name used for lookup and operator-facing
            diagnostics.
        member_name: Stable member name used for lookup and operator-facing
            diagnostics.
        exc: Exception consumed while the function attempts to re-raise one
            nested failure with the exact archive/member chain.

    Raises:
        ValueError: If the supplied input cannot be used to re-raise one nested
            failure with the exact archive/member chain.
    """
    raise ValueError(
        "cannot inspect member "
        f"{_archive_path_label(member_name)} inside archive "
        f"{_archive_path_label(archive_name)}: "
        f"{type(exc).__name__}: {exc}"
    ) from exc


def _sanitize_zip(
    data: bytes,
    name: str,
    sanitizer: Any,
    report: BundleSanitizationReport,
    depth: int,
    max_archive_depth: int,
    limits: BundleSanitizationLimits,
    budget: _InspectionBudget,
) -> tuple[bytes, bool]:
    """
    Sanitize ZIP.

    The implementation uses ``data``, ``name``, ``sanitizer``, ``report``, and
    ``depth`` to sanitize ZIP. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. If the function
    cannot sanitize ZIP, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        data: Bounded byte sequence supplied as data.
        name: Stable name used for lookup and operator-facing diagnostics.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        report: Report object whose ``scanned_archives`` state is read while
            performing sanitize ZIP.
        depth: Numeric depth used while the operation performs bounded
            accounting.
        max_archive_depth: Upper bound enforced for max archive depth; the
            consuming boundary rejects or truncates values that exceed it.
        limits: Limits governing sanitize ZIP.
        budget: Budget object whose ``charge_bytes`` and ``charge_members``
            state is read while performing sanitize ZIP.

    Returns:
        A tuple containing the fields that represent ZIP.

    Raises:
        ValueError: If ZIP central-directory member count changed during parse;
            unindexed bytes precede the first ZIP member; multi-disk ZIP
            archives are not distributable; or unsafe ZIP member path contains
            NUL; or another input invariant is violated.
    """
    report.scanned_archives += 1
    classic_end_offset = _validate_zip_terminator(data, name=name)
    validated_member_count = _validate_zip_central_directory(
        data,
        limits=limits,
        sanitizer=sanitizer,
        classic_end_offset=classic_end_offset,
    )
    source_buffer = io.BytesIO(data)
    output_buffer = io.BytesIO()
    changed = False
    with (
        zipfile.ZipFile(source_buffer, "r") as source,
        zipfile.ZipFile(output_buffer, "w", allowZip64=True) as output,
    ):
        sanitized_archive_comment, archive_comment_changed = _sanitize_zip_comment(
            source.comment, sanitizer, label="archive"
        )
        output.comment = sanitized_archive_comment
        changed = archive_comment_changed
        infos = source.infolist()
        if len(infos) != validated_member_count:
            raise ValueError("ZIP central-directory member count changed during parse")
        if infos and min(info.header_offset for info in infos) != 0:
            raise ValueError("unindexed bytes precede the first ZIP member")
        if any(info.volume != 0 for info in infos):
            raise ValueError("multi-disk ZIP archives are not distributable")
        budget.charge_members(len(infos), label=name, limits=limits)
        total_size = 0
        seen_names: dict[str, tuple[Any, ...]] = {}
        portable_names: dict[str, str] = {}
        zip_path_root = _ZipPathNode()
        path_nodes = 0
        tracked_path_bytes = 0
        for info in infos:
            if "\x00" in info.orig_filename:
                raise ValueError("unsafe ZIP member path contains NUL")
            if any(
                sanitizer.sanitize(candidate) != candidate
                for candidate in (info.orig_filename, info.filename)
            ):
                raise ValueError("sensitive data in ZIP member path metadata")
            if info.orig_filename != info.filename:
                raise ValueError(
                    "ambiguous ZIP Unicode path metadata: "
                    f"{_archive_path_label(info.orig_filename)} -> "
                    f"{_archive_path_label(info.filename)}"
                )
            payload_start, payload_end, local_metadata_fingerprint = (
                _validate_zip_local_header(data, info, sanitizer=sanitizer)
            )
            sanitized_member_comment, member_comment_changed = _sanitize_zip_comment(
                info.comment, sanitizer, label="member"
            )
            output_info = copy.copy(info)
            output_info.comment = sanitized_member_comment
            changed = changed or member_comment_changed
            is_directory = info.is_dir()
            if info.external_attr & 0x08:
                raise ValueError(
                    "ZIP member type conflicts with its path syntax: "
                    f"{_archive_path_label(info.filename)}"
                )
            if info.external_attr & 0x10 and not is_directory:
                raise ValueError(
                    "ZIP member type conflicts with its path syntax: "
                    f"{_archive_path_label(info.filename)}"
                )
            declared_type = stat.S_IFMT(info.external_attr >> 16)
            expected_type = stat.S_IFDIR if is_directory else stat.S_IFREG
            if declared_type and declared_type != expected_type:
                raise ValueError(
                    "ZIP member type conflicts with its path syntax: "
                    f"{_archive_path_label(info.filename)}"
                )
            if (info.external_attr >> 16) & (
                stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
            ):
                safe_mode = expected_type | ((info.external_attr >> 16) & 0o777)
                output_info.create_system = 3
                output_info.external_attr = (safe_mode << 16) | (
                    info.external_attr & 0xFFFF
                )
                # Once extraction-sensitive mode metadata forces a rewrite,
                # drop optional extra fields instead of carrying alternate
                # extraction semantics into the normalized archive.
                output_info.extra = b""
                output.comment = b""
                changed = True
            normalized_name = _validate_member_name(
                info.filename,
                directory=is_directory,
                max_path_depth=limits.max_archive_path_depth,
            )
            portable_name = _portable_path_key(normalized_name)
            previous_portable_name = portable_names.get(portable_name)
            if (
                previous_portable_name is not None
                and previous_portable_name != normalized_name
            ):
                raise ValueError(
                    "case-colliding ZIP member paths are not distributable: "
                    f"{_archive_path_label(info.filename)}"
                )
            portable_names[portable_name] = normalized_name
            path_nodes, tracked_path_bytes = _register_zip_member_path(
                zip_path_root,
                portable_name,
                directory=is_directory,
                path_nodes=path_nodes,
                tracked_path_bytes=tracked_path_bytes,
                limits=limits,
            )
            if info.flag_bits & 0x1:
                raise ValueError(
                    "encrypted ZIP member is not inspectable: "
                    f"{_archive_path_label(info.filename)}"
                )
            if info.flag_bits & 0x08:
                # Re-emitting into the seekable output clears the descriptor
                # flag and binds the member boundary for streaming extractors.
                changed = True
            if is_directory:
                if info.file_size or info.compress_size:
                    raise ValueError(
                        "ZIP directory member contains payload bytes: "
                        f"{_archive_path_label(info.filename)}"
                    )
                with source.open(info, "r") as directory_stream:
                    if directory_stream.read(1):
                        raise ValueError(
                            "ZIP directory member contains payload bytes: "
                            f"{_archive_path_label(info.filename)}"
                        )
                fingerprint = (
                    "directory",
                    _zip_member_metadata_fingerprint(output_info),
                    local_metadata_fingerprint,
                )
                if (
                    normalized_name in seen_names
                    and seen_names[normalized_name] != fingerprint
                ):
                    raise ValueError(
                        "conflicting duplicate ZIP member: "
                        f"{_archive_path_label(info.filename)}"
                    )
                seen_names[normalized_name] = fingerprint
                output.writestr(output_info, b"")
                continue
            # Unix-created entries carry st_mode in the high half of
            # external_attr.  Writers frequently emit permission bits with no
            # file-type field (``zipfile.writestr`` yields 0o600 and S_IFMT 0),
            # so only a *declared* non-regular type is rejected.  Anything that
            # does declare a type must be a regular file: a symlink, device, or
            # fifo is non-distributable, matching the TAR member-type policy.
            if info.file_size > limits.max_archive_member_bytes:
                raise ValueError(
                    f"archive member {_archive_path_label(info.filename)} exceeds "
                    f"{limits.max_archive_member_bytes} bytes: {info.file_size}"
                )
            total_size += info.file_size
            if total_size > limits.max_archive_total_bytes:
                raise ValueError(
                    f"archive expanded size exceeds {limits.max_archive_total_bytes} "
                    f"bytes while inspecting {info.filename!r}"
                )
            _check_compression_ratio(
                info.compress_size,
                info.file_size,
                label=f"ZIP member {info.filename!r}",
                limits=limits,
            )
            _validate_zip_compressed_payload(data[payload_start:payload_end], info)
            with source.open(info, "r") as member_stream:
                member_data = _read_bounded(
                    member_stream,
                    limits.max_archive_member_bytes,
                    label=f"ZIP member {info.filename!r}",
                    budget=budget,
                    limits=limits,
                )
            if len(member_data) != info.file_size:
                raise ValueError(
                    f"ZIP member size mismatch for {info.filename!r}: "
                    f"expected {info.file_size}, read {len(member_data)}"
                )
            fingerprint = (
                "file",
                hashlib.sha256(member_data).hexdigest(),
                _zip_member_metadata_fingerprint(output_info),
                local_metadata_fingerprint,
            )
            if (
                normalized_name in seen_names
                and seen_names[normalized_name] != fingerprint
            ):
                raise ValueError(f"conflicting duplicate ZIP member: {info.filename!r}")
            seen_names[normalized_name] = fingerprint
            budget.charge_bytes(len(member_data), label=info.filename, limits=limits)
            try:
                sanitized, member_changed = _sanitize_payload(
                    member_data,
                    info.filename,
                    sanitizer,
                    report,
                    depth + 1,
                    max_archive_depth,
                    limits,
                    budget,
                )
            except Exception as exc:
                _raise_member_error(name, info.filename, exc)
            changed = changed or member_changed
            output.writestr(output_info, sanitized)
    return (output_buffer.getvalue(), True) if changed else (data, False)


def _sanitize_tar(
    data: bytes,
    name: str,
    sanitizer: Any,
    report: BundleSanitizationReport,
    depth: int,
    max_archive_depth: int,
    limits: BundleSanitizationLimits,
    budget: _InspectionBudget,
) -> tuple[bytes, bool]:
    """
    Sanitize TAR.

    The implementation uses ``data``, ``name``, ``sanitizer``, ``report``, and
    ``depth`` to sanitize TAR. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. If the function
    cannot sanitize TAR, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        data: Bounded byte sequence supplied as data.
        name: Stable name used for lookup and operator-facing diagnostics.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        report: Report object whose ``scanned_archives`` state is read while
            performing sanitize TAR.
        depth: Numeric depth used while the operation performs bounded
            accounting.
        max_archive_depth: Upper bound enforced for max archive depth; the
            consuming boundary rejects or truncates values that exceed it.
        limits: Limits governing sanitize TAR.
        budget: Budget object whose ``charge_bytes`` and ``charge_members``
            state is read while performing sanitize TAR.

    Returns:
        A tuple containing ``byte sequence`` and ``success flag`` in that order.

    Raises:
        ValueError: If archive member count exceeds ``max_archive_members``; the
            supplied input cannot be used to sanitize TAR; archive metadata
            exceeds ``max_archive_metadata_bytes`` bytes; or archive path node
            count exceeds ``max_archive_path_nodes``; or another input invariant
            is violated.
    """
    report.scanned_archives += 1
    compression_kind = _compressed_stream_kind(data)
    if compression_kind:
        source_data = _decompress_stream_strict(
            data,
            name,
            compression_kind,
            limits.max_decompressed_stream_bytes,
            max_frames=limits.max_archive_members,
            check_deadline=budget.check_deadline,
        )
    else:
        source_data = data
    source_buffer = io.BytesIO(source_data)
    output_buffer = io.BytesIO()
    changed = False
    member_count = 0
    total_size = 0
    metadata_size = 0
    path_nodes = 0
    tracked_path_bytes = 0
    seen_names: dict[str, tuple[str, str]] = {}
    portable_names: dict[str, str] = {}
    sanitized_name_sources: dict[str, str] = {}
    with (
        tarfile.open(
            fileobj=source_buffer,
            mode="r:",
            tarinfo=_bounded_sanitizer_tarinfo_type(limits),
        ) as source,
        tarfile.open(
            fileobj=output_buffer,
            mode=_tar_write_mode(name, compression_kind),
            format=source.format,
        ) as output,
    ):
        raw_members: list[tarfile.TarInfo] = []
        normalized_members: list[tuple[tarfile.TarInfo, tarfile.TarInfo, str]] = []
        renamed_member_paths = False
        has_link_members = False
        for source_member in source:
            raw_members.append(source_member)
            member_count += 1
            if member_count > limits.max_archive_members:
                raise ValueError(
                    f"archive member count exceeds {limits.max_archive_members}"
                )
            sanitized_member, metadata_changed = _sanitize_tar_logical_metadata(
                source_member,
                sanitizer,
            )
            changed = changed or metadata_changed
            source_shape_name = "/".join(
                part
                for part in source_member.name.rstrip("/").split("/")
                if part not in ("", ".")
            )
            original_normalized_name = _validate_member_name(
                source_member.name,
                directory=source_member.isdir(),
                max_path_depth=limits.max_archive_path_depth,
                allow_root_directory=True,
                canonicalize_portable=True,
            )
            normalized_name = _validate_member_name(
                sanitized_member.name,
                directory=sanitized_member.isdir(),
                max_path_depth=limits.max_archive_path_depth,
                allow_root_directory=True,
                canonicalize_portable=True,
            )
            renamed_member_paths = (
                renamed_member_paths
                or original_normalized_name != source_shape_name
                or normalized_name != original_normalized_name
            )
            changed = changed or normalized_name != source_shape_name
            has_link_members = (
                has_link_members or source_member.type in _DISTRIBUTABLE_TAR_LINK_TYPES
            )
            if "path" in sanitized_member.pax_headers:
                pax_path = sanitized_member.pax_headers["path"]
                if not _tar_extension_path_matches_member(
                    pax_path,
                    sanitized_member,
                ):
                    raise ValueError("ambiguous TAR PAX path metadata")
                directory_slash = sanitized_member.isdir() and pax_path.endswith("/")
                sanitized_member.pax_headers["path"] = normalized_name + (
                    "/" if directory_slash else ""
                )
            sanitized_member.name = normalized_name
            member_metadata_size = max(
                _tar_member_metadata_size(source_member),
                _tar_member_metadata_size(sanitized_member),
            )
            if member_metadata_size > limits.max_archive_metadata_member_bytes:
                raise ValueError(
                    "archive member metadata exceeds "
                    f"{limits.max_archive_metadata_member_bytes} bytes: "
                    f"{_archive_path_label(source_member.name)}"
                )
            metadata_size += member_metadata_size
            if metadata_size > limits.max_archive_metadata_bytes:
                raise ValueError(
                    "archive metadata exceeds "
                    f"{limits.max_archive_metadata_bytes} bytes"
                )
            if not normalized_name:
                # A leading root-directory entry is emitted by ordinary GNU
                # `tar -C directory .`. Retain compatibility without letting
                # its mode/timestamp mutate a consumer's extraction root.
                changed = True
                continue
            previous_source_name = sanitized_name_sources.get(normalized_name)
            if (
                previous_source_name is not None
                and previous_source_name != source_shape_name
            ):
                raise ValueError(
                    "sanitized TAR member paths collide: "
                    f"{_archive_path_label(source_member.name)}"
                )
            sanitized_name_sources[normalized_name] = source_shape_name
            portable_name = _portable_path_key(normalized_name)
            previous_portable_name = portable_names.get(portable_name)
            if (
                previous_portable_name is not None
                and previous_portable_name != normalized_name
            ):
                raise ValueError(
                    "case-colliding TAR member paths are not distributable: "
                    f"{_archive_path_label(source_member.name)}"
                )
            portable_names[portable_name] = normalized_name
            name_nodes = normalized_name.count("/") + 1
            target_nodes = (
                sanitized_member.linkname.count("/") + 1
                if source_member.type in _DISTRIBUTABLE_TAR_LINK_TYPES
                else 0
            )
            path_nodes += name_nodes + target_nodes
            if path_nodes > limits.max_archive_path_nodes:
                raise ValueError(
                    f"archive path node count exceeds {limits.max_archive_path_nodes}"
                )
            tracked_path_bytes += (
                _encoded_metadata_size(normalized_name)
                + _encoded_metadata_size(sanitized_member.linkname)
                + _TAR_PATH_NODE_STATE_BYTES * (name_nodes + target_nodes)
            )
            if tracked_path_bytes > limits.max_archive_tracked_path_bytes:
                raise ValueError(
                    "archive tracked path metadata exceeds "
                    f"{limits.max_archive_tracked_path_bytes} bytes"
                )
            normalized_members.append(
                (source_member, sanitized_member, normalized_name)
            )

        if renamed_member_paths and has_link_members:
            raise ValueError(
                "TAR member paths cannot be rewritten in an archive containing links"
            )

        path_trie = _build_tar_path_trie(
            [
                (sanitized_member, normalized_name)
                for _source_member, sanitized_member, normalized_name in normalized_members
            ]
        )
        terminal_types: dict[str, set[str]] = {}
        first_regular_positions: dict[str, int] = {}
        for position, (
            source_member,
            sanitized_member,
            normalized_name,
        ) in enumerate(normalized_members):
            if sanitized_member.type not in _DISTRIBUTABLE_TAR_LINK_TYPES:
                member_type = _tar_member_type(sanitized_member)
                terminal_types.setdefault(normalized_name, set()).add(member_type)
                if member_type == "file":
                    first_regular_positions.setdefault(normalized_name, position)
                continue
            if not normalized_name:
                raise ValueError(
                    "unsafe archive link member path: "
                    f"{_archive_path_label(source_member.name)}"
                )
        link_specs: dict[str, _TarLinkSpec] = {}
        for position, (
            source_member,
            sanitized_member,
            normalized_name,
        ) in enumerate(normalized_members):
            if sanitized_member.type not in _DISTRIBUTABLE_TAR_LINK_TYPES:
                continue
            target, requires_directory = _validate_link_target(
                normalized_name,
                sanitized_member.linkname or "",
                is_symlink=sanitized_member.issym(),
                path_trie=path_trie,
                max_path_depth=limits.max_archive_path_depth,
            )
            spec = _TarLinkSpec(
                target=target,
                is_hardlink=sanitized_member.islnk(),
                requires_directory=requires_directory,
            )
            if (
                spec.is_hardlink
                and target in first_regular_positions
                and first_regular_positions[target] >= position
            ):
                raise ValueError(
                    "TAR hard link target must precede the link: "
                    f"{_archive_path_label(source_member.name)}"
                )
            previous = link_specs.get(normalized_name)
            if previous is not None and previous != spec:
                raise ValueError(
                    "conflicting duplicate TAR member: "
                    f"{_archive_path_label(source_member.name)}"
                )
            link_specs[normalized_name] = spec
        resolved_links = _validate_tar_link_graph(link_specs, terminal_types)
        _validate_tar_directory_link_cycles(link_specs, resolved_links)

        for source_member, sanitized_member, normalized_name in normalized_members:
            # Validate against the complete link-name set, not only links seen
            # earlier in archive order. A later member can still replace an
            # ancestor path during extraction.
            if _passes_through_link(normalized_name, path_trie):
                raise ValueError(
                    "TAR member is nested beneath a link member: "
                    f"{_archive_path_label(source_member.name)}"
                )
            member = copy.copy(sanitized_member)
            member.pax_headers = dict(sanitized_member.pax_headers)
            if source_member.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                member.mode = source_member.mode & 0o777
                member.pax_headers = {}
                changed = True
            if not source_member.isfile():
                is_link = source_member.type in _DISTRIBUTABLE_TAR_LINK_TYPES
                if not source_member.isdir() and not is_link:
                    raise ValueError(
                        "unsupported TAR member type is not distributable: "
                        f"{_archive_path_label(source_member.name)} "
                        f"({source_member.type!r})"
                    )
                if source_member.size:
                    raise ValueError(
                        "non-file TAR member contains payload bytes: "
                        f"{_archive_path_label(source_member.name)}"
                    )
                fingerprint = (
                    f"type:{source_member.type!r}",
                    source_member.linkname or "",
                )
                if (
                    normalized_name in seen_names
                    and seen_names[normalized_name] != fingerprint
                ):
                    raise ValueError(
                        "conflicting duplicate TAR member: "
                        f"{_archive_path_label(source_member.name)}"
                    )
                seen_names[normalized_name] = fingerprint
                output.addfile(member)
                continue
            if source_member.size > limits.max_archive_member_bytes:
                raise ValueError(
                    f"archive member {_archive_path_label(source_member.name)} exceeds "
                    f"{limits.max_archive_member_bytes} bytes: {source_member.size}"
                )
            total_size += source_member.size
            if total_size > limits.max_archive_total_bytes:
                raise ValueError(
                    f"archive expanded size exceeds {limits.max_archive_total_bytes} "
                    "bytes while inspecting "
                    f"{_archive_path_label(source_member.name)}"
                )
            extracted = source.extractfile(source_member)
            if extracted is None:
                output.addfile(member)
                continue
            member_data = _read_bounded(
                extracted,
                limits.max_archive_member_bytes,
                label=f"TAR member {_archive_path_label(source_member.name)}",
                budget=budget,
                limits=limits,
            )
            if len(member_data) != source_member.size:
                raise ValueError(
                    "TAR member size mismatch for "
                    f"{_archive_path_label(source_member.name)}: "
                    f"expected {source_member.size}, read {len(member_data)}"
                )
            fingerprint = ("file", hashlib.sha256(member_data).hexdigest())
            if (
                normalized_name in seen_names
                and seen_names[normalized_name] != fingerprint
            ):
                raise ValueError(
                    "conflicting duplicate TAR member: "
                    f"{_archive_path_label(source_member.name)}"
                )
            seen_names[normalized_name] = fingerprint
            budget.charge_bytes(
                len(member_data), label=source_member.name, limits=limits
            )
            try:
                sanitized, member_changed = _sanitize_payload(
                    member_data,
                    member.name,
                    sanitizer,
                    report,
                    depth + 1,
                    max_archive_depth,
                    limits,
                    budget,
                )
            except Exception as exc:
                _raise_member_error(name, source_member.name, exc)
            changed = changed or member_changed
            member.size = len(sanitized)
            output.addfile(member, io.BytesIO(sanitized))
        changed = (
            _validate_tar_raw_framing(
                source_data,
                raw_members,
                source.offset,
                sanitizer=sanitizer,
                name=name,
            )
            or changed
        )
        _validate_tar_terminator(source_data, source.offset, name=name)
    budget.charge_members(member_count, label=name, limits=limits)
    _check_compression_ratio(
        len(data), total_size, label=f"TAR archive {name!r}", limits=limits
    )
    if not changed:
        return data, False
    rewritten = output_buffer.getvalue()
    if compression_kind == "zstd":
        rewritten = zstandard.ZstdCompressor().compress(rewritten)
    return rewritten, True


def _sanitize_compressed_stream(
    data: bytes,
    name: str,
    kind: str,
    sanitizer: Any,
    report: BundleSanitizationReport,
    depth: int,
    max_archive_depth: int,
    limits: BundleSanitizationLimits,
    budget: _InspectionBudget,
) -> tuple[bytes, bool]:
    """
    Sanitize compressed stream.

    The implementation uses ``data``, ``name``, ``kind``, ``sanitizer``, and
    ``report`` to sanitize compressed stream.

    Args:
        data: Bounded byte sequence supplied as data.
        name: Stable name used for lookup and operator-facing diagnostics.
        kind: Text supplied as kind in the format accepted by this function.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        report: Report object whose ``scanned_archives`` state is read while
            performing sanitize compressed stream.
        depth: Numeric depth used while the operation performs bounded
            accounting.
        max_archive_depth: Upper bound enforced for max archive depth; the
            consuming boundary rejects or truncates values that exceed it.
        limits: Limits governing sanitize compressed stream.
        budget: Budget object whose ``charge_bytes`` state is read while
            performing sanitize compressed stream.

    Returns:
        A tuple containing ``byte sequence`` and ``success flag`` in that order.
    """
    report.scanned_archives += 1
    decompressed = _decompress_stream_strict(
        data,
        name,
        kind,
        limits.max_decompressed_stream_bytes,
        max_frames=limits.max_archive_members,
        check_deadline=budget.check_deadline,
    )

    _check_compression_ratio(
        len(data),
        len(decompressed),
        label=f"compressed stream {name!r}",
        limits=limits,
    )
    budget.charge_bytes(len(decompressed), label=name, limits=limits)

    sanitized, changed = _sanitize_payload(
        decompressed,
        _without_compression_suffix(name),
        sanitizer,
        report,
        depth + 1,
        max_archive_depth,
        limits,
        budget,
    )
    if not changed:
        return data, False
    if kind == "gzip":
        return gzip.compress(sanitized, mtime=0), True
    if kind == "bzip2":
        return bz2.compress(sanitized), True
    if kind == "xz":
        return lzma.compress(sanitized), True
    return zstandard.ZstdCompressor().compress(sanitized), True


def _sanitize_payload(
    data: bytes,
    name: str,
    sanitizer: Any,
    report: BundleSanitizationReport,
    depth: int,
    max_archive_depth: int,
    limits: BundleSanitizationLimits,
    budget: _InspectionBudget,
    context: _StructuredDocumentContext | None = None,
) -> tuple[bytes, bool]:
    """
    Sanitize payload.

    The implementation uses ``data``, ``name``, ``sanitizer``, ``report``, and
    ``depth`` to sanitize payload. If the function cannot sanitize payload, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        data: Bounded byte sequence supplied as data.
        name: Stable name used for lookup and operator-facing diagnostics.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        report: Report object whose ``preserved_binary_files`` state is read
            while performing sanitize payload.
        depth: Numeric depth used while the operation performs bounded
            accounting.
        max_archive_depth: Upper bound enforced for max archive depth; the
            consuming boundary rejects or truncates values that exceed it.
        limits: Limits governing sanitize payload.
        budget: Budget object whose ``check_deadline`` state is read while
            performing sanitize payload.
        context: Runtime context carrying state shared across this operation.

    Returns:
        A tuple containing ``data`` and ``success flag`` in that order.

    Raises:
        ValueError: If unsupported archive format is not inspectable: ``name``;
            or nested archive depth exceeds ``max_archive_depth``: ``name``.
    """
    budget.check_deadline()
    kind = _archive_kind(name, data)
    if kind:
        if kind == "unsupported":
            raise ValueError(f"unsupported archive format is not inspectable: {name}")
        if depth >= max_archive_depth:
            raise ValueError(
                f"nested archive depth exceeds {max_archive_depth}: {name}"
            )
        if kind == "zip":
            return _sanitize_zip(
                data,
                name,
                sanitizer,
                report,
                depth,
                max_archive_depth,
                limits,
                budget,
            )
        if kind == "tar":
            return _sanitize_tar(
                data,
                name,
                sanitizer,
                report,
                depth,
                max_archive_depth,
                limits,
                budget,
            )
        return _sanitize_compressed_stream(
            data,
            name,
            kind,
            sanitizer,
            report,
            depth,
            max_archive_depth,
            limits,
            budget,
        )

    lowered = name.lower()
    if lowered.endswith((".json", ".jsonl", ".ndjson")):
        return _sanitize_json_bytes(data, name, sanitizer, context=context)
    if lowered.endswith((".yaml", ".yml")):
        return _sanitize_yaml_bytes(data, sanitizer, limits, budget)
    if _looks_like_text(data, name):
        return _sanitize_text_bytes(data, sanitizer)
    report.preserved_binary_files += 1
    return data, False


_is_sha256 = archive_validation_is_sha256


def _load_bounded_json(data: bytes) -> Any:
    """
    Load bounded JSON.

    After applying local validation, the function forwards ``data`` to
    ``archive_validation_load_json`` and preserves its return and exception
    contract. Parsing or I/O must finish before the validated representation is
    made available to the caller.

    Args:
        data: Bounded byte sequence supplied as data.

    Returns:
        The bounded JSON value selected by the operation.
    """
    return archive_validation_load_json(data)


def _validation_record_collector_root(
    bundle: _PinnedBundle,
    record_path: Path,
) -> Path:
    """
    Return the validation record collector root.

    The implementation uses ``bundle`` and ``record_path`` to produce the
    validation record collector root. If the function cannot produce the
    validation record collector root, its exception reaches the caller instead
    of being converted into a successful result.

    Args:
        bundle: Bundle object whose ``entry``, ``path``, ``relative``, and
            ``root_path`` state is read while performing validation record
            collector root.
        record_path: filesystem location used as the record path for this
            operation.

    Returns:
        The validated validation record collector root filesystem path.

    Raises:
        ValueError: If archive validation record is not a direct regular file;
            or archive validation collector root is not a directory.
    """
    relative = bundle.relative(record_path)
    entry = bundle.entry(relative)
    parts = _validated_relative_parts(relative)
    if not stat.S_ISREG(entry.mode) or len(parts) < 2 or parts[-2] != "diagnostic":
        raise ValueError("archive validation record is not a direct regular file")
    collector_parts = parts[:-2]
    if not collector_parts:
        return bundle.root_path
    collector_relative = "/".join(collector_parts)
    collector_entry = bundle.entry(collector_relative)
    if not stat.S_ISDIR(collector_entry.mode):
        raise ValueError("archive validation collector root is not a directory")
    return bundle.path(collector_relative)


def _validated_artifact_path_parts(path_text: str) -> tuple[str, ...]:
    """
    Validate one collector-relative POSIX path without touching the target.

    The implementation uses ``path_text`` to validate one collector-relative
    POSIX path without touching the target. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        path_text: Text supplied as path text in the format accepted by this
            function.

    Returns:
        The validated artifact path parts returned in operation-defined order.

    Raises:
        ValueError: If archive validation filename is unsafe; or archive
            validation filename escapes its collector.
    """

    if (
        not path_text
        or len(path_text) > 2_048
        or "\\" in path_text
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in path_text
        )
    ):
        raise ValueError("archive validation filename is unsafe")
    raw_parts = path_text.split("/")
    pure_path = PurePosixPath(path_text)
    if (
        pure_path.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
        or not pure_path.parts
    ):
        raise ValueError("archive validation filename escapes its collector")
    return pure_path.parts


def _resolve_direct_validation_artifact(
    bundle: _PinnedBundle,
    collector_root: Path,
    path_text: str,
) -> Path:
    """
    Resolve direct validation artifact.

    After applying local validation, the function forwards ``bundle``,
    ``collector_root``, and ``path_text`` to ``bundle.path`` and preserves its
    return and exception contract.

    Args:
        bundle: Bundle object whose ``entry``, ``path``, ``relative``, and
            ``root_path`` state is read while performing direct validation
            artifact.
        collector_root: filesystem location used as the collector root for this
            operation.
        path_text: Text supplied as path text in the format accepted by this
            function.

    Returns:
        The validated direct validation artifact filesystem path.

    Raises:
        ValueError: If archive validation artifact uses a symbolic path; or
            archive validation artifact is not a regular file.
    """
    parts = _validated_artifact_path_parts(path_text)
    collector_parts = (
        ()
        if collector_root == bundle.root_path
        else _validated_relative_parts(bundle.relative(collector_root))
    )
    relative = "/".join((*collector_parts, *parts))
    entry = bundle.entry(relative)
    if stat.S_ISLNK(entry.mode):
        raise ValueError("archive validation artifact uses a symbolic path")
    if not stat.S_ISREG(entry.mode):
        raise ValueError("archive validation artifact is not a regular file")
    return bundle.path(relative)


def _supported_validation_archive(path_text: str) -> bool:
    """
    Return the supported validation archive.

    After applying local validation, the function forwards ``path_text`` to
    ``endswith`` and preserves its return and exception contract.

    Args:
        path_text: Text supplied as path text in the format accepted by this
            function.

    Returns:
        Whether the supported validation archive operation succeeds.
    """
    return path_text.casefold().endswith(ARCHIVE_VALIDATION_SUPPORTED_SUFFIXES)


def _enumerate_collector_archive_keys(
    bundle: _PinnedBundle,
    collector_root: Path,
    remaining_artifacts: list[int],
) -> dict[str, Path]:
    """
    Build a bounded filename-hash lookup for a previously redacted receipt.

    The implementation uses ``bundle``, ``collector_root``, and
    ``remaining_artifacts`` to build a bounded filename-hash lookup for a
    previously redacted receipt. If the function cannot build a bounded
    filename-hash lookup for a previously redacted receipt, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        bundle: Bundle object whose ``entries``, ``relative``, and ``root_path``
            state is read while performing bounded filename-hash lookup for a
            previously redacted receipt.
        collector_root: filesystem location used as the collector root for this
            operation.
        remaining_artifacts: Entries supplied as ``remaining_artifacts`` without
            transferring container ownership.

    Returns:
        The validated ``artifacts``.

    Raises:
        ValueError: If archive validation artifact enumeration exceeds limit; or
            duplicate archive validation artifact path key.
    """

    artifacts: dict[str, Path] = {}
    if remaining_artifacts[0] <= 0:
        raise ValueError("archive validation artifact enumeration exceeds limit")
    collector_parts = (
        ()
        if collector_root == bundle.root_path
        else _validated_relative_parts(bundle.relative(collector_root))
    )
    for entry in bundle.entries:
        remaining_artifacts[0] -= 1
        if remaining_artifacts[0] < 0:
            raise ValueError("archive validation artifact enumeration exceeds limit")
        parts = _validated_relative_parts(entry.relative_path)
        if parts[: len(collector_parts)] != collector_parts:
            continue
        if not stat.S_ISREG(entry.mode):
            continue
        relative = "/".join(parts[len(collector_parts) :])
        if not _supported_validation_archive(relative):
            continue
        resolved = _resolve_direct_validation_artifact(
            bundle,
            collector_root,
            relative,
        )
        key = archive_validation_path_sha256(relative)
        if key in artifacts and artifacts[key] != resolved:
            raise ValueError("duplicate archive validation artifact path key")
        artifacts[key] = resolved
    return artifacts


def _resolve_bound_validation_artifact(
    bundle: _PinnedBundle,
    collector_root: Path,
    artifact_path: Any,
    artifact_path_sha256: Any,
    enumeration_cache: dict[Path, dict[str, Path]],
    remaining_artifacts: list[int],
) -> Path:
    """
    Resolve a canonical path or its filename hash after prior redaction.

    Historical producer evidence can contain a pre-substitution template. It
    must still bind through its immutable path key or fail with the same
    no-bound-artifact outcome as redacted display.

    Args:
        bundle: Bundle consumed while the function attempts to resolve a
            canonical path or its filename hash after prior redaction.
        collector_root: filesystem location used as the collector root for this
            operation.
        artifact_path: filesystem location used as the artifact path for this
            operation.
        artifact_path_sha256: Artifact path SHA-256 consumed while the function
            attempts to resolve a canonical path or its filename hash after
            prior redaction.
        enumeration_cache: filesystem location used as the enumeration cache for
            this operation.
        remaining_artifacts: Entries supplied as ``remaining_artifacts`` without
            transferring container ownership.

    Returns:
        The validated bound validation artifact filesystem path.

    Raises:
        ValueError: If archive validation artifact binding is malformed; archive
            validation target is not a supported archive; or redacted archive
            validation path has no bound supported artifact.
    """

    if not isinstance(artifact_path, str) or not _is_sha256(artifact_path_sha256):
        raise ValueError("archive validation artifact binding is malformed")

    if archive_validation_path_sha256(artifact_path) == artifact_path_sha256:
        if not _supported_validation_archive(artifact_path):
            raise ValueError("archive validation target is not a supported archive")
        try:
            return _resolve_direct_validation_artifact(
                bundle,
                collector_root,
                artifact_path,
            )
        except _BundleEntryMissing:
            # Historical producer evidence can contain a pre-substitution
            # template. It must still bind through its immutable path key or
            # fail with the same no-bound-artifact outcome as redacted display.
            pass

    artifacts = enumeration_cache.get(collector_root)
    if artifacts is None:
        artifacts = _enumerate_collector_archive_keys(
            bundle,
            collector_root,
            remaining_artifacts,
        )
        enumeration_cache[collector_root] = artifacts
    try:
        return artifacts[artifact_path_sha256]
    except KeyError as error:
        raise ValueError(
            "redacted archive validation path has no bound supported artifact"
        ) from error


def _canonical_receipt_shape(entry: dict[str, Any]) -> None:
    """
    Return the canonical receipt shape.

    The implementation uses ``entry`` to produce the canonical receipt shape. If
    the function cannot produce the canonical receipt shape, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        entry: Mapping supplying fields for canonical receipt shape.

    Raises:
        ValueError: If archive validation receipt is not canonical service
            evidence.
    """
    if (
        entry.get("schema") != ARCHIVE_VALIDATION_SCHEMA
        or entry.get("producer") != ARCHIVE_VALIDATION_PRODUCER
        or entry.get("receipt_role") != ARCHIVE_VALIDATION_PRIMARY_ROLE
        or not _is_sha256(entry.get("validation_id"))
    ):
        raise ValueError("archive validation receipt is not canonical service evidence")


def _validate_invalid_primary_receipt(entry: dict[str, Any]) -> None:
    """
    Validate immutable evidence for an attachment that was never published.

    The implementation uses ``entry`` to validate immutable evidence for an
    attachment that was never published. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        entry: Mapping supplying fields for immutable evidence for an attachment
            that was never published.

    Raises:
        ValueError: If invalid archive validation receipt is malformed.
    """

    _canonical_receipt_shape(entry)
    requested_filename = entry.get("filename")
    if (
        entry.get("normalization") is not None
        or not _is_sha256(entry.get("requested_filename_sha256"))
        or not isinstance(requested_filename, str)
        or archive_validation_path_sha256(requested_filename)
        != entry.get("requested_filename_sha256")
        or any(
            field in entry
            for field in (
                "artifact_path",
                "artifact_path_sha256",
                "pre_sanitization_saved_size",
                "pre_sanitization_saved_sha256",
                "sanitization_rewritten",
            )
        )
        or archive_validation_receipt_id(entry) != entry["validation_id"]
    ):
        raise ValueError("invalid archive validation receipt is malformed")


def _producer_saved_identity(entry: dict[str, Any]) -> tuple[int, str, bool]:
    """
    Return the producer saved identity.

    The implementation uses ``entry`` to produce the producer saved identity. If
    the function cannot produce the producer saved identity, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        entry: Mapping supplying fields for producer saved identity.

    Returns:
        A tuple containing ``integer count``, ``status or message text``, and
        ``success flag`` in that order.

    Raises:
        ValueError: If archive pre-sanitization identity is malformed.
    """
    prior_fields = (
        "pre_sanitization_saved_size",
        "pre_sanitization_saved_sha256",
        "sanitization_rewritten",
    )
    prior_present = [key in entry for key in prior_fields]
    if any(prior_present):
        if (
            not all(prior_present)
            or type(entry["pre_sanitization_saved_size"]) is not int
            or entry["pre_sanitization_saved_size"] <= 0
            or not _is_sha256(entry["pre_sanitization_saved_sha256"])
            or entry["sanitization_rewritten"] is not True
        ):
            raise ValueError("archive pre-sanitization identity is malformed")
        return (
            entry["pre_sanitization_saved_size"],
            entry["pre_sanitization_saved_sha256"],
            True,
        )
    return entry["saved_size"], entry["saved_sha256"], False


def _validate_primary_receipt_identity(
    entry: dict[str, Any],
    *,
    exact_normalized_original_sha256: str | None = None,
) -> tuple[int, str, bool]:
    """
    Validate primary receipt identity.

    The implementation uses ``entry`` and ``exact_normalized_original_sha256``
    to validate primary receipt identity. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        entry: Mapping supplying fields for primary receipt identity.
        exact_normalized_original_sha256: Optional exact normalized original
            SHA-256; ``None`` selects the function's default behavior.

    Returns:
        A tuple containing ``producer size``, ``producer SHA-256``, and
        ``already reconciled`` in that order.

    Raises:
        ValueError: If archive validation identity is malformed; valid archive
            receipt has inconsistent source identity; normalized archive receipt
            has inconsistent provenance; or unsupported archive validation
            status; or another input invariant is violated.
    """
    saved_size = entry.get("saved_size")
    saved_sha256 = entry.get("saved_sha256")
    original_size = entry.get("original_size")
    original_sha256 = entry.get("original_sha256")
    if (
        type(saved_size) is not int
        or saved_size <= 0
        or not _is_sha256(saved_sha256)
        or type(original_size) is not int
        or original_size <= 0
        or not _is_sha256(original_sha256)
    ):
        raise ValueError("archive validation identity is malformed")

    producer_size, producer_sha256, already_reconciled = _producer_saved_identity(entry)
    status = entry.get("status")
    normalization = entry.get("normalization")
    if status == "valid":
        if normalization is not None or (original_size, original_sha256) != (
            producer_size,
            producer_sha256,
        ):
            raise ValueError("valid archive receipt has inconsistent source identity")
    elif status == "normalized":
        if (
            normalization != "removed_exact_trailing_empty_json_array"
            or original_size != producer_size + 2
            or (
                exact_normalized_original_sha256 is not None
                and original_sha256 != exact_normalized_original_sha256
            )
            or (
                exact_normalized_original_sha256 is None
                and original_sha256 == producer_sha256
            )
        ):
            raise ValueError("normalized archive receipt has inconsistent provenance")
    else:  # pragma: no cover - guarded by the caller
        raise ValueError("unsupported archive validation status")

    if already_reconciled and (saved_size, saved_sha256) == (
        producer_size,
        producer_sha256,
    ):
        raise ValueError("reconciled archive receipt did not change saved identity")
    if archive_validation_receipt_id(entry) != entry["validation_id"]:
        raise ValueError("archive validation ID does not match immutable provenance")
    return producer_size, producer_sha256, already_reconciled


def _diagnostic_entries(
    bundle: _PinnedBundle, filename_prefix: str
) -> list[_PinnedBundleEntry]:
    """
    Return the diagnostic entries.

    The implementation uses ``bundle`` and ``filename_prefix`` to produce the
    diagnostic entries. If the function cannot produce the diagnostic entries,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        bundle: Bundle object whose ``entries`` state is read while performing
            diagnostic entries.
        filename_prefix: Text supplied as filename prefix in the format accepted
            by this function.

    Returns:
        The validated ``matches``.

    Raises:
        ValueError: If ``filename_prefix`` diagnostic count exceeds limit.
    """
    matches: list[_PinnedBundleEntry] = []
    for entry in bundle.entries:
        parts = _validated_relative_parts(entry.relative_path)
        if (
            len(parts) >= 2
            and parts[-2] == "diagnostic"
            and parts[-1].startswith(filename_prefix)
            and parts[-1].endswith(".json")
        ):
            matches.append(entry)
    if len(matches) > _ARCHIVE_VALIDATION_RECORD_COUNT_LIMIT:
        raise ValueError(f"{filename_prefix} diagnostic count exceeds limit")
    return matches


def _bind_archive_validation_receipts(
    bundle: _PinnedBundle,
    limits: BundleSanitizationLimits,
) -> _ArchiveValidationPlan:
    """
    Pre-bind service-owned primary receipts before metadata is sanitized.

    After applying local validation, the function forwards ``bundle`` and
    ``limits`` to ``_ArchiveValidationPlan`` and preserves its return and
    exception contract. Remote I/O uses the configured transport policy and
    returns only after its response or failure has been observed.

    Args:
        bundle: Bundle object whose ``path`` and ``root_path`` state is read
            while performing pre-bind service-owned primary receipts before
            metadata is sanitized.
        limits: Limits governing pre-bind service-owned primary receipts before
            metadata is sanitized.

    Returns:
        A ``_ArchiveValidationPlan`` representing bind archive validation
        receipts.

    Raises:
        ValueError: If archive validation evidence exceeds aggregate byte limit;
            the archive validation record is not a bounded JSON array; archive
            validation evidence exceeds aggregate entry limit; or the archive
            validation entry is not an object; or another input invariant is
            violated.
    """

    record_entries = _diagnostic_entries(bundle, "archive_validation_")

    records: list[_BoundValidationRecord] = []
    primary_summaries: dict[str, tuple[str, Any]] = {}
    artifact_identity_cache: dict[Path, _StableFileIdentity] = {}
    receipt_artifacts: set[Path] = set()
    enumeration_cache: dict[Path, dict[str, Path]] = {}
    remaining_artifacts = [_ARCHIVE_VALIDATION_ARTIFACT_SCAN_LIMIT]
    total_evidence_bytes = 0
    total_evidence_entries = 0

    for record_entry in record_entries:
        record_path = bundle.path(record_entry.relative_path)
        record_data, record_identity = _read_regular_file_stable_bounded(
            bundle,
            record_path,
            _ARCHIVE_VALIDATION_RECORD_LIMIT,
        )
        total_evidence_bytes += len(record_data)
        if total_evidence_bytes > limits.max_archive_validation_total_bytes:
            raise ValueError("archive validation evidence exceeds aggregate byte limit")
        document = _load_bounded_json(record_data)
        if (
            not isinstance(document, list)
            or len(document) > _ARCHIVE_VALIDATION_ENTRY_LIMIT
        ):
            raise ValueError("archive validation record must be a bounded JSON array")
        total_evidence_entries += len(document)
        if total_evidence_entries > limits.max_archive_validation_total_entries:
            raise ValueError(
                "archive validation evidence exceeds aggregate entry limit"
            )
        collector_root = _validation_record_collector_root(bundle, record_path)
        receipts: list[_BoundArchiveReceipt] = []
        has_invalid_receipts = False

        for index, entry in enumerate(document):
            if not isinstance(entry, dict):
                raise ValueError("archive validation entry must be an object")
            status = entry.get("status")
            if status == "invalid":
                has_invalid_receipts = True
                # Historical invalid receipts have no persisted artifact and remain
                # immutable. New versioned invalid receipts can still be referenced.
                if entry.get("schema") == ARCHIVE_VALIDATION_SCHEMA:
                    _validate_invalid_primary_receipt(entry)
                    validation_id = entry["validation_id"]
                    if validation_id in primary_summaries:
                        raise ValueError("duplicate archive validation ID")
                    primary_summaries[validation_id] = (
                        status,
                        entry.get("normalization"),
                    )
                continue
            if status not in {"valid", "normalized"}:
                raise ValueError("archive validation entry has an unsupported status")

            _canonical_receipt_shape(entry)
            artifact_path = entry.get("artifact_path")
            if entry.get("filename") != artifact_path:
                raise ValueError("archive validation filename aliases disagree")
            artifact_path_key = entry.get("artifact_path_sha256")
            resolved_artifact = _resolve_bound_validation_artifact(
                bundle,
                collector_root,
                artifact_path,
                artifact_path_key,
                enumeration_cache,
                remaining_artifacts,
            )
            if resolved_artifact in receipt_artifacts:
                raise ValueError("archive artifact has more than one primary receipt")
            receipt_artifacts.add(resolved_artifact)
            initial_identity = artifact_identity_cache.get(resolved_artifact)
            exact_normalized_original_sha256: str | None = None
            if initial_identity is None:
                if (
                    status == "normalized"
                    and "pre_sanitization_saved_size" not in entry
                    and "pre_sanitization_saved_sha256" not in entry
                    and "sanitization_rewritten" not in entry
                ):
                    (
                        initial_identity,
                        exact_normalized_original_sha256,
                    ) = _capture_regular_file_identity_with_appended_digest(
                        bundle,
                        resolved_artifact,
                        limits.max_top_level_bytes,
                        b"[]",
                    )
                else:
                    initial_identity = _capture_regular_file_identity_bounded(
                        bundle,
                        resolved_artifact,
                        limits.max_top_level_bytes,
                    )
                artifact_identity_cache[resolved_artifact] = initial_identity
            producer_size, producer_sha256, already_reconciled = (
                _validate_primary_receipt_identity(
                    entry,
                    exact_normalized_original_sha256=(exact_normalized_original_sha256),
                )
            )
            if (initial_identity.size, initial_identity.sha256) != (
                entry["saved_size"],
                entry["saved_sha256"],
            ):
                raise ValueError(
                    "archive receipt does not match pre-sanitization bytes"
                )

            validation_id = entry["validation_id"]
            if validation_id in primary_summaries:
                raise ValueError("duplicate archive validation ID")
            primary_summaries[validation_id] = (
                status,
                entry.get("normalization"),
            )
            receipts.append(
                _BoundArchiveReceipt(
                    record_index=index,
                    validation_id=validation_id,
                    artifact_path=resolved_artifact,
                    artifact_relative_path=resolved_artifact.relative_to(
                        bundle.root_path
                    ).as_posix(),
                    artifact_path_sha256=artifact_path_key,
                    status=status,
                    normalization=entry.get("normalization"),
                    original_size=entry["original_size"],
                    original_sha256=entry["original_sha256"],
                    current_saved_size=entry["saved_size"],
                    current_saved_sha256=entry["saved_sha256"],
                    producer_saved_size=producer_size,
                    producer_saved_sha256=producer_sha256,
                    already_reconciled=already_reconciled,
                    initial_artifact_identity=initial_identity,
                )
            )
        records.append(
            _BoundValidationRecord(
                path=record_path,
                data=record_data,
                identity=record_identity,
                receipts=tuple(receipts),
                has_invalid_receipts=has_invalid_receipts,
            )
        )

    references: list[_BoundReferenceRecord] = []
    reference_entries = _diagnostic_entries(bundle, "diagnostic_responses_")
    for reference_entry in reference_entries:
        reference_path = bundle.path(reference_entry.relative_path)
        data, identity = _read_regular_file_stable_bounded(
            bundle,
            reference_path,
            _ARCHIVE_VALIDATION_RECORD_LIMIT,
        )
        total_evidence_bytes += len(data)
        if total_evidence_bytes > limits.max_archive_validation_total_bytes:
            raise ValueError("archive validation evidence exceeds aggregate byte limit")
        document = _load_bounded_json(data)
        if (
            not isinstance(document, list)
            or len(document) > _ARCHIVE_VALIDATION_ENTRY_LIMIT
        ):
            raise ValueError(
                "archive validation references must be a bounded JSON array"
            )
        total_evidence_entries += len(document)
        if total_evidence_entries > limits.max_archive_validation_total_entries:
            raise ValueError(
                "archive validation evidence exceeds aggregate entry limit"
            )
        bound_references: list[_BoundArchiveReference] = []
        for response_index, response in enumerate(document):
            if not isinstance(response, dict):
                raise ValueError("diagnostic response must be an object")
            reference = response.get("archive_validation")
            if reference is None:
                continue
            if not isinstance(reference, dict):
                raise ValueError("archive validation reference must be an object")
            if (
                reference.get("status") == "invalid"
                and reference.get("receipt_role") != ARCHIVE_VALIDATION_REFERENCE_ROLE
            ):
                # Legacy invalid evidence does not describe a saved artifact.
                continue
            forbidden_identity_fields = {
                "original_size",
                "original_sha256",
                "saved_size",
                "saved_sha256",
                "pre_sanitization_saved_size",
                "pre_sanitization_saved_sha256",
                "sanitization_rewritten",
            }
            if forbidden_identity_fields.intersection(reference):
                raise ValueError(
                    "diagnostic response contains a mutable archive receipt copy"
                )
            if (
                reference.get("schema") != ARCHIVE_VALIDATION_SCHEMA
                or reference.get("producer") != ARCHIVE_VALIDATION_PRODUCER
                or reference.get("receipt_role") != ARCHIVE_VALIDATION_REFERENCE_ROLE
                or not _is_sha256(reference.get("validation_id"))
            ):
                raise ValueError(
                    "diagnostic response archive reference is not canonical"
                )
            validation_id = reference["validation_id"]
            primary = primary_summaries.get(validation_id)
            if primary is None or primary != (
                reference.get("status"),
                reference.get("normalization"),
            ):
                raise ValueError(
                    "diagnostic response archive reference drifted from primary"
                )
            bound_references.append(
                _BoundArchiveReference(
                    response_index=response_index,
                    validation_id=validation_id,
                    status=reference["status"],
                    normalization=reference.get("normalization"),
                )
            )
        if bound_references:
            references.append(
                _BoundReferenceRecord(
                    path=reference_path,
                    data=data,
                    identity=identity,
                    references=tuple(bound_references),
                )
            )
    return _ArchiveValidationPlan(
        records=tuple(records),
        references=tuple(references),
        primary_summaries=primary_summaries,
        bound_artifacts=frozenset(receipt_artifacts),
    )


def _rewrite_map(
    root: Path,
    rewrites: list[_SanitizedArtifactRewrite],
) -> dict[str, _SanitizedArtifactRewrite]:
    """
    Return the rewrite map.

    The implementation uses ``root`` and ``rewrites`` to produce the rewrite
    map. If the function cannot produce the rewrite map, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        root: filesystem location used as the root for this operation.
        rewrites: Entries supplied as ``rewrites`` without transferring
            container ownership.

    Returns:
        The validated ``rewritten``.

    Raises:
        ValueError: If duplicate sanitizer rewrite identity.
    """
    rewritten = {item.relative_path: item for item in rewrites}
    if len(rewritten) != len(rewrites):
        raise ValueError("duplicate sanitizer rewrite identity")
    for relative in rewritten:
        _validated_artifact_path_parts(relative)
        root.joinpath(*PurePosixPath(relative).parts).relative_to(root)
    return rewritten


def _validate_staged_references(
    plan: _ArchiveValidationPlan,
    scanned_identities: dict[Path, _StableFileIdentity],
    evidence_replacements: dict[Path, bytes],
) -> None:
    """
    Validate staged references.

    The implementation uses ``plan``, ``scanned_identities``, and
    ``evidence_replacements`` to validate staged references. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path. Remote I/O uses the
    configured transport policy and returns only after its response or failure
    has been observed.

    Args:
        plan: Plan object whose ``get``, ``primary_summaries``, and
            ``references`` state is read while performing staged references.
        scanned_identities: filesystem location used as the scanned identities
            for this operation.
        evidence_replacements: filesystem location used as the evidence
            replacements for this operation.

    Raises:
        ValueError: If archive reference changed during sanitization preflight;
            archive validation reference changed shape; archive validation
            reference disappeared; or archive validation reference role
            disappeared; or another input invariant is violated.
    """
    for reference_record in plan.references:
        if scanned_identities.get(reference_record.path) != reference_record.identity:
            raise ValueError("archive reference changed during sanitization preflight")
        data = evidence_replacements.get(
            reference_record.path,
            reference_record.data,
        )
        document = _load_bounded_json(data)
        if not isinstance(document, list):
            raise ValueError("archive validation reference changed shape")
        observed: list[_BoundArchiveReference] = []
        for response_index, response in enumerate(document):
            if not isinstance(response, dict):
                raise ValueError("archive validation reference changed shape")
            reference = response.get("archive_validation")
            if reference is None:
                continue
            if not isinstance(reference, dict):
                raise ValueError("archive validation reference disappeared")
            if reference.get("receipt_role") != ARCHIVE_VALIDATION_REFERENCE_ROLE:
                raise ValueError("archive validation reference role disappeared")
            if any(
                key in reference
                for key in (
                    "original_size",
                    "original_sha256",
                    "saved_size",
                    "saved_sha256",
                    "pre_sanitization_saved_size",
                    "pre_sanitization_saved_sha256",
                    "sanitization_rewritten",
                )
            ):
                raise ValueError("archive validation reference gained mutable identity")
            primary = plan.primary_summaries.get(reference.get("validation_id"))
            if (
                reference.get("schema") != ARCHIVE_VALIDATION_SCHEMA
                or reference.get("producer") != ARCHIVE_VALIDATION_PRODUCER
                or reference.get("receipt_role") != ARCHIVE_VALIDATION_REFERENCE_ROLE
                or primary is None
                or primary != (reference.get("status"), reference.get("normalization"))
            ):
                raise ValueError(
                    "archive validation reference drifted after sanitization"
                )
            observed.append(
                _BoundArchiveReference(
                    response_index=response_index,
                    validation_id=reference["validation_id"],
                    status=reference["status"],
                    normalization=reference.get("normalization"),
                )
            )
        if tuple(observed) != reference_record.references:
            raise ValueError("archive validation reference disappeared or moved")


def _stage_archive_validation_provenance(
    root: Path,
    plan: _ArchiveValidationPlan,
    rewrites: list[_SanitizedArtifactRewrite],
    scanned_identities: dict[Path, _StableFileIdentity],
    evidence_replacements: dict[Path, bytes],
) -> int:
    """
    Stage primary receipts against final bytes without mutating the tree.

    The implementation uses ``root``, ``plan``, ``rewrites``,
    ``scanned_identities``, and ``evidence_replacements`` to stage primary
    receipts against final bytes without mutating the tree. If the function
    cannot stage primary receipts against final bytes without mutating the tree,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        root: filesystem location used as the root for this operation.
        plan: Plan object whose ``records`` state is read while performing stage
            primary receipts against final bytes without mutating the tree.
        rewrites: Entries supplied as ``rewrites`` without transferring
            container ownership.
        scanned_identities: filesystem location used as the scanned identities
            for this operation.
        evidence_replacements: filesystem location used as the evidence
            replacements for this operation.

    Returns:
        The validated ``reconciled_total``.

    Raises:
        ValueError: If archive validation record changed during preflight;
            archive validation record changed shape; archive validation entry
            disappeared during sanitization; or archive validation entry changed
            shape; or another input invariant is violated.
    """

    rewritten = _rewrite_map(root, rewrites)
    _validate_staged_references(plan, scanned_identities, evidence_replacements)
    final_identity_cache: dict[Path, tuple[int, str]] = {}
    reconciled_total = 0

    for record in plan.records:
        if not record.receipts:
            continue
        if scanned_identities.get(record.path) != record.identity:
            raise ValueError("archive validation record changed during preflight")
        current_data = evidence_replacements.get(
            record.path,
            record.data,
        )
        document = _load_bounded_json(current_data)
        if (
            not isinstance(document, list)
            or len(document) > _ARCHIVE_VALIDATION_ENTRY_LIMIT
        ):
            raise ValueError("archive validation record changed shape")
        original_document = copy.deepcopy(document)
        reconciled_in_record = 0

        for receipt in record.receipts:
            if receipt.record_index >= len(document):
                raise ValueError(
                    "archive validation entry disappeared during sanitization"
                )
            entry = document[receipt.record_index]
            if not isinstance(entry, dict):
                raise ValueError("archive validation entry changed shape")
            if (
                entry.get("status") != receipt.status
                or entry.get("normalization") != receipt.normalization
            ):
                raise ValueError(
                    "archive validation status drifted during sanitization"
                )

            # Cryptographic and schema fields are structural evidence, not secret
            # payload text. Restore them if an over-broad string rule matched a
            # coincidental substring while preserving the sanitized path display.
            entry["schema"] = ARCHIVE_VALIDATION_SCHEMA
            entry["producer"] = ARCHIVE_VALIDATION_PRODUCER
            entry["receipt_role"] = ARCHIVE_VALIDATION_PRIMARY_ROLE
            entry["validation_id"] = receipt.validation_id
            entry["artifact_path_sha256"] = receipt.artifact_path_sha256
            entry["original_size"] = receipt.original_size
            entry["original_sha256"] = receipt.original_sha256

            display_path = entry.get("artifact_path")
            if (
                not isinstance(display_path, str)
                or entry.get("filename") != display_path
            ):
                raise ValueError("archive validation path display drifted")

            final_identity = final_identity_cache.get(receipt.artifact_path)
            if final_identity is None:
                rewrite = rewritten.get(receipt.artifact_relative_path)
                final_identity = (
                    (rewrite.after_size, rewrite.after_sha256)
                    if rewrite is not None
                    else (
                        receipt.initial_artifact_identity.size,
                        receipt.initial_artifact_identity.sha256,
                    )
                )
                final_identity_cache[receipt.artifact_path] = final_identity
            if final_identity == (
                receipt.current_saved_size,
                receipt.current_saved_sha256,
            ):
                entry["saved_size"] = receipt.current_saved_size
                entry["saved_sha256"] = receipt.current_saved_sha256
                if receipt.already_reconciled:
                    entry["pre_sanitization_saved_size"] = receipt.producer_saved_size
                    entry["pre_sanitization_saved_sha256"] = (
                        receipt.producer_saved_sha256
                    )
                    entry["sanitization_rewritten"] = True
                continue

            rewrite = rewritten.get(receipt.artifact_relative_path)
            if rewrite is None:
                raise ValueError(
                    "archive bytes changed without a sanitizer-owned rewrite"
                )
            if (rewrite.before_size, rewrite.before_sha256) != (
                receipt.initial_artifact_identity.size,
                receipt.initial_artifact_identity.sha256,
            ) or (rewrite.after_size, rewrite.after_sha256) != (
                final_identity[0],
                final_identity[1],
            ):
                raise ValueError("archive rewrite identity does not match its receipt")
            if receipt.already_reconciled:
                raise ValueError("archive changed after provenance was reconciled")

            entry["pre_sanitization_saved_size"] = receipt.current_saved_size
            entry["pre_sanitization_saved_sha256"] = receipt.current_saved_sha256
            entry["saved_size"] = final_identity[0]
            entry["saved_sha256"] = final_identity[1]
            entry["sanitization_rewritten"] = True
            reconciled_in_record += 1

        if document != original_document:
            if record.has_invalid_receipts:
                raise ValueError(
                    "mixed invalid archive receipt record cannot be rewritten "
                    "without changing immutable invalid evidence"
                )
            rendered = (
                json.dumps(document, ensure_ascii=True, indent=2) + "\n"
            ).encode("utf-8")
            if len(rendered) > _ARCHIVE_VALIDATION_RECORD_LIMIT:
                raise ValueError("reconciled archive validation record is oversized")
            evidence_replacements[record.path] = rendered
            reconciled_total += reconciled_in_record
    return reconciled_total


def validate_required_archive_backends() -> None:
    """
    Exercise the frozen Zstandard→TAR→text sanitization path end to end.

    Import success alone is insufficient for PyInstaller packages because the
    Python wrapper can be present while its native backend is absent. This small
    deterministic probe runs at frozen startup and therefore qualifies the exact
    executable bytes and the canonical ``.tar.zst`` contract.

    Raises:
        RuntimeError: If required Zstandard archive backend is unavailable;
            archive backend probe did not sanitize its canary; archive backend
            probe lost its TAR member; or archive backend probe failed
            redaction; or another input invariant is violated.
    """

    if zstandard is None:
        raise RuntimeError("required Zstandard archive backend is unavailable")

    canary = "nvdebug-frozen-zstd-self-check"

    class _CanarySanitizer:
        """
        Implement the canary sanitizer boundary used by the NVDebug runtime.

        The type coordinates ``sanitize`` and retains the state those operations
        share between calls. Resource ownership remains inside the instance
        until the matching close, exit, or cleanup operation completes.
        """

        enabled = True

        @staticmethod
        def sanitize(value: str) -> str:
            """
            Sanitize the supplied value for safe downstream use.

            After applying local validation, the function forwards ``value`` to
            ``value.replace`` and preserves its return and exception contract.
            Filesystem effects remain confined to the caller-selected paths and
            the owning resource lifecycle.

            Args:
                value: Text supplied as value in the format accepted by this
                    function.

            Returns:
                The canonical result text.
            """
            return value.replace(canary, "[REDACTED]")

    try:
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode="w") as archive:
            content = f"credential={canary}\n".encode()
            member = tarfile.TarInfo("probe/credential.txt")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        compressed = zstandard.ZstdCompressor().compress(inner.getvalue())
        sanitized, changed = _sanitize_payload(
            compressed,
            "probe.tar.zst",
            _CanarySanitizer(),
            BundleSanitizationReport(),
            0,
            4,
            BundleSanitizationLimits(),
            _InspectionBudget(),
        )
        if not changed:
            raise RuntimeError("archive backend probe did not sanitize its canary")
        decoded = zstandard.ZstdDecompressor().decompress(sanitized)
        with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
            extracted = archive.extractfile("probe/credential.txt")
            if extracted is None:
                raise RuntimeError("archive backend probe lost its TAR member")
            result = extracted.read()
        if canary.encode() in result or b"[REDACTED]" not in result:
            raise RuntimeError("archive backend probe failed redaction")
    except RuntimeError:
        raise
    except Exception as error:
        raise RuntimeError(
            "required Zstandard archive backend failed its functional self-check"
        ) from error


def _requires_redfish_archive_receipt(root: Path, path: Path) -> bool:
    """
    Return the requires Redfish archive receipt.

    The implementation uses ``root`` and ``path`` to produce the requires
    Redfish archive receipt.

    Args:
        root: filesystem location used as the root for this operation.
        path: filesystem location used as the path for this operation.

    Returns:
        Whether the requires Redfish archive receipt operation succeeds.
    """
    relative = path.relative_to(root)
    parts = relative.parts
    try:
        redfish_index = tuple(part.casefold() for part in parts).index("redfish")
    except ValueError:
        return False
    return redfish_index + 1 < len(parts) and _supported_validation_archive(
        relative.as_posix()
    )


def _snapshot_file(identity: _StableFileIdentity) -> SnapshotFile:
    """
    Return the snapshot file.

    After applying local validation, the function forwards ``identity`` to
    ``SnapshotFile`` and preserves its return and exception contract.

    Args:
        identity: Identity object whose ``ctime_ns``, ``device``, ``inode``,
            ``links``, and ``mode`` state is read while performing snapshot
            file.

    Returns:
        A ``SnapshotFile`` representing snapshot file.
    """
    return SnapshotFile(
        size=identity.size,
        sha256=identity.sha256,
        device=identity.device,
        inode=identity.inode,
        links=identity.links,
        mode=identity.mode,
        mtime_ns=identity.mtime_ns,
        ctime_ns=identity.ctime_ns,
    )


@dataclass
class _ReplacementSpool:
    """
    Implement the replacement spool boundary used by the NVDebug runtime.

    The coherent record keeps ``root``, ``max_files``, ``max_bytes``, ``files``,
    and ``bytes`` together so consumers observe one replacement spool state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        root: Validated filesystem location associated with root.
        max_files: Maximum files admitted by this record.
        max_bytes: Maximum bytes admitted by this record.
        files: Number of files represented by this record.
        bytes: Cumulative byte count represented by this record.
    """

    root: Path
    max_files: int
    max_bytes: int
    files: int = 0
    bytes: int = 0

    def add(self, data: bytes) -> StagedReplacement:
        """
        Add the supplied entry to the owned collection.

        After applying local validation, the function forwards ``data`` to
        ``StagedReplacement`` and preserves its return and exception contract.
        It updates ``bytes`` and ``files`` on the instance as part of that state
        transition. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle. Cleanup in the ``finally`` path
        runs for successful, failed, and cancelled execution.

        Args:
            data: Bounded byte sequence supplied as data.

        Returns:
            A ``StagedReplacement`` returned after add the supplied entry to the
            owned collection.

        Raises:
            ValueError: If bundle rewrite count exceeds its aggregate limit; or
                bundle rewrite bytes exceed their aggregate limit.
            OSError: If short write while spooling bundle replacement.
        """
        if self.files >= self.max_files:
            raise ValueError("bundle rewrite count exceeds its aggregate limit")
        if self.bytes + len(data) > self.max_bytes:
            raise ValueError("bundle rewrite bytes exceed their aggregate limit")
        path = self.root / f"replacement-{self.files:08d}"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(path, flags, 0o600)
        try:
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:])
                if written <= 0:  # pragma: no cover - defensive OS contract guard
                    raise OSError("short write while spooling bundle replacement")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        self.files += 1
        self.bytes += len(data)
        return StagedReplacement(
            path=path,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )


def _sanitize_bound_bundle(
    bundle: _PinnedBundle,
    sanitizer: Any,
    validation_plan: _ArchiveValidationPlan,
    report: BundleSanitizationReport,
    active_limits: BundleSanitizationLimits,
    max_archive_depth: int,
    validated_status_leaf_digests: frozenset[_StatusLeafDigest],
    progress_callback: Callable[[int, int], None] | None,
) -> BundleSanitizationReport:
    """
    Sanitize bound bundle.

    The implementation uses ``bundle``, ``sanitizer``, ``validation_plan``,
    ``report``, and ``active_limits`` to sanitize bound bundle. The operation
    mutates ``report`` in place; ownership of those objects remains with the
    caller. If the function cannot sanitize bound bundle, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        bundle: Bundle object whose ``binding_matches``,
            ``directory_snapshots``, ``entries``, ``path``, and ``root_path``
            state is read while performing sanitize bound bundle.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        validation_plan: Validation plan object whose ``bound_artifacts``,
            ``records``, and ``references`` state is read while performing
            sanitize bound bundle.
        report: Report object whose ``append``, ``errors``,
            ``reconciled_archive_validations``, ``sanitized_files``, and
            ``scanned_files`` state is read while performing sanitize bound
            bundle.
        active_limits: Active limits governing sanitize bound bundle.
        max_archive_depth: Upper bound enforced for max archive depth; the
            consuming boundary rejects or truncates values that exceed it.
        validated_status_leaf_digests: Entries supplied as
            ``validated_status_leaf_digests`` without transferring container
            ownership.
        progress_callback: Callable invoked at the progress callback boundary.

    Returns:
        A ``BundleSanitizationReport`` representing bound bundle.

    Raises:
        ValueError: If bundle files exceed the aggregate byte limit; redfish
            archive has no bound primary validation receipt; the supplied input
            cannot be used to sanitize bound bundle; or archive evidence
            rewrites exceed their aggregate byte limit; or another input
            invariant is violated.
    """
    root_path = bundle.root_path
    immutable_invalid_records = {
        record.path for record in validation_plan.records if record.has_invalid_receipts
    }
    evidence_original = {record.path: record.data for record in validation_plan.records}
    evidence_original.update(
        {record.path: record.data for record in validation_plan.references}
    )
    evidence_replacements: dict[Path, bytes] = {}
    original_identities: dict[Path, _StableFileIdentity] = {}
    rewrites: list[_SanitizedArtifactRewrite] = []
    inspection_budget = _InspectionBudget(
        deadline=time.monotonic() + active_limits.max_seconds
    )
    aggregate_bytes = 0
    evidence_replacement_bytes = 0
    evidence_replacement_limit = min(
        active_limits.max_archive_validation_total_bytes,
        active_limits.max_bundle_rewrite_bytes,
    )

    with tempfile.TemporaryDirectory(prefix="nvdebug-sanitizer-") as spool_name:
        spool = _ReplacementSpool(
            Path(spool_name),
            max_files=active_limits.max_bundle_rewrite_files,
            max_bytes=active_limits.max_bundle_rewrite_bytes,
        )
        replacements: dict[Path, StagedReplacement] = {}
        total_entries = len(bundle.entries)
        for entry_index, entry in enumerate(bundle.entries, start=1):
            path = bundle.path(entry.relative_path)
            if stat.S_ISLNK(entry.mode):
                report.errors.append(
                    sanitizer.sanitize(
                        f"{path}: unsafe symbolic link is not distributable"
                    )
                )
                _advance_sanitization_progress(
                    progress_callback, entry_index, total_entries
                )
                continue
            if stat.S_ISDIR(entry.mode):
                _advance_sanitization_progress(
                    progress_callback, entry_index, total_entries
                )
                continue
            if not stat.S_ISREG(entry.mode):
                report.errors.append(
                    sanitizer.sanitize(
                        f"{path}: unsupported non-regular filesystem entry"
                    )
                )
                _advance_sanitization_progress(
                    progress_callback, entry_index, total_entries
                )
                continue
            report.scanned_files += 1
            try:
                original, original_identity = _read_regular_file_stable_bounded(
                    bundle,
                    path,
                    active_limits.max_top_level_bytes,
                )
                aggregate_bytes += len(original)
                if aggregate_bytes > active_limits.max_bundle_total_bytes:
                    raise ValueError("bundle files exceed the aggregate byte limit")
                original_identities[path] = original_identity
                if (
                    _requires_redfish_archive_receipt(root_path, path)
                    and path not in validation_plan.bound_artifacts
                ):
                    raise ValueError(
                        "Redfish archive has no bound primary validation receipt"
                    )
                with inspection_budget.hold(
                    len(original),
                    label=f"top-level artifact {path.name!r}",
                    limits=active_limits,
                ):
                    sanitized, changed = _sanitize_payload(
                        original,
                        path.name,
                        sanitizer,
                        report,
                        0,
                        max_archive_depth,
                        active_limits,
                        inspection_budget,
                        context=_StructuredDocumentContext(
                            bundle=bundle,
                            artifact_path=path,
                            artifact_size=len(original),
                            artifact_sha256=hashlib.sha256(original).hexdigest(),
                            validated_status_leaf_digests=validated_status_leaf_digests,
                        ),
                    )
                if len(sanitized) > active_limits.max_top_level_bytes:
                    raise ValueError(
                        "sanitized artifact exceeds "
                        f"{active_limits.max_top_level_bytes} bytes: {len(sanitized)}"
                    )
                if not changed:
                    _advance_sanitization_progress(
                        progress_callback, entry_index, total_entries
                    )
                    continue
                if path in immutable_invalid_records:
                    report.errors.append(
                        sanitizer.sanitize(
                            f"{path}: immutable or unbound archive evidence contains "
                            "distributable-sensitive content"
                        )
                    )
                    _advance_sanitization_progress(
                        progress_callback, entry_index, total_entries
                    )
                    continue
                rewrites.append(
                    _SanitizedArtifactRewrite(
                        relative_path=path.relative_to(root_path).as_posix(),
                        before_size=len(original),
                        before_sha256=hashlib.sha256(original).hexdigest(),
                        after_size=len(sanitized),
                        after_sha256=hashlib.sha256(sanitized).hexdigest(),
                    )
                )
                if path in evidence_original:
                    evidence_replacement_bytes += len(sanitized)
                    if evidence_replacement_bytes > evidence_replacement_limit:
                        raise ValueError(
                            "archive evidence rewrites exceed their aggregate byte limit"
                        )
                    evidence_replacements[path] = sanitized
                else:
                    replacements[path] = spool.add(sanitized)
            except Exception as exc:
                report.errors.append(
                    sanitizer.sanitize(f"{path}: {type(exc).__name__}: {exc}")
                )
            _advance_sanitization_progress(
                progress_callback, entry_index, total_entries
            )
        if report.errors:
            return report

        try:
            reconciled_count = _stage_archive_validation_provenance(
                root_path,
                validation_plan,
                rewrites,
                original_identities,
                evidence_replacements,
            )
        except Exception as exc:
            report.errors.append(
                sanitizer.sanitize(
                    f"{root_path}: archive receipt reconciliation failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )
            return report

        if (
            sum(len(data) for data in evidence_replacements.values())
            > evidence_replacement_limit
        ):
            report.errors.append(
                "archive receipt reconciliation exceeds its aggregate byte limit"
            )
            return report

        for path, data in evidence_replacements.items():
            if data != evidence_original[path]:
                replacements[path] = spool.add(data)
        expected = {
            path.relative_to(root_path).as_posix(): _snapshot_file(identity)
            for path, identity in original_identities.items()
        }
        expected_directories = bundle.directory_snapshots()
        if not replacements:
            try:
                if not bundle.binding_matches():
                    raise ValueError("bundle root changed during sanitization")
                validate_unchanged_files(
                    root_path,
                    expected,
                    expected_directories,
                )
            except Exception as exc:
                report.errors.append(
                    sanitizer.sanitize(
                        f"{root_path}: bundle snapshot validation failed: "
                        f"{type(exc).__name__}: {exc}"
                    )
                )
            return report
        # Bind every regular file inspected during this pass, including files
        # whose contents did not require a rewrite.  Otherwise a clean sibling
        # could change after inspection but before publication and the bundle
        # could be reported complete with uninspected bytes.
        staged = {
            path.relative_to(root_path).as_posix(): replacement
            for path, replacement in replacements.items()
        }
        try:
            if not bundle.binding_matches():
                raise ValueError("bundle root changed before transaction publication")
            publish_changed_files(
                root_path,
                expected,
                staged,
                expected_directories,
            )
        except Exception as exc:
            report.errors.append(
                sanitizer.sanitize(
                    f"{root_path}: bundle transaction failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )
            return report
        report.sanitized_files = len(rewrites)
        report.reconciled_archive_validations = reconciled_count
        return report


def _resolve_sanitization_workers(requested: int | None) -> int:
    """
    Resolve the compatibility worker setting without weakening the transaction.

    The pinned sanitizer owns one aggregate inspection budget and publishes all
    replacements in one filesystem transaction. Per-artifact worker writes and
    budgets cannot preserve those guarantees, so concurrent requests fail closed
    until a transaction-aware parallel design is implemented.

    Args:
        requested: Optional requested; ``None`` selects the function's default
            behavior.

    Returns:
        The numeric sanitization workers value.

    Raises:
        ValueError: If the parallel bundle sanitization is unavailable until it
            preserves whole-bundle transaction and aggregate inspection-budget
            guarantees; max_workers are not 1.
    """

    if requested is None:
        return 1
    workers = max(1, int(requested))
    if workers > 1:
        raise ValueError(
            "parallel bundle sanitization is unavailable until it preserves "
            "whole-bundle transaction and aggregate inspection-budget guarantees; "
            "max_workers must be 1"
        )
    return workers


def _advance_sanitization_progress(
    callback: Callable[[int, int], None] | None,
    done: int,
    total: int,
) -> None:
    """
    Report deterministic serial progress without affecting sanitization.

    The implementation uses ``callback``, ``done``, and ``total`` to report
    deterministic serial progress without affecting sanitization.

    Args:
        callback: Callable invoked at the callback boundary.
        done: Numeric done used while the operation performs bounded accounting.
        total: Numeric total used while the operation performs bounded
            accounting.
    """

    if callback is None:
        return
    try:
        callback(done, total)
    except Exception:
        pass


def sanitize_distributable_bundle(
    root: str | Path,
    sanitizer: Any,
    *,
    max_archive_depth: int = 4,
    limits: BundleSanitizationLimits | None = None,
    validated_status_leaf_digests: tuple[_StatusLeafDigest, ...] | None = None,
    max_workers: int | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> BundleSanitizationReport:
    """
    Sanitize text in ``root`` and supported nested archives in place.

    Files which cannot be inspected are left untouched and recorded in
    ``report.errors``. Callers can then surface the incomplete sanitization
    without destroying collected diagnostic evidence.

    Args:
        root: filesystem location used as the root for this operation.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        max_archive_depth: Upper bound enforced for max archive depth; the
            consuming boundary rejects or truncates values that exceed it.
        limits: Optional Limits governing sanitize text in ``root`` and
            supported nested archives in place.
        validated_status_leaf_digests: Optional validated status leaf digests;
            ``None`` selects the function's default behavior.
        max_workers: Upper bound enforced for max workers; the consuming
            boundary rejects or truncates values that exceed it.
        progress_callback: Callable invoked at the progress callback boundary.

    Returns:
        A ``BundleSanitizationReport`` representing distributable bundle.

    Raises:
        ValueError: If the bundle sanitization memory and time limits is not
            positive; or bundle root changed during transaction recovery.
    """
    report = BundleSanitizationReport()
    if not _enabled(sanitizer):
        return report
    try:
        _resolve_sanitization_workers(max_workers)
    except (TypeError, ValueError) as exc:
        report.errors.append(
            sanitizer.sanitize(
                f"{Path(root)}: invalid bundle sanitization worker request: {exc}"
            )
        )
        return report
    active_limits = limits or BundleSanitizationLimits()
    if (
        active_limits.max_resident_bytes <= 0
        or active_limits.max_decompressor_memory_bytes <= 0
        or active_limits.max_seconds <= 0
        or active_limits.max_yaml_nodes <= 0
        or active_limits.max_yaml_aliases <= 0
        or active_limits.max_yaml_depth <= 0
    ):
        raise ValueError("bundle sanitization memory and time limits must be positive")
    status_leaf_digests = _normalize_validated_status_leaf_digests(
        validated_status_leaf_digests
    )

    root_input = Path(root)
    try:
        bundle = _PinnedBundle.open(root_input)
    except Exception as exc:
        report.errors.append(
            sanitizer.sanitize(f"{root_input}: {type(exc).__name__}: {exc}")
        )
        return report

    try:
        root_path = bundle.root_path
        try:
            recover_changed_file_transaction(root_path)
            if not bundle.binding_matches():
                raise ValueError("bundle root changed during transaction recovery")
        except Exception as exc:
            report.errors.append(
                sanitizer.sanitize(
                    f"{root_path}: bundle transaction recovery failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )
            return report

        try:
            bundle.walk(active_limits)
        except Exception as exc:
            report.errors.append(
                sanitizer.sanitize(
                    f"{root_path}: bundle namespace enumeration failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )
            return report

        try:
            validation_plan = _bind_archive_validation_receipts(
                bundle,
                active_limits,
            )
        except Exception as exc:
            report.errors.append(
                sanitizer.sanitize(
                    f"{root_path}: archive receipt binding failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )
            return report

        for record in validation_plan.records:
            try:
                path_is_sensitive = any(
                    sanitizer.sanitize(receipt.artifact_relative_path)
                    != receipt.artifact_relative_path
                    for receipt in record.receipts
                )
            except Exception as exc:
                report.errors.append(
                    "archive filesystem path sensitivity check failed: "
                    f"{type(exc).__name__}"
                )
                path_is_sensitive = True
            if path_is_sensitive:
                report.errors.append(
                    "bound archive filesystem path contains sanitizer-sensitive "
                    "text and cannot be published safely"
                )

        if report.errors:
            return report
        return _sanitize_bound_bundle(
            bundle,
            sanitizer,
            validation_plan,
            report,
            active_limits,
            max_archive_depth,
            status_leaf_digests,
            progress_callback,
        )
    finally:
        bundle.close()
