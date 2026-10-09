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
Fail-closed, resource-bounded extraction for untrusted archives.

This module owns the bounded archive boundary and exposes
``ArchivePolicyError``, ``ArchiveExtractionResult``, ``TarArchiveMember``,
``ArchiveLimits``, and ``_reject_duplicate_archive_limit_override_keys``.
Keeping those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import bz2
import errno
import hashlib
import json
import logging
import lzma
import math
import os
import stat
import struct
import tarfile
import tempfile
import time
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator, Mapping, Optional, Union

from ..utils.filesystem_identity import filesystem_owner_uid

from .archive_member_policy import (
    MemberNamePolicyError,
    validate_distributable_member_name,
)
from .runtime_boundary_profile import (
    DEFAULT_RUNTIME_BOUNDARIES,
    resolve_runtime_boundaries,
)
from .strict_zstd import StrictZstdError, StrictZstdReader

COPY_CHUNK_BYTES = 1024 * 1024
CAPACITY_RECHECK_BYTES = 64 * 1024 * 1024
CAPACITY_RECHECK_NODES = 1024
_ZIP_END_SIGNATURE = b"PK\x05\x06"
_ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
_ZIP64_END_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP_END_BYTES = 22
_ZIP_MAX_COMMENT_BYTES = (1 << 16) - 1
_ZIP_CENTRAL_FIXED_BYTES = 46
_ZIP64_LOCATOR_BYTES = 20
_ZIP64_END_FIXED_BYTES = 56
_ZIP64_MAX_END_RECORD_BYTES = 1024 * 1024
_ZIP_UINT16_MAX = (1 << 16) - 1
_ZIP_UINT32_MAX = (1 << 32) - 1
_COMPRESSED_TAR_HEADER_BYTES = 13
_GZIP_MAGIC = b"\x1f\x8b"
_BZIP2_MAGIC = b"BZh"
_BZIP2_BLOCK_MAGIC = b"1AY&SY"
_BZIP2_END_MAGIC = b"\x17rE8P\x90"
_LZMA_ALONE_TAR_PREFIX = b"\x5d\x00\x00\x80"
_GZIP_DECOMPRESSOR_BYTES = 256 * 1024
_BZIP2_DECOMPRESSOR_OVERHEAD_BYTES = 256 * 1024
_BZIP2_MAX_DECOMPRESSOR_BYTES = (4 * 900_000) + _BZIP2_DECOMPRESSOR_OVERHEAD_BYTES
_ZIP_DECOMPRESSOR_BYTES = {
    zipfile.ZIP_STORED: 0,
    zipfile.ZIP_DEFLATED: _GZIP_DECOMPRESSOR_BYTES,
}
_LZMA1_DECOMPRESSOR_OVERHEAD_BYTES = 1024 * 1024
_LZMA1_BASE_PROBABILITIES = 1846
_LZMA1_LITERAL_PROBABILITIES = 768
_XZ_MAGIC = b"\xfd7zXZ\x00"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_MIB = 1024 * 1024
_GIB = 1024 * _MIB
_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)

ARCHIVE_LIMIT_PROFILE_ENV = "NVDEBUG_ARCHIVE_LIMIT_PROFILE"
ARCHIVE_LIMIT_OVERRIDES_ENV = "NVDEBUG_ARCHIVE_LIMIT_OVERRIDES"
DEFAULT_ARCHIVE_LIMIT_PROFILE = "standard"
_MAX_ARCHIVE_LIMIT_OVERRIDES_BYTES = 16 * 1024
_MAX_OPERATOR_INTEGER_LIMIT = (1 << 63) - 1

logger = logging.getLogger(__name__)


class ArchivePolicyError(ValueError):
    """
    An archive violated a stable extraction policy.

    Callers receive this exception when the archive policy error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """

    def __init__(self, reason: str) -> None:
        """
        Initialize an ``ArchivePolicyError`` instance.

        The initializer records ``reason`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            reason: Text supplied as reason in the format accepted by this
                function.
        """
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ArchiveExtractionResult:
    """
    Structured telemetry for a completed controlled extraction.

    The immutable record keeps ``members``, ``dropped_links``,
    ``dropped_special_members``, and ``regular_files`` together so consumers
    observe one archive extraction state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        members: Number of members represented by this record.
        dropped_links: Number of dropped links represented by this record.
        dropped_special_members: Number of dropped special members represented
            by this record.
        regular_files: Number of regular files represented by this record.
    """

    members: int
    dropped_links: int = 0
    dropped_special_members: int = 0
    regular_files: int = 0

    @property
    def dropped_members(self) -> int:
        """
        Return the total number of safely omitted archive members.

        Each access computes the value from ``dropped_links`` and
        ``dropped_special_members`` on the current instance; the derived view is
        not stored as independent state.

        Returns:
            The numeric dropped members value.
        """
        return self.dropped_links + self.dropped_special_members


@dataclass(frozen=True)
class TarArchiveMember:
    """
    Immutable metadata exposed during bounded TAR inspection.

    The immutable record keeps ``name``, ``size``, ``mtime``, ``mode``,
    ``kind``, and ``original_name`` together so consumers observe one TAR
    archive member state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        name: Canonical text used as name.
        size: Cumulative byte count represented by this record.
        mtime: Mtime retained as part of the record's public state.
        mode: Numeric mode retained by this record.
        kind: Container-kind discriminator.
        link_kind: Link subtype when ``kind`` is ``link``; otherwise ``None``.
        duplicate: Whether duplicate applies to this record.
        original_name: Bounded producer-supplied name before compatibility
            normalization.
    """

    name: str
    size: int
    mtime: Any
    mode: int
    kind: str = "file"
    link_kind: Optional[str] = None
    duplicate: bool = False
    original_name: str = ""


@dataclass(frozen=True)
class TarArchiveRewriteResult:
    """
    Record source and rewritten validation for a link-free TAR artifact.

    The immutable record binds the fully scanned source accounting to the
    independently validated rewritten archive. Callers can therefore preserve
    controlled-drop telemetry without treating output creation alone as proof
    that every source byte was admitted.

    Attributes:
        source: Validation accounting for the complete untrusted source TAR.
        rewritten: Validation accounting for the regular-file-only gzip TAR.
    """

    source: ArchiveExtractionResult
    rewritten: ArchiveExtractionResult


@dataclass(frozen=True)
class ArchiveLimits:
    """
    Resource limits applied before and during extraction.

    The immutable record keeps ``max_members``, ``max_member_bytes``,
    ``max_total_bytes``, ``max_metadata_bytes``, and
    ``max_metadata_member_bytes`` together so consumers observe one archive
    state. Construction validates cross-field invariants before the instance is
    exposed.

    Attributes:
        max_members: Maximum members admitted by this record.
        max_member_bytes: Maximum member bytes admitted by this record.
        max_total_bytes: Maximum total bytes admitted by this record.
        max_metadata_bytes: Maximum metadata bytes admitted by this record.
        max_metadata_member_bytes: Maximum metadata member bytes admitted by
            this record.
        max_zip_central_directory_bytes: Maximum ZIP central directory bytes
            admitted by this record.
        max_path_nodes: Maximum path nodes admitted by this record.
        max_tracked_path_bytes: Maximum tracked path bytes admitted by this
            record.
        max_compression_ratio: Maximum compression ratio admitted by this
            record.
        max_path_depth: Maximum path depth admitted by this record.
        max_input_bytes: Maximum input bytes admitted by this record.
        max_decompressor_memory_bytes: Maximum decompressor memory bytes
            admitted by this record.
        max_seconds: Maximum seconds admitted by this record.
        disk_reserve_bytes: Byte count recorded for disk reserve.
        inode_reserve: Numeric inode reserve retained by this record.
    """

    max_members: int = 100_000
    max_member_bytes: int = 512 * _MIB
    max_total_bytes: int = 2 * _GIB
    max_metadata_bytes: int = 64 * _MIB
    max_metadata_member_bytes: int = 8 * _MIB
    max_zip_central_directory_bytes: int = 64 * _MIB
    max_path_nodes: int = 250_000
    max_tracked_path_bytes: int = 128 * _MIB
    max_compression_ratio: float = 1000.0
    max_path_depth: int = 64
    max_input_bytes: int = 4 * _GIB
    max_decompressor_memory_bytes: int = 256 * _MIB
    max_seconds: float = 900.0
    disk_reserve_bytes: int = 512 * _MIB
    inode_reserve: int = 4_096

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized ArchiveLimits state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            ValueError: If the archive integer limits is not positive; the
                archive compression ratio is not positive and finite; the
                archive time limit is not positive and finite; or archive member
                limit cannot exceed total limit; or another input invariant is
                violated.
        """
        integers = (
            self.max_members,
            self.max_member_bytes,
            self.max_total_bytes,
            self.max_metadata_bytes,
            self.max_metadata_member_bytes,
            self.max_zip_central_directory_bytes,
            self.max_path_nodes,
            self.max_tracked_path_bytes,
            self.max_path_depth,
            self.max_input_bytes,
            self.max_decompressor_memory_bytes,
            self.disk_reserve_bytes,
            self.inode_reserve,
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in integers
        ):
            raise ValueError("Archive integer limits must be positive")
        if (
            not math.isfinite(self.max_compression_ratio)
            or self.max_compression_ratio <= 0
        ):
            raise ValueError("Archive compression ratio must be positive and finite")
        if not math.isfinite(self.max_seconds) or self.max_seconds <= 0:
            raise ValueError("Archive time limit must be positive and finite")
        if self.max_member_bytes > self.max_total_bytes:
            raise ValueError("Archive member limit cannot exceed total limit")
        if self.max_metadata_member_bytes > self.max_metadata_bytes:
            raise ValueError(
                "Archive metadata record limit cannot exceed metadata limit"
            )


STANDARD_ARCHIVE_LIMITS = ArchiveLimits()
LARGE_ARCHIVE_LIMITS = ArchiveLimits(
    max_members=250_000,
    max_member_bytes=2 * _GIB,
    max_total_bytes=8 * _GIB,
    max_metadata_bytes=256 * _MIB,
    max_metadata_member_bytes=16 * _MIB,
    max_zip_central_directory_bytes=512 * _MIB,
    max_path_nodes=500_000,
    max_tracked_path_bytes=256 * _MIB,
    max_input_bytes=32 * _GIB,
    max_decompressor_memory_bytes=512 * _MIB,
    max_seconds=1800.0,
    disk_reserve_bytes=512 * _MIB,
    inode_reserve=4_096,
)
XLARGE_ARCHIVE_LIMITS = ArchiveLimits(
    max_members=1_000_000,
    max_member_bytes=32 * _GIB,
    max_total_bytes=128 * _GIB,
    max_metadata_bytes=1 * _GIB,
    max_metadata_member_bytes=256 * _MIB,
    max_zip_central_directory_bytes=2 * _GIB,
    max_path_nodes=2_000_000,
    max_tracked_path_bytes=1 * _GIB,
    max_input_bytes=256 * _GIB,
    max_decompressor_memory_bytes=1 * _GIB,
    max_seconds=3600.0,
    disk_reserve_bytes=512 * _MIB,
    inode_reserve=4_096,
)
HARD_ARCHIVE_LIMITS = XLARGE_ARCHIVE_LIMITS
DEFAULT_ARCHIVE_LIMITS = STANDARD_ARCHIVE_LIMITS
COLLECTION_ARCHIVE_LIMITS = XLARGE_ARCHIVE_LIMITS
OPERATOR_ARCHIVE_LIMIT_CEILING = replace(
    XLARGE_ARCHIVE_LIMITS,
    max_members=8_000_000,
    max_member_bytes=256 * _GIB,
    max_total_bytes=1024 * _GIB,
    max_metadata_bytes=8 * _GIB,
    max_metadata_member_bytes=1 * _GIB,
    max_zip_central_directory_bytes=8 * _GIB,
    max_path_nodes=16_000_000,
    max_tracked_path_bytes=8 * _GIB,
    max_input_bytes=2048 * _GIB,
)

_ARCHIVE_CREATION_BOUNDARY_KEYS = {
    "max_members": "finalization_archive_max_members",
    "max_member_bytes": "finalization_archive_max_member_bytes",
    "max_total_bytes": "finalization_archive_max_total_bytes",
    "max_metadata_bytes": "finalization_archive_max_metadata_bytes",
    "max_metadata_member_bytes": "finalization_archive_max_metadata_member_bytes",
    "max_zip_central_directory_bytes": (
        "finalization_archive_max_zip_central_directory_bytes"
    ),
    "max_path_nodes": "finalization_archive_max_path_nodes",
    "max_tracked_path_bytes": "finalization_archive_max_tracked_path_bytes",
    "max_input_bytes": "finalization_archive_max_input_bytes",
    "max_decompressor_memory_bytes": (
        "finalization_archive_max_decompressor_memory_bytes"
    ),
    "max_seconds": "finalization_archive_max_seconds",
    "disk_reserve_bytes": "finalization_archive_disk_reserve_bytes",
    "inode_reserve": "finalization_archive_inode_reserve",
}


def _archive_creation_limits_from_resolved_boundaries(
    boundaries: Mapping[str, int],
) -> ArchiveLimits:
    """
    Project resolved catalog values into one archive creation policy.

    Fields intentionally absent from the catalog retain the strict structural
    defaults defined by :class:`ArchiveLimits`.

    Args:
        boundaries: Complete validated runtime boundary mapping.

    Returns:
        The projected finite archive creation limits.
    """
    return ArchiveLimits(
        **{
            field_name: boundaries[boundary_name]
            for field_name, boundary_name in _ARCHIVE_CREATION_BOUNDARY_KEYS.items()
        }
    )


# These are compatibility defaults and hard safety ceilings, not operator
# profiles. Live runs receive their operational values from the catalog.
HARD_ARCHIVE_CREATION_LIMITS = _archive_creation_limits_from_resolved_boundaries(
    DEFAULT_RUNTIME_BOUNDARIES
)
DEFAULT_ARCHIVE_CREATION_LIMITS = HARD_ARCHIVE_CREATION_LIMITS

_LIMIT_FIELDS = (
    "max_members",
    "max_member_bytes",
    "max_total_bytes",
    "max_metadata_bytes",
    "max_metadata_member_bytes",
    "max_zip_central_directory_bytes",
    "max_path_nodes",
    "max_tracked_path_bytes",
    "max_compression_ratio",
    "max_path_depth",
    "max_input_bytes",
    "max_decompressor_memory_bytes",
    "max_seconds",
)
_OPERATOR_OVERRIDABLE_INTEGER_LIMITS = frozenset(
    {
        "max_members",
        "max_member_bytes",
        "max_total_bytes",
        "max_metadata_bytes",
        "max_metadata_member_bytes",
        "max_zip_central_directory_bytes",
        "max_path_nodes",
        "max_tracked_path_bytes",
        "max_input_bytes",
    }
)


def _reject_duplicate_archive_limit_override_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    """
    Reject duplicate archive limit override keys.

    The implementation uses ``pairs`` to reject duplicate archive limit override
    keys. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        pairs: Entries supplied as ``pairs`` without transferring container
            ownership.

    Returns:
        The validated ``document``.

    Raises:
        ValueError: If duplicate archive limit override: ``name``.
    """
    document: dict[str, object] = {}
    for name, value in pairs:
        if name in document:
            raise ValueError(f"duplicate archive limit override: {name}")
        document[name] = value
    return document


def _archive_limit_overrides_from_environment() -> dict[str, int]:
    """
    Parse explicit finite capacity overrides from one JSON environment key.

    The implementation uses current instance state to parse explicit finite
    capacity overrides from one JSON environment key. Parsing or I/O must finish
    before the validated representation is made available to the caller. If the
    function cannot parse explicit finite capacity overrides from one JSON
    environment key, its exception reaches the caller instead of being converted
    into a successful result.

    Returns:
        A mapping containing archive limit overrides from environment.

    Raises:
        ValueError: If archive limit override document is too large.
        ArchivePolicyError: If invalid_limit_override.
    """
    raw = os.environ.get(ARCHIVE_LIMIT_OVERRIDES_ENV)
    if raw is None or not raw.strip():
        return {}
    try:
        if len(raw.encode("utf-8")) > _MAX_ARCHIVE_LIMIT_OVERRIDES_BYTES:
            raise ValueError("archive limit override document is too large")
        parsed = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_archive_limit_override_keys,
        )
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise ArchivePolicyError("invalid_limit_override") from error
    if not isinstance(parsed, dict):
        raise ArchivePolicyError("invalid_limit_override")

    overrides: dict[str, int] = {}
    for name, value in parsed.items():
        if name not in _OPERATOR_OVERRIDABLE_INTEGER_LIMITS:
            raise ArchivePolicyError("invalid_limit_override")
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
            or value > _MAX_OPERATOR_INTEGER_LIMIT
        ):
            raise ArchivePolicyError("invalid_limit_override")
        overrides[name] = value
    return overrides


def resolve_archive_limits(
    limits: Optional[ArchiveLimits] = None,
    *,
    default_limits: Optional[ArchiveLimits] = None,
) -> ArchiveLimits:
    """
    Resolve and validate one per-call archive policy.

    The optional ``default_limits`` lets a bounded subsystem select a stricter
    or roomier reviewed baseline without changing the repository-wide inbound
    archive default. An explicit environment profile always wins, and finite
    environment overrides are layered onto whichever default or named profile
    was selected. Filesystem effects remain confined to caller-owned paths.

    Args:
        limits: Optional Limits governing and validate one per-call archive
            policy.
        default_limits: Optional baseline used only when ``limits`` and the
            profile environment variable are both absent.

    Returns:
        The validated ``limits``.

    Raises:
        ArchivePolicyError: If invalid_limit_profile; invalid_limit_override;
            archive_limit_ceiling; or archive_reserve_floor.
        TypeError: If either supplied limit value is not an
            ``ArchiveLimits`` instance; or both values are supplied.
    """
    if limits is not None and default_limits is not None:
        raise TypeError("limits and default_limits cannot both be supplied")
    if default_limits is not None and not isinstance(default_limits, ArchiveLimits):
        raise TypeError("default_limits must be an ArchiveLimits instance")
    if limits is None:
        profile = os.environ.get(ARCHIVE_LIMIT_PROFILE_ENV)
        if profile is None:
            limits = (
                default_limits
                if default_limits is not None
                else STANDARD_ARCHIVE_LIMITS
            )
            if default_limits is not None and any(
                getattr(default_limits, field_name)
                > getattr(HARD_ARCHIVE_LIMITS, field_name)
                for field_name in _LIMIT_FIELDS
            ):
                raise ArchivePolicyError("archive_limit_ceiling")
        else:
            normalized = profile.strip().casefold()
            if normalized == "standard":
                limits = STANDARD_ARCHIVE_LIMITS
            elif normalized == "large":
                limits = LARGE_ARCHIVE_LIMITS
            elif normalized == "xlarge":
                limits = XLARGE_ARCHIVE_LIMITS
            else:
                raise ArchivePolicyError("invalid_limit_profile")
        overrides = _archive_limit_overrides_from_environment()
        if overrides:
            try:
                limits = replace(limits, **overrides)
            except ValueError as error:
                raise ArchivePolicyError("invalid_limit_override") from error
        from_environment = True
    elif not isinstance(limits, ArchiveLimits):
        raise TypeError("limits must be an ArchiveLimits instance")
    else:
        from_environment = False

    ceiling = (
        OPERATOR_ARCHIVE_LIMIT_CEILING if from_environment else HARD_ARCHIVE_LIMITS
    )
    if any(
        getattr(limits, field_name) > getattr(ceiling, field_name)
        for field_name in _LIMIT_FIELDS
    ):
        raise ArchivePolicyError("archive_limit_ceiling")
    if (
        limits.disk_reserve_bytes < STANDARD_ARCHIVE_LIMITS.disk_reserve_bytes
        or limits.inode_reserve < STANDARD_ARCHIVE_LIMITS.inode_reserve
    ):
        raise ArchivePolicyError("archive_reserve_floor")
    return limits


def resolve_collection_archive_limits() -> ArchiveLimits:
    """
    Return the fixed finite policy for tool-created collection archives.

    Live Host and BMC collectors create archives from an authenticated DUT and
    must not silently inherit the smaller inbound-archive profile selected for
    offline parsing. Collection size expectations are operational warning
    thresholds owned by the services; this policy is the independent hard
    safety boundary used for complete transfer, validation, and persistence.
    Explicitly resolving the reviewed xlarge policy also prevents ambient
    environment profile settings from truncating an otherwise complete live
    collection.

    Returns:
        The validated finite xlarge collection archive limits.
    """

    return resolve_archive_limits(COLLECTION_ARCHIVE_LIMITS)


def _format_collection_archive_byte_count(value: int) -> str:
    """
    Format one validated collection byte count for a runtime advisory.

    Large values include a two-decimal binary-unit projection while retaining
    the exact byte count needed for support and policy diagnostics. Small test
    and boundary values remain readable without a misleading zero-unit prefix.

    Args:
        value: Positive byte count already validated by the caller.

    Returns:
        The human-readable and exact byte-count text.
    """

    if value >= _GIB:
        return f"{value / _GIB:.2f} GiB ({value} bytes)"
    if value >= _MIB:
        return f"{value / _MIB:.2f} MiB ({value} bytes)"
    return f"{value} bytes"


def collection_archive_size_advisory(
    expected_bytes: int,
    observed_bytes: int,
    hard_limit_bytes: int,
) -> Optional[str]:
    """
    Describe a safe collection that exceeded its expected archive size.

    The expected value is deliberately advisory. The returned message makes
    clear that collection continues without threshold-driven truncation while
    retaining a separate finite hard ceiling. Callers must reject values above
    that hard ceiling before requesting an advisory.

    Args:
        expected_bytes: Operational size at which the collector should warn.
        observed_bytes: Complete archive size observed by the collector.
        hard_limit_bytes: Finite safety ceiling enforced by the collector.

    Returns:
        A runtime-log advisory when the expectation was exceeded, otherwise
        ``None``.

    Raises:
        ValueError: If a byte count is not a positive integer, the expected
            threshold exceeds the hard ceiling, or the observed archive is
            already outside the hard ceiling.
    """

    values = (expected_bytes, observed_bytes, hard_limit_bytes)
    if any(type(value) is not int or value <= 0 for value in values):
        raise ValueError("collection archive byte counts must be positive integers")
    if expected_bytes > hard_limit_bytes:
        raise ValueError("collection archive expectation exceeds its hard ceiling")
    if observed_bytes > hard_limit_bytes:
        raise ValueError("collection archive exceeds its hard ceiling")
    if observed_bytes <= expected_bytes:
        return None
    return (
        "Collection archive exceeded its expected size threshold "
        f"(expected {_format_collection_archive_byte_count(expected_bytes)}; "
        f"observed {_format_collection_archive_byte_count(observed_bytes)}). "
        "Capture is continuing under the finite "
        f"{_format_collection_archive_byte_count(hard_limit_bytes)} safety "
        "ceiling; the expected threshold does not truncate the artifact."
    )


def resolve_archive_creation_limits(
    limits: Optional[ArchiveLimits] = None,
) -> ArchiveLimits:
    """
    Resolve limits for a tool-owned local bundle or report tree.

    Extraction defaults stay deliberately small because downloaded archives are
    untrusted.  A completed collection tree is already present on local disk and
    routinely grows well beyond those extraction defaults, especially for rack
    and L3 runs. Live callers pass the catalog-resolved policy explicitly;
    offline callers use the finite compatibility default.

    Args:
        limits: Optional explicit local-creation limits; ``None`` selects the
            code-owned compatibility default.

    Returns:
        The validated finite limits for trusted local archive creation.

    Raises:
        ArchivePolicyError: If the limit ceiling or reserve floor is invalid.
        TypeError: If ``limits`` is not an ``ArchiveLimits`` instance.
    """

    if limits is None:
        limits = DEFAULT_ARCHIVE_CREATION_LIMITS
    elif not isinstance(limits, ArchiveLimits):
        raise TypeError("limits must be an ArchiveLimits instance")

    if any(
        getattr(limits, field_name) > getattr(HARD_ARCHIVE_CREATION_LIMITS, field_name)
        for field_name in _LIMIT_FIELDS
    ):
        raise ArchivePolicyError("archive_creation_limit_ceiling")
    if (
        limits.disk_reserve_bytes < STANDARD_ARCHIVE_LIMITS.disk_reserve_bytes
        or limits.inode_reserve < STANDARD_ARCHIVE_LIMITS.inode_reserve
    ):
        raise ArchivePolicyError("archive_reserve_floor")
    return limits


def archive_creation_limits_from_runtime_boundaries(
    boundaries: Mapping[str, Any] | None,
) -> ArchiveLimits:
    """
    Build validated local-creation limits from catalog-resolved values.

    Partial and absent mappings inherit compatibility defaults. Catalog values
    are validated against the code-owned range before projection.

    Args:
        boundaries: Optional partial or complete runtime boundary mapping.

    Returns:
        The validated finite local archive creation limits.
    """

    resolved = resolve_runtime_boundaries(
        None,
        boundaries if isinstance(boundaries, Mapping) else {},
    )
    return resolve_archive_creation_limits(
        _archive_creation_limits_from_resolved_boundaries(resolved)
    )


_PATH_EXPLICIT = 1
_PATH_REGULAR = 2
_PATH_HAS_CHILDREN = 4
_PATH_OUTPUT = 8
_PATH_ENTRY_STATE_BYTES = 64


@dataclass
class _PathEntry:
    """
    Implement the path entry boundary used by the NVDebug runtime.

    The coherent record keeps ``flags``, ``fingerprint``, ``content_digest``,
    and ``content_digest_reserved`` together so consumers observe one path entry
    state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        flags: Number of flags represented by this record.
        fingerprint: Collection of fingerprint entries retained by this record.
        content_digest: Bounded byte sequence retained as content digest.
        content_digest_reserved: Whether content digest reserved applies to this
            record.
    """

    flags: int
    fingerprint: Optional[tuple[object, ...]] = None
    content_digest: Optional[bytes] = None
    content_digest_reserved: bool = False


@dataclass
class _PathRegistry:
    """
    Manage path registry operations for the NVDebug runtime.

    The coherent record keeps ``entries``, ``tracked_bytes``, and
    ``output_nodes`` together so consumers observe one path registry state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        entries: Mapping that retains the entries fields for this record.
        tracked_bytes: Byte count recorded for tracked.
        output_nodes: Number of output nodes represented by this record.
    """

    entries: dict[str, _PathEntry] = field(default_factory=dict)
    tracked_bytes: int = 0
    output_nodes: int = 0

    @property
    def unique_nodes(self) -> int:
        """
        Return the unique nodes.

        Each access computes the value from ``entries`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            The numeric unique nodes value.
        """
        return len(self.entries)

    def _charge_tracked_bytes(self, amount: int, limits: ArchiveLimits) -> None:
        """
        Charge tracked bytes.

        The implementation uses ``amount`` and ``limits`` to charge tracked
        bytes. It updates ``tracked_bytes`` on the instance as part of that
        state transition. If the function cannot charge tracked bytes, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            amount: Numeric amount used while the operation performs bounded
                accounting.
            limits: Limits governing charge tracked bytes.

        Raises:
            ArchivePolicyError: If path_bytes_limit.
        """
        if self.tracked_bytes + amount > limits.max_tracked_path_bytes:
            raise ArchivePolicyError("path_bytes_limit")
        self.tracked_bytes += amount

    def _add_flags(
        self,
        path: str,
        flags: int,
        limits: ArchiveLimits,
    ) -> None:
        """
        Add flags.

        The implementation uses ``path``, ``flags``, and ``limits`` to add
        flags. It updates ``output_nodes`` on the instance as part of that state
        transition. If the function cannot add flags, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            path: filesystem location used as the path for this operation.
            flags: Numeric flags used while the operation performs bounded
                accounting.
            limits: Limits governing add flags.

        Raises:
            ArchivePolicyError: If path_node_limit.
        """
        current = self.entries.get(path)
        if current is not None:
            if flags & _PATH_OUTPUT and not current.flags & _PATH_OUTPUT:
                self.output_nodes += 1
            current.flags |= flags
            return

        encoded_bytes = len(path.encode("utf-8", errors="surrogateescape"))
        if self.unique_nodes + 1 > limits.max_path_nodes:
            raise ArchivePolicyError("path_node_limit")
        self._charge_tracked_bytes(
            encoded_bytes + _PATH_ENTRY_STATE_BYTES,
            limits,
        )
        self.entries[path] = _PathEntry(flags)
        if flags & _PATH_OUTPUT:
            self.output_nodes += 1

    def register(
        self,
        parts: tuple[str, ...],
        *,
        directory: bool,
        limits: ArchiveLimits,
        output: bool = True,
        fingerprint: Optional[tuple[object, ...]] = None,
    ) -> bool:
        """
        Return the register.

        The implementation uses ``parts``, ``directory``, ``limits``,
        ``output``, and ``fingerprint`` to produce the register. If the function
        cannot produce the register, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            parts: Entries supplied as ``parts`` without transferring container
                ownership.
            directory: filesystem location used as the directory for this
                operation.
            limits: Limits governing register.
            output: Whether output is enabled or required for this operation.
            fingerprint: Optional fingerprint; ``None`` selects the function's
                default behavior.

        Returns:
            Whether the register operation succeeds.

        Raises:
            ArchivePolicyError: If duplicate_member; or
                file_directory_collision.
        """
        normalized = "/".join(parts)
        current = self.entries.get(normalized)
        if current is not None and current.flags & _PATH_EXPLICIT:
            if (
                fingerprint is None
                or current.fingerprint is None
                or current.fingerprint != fingerprint
            ):
                raise ArchivePolicyError("duplicate_member")
            return False
        if not directory and current is not None and current.flags & _PATH_HAS_CHILDREN:
            raise ArchivePolicyError("file_directory_collision")

        for index in range(1, len(parts)):
            prefix = "/".join(parts[:index])
            prefix_entry = self.entries.get(prefix)
            if prefix_entry is not None and prefix_entry.flags & _PATH_REGULAR:
                raise ArchivePolicyError("file_directory_collision")

        for index in range(1, len(parts)):
            prefix = "/".join(parts[:index])
            flags = _PATH_HAS_CHILDREN
            if output:
                flags |= _PATH_OUTPUT
            self._add_flags(prefix, flags, limits)
        flags = _PATH_EXPLICIT
        if not directory:
            flags |= _PATH_REGULAR
        if output:
            flags |= _PATH_OUTPUT
        self._add_flags(normalized, flags, limits)
        fingerprint_bytes = sum(
            (
                len(value)
                if isinstance(value, bytes)
                else (
                    len(value.encode("utf-8", errors="surrogateescape"))
                    if isinstance(value, str)
                    else 8
                )
            )
            for value in fingerprint or ()
        )
        self._charge_tracked_bytes(fingerprint_bytes, limits)
        self.entries[normalized].fingerprint = fingerprint
        return True

    def record_content_digest(
        self,
        parts: tuple[str, ...],
        digest: bytes,
        *,
        duplicate: bool,
        limits: ArchiveLimits,
    ) -> None:
        """
        Record content digest.

        The implementation uses ``parts``, ``digest``, ``duplicate``, and
        ``limits`` to record content digest. If the function cannot record
        content digest, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            parts: Entries supplied as ``parts`` without transferring container
                ownership.
            digest: Bounded byte sequence supplied as digest.
            duplicate: Whether duplicate is enabled or required for this
                operation.
            limits: Limits governing record content digest.

        Raises:
            ArchivePolicyError: If duplicate_member.
        """
        entry = self.entries["/".join(parts)]
        if duplicate:
            if entry.content_digest != digest:
                raise ArchivePolicyError("duplicate_member")
            return
        if entry.content_digest is not None:
            raise ArchivePolicyError("duplicate_member")
        if not entry.content_digest_reserved:
            self._charge_tracked_bytes(len(digest), limits)
            entry.content_digest_reserved = True
        entry.content_digest = digest

    def reserve_content_digest(
        self,
        parts: tuple[str, ...],
        *,
        limits: ArchiveLimits,
    ) -> None:
        """
        Charge digest storage during preflight, before extraction writes.

        The implementation uses ``parts`` and ``limits`` to charge digest
        storage during preflight, before extraction writes.

        Args:
            parts: Entries supplied as ``parts`` without transferring container
                ownership.
            limits: Limits governing charge digest storage during preflight,
                before extraction writes.
        """
        entry = self.entries["/".join(parts)]
        if entry.content_digest_reserved:
            return
        self._charge_tracked_bytes(hashlib.sha256().digest_size, limits)
        entry.content_digest_reserved = True


@dataclass
class _CreatedEntry:
    """
    Implement the created entry boundary used by the NVDebug runtime.

    The coherent record keeps ``path``, ``identity``, and ``is_directory``
    together so consumers observe one created entry state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        identity: Collection of identity entries retained by this record.
        is_directory: Whether directory applies to this record.
    """

    path: Path
    identity: tuple[int, int]
    is_directory: bool


@dataclass
class _DestinationRoot:
    """
    Implement the destination root boundary used by the NVDebug runtime.

    The coherent record keeps ``path``, ``descriptor``, and ``identity``
    together so consumers observe one destination root state. Consumers receive
    the fields as one unit instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        descriptor: Numeric descriptor retained by this record.
        identity: Collection of identity entries retained by this record.
    """

    path: Path
    descriptor: int
    identity: tuple[int, int]


@dataclass
class _ExtractionState:
    """
    Represent extraction state data exchanged by the runtime.

    The coherent record keeps ``created``, ``total_bytes``, and
    ``processed_nodes`` together so consumers observe one extraction state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        created: Collection of created entries retained by this record.
        total_bytes: Byte count recorded for total.
        processed_nodes: Number of processed nodes represented by this record.
    """

    created: list[_CreatedEntry] = field(default_factory=list)
    total_bytes: int = 0
    processed_nodes: int = 0


@dataclass
class _TarState:
    """
    Represent TAR state data exchanged by the runtime.

    The coherent record keeps ``paths``, ``members``, ``total_bytes``,
    ``output_bytes``, and ``regular_files`` together so consumers observe one
    TAR state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        paths: Canonical text used as paths.
        members: Number of members represented by this record.
        total_bytes: Byte count recorded for total.
        output_bytes: Byte count recorded for output.
        regular_files: Number of regular files represented by this record.
        dropped_links: Number of dropped links represented by this record.
        dropped_special_members: Number of dropped special members represented
            by this record.
        sequence_hasher: Sequence hasher retained as part of the record's public
            state.
    """

    paths: _PathRegistry = field(default_factory=_PathRegistry)
    members: int = 0
    total_bytes: int = 0
    output_bytes: int = 0
    regular_files: int = 0
    dropped_links: int = 0
    dropped_special_members: int = 0
    sequence_hasher: Any = field(default_factory=hashlib.sha256, repr=False)


@dataclass(frozen=True)
class _TarMemberPlan:
    """
    Implement the TAR member plan boundary used by the NVDebug runtime.

    The immutable record keeps ``parts``, ``kind``, ``duplicate``,
    ``fingerprint``, and ``output`` together so consumers observe one TAR member
    plan state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        parts: Collection of parts entries retained by this record.
        kind: Container-kind discriminator.
        duplicate: Whether duplicate applies to this record.
        fingerprint: Collection of fingerprint entries retained by this record.
        output: Whether output applies to this record.
    """

    parts: tuple[str, ...]
    kind: str
    duplicate: bool
    fingerprint: tuple[object, ...]
    output: bool


@dataclass(frozen=True)
class _ArchiveSummary:
    """
    Implement the archive summary boundary used by the NVDebug runtime.

    The immutable record keeps ``members``, ``total_bytes``, ``output_bytes``,
    ``path_nodes``, and ``tracked_path_bytes`` together so consumers observe one
    archive summary state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        members: Number of members represented by this record.
        total_bytes: Byte count recorded for total.
        output_bytes: Byte count recorded for output.
        path_nodes: Number of path nodes represented by this record.
        tracked_path_bytes: Byte count recorded for tracked path.
        regular_files: Number of regular files represented by this record.
        dropped_links: Number of dropped links represented by this record.
        dropped_special_members: Number of dropped special members represented
            by this record.
        member_fingerprint: Bounded byte sequence retained as member
            fingerprint.
    """

    members: int
    total_bytes: int
    output_bytes: int
    path_nodes: int
    tracked_path_bytes: int
    regular_files: int = 0
    dropped_links: int = 0
    dropped_special_members: int = 0
    member_fingerprint: bytes = b""


def _extraction_result(summary: _ArchiveSummary) -> ArchiveExtractionResult:
    """
    Return the extraction result.

    After applying local validation, the function forwards ``summary`` to
    ``ArchiveExtractionResult`` and preserves its return and exception contract.

    Args:
        summary: Summary object whose ``dropped_links``,
            ``dropped_special_members``, ``members``, and ``regular_files``
            state is read while performing extraction result.

    Returns:
        An ``ArchiveExtractionResult`` representing extraction result.
    """
    return ArchiveExtractionResult(
        members=summary.members,
        regular_files=summary.regular_files,
        dropped_links=summary.dropped_links,
        dropped_special_members=summary.dropped_special_members,
    )


def _report_controlled_drops(result: ArchiveExtractionResult) -> None:
    """
    Report archive members dropped by the bounded policy.

    The implementation uses ``result`` to report archive members dropped by the
    bounded policy.

    Args:
        result: Result object whose ``dropped_links``, ``dropped_members``, and
            ``dropped_special_members`` state is read while performing report
            archive members dropped by the bounded policy.
    """
    if not result.dropped_members:
        return
    logger.warning(
        "archive.controlled_member_drop: skipped %d unsupported member(s) "
        "(links=%d, other_special=%d)",
        result.dropped_members,
        result.dropped_links,
        result.dropped_special_members,
    )


@dataclass
class _ZipValidation:
    """
    Implement the ZIP validation boundary used by the NVDebug runtime.

    The coherent record keeps ``entries``, ``summary``, and ``paths`` together
    so consumers observe one ZIP validation state. Consumers receive the fields
    as one unit instead of assembling partial state.

    Attributes:
        entries: Whether entries applies to this record.
        summary: Summary retained as part of the record's public state.
        paths: Canonical text used as paths.
    """

    entries: list[tuple[zipfile.ZipInfo, tuple[str, ...], bool, int, bool]]
    summary: _ArchiveSummary
    paths: _PathRegistry


@dataclass
class _TarMetadataBudget:
    """
    Implement the TAR metadata budget boundary used by the NVDebug runtime.

    The coherent record keeps ``bytes`` and ``extended_headers`` together so
    consumers observe one TAR metadata budget state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        bytes: Cumulative byte count represented by this record.
        extended_headers: Number of extended headers represented by this record.
    """

    bytes: int = 0
    extended_headers: int = 0


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    """
    Return the identity.

    The implementation uses ``metadata`` to produce the identity.

    Args:
        metadata: Metadata object whose ``st_dev`` and ``st_ino`` state is read
            while performing identity.

    Returns:
        A tuple containing ``st dev`` and ``st ino`` in that order.
    """
    return metadata.st_dev, metadata.st_ino


def _source_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    """
    Return the source fingerprint.

    The implementation uses ``metadata`` to produce the source fingerprint.

    Args:
        metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing
            source fingerprint.

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


def _assert_source_unchanged(
    stream: BinaryIO,
    metadata: os.stat_result,
    *,
    path: Optional[Path] = None,
) -> None:
    """
    Verify that a pinned source and its optional path remain unchanged.

    Descriptor fingerprints detect in-place mutation. When a path is available,
    its device and inode are also matched to the descriptor so atomic replacement
    cannot depend on filesystem-specific unlink timestamp behavior.

    Args:
        stream: Open source stream whose descriptor identity is verified.
        metadata: Metadata captured immediately after opening the source.
        path: Optional filesystem path that must still name the open source.

    Raises:
        ArchivePolicyError: If the descriptor changed or the path no longer
            names the pinned source.
    """
    try:
        current = os.fstat(stream.fileno())
        current_path = path.lstat() if path is not None else None
    except (AttributeError, OSError, ValueError) as error:
        raise ArchivePolicyError("source_changed") from error
    if _source_fingerprint(current) != _source_fingerprint(metadata):
        raise ArchivePolicyError("source_changed")
    if current_path is not None and (
        not stat.S_ISREG(current_path.st_mode)
        or _identity(current_path) != _identity(current)
    ):
        raise ArchivePolicyError("source_changed")


def _check_deadline(deadline: float) -> None:
    """
    Check deadline.

    The implementation uses ``deadline`` to check deadline. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Raises:
        ArchivePolicyError: If time_limit.
    """
    if time.monotonic() > deadline:
        raise ArchivePolicyError("time_limit")


class _DeadlineReader:
    """
    Check elapsed time around every read performed by tarfile.

    The type coordinates ``read``, ``seek``, and ``tell`` and retains the state
    those operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(self, stream: BinaryIO, deadline: float) -> None:
        """
        Initialize a ``_DeadlineReader`` instance.

        The initializer records ``_deadline`` and ``_stream`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            stream: Stream consumed while the function attempts to initialize a
                ``_DeadlineReader`` instance.
            deadline: Absolute monotonic deadline after which the operation must
                stop.
        """
        self._stream = stream
        self._deadline = deadline

    def read(self, size: int = -1) -> bytes:
        """
        Read bounded data from the owned source.

        The implementation uses ``size`` to read bounded data from the owned
        source. Parsing or I/O must finish before the validated representation
        is made available to the caller.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The validated ``data``.
        """
        _check_deadline(self._deadline)
        data = self._stream.read(size)
        _check_deadline(self._deadline)
        return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """
        Return the seek.

        The implementation uses ``offset`` and ``whence`` to produce the seek.

        Args:
            offset: Numeric offset used by the operation's bounded accounting.
            whence: Numeric whence used while the operation performs bounded
                accounting.

        Returns:
            The validated ``position``.
        """
        _check_deadline(self._deadline)
        position = self._stream.seek(offset, whence)
        _check_deadline(self._deadline)
        return position

    def tell(self) -> int:
        """
        Return the current stream position.

        After applying local validation, the function forwards current instance
        state to ``self._stream.tell`` and preserves its return and exception
        contract.

        Returns:
            The numeric tell value.
        """
        return self._stream.tell()

    def __getattr__(self, name: str):
        """
        Return the requested value from the _DeadlineReader.

        After applying local validation, the function forwards ``name`` to
        ``getattr`` and preserves its return and exception contract.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.

        Returns:
            The requested value from the _DeadlineReader.
        """
        return getattr(self._stream, name)


@contextmanager
def _open_source(
    source: Union[str, os.PathLike[str]],
    limits: ArchiveLimits,
) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """
    Open source.

    The implementation uses ``source`` and ``limits`` to open source. If the
    function cannot open source, its exception reaches the caller instead of
    being converted into a successful result.

    Args:
        source: filesystem location used as the source for this operation.
        limits: Limits governing open source.

    Yields:
        Each open source admitted by the operation, in deterministic iteration
        order.

    Raises:
        ArchivePolicyError: If source_unavailable; source_symlink;
            source_not_regular; or input_size_limit; or another input invariant
            is violated.
    """
    path = Path(source)
    try:
        before = path.lstat()
    except OSError as error:
        raise ArchivePolicyError("source_unavailable") from error
    if stat.S_ISLNK(before.st_mode):
        raise ArchivePolicyError("source_symlink")
    if not stat.S_ISREG(before.st_mode):
        raise ArchivePolicyError("source_not_regular")
    if before.st_size > limits.max_input_bytes:
        raise ArchivePolicyError("input_size_limit")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise ArchivePolicyError("source_open_failed") from error
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_size > limits.max_input_bytes
        or _source_fingerprint(opened) != _source_fingerprint(before)
    ):
        os.close(descriptor)
        raise ArchivePolicyError("source_identity_changed")

    with os.fdopen(descriptor, "rb") as stream:
        yield stream, opened
        _assert_source_unchanged(stream, opened, path=path)


def _member_parts(
    name: str, *, directory: bool, limits: ArchiveLimits
) -> tuple[str, ...]:
    """
    Return the validated components of one untrusted archive member name.

    The decision itself belongs to ``utils.archive_member_policy``, which every
    archive producer and consumer shares so an admitted name can never fail at
    the next boundary. This wrapper only binds the ceiling to the caller's
    ``limits`` and restates the refusal as the archive-policy error the
    extractor's callers already handle. TAR producer prefixes are normalized by
    ``_normalized_tar_member_name`` before this function runs; nothing is
    rewritten here.

    Rejection stays fail-closed for the whole archive rather than dropping the
    member, because the caller cannot know whether the omitted member was the
    one the operator needed and the rollback in ``_cleanup_created`` already
    removes anything created so far.

    Args:
        name: Untrusted member name taken from the archive's own metadata.
        directory: Whether the member is a directory entry, in which case one
            trailing ``/`` is the archive's directory spelling.
        limits: Archive limits in force, supplying the operator-configurable
            ``max_path_depth`` ceiling.

    Returns:
        The validated ``parts``, in order and free of empty, ``.``, and ``..``
        components.

    Raises:
        ArchivePolicyError: If unsafe_member_path; or path_depth_limit.
    """
    try:
        return validate_distributable_member_name(
            name,
            max_path_depth=limits.max_path_depth,
            directory=directory,
        )
    except MemberNamePolicyError as error:
        raise ArchivePolicyError(error.reason) from error


def _normalized_tar_member_name(name: str, *, allow_absolute: bool) -> str:
    """
    Normalize only TAR producer prefixes that preserve one safe pathname.

    The implementation uses ``name`` and ``allow_absolute`` to normalize only
    TAR producer prefixes that preserve one safe pathname. The source value
    keeps its ownership while the normalized representation is returned
    separately.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.
        allow_absolute: Whether allow absolute is enabled or required for this
            operation.

    Returns:
        The validated ``normalized``.
    """
    normalized = name.lstrip("/") if allow_absolute else name
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _metadata_length(value: Union[str, bytes]) -> int:
    """
    Return the metadata length.

    The implementation uses ``value`` to produce the metadata length.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        The numeric metadata length value.
    """
    if isinstance(value, bytes):
        return len(value)
    return len(value.encode("utf-8", errors="surrogateescape"))


def _account_tar_metadata(
    budget: _TarMetadataBudget,
    amount: int,
    limits: ArchiveLimits,
) -> None:
    """
    Account for TAR metadata.

    The implementation uses ``budget``, ``amount``, and ``limits`` to account
    for TAR metadata. If the function cannot account for TAR metadata, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        budget: Budget object whose ``bytes`` state is read while performing
            account for TAR metadata.
        amount: Numeric amount used while the operation performs bounded
            accounting.
        limits: Limits governing account for TAR metadata.

    Raises:
        ArchivePolicyError: If metadata_member_size_limit; or
            metadata_size_limit.
    """
    if amount < 0 or amount > limits.max_metadata_member_bytes:
        raise ArchivePolicyError("metadata_member_size_limit")
    budget.bytes += amount
    if budget.bytes > limits.max_metadata_bytes:
        raise ArchivePolicyError("metadata_size_limit")


def _bounded_tarinfo_class(
    limits: ArchiveLimits,
    budget: _TarMetadataBudget,
    deadline: float,
    max_stream_bytes: int,
) -> type[tarfile.TarInfo]:
    """
    Bind limits to tarfile's pre-yield extended-header parsers.

    The implementation uses ``limits``, ``budget``, ``deadline``, and
    ``max_stream_bytes`` to bind limits to tarfile's pre-yield extended-header
    parsers.

    Args:
        limits: Limits governing bind limits to tarfile's pre-yield
            extended-header parsers.
        budget: Budget consumed while the function attempts to bind limits to
            tarfile's pre-yield extended-header parsers.
        deadline: Absolute monotonic deadline after which the operation must
            stop.
        max_stream_bytes: Upper bound enforced for max stream bytes; the
            consuming boundary rejects or truncates values that exceed it.

    Returns:
        The validated ``_BoundedTarInfo``.
    """

    class _BoundedTarInfo(tarfile.TarInfo):
        """
        Implement the bounded TAR info boundary used by the NVDebug runtime.

        The type coordinates ``_account_extended_header``, ``_proc_pax``,
        ``_proc_gnulong``, ``_proc_sparse``, and ``_proc_gnusparse_00`` and
        retains the state those operations share between calls. Resource
        ownership remains inside the instance until the matching close, exit, or
        cleanup operation completes.
        """

        def _account_extended_header(self, archive: tarfile.TarFile) -> None:
            """
            Account for extended header.

            The implementation uses ``archive`` to account for extended header.
            If the function cannot account for extended header, its exception
            reaches the caller instead of being converted into a successful
            result.

            Args:
                archive: Archive object whose ``fileobj`` and ``tell`` state is
                    read while performing account for extended header.

            Raises:
                ArchivePolicyError: If member_count_limit; or tar_read_failed.
            """
            _check_deadline(deadline)
            budget.extended_headers += 1
            if budget.extended_headers > limits.max_members:
                raise ArchivePolicyError("member_count_limit")
            _account_tar_metadata(budget, self.size, limits)
            try:
                stream_end = archive.fileobj.tell() + self._block(self.size)
            except (AttributeError, OSError, tarfile.TarError, ValueError) as error:
                raise ArchivePolicyError("tar_read_failed") from error
            _admit_tar_stream_extent(stream_end, max_stream_bytes)

        def _proc_pax(self, archive):
            """
            Return the proc PAX.

            After applying local validation, the function forwards ``archive``
            to ``_proc_pax`` and preserves its return and exception contract.

            Args:
                archive: Archive consumed while the function attempts to produce
                    the proc PAX.

            Returns:
                The proc PAX.
            """
            self._account_extended_header(archive)
            return super()._proc_pax(archive)

        def _proc_gnulong(self, archive):
            """
            Return the proc gnulong.

            After applying local validation, the function forwards ``archive``
            to ``_proc_gnulong`` and preserves its return and exception
            contract.

            Args:
                archive: Archive consumed while the function attempts to produce
                    the proc gnulong.

            Returns:
                The proc gnulong.
            """
            self._account_extended_header(archive)
            return super()._proc_gnulong(archive)

        def _proc_sparse(self, archive):
            """
            Reject unsupported sparse TAR member metadata.

            The implementation uses ``archive`` to reject unsupported sparse TAR
            member metadata. Every required invariant is checked before a
            successful value is returned; invalid input follows the function's
            explicit exception path.

            Args:
                archive: Archive consumed while the function attempts to reject
                    unsupported sparse TAR member metadata.

            Raises:
                ArchivePolicyError: If sparse_member.
            """
            raise ArchivePolicyError("sparse_member")

        def _proc_gnusparse_00(self, member, raw_headers):
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
                ArchivePolicyError: If sparse_member.
            """
            raise ArchivePolicyError("sparse_member")

        def _proc_gnusparse_01(self, member, pax_headers):
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
                ArchivePolicyError: If sparse_member.
            """
            raise ArchivePolicyError("sparse_member")

        def _proc_gnusparse_10(self, member, pax_headers, archive):
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
                ArchivePolicyError: If sparse_member.
            """
            raise ArchivePolicyError("sparse_member")

    return _BoundedTarInfo


def _raise_if_destination_capacity_error(error: OSError, path: Path) -> None:
    """
    Translate destination-capacity failures into archive policy errors.

    The implementation uses ``error`` and ``path`` to translate
    destination-capacity failures into archive policy errors. If the function
    cannot translate destination-capacity failures into archive policy errors,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        error: Exception or failure detail associated with the operation.
        path: filesystem location used as the path for this operation.

    Raises:
        ArchivePolicyError: If input or state violates constraints required to
            translate destination-capacity failures into archive policy errors.
    """
    if error.errno not in {errno.ENOSPC, errno.EDQUOT}:
        return

    reason = "destination_space_limit"
    try:
        filesystem = os.statvfs(path)
        if (
            getattr(filesystem, "f_files", 0) > 0
            and getattr(filesystem, "f_favail", 1) <= 0
        ):
            reason = "destination_inode_limit"
    except (AttributeError, OSError):
        pass
    raise ArchivePolicyError(reason) from error


def _prepare_destination(
    destination: Union[str, os.PathLike[str]],
    state: _ExtractionState,
) -> _DestinationRoot:
    """
    Prepare destination.

    After applying local validation, the function forwards ``destination`` and
    ``state`` to ``_DestinationRoot`` and preserves its return and exception
    contract. The operation mutates ``state`` in place; ownership of those
    objects remains with the caller. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        destination: filesystem location used as the destination for this
            operation.
        state: State object whose ``append`` and ``created`` state is read while
            performing prepare destination.

    Returns:
        A ``_DestinationRoot`` representing prepare destination.

    Raises:
        ArchivePolicyError: If destination_create_failed;
            destination_unavailable; destination_not_directory; or input or
            state violates constraints required to prepare destination; or
            another input invariant is violated.
    """
    root = Path(destination)
    created = False
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        try:
            root.mkdir(mode=0o700, parents=False, exist_ok=False)
            created = True
        except OSError as error:
            _raise_if_destination_capacity_error(error, root.parent)
            raise ArchivePolicyError("destination_create_failed") from error
    except OSError as error:
        raise ArchivePolicyError("destination_unavailable") from error
    else:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ArchivePolicyError("destination_not_directory")

    try:
        descriptor = os.open(root, _DIRECTORY_OPEN_FLAGS)
        opened = os.fstat(descriptor)
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        if created:
            try:
                root.rmdir()
            except OSError:
                pass
            reason = "destination_create_failed"
        else:
            reason = "destination_changed"
        raise ArchivePolicyError(reason) from error

    if not stat.S_ISDIR(opened.st_mode):
        os.close(descriptor)
        if created:
            try:
                root.rmdir()
            except OSError:
                pass
        raise ArchivePolicyError("destination_not_directory")
    if not created and _identity(opened) != _identity(metadata):
        os.close(descriptor)
        raise ArchivePolicyError("destination_changed")

    identity = _identity(opened)
    if created:
        state.created.append(_CreatedEntry(root, identity, True))
        try:
            os.fchmod(descriptor, 0o700)
        except OSError as error:
            os.close(descriptor)
            raise ArchivePolicyError("destination_create_failed") from error
    return _DestinationRoot(root, descriptor, identity)


def _admit_destination(
    root: Path,
    *,
    expected_bytes: int,
    expected_nodes: int,
    limits: ArchiveLimits,
) -> None:
    """
    Best-effort admission using space available to the current user.

    The implementation uses ``root``, ``expected_bytes``, ``expected_nodes``,
    and ``limits`` to best-effort admission using space available to the current
    user. If the function cannot best-effort admission using space available to
    the current user, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        root: filesystem location used as the root for this operation.
        expected_bytes: Numeric expected bytes used while the operation performs
            bounded accounting.
        expected_nodes: Numeric expected nodes used while the operation performs
            bounded accounting.
        limits: Limits governing best-effort admission using space available to
            the current user.

    Raises:
        ArchivePolicyError: If destination_space_limit; or
            destination_inode_limit.
    """
    try:
        filesystem = os.statvfs(root)
    except (AttributeError, OSError):
        return

    fragment_size = getattr(filesystem, "f_frsize", 0) or getattr(
        filesystem,
        "f_bsize",
        0,
    )
    available_blocks = getattr(filesystem, "f_bavail", -1)
    if fragment_size > 0 and available_blocks >= 0:
        available_bytes = fragment_size * available_blocks
        if available_bytes < expected_bytes + limits.disk_reserve_bytes:
            raise ArchivePolicyError("destination_space_limit")

    total_inodes = getattr(filesystem, "f_files", 0)
    available_inodes = getattr(filesystem, "f_favail", -1)
    if total_inodes > 0 and available_inodes >= 0:
        if available_inodes < expected_nodes + limits.inode_reserve:
            raise ArchivePolicyError("destination_inode_limit")


@dataclass
class _DestinationAdmission:
    """
    Implement the destination admission boundary used by the NVDebug runtime.

    The coherent record keeps ``root``, ``summary``, ``limits``,
    ``next_byte_check``, and ``next_node_check`` together so consumers observe
    one destination admission state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        root: Validated filesystem location associated with root.
        summary: Summary retained as part of the record's public state.
        limits: Limits retained as part of the record's public state.
        next_byte_check: Numeric next byte check retained by this record.
        next_node_check: Numeric next node check retained by this record.
    """

    root: Path
    summary: _ArchiveSummary
    limits: ArchiveLimits
    next_byte_check: int = CAPACITY_RECHECK_BYTES
    next_node_check: int = CAPACITY_RECHECK_NODES

    def check(self, state: _ExtractionState, *, force: bool = False) -> None:
        """
        Check the current input against the owned invariant.

        The implementation uses ``state`` and ``force`` to check the current
        input against the owned invariant. Every required invariant is checked
        before a successful value is returned; invalid input follows the
        function's explicit exception path. It updates ``next_byte_check`` and
        ``next_node_check`` on the instance as part of that state transition.

        Args:
            state: State object whose ``processed_nodes`` and ``total_bytes``
                state is read while performing current input against the owned
                invariant.
            force: Whether force is enabled or required for this operation.
        """
        if (
            not force
            and state.total_bytes < self.next_byte_check
            and state.processed_nodes < self.next_node_check
        ):
            return
        _admit_destination(
            self.root,
            expected_bytes=max(self.summary.output_bytes - state.total_bytes, 0),
            expected_nodes=max(self.summary.path_nodes - state.processed_nodes, 0),
            limits=self.limits,
        )
        self.next_byte_check = state.total_bytes + CAPACITY_RECHECK_BYTES
        self.next_node_check = state.processed_nodes + CAPACITY_RECHECK_NODES


def _assert_root_identity(root: _DestinationRoot) -> None:
    """
    Verify root identity.

    The implementation uses ``root`` to verify root identity. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        root: filesystem location used as the root for this operation.

    Raises:
        ArchivePolicyError: If destination_changed.
    """
    opened = _assert_open_directory_path(root.descriptor, root.path)
    if _identity(opened) != root.identity:
        raise ArchivePolicyError("destination_changed")


def _assert_open_directory_path(
    descriptor: int,
    path: Path,
) -> os.stat_result:
    """
    Verify open directory path.

    The implementation uses ``descriptor`` and ``path`` to verify open directory
    path. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        path: filesystem location used as the path for this operation.

    Returns:
        The validated ``opened``.

    Raises:
        ArchivePolicyError: If destination_changed.
    """
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
    except OSError as error:
        raise ArchivePolicyError("destination_changed") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or _identity(current) != _identity(opened)
    ):
        raise ArchivePolicyError("destination_changed")
    return opened


def _raise_unsafe_destination_component(error: OSError) -> None:
    """
    Reject an unsafe archive destination component.

    The implementation uses ``error`` to reject an unsafe archive destination
    component. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        error: Exception or failure detail associated with the operation.

    Raises:
        ArchivePolicyError: If unsafe_destination_component.
    """
    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
        raise ArchivePolicyError("unsafe_destination_component") from error


@contextmanager
def _open_destination_directory(
    root: _DestinationRoot,
    parts: tuple[str, ...],
    state: _ExtractionState,
) -> Iterator[tuple[int, Path]]:
    """
    Open destination directory.

    The implementation uses ``root``, ``parts``, and ``state`` to open
    destination directory. The operation mutates ``state`` in place; ownership
    of those objects remains with the caller. If the function cannot open
    destination directory, its exception reaches the caller instead of being
    converted into a successful result. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        root: filesystem location used as the root for this operation.
        parts: Entries supplied as ``parts`` without transferring container
            ownership.
        state: State object whose ``append`` and ``created`` state is read while
            performing open destination directory.

    Yields:
        Each open destination directory admitted by the operation, in
        deterministic iteration order.

    Raises:
        ArchivePolicyError: If destination_changed; directory_create_failed;
            destination_unavailable; or unsafe_destination_component.
    """
    try:
        descriptor = os.dup(root.descriptor)
    except OSError as error:
        raise ArchivePolicyError("destination_changed") from error
    current = root.path
    try:
        for part in parts:
            _assert_open_directory_path(descriptor, current)
            current = current / part
            next_descriptor = None
            try:
                next_descriptor = os.open(
                    part,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except OSError as error:
                    _raise_if_destination_capacity_error(error, root.path)
                    raise ArchivePolicyError("directory_create_failed") from error
                try:
                    next_descriptor = os.open(
                        part,
                        _DIRECTORY_OPEN_FLAGS,
                        dir_fd=descriptor,
                    )
                except OSError as error:
                    try:
                        os.rmdir(part, dir_fd=descriptor)
                    except OSError:
                        pass
                    _raise_if_destination_capacity_error(error, root.path)
                    raise ArchivePolicyError("directory_create_failed") from error
                try:
                    metadata = os.fstat(next_descriptor)
                except OSError as error:
                    os.close(next_descriptor)
                    try:
                        os.rmdir(part, dir_fd=descriptor)
                    except OSError:
                        pass
                    raise ArchivePolicyError("directory_create_failed") from error
                state.created.append(_CreatedEntry(current, _identity(metadata), True))
                try:
                    os.fchmod(next_descriptor, 0o700)
                except OSError as error:
                    os.close(next_descriptor)
                    raise ArchivePolicyError("directory_create_failed") from error
            except OSError as error:
                _raise_unsafe_destination_component(error)
                raise ArchivePolicyError("destination_unavailable") from error
            else:
                try:
                    metadata = os.fstat(next_descriptor)
                except OSError as error:
                    os.close(next_descriptor)
                    raise ArchivePolicyError("destination_unavailable") from error

            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_descriptor)
                raise ArchivePolicyError("unsafe_destination_component")
            try:
                _assert_open_directory_path(next_descriptor, current)
            except Exception:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
        _assert_open_directory_path(descriptor, current)
        yield descriptor, current
        _assert_open_directory_path(descriptor, current)
    finally:
        os.close(descriptor)


@contextmanager
def _new_output_file(
    root: _DestinationRoot,
    parts: tuple[str, ...],
    state: _ExtractionState,
) -> Iterator[BinaryIO]:
    """
    Return the new output file.

    The implementation uses ``root``, ``parts``, and ``state`` to produce the
    new output file. The operation mutates ``state`` in place; ownership of
    those objects remains with the caller. Filesystem effects remain confined to
    the caller-selected paths and the owning resource lifecycle. If the function
    cannot produce the new output file, its exception reaches the caller instead
    of being converted into a successful result.

    Args:
        root: filesystem location used as the root for this operation.
        parts: Entries supplied as ``parts`` without transferring container
            ownership.
        state: State object whose ``append`` and ``created`` state is read while
            performing new output file.

    Yields:
        Each new output file admitted by the operation, in deterministic
        iteration order.

    Raises:
        ArchivePolicyError: If destination_collision; or
            destination_permissions.
    """
    with _open_destination_directory(root, parts[:-1], state) as (
        parent_descriptor,
        parent,
    ):
        target = parent / parts[-1]
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = None
        identity = None
        try:
            _assert_open_directory_path(parent_descriptor, parent)
            descriptor = os.open(
                parts[-1],
                flags,
                0o600,
                dir_fd=parent_descriptor,
            )
            metadata = os.fstat(descriptor)
            identity = _identity(metadata)
            _assert_open_directory_path(parent_descriptor, parent)
        except Exception as error:
            if descriptor is not None:
                os.close(descriptor)
            if identity is not None:
                _unlink_created_file_at(parent_descriptor, parts[-1], identity)
            if isinstance(error, ArchivePolicyError):
                raise
            if isinstance(error, OSError):
                _raise_if_destination_capacity_error(error, root.path)
                raise ArchivePolicyError("destination_collision") from error
            raise
        state.created.append(_CreatedEntry(target, identity, False))
        try:
            os.fchmod(descriptor, 0o600)
        except OSError as error:
            os.close(descriptor)
            _unlink_created_file_at(parent_descriptor, parts[-1], identity)
            raise ArchivePolicyError("destination_permissions") from error
        try:
            with os.fdopen(descriptor, "wb") as stream:
                yield stream
            _assert_open_directory_path(parent_descriptor, parent)
        except Exception as error:
            try:
                os.close(descriptor)
            except OSError:
                pass
            _unlink_created_file_at(parent_descriptor, parts[-1], identity)
            if isinstance(error, OSError):
                _raise_if_destination_capacity_error(error, root.path)
            raise


def _unlink_created_file_at(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    """
    Remove created file at.

    The implementation uses ``parent_descriptor``, ``name``, and
    ``expected_identity`` to remove created file at.

    Args:
        parent_descriptor: Numeric parent descriptor used while the operation
            performs bounded accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        expected_identity: Entries supplied as ``expected_identity`` without
            transferring container ownership.
    """
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISREG(metadata.st_mode) and _identity(metadata) == expected_identity:
            os.unlink(name, dir_fd=parent_descriptor)
    except OSError:
        pass


def _cleanup_created(state: _ExtractionState) -> None:
    """
    Clean up created.

    The implementation uses ``state`` to clean up created. Filesystem effects
    remain confined to the caller-selected paths and the owning resource
    lifecycle.

    Args:
        state: State object whose ``created`` state is read while performing
            clean up created.
    """
    for entry in reversed(state.created):
        try:
            metadata = entry.path.lstat()
            if _identity(metadata) != entry.identity:
                continue
            if entry.is_directory:
                if stat.S_ISDIR(metadata.st_mode):
                    entry.path.rmdir()
            elif stat.S_ISREG(metadata.st_mode):
                entry.path.unlink()
        except OSError:
            continue


def _copy_member(
    source: BinaryIO,
    target: BinaryIO,
    *,
    expected_bytes: int,
    limits: ArchiveLimits,
    state: _ExtractionState,
    deadline: float,
    admission: _DestinationAdmission,
    hasher: Optional[Any] = None,
) -> Optional[bytes]:
    """
    Copy member.

    The implementation uses ``source``, ``target``, ``expected_bytes``,
    ``limits``, and ``state`` to copy member. The operation mutates ``hasher``
    in place; ownership of those objects remains with the caller. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot copy member, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        source: Source object whose ``read`` state is read while performing copy
            member.
        target: Target object whose ``write`` state is read while performing
            copy member.
        expected_bytes: Numeric expected bytes used while the operation performs
            bounded accounting.
        limits: Limits governing copy member.
        state: State object whose ``total_bytes`` state is read while performing
            copy member.
        deadline: Absolute monotonic deadline after which the operation must
            stop.
        admission: Admission object whose ``check`` and ``root`` state is read
            while performing copy member.
        hasher: Optional hasher; ``None`` selects the function's default
            behavior.

    Returns:
        The bounded copy member bytes, or ``None`` when the requested value is
        unavailable.

    Raises:
        ArchivePolicyError: If member_size_limit; total_size_limit;
            destination_space_limit; or member_size_mismatch.
    """
    member_bytes = 0
    while True:
        _check_deadline(deadline)
        chunk = source.read(COPY_CHUNK_BYTES)
        if not chunk:
            break
        member_bytes += len(chunk)
        if member_bytes > limits.max_member_bytes:
            raise ArchivePolicyError("member_size_limit")
        if state.total_bytes + len(chunk) > limits.max_total_bytes:
            raise ArchivePolicyError("total_size_limit")
        if hasher is not None:
            hasher.update(chunk)
        try:
            written = target.write(chunk)
        except OSError as error:
            _raise_if_destination_capacity_error(error, admission.root)
            raise
        if written != len(chunk):
            raise ArchivePolicyError("destination_space_limit")
        state.total_bytes += len(chunk)
        admission.check(state)
    if member_bytes != expected_bytes:
        raise ArchivePolicyError("member_size_mismatch")
    return None if hasher is None else hasher.digest()


class BoundedTarMemberReader:
    """
    Read one inspected TAR member in finite chunks on the active scan.

    Instances are valid only for the duration of their visitor callback. A
    caller must request a positive byte count; requests are clamped to the
    shared copy chunk so a configuration mistake cannot turn one read into a
    large allocation. The owning inspector drains any unread suffix and verifies
    the complete member before advancing the archive.
    """

    def __init__(
        self,
        source: BinaryIO,
        *,
        expected_bytes: int,
        deadline: float,
    ) -> None:
        """
        Initialize a ``BoundedTarMemberReader`` instance.

        The initializer records ``_active``, ``_bytes_read``, ``_deadline``,
        ``_expected_bytes``, and ``_hasher`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            source: Source consumed while the function attempts to initialize a
                ``BoundedTarMemberReader`` instance.
            expected_bytes: Numeric expected bytes used while the operation
                performs bounded accounting.
            deadline: Absolute monotonic deadline after which the operation must
                stop.
        """
        self._source = source
        self._expected_bytes = expected_bytes
        self._deadline = deadline
        self._bytes_read = 0
        self._hasher = hashlib.sha256()
        self._active = True

    @property
    def bytes_read(self) -> int:
        """
        Return bytes consumed by the visitor and the inspector drain.

        Each access computes the value from ``_bytes_read`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric bytes read value.
        """

        return self._bytes_read

    def read(self, size: int) -> bytes:
        """
        Read at most one bounded chunk from the current member.

        The implementation uses ``size`` to read at most one bounded chunk from
        the current member. Parsing or I/O must finish before the validated
        representation is made available to the caller. It updates
        ``_bytes_read`` on the instance as part of that state transition. If the
        function cannot read at most one bounded chunk from the current member,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The validated ``chunk``.

        Raises:
            ValueError: If TAR member reader is no longer active; or TAR member
                reads require a positive integer size.
            ArchivePolicyError: If tar_member_unreadable; or
                member_size_mismatch.
        """

        if not self._active:
            raise ValueError("TAR member reader is no longer active")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError("TAR member reads require a positive integer size")
        _check_deadline(self._deadline)
        chunk = self._source.read(min(size, COPY_CHUNK_BYTES))
        _check_deadline(self._deadline)
        if not isinstance(chunk, bytes):
            raise ArchivePolicyError("tar_member_unreadable")
        self._bytes_read += len(chunk)
        if self._bytes_read > self._expected_bytes:
            raise ArchivePolicyError("member_size_mismatch")
        self._hasher.update(chunk)
        return chunk

    def _finish(self) -> bytes:
        """
        Finalize the current operation.

        After applying local validation, the function forwards current instance
        state to ``self._hasher.digest`` and preserves its return and exception
        contract. It updates ``_active`` on the instance as part of that state
        transition. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle. Cleanup in the ``finally`` path
        runs for successful, failed, and cancelled execution.

        Returns:
            The bounded finish bytes.

        Raises:
            ArchivePolicyError: If member_size_mismatch.
        """
        try:
            while self.read(COPY_CHUNK_BYTES):
                pass
            if self._bytes_read != self._expected_bytes:
                raise ArchivePolicyError("member_size_mismatch")
            return self._hasher.digest()
        finally:
            self._active = False


TarArchiveVisitor = Callable[[TarArchiveMember, BoundedTarMemberReader], None]
TarArchiveMetadataVisitor = Callable[[TarArchiveMember], None]


def _digest_member(
    source: BinaryIO,
    *,
    expected_bytes: int,
    limits: ArchiveLimits,
    deadline: float,
) -> bytes:
    """
    Return the digest member.

    After applying local validation, the function forwards ``source``,
    ``expected_bytes``, ``limits``, and ``deadline`` to ``hasher.digest`` and
    preserves its return and exception contract. Filesystem effects remain
    confined to the caller-selected paths and the owning resource lifecycle.

    Args:
        source: Source object whose ``read`` state is read while performing
            digest member.
        expected_bytes: Numeric expected bytes used while the operation performs
            bounded accounting.
        limits: Limits governing digest member.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The bounded digest member bytes.

    Raises:
        ArchivePolicyError: If member_size_limit; or member_size_mismatch.
    """
    member_bytes = 0
    hasher = hashlib.sha256()
    while True:
        _check_deadline(deadline)
        chunk = source.read(COPY_CHUNK_BYTES)
        if not chunk:
            break
        member_bytes += len(chunk)
        if member_bytes > limits.max_member_bytes:
            raise ArchivePolicyError("member_size_limit")
        hasher.update(chunk)
    if member_bytes != expected_bytes:
        raise ArchivePolicyError("member_size_mismatch")
    return hasher.digest()


def _read_zip_region(
    stream: BinaryIO,
    offset: int,
    size: int,
    deadline: float,
) -> bytes:
    """
    Read ZIP region.

    The implementation uses ``stream``, ``offset``, ``size``, and ``deadline``
    to read ZIP region. Parsing or I/O must finish before the validated
    representation is made available to the caller. If the function cannot read
    ZIP region, its exception reaches the caller instead of being converted into
    a successful result.

    Args:
        stream: Stream object whose ``read`` and ``seek`` state is read while
            performing ZIP region.
        offset: Numeric offset used by the operation's bounded accounting.
        size: Numeric size used by the operation's bounded accounting.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The validated ``payload``.

    Raises:
        ArchivePolicyError: If zip64_end_record.
    """
    if offset < 0 or size < 0:
        raise ArchivePolicyError("zip64_end_record")
    _check_deadline(deadline)
    try:
        stream.seek(offset)
        payload = stream.read(size)
    except (OSError, ValueError) as error:
        raise ArchivePolicyError("zip64_end_record") from error
    _check_deadline(deadline)
    if len(payload) != size:
        raise ArchivePolicyError("zip64_end_record")
    return payload


def _zip64_end_record_at(
    stream: BinaryIO,
    *,
    offset: int,
    locator_offset: int,
    deadline: float,
) -> Optional[tuple[int, ...]]:
    """
    Return the zip64 end record at.

    After applying local validation, the function forwards ``stream``,
    ``offset``, ``locator_offset``, and ``deadline`` to ``tuple`` and preserves
    its return and exception contract.

    Args:
        stream: Stream consumed while the function attempts to produce the zip64
            end record at.
        offset: Numeric offset used by the operation's bounded accounting.
        locator_offset: Numeric locator offset used by the operation's bounded
            accounting.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The zip64 end record at returned in operation-defined order, or ``None``
        when the requested value is unavailable.

    Raises:
        ArchivePolicyError: If zip64_end_record; or zip64_end_record_limit.
    """
    if offset < 0 or offset + 12 > locator_offset:
        return None
    prefix = _read_zip_region(stream, offset, 12, deadline)
    if prefix[:4] != _ZIP64_END_SIGNATURE:
        return None
    record_payload_size = struct.unpack_from("<Q", prefix, 4)[0]
    total_size = 12 + record_payload_size
    if offset + total_size != locator_offset:
        return None
    if record_payload_size < 44:
        raise ArchivePolicyError("zip64_end_record")
    if total_size > _ZIP64_MAX_END_RECORD_BYTES:
        raise ArchivePolicyError("zip64_end_record_limit")
    fixed = _read_zip_region(stream, offset, _ZIP64_END_FIXED_BYTES, deadline)
    try:
        fields = struct.unpack("<4sQ2H2I4Q", fixed)
    except struct.error as error:
        raise ArchivePolicyError("zip64_end_record") from error
    if fields[0] != _ZIP64_END_SIGNATURE or fields[1] != record_payload_size:
        raise ArchivePolicyError("zip64_end_record")
    return tuple(int(value) for value in fields[1:])


def _zip64_end_record_in_buffer(
    payload: bytes,
    *,
    index: int,
    absolute_offset: int,
    locator_offset: int,
) -> Optional[tuple[int, ...]]:
    """
    Return the zip64 end record in buffer.

    After applying local validation, the function forwards ``payload``,
    ``index``, ``absolute_offset``, and ``locator_offset`` to ``tuple`` and
    preserves its return and exception contract.

    Args:
        payload: Bounded byte sequence supplied as payload.
        index: Zero-based position within the containing sequence.
        absolute_offset: Numeric absolute offset used by the operation's bounded
            accounting.
        locator_offset: Numeric locator offset used by the operation's bounded
            accounting.

    Returns:
        The zip64 end record in buffer returned in operation-defined order, or
        ``None`` when the requested value is unavailable.

    Raises:
        ArchivePolicyError: If zip64_end_record; or zip64_end_record_limit.
    """
    if len(payload) - index < 12:
        return None
    record_payload_size = struct.unpack_from("<Q", payload, index + 4)[0]
    total_size = 12 + record_payload_size
    if absolute_offset + total_size != locator_offset:
        return None
    if record_payload_size < 44 or len(payload) - index < _ZIP64_END_FIXED_BYTES:
        raise ArchivePolicyError("zip64_end_record")
    if total_size > _ZIP64_MAX_END_RECORD_BYTES:
        raise ArchivePolicyError("zip64_end_record_limit")
    try:
        fields = struct.unpack_from("<4sQ2H2I4Q", payload, index)
    except struct.error as error:
        raise ArchivePolicyError("zip64_end_record") from error
    if fields[0] != _ZIP64_END_SIGNATURE or fields[1] != record_payload_size:
        raise ArchivePolicyError("zip64_end_record")
    return tuple(int(value) for value in fields[1:])


def _find_zip64_end_record(
    stream: BinaryIO,
    *,
    locator_offset: int,
    declared_offset: int,
    deadline: float,
) -> tuple[int, tuple[int, ...]]:
    """
    Find zip64 end record.

    After applying local validation, the function forwards ``stream``,
    ``locator_offset``, ``declared_offset``, and ``deadline`` to ``next`` and
    preserves its return and exception contract.

    Args:
        stream: Stream consumed while the function attempts to find zip64 end
            record.
        locator_offset: Numeric locator offset used by the operation's bounded
            accounting.
        declared_offset: Numeric declared offset used by the operation's bounded
            accounting.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        A tuple containing the fields that represent zip64 end record.

    Raises:
        ArchivePolicyError: If zip64_end_record.
    """
    candidates: dict[int, tuple[int, ...]] = {}
    direct = _zip64_end_record_at(
        stream,
        offset=declared_offset,
        locator_offset=locator_offset,
        deadline=deadline,
    )
    if direct is not None:
        candidates[declared_offset] = direct

    search_size = min(locator_offset, _ZIP64_MAX_END_RECORD_BYTES)
    search_offset = locator_offset - search_size
    search = _read_zip_region(stream, search_offset, search_size, deadline)
    cursor = 0
    while True:
        _check_deadline(deadline)
        index = search.find(_ZIP64_END_SIGNATURE, cursor)
        if index < 0:
            break
        candidate_offset = search_offset + index
        parsed = _zip64_end_record_in_buffer(
            search,
            index=index,
            absolute_offset=candidate_offset,
            locator_offset=locator_offset,
        )
        if parsed is not None:
            candidates[candidate_offset] = parsed
            if len(candidates) > 1:
                raise ArchivePolicyError("zip64_end_record")
        cursor = index + 1
    if len(candidates) != 1:
        raise ArchivePolicyError("zip64_end_record")
    return next(iter(candidates.items()))


def _inspect_zip_central_directory(
    stream: BinaryIO,
    limits: ArchiveLimits,
    deadline: float,
) -> int:
    """
    Inspect ZIP central directory.

    Match CPython's EOCD search window exactly. Its implementation uses
    ``rfind`` and will select the last signature in this window even when that
    record's comment length does not reach EOF.

    Args:
        stream: Stream object whose ``read``, ``seek``, and ``tell`` state is
            read while performing inspect ZIP central directory.
        limits: Limits governing inspect ZIP central directory.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The validated ``observed``.

    Raises:
        ArchivePolicyError: If zip_end_record; zip64_locator_missing;
            zip_multidisk; or zip64_classic_mismatch; or another input invariant
            is violated.
    """
    _check_deadline(deadline)
    original_position = stream.tell()
    try:
        size = stream.seek(0, os.SEEK_END)
        # Match CPython's EOCD search window exactly.  Its implementation uses
        # ``rfind`` and will select the last signature in this window even when
        # that record's comment length does not reach EOF.
        tail_size = min(size, _ZIP_END_BYTES + _ZIP_MAX_COMMENT_BYTES + 1)
        stream.seek(size - tail_size)
        tail = stream.read(tail_size)
        _check_deadline(deadline)
        candidates = []
        offset = tail.find(_ZIP_END_SIGNATURE)
        while offset >= 0:
            if len(tail) - offset >= _ZIP_END_BYTES:
                comment_size = struct.unpack_from("<H", tail, offset + 20)[0]
                absolute = size - tail_size + offset
                if absolute + _ZIP_END_BYTES + comment_size == size:
                    candidates.append((offset, absolute))
            offset = tail.find(_ZIP_END_SIGNATURE, offset + 1)
        if len(candidates) != 1 or tail.rfind(_ZIP_END_SIGNATURE) != candidates[0][0]:
            raise ArchivePolicyError("zip_end_record")

        offset, end_offset = candidates[0]
        (
            _signature,
            disk_number,
            central_disk,
            entries_on_disk,
            total_entries,
            directory_size,
            directory_offset,
            archive_comment_size,
        ) = struct.unpack_from("<4s4H2IH", tail, offset)
        zip64_non_count_required = (
            disk_number == _ZIP_UINT16_MAX
            or central_disk == _ZIP_UINT16_MAX
            or directory_size == _ZIP_UINT32_MAX
            or directory_offset == _ZIP_UINT32_MAX
        )
        locator_offset = end_offset - _ZIP64_LOCATOR_BYTES
        locator = (
            _read_zip_region(
                stream,
                locator_offset,
                _ZIP64_LOCATOR_BYTES,
                deadline,
            )
            if locator_offset >= 0
            else b""
        )
        has_zip64 = locator[:4] == _ZIP64_LOCATOR_SIGNATURE
        # A classic archive with exactly 65,535 members legitimately stores
        # 0xffff in both count fields without a ZIP64 locator. The bounded
        # central-directory walk below disambiguates that exact count. Disk,
        # size, and offset sentinels remain unambiguously ZIP64-only.
        if zip64_non_count_required and not has_zip64:
            raise ArchivePolicyError("zip64_locator_missing")

        if has_zip64:
            (
                _locator_signature,
                zip64_disk_with_record,
                declared_zip64_offset,
                zip64_total_disks,
            ) = struct.unpack("<4sIQI", locator)
            if zip64_disk_with_record != 0 or zip64_total_disks != 1:
                raise ArchivePolicyError("zip_multidisk")
            zip64_offset, zip64 = _find_zip64_end_record(
                stream,
                locator_offset=locator_offset,
                declared_offset=declared_zip64_offset,
                deadline=deadline,
            )
            (
                _record_payload_size,
                _version_made,
                _version_needed,
                zip64_disk_number,
                zip64_central_disk,
                zip64_entries_on_disk,
                zip64_total_entries,
                zip64_directory_size,
                zip64_directory_offset,
            ) = zip64
            if (
                zip64_disk_number != 0
                or zip64_central_disk != 0
                or zip64_entries_on_disk != zip64_total_entries
            ):
                raise ArchivePolicyError("zip_multidisk")
            compatibility = (
                (disk_number, _ZIP_UINT16_MAX, zip64_disk_number),
                (central_disk, _ZIP_UINT16_MAX, zip64_central_disk),
                (entries_on_disk, _ZIP_UINT16_MAX, zip64_entries_on_disk),
                (total_entries, _ZIP_UINT16_MAX, zip64_total_entries),
                (directory_size, _ZIP_UINT32_MAX, zip64_directory_size),
                (directory_offset, _ZIP_UINT32_MAX, zip64_directory_offset),
            )
            if any(
                classic_value != sentinel and classic_value != zip64_value
                for classic_value, sentinel, zip64_value in compatibility
            ):
                raise ArchivePolicyError("zip64_classic_mismatch")
            archive_prefix = zip64_offset - declared_zip64_offset
            central_end = zip64_offset
            total_entries = zip64_total_entries
            directory_size = zip64_directory_size
            directory_offset = zip64_directory_offset
        else:
            if (
                disk_number != 0
                or central_disk != 0
                or entries_on_disk != total_entries
            ):
                raise ArchivePolicyError("zip_multidisk")
            archive_prefix = end_offset - directory_size - directory_offset
            central_end = end_offset

        if total_entries > limits.max_members:
            raise ArchivePolicyError("member_count_limit")
        if directory_size > limits.max_zip_central_directory_bytes:
            raise ArchivePolicyError("zip_central_directory_limit")
        if archive_comment_size > limits.max_metadata_member_bytes:
            raise ArchivePolicyError("metadata_member_size_limit")

        if archive_prefix < 0:
            raise ArchivePolicyError("zip_central_directory")
        central_start = archive_prefix + directory_offset
        if central_start + directory_size != central_end:
            raise ArchivePolicyError("zip_central_directory")

        stream.seek(central_start)
        consumed = 0
        observed = 0
        metadata_bytes = archive_comment_size
        while consumed < directory_size:
            _check_deadline(deadline)
            fixed = stream.read(_ZIP_CENTRAL_FIXED_BYTES)
            if (
                len(fixed) != _ZIP_CENTRAL_FIXED_BYTES
                or fixed[:4] != _ZIP_CENTRAL_SIGNATURE
            ):
                raise ArchivePolicyError("zip_central_directory")
            name_size, extra_size, comment_size = struct.unpack_from("<HHH", fixed, 28)
            record_metadata_bytes = name_size + extra_size + comment_size
            if record_metadata_bytes > limits.max_metadata_member_bytes:
                raise ArchivePolicyError("metadata_member_size_limit")
            metadata_bytes += record_metadata_bytes
            if metadata_bytes > limits.max_metadata_bytes:
                raise ArchivePolicyError("metadata_size_limit")
            record_size = (
                _ZIP_CENTRAL_FIXED_BYTES + name_size + extra_size + comment_size
            )
            if consumed + record_size > directory_size:
                raise ArchivePolicyError("zip_central_directory")
            stream.seek(record_size - _ZIP_CENTRAL_FIXED_BYTES, os.SEEK_CUR)
            consumed += record_size
            observed += 1
            if observed > limits.max_members:
                raise ArchivePolicyError("member_count_limit")
        if consumed != directory_size or observed != total_entries:
            raise ArchivePolicyError("zip_member_count")
        return observed
    finally:
        stream.seek(original_position)


def inspect_zip_central_directory_extent(
    stream: BinaryIO,
    *,
    limits: Optional[ArchiveLimits] = None,
    deadline: Optional[float] = None,
) -> int:
    """
    Bound a ZIP's declared member count and directory size before parsing.

    Public entry point for :func:`_inspect_zip_central_directory` so callers
    outside this module -- for example the Redfish artifact store's streamed
    validator -- can reject an oversized declared central directory before
    constructing :class:`zipfile.ZipFile`/calling ``infolist()``, instead of
    duplicating this module's end-of-central-directory parser.

    Args:
        stream: Seekable ZIP stream positioned anywhere; its position is
            restored before this function returns.
        limits: Optional archive limits; ``None`` resolves the configured
            inbound profile via :func:`resolve_archive_limits`.
        deadline: Optional absolute monotonic deadline; ``None`` derives one
            from the resolved limits' ``max_seconds``.

    Returns:
        The declared and structurally verified central-directory entry count.

    Raises:
        ArchivePolicyError: If the end-of-central-directory record is
            missing, malformed, multidisk, or declares a member count or
            central-directory size beyond ``limits``.
    """
    resolved_limits = resolve_archive_limits(limits)
    resolved_deadline = (
        time.monotonic() + resolved_limits.max_seconds if deadline is None else deadline
    )
    return _inspect_zip_central_directory(stream, resolved_limits, resolved_deadline)


def _validate_zip_infos(
    archive: zipfile.ZipFile,
    limits: ArchiveLimits,
    deadline: float,
    *,
    expected_members: Optional[int] = None,
    skip_links: bool = False,
    input_size: int = 0,
) -> _ZipValidation:
    """
    Validate ZIP infos.

    After applying local validation, the function forwards ``archive``,
    ``limits``, ``deadline``, ``expected_members``, and ``skip_links`` to
    ``_ZipValidation`` and preserves its return and exception contract. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        archive: Archive object whose ``comment`` and ``infolist`` state is read
            while performing ZIP infos.
        limits: Limits governing ZIP infos.
        deadline: Absolute monotonic deadline after which the operation must
            stop.
        expected_members: Optional expected members; ``None`` selects the
            function's default behavior.
        skip_links: Whether skip links is enabled or required for this
            operation.
        input_size: Numeric input size used by the operation's bounded
            accounting.

    Returns:
        A ``_ZipValidation`` representing ZIP infos.

    Raises:
        ArchivePolicyError: If zip_member_count; member_count_limit;
            metadata_member_size_limit; or metadata_size_limit; or another input
            invariant is violated.
    """
    infos = archive.infolist()
    if expected_members is not None and len(infos) != expected_members:
        raise ArchivePolicyError("zip_member_count")
    if len(infos) > limits.max_members:
        raise ArchivePolicyError("member_count_limit")

    metadata_bytes = _metadata_length(archive.comment)
    if metadata_bytes > limits.max_metadata_member_bytes:
        raise ArchivePolicyError("metadata_member_size_limit")
    if metadata_bytes > limits.max_metadata_bytes:
        raise ArchivePolicyError("metadata_size_limit")
    total_bytes = 0
    output_bytes = 0
    dropped_links = 0
    regular_files = 0
    paths = _PathRegistry()
    validated = []
    for info in infos:
        _check_deadline(deadline)
        record_metadata_bytes = (
            _metadata_length(info.filename)
            + _metadata_length(info.comment)
            + _metadata_length(info.extra)
        )
        if record_metadata_bytes > limits.max_metadata_member_bytes:
            raise ArchivePolicyError("metadata_member_size_limit")
        metadata_bytes += record_metadata_bytes
        if metadata_bytes > limits.max_metadata_bytes:
            raise ArchivePolicyError("metadata_size_limit")
        directory = info.is_dir()
        parts = _member_parts(info.filename, directory=directory, limits=limits)
        if info.flag_bits & 0x1:
            raise ArchivePolicyError("encrypted_member")
        # CPython expands BZIP2 and LZMA ZIP members with an unbounded
        # single-shot decompressor call.  DEFLATE passes an explicit maximum
        # output length and is therefore the only admitted compressed codec.
        if info.compress_type in (zipfile.ZIP_LZMA, zipfile.ZIP_BZIP2):
            raise ArchivePolicyError("decompressor_memory_limit")
        decompressor_bytes = _ZIP_DECOMPRESSOR_BYTES.get(info.compress_type)
        if decompressor_bytes is None:
            raise ArchivePolicyError("unsupported_compression")
        if decompressor_bytes > limits.max_decompressor_memory_bytes:
            raise ArchivePolicyError("decompressor_memory_limit")

        mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        symlink = info.create_system == 3 and file_type == stat.S_IFLNK
        if symlink:
            if not skip_links:
                raise ArchivePolicyError("special_member")
            paths.register(
                parts,
                directory=False,
                limits=limits,
                output=False,
                fingerprint=(
                    "zip_symlink",
                    info.file_size,
                    info.compress_size,
                    info.CRC,
                    mode,
                ),
            )
            dropped_links += 1
            continue
        if directory:
            if file_type not in {0, stat.S_IFDIR} or info.file_size:
                raise ArchivePolicyError("special_member")
            fingerprint = ("zip_directory", mode)
        else:
            if info.create_system == 3 and file_type not in {
                0,
                stat.S_IFREG,
                stat.S_IFLNK,
            }:
                raise ArchivePolicyError("special_member")
            if info.file_size > limits.max_member_bytes:
                raise ArchivePolicyError("member_size_limit")
            if info.file_size:
                if info.compress_size <= 0:
                    raise ArchivePolicyError("compression_ratio_limit")
                if info.file_size / info.compress_size > limits.max_compression_ratio:
                    raise ArchivePolicyError("compression_ratio_limit")
            total_bytes += info.file_size
            if total_bytes > limits.max_total_bytes:
                raise ArchivePolicyError("total_size_limit")
            if (
                input_size > 0
                and total_bytes / input_size > limits.max_compression_ratio
            ):
                raise ArchivePolicyError("compression_ratio_limit")
            fingerprint = (
                "zip_file",
                info.file_size,
                getattr(info, "CRC", 0),
                mode,
            )
        before_output_nodes = paths.output_nodes
        first = paths.register(
            parts,
            directory=directory,
            limits=limits,
            fingerprint=fingerprint,
        )
        if not directory and first:
            regular_files += 1
            output_bytes += info.file_size
            paths.reserve_content_digest(parts, limits=limits)
        validated.append(
            (
                info,
                parts,
                directory,
                paths.output_nodes - before_output_nodes,
                first,
            )
        )
    return _ZipValidation(
        entries=validated,
        summary=_ArchiveSummary(
            members=len(infos),
            total_bytes=total_bytes,
            output_bytes=output_bytes,
            path_nodes=paths.output_nodes,
            tracked_path_bytes=paths.tracked_bytes,
            regular_files=regular_files,
            dropped_links=dropped_links,
        ),
        paths=paths,
    )


def _extract_validated_zip(
    archive: zipfile.ZipFile,
    destination: Union[str, os.PathLike[str]],
    limits: ArchiveLimits,
    deadline: float,
    *,
    expected_members: Optional[int] = None,
    input_size: int = 0,
) -> tuple[_ExtractionState, _ArchiveSummary]:
    """
    Extract validated ZIP.

    The implementation uses ``archive``, ``destination``, ``limits``,
    ``deadline``, and ``expected_members`` to extract validated ZIP. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot extract validated ZIP, its exception
    reaches the caller instead of being converted into a successful result.
    Cleanup in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        archive: Archive object whose ``open`` state is read while performing
            extract validated ZIP.
        destination: filesystem location used as the destination for this
            operation.
        limits: Limits governing extract validated ZIP.
        deadline: Absolute monotonic deadline after which the operation must
            stop.
        expected_members: Optional expected members; ``None`` selects the
            function's default behavior.
        input_size: Numeric input size used by the operation's bounded
            accounting.

    Returns:
        A tuple containing ``state`` and ``summary`` in that order.

    Raises:
        ArchivePolicyError: If zip_extract_failed.
    """
    validation = _validate_zip_infos(
        archive,
        limits,
        deadline,
        expected_members=expected_members,
        skip_links=True,
        input_size=input_size,
    )
    state = _ExtractionState()
    root = None
    try:
        root = _prepare_destination(destination, state)
        admission = _DestinationAdmission(
            root.path,
            validation.summary,
            limits,
        )
        admission.check(state, force=True)
        for info, parts, directory, new_nodes, output in validation.entries:
            admission.check(state)
            _assert_root_identity(root)
            if directory:
                if not output:
                    continue
                with _open_destination_directory(root, parts, state):
                    pass
                state.processed_nodes += new_nodes
                admission.check(state)
                continue
            if not output:
                with archive.open(info, "r") as source:
                    content_digest = _digest_member(
                        source,
                        expected_bytes=info.file_size,
                        limits=limits,
                        deadline=deadline,
                    )
                validation.paths.record_content_digest(
                    parts,
                    content_digest,
                    duplicate=True,
                    limits=limits,
                )
                logger.warning(
                    "archive.identical_duplicate_member: accepted "
                    "extraction-compatible duplicate %r",
                    "/".join(parts),
                )
                continue
            with (
                archive.open(info, "r") as source,
                _new_output_file(root, parts, state) as target,
            ):
                state.processed_nodes += new_nodes
                admission.check(state)
                content_hasher = hashlib.sha256()
                _copy_member(
                    source,
                    target,
                    expected_bytes=info.file_size,
                    limits=limits,
                    state=state,
                    deadline=deadline,
                    admission=admission,
                    hasher=content_hasher,
                )
                content_digest = content_hasher.digest()
            validation.paths.record_content_digest(
                parts,
                content_digest,
                duplicate=False,
                limits=limits,
            )
        admission.check(state, force=True)
        _assert_root_identity(root)
        return state, validation.summary
    except Exception as error:
        _cleanup_created(state)
        if isinstance(error, ArchivePolicyError):
            raise
        if isinstance(
            error,
            (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError),
        ):
            raise ArchivePolicyError("zip_extract_failed") from error
        raise
    finally:
        if root is not None:
            os.close(root.descriptor)


def _validate_zip_stream(
    stream: BinaryIO,
    *,
    input_size: int,
    limits: ArchiveLimits,
    deadline: float,
) -> _ArchiveSummary:
    """
    Validate one seekable ZIP stream after its descriptor is pinned.

    The implementation uses ``stream``, ``input_size``, ``limits``, and
    ``deadline`` to validate one seekable ZIP stream after its descriptor is
    pinned. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        stream: Stream object whose ``seek`` state is read while performing one
            seekable ZIP stream after its descriptor is pinned.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        limits: Limits governing one seekable ZIP stream after its descriptor is
            pinned.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        A ``_ArchiveSummary`` representing ZIP stream.

    Raises:
        ArchivePolicyError: If zip_read_failed.
    """

    expected = _inspect_zip_central_directory(stream, limits, deadline)
    stream.seek(0)
    try:
        with zipfile.ZipFile(_DeadlineReader(stream, deadline), "r") as archive:
            validation = _validate_zip_infos(
                archive,
                limits,
                deadline,
                expected_members=expected,
                input_size=input_size,
            )
            for info, parts, directory, _new_nodes, output in validation.entries:
                _check_deadline(deadline)
                if directory:
                    continue
                with archive.open(info, "r") as member_stream:
                    content_digest = _digest_member(
                        member_stream,
                        expected_bytes=info.file_size,
                        limits=limits,
                        deadline=deadline,
                    )
                validation.paths.record_content_digest(
                    parts,
                    content_digest,
                    duplicate=not output,
                    limits=limits,
                )
                if not output:
                    logger.warning(
                        "archive.identical_duplicate_member: accepted "
                        "validation-compatible duplicate %r",
                        "/".join(parts),
                    )
            return validation.summary
    except ArchivePolicyError:
        raise
    except (
        OSError,
        RuntimeError,
        zipfile.BadZipFile,
        NotImplementedError,
    ) as error:
        raise ArchivePolicyError("zip_read_failed") from error


def _validate_open_zip_stream_with_limits(
    stream: BinaryIO,
    limits: ArchiveLimits,
) -> ArchiveExtractionResult:
    """
    Validate a pinned, seekable ZIP stream with pre-resolved finite limits.

    The implementation uses ``stream`` and ``limits`` to validate an already
    pinned ZIP after its inbound or local-creation policy boundary has been
    resolved. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.
    Cleanup in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        stream: Stream object whose ``seek`` and ``tell`` state is read while
            validating the pinned, seekable ZIP stream.
        limits: Resolved finite limits governing the ZIP validation.

    Returns:
        The validated ``result``.

    Raises:
        ArchivePolicyError: If zip_seek_required; or input_size_limit.
    """

    deadline = time.monotonic() + limits.max_seconds
    try:
        original_position = stream.tell()
        input_size = stream.seek(0, os.SEEK_END)
        stream.seek(0)
    except (AttributeError, OSError, ValueError) as error:
        raise ArchivePolicyError("zip_seek_required") from error
    if input_size > limits.max_input_bytes:
        raise ArchivePolicyError("input_size_limit")
    try:
        summary = _validate_zip_stream(
            stream,
            input_size=input_size,
            limits=limits,
            deadline=deadline,
        )
    finally:
        try:
            stream.seek(original_position)
        except (OSError, ValueError):
            pass
    result = _extraction_result(summary)
    _report_controlled_drops(result)
    return result


def validate_open_zip_stream(
    stream: BinaryIO,
    *,
    limits: Optional[ArchiveLimits] = None,
) -> ArchiveExtractionResult:
    """
    Validate an untrusted pinned ZIP under the inbound finite policy.

    The caller retains ownership of the stream while the standard inbound
    policy verifies every member without materializing the archive.

    Args:
        stream: Pinned, seekable ZIP stream to validate.
        limits: Optional inbound limits; ``None`` resolves the configured
            inbound profile.

    Returns:
        The bounded validation and extraction accounting result.
    """

    return _validate_open_zip_stream_with_limits(
        stream,
        resolve_archive_limits(limits),
    )


def validate_open_zip_stream_for_creation(
    stream: BinaryIO,
    *,
    limits: Optional[ArchiveLimits] = None,
) -> ArchiveExtractionResult:
    """
    Verify a tool-created pinned ZIP under the local creation policy.

    This separate entry point prevents filesystem-scale local output limits
    from becoming valid policy for downloaded or otherwise untrusted input.

    Args:
        stream: Pinned, seekable tool-created ZIP stream to validate.
        limits: Optional creation limits; ``None`` selects the code-owned
            compatibility limits.

    Returns:
        The bounded validation and extraction accounting result.
    """

    return _validate_open_zip_stream_with_limits(
        stream,
        resolve_archive_creation_limits(limits),
    )


def validate_zip_archive(
    source: Union[str, os.PathLike[str]],
    *,
    limits: Optional[ArchiveLimits] = None,
) -> ArchiveExtractionResult:
    """
    Validate a ZIP completely without materializing its members.

    Central-directory structure and declared resources are admitted before any
    payload is expanded. Every accepted regular member is then read through the
    same deadline-aware descriptor so decompressor errors, short reads, and CRC
    mismatches fail closed. Duplicate paths must also carry identical content,
    matching extraction semantics.

    Args:
        source: filesystem location used as the source for this operation.
        limits: Optional Limits governing ZIP completely without materializing
            its members.

    Returns:
        The validated ``result``.

    Raises:
        ArchivePolicyError: If source_changed.
    """

    limits = resolve_archive_limits(limits)
    deadline = time.monotonic() + limits.max_seconds
    with _open_source(source, limits) as (stream, metadata):
        summary = _validate_zip_stream(
            stream,
            input_size=metadata.st_size,
            limits=limits,
            deadline=deadline,
        )
        if _source_fingerprint(os.fstat(stream.fileno())) != _source_fingerprint(
            metadata
        ):
            raise ArchivePolicyError("source_changed")

    result = _extraction_result(summary)
    _report_controlled_drops(result)
    return result


def extract_zip_archive(
    source: Union[str, os.PathLike[str]],
    destination: Union[str, os.PathLike[str]],
    *,
    limits: Optional[ArchiveLimits] = None,
    return_result: bool = False,
) -> Optional[ArchiveExtractionResult]:
    """
    Preflight and extract one ZIP through a single no-follow descriptor.

    The implementation uses ``source``, ``destination``, ``limits``, and
    ``return_result`` to preflight and extract one ZIP through a single
    no-follow descriptor. If the function cannot preflight and extract one ZIP
    through a single no-follow descriptor, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        source: filesystem location used as the source for this operation.
        destination: filesystem location used as the destination for this
            operation.
        limits: Optional Limits governing preflight and extract one ZIP through
            a single no-follow descriptor.
        return_result: Whether return result is enabled or required for this
            operation.

    Returns:
        An ``ArchiveExtractionResult`` representing ZIP archive, or ``None``
        when the requested value is unavailable.

    Raises:
        ArchivePolicyError: If zip_read_failed; source_changed; or
            zip_extract_failed.
    """
    limits = resolve_archive_limits(limits)
    deadline = time.monotonic() + limits.max_seconds
    extraction = None
    summary = None
    try:
        with _open_source(source, limits) as (stream, metadata):
            expected = _inspect_zip_central_directory(stream, limits, deadline)
            stream.seek(0)
            try:
                with zipfile.ZipFile(_DeadlineReader(stream, deadline), "r") as archive:
                    extraction, summary = _extract_validated_zip(
                        archive,
                        destination,
                        limits,
                        deadline,
                        expected_members=expected,
                        input_size=metadata.st_size,
                    )
            except ArchivePolicyError:
                raise
            except (
                OSError,
                RuntimeError,
                zipfile.BadZipFile,
                NotImplementedError,
            ) as error:
                raise ArchivePolicyError("zip_read_failed") from error
            if _source_fingerprint(os.fstat(stream.fileno())) != _source_fingerprint(
                metadata
            ):
                raise ArchivePolicyError("source_changed")
    except Exception:
        if extraction is not None:
            _cleanup_created(extraction)
        raise
    if summary is None:
        raise ArchivePolicyError("zip_extract_failed")
    result = _extraction_result(summary)
    _report_controlled_drops(result)
    return result if return_result else None


def extract_open_zip(
    archive: zipfile.ZipFile,
    destination: Union[str, os.PathLike[str]],
    *,
    limits: Optional[ArchiveLimits] = None,
    return_result: bool = False,
) -> Optional[ArchiveExtractionResult]:
    """
    Compatibility path for an already-open ZIP.

    The implementation uses ``archive``, ``destination``, ``limits``, and
    ``return_result`` to compatibility path for an already-open ZIP. If the
    function cannot compatibility path for an already-open ZIP, its exception
    reaches the caller instead of being converted into a successful result.
    Cleanup in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        archive: Archive object whose ``fp`` state is read while performing
            compatibility path for an already-open ZIP.
        destination: filesystem location used as the destination for this
            operation.
        limits: Optional Limits governing compatibility path for an already-open
            ZIP.
        return_result: Whether return result is enabled or required for this
            operation.

    Returns:
        An ``ArchiveExtractionResult`` representing open ZIP, or ``None`` when
        the requested value is unavailable.

    Raises:
        ArchivePolicyError: If zip_closed; zip_seek_required; or
            input_size_limit.
    """
    limits = resolve_archive_limits(limits)
    deadline = time.monotonic() + limits.max_seconds
    stream = archive.fp
    if stream is None or getattr(stream, "closed", False):
        raise ArchivePolicyError("zip_closed")
    try:
        seekable = stream.seekable()
    except (AttributeError, OSError, ValueError) as error:
        raise ArchivePolicyError("zip_seek_required") from error
    if not seekable:
        raise ArchivePolicyError("zip_seek_required")
    try:
        original_position = stream.tell()
        try:
            stream.seek(0, os.SEEK_END)
            input_size = stream.tell()
        finally:
            stream.seek(original_position)
    except (OSError, ValueError) as error:
        raise ArchivePolicyError("zip_seek_required") from error
    if input_size > limits.max_input_bytes:
        raise ArchivePolicyError("input_size_limit")
    expected = _inspect_zip_central_directory(stream, limits, deadline)
    _state, summary = _extract_validated_zip(
        archive,
        destination,
        limits,
        deadline,
        expected_members=expected,
        input_size=input_size,
    )
    result = _extraction_result(summary)
    _report_controlled_drops(result)
    return result if return_result else None


def _decompressed_tar_output_limit(
    input_size: int,
    limits: ArchiveLimits,
) -> int:
    """
    Bound TAR payload, metadata, headers, and block padding.

    After applying local validation, the function forwards ``input_size`` and
    ``limits`` to ``min`` and preserves its return and exception contract.

    Args:
        input_size: Numeric input size used by the operation's bounded
            accounting.
        limits: Limits governing bound TAR payload, metadata, headers, and block
            padding.

    Returns:
        The numeric decompressed TAR output limit.
    """
    structural_bytes = limits.max_metadata_bytes + (
        (2 * limits.max_members + 2) * tarfile.BLOCKSIZE * 2
    )
    expanded_limit = limits.max_total_bytes + structural_bytes
    ratio_limit = (
        math.ceil(input_size * limits.max_compression_ratio)
        if input_size > 0
        else expanded_limit
    )
    return min(expanded_limit, ratio_limit)


def _admit_tar_stream_extent(stream_end: int, maximum: int) -> None:
    """
    Reject parsed TAR structure that exceeds its container expansion bound.

    The implementation uses ``stream_end`` and ``maximum`` to reject parsed TAR
    structure that exceeds its container expansion bound. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        stream_end: Numeric stream end used while the operation performs bounded
            accounting.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.

    Raises:
        ArchivePolicyError: If decompressed_stream_limit.
    """
    if stream_end < 0 or stream_end > maximum:
        raise ArchivePolicyError("decompressed_stream_limit")


def _admit_spool_write(
    output: BinaryIO,
    *,
    next_write_bytes: int,
    limits: ArchiveLimits,
) -> None:
    """
    Best-effort reserve check for the filesystem backing a temporary spool.

    The implementation uses ``output``, ``next_write_bytes``, and ``limits`` to
    best-effort reserve check for the filesystem backing a temporary spool. If
    the function cannot best-effort reserve check for the filesystem backing a
    temporary spool, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        output: Output object whose ``fileno`` state is read while performing
            best-effort reserve check for the filesystem backing a temporary
            spool.
        next_write_bytes: Numeric next write bytes used while the operation
            performs bounded accounting.
        limits: Limits governing best-effort reserve check for the filesystem
            backing a temporary spool.

    Raises:
        ArchivePolicyError: If destination_space_limit.
    """
    try:
        filesystem = os.fstatvfs(output.fileno())
    except (AttributeError, OSError):
        return
    fragment_size = getattr(filesystem, "f_frsize", 0) or getattr(
        filesystem,
        "f_bsize",
        0,
    )
    available_blocks = getattr(filesystem, "f_bavail", -1)
    if fragment_size > 0 and available_blocks >= 0:
        available_bytes = fragment_size * available_blocks
        if available_bytes < next_write_bytes + limits.disk_reserve_bytes:
            raise ArchivePolicyError("destination_space_limit")


def _decompress_bzip2_bounded(
    source: BinaryIO,
    output: BinaryIO,
    *,
    input_size: int,
    limits: ArchiveLimits,
    deadline: float,
) -> int:
    """
    Decode concatenated bzip2 frames with an explicit output allocation cap.

    The implementation uses ``source``, ``output``, ``input_size``, ``limits``,
    and ``deadline`` to decode concatenated bzip2 frames with an explicit output
    allocation cap. Parsing or I/O must finish before the validated
    representation is made available to the caller. Filesystem effects remain
    confined to the caller-selected paths and the owning resource lifecycle. If
    the function cannot decode concatenated bzip2 frames with an explicit output
    allocation cap, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        source: Source object whose ``seek`` state is read while performing
            concatenated bzip2 frames with an explicit output allocation cap.
        output: Output object whose ``flush`` and ``write`` state is read while
            performing concatenated bzip2 frames with an explicit output
            allocation cap.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        limits: Limits governing concatenated bzip2 frames with an explicit
            output allocation cap.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The validated ``written``.

    Raises:
        ArchivePolicyError: If bzip2_trailing_data; decompressor_memory_limit;
            bzip2_truncated; or decompressed_stream_limit; or another input
            invariant is violated.
    """

    maximum = _decompressed_tar_output_limit(input_size, limits)
    source.seek(0)
    reader = _DeadlineReader(source, deadline)
    written = 0
    pending = reader.read(COPY_CHUNK_BYTES)
    try:
        while pending:
            while len(pending) < _COMPRESSED_TAR_HEADER_BYTES:
                additional = reader.read(_COMPRESSED_TAR_HEADER_BYTES - len(pending))
                if not additional:
                    raise ArchivePolicyError("bzip2_trailing_data")
                pending += additional
            required = _bzip2_decompressor_memory_requirement(
                pending[:_COMPRESSED_TAR_HEADER_BYTES]
            )
            if required > limits.max_decompressor_memory_bytes:
                raise ArchivePolicyError("decompressor_memory_limit")
            decoder = bz2.BZ2Decompressor()
            while not decoder.eof:
                compressed = pending if decoder.needs_input else b""
                pending = b""
                if not compressed and decoder.needs_input:
                    compressed = reader.read(COPY_CHUNK_BYTES)
                if not compressed and decoder.needs_input:
                    raise ArchivePolicyError("bzip2_truncated")
                chunk = decoder.decompress(
                    compressed,
                    max_length=min(COPY_CHUNK_BYTES, maximum + 1 - written),
                )
                _check_deadline(deadline)
                if chunk:
                    written += len(chunk)
                    if written > maximum:
                        raise ArchivePolicyError("decompressed_stream_limit")
                    _admit_spool_write(
                        output,
                        next_write_bytes=len(chunk),
                        limits=limits,
                    )
                    try:
                        copied = output.write(chunk)
                    except OSError as error:
                        _raise_if_destination_capacity_error(
                            error,
                            Path(tempfile.gettempdir()),
                        )
                        raise ArchivePolicyError("temporary_write_failed") from error
                    if copied != len(chunk):
                        raise ArchivePolicyError("destination_space_limit")
                elif not decoder.needs_input and not decoder.eof:
                    raise ArchivePolicyError("bzip2_no_progress")
            pending = decoder.unused_data or reader.read(COPY_CHUNK_BYTES)
            if len(pending) >= len(_BZIP2_MAGIC) and not pending.startswith(
                _BZIP2_MAGIC
            ):
                raise ArchivePolicyError("bzip2_trailing_data")
    except ArchivePolicyError:
        raise
    except MemoryError as error:
        raise ArchivePolicyError("decompressor_memory_limit") from error
    except (EOFError, OSError) as error:
        raise ArchivePolicyError("bzip2_decompression_failed") from error
    try:
        output.flush()
    except OSError as error:
        _raise_if_destination_capacity_error(
            error,
            Path(tempfile.gettempdir()),
        )
        raise ArchivePolicyError("temporary_write_failed") from error
    return written


def _decompress_xz_bounded(
    source: BinaryIO,
    output: BinaryIO,
    *,
    input_size: int,
    limits: ArchiveLimits,
    deadline: float,
    maximum_output_bytes: Optional[int] = None,
) -> int:
    """
    Decode one XZ stream with explicit memory, output, ratio, and time caps.

    The implementation uses ``source``, ``output``, ``input_size``, ``limits``,
    and ``deadline`` to decode one XZ stream with explicit memory, output,
    ratio, and time caps. Parsing or I/O must finish before the validated
    representation is made available to the caller. Filesystem effects remain
    confined to the caller-selected paths and the owning resource lifecycle. If
    the function cannot decode one XZ stream with explicit memory, output,
    ratio, and time caps, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        source: Source object whose ``seek`` state is read while performing one
            XZ stream with explicit memory, output, ratio, and time caps.
        output: Output object whose ``flush`` and ``write`` state is read while
            performing one XZ stream with explicit memory, output, ratio, and
            time caps.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        limits: Limits governing one XZ stream with explicit memory, output,
            ratio, and time caps.
        deadline: Absolute monotonic deadline after which the operation must
            stop.
        maximum_output_bytes: Upper bound enforced for output bytes; the
            consuming boundary rejects or truncates values that exceed it.

    Returns:
        The validated ``written``.

    Raises:
        ValueError: If the maximum xz output bytes are not a positive integer.
        ArchivePolicyError: If xz_truncated; decompressed_stream_limit;
            temporary_write_failed; or destination_space_limit; or another input
            invariant is violated.
    """
    maximum = _decompressed_tar_output_limit(input_size, limits)
    if maximum_output_bytes is not None:
        if (
            not isinstance(maximum_output_bytes, int)
            or isinstance(maximum_output_bytes, bool)
            or maximum_output_bytes <= 0
        ):
            raise ValueError("maximum XZ output bytes must be a positive integer")
        maximum = min(maximum, maximum_output_bytes)
    source.seek(0)
    reader = _DeadlineReader(source, deadline)
    written = 0
    try:
        decoder = lzma.LZMADecompressor(
            format=lzma.FORMAT_XZ,
            memlimit=limits.max_decompressor_memory_bytes,
        )
        while not decoder.eof:
            compressed = reader.read(COPY_CHUNK_BYTES) if decoder.needs_input else b""
            if not compressed and decoder.needs_input:
                raise ArchivePolicyError("xz_truncated")
            chunk = decoder.decompress(
                compressed,
                max_length=min(COPY_CHUNK_BYTES, maximum + 1 - written),
            )
            _check_deadline(deadline)
            if chunk:
                written += len(chunk)
                if written > maximum:
                    raise ArchivePolicyError("decompressed_stream_limit")
                _admit_spool_write(
                    output,
                    next_write_bytes=len(chunk),
                    limits=limits,
                )
                try:
                    copied = output.write(chunk)
                except OSError as error:
                    _raise_if_destination_capacity_error(
                        error,
                        Path(tempfile.gettempdir()),
                    )
                    raise ArchivePolicyError("temporary_write_failed") from error
                if copied != len(chunk):
                    raise ArchivePolicyError("destination_space_limit")
            elif not decoder.needs_input and not decoder.eof:
                raise ArchivePolicyError("xz_no_progress")

        trailing_bytes = len(decoder.unused_data)
        trailing_nonzero = any(decoder.unused_data)
        while True:
            chunk = reader.read(COPY_CHUNK_BYTES)
            if not chunk:
                break
            trailing_bytes += len(chunk)
            trailing_nonzero = trailing_nonzero or any(chunk)
        if trailing_nonzero or trailing_bytes % 4:
            raise ArchivePolicyError("xz_trailing_data")
    except ArchivePolicyError:
        raise
    except MemoryError as error:
        raise ArchivePolicyError("decompressor_memory_limit") from error
    except lzma.LZMAError as error:
        reason = (
            "decompressor_memory_limit"
            if "memory usage limit" in str(error).casefold()
            else "xz_decompression_failed"
        )
        raise ArchivePolicyError(reason) from error
    try:
        output.flush()
    except OSError as error:
        _raise_if_destination_capacity_error(
            error,
            Path(tempfile.gettempdir()),
        )
        raise ArchivePolicyError("temporary_write_failed") from error
    return written


class _DiscardingBinaryWriter:
    """
    A write sink used when bounded decompression is validation-only.

    The type coordinates ``write`` and ``flush`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def write(self, value: bytes) -> int:
        """
        Write the supplied data to the owned destination.

        After applying local validation, the function forwards ``value`` to
        ``len`` and preserves its return and exception contract. Success is
        reported only after the owning output boundary has completed its
        required write or publication step.

        Args:
            value: Bounded byte sequence supplied as value.

        Returns:
            The numeric write value.
        """
        return len(value)

    def flush(self) -> None:
        """
        Flush buffered data through the owned destination.

        The implementation uses current instance state to flush buffered data
        through the owned destination.
        """
        return None


def validate_xz_file(
    source: Union[str, os.PathLike[str]],
    *,
    limits: Optional[ArchiveLimits] = None,
) -> int:
    """
    Validate one standalone XZ stream under the shared archive limits.

    Unlike :func:`lzma.open`, this path supplies liblzma's memory limit before
    decoding begins. It also consumes the complete stream, validates its footer
    and padding, rejects non-padding trailing data, and retains the configured
    input, output, compression-ratio, and wall-clock ceilings.

    Args:
        source: filesystem location used as the source for this operation.
        limits: Optional Limits governing one standalone XZ stream under the
            shared archive limits.

    Returns:
        The validated ``written``.

    Raises:
        ArchivePolicyError: If source_changed.
    """

    active_limits = resolve_archive_limits(limits)
    deadline = time.monotonic() + active_limits.max_seconds
    with _open_source(source, active_limits) as (stream, metadata):
        written = _decompress_xz_bounded(
            stream,
            _DiscardingBinaryWriter(),
            input_size=metadata.st_size,
            limits=active_limits,
            deadline=deadline,
            maximum_output_bytes=min(
                active_limits.max_member_bytes,
                active_limits.max_total_bytes,
            ),
        )
        if _source_fingerprint(os.fstat(stream.fileno())) != _source_fingerprint(
            metadata
        ):
            raise ArchivePolicyError("source_changed")
    return written


def _decompress_zstd_bounded(
    source: BinaryIO,
    output: BinaryIO,
    *,
    input_size: int,
    limits: ArchiveLimits,
    deadline: float,
) -> int:
    """
    Decode a zstd stream with explicit window, output, and time caps.

    The implementation uses ``source``, ``output``, ``input_size``, ``limits``,
    and ``deadline`` to decode a zstd stream with explicit window, output, and
    time caps. Parsing or I/O must finish before the validated representation is
    made available to the caller. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. If the function
    cannot decode a zstd stream with explicit window, output, and time caps, its
    exception reaches the caller instead of being converted into a successful
    result. Cleanup in the ``finally`` path runs for successful, failed, and
    cancelled execution.

    Args:
        source: Source object whose ``seek`` state is read while performing zstd
            stream with explicit window, output, and time caps.
        output: Output object whose ``flush`` and ``write`` state is read while
            performing zstd stream with explicit window, output, and time caps.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        limits: Limits governing zstd stream with explicit window, output, and
            time caps.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The validated ``written``.

    Raises:
        ArchivePolicyError: If decompressed_stream_limit;
            temporary_write_failed; destination_space_limit; or
            decompressor_memory_limit; or another input invariant is violated.
    """

    maximum = _decompressed_tar_output_limit(input_size, limits)
    source.seek(0)
    reader = None
    written = 0
    try:
        reader = StrictZstdReader(
            _DeadlineReader(source, deadline),
            max_window_size=limits.max_decompressor_memory_bytes,
            max_output_bytes=maximum,
            max_input_bytes=max(1, input_size),
            max_frames=limits.max_members,
            check_deadline=lambda: _check_deadline(deadline),
        )
        while True:
            _check_deadline(deadline)
            chunk = reader.read(min(COPY_CHUNK_BYTES, max(1, maximum - written)))
            _check_deadline(deadline)
            if not chunk:
                break
            written += len(chunk)
            if written > maximum:
                raise ArchivePolicyError("decompressed_stream_limit")
            _admit_spool_write(
                output,
                next_write_bytes=len(chunk),
                limits=limits,
            )
            try:
                copied = output.write(chunk)
            except OSError as error:
                _raise_if_destination_capacity_error(
                    error,
                    Path(tempfile.gettempdir()),
                )
                raise ArchivePolicyError("temporary_write_failed") from error
            if copied != len(chunk):
                raise ArchivePolicyError("destination_space_limit")
    except ArchivePolicyError:
        raise
    except MemoryError as error:
        raise ArchivePolicyError("decompressor_memory_limit") from error
    except StrictZstdError as error:
        reason = {
            "decompressor_memory_limit": "decompressor_memory_limit",
            "output_size_limit": "decompressed_stream_limit",
            "input_size_limit": "input_size_limit",
            "frame_count_limit": "zstd_frame_count_limit",
            "truncated_frame": "zstd_truncated",
            "non_frame_suffix": "zstd_trailing_data",
            "empty_stream": "zstd_decompression_failed",
        }.get(error.reason, "zstd_decompression_failed")
        raise ArchivePolicyError(reason) from error
    finally:
        if reader is not None:
            reader.close()
    try:
        output.flush()
    except OSError as error:
        _raise_if_destination_capacity_error(
            error,
            Path(tempfile.gettempdir()),
        )
        raise ArchivePolicyError("temporary_write_failed") from error
    return written


@contextmanager
def _open_bounded_bzip2_tar(
    source: BinaryIO,
    *,
    input_size: int,
    limits: ArchiveLimits,
    deadline: float,
) -> Iterator[BinaryIO]:
    """
    Open bounded bzip2 TAR.

    The implementation uses ``source``, ``input_size``, ``limits``, and
    ``deadline`` to open bounded bzip2 TAR. If the function cannot open bounded
    bzip2 TAR, its exception reaches the caller instead of being converted into
    a successful result.

    Args:
        source: Source consumed while the function attempts to open bounded
            bzip2 TAR.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        limits: Limits governing open bounded bzip2 TAR.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Yields:
        Each open bounded bzip2 TAR admitted by the operation, in deterministic
        iteration order.

    Raises:
        ArchivePolicyError: If temporary_file_create_failed.
    """
    try:
        spool = tempfile.TemporaryFile(prefix="nvdebug_bzip2_", suffix=".tar")
    except OSError as error:
        _raise_if_destination_capacity_error(
            error,
            Path(tempfile.gettempdir()),
        )
        raise ArchivePolicyError("temporary_file_create_failed") from error
    with spool:
        _decompress_bzip2_bounded(
            source,
            spool,
            input_size=input_size,
            limits=limits,
            deadline=deadline,
        )
        spool.seek(0)
        yield spool


@contextmanager
def _open_bounded_xz_tar(
    source: BinaryIO,
    *,
    input_size: int,
    limits: ArchiveLimits,
    deadline: float,
) -> Iterator[BinaryIO]:
    """
    Open bounded xz TAR.

    The implementation uses ``source``, ``input_size``, ``limits``, and
    ``deadline`` to open bounded xz TAR. If the function cannot open bounded xz
    TAR, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        source: Source consumed while the function attempts to open bounded xz
            TAR.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        limits: Limits governing open bounded xz TAR.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Yields:
        Each open bounded xz TAR admitted by the operation, in deterministic
        iteration order.

    Raises:
        ArchivePolicyError: If temporary_file_create_failed.
    """
    try:
        spool = tempfile.TemporaryFile(prefix="nvdebug_xz_", suffix=".tar")
    except OSError as error:
        _raise_if_destination_capacity_error(
            error,
            Path(tempfile.gettempdir()),
        )
        raise ArchivePolicyError("temporary_file_create_failed") from error
    with spool:
        _decompress_xz_bounded(
            source,
            spool,
            input_size=input_size,
            limits=limits,
            deadline=deadline,
        )
        spool.seek(0)
        yield spool


@contextmanager
def _open_bounded_zstd_tar(
    source: BinaryIO,
    *,
    input_size: int,
    limits: ArchiveLimits,
    deadline: float,
) -> Iterator[BinaryIO]:
    """
    Open bounded zstd TAR.

    The implementation uses ``source``, ``input_size``, ``limits``, and
    ``deadline`` to open bounded zstd TAR. If the function cannot open bounded
    zstd TAR, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        source: Source consumed while the function attempts to open bounded zstd
            TAR.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        limits: Limits governing open bounded zstd TAR.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Yields:
        Each open bounded zstd TAR admitted by the operation, in deterministic
        iteration order.

    Raises:
        ArchivePolicyError: If temporary_file_create_failed.
    """
    try:
        spool = tempfile.TemporaryFile(prefix="nvdebug_zstd_", suffix=".tar")
    except OSError as error:
        _raise_if_destination_capacity_error(
            error,
            Path(tempfile.gettempdir()),
        )
        raise ArchivePolicyError("temporary_file_create_failed") from error
    with spool:
        _decompress_zstd_bounded(
            source,
            spool,
            input_size=input_size,
            limits=limits,
            deadline=deadline,
        )
        spool.seek(0)
        yield spool


def _stream_is_xz(stream: BinaryIO, deadline: float) -> bool:
    """
    Return the stream is xz.

    The implementation uses ``stream`` and ``deadline`` to produce the stream is
    xz. Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        stream: Stream object whose ``seek`` and ``tell`` state is read while
            performing stream is xz.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        Whether the stream is xz operation succeeds.
    """
    position = stream.tell()
    try:
        return _DeadlineReader(stream, deadline).read(len(_XZ_MAGIC)) == _XZ_MAGIC
    finally:
        stream.seek(position)


def _stream_is_bzip2(stream: BinaryIO, deadline: float) -> bool:
    """
    Return the stream is bzip2.

    The implementation uses ``stream`` and ``deadline`` to produce the stream is
    bzip2. Filesystem effects remain confined to the caller-selected paths and
    the owning resource lifecycle. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        stream: Stream object whose ``seek`` and ``tell`` state is read while
            performing stream is bzip2.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        Whether the stream is bzip2 operation succeeds.
    """
    position = stream.tell()
    try:
        return _DeadlineReader(stream, deadline).read(len(_BZIP2_MAGIC)) == _BZIP2_MAGIC
    finally:
        stream.seek(position)


def _stream_is_zstd(stream: BinaryIO, deadline: float) -> bool:
    """
    Return the stream is zstd.

    The implementation uses ``stream`` and ``deadline`` to produce the stream is
    zstd. Filesystem effects remain confined to the caller-selected paths and
    the owning resource lifecycle. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        stream: Stream object whose ``seek`` and ``tell`` state is read while
            performing stream is zstd.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        Whether the stream is zstd operation succeeds.
    """
    position = stream.tell()
    try:
        return _DeadlineReader(stream, deadline).read(len(_ZSTD_MAGIC)) == _ZSTD_MAGIC
    finally:
        stream.seek(position)


def _tar_decompressor_memory_requirement(header: bytes) -> int:
    """
    Return a conservative decoder working-set admission for TAR streams.

    Inflate's 32-KiB window is small; keep extra room for decoder state and the
    buffered streaming adapter used by tarfile.

    Args:
        header: Bounded byte sequence supplied as header.

    Returns:
        The numeric TAR decompressor memory requirement value.

    Raises:
        ArchivePolicyError: If tar_read_failed.
    """
    if header.startswith(_GZIP_MAGIC):
        if len(header) < 3 or header[2] != 8:
            raise ArchivePolicyError("tar_read_failed")
        # Inflate's 32-KiB window is small; keep extra room for decoder state
        # and the buffered streaming adapter used by tarfile.
        return _GZIP_DECOMPRESSOR_BYTES

    if header.startswith(_BZIP2_MAGIC):
        return _bzip2_decompressor_memory_requirement(header)

    # tarfile's streaming auto-detector recognizes the stdlib LZMA-alone
    # encoding by this prefix. Its 13-byte header declares properties and the
    # dictionary size but provides no magic distinct from arbitrary data.
    if header.startswith(_LZMA_ALONE_TAR_PREFIX):
        if len(header) < _COMPRESSED_TAR_HEADER_BYTES:
            raise ArchivePolicyError("tar_read_failed")
        property_byte = header[0]
        if property_byte >= 9 * 5 * 5:
            raise ArchivePolicyError("tar_read_failed")
        lc = property_byte % 9
        remainder = property_byte // 9
        lp = remainder % 5
        pb = remainder // 5
        if pb > 4 or lc + lp > 4:
            raise ArchivePolicyError("tar_read_failed")
        dictionary_bytes = max(struct.unpack_from("<I", header, 1)[0], 4096)
        probability_bytes = 2 * (
            _LZMA1_BASE_PROBABILITIES + (_LZMA1_LITERAL_PROBABILITIES << (lc + lp))
        )
        return dictionary_bytes + probability_bytes + _LZMA1_DECOMPRESSOR_OVERHEAD_BYTES

    return 0


def _bzip2_decompressor_memory_requirement(header: bytes) -> int:
    """
    Admit a bzip2 frame, including an empty frame with immediate EOS.

    bzip2 decompression is approximately four times the encoded 100,000-byte
    block-size digit, plus decoder and stream state.

    Args:
        header: Bounded byte sequence supplied as header.

    Returns:
        The numeric bzip2 decompressor memory requirement value.

    Raises:
        ArchivePolicyError: If tar_read_failed.
    """

    if (
        len(header) < 10
        or not header.startswith(_BZIP2_MAGIC)
        or header[3:4] < b"1"
        or header[3:4] > b"9"
        or header[4:10] not in {_BZIP2_BLOCK_MAGIC, _BZIP2_END_MAGIC}
    ):
        raise ArchivePolicyError("tar_read_failed")
    # bzip2 decompression is approximately four times the encoded
    # 100,000-byte block-size digit, plus decoder and stream state.
    block_bytes = (header[3] - ord("0")) * 100_000
    return (4 * block_bytes) + _BZIP2_DECOMPRESSOR_OVERHEAD_BYTES


def _admit_tar_decompressor_memory(
    stream: BinaryIO,
    limits: ArchiveLimits,
    deadline: float,
) -> None:
    """
    Admit TAR decompressor memory.

    The implementation uses ``stream``, ``limits``, and ``deadline`` to admit
    TAR decompressor memory. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. If the function
    cannot admit TAR decompressor memory, its exception reaches the caller
    instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        stream: Stream object whose ``seek`` and ``tell`` state is read while
            performing admit TAR decompressor memory.
        limits: Limits governing admit TAR decompressor memory.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Raises:
        ArchivePolicyError: If decompressor_memory_limit.
    """
    position = stream.tell()
    try:
        header = _DeadlineReader(stream, deadline).read(_COMPRESSED_TAR_HEADER_BYTES)
    finally:
        stream.seek(position)
    required = _tar_decompressor_memory_requirement(header)
    if required > limits.max_decompressor_memory_bytes:
        raise ArchivePolicyError("decompressor_memory_limit")


def _record_tar_member_fingerprint(
    state: _TarState,
    plan: _TarMemberPlan,
    content_digest: Optional[bytes] = None,
) -> None:
    """
    Record TAR member fingerprint.

    The implementation uses ``state``, ``plan``, and ``content_digest`` to
    record TAR member fingerprint. The operation mutates ``state`` in place;
    ownership of those objects remains with the caller.

    Args:
        state: State object whose ``sequence_hasher`` and ``update`` state is
            read while performing record TAR member fingerprint.
        plan: Plan object whose ``fingerprint`` and ``parts`` state is read
            while performing record TAR member fingerprint.
        content_digest: Optional content digest; ``None`` selects the function's
            default behavior.
    """
    values: tuple[object, ...] = (
        "/".join(plan.parts),
        *plan.fingerprint,
        content_digest if content_digest is not None else b"",
    )
    for value in values:
        if isinstance(value, bytes):
            tag = b"b"
            encoded = value
        elif isinstance(value, int):
            tag = b"i"
            encoded = str(value).encode("ascii")
        else:
            tag = b"s"
            encoded = str(value).encode("utf-8", errors="surrogateescape")
        state.sequence_hasher.update(tag)
        state.sequence_hasher.update(len(encoded).to_bytes(8, "big"))
        state.sequence_hasher.update(encoded)


def _finish_tar_member(
    state: _TarState,
    plan: _TarMemberPlan,
    *,
    limits: ArchiveLimits,
    content_digest: Optional[bytes] = None,
    warn_duplicate: bool = False,
) -> None:
    """
    Finish TAR member.

    The implementation uses ``state``, ``plan``, ``limits``, ``content_digest``,
    and ``warn_duplicate`` to finish TAR member. If the function cannot finish
    TAR member, its exception reaches the caller instead of being converted into
    a successful result.

    Args:
        state: State object whose ``paths`` and ``record_content_digest`` state
            is read while performing finish TAR member.
        plan: Plan object whose ``duplicate``, ``kind``, and ``parts`` state is
            read while performing finish TAR member.
        limits: Limits governing finish TAR member.
        content_digest: Optional content digest; ``None`` selects the function's
            default behavior.
        warn_duplicate: Whether warn duplicate is enabled or required for this
            operation.

    Raises:
        ArchivePolicyError: If tar_member_unreadable.
    """
    if plan.kind == "file":
        if content_digest is None:
            raise ArchivePolicyError("tar_member_unreadable")
        state.paths.record_content_digest(
            plan.parts,
            content_digest,
            duplicate=plan.duplicate,
            limits=limits,
        )
    _record_tar_member_fingerprint(state, plan, content_digest)
    if plan.duplicate and warn_duplicate:
        logger.warning(
            "archive.identical_duplicate_member: accepted "
            "extraction-compatible duplicate %r",
            "/".join(plan.parts),
        )


def _validate_tar_member(
    member: tarfile.TarInfo,
    state: _TarState,
    metadata_budget: _TarMetadataBudget,
    *,
    input_size: int,
    max_stream_bytes: int,
    limits: ArchiveLimits,
    deadline: float,
    skip_special_members: bool = False,
) -> _TarMemberPlan:
    """
    Validate TAR member.

    The implementation uses ``member``, ``state``, ``metadata_budget``,
    ``input_size``, and ``max_stream_bytes`` to validate TAR member. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        member: Member object whose ``_block``, ``devmajor``, ``devminor``,
            ``gid``, and ``gname`` state is read while performing TAR member.
        state: State object whose ``dropped_links``,
            ``dropped_special_members``, ``members``, ``output_bytes``, and
            ``paths`` state is read while performing TAR member.
        metadata_budget: Metadata budget consumed while the function attempts to
            validate TAR member.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        max_stream_bytes: Upper bound enforced for max stream bytes; the
            consuming boundary rejects or truncates values that exceed it.
        limits: Limits governing TAR member.
        deadline: Absolute monotonic deadline after which the operation must
            stop.
        skip_special_members: Whether skip special members is enabled or
            required for this operation.

    Returns:
        A ``_TarMemberPlan`` representing TAR member.

    Raises:
        ArchivePolicyError: If member_count_limit; member_size_limit;
            tar_read_failed; or sparse_member; or another input invariant is
            violated.
    """
    _check_deadline(deadline)
    state.members += 1
    if state.members > limits.max_members:
        raise ArchivePolicyError("member_count_limit")
    metadata_bytes = (
        _metadata_length(member.name)
        + _metadata_length(member.uname)
        + _metadata_length(member.gname)
        + _metadata_length(member.linkname)
        + sum(
            _metadata_length(key) + _metadata_length(value)
            for key, value in member.pax_headers.items()
        )
    )
    _account_tar_metadata(metadata_budget, metadata_bytes, limits)
    directory = member.isdir()
    regular = member.isfile()
    link = member.issym() or member.islnk()
    if member.size < 0:
        raise ArchivePolicyError("member_size_limit")
    try:
        stream_end = member.offset_data + member._block(member.size)
    except (AttributeError, tarfile.TarError, ValueError) as error:
        raise ArchivePolicyError("tar_read_failed") from error
    if not member.isfile():
        _admit_tar_stream_extent(stream_end, max_stream_bytes)
    if (
        getattr(member, "sparse", None)
        or getattr(member, "issparse", lambda: False)()
        or any("sparse" in key.casefold() for key in member.pax_headers)
    ):
        raise ArchivePolicyError("sparse_member")
    if directory and member.name in {".", "./"}:
        return _TarMemberPlan(
            parts=(),
            kind="directory",
            duplicate=False,
            fingerprint=("directory", member.mode, member.uid, member.gid),
            output=False,
        )

    # Preserve the historical TAR-only compatibility for archives produced
    # with tar -P and the leading "./" emitted by common tar commands. ZIP
    # paths remain fail-closed.
    normalized_name = _normalized_tar_member_name(
        member.name,
        allow_absolute=True,
    )
    parts = _member_parts(
        normalized_name,
        directory=directory,
        limits=limits,
    )
    if link or (not directory and not regular):
        if not skip_special_members:
            raise ArchivePolicyError("special_member")
        kind = "link" if link else "special"
        fingerprint = (
            kind,
            member.type,
            member.linkname,
            member.mode,
            member.uid,
            member.gid,
            member.devmajor,
            member.devminor,
        )
        first = state.paths.register(
            parts,
            directory=False,
            limits=limits,
            output=False,
            fingerprint=fingerprint,
        )
        if link:
            state.dropped_links += 1
        else:
            state.dropped_special_members += 1
        return _TarMemberPlan(
            parts=parts,
            kind=kind,
            duplicate=not first,
            fingerprint=fingerprint,
            output=False,
        )
    if directory:
        if member.size:
            raise ArchivePolicyError("special_member")
        fingerprint = ("directory", member.mode, member.uid, member.gid)
        first = state.paths.register(
            parts,
            directory=True,
            limits=limits,
            fingerprint=fingerprint,
        )
        return _TarMemberPlan(
            parts=parts,
            kind="directory",
            duplicate=not first,
            fingerprint=fingerprint,
            output=first,
        )
    if member.size > limits.max_member_bytes:
        raise ArchivePolicyError("member_size_limit")
    state.total_bytes += member.size
    if state.total_bytes > limits.max_total_bytes:
        raise ArchivePolicyError("total_size_limit")
    if input_size > 0 and state.total_bytes / input_size > limits.max_compression_ratio:
        raise ArchivePolicyError("compression_ratio_limit")
    _admit_tar_stream_extent(stream_end, max_stream_bytes)
    fingerprint = ("file", member.size, member.mode, member.uid, member.gid)
    first = state.paths.register(
        parts,
        directory=False,
        limits=limits,
        fingerprint=fingerprint,
    )
    if first:
        state.output_bytes += member.size
        state.regular_files += 1
    return _TarMemberPlan(
        parts=parts,
        kind="file",
        duplicate=not first,
        fingerprint=fingerprint,
        output=first,
    )


def _validate_tar_terminal_padding(
    stream: BinaryIO,
    *,
    deadline: float,
    max_stream_bytes: int,
) -> None:
    """
    Require the second TAR end block and only zero padding through EOF.

    Python's streaming TAR reader stops after consuming the first 512-byte
    zero block. A structurally complete TAR requires a second zero block, and
    bytes after those blocks may only be zero record padding. Draining the
    decompressed stream also forces compressed-container footer validation.

    Args:
        stream: TAR reader positioned immediately after its first end block.
        deadline: Absolute monotonic deadline applied around every read.
        max_stream_bytes: Maximum admitted decompressed TAR extent.

    Raises:
        ArchivePolicyError: If the stream position is invalid, the second end
            block is missing, nonzero trailing data is present, record padding
            is incomplete, or the decompressed extent exceeds its bound.
    """

    try:
        initial_position = stream.tell()
    except (AttributeError, OSError, ValueError) as error:
        raise ArchivePolicyError("tar_read_failed") from error
    if initial_position < tarfile.BLOCKSIZE or (initial_position % tarfile.BLOCKSIZE):
        raise ArchivePolicyError("tar_read_failed")

    trailing_bytes = 0
    while True:
        _check_deadline(deadline)
        try:
            chunk = stream.read(COPY_CHUNK_BYTES)
        except (OSError, tarfile.TarError, ValueError) as error:
            raise ArchivePolicyError("tar_read_failed") from error
        _check_deadline(deadline)
        if not chunk:
            break
        if not isinstance(chunk, bytes) or any(chunk):
            raise ArchivePolicyError("tar_read_failed")
        trailing_bytes += len(chunk)
        _admit_tar_stream_extent(
            initial_position + trailing_bytes,
            max_stream_bytes,
        )

    final_position = initial_position + trailing_bytes
    if trailing_bytes < tarfile.BLOCKSIZE or final_position % tarfile.BLOCKSIZE:
        raise ArchivePolicyError("tar_read_failed")


def _scan_tar(
    stream: BinaryIO,
    *,
    input_size: int,
    limits: ArchiveLimits,
    deadline: float,
    skip_special_members: bool = False,
    visitor: Optional[TarArchiveVisitor] = None,
    metadata_visitor: Optional[TarArchiveMetadataVisitor] = None,
) -> _ArchiveSummary:
    """
    Scan TAR.

    After applying local validation, the function forwards ``stream``,
    ``input_size``, ``limits``, ``deadline``, and ``skip_special_members`` to
    ``_ArchiveSummary`` and preserves its return and exception contract.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        stream: Stream consumed while the function attempts to scan TAR.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        limits: Limits governing scan TAR.
        deadline: Absolute monotonic deadline after which the operation must
            stop.
        skip_special_members: Whether skip special members is enabled or
            required for this operation.
        visitor: Optional visitor; ``None`` selects the function's default
            behavior.
        metadata_visitor: Optional metadata visitor; ``None`` selects the
            function's default behavior.

    Returns:
        A ``_ArchiveSummary`` representing scan TAR.

    Raises:
        ArchivePolicyError: If tar_member_unreadable; or tar_read_failed.
    """
    state = _TarState()
    metadata_budget = _TarMetadataBudget()
    max_stream_bytes = _decompressed_tar_output_limit(input_size, limits)
    try:
        with tarfile.open(
            fileobj=_DeadlineReader(stream, deadline),
            mode="r|*",
            tarinfo=_bounded_tarinfo_class(
                limits,
                metadata_budget,
                deadline,
                max_stream_bytes,
            ),
        ) as archive:
            for member in archive:
                try:
                    plan = _validate_tar_member(
                        member,
                        state,
                        metadata_budget,
                        input_size=input_size,
                        max_stream_bytes=max_stream_bytes,
                        limits=limits,
                        deadline=deadline,
                        skip_special_members=skip_special_members,
                    )
                    archive_member = TarArchiveMember(
                        name="/".join(plan.parts),
                        size=member.size,
                        mtime=member.mtime,
                        mode=member.mode,
                        kind=plan.kind,
                        link_kind=(
                            "symlink"
                            if member.issym()
                            else "hardlink" if member.islnk() else None
                        ),
                        duplicate=plan.duplicate,
                        original_name=member.name,
                    )
                    if metadata_visitor is not None:
                        metadata_visitor(archive_member)
                    content_digest = None
                    if plan.kind == "file":
                        source = archive.extractfile(member)
                        if source is None:
                            raise ArchivePolicyError("tar_member_unreadable")
                        with source:
                            if visitor is None:
                                content_digest = _digest_member(
                                    source,
                                    expected_bytes=member.size,
                                    limits=limits,
                                    deadline=deadline,
                                )
                            else:
                                reader = BoundedTarMemberReader(
                                    source,
                                    expected_bytes=member.size,
                                    deadline=deadline,
                                )
                                try:
                                    visitor(archive_member, reader)
                                except BaseException:
                                    reader._active = False
                                    raise
                                content_digest = reader._finish()
                    _finish_tar_member(
                        state,
                        plan,
                        limits=limits,
                        content_digest=content_digest,
                        warn_duplicate=True,
                    )
                finally:
                    archive.members.clear()
            _validate_tar_terminal_padding(
                archive.fileobj,
                deadline=deadline,
                max_stream_bytes=max_stream_bytes,
            )
            _admit_tar_stream_extent(archive.fileobj.tell(), max_stream_bytes)
    except ArchivePolicyError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise ArchivePolicyError("tar_read_failed") from error
    _check_deadline(deadline)
    return _ArchiveSummary(
        members=state.members,
        total_bytes=state.total_bytes,
        output_bytes=state.output_bytes,
        path_nodes=state.paths.output_nodes,
        tracked_path_bytes=state.paths.tracked_bytes,
        regular_files=state.regular_files,
        dropped_links=state.dropped_links,
        dropped_special_members=state.dropped_special_members,
        member_fingerprint=state.sequence_hasher.digest(),
    )


def _extract_tar_stream(
    stream: BinaryIO,
    destination: Union[str, os.PathLike[str]],
    *,
    input_size: int,
    expected_summary: _ArchiveSummary,
    limits: ArchiveLimits,
    deadline: float,
) -> _ExtractionState:
    """
    Extract TAR stream.

    The implementation uses ``stream``, ``destination``, ``input_size``,
    ``expected_summary``, and ``limits`` to extract TAR stream. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot extract TAR stream, its exception reaches
    the caller instead of being converted into a successful result. Cleanup in
    the ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        stream: Stream consumed while the function attempts to extract TAR
            stream.
        destination: filesystem location used as the destination for this
            operation.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        expected_summary: Expected summary consumed while the function attempts
            to extract TAR stream.
        limits: Limits governing extract TAR stream.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The validated ``extraction``.

    Raises:
        ArchivePolicyError: If tar_member_unreadable; tar_changed; or
            tar_extract_failed.
    """
    validation = _TarState()
    metadata_budget = _TarMetadataBudget()
    extraction = _ExtractionState()
    max_stream_bytes = _decompressed_tar_output_limit(input_size, limits)
    root = None
    try:
        root = _prepare_destination(destination, extraction)
        admission = _DestinationAdmission(
            root.path,
            expected_summary,
            limits,
        )
        admission.check(extraction, force=True)
        with tarfile.open(
            fileobj=_DeadlineReader(stream, deadline),
            mode="r|*",
            tarinfo=_bounded_tarinfo_class(
                limits,
                metadata_budget,
                deadline,
                max_stream_bytes,
            ),
        ) as archive:
            for member in archive:
                try:
                    admission.check(extraction)
                    plan = _validate_tar_member(
                        member,
                        validation,
                        metadata_budget,
                        input_size=input_size,
                        max_stream_bytes=max_stream_bytes,
                        limits=limits,
                        deadline=deadline,
                        skip_special_members=True,
                    )
                    _assert_root_identity(root)
                    if plan.kind in {"link", "special"}:
                        _finish_tar_member(validation, plan, limits=limits)
                        continue
                    if plan.kind == "directory":
                        _finish_tar_member(validation, plan, limits=limits)
                        if not plan.output:
                            continue
                        with _open_destination_directory(
                            root,
                            plan.parts,
                            extraction,
                        ):
                            pass
                        extraction.processed_nodes = validation.paths.output_nodes
                        admission.check(extraction)
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        raise ArchivePolicyError("tar_member_unreadable")
                    if not plan.output:
                        with source:
                            content_digest = _digest_member(
                                source,
                                expected_bytes=member.size,
                                limits=limits,
                                deadline=deadline,
                            )
                        _finish_tar_member(
                            validation,
                            plan,
                            limits=limits,
                            content_digest=content_digest,
                        )
                        continue
                    with (
                        source,
                        _new_output_file(
                            root,
                            plan.parts,
                            extraction,
                        ) as target,
                    ):
                        extraction.processed_nodes = validation.paths.output_nodes
                        admission.check(extraction)
                        content_digest = _copy_member(
                            source,
                            target,
                            expected_bytes=member.size,
                            limits=limits,
                            state=extraction,
                            deadline=deadline,
                            admission=admission,
                            hasher=hashlib.sha256(),
                        )
                    _finish_tar_member(
                        validation,
                        plan,
                        limits=limits,
                        content_digest=content_digest,
                    )
                finally:
                    archive.members.clear()
            _admit_tar_stream_extent(archive.fileobj.tell(), max_stream_bytes)
        observed_summary = _ArchiveSummary(
            members=validation.members,
            total_bytes=validation.total_bytes,
            output_bytes=validation.output_bytes,
            path_nodes=validation.paths.output_nodes,
            tracked_path_bytes=validation.paths.tracked_bytes,
            regular_files=validation.regular_files,
            dropped_links=validation.dropped_links,
            dropped_special_members=validation.dropped_special_members,
            member_fingerprint=validation.sequence_hasher.digest(),
        )
        if observed_summary != expected_summary:
            raise ArchivePolicyError("tar_changed")
        admission.check(extraction, force=True)
        _assert_root_identity(root)
        return extraction
    except Exception as error:
        _cleanup_created(extraction)
        if isinstance(error, ArchivePolicyError):
            raise
        if isinstance(error, (OSError, tarfile.TarError)):
            raise ArchivePolicyError("tar_extract_failed") from error
        raise
    finally:
        if root is not None:
            os.close(root.descriptor)


def _inspect_open_tar_stream_with_limits(
    stream: BinaryIO,
    metadata: os.stat_result,
    *,
    limits: ArchiveLimits,
    visitor: Optional[TarArchiveVisitor],
    metadata_visitor: Optional[TarArchiveMetadataVisitor],
    source_path: Optional[Path] = None,
) -> ArchiveExtractionResult:
    """
    Inspect one already-pinned TAR stream under one shared deadline.

    The implementation uses ``stream``, ``metadata``, ``limits``, ``visitor``,
    and ``metadata_visitor`` to inspect one already-pinned TAR stream under one
    shared deadline. If the function cannot inspect one already-pinned TAR
    stream under one shared deadline, its exception reaches the caller instead
    of being converted into a successful result.

    Args:
        stream: Stream object whose ``fileno`` state is read while performing
            inspect one already-pinned TAR stream under one shared deadline.
        metadata: Metadata object whose ``st_size`` state is read while
            performing inspect one already-pinned TAR stream under one shared
            deadline.
        limits: Limits governing inspect one already-pinned TAR stream under one
            shared deadline.
        visitor: Visitor consumed while the function attempts to inspect one
            already-pinned TAR stream under one shared deadline.
        metadata_visitor: Metadata visitor consumed while the function attempts
            to inspect one already-pinned TAR stream under one shared deadline.
        source_path: Optional path that must continue to name the pinned stream.

    Returns:
        The validated ``result``.

    Raises:
        ArchivePolicyError: If source_changed; or tar_read_failed.
    """

    deadline = time.monotonic() + limits.max_seconds
    summary = None
    _admit_tar_decompressor_memory(stream, limits, deadline)
    _assert_source_unchanged(stream, metadata, path=source_path)

    def scan(candidate: BinaryIO) -> _ArchiveSummary:
        """
        Scan the bounded input for admissible records.

        After applying local validation, the function forwards ``candidate`` to
        ``_scan_tar`` and preserves its return and exception contract.

        Args:
            candidate: Candidate value or resource evaluated by this operation.

        Returns:
            A ``_ArchiveSummary`` representing scan.

        Raises:
            ArchivePolicyError: If source_changed.
        """
        _assert_source_unchanged(stream, metadata, path=source_path)
        return _scan_tar(
            candidate,
            input_size=metadata.st_size,
            limits=limits,
            deadline=deadline,
            skip_special_members=True,
            visitor=visitor,
            metadata_visitor=metadata_visitor,
        )

    if _stream_is_bzip2(stream, deadline):
        with _open_bounded_bzip2_tar(
            stream,
            input_size=metadata.st_size,
            limits=limits,
            deadline=deadline,
        ) as tar_stream:
            summary = scan(tar_stream)
    elif _stream_is_zstd(stream, deadline):
        with _open_bounded_zstd_tar(
            stream,
            input_size=metadata.st_size,
            limits=limits,
            deadline=deadline,
        ) as tar_stream:
            summary = scan(tar_stream)
    elif _stream_is_xz(stream, deadline):
        with _open_bounded_xz_tar(
            stream,
            input_size=metadata.st_size,
            limits=limits,
            deadline=deadline,
        ) as tar_stream:
            summary = scan(tar_stream)
    else:
        summary = scan(stream)
    _assert_source_unchanged(stream, metadata, path=source_path)

    if summary is None:
        raise ArchivePolicyError("tar_read_failed")
    result = _extraction_result(summary)
    _report_controlled_drops(result)
    return result


def _inspect_tar_archive_with_limits(
    source: Union[str, os.PathLike[str]],
    *,
    limits: ArchiveLimits,
    visitor: Optional[TarArchiveVisitor],
    metadata_visitor: Optional[TarArchiveMetadataVisitor],
) -> ArchiveExtractionResult:
    """
    Inspect one TAR from one pinned source under one shared deadline.

    After applying local validation, the function forwards ``source``,
    ``limits``, ``visitor``, and ``metadata_visitor`` to
    ``_inspect_open_tar_stream_with_limits`` and preserves its return and
    exception contract.

    Args:
        source: filesystem location used as the source for this operation.
        limits: Limits governing inspect one TAR from one pinned source under
            one shared deadline.
        visitor: Visitor consumed while the function attempts to inspect one TAR
            from one pinned source under one shared deadline.
        metadata_visitor: Metadata visitor consumed while the function attempts
            to inspect one TAR from one pinned source under one shared deadline.

    Returns:
        An ``ArchiveExtractionResult`` representing inspect TAR archive with
        limits.
    """

    with _open_source(source, limits) as (stream, metadata):
        return _inspect_open_tar_stream_with_limits(
            stream,
            metadata,
            limits=limits,
            visitor=visitor,
            metadata_visitor=metadata_visitor,
            source_path=Path(source),
        )


def _validate_open_tar_stream_with_limits(
    stream: BinaryIO,
    limits: ArchiveLimits,
) -> ArchiveExtractionResult:
    """
    Validate a pinned, seekable regular TAR with pre-resolved finite limits.

    After applying local validation, the function forwards ``stream`` and
    ``limits`` to ``_inspect_open_tar_stream_with_limits`` and preserves its
    return and exception contract. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path. Cleanup in the ``finally`` path runs for successful, failed,
    and cancelled execution.

    Args:
        stream: Stream object whose ``fileno``, ``seek``, and ``tell`` state is
            read while validating the pinned, seekable regular TAR stream.
        limits: Resolved finite limits governing the TAR validation.

    Returns:
        An ``ArchiveExtractionResult`` representing open TAR stream.

    Raises:
        ArchivePolicyError: If tar_seek_required; source_not_regular; or
            input_size_limit.
    """

    try:
        original_position = stream.tell()
        metadata = os.fstat(stream.fileno())
        stream.seek(0)
    except (AttributeError, OSError, ValueError) as error:
        raise ArchivePolicyError("tar_seek_required") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ArchivePolicyError("source_not_regular")
    if metadata.st_size > limits.max_input_bytes:
        raise ArchivePolicyError("input_size_limit")
    try:
        return _inspect_open_tar_stream_with_limits(
            stream,
            metadata,
            limits=limits,
            visitor=None,
            metadata_visitor=None,
        )
    finally:
        try:
            stream.seek(original_position)
        except (OSError, ValueError):
            pass


def validate_open_tar_stream(
    stream: BinaryIO,
    *,
    limits: Optional[ArchiveLimits] = None,
) -> ArchiveExtractionResult:
    """
    Validate an untrusted pinned TAR under the inbound finite policy.

    The caller retains ownership of the regular-file stream while the standard
    inbound policy verifies every member without materializing the archive.

    Args:
        stream: Pinned, seekable TAR stream to validate.
        limits: Optional inbound limits; ``None`` resolves the configured
            inbound profile.

    Returns:
        The bounded validation and extraction accounting result.
    """

    return _validate_open_tar_stream_with_limits(
        stream,
        resolve_archive_limits(limits),
    )


def validate_open_tar_stream_for_creation(
    stream: BinaryIO,
    *,
    limits: Optional[ArchiveLimits] = None,
) -> ArchiveExtractionResult:
    """
    Verify a tool-created pinned TAR under the local creation policy.

    This trusted-local entry point keeps creation-scale limits separate from
    downloaded or otherwise untrusted TAR validation.

    Args:
        stream: Pinned, seekable tool-created TAR stream to validate.
        limits: Optional creation limits; ``None`` selects the code-owned
            compatibility limits.

    Returns:
        The bounded validation and extraction accounting result.
    """

    return _validate_open_tar_stream_with_limits(
        stream,
        resolve_archive_creation_limits(limits),
    )


def validate_tar_archive(
    source: Union[str, os.PathLike[str]],
    *,
    limits: Optional[ArchiveLimits] = None,
) -> ArchiveExtractionResult:
    """
    Validate a TAR completely without materializing its members.

    The validation path shares the extraction policy's no-follow source open,
    decompressor-memory admission, member and aggregate byte ceilings,
    compression-ratio checks, metadata bounds, and wall-clock deadline. It is
    intended for callers that must prove a downloaded archive is complete but
    retain the archive itself rather than its extracted contents.

    Args:
        source: filesystem location used as the source for this operation.
        limits: Optional Limits governing TAR completely without materializing
            its members.

    Returns:
        An ``ArchiveExtractionResult`` representing TAR archive.
    """

    return _inspect_tar_archive_with_limits(
        source,
        limits=resolve_archive_limits(limits),
        visitor=None,
        metadata_visitor=None,
    )


def inspect_tar_archive(
    source: Union[str, os.PathLike[str]],
    visitor: TarArchiveVisitor,
    *,
    limits: Optional[ArchiveLimits] = None,
) -> ArchiveExtractionResult:
    """
    Validate a TAR while visiting regular members on the pinned stream.

    The synchronous visitor receives immutable member metadata and a bounded,
    positive-size reader. It must not retain the reader after returning. Any
    unread member suffix is drained and hashed by the inspector, so semantic
    checks cannot bypass complete payload, duplicate-content, footer, source
    identity, or resource-policy validation.

    Args:
        source: filesystem location used as the source for this operation.
        visitor: Visitor consumed while the function attempts to validate a TAR
            while visiting regular members on the pinned stream.
        limits: Optional Limits governing TAR while visiting regular members on
            the pinned stream.

    Returns:
        An ``ArchiveExtractionResult`` representing inspect TAR archive.

    Raises:
        TypeError: If the tar archive visitor is not callable.
    """

    if not callable(visitor):
        raise TypeError("TAR archive visitor must be callable")
    return _inspect_tar_archive_with_limits(
        source,
        limits=resolve_archive_limits(limits),
        visitor=visitor,
        metadata_visitor=None,
    )


def inspect_tar_archive_metadata(
    source: Union[str, os.PathLike[str]],
    visitor: TarArchiveMetadataVisitor,
    *,
    limits: Optional[ArchiveLimits] = None,
) -> ArchiveExtractionResult:
    """
    Validate a TAR while visiting every member on the pinned stream.

    The callback receives only immutable, already-normalized metadata. Regular
    member bodies are still drained and hashed by the bounded scanner, while
    links and special members remain visible to callers that need stricter
    semantic policy than the shared controlled-drop behavior.

    Args:
        source: filesystem location used as the source for this operation.
        visitor: Visitor consumed while the function attempts to validate a TAR
            while visiting every member on the pinned stream.
        limits: Optional Limits governing TAR while visiting every member on the
            pinned stream.

    Returns:
        An ``ArchiveExtractionResult`` representing inspect TAR archive
        metadata.

    Raises:
        TypeError: If the tar archive metadata visitor is not callable.
    """

    if not callable(visitor):
        raise TypeError("TAR archive metadata visitor must be callable")
    return _inspect_tar_archive_with_limits(
        source,
        limits=resolve_archive_limits(limits),
        visitor=None,
        metadata_visitor=visitor,
    )


def rewrite_tar_gz_regular_files(
    source: Union[str, os.PathLike[str]],
    destination: Union[str, os.PathLike[str]],
    *,
    limits: Optional[ArchiveLimits] = None,
    metadata_visitor: Optional[TarArchiveMetadataVisitor] = None,
) -> TarArchiveRewriteResult:
    """
    Rewrite one validated TAR as a gzip TAR containing only regular files.

    The source is scanned through the same bounded, no-follow policy used by
    extraction. Regular member bytes stream directly into an exclusively
    created mode-0600 destination; links, special members, directory entries,
    duplicate paths, ownership names, and privileged mode bits are not copied.
    The completed destination is independently revalidated before return.

    Args:
        source: Untrusted TAR path to scan without following its filesystem
            identity or archive links.
        destination: Absent path below an owner-private directory where the
            rewritten gzip TAR is created.
        limits: Optional archive limits; ``None`` selects the active bounded
            archive profile.
        metadata_visitor: Optional callback receiving every validated source
            member before controlled filtering.

    Returns:
        A record binding source validation to rewritten-output validation.

    Raises:
        ArchivePolicyError: If the destination boundary is unsafe, a duplicate
            regular path is present, the source changes or violates archive
            policy, output creation fails, or rewritten accounting diverges.

    Side Effects:
        Creates ``destination`` with mode 0600 on success. Removes the exact
        newly created destination when validation or rewriting fails.
    """

    resolved_limits = resolve_archive_limits(limits)
    source_path = Path(source)
    destination_path = Path(destination)
    if source_path.absolute() == destination_path.absolute():
        raise ArchivePolicyError("rewrite_destination_matches_source")

    try:
        parent_metadata = destination_path.parent.lstat()
        owner_uid = filesystem_owner_uid(
            destination_path.parent, observed_uid=parent_metadata.st_uid
        )
    except OSError as error:
        raise ArchivePolicyError("rewrite_destination_parent_unavailable") from error
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or parent_metadata.st_uid != owner_uid
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise ArchivePolicyError("rewrite_destination_parent_unsafe")

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    source_result: ArchiveExtractionResult | None = None
    rewritten_result: ArchiveExtractionResult | None = None
    try:
        try:
            descriptor = os.open(destination_path, flags, 0o600)
            os.fchmod(descriptor, 0o600)
            created = os.fstat(descriptor)
        except OSError as error:
            raise ArchivePolicyError("rewrite_destination_create_failed") from error
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_uid != owner_uid
            or stat.S_IMODE(created.st_mode) != 0o600
            or created.st_nlink != 1
            or created.st_size != 0
        ):
            raise ArchivePolicyError("rewrite_destination_unsafe")
        created_identity = (created.st_dev, created.st_ino)

        with os.fdopen(descriptor, "w+b") as target:
            descriptor = -1
            with tarfile.open(
                fileobj=target,
                mode="w:gz",
                format=tarfile.PAX_FORMAT,
            ) as rewritten_archive:

                def copy_regular_member(
                    member: TarArchiveMember, reader: BoundedTarMemberReader
                ) -> None:
                    """
                    Copy one validated unique regular member into the rewrite.

                    The callback rebuilds metadata from normalized fields and
                    streams bytes through the inspector-owned bounded reader;
                    it never reopens a path named by archive input.

                    Args:
                        member: Immutable normalized source-member metadata.
                        reader: Bounded reader for exactly this member's bytes.

                    Raises:
                        ArchivePolicyError: If a duplicate path reaches the
                            regular-member rewrite boundary.

                    Side Effects:
                        Appends one regular member to ``rewritten_archive`` and
                        consumes its bounded source reader.
                    """

                    if member.duplicate:
                        raise ArchivePolicyError("duplicate_member")
                    rewritten_member = tarfile.TarInfo(member.name)
                    rewritten_member.size = member.size
                    rewritten_member.mode = member.mode & 0o777
                    rewritten_member.mtime = (
                        int(member.mtime)
                        if isinstance(member.mtime, (int, float))
                        and not isinstance(member.mtime, bool)
                        and math.isfinite(member.mtime)
                        else 0
                    )
                    rewritten_member.uid = 0
                    rewritten_member.gid = 0
                    rewritten_member.uname = ""
                    rewritten_member.gname = ""
                    rewritten_archive.addfile(rewritten_member, reader)

                source_result = _inspect_tar_archive_with_limits(
                    source_path,
                    limits=resolved_limits,
                    visitor=copy_regular_member,
                    metadata_visitor=metadata_visitor,
                )
            target.flush()
            os.fsync(target.fileno())
            target.seek(0)
            rewritten_result = _validate_open_tar_stream_with_limits(
                target,
                resolved_limits,
            )
            final_metadata = os.fstat(target.fileno())
            if (
                (final_metadata.st_dev, final_metadata.st_ino) != created_identity
                or final_metadata.st_nlink != 1
                or final_metadata.st_size <= 0
            ):
                raise ArchivePolicyError("rewrite_destination_changed")
        if source_result is None or rewritten_result is None:
            raise ArchivePolicyError("rewrite_incomplete")
        if (
            source_result.regular_files <= 0
            or rewritten_result.members != source_result.regular_files
            or rewritten_result.regular_files != source_result.regular_files
            or rewritten_result.dropped_members != 0
        ):
            raise ArchivePolicyError("rewrite_accounting_mismatch")
        try:
            published_metadata = destination_path.lstat()
        except OSError as error:
            raise ArchivePolicyError("rewrite_destination_changed") from error
        if (
            not stat.S_ISREG(published_metadata.st_mode)
            or (published_metadata.st_dev, published_metadata.st_ino)
            != created_identity
            or published_metadata.st_uid != owner_uid
            or stat.S_IMODE(published_metadata.st_mode) != 0o600
            or published_metadata.st_nlink != 1
            or published_metadata.st_size <= 0
        ):
            raise ArchivePolicyError("rewrite_destination_changed")
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            current = destination_path.lstat()
            if (
                created_identity is not None
                and (
                    current.st_dev,
                    current.st_ino,
                )
                == created_identity
            ):
                destination_path.unlink()
        except OSError:
            pass
        raise
    return TarArchiveRewriteResult(
        source=source_result,
        rewritten=rewritten_result,
    )


def extract_tar_archive(
    source: Union[str, os.PathLike[str]],
    destination: Union[str, os.PathLike[str]],
    *,
    limits: Optional[ArchiveLimits] = None,
    return_result: bool = False,
) -> Optional[ArchiveExtractionResult]:
    """
    Validate a TAR completely, then extract it with the same descriptor.

    The implementation uses ``source``, ``destination``, ``limits``, and
    ``return_result`` to validate a TAR completely, then extract it with the
    same descriptor. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        source: filesystem location used as the source for this operation.
        destination: filesystem location used as the destination for this
            operation.
        limits: Optional Limits governing TAR completely, then extract it with
            the same descriptor.
        return_result: Whether return result is enabled or required for this
            operation.

    Returns:
        An ``ArchiveExtractionResult`` representing TAR archive, or ``None``
        when the requested value is unavailable.

    Raises:
        ArchivePolicyError: If source_changed; or tar_extract_failed.
    """
    limits = resolve_archive_limits(limits)
    deadline = time.monotonic() + limits.max_seconds
    extraction = None
    summary = None
    try:
        with _open_source(source, limits) as (stream, metadata):
            _admit_tar_decompressor_memory(stream, limits, deadline)
            if _stream_is_bzip2(stream, deadline):
                with _open_bounded_bzip2_tar(
                    stream,
                    input_size=metadata.st_size,
                    limits=limits,
                    deadline=deadline,
                ) as tar_stream:
                    if _source_fingerprint(
                        os.fstat(stream.fileno())
                    ) != _source_fingerprint(metadata):
                        raise ArchivePolicyError("source_changed")
                    summary = _scan_tar(
                        tar_stream,
                        input_size=metadata.st_size,
                        limits=limits,
                        deadline=deadline,
                        skip_special_members=True,
                    )
                    tar_stream.seek(0)
                    extraction = _extract_tar_stream(
                        tar_stream,
                        destination,
                        input_size=metadata.st_size,
                        expected_summary=summary,
                        limits=limits,
                        deadline=deadline,
                    )
            elif _stream_is_zstd(stream, deadline):
                with _open_bounded_zstd_tar(
                    stream,
                    input_size=metadata.st_size,
                    limits=limits,
                    deadline=deadline,
                ) as tar_stream:
                    if _source_fingerprint(
                        os.fstat(stream.fileno())
                    ) != _source_fingerprint(metadata):
                        raise ArchivePolicyError("source_changed")
                    summary = _scan_tar(
                        tar_stream,
                        input_size=metadata.st_size,
                        limits=limits,
                        deadline=deadline,
                        skip_special_members=True,
                    )
                    tar_stream.seek(0)
                    extraction = _extract_tar_stream(
                        tar_stream,
                        destination,
                        input_size=metadata.st_size,
                        expected_summary=summary,
                        limits=limits,
                        deadline=deadline,
                    )
            elif _stream_is_xz(stream, deadline):
                with _open_bounded_xz_tar(
                    stream,
                    input_size=metadata.st_size,
                    limits=limits,
                    deadline=deadline,
                ) as tar_stream:
                    if _source_fingerprint(
                        os.fstat(stream.fileno())
                    ) != _source_fingerprint(metadata):
                        raise ArchivePolicyError("source_changed")
                    summary = _scan_tar(
                        tar_stream,
                        input_size=metadata.st_size,
                        limits=limits,
                        deadline=deadline,
                        skip_special_members=True,
                    )
                    tar_stream.seek(0)
                    extraction = _extract_tar_stream(
                        tar_stream,
                        destination,
                        input_size=metadata.st_size,
                        expected_summary=summary,
                        limits=limits,
                        deadline=deadline,
                    )
            else:
                summary = _scan_tar(
                    stream,
                    input_size=metadata.st_size,
                    limits=limits,
                    deadline=deadline,
                    skip_special_members=True,
                )
                if _source_fingerprint(
                    os.fstat(stream.fileno())
                ) != _source_fingerprint(metadata):
                    raise ArchivePolicyError("source_changed")
                stream.seek(0)
                extraction = _extract_tar_stream(
                    stream,
                    destination,
                    input_size=metadata.st_size,
                    expected_summary=summary,
                    limits=limits,
                    deadline=deadline,
                )
            if _source_fingerprint(os.fstat(stream.fileno())) != _source_fingerprint(
                metadata
            ):
                raise ArchivePolicyError("source_changed")
    except Exception:
        if extraction is not None:
            _cleanup_created(extraction)
        raise
    if summary is None:
        raise ArchivePolicyError("tar_extract_failed")
    result = _extraction_result(summary)
    _report_controlled_drops(result)
    return result if return_result else None


def _read_stream_bounded(
    stream: BinaryIO,
    *,
    expected_bytes: int,
    maximum_bytes: int,
    deadline: float,
) -> bytes:
    """
    Read stream bounded.

    After applying local validation, the function forwards ``stream``,
    ``expected_bytes``, ``maximum_bytes``, and ``deadline`` to ``bytes`` and
    preserves its return and exception contract. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        stream: Stream object whose ``read`` state is read while performing
            stream bounded.
        expected_bytes: Numeric expected bytes used while the operation performs
            bounded accounting.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The stream bounded bytes.

    Raises:
        ArchivePolicyError: If metadata_member_size_limit; or
            member_size_mismatch.
    """
    if expected_bytes > maximum_bytes:
        raise ArchivePolicyError("metadata_member_size_limit")
    result = bytearray()
    while True:
        _check_deadline(deadline)
        chunk = stream.read(min(COPY_CHUNK_BYTES, maximum_bytes + 1 - len(result)))
        if not chunk:
            break
        result.extend(chunk)
        if len(result) > maximum_bytes:
            raise ArchivePolicyError("metadata_member_size_limit")
    if len(result) != expected_bytes:
        raise ArchivePolicyError("member_size_mismatch")
    return bytes(result)


def _read_tar_member_from_stream(
    stream: BinaryIO,
    *,
    input_size: int,
    suffix: str,
    maximum_bytes: int,
    limits: ArchiveLimits,
    deadline: float,
) -> Optional[bytes]:
    """
    Read TAR member from stream.

    The implementation uses ``stream``, ``input_size``, ``suffix``,
    ``maximum_bytes``, and ``limits`` to read TAR member from stream. Parsing or
    I/O must finish before the validated representation is made available to the
    caller. If the function cannot read TAR member from stream, its exception
    reaches the caller instead of being converted into a successful result.
    Cleanup in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        stream: Stream object whose ``seek`` state is read while performing TAR
            member from stream.
        input_size: Numeric input size used by the operation's bounded
            accounting.
        suffix: Text supplied as suffix in the format accepted by this function.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.
        limits: Limits governing TAR member from stream.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The validated ``selected``, or ``None`` when no value qualifies.

    Raises:
        ArchivePolicyError: If tar_member_unreadable; tar_read_failed; or
            tar_changed.
    """
    expected_summary = _scan_tar(
        stream,
        input_size=input_size,
        limits=limits,
        deadline=deadline,
    )
    stream.seek(0)
    state = _TarState()
    metadata_budget = _TarMetadataBudget()
    max_stream_bytes = _decompressed_tar_output_limit(input_size, limits)
    selected: Optional[bytes] = None
    try:
        with tarfile.open(
            fileobj=_DeadlineReader(stream, deadline),
            mode="r|*",
            tarinfo=_bounded_tarinfo_class(
                limits,
                metadata_budget,
                deadline,
                max_stream_bytes,
            ),
        ) as archive:
            for member in archive:
                try:
                    plan = _validate_tar_member(
                        member,
                        state,
                        metadata_budget,
                        input_size=input_size,
                        max_stream_bytes=max_stream_bytes,
                        limits=limits,
                        deadline=deadline,
                    )
                    if plan.kind != "file":
                        _finish_tar_member(state, plan, limits=limits)
                        continue
                    normalized = "/".join(plan.parts)
                    member_stream = archive.extractfile(member)
                    if member_stream is None:
                        raise ArchivePolicyError("tar_member_unreadable")
                    if selected is None and (
                        normalized == suffix or normalized.endswith(f"/{suffix}")
                    ):
                        with member_stream:
                            selected = _read_stream_bounded(
                                member_stream,
                                expected_bytes=member.size,
                                maximum_bytes=maximum_bytes,
                                deadline=deadline,
                            )
                        _finish_tar_member(
                            state,
                            plan,
                            limits=limits,
                            content_digest=hashlib.sha256(selected).digest(),
                        )
                        continue
                    with member_stream:
                        content_digest = _digest_member(
                            member_stream,
                            expected_bytes=member.size,
                            limits=limits,
                            deadline=deadline,
                        )
                    _finish_tar_member(
                        state,
                        plan,
                        limits=limits,
                        content_digest=content_digest,
                    )
                finally:
                    archive.members.clear()
            _admit_tar_stream_extent(archive.fileobj.tell(), max_stream_bytes)
    except ArchivePolicyError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise ArchivePolicyError("tar_read_failed") from error
    observed_summary = _ArchiveSummary(
        members=state.members,
        total_bytes=state.total_bytes,
        output_bytes=state.output_bytes,
        path_nodes=state.paths.output_nodes,
        tracked_path_bytes=state.paths.tracked_bytes,
        regular_files=state.regular_files,
        member_fingerprint=state.sequence_hasher.digest(),
    )
    if observed_summary != expected_summary:
        raise ArchivePolicyError("tar_changed")
    return selected


def read_archive_member_bounded(
    source: Union[str, os.PathLike[str]],
    member_suffix: str,
    *,
    maximum_bytes: int,
    limits: Optional[ArchiveLimits] = None,
) -> Optional[bytes]:
    """
    Read one matching regular member without unbounded archive metadata.

    The implementation uses ``source``, ``member_suffix``, ``maximum_bytes``,
    and ``limits`` to read one matching regular member without unbounded archive
    metadata. Parsing or I/O must finish before the validated representation is
    made available to the caller. If the function cannot read one matching
    regular member without unbounded archive metadata, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        source: filesystem location used as the source for this operation.
        member_suffix: Text supplied as member suffix in the format accepted by
            this function.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.
        limits: Optional Limits governing one matching regular member without
            unbounded archive metadata.

    Returns:
        The archive member bounded bytes, or ``None`` when the requested value
        is unavailable.

    Raises:
        ValueError: If the maximum_bytes is not positive.
        ArchivePolicyError: If metadata_member_size_limit; zip_read_failed; or
            source_changed.
    """
    if maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be positive")
    limits = resolve_archive_limits(limits)
    if maximum_bytes > limits.max_metadata_member_bytes:
        raise ArchivePolicyError("metadata_member_size_limit")
    suffix = member_suffix.replace("\\", "/").lstrip("/")
    deadline = time.monotonic() + limits.max_seconds
    path = Path(source)
    with _open_source(path, limits) as (stream, metadata):
        if path.name.casefold().endswith(".zip"):
            expected = _inspect_zip_central_directory(stream, limits, deadline)
            stream.seek(0)
            try:
                with zipfile.ZipFile(_DeadlineReader(stream, deadline), "r") as archive:
                    validation = _validate_zip_infos(
                        archive,
                        limits,
                        deadline,
                        expected_members=expected,
                        input_size=metadata.st_size,
                    )
                    for (
                        info,
                        parts,
                        directory,
                        _new_nodes,
                        _output,
                    ) in validation.entries:
                        normalized = "/".join(parts)
                        if not directory and (
                            normalized == suffix or normalized.endswith(f"/{suffix}")
                        ):
                            with archive.open(info, "r") as member_stream:
                                return _read_stream_bounded(
                                    member_stream,
                                    expected_bytes=info.file_size,
                                    maximum_bytes=maximum_bytes,
                                    deadline=deadline,
                                )
                    return None
            except ArchivePolicyError:
                raise
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise ArchivePolicyError("zip_read_failed") from error

        _admit_tar_decompressor_memory(stream, limits, deadline)
        if _stream_is_bzip2(stream, deadline):
            with _open_bounded_bzip2_tar(
                stream,
                input_size=metadata.st_size,
                limits=limits,
                deadline=deadline,
            ) as tar_stream:
                if _source_fingerprint(
                    os.fstat(stream.fileno())
                ) != _source_fingerprint(metadata):
                    raise ArchivePolicyError("source_changed")
                return _read_tar_member_from_stream(
                    tar_stream,
                    input_size=metadata.st_size,
                    suffix=suffix,
                    maximum_bytes=maximum_bytes,
                    limits=limits,
                    deadline=deadline,
                )
        if _stream_is_zstd(stream, deadline):
            with _open_bounded_zstd_tar(
                stream,
                input_size=metadata.st_size,
                limits=limits,
                deadline=deadline,
            ) as tar_stream:
                if _source_fingerprint(
                    os.fstat(stream.fileno())
                ) != _source_fingerprint(metadata):
                    raise ArchivePolicyError("source_changed")
                return _read_tar_member_from_stream(
                    tar_stream,
                    input_size=metadata.st_size,
                    suffix=suffix,
                    maximum_bytes=maximum_bytes,
                    limits=limits,
                    deadline=deadline,
                )
        if _stream_is_xz(stream, deadline):
            with _open_bounded_xz_tar(
                stream,
                input_size=metadata.st_size,
                limits=limits,
                deadline=deadline,
            ) as tar_stream:
                if _source_fingerprint(
                    os.fstat(stream.fileno())
                ) != _source_fingerprint(metadata):
                    raise ArchivePolicyError("source_changed")
                return _read_tar_member_from_stream(
                    tar_stream,
                    input_size=metadata.st_size,
                    suffix=suffix,
                    maximum_bytes=maximum_bytes,
                    limits=limits,
                    deadline=deadline,
                )
        return _read_tar_member_from_stream(
            stream,
            input_size=metadata.st_size,
            suffix=suffix,
            maximum_bytes=maximum_bytes,
            limits=limits,
            deadline=deadline,
        )


def read_regular_file_bounded(
    source: Union[str, os.PathLike[str]],
    *,
    maximum_bytes: int,
    limits: Optional[ArchiveLimits] = None,
) -> bytes:
    """
    Read one regular no-follow file through its prevalidated descriptor.

    After applying local validation, the function forwards ``source``,
    ``maximum_bytes``, and ``limits`` to ``_read_stream_bounded`` and preserves
    its return and exception contract. Parsing or I/O must finish before the
    validated representation is made available to the caller.

    Args:
        source: filesystem location used as the source for this operation.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.
        limits: Optional Limits governing one regular no-follow file through its
            prevalidated descriptor.

    Returns:
        The regular file bounded bytes.

    Raises:
        ValueError: If the maximum_bytes is not positive.
        ArchivePolicyError: If metadata_member_size_limit.
    """
    if maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be positive")
    limits = resolve_archive_limits(limits)
    if maximum_bytes > limits.max_metadata_member_bytes:
        raise ArchivePolicyError("metadata_member_size_limit")
    narrowed_limits = replace(limits, max_input_bytes=maximum_bytes)
    with _open_source(source, narrowed_limits) as (stream, metadata):
        return _read_stream_bounded(
            stream,
            expected_bytes=metadata.st_size,
            maximum_bytes=maximum_bytes,
            deadline=time.monotonic() + narrowed_limits.max_seconds,
        )


__all__ = [
    "ARCHIVE_LIMIT_PROFILE_ENV",
    "ARCHIVE_LIMIT_OVERRIDES_ENV",
    "ArchiveExtractionResult",
    "ArchiveLimits",
    "ArchivePolicyError",
    "BoundedTarMemberReader",
    "COLLECTION_ARCHIVE_LIMITS",
    "DEFAULT_ARCHIVE_CREATION_LIMITS",
    "DEFAULT_ARCHIVE_LIMIT_PROFILE",
    "DEFAULT_ARCHIVE_LIMITS",
    "HARD_ARCHIVE_LIMITS",
    "HARD_ARCHIVE_CREATION_LIMITS",
    "LARGE_ARCHIVE_LIMITS",
    "OPERATOR_ARCHIVE_LIMIT_CEILING",
    "STANDARD_ARCHIVE_LIMITS",
    "XLARGE_ARCHIVE_LIMITS",
    "TarArchiveMember",
    "TarArchiveRewriteResult",
    "archive_creation_limits_from_runtime_boundaries",
    "collection_archive_size_advisory",
    "extract_open_zip",
    "extract_tar_archive",
    "extract_zip_archive",
    "inspect_tar_archive",
    "inspect_tar_archive_metadata",
    "inspect_zip_central_directory_extent",
    "read_archive_member_bounded",
    "read_regular_file_bounded",
    "resolve_archive_limits",
    "resolve_archive_creation_limits",
    "resolve_collection_archive_limits",
    "rewrite_tar_gz_regular_files",
    "validate_open_tar_stream",
    "validate_open_tar_stream_for_creation",
    "validate_open_zip_stream",
    "validate_open_zip_stream_for_creation",
    "validate_tar_archive",
    "validate_xz_file",
    "validate_zip_archive",
]
