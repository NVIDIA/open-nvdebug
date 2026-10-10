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
One bounded, immutable byte authority for a runtime Telemetry Catalog.

This module owns the catalog snapshot boundary and exposes
``CatalogSnapshotFacts``, ``CatalogSnapshot``, ``_metadata_signature``,
``_public_catalog_name``, and ``read_catalog_snapshot``. Keeping those contracts
together gives importers one source of truth for their validation, lifecycle,
and compatibility behavior.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from . import run_limits

if TYPE_CHECKING:
    from .excel_reader import SheetData


MAX_CATALOG_SNAPSHOT_BYTES = 50 * 1024 * 1024
MAX_CATALOG_NAME_CHARS = 128
_READ_CHUNK_BYTES = 64 * 1024
_CATALOG_VERSION_PATTERN = re.compile(
    r"Telemetry_Catalog_v(?P<version>[0-9]+\.[0-9]+(?:\.[0-9]+)?)\.xlsx"
)
_CATALOG_BINDINGS = frozenset({"manifest_bound", "operator_supplied", "discovered"})


@dataclass(frozen=True, slots=True)
class CatalogSnapshotFacts:
    """
    Nonsecret, bounded facts safe to carry into run identity metadata.

    The immutable record keeps ``catalog_sha256``, ``catalog_byte_count``,
    ``catalog_name``, ``catalog_version``, and ``catalog_binding`` together so
    consumers observe one catalog snapshot facts state. Construction validates
    cross-field invariants before the instance is exposed.

    Attributes:
        catalog_sha256: Lowercase SHA-256 digest binding the catalog content.
        catalog_byte_count: Number of catalog byte entries represented by the
            record.
        catalog_name: Canonical text used as catalog name.
        catalog_version: Canonical text used as catalog version.
        catalog_binding: Canonical text used as catalog binding.
    """

    catalog_sha256: str
    catalog_byte_count: int
    catalog_name: str
    catalog_version: str
    catalog_binding: str = "discovered"

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized CatalogSnapshotFacts state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            ValueError: If the catalog snapshot digest is not lowercase SHA-256;
                catalog snapshot byte count is outside the runtime limit;
                catalog snapshot binding is invalid; or unknown catalog names
                cannot claim a version; or another input invariant is violated.
        """
        if not re.fullmatch(r"[0-9a-f]{64}", self.catalog_sha256):
            raise ValueError("catalog snapshot digest must be lowercase SHA-256")
        if (
            isinstance(self.catalog_byte_count, bool)
            or not isinstance(self.catalog_byte_count, int)
            or self.catalog_byte_count <= 0
            or self.catalog_byte_count > MAX_CATALOG_SNAPSHOT_BYTES
        ):
            raise ValueError("catalog snapshot byte count is outside the runtime limit")
        if self.catalog_binding not in _CATALOG_BINDINGS:
            raise ValueError("catalog snapshot binding is invalid")
        if self.catalog_name == "unknown":
            if self.catalog_version != "unknown":
                raise ValueError("unknown catalog names cannot claim a version")
            return
        match = _CATALOG_VERSION_PATTERN.fullmatch(self.catalog_name)
        if (
            len(self.catalog_name) > MAX_CATALOG_NAME_CHARS
            or match is None
            or match.group("version") != self.catalog_version
        ):
            raise ValueError("catalog snapshot name and version are inconsistent")

    def to_dict(self) -> dict[str, str | int]:
        """
        Return the public machine-readable representation.

        The implementation uses current instance state to produce the public
        machine-readable representation.

        Returns:
            A mapping containing the ``catalog_sha256``, ``catalog_byte_count``,
            ``catalog_name``, ``catalog_version``, and ``catalog_binding``
            fields.
        """

        return {
            "catalog_sha256": self.catalog_sha256,
            "catalog_byte_count": self.catalog_byte_count,
            "catalog_name": self.catalog_name,
            "catalog_version": self.catalog_version,
            "catalog_binding": self.catalog_binding,
        }


class CatalogSnapshot:
    """
    Opaque owner of the exact workbook bytes used by runtime parsers.

    The payload has no public accessor and cannot be pickled. Catalog parsers
    receive a fresh in-memory workbook stream through :meth:`read_excel`, while
    later provenance consumers receive only :attr:`facts`.
    """

    __slots__ = ("__content", "_facts")

    def __init__(self, content: bytes, facts: CatalogSnapshotFacts) -> None:
        """
        Initialize a ``CatalogSnapshot`` instance.

        The initializer establishes the instance invariants required by later
        operations before the object becomes visible to callers. If the function
        cannot initialize a ``CatalogSnapshot`` instance, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            content: Bounded byte sequence supplied as content.
            facts: Facts object whose ``catalog_byte_count`` and
                ``catalog_sha256`` state is read while performing initialize a
                ``CatalogSnapshot`` instance.

        Raises:
            ValueError: If the catalog snapshot content is not non-empty bytes;
                catalog snapshot exceeds the runtime size limit; or catalog
                snapshot facts do not match its content.
        """
        if not isinstance(content, bytes) or not content:
            raise ValueError("catalog snapshot content must be non-empty bytes")
        if len(content) > MAX_CATALOG_SNAPSHOT_BYTES:
            raise ValueError("catalog snapshot exceeds the runtime size limit")
        expected_digest = hashlib.sha256(content).hexdigest()
        if (
            facts.catalog_byte_count != len(content)
            or facts.catalog_sha256 != expected_digest
        ):
            raise ValueError("catalog snapshot facts do not match its content")
        object.__setattr__(self, "_CatalogSnapshot__content", bytes(content))
        object.__setattr__(self, "_facts", facts)

    def __setattr__(self, name: str, value: object) -> None:
        """
        Update an attribute through the CatalogSnapshot state boundary.

        The implementation uses ``name`` and ``value`` to update an attribute
        through the CatalogSnapshot state boundary. If the function cannot
        update an attribute through the CatalogSnapshot state boundary, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.
            value: Value evaluated while performing update an attribute through
                the CatalogSnapshot state boundary.

        Raises:
            AttributeError: If catalog snapshots are immutable.
        """
        del name, value
        raise AttributeError("catalog snapshots are immutable")

    def __delattr__(self, name: str) -> None:
        """
        Remove an attribute through the CatalogSnapshot state boundary.

        The implementation uses ``name`` to remove an attribute through the
        CatalogSnapshot state boundary. If the function cannot remove an
        attribute through the CatalogSnapshot state boundary, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.

        Raises:
            AttributeError: If catalog snapshots are immutable.
        """
        del name
        raise AttributeError("catalog snapshots are immutable")

    @property
    def facts(self) -> CatalogSnapshotFacts:
        """
        Return bounded facts without exposing the workbook payload.

        Each access computes the value from ``_facts`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            A ``CatalogSnapshotFacts`` representing facts.
        """

        return self._facts

    def read_excel(
        self,
        sheet_name: str,
        keep_default_na: bool = True,
        *,
        maximum_rows: int = run_limits.MAX_CATALOG_SHEET_ROWS,
        maximum_cells: int = run_limits.MAX_CATALOG_SHEET_CELLS,
    ) -> SheetData:
        """
        Parse one worksheet from this exact immutable byte snapshot.

        After applying local validation, the function forwards ``sheet_name``
        and ``keep_default_na`` to ``excel_reader._read_excel_bytes`` and
        preserves its return and exception contract. Parsing or I/O must finish
        before the validated representation is made available to the caller.

        Args:
            sheet_name: Stable sheet name used for lookup and operator-facing
                diagnostics.
            keep_default_na: Whether keep default na is enabled or required for
                this operation.
            maximum_rows: Maximum data rows that may be materialized.
            maximum_cells: Maximum header and data cells that may be inspected.

        Returns:
            A ``SheetData`` representing excel.
        """

        # Import lazily so excel_reader remains the low-level parser and does
        # not need to import this capability-owning module.
        from . import excel_reader

        return excel_reader._read_excel_bytes(  # noqa: SLF001
            self.__content,
            sheet_name=sheet_name,
            keep_default_na=keep_default_na,
            source_label=self.facts.catalog_name,
            maximum_rows=maximum_rows,
            maximum_cells=maximum_cells,
        )

    def __repr__(self) -> str:
        """
        Return a developer-facing representation of the CatalogSnapshot.

        The implementation uses current instance state to produce a
        developer-facing representation of the CatalogSnapshot.

        Returns:
            The canonical repr text.
        """
        return f"CatalogSnapshot(facts={self.facts!r})"

    def __copy__(self) -> CatalogSnapshot:
        """
        Copy operation.

        The implementation uses current instance state to copy operation.

        Returns:
            The validated ``self``.
        """
        return self

    def __deepcopy__(self, memo: object) -> CatalogSnapshot:
        """
        Return the deepcopy.

        The implementation uses ``memo`` to produce the deepcopy.

        Args:
            memo: Memo consumed while the function attempts to produce the
                deepcopy.

        Returns:
            The validated ``self``.
        """
        del memo
        return self

    def __reduce_ex__(self, protocol: int) -> object:
        """
        Return the reduce ex.

        The implementation uses ``protocol`` to produce the reduce ex. If the
        function cannot produce the reduce ex, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            protocol: Numeric protocol used while the operation performs bounded
                accounting.

        Returns:
            The reduce ex selected by this operation.

        Raises:
            TypeError: If catalog snapshots cannot be serialized.
        """
        del protocol
        raise TypeError("catalog snapshots cannot be serialized")


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    """
    Return fields that must remain stable while the descriptor is read.

    The implementation uses ``metadata`` to produce fields that must remain
    stable while the descriptor is read.

    Args:
        metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing
            fields that must remain stable while the descriptor is read.

    Returns:
        A tuple containing ``st dev``, ``st ino``, ``s ifmt``, ``st nlink``,
        ``st size``, ``st mtime ns``, and ``st ctime ns`` in that order.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _public_catalog_name(candidate: Path) -> tuple[str, str]:
    """
    Derive bounded basename/version facts without retaining a source path.

    The implementation uses ``candidate`` to derive bounded basename/version
    facts without retaining a source path.

    Args:
        candidate: Candidate value or resource evaluated by this operation.

    Returns:
        A tuple containing the bounded catalog basename and its extracted
        version, or two ``"unknown"`` sentinels when the name is invalid.
    """

    raw_name = candidate.name
    if len(raw_name) > MAX_CATALOG_NAME_CHARS:
        return "unknown", "unknown"
    version_match = _CATALOG_VERSION_PATTERN.fullmatch(raw_name)
    if version_match is None:
        return "unknown", "unknown"
    name = raw_name
    version = version_match.group("version")
    return name, version


def read_catalog_snapshot(
    path: str | Path,
    *,
    maximum_bytes: int = MAX_CATALOG_SNAPSHOT_BYTES,
    catalog_binding: str = "discovered",
) -> CatalogSnapshot:
    """
    Read a stable no-follow regular file once into immutable bounded bytes.

    On platforms without O_NOFOLLOW this prevents a race-swapped FIFO from
    blocking before fstat can reject it.

    Args:
        path: filesystem location used as the path for this operation.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.
        catalog_binding: Text supplied as catalog binding in the format accepted
            by this function.

    Returns:
        A ``CatalogSnapshot`` representing catalog snapshot.

    Raises:
        ValueError: If the maximum catalog size is not between 1 and
            ``MAX_CATALOG_SNAPSHOT_BYTES`` bytes; the telemetry catalog is not a
            non-symlink regular file; telemetry Catalog exceeds the
            ``maximum_bytes``-byte runtime limit; or telemetry Catalog changed
            while it was opened; or another input invariant is violated.
    """

    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or maximum_bytes <= 0
        or maximum_bytes > MAX_CATALOG_SNAPSHOT_BYTES
    ):
        raise ValueError(
            "maximum catalog size must be between 1 and "
            f"{MAX_CATALOG_SNAPSHOT_BYTES} bytes"
        )

    candidate = Path(path)
    path_before = candidate.lstat()
    if not stat.S_ISREG(path_before.st_mode):
        raise ValueError("Telemetry Catalog must be a non-symlink regular file")
    if path_before.st_size > maximum_bytes:
        raise ValueError(
            f"Telemetry Catalog exceeds the {maximum_bytes}-byte runtime limit"
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    # On platforms without O_NOFOLLOW this prevents a race-swapped FIFO from
    # blocking before fstat can reject it.
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(candidate, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("Telemetry Catalog must be a non-symlink regular file")
        if _metadata_signature(opened) != _metadata_signature(path_before):
            raise ValueError("Telemetry Catalog changed while it was opened")
        if opened.st_size > maximum_bytes:
            raise ValueError(
                f"Telemetry Catalog exceeds the {maximum_bytes}-byte runtime limit"
            )

        chunks: list[bytes] = []
        total = 0
        digest = hashlib.sha256()
        while True:
            block = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, maximum_bytes - total + 1),
            )
            if not block:
                break
            total += len(block)
            if total > maximum_bytes:
                raise ValueError(
                    f"Telemetry Catalog exceeds the {maximum_bytes}-byte runtime limit"
                )
            chunks.append(block)
            digest.update(block)

        opened_after = os.fstat(descriptor)
        try:
            path_after = candidate.lstat()
        except OSError as error:
            raise ValueError("Telemetry Catalog changed while it was read") from error
        if (
            not stat.S_ISREG(path_after.st_mode)
            or _metadata_signature(opened_after) != _metadata_signature(opened)
            or _metadata_signature(path_after) != _metadata_signature(opened)
        ):
            raise ValueError("Telemetry Catalog changed while it was read")
    finally:
        os.close(descriptor)

    if total == 0:
        raise ValueError("Telemetry Catalog is empty")
    content = b"".join(chunks)
    name, version = _public_catalog_name(candidate)
    facts = CatalogSnapshotFacts(
        catalog_sha256=digest.hexdigest(),
        catalog_byte_count=total,
        catalog_name=name,
        catalog_version=version,
        catalog_binding=catalog_binding,
    )
    return CatalogSnapshot(content, facts)
