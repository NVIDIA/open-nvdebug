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
Safely stream untrusted tar artifacts without extracting them.

This module owns archive transport and resource-limit enforcement. Callers own
the meaning of individual regular-file members and must inspect them
synchronously through the bounded reader supplied to the visitor.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import math
import os
import stat
import tarfile
import time
import zlib
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, NoReturn, Optional

from ..utils.archive_member_policy import (
    has_unsafe_member_characters,
    member_name_parts_or_none,
)
from ..utils.bounded_archive import ArchiveLimits
from ..utils.strict_zstd import StrictZstdError, StrictZstdReader

ZSTD_MAX_WINDOW_BYTES = 128 * 1024 * 1024
XZ_MAX_DECODER_MEMORY_BYTES = 128 * 1024 * 1024
TAR_EXTENSION_HEADER_LIMIT_BYTES = 64 * 1024
COMPRESSED_INPUT_LIMIT_BYTES = 512 * 1024 * 1024
ARCHIVE_SCAN_SECONDS_LIMIT = 900.0
_COMPRESSED_READ_CHUNK = 64 * 1024

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_GZIP_MAGIC = b"\x1f\x8b"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_BZIP2_MAGIC = b"BZh"


class ArchiveLimitExceeded(Exception):
    """
    An archive crossed an explicit scan resource limit.

    Callers receive this exception when the archive limit exceeded invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


class ArchiveScanError(Exception):
    """
    The archive or its compression stream could not be read.

    Callers receive this exception when the archive scan error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


def _source_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """
    Return the complete identity frozen for one archive scan.

    The implementation uses ``metadata`` to produce the complete identity frozen
    for one archive scan.

    Args:
        metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing
            complete identity frozen for one archive scan.

    Returns:
        A tuple containing ``st dev``, ``st ino``, ``st mode``, ``st nlink``,
        ``st size``, ``st mtime ns``, and ``st ctime ns`` in that order.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class _BoundedCompressedReadStream(io.RawIOBase):
    """
    Bound compressed reads and check the scan deadline around each call.

    The type coordinates ``consumed``, ``readable``, ``_check_deadline``,
    ``read``, and ``readinto`` and retains the state those operations share
    between calls. Resource ownership remains inside the instance until the
    matching close, exit, or cleanup operation completes.
    """

    def __init__(self, stream: Any, limit: int, deadline: float):
        """
        Initialize a ``_BoundedCompressedReadStream`` instance.

        The initializer records ``_consumed``, ``_deadline``, ``_limit``, and
        ``_stream`` for later operations and establishes the instance invariants
        before any public method runs.

        Args:
            stream: Stream consumed while the function attempts to initialize a
                ``_BoundedCompressedReadStream`` instance.
            limit: Numeric limit used while the operation performs bounded
                accounting.
            deadline: Absolute monotonic deadline after which the operation must
                stop.
        """
        self._stream = stream
        self._limit = limit
        self._deadline = deadline
        self._consumed = 0

    @property
    def consumed(self) -> int:
        """
        Return the number of bytes consumed from the stream.

        Each access computes the value from ``_consumed`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric consumed value.
        """
        return self._consumed

    def readable(self) -> bool:
        """
        Return whether the stream supports reading.

        The implementation uses current instance state to determine whether the
        stream supports reading.

        Returns:
            Whether the stream supports reading.
        """
        return True

    def _check_deadline(self) -> None:
        """
        Check deadline.

        The implementation uses current instance state to check deadline. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Raises:
            ArchiveLimitExceeded: If archive scan deadline exceeded.
        """
        if time.monotonic() > self._deadline:
            raise ArchiveLimitExceeded("archive scan deadline exceeded")

    def read(self, size: int = -1) -> bytes:
        """
        Read bounded data from the owned source.

        The implementation uses ``size`` to read bounded data from the owned
        source. Parsing or I/O must finish before the validated representation
        is made available to the caller. It updates ``_consumed`` on the
        instance as part of that state transition. If the function cannot read
        bounded data from the owned source, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The bounded result bytes.

        Raises:
            ArchiveScanError: If archive source returned non-bytes content.
            ArchiveLimitExceeded: If compressed archive exceeds ``_limit``
                bytes.
        """
        if size == 0:
            return b""
        self._check_deadline()
        remaining = self._limit - self._consumed
        request_size = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self._stream.read(max(1, request_size))
        self._check_deadline()
        if not isinstance(data, bytes):
            raise ArchiveScanError("archive source returned non-bytes content")
        self._consumed += len(data)
        if self._consumed > self._limit:
            raise ArchiveLimitExceeded(
                f"compressed archive exceeds {self._limit} bytes"
            )
        return data

    def readinto(self, buffer: Any) -> int:
        """
        Read bounded data into the caller-provided buffer.

        After applying local validation, the function forwards ``buffer`` to
        ``len`` and preserves its return and exception contract. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            buffer: Mapping supplying fields for bounded data into the
                caller-provided buffer.

        Returns:
            The numeric readinto value.
        """
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


def _bounded_tarinfo_type(extension_header_limit: int) -> type[tarfile.TarInfo]:
    """
    Build a TarInfo type that rejects oversized extension payloads.

    ``tarfile`` normally reads an entire PAX or GNU long-name payload while
    turning its header into the following logical member. Checking the declared
    size in ``_proc_member`` keeps that allocation behind an explicit cap.

    Args:
        extension_header_limit: Upper bound enforced for extension header limit;
            the consuming boundary rejects or truncates values that exceed it.

    Returns:
        The validated ``_BoundedTarInfo``.
    """

    class _BoundedTarInfo(tarfile.TarInfo):
        """
        Implement the bounded TAR info boundary used by the NVDebug runtime.

        The type coordinates ``fromtarfile``, ``_fromtarfile``,
        ``_reject_sparse``, ``_proc_member``, and ``_proc_sparse`` and retains
        the state those operations share between calls. Resource ownership
        remains inside the instance until the matching close, exit, or cleanup
        operation completes.
        """

        @classmethod
        def fromtarfile(cls, archive: tarfile.TarFile) -> tarfile.TarInfo:
            """
            Parse a header through the bounded path on Python 3.11+.

            Python 3.12 delegates ``fromtarfile`` to ``_fromtarfile`` while
            Python 3.11 implements only ``fromtarfile``. Overriding both keeps
            structural end-marker accounting active in every supported runtime.

            Args:
                archive: Archive consumed while the function attempts to parse a
                    header through the bounded path on Python 3.11+.

            Returns:
                A ``TarInfo`` representing fromtarfile.
            """
            return cls._fromtarfile(archive)

        @classmethod
        def _fromtarfile(
            cls,
            archive: tarfile.TarFile,
            *,
            dircheck: bool = True,
        ) -> tarfile.TarInfo:
            """
            Parse one header while tracking structural tar terminators.

            After applying local validation, the function forwards ``archive``
            and ``dircheck`` to ``member._proc_member`` and preserves its return
            and exception contract. Parsing or I/O must finish before the
            validated representation is made available to the caller. Filesystem
            effects remain confined to the caller-selected paths and the owning
            resource lifecycle.

            Args:
                archive: Archive object whose ``_bounded_zero_header_blocks``,
                    ``encoding``, ``errors``, ``fileobj``, and ``read`` state is
                    read while performing one header while tracking structural
                    tar terminators.
                dircheck: Whether dircheck is enabled or required for this
                    operation.

            Returns:
                A ``TarInfo`` representing fromtarfile.
            """
            buffer = archive.fileobj.read(tarfile.BLOCKSIZE)
            if len(buffer) == tarfile.BLOCKSIZE and not any(buffer):
                archive._bounded_zero_header_blocks = (  # type: ignore[attr-defined]
                    getattr(archive, "_bounded_zero_header_blocks", 0) + 1
                )
            elif buffer:
                archive._bounded_zero_header_blocks = 0  # type: ignore[attr-defined]
            try:
                if hasattr(cls, "_frombuf"):
                    member = cls._frombuf(
                        buffer,
                        archive.encoding,
                        archive.errors,
                        dircheck=dircheck,
                    )
                else:
                    member = cls.frombuf(
                        buffer,
                        archive.encoding,
                        archive.errors,
                    )
            except tarfile.HeaderError:
                if buffer and any(buffer):
                    setattr(archive, "_bounded_invalid_header_seen", True)
                raise
            member.offset = archive.fileobj.tell() - tarfile.BLOCKSIZE
            return member._proc_member(archive)

        @staticmethod
        def _reject_sparse() -> NoReturn:
            """
            Reject sparse.

            The implementation uses current instance state to reject sparse.
            Every required invariant is checked before a successful value is
            returned; invalid input follows the function's explicit exception
            path.

            Raises:
                ArchiveLimitExceeded: If GNU sparse tar members are unsupported
                    by the bounded scanner.
            """
            raise ArchiveLimitExceeded(
                "GNU sparse tar members are unsupported by the bounded scanner"
            )

        def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
            """
            Process one archive member through the bounded parser.

            After applying local validation, the function forwards ``archive``
            to ``_proc_member`` and preserves its return and exception contract.
            Terminal status is emitted only after one archive member through the
            bounded parser and its owned cleanup have completed.

            Args:
                archive: Archive consumed while the function attempts to process
                    one archive member through the bounded parser.

            Returns:
                A ``TarInfo`` representing proc member.

            Raises:
                ArchiveLimitExceeded: If tar extension header exceeds
                    ``extension_header_limit`` bytes.
            """
            extension_types = (
                tarfile.GNUTYPE_LONGNAME,
                tarfile.GNUTYPE_LONGLINK,
                tarfile.XHDTYPE,
                tarfile.XGLTYPE,
                tarfile.SOLARIS_XHDTYPE,
            )
            if self.type in extension_types and self.size > extension_header_limit:
                raise ArchiveLimitExceeded(
                    f"tar extension header exceeds {extension_header_limit} bytes"
                )
            return super()._proc_member(archive)

        def _proc_sparse(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
            """
            Reject unsupported sparse TAR member metadata.

            The implementation uses ``archive`` to reject unsupported sparse TAR
            member metadata. Every required invariant is checked before a
            successful value is returned; invalid input follows the function's
            explicit exception path.

            Args:
                archive: Archive consumed while the function attempts to reject
                    unsupported sparse TAR member metadata.

            Returns:
                A ``TarInfo`` representing proc sparse.
            """
            self._reject_sparse()

        def _proc_gnusparse_00(
            self,
            next_member: tarfile.TarInfo,
            raw_headers: Any,
        ) -> None:
            """
            Reject unsupported GNU sparse 0.0 metadata.

            The implementation uses ``next_member`` and ``raw_headers`` to
            reject unsupported GNU sparse 0.0 metadata. Every required invariant
            is checked before a successful value is returned; invalid input
            follows the function's explicit exception path.

            Args:
                next_member: Next member consumed while the function attempts to
                    reject unsupported GNU sparse 0.0 metadata.
                raw_headers: Raw headers consumed while the function attempts to
                    reject unsupported GNU sparse 0.0 metadata.
            """
            self._reject_sparse()

        def _proc_gnusparse_01(
            self,
            next_member: tarfile.TarInfo,
            pax_headers: Any,
        ) -> None:
            """
            Reject unsupported GNU sparse 0.1 metadata.

            The implementation uses ``next_member`` and ``pax_headers`` to
            reject unsupported GNU sparse 0.1 metadata. Every required invariant
            is checked before a successful value is returned; invalid input
            follows the function's explicit exception path.

            Args:
                next_member: Next member consumed while the function attempts to
                    reject unsupported GNU sparse 0.1 metadata.
                pax_headers: PAX headers consumed while the function attempts to
                    reject unsupported GNU sparse 0.1 metadata.
            """
            self._reject_sparse()

        def _proc_gnusparse_10(
            self,
            next_member: tarfile.TarInfo,
            pax_headers: Any,
            archive: tarfile.TarFile,
        ) -> None:
            """
            Reject unsupported GNU sparse 1.0 metadata.

            The implementation uses ``next_member``, ``pax_headers``, and
            ``archive`` to reject unsupported GNU sparse 1.0 metadata. Every
            required invariant is checked before a successful value is returned;
            invalid input follows the function's explicit exception path.

            Args:
                next_member: Next member consumed while the function attempts to
                    reject unsupported GNU sparse 1.0 metadata.
                pax_headers: PAX headers consumed while the function attempts to
                    reject unsupported GNU sparse 1.0 metadata.
                archive: Archive consumed while the function attempts to reject
                    unsupported GNU sparse 1.0 metadata.
            """
            self._reject_sparse()

    return _BoundedTarInfo


class _BoundedReadStream(io.RawIOBase):
    """
    Count and limit decompressed bytes consumed by tarfile.

    The type coordinates ``readable``, ``consumed``, ``read``, and ``readinto``
    and retains the state those operations share between calls. Resource
    ownership remains inside the instance until the matching close, exit, or
    cleanup operation completes.
    """

    def __init__(self, stream: Any, limit: int, deadline: float):
        """
        Initialize a ``_BoundedReadStream`` instance.

        The initializer records ``_consumed``, ``_deadline``, ``_limit``, and
        ``_stream`` for later operations and establishes the instance invariants
        before any public method runs.

        Args:
            stream: Stream consumed while the function attempts to initialize a
                ``_BoundedReadStream`` instance.
            limit: Numeric limit used while the operation performs bounded
                accounting.
            deadline: Absolute monotonic deadline after which the operation must
                stop.
        """
        self._stream = stream
        self._limit = limit
        self._deadline = deadline
        self._consumed = 0

    def readable(self) -> bool:
        """
        Return whether the stream supports reading.

        The implementation uses current instance state to determine whether the
        stream supports reading.

        Returns:
            Whether the stream supports reading.
        """
        return True

    @property
    def consumed(self) -> int:
        """
        Return the number of bytes consumed from the stream.

        Each access computes the value from ``_consumed`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric consumed value.
        """
        return self._consumed

    def read(self, size: int = -1) -> bytes:
        """
        Read bounded data from the owned source.

        The implementation uses ``size`` to read bounded data from the owned
        source. Parsing or I/O must finish before the validated representation
        is made available to the caller. It updates ``_consumed`` on the
        instance as part of that state transition. If the function cannot read
        bounded data from the owned source, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The validated ``data``.

        Raises:
            ArchiveLimitExceeded: If archive scan deadline exceeded; or
                decompressed archive exceeds ``_limit`` bytes.
        """
        if time.monotonic() > self._deadline:
            raise ArchiveLimitExceeded("archive scan deadline exceeded")
        remaining = self._limit - self._consumed
        request_size = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = bytes(self._stream.read(request_size))
        if time.monotonic() > self._deadline:
            raise ArchiveLimitExceeded("archive scan deadline exceeded")
        if self._consumed + len(data) > self._limit:
            raise ArchiveLimitExceeded(
                f"decompressed archive exceeds {self._limit} bytes"
            )
        self._consumed += len(data)
        return data

    def readinto(self, buffer: Any) -> int:
        """
        Read bounded data into the caller-provided buffer.

        After applying local validation, the function forwards ``buffer`` to
        ``len`` and preserves its return and exception contract. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            buffer: Mapping supplying fields for bounded data into the
                caller-provided buffer.

        Returns:
            The numeric readinto value.
        """
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


class _XZStreamReader(io.RawIOBase):
    """
    Incrementally decode one XZ stream under an explicit memory limit.

    The type coordinates ``readable``, ``read``, ``_validate_trailing_padding``,
    and ``readinto`` and retains the state those operations share between calls.
    Resource ownership remains inside the instance until the matching close,
    exit, or cleanup operation completes.
    """

    def __init__(self, stream: Any, memory_limit: int):
        """
        Initialize a ``_XZStreamReader`` instance.

        The initializer records ``_decoder``, ``_finished``, and ``_stream`` for
        later operations and establishes the instance invariants before any
        public method runs.

        Args:
            stream: Stream consumed while the function attempts to initialize a
                ``_XZStreamReader`` instance.
            memory_limit: Upper bound enforced for memory limit; the consuming
                boundary rejects or truncates values that exceed it.
        """
        self._stream = stream
        self._decoder = lzma.LZMADecompressor(
            format=lzma.FORMAT_XZ,
            memlimit=memory_limit,
        )
        self._finished = False

    def readable(self) -> bool:
        """
        Return whether the stream supports reading.

        The implementation uses current instance state to determine whether the
        stream supports reading.

        Returns:
            Whether the stream supports reading.
        """
        return True

    def read(self, size: int = -1) -> bytes:
        """
        Read bounded data from the owned source.

        The implementation uses ``size`` to read bounded data from the owned
        source. Parsing or I/O must finish before the validated representation
        is made available to the caller. It updates ``_finished`` on the
        instance as part of that state transition. If the function cannot read
        bounded data from the owned source, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The bounded result bytes.

        Raises:
            EOFError: If truncated XZ stream.
        """
        if size == 0 or self._finished:
            return b""
        if size < 0:
            chunks: list[bytes] = []
            while True:
                chunk = self.read(_COMPRESSED_READ_CHUNK)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)

        output = bytearray()
        while len(output) < size and not self._finished:
            if self._decoder.needs_input:
                compressed = self._stream.read(_COMPRESSED_READ_CHUNK)
                if not compressed:
                    if not self._decoder.eof:
                        raise EOFError("truncated XZ stream")
                    self._finished = True
                    break
            else:
                compressed = b""

            output.extend(
                self._decoder.decompress(
                    compressed,
                    max_length=size - len(output),
                )
            )
            if self._decoder.eof:
                self._validate_trailing_padding()
                self._finished = True

        return bytes(output)

    def _validate_trailing_padding(self) -> None:
        """
        Allow XZ stream padding, but reject hidden concatenated content.

        The implementation uses current instance state to allow XZ stream
        padding, but reject hidden concatenated content. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle. If the function cannot allow XZ stream padding, but reject
        hidden concatenated content, its exception reaches the caller instead of
        being converted into a successful result.

        Raises:
            ArchiveScanError: If concatenated or trailing non-padding XZ data is
                unsupported by the bounded scanner; or xZ stream padding is not
                aligned to a four-byte boundary.
        """
        padding_bytes = 0
        trailing = self._decoder.unused_data
        while True:
            if trailing:
                if any(trailing):
                    raise ArchiveScanError(
                        "concatenated or trailing non-padding XZ data is "
                        "unsupported by the bounded scanner"
                    )
                padding_bytes += len(trailing)
            trailing = self._stream.read(_COMPRESSED_READ_CHUNK)
            if not trailing:
                break
        if padding_bytes % 4:
            raise ArchiveScanError(
                "XZ stream padding is not aligned to a four-byte boundary"
            )

    def readinto(self, buffer: Any) -> int:
        """
        Read bounded data into the caller-provided buffer.

        After applying local validation, the function forwards ``buffer`` to
        ``len`` and preserves its return and exception contract. Parsing or I/O
        must finish before the validated representation is made available to the
        caller.

        Args:
            buffer: Mapping supplying fields for bounded data into the
                caller-provided buffer.

        Returns:
            The numeric readinto value.
        """
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


@dataclass(frozen=True)
class SafeTarMember:
    """
    Metadata for one normalized regular-file member.

    The immutable record keeps ``path``, ``size``, and ``mtime`` together so
    consumers observe one safe TAR member state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        size: Cumulative byte count represented by this record.
        mtime: Mtime retained as part of the record's public state.
    """

    path: PurePosixPath
    size: int
    mtime: Any


MemberReader = Callable[[int], bytes]
MemberVisitor = Callable[[SafeTarMember, MemberReader], None]


def normalize_tar_member_path(
    value: Any,
    *,
    max_path_depth: Optional[int] = None,
) -> Optional[PurePosixPath]:
    """
    Normalize one tar member name under the shared archive member policy.

    The admitted set now matches ``utils.bounded_archive._member_parts`` through
    the shared ``utils.archive_member_policy`` decision, so a name this scanner
    reports cannot be one the sanctioned extractor would refuse. A backslash is
    rejected rather than rewritten into a separator, a drive-letter prefix is
    refused, and empty and ``.`` components are decided on the raw split before
    ``PurePosixPath`` can silently collapse them.

    Two producer spellings are preserved so ordinary archives are not marked
    partial: one trailing ``/`` is the directory spelling and is stripped, and a
    leading ``./`` is the prefix ``tar`` emits. The archive root itself, spelled
    ``.`` or ``./``, normalizes to ``.`` exactly as before so the caller's
    directory branch skips it instead of counting a rejected member. Absolute
    names remain refused; unlike the extractor, this scanner never had a
    ``tar -P`` compatibility path and does not gain one here.

    Args:
        value: Untrusted member name from the archive's own metadata. A
            non-string value is coerced with ``str`` and then judged on its
            characters like any other candidate.
        max_path_depth: Optional component ceiling. ``None`` binds the decision
            to ``ArchiveLimits.max_path_depth``, the same operator-configurable
            bound the extractor enforces, rather than a scanner-local constant.

    Returns:
        The validated ``path``, or ``None`` when the name violates the policy.
        The caller records ``None`` as one rejected member and continues, which
        marks the archive partial without ending the scan.
    """
    raw = str(value or "")
    if not raw or has_unsafe_member_characters(raw):
        return None
    depth = ArchiveLimits().max_path_depth if max_path_depth is None else max_path_depth
    normalized = raw[:-1] if raw.endswith("/") else raw
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", "."}:
        return PurePosixPath(".")
    parts = member_name_parts_or_none(normalized, max_path_depth=depth)
    if parts is None:
        return None
    return PurePosixPath(*parts)


class BoundedTarScanner:
    """
    Visit safe regular members under explicit stream and tar limits.

    The type coordinates ``scan``, ``_decompressed_stream``, and
    ``_check_deadline`` and retains the state those operations share between
    calls. Resource ownership remains inside the instance until the matching
    close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        path: Path,
        *,
        decompressed_limit: int,
        logical_size_limit: int,
        member_limit: int,
        member_name_limit: int,
        extension_header_limit: int = TAR_EXTENSION_HEADER_LIMIT_BYTES,
        max_zstd_window_bytes: int = ZSTD_MAX_WINDOW_BYTES,
        max_xz_decoder_memory_bytes: int = XZ_MAX_DECODER_MEMORY_BYTES,
        compressed_size_limit: int = COMPRESSED_INPUT_LIMIT_BYTES,
        max_seconds: float = ARCHIVE_SCAN_SECONDS_LIMIT,
        max_zstd_frames: Optional[int] = None,
    ):
        """
        Initialize a ``BoundedTarScanner`` instance.

        The initializer records ``compressed_bytes``, ``compressed_size_limit``,
        ``decompressed_bytes``, ``decompressed_limit``, and
        ``extension_header_limit`` for later operations and establishes the
        instance invariants before any public method runs. If the function
        cannot initialize a ``BoundedTarScanner`` instance, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            path: filesystem location used as the path for this operation.
            decompressed_limit: Upper bound enforced for decompressed limit; the
                consuming boundary rejects or truncates values that exceed it.
            logical_size_limit: Upper bound enforced for logical size limit; the
                consuming boundary rejects or truncates values that exceed it.
            member_limit: Upper bound enforced for member limit; the consuming
                boundary rejects or truncates values that exceed it.
            member_name_limit: Upper bound enforced for member name limit; the
                consuming boundary rejects or truncates values that exceed it.
            extension_header_limit: Upper bound enforced for extension header
                limit; the consuming boundary rejects or truncates values that
                exceed it.
            max_zstd_window_bytes: Upper bound enforced for max zstd window
                bytes; the consuming boundary rejects or truncates values that
                exceed it.
            max_xz_decoder_memory_bytes: Upper bound enforced for max xz decoder
                memory bytes; the consuming boundary rejects or truncates values
                that exceed it.
            compressed_size_limit: Upper bound enforced for compressed size
                limit; the consuming boundary rejects or truncates values that
                exceed it.
            max_seconds: Maximum duration in seconds allowed for max seconds.
            max_zstd_frames: Upper bound enforced for max zstd frames; the
                consuming boundary rejects or truncates values that exceed it.

        Raises:
            ValueError: If the archive scanner limits are not positive integers;
                the archive scanner deadline is not positive and finite; or the
                zstandard frame limit is not a positive integer.
        """
        integer_limits = (
            decompressed_limit,
            logical_size_limit,
            member_limit,
            member_name_limit,
            extension_header_limit,
            max_zstd_window_bytes,
            max_xz_decoder_memory_bytes,
            compressed_size_limit,
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in integer_limits
        ):
            raise ValueError("archive scanner limits must be positive integers")
        if not math.isfinite(max_seconds) or max_seconds <= 0:
            raise ValueError("archive scanner deadline must be positive and finite")
        if max_zstd_frames is None:
            max_zstd_frames = member_limit
        if (
            not isinstance(max_zstd_frames, int)
            or isinstance(max_zstd_frames, bool)
            or max_zstd_frames <= 0
        ):
            raise ValueError("Zstandard frame limit must be a positive integer")
        self.path = Path(path)
        self.decompressed_limit = decompressed_limit
        self.logical_size_limit = logical_size_limit
        self.member_limit = member_limit
        self.member_name_limit = member_name_limit
        self.extension_header_limit = extension_header_limit
        self.max_zstd_window_bytes = max_zstd_window_bytes
        self.max_xz_decoder_memory_bytes = max_xz_decoder_memory_bytes
        self.compressed_size_limit = compressed_size_limit
        self.max_seconds = float(max_seconds)
        self.max_zstd_frames = max_zstd_frames
        self.decompressed_bytes = 0
        self.compressed_bytes = 0
        self.members_visited = 0
        self.rejected_members = 0
        self.member_limit_reached = False

    def scan(self, visitor: MemberVisitor) -> None:
        """
        Stream the archive and synchronously visit each safe file member.

        The implementation uses ``visitor`` to stream the archive and
        synchronously visit each safe file member. It updates
        ``compressed_bytes``, ``decompressed_bytes``, ``member_limit_reached``,
        ``members_visited``, and ``rejected_members`` on the instance as part of
        that state transition. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot stream the archive and synchronously visit each safe file member,
        its exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Args:
            visitor: Visitor consumed while the function attempts to stream the
                archive and synchronously visit each safe file member.

        Raises:
            ArchiveScanError: If archive source is unavailable: ``__name__``;
                archive scanning lacks no-follow file access; the archive source
                is not a single-link regular file; or archive source identity
                changed before scanning; or another input invariant is violated.
            ArchiveLimitExceeded: If compressed archive exceeds
                ``compressed_size_limit`` bytes; archive scan deadline exceeded;
                archive logical member size exceeds ``logical_size_limit``
                bytes; or archive decompressed size exceeds
                ``decompressed_limit`` bytes.
        """
        bounded_stream: Optional[_BoundedReadStream] = None
        compressed_stream: Optional[_BoundedCompressedReadStream] = None
        logical_bytes = 0
        deadline = time.monotonic() + self.max_seconds
        descriptor: Optional[int] = None
        opened: Optional[os.stat_result] = None
        try:
            with ExitStack() as stack:
                try:
                    visible = self.path.lstat()
                except OSError as exc:
                    raise ArchiveScanError(
                        f"archive source is unavailable: {type(exc).__name__}"
                    ) from exc
                no_follow = getattr(os, "O_NOFOLLOW", None)
                if no_follow is None:
                    raise ArchiveScanError(
                        "archive scanning requires no-follow file access"
                    )
                if not stat.S_ISREG(visible.st_mode) or visible.st_nlink != 1:
                    raise ArchiveScanError(
                        "archive source must be a single-link regular file"
                    )
                if visible.st_size > self.compressed_size_limit:
                    raise ArchiveLimitExceeded(
                        "compressed archive exceeds "
                        f"{self.compressed_size_limit} bytes"
                    )

                flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
                descriptor = os.open(self.path, flags)
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or opened.st_size > self.compressed_size_limit
                    or _source_identity(opened) != _source_identity(visible)
                ):
                    raise ArchiveScanError(
                        "archive source identity changed before scanning"
                    )

                raw_stream = stack.enter_context(
                    os.fdopen(descriptor, "rb", closefd=False)
                )
                if time.monotonic() > deadline:
                    raise ArchiveLimitExceeded("archive scan deadline exceeded")
                magic = raw_stream.read(6)
                if time.monotonic() > deadline:
                    raise ArchiveLimitExceeded("archive scan deadline exceeded")
                raw_stream.seek(0)
                compressed_stream = _BoundedCompressedReadStream(
                    raw_stream,
                    min(opened.st_size, self.compressed_size_limit),
                    deadline,
                )
                decompressed_stream = self._decompressed_stream(
                    compressed_stream,
                    magic,
                    deadline,
                    opened.st_size,
                )
                if decompressed_stream is not compressed_stream:
                    stack.callback(decompressed_stream.close)
                bounded_stream = _BoundedReadStream(
                    decompressed_stream,
                    self.decompressed_limit,
                    deadline,
                )
                archive = stack.enter_context(
                    tarfile.open(
                        fileobj=bounded_stream,
                        mode="r|",
                        tarinfo=_bounded_tarinfo_type(self.extension_header_limit),
                        ignore_zeros=True,
                    )
                )

                for member_index, tar_member in enumerate(archive):
                    if member_index >= self.member_limit:
                        self.member_limit_reached = True
                        break
                    self.members_visited = member_index + 1
                    member_path = normalize_tar_member_path(tar_member.name)
                    if (
                        member_path is None
                        or len(tar_member.name) > self.member_name_limit
                    ):
                        self.rejected_members += 1
                        continue
                    if tar_member.isdir():
                        continue
                    if not tar_member.isfile() or tar_member.size < 0:
                        self.rejected_members += 1
                        continue

                    logical_bytes += tar_member.size
                    if logical_bytes > self.logical_size_limit:
                        raise ArchiveLimitExceeded(
                            "archive logical member size exceeds "
                            f"{self.logical_size_limit} bytes"
                        )

                    read_called = False

                    def read_member(
                        size: int,
                        *,
                        _member: tarfile.TarInfo = tar_member,
                    ) -> bytes:
                        """
                        Read member.

                        The implementation uses ``size`` and ``_member`` to read
                        member. Parsing or I/O must finish before the validated
                        representation is made available to the caller. If the
                        function cannot read member, its exception reaches the
                        caller instead of being converted into a successful
                        result.

                        Args:
                            size: Numeric size used by the operation's bounded
                                accounting.
                            _member: Member object whose ``size`` state is read
                                while performing member.

                        Returns:
                            The bounded member bytes.

                        Raises:
                            RuntimeError: If an archive member can only be read
                                once while streaming.
                        """
                        nonlocal read_called
                        if read_called:
                            raise RuntimeError(
                                "An archive member can only be read once while "
                                "streaming."
                            )
                        read_called = True
                        stream = archive.extractfile(_member)
                        if stream is None:
                            return b""
                        with stream:
                            return stream.read(min(_member.size, max(0, int(size))))

                    visitor(
                        SafeTarMember(
                            path=member_path,
                            size=tar_member.size,
                            mtime=tar_member.mtime,
                        ),
                        read_member,
                    )
                # Drain through the same byte and time bounds to validate the
                # compression frame even when member inspection is incomplete.
                # At the member limit, unread TAR headers/payloads are ordinary
                # uninspected content, not bytes following a proven TAR end.
                # Only a completed member traversal permits a trailing-data
                # corruption claim; member-limit coverage remains explicit.
                while trailing := bounded_stream.read(_COMPRESSED_READ_CHUNK):
                    if not self.member_limit_reached and any(trailing):
                        raise ArchiveScanError(
                            "tar stream contains nonzero trailing data"
                        )
                if not self.member_limit_reached and (
                    getattr(archive, "_bounded_zero_header_blocks", 0) < 2
                    or getattr(
                        archive,
                        "_bounded_invalid_header_seen",
                        False,
                    )
                ):
                    raise ArchiveScanError(
                        "tar stream is missing valid end-of-archive blocks"
                    )
                if compressed_stream.consumed != opened.st_size:
                    raise ArchiveScanError(
                        "archive compressed input was not consumed completely"
                    )
                final = os.fstat(descriptor)
                try:
                    visible_after = self.path.lstat()
                except OSError as exc:
                    raise ArchiveScanError(
                        "archive source changed during scanning"
                    ) from exc
                if _source_identity(final) != _source_identity(
                    opened
                ) or _source_identity(visible_after) != _source_identity(opened):
                    raise ArchiveScanError("archive source changed during scanning")
        except ArchiveLimitExceeded:
            raise
        except StrictZstdError as exc:
            if exc.reason == "output_size_limit":
                raise ArchiveLimitExceeded(
                    "archive decompressed size exceeds "
                    f"{self.decompressed_limit} bytes"
                ) from exc
            detail = (
                "Zstandard frame requires too much memory"
                if exc.reason == "decompressor_memory_limit"
                else f"invalid Zstandard stream: {exc.reason}"
            )
            raise ArchiveScanError(detail) from exc
        except (
            EOFError,
            lzma.LZMAError,
            OSError,
            tarfile.TarError,
            zlib.error,
        ) as exc:
            raise ArchiveScanError(f"{type(exc).__name__}: {exc}") from exc
        finally:
            if bounded_stream is not None:
                self.decompressed_bytes = bounded_stream.consumed
            if compressed_stream is not None:
                self.compressed_bytes = compressed_stream.consumed
            if descriptor is not None:
                os.close(descriptor)

    def _decompressed_stream(
        self,
        raw_stream: Any,
        magic: bytes,
        deadline: float,
        input_size: int,
    ) -> Any:
        """
        Return the decompressed stream.

        The implementation uses ``raw_stream``, ``magic``, ``deadline``, and
        ``input_size`` to produce the decompressed stream.

        Args:
            raw_stream: Raw stream consumed while the function attempts to
                produce the decompressed stream.
            magic: Bounded byte sequence supplied as magic.
            deadline: Absolute monotonic deadline after which the operation must
                stop.
            input_size: Numeric input size used by the operation's bounded
                accounting.

        Returns:
            The decompressed stream.
        """
        if magic.startswith(_ZSTD_MAGIC):
            return StrictZstdReader(
                raw_stream,
                max_window_size=self.max_zstd_window_bytes,
                max_output_bytes=self.decompressed_limit,
                max_input_bytes=max(1, input_size),
                max_frames=self.max_zstd_frames,
                check_deadline=lambda: self._check_deadline(deadline),
            )
        if magic.startswith(_GZIP_MAGIC):
            return gzip.GzipFile(fileobj=raw_stream, mode="rb")
        if magic.startswith(_XZ_MAGIC):
            return _XZStreamReader(
                raw_stream,
                self.max_xz_decoder_memory_bytes,
            )
        if magic.startswith(_BZIP2_MAGIC):
            return bz2.BZ2File(raw_stream, mode="rb")
        return raw_stream

    @staticmethod
    def _check_deadline(deadline: float) -> None:
        """
        Check deadline.

        The implementation uses ``deadline`` to check deadline. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path.

        Args:
            deadline: Absolute monotonic deadline after which the operation must
                stop.

        Raises:
            ArchiveLimitExceeded: If archive scan deadline exceeded.
        """
        if time.monotonic() > deadline:
            raise ArchiveLimitExceeded("archive scan deadline exceeded")
