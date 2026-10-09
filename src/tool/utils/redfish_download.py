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
Ownership-safe handle for a Redfish response streamed to private storage.

This module owns the redfish download boundary and exposes
``TruncatedRedfishErrorBody`` and ``StreamedRedfishBody``. Keeping those
contracts together gives importers one source of truth for their validation,
lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional


class TruncatedRedfishErrorBody:
    """
    Process-private, bounded evidence from an oversized error response.

    The complete response is never retained. Raw head/tail windows never cross
    the publication boundary: a truncation boundary can split an otherwise
    recognizable credential, so ordinary text sanitization cannot prove that
    either fragment is safe. Public capture contains only sizes and digests.
    """

    __slots__ = (
        "received_size_bytes",
        "prefix_bytes",
        "suffix_bytes",
        "received_sha256",
        "response_limit_bytes",
        "evidence_limit_bytes",
        "content_type",
        "declared_size_bytes",
        "http_status",
        "attempt_number",
        "stream_complete",
        "read_error_type",
    )

    def __init__(
        self,
        *,
        received_size_bytes: int,
        prefix_bytes: bytes,
        suffix_bytes: bytes,
        received_sha256: str,
        response_limit_bytes: int,
        evidence_limit_bytes: int,
        content_type: Optional[str] = None,
        declared_size_bytes: Optional[int] = None,
        http_status: Optional[int] = None,
        attempt_number: Optional[int] = None,
        stream_complete: bool = True,
        read_error_type: Optional[str] = None,
    ) -> None:
        """
        Initialize a ``TruncatedRedfishErrorBody`` instance.

        The initializer records ``attempt_number``, ``content_type``,
        ``declared_size_bytes``, ``evidence_limit_bytes``, and ``http_status``
        for later operations and establishes the instance invariants before any
        public method runs.

        Args:
            received_size_bytes: Numeric received size bytes used while the
                operation performs bounded accounting.
            prefix_bytes: Bounded byte sequence supplied as prefix bytes.
            suffix_bytes: Bounded byte sequence supplied as suffix bytes.
            received_sha256: Text supplied as received SHA-256 in the format
                accepted by this function.
            response_limit_bytes: Numeric response limit bytes used while the
                operation performs bounded accounting.
            evidence_limit_bytes: Numeric evidence limit bytes used while the
                operation performs bounded accounting.
            content_type: Optional content type; ``None`` selects the function's
                default behavior.
            declared_size_bytes: Optional declared size bytes; ``None`` selects
                the function's default behavior.
            http_status: Optional HTTP status; ``None`` selects the function's
                default behavior.
            attempt_number: Optional attempt number; ``None`` selects the
                function's default behavior.
            stream_complete: Whether stream complete is enabled or required for
                this operation.
            read_error_type: Optional read error type; ``None`` selects the
                function's default behavior.
        """
        self.received_size_bytes = max(0, int(received_size_bytes))
        self.prefix_bytes = bytes(prefix_bytes)
        self.suffix_bytes = bytes(suffix_bytes)
        self.received_sha256 = str(received_sha256)
        self.response_limit_bytes = max(1, int(response_limit_bytes))
        self.evidence_limit_bytes = max(1, int(evidence_limit_bytes))
        self.content_type = content_type
        self.declared_size_bytes = (
            max(0, int(declared_size_bytes))
            if declared_size_bytes is not None
            else None
        )
        self.http_status = (
            int(http_status)
            if isinstance(http_status, int)
            and not isinstance(http_status, bool)
            and 100 <= http_status <= 599
            else None
        )
        self.attempt_number = (
            int(attempt_number)
            if isinstance(attempt_number, int)
            and not isinstance(attempt_number, bool)
            and attempt_number > 0
            else None
        )
        self.stream_complete = bool(stream_complete)
        self.read_error_type = (
            "".join(
                character
                for character in str(read_error_type)[:96]
                if character.isalnum() or character in "_.-"
            )
            or None
            if read_error_type
            else None
        )

    def __repr__(self) -> str:
        """
        Return a developer-facing representation of the TruncatedRedfishErrorBody.

        The implementation uses current instance state to produce a
        developer-facing representation of the TruncatedRedfishErrorBody.

        Returns:
            The canonical repr text.
        """
        return (
            "TruncatedRedfishErrorBody("
            f"received_size_bytes={self.received_size_bytes}, "
            f"retained_size_bytes={self.retained_size_bytes}, "
            f"received_sha256='{self.received_sha256}')"
        )

    __str__ = __repr__

    @property
    def original_size_bytes(self) -> Optional[int]:
        """
        Return the exact original size only after a complete stream read.

        Each access computes the value from ``received_size_bytes`` and
        ``stream_complete`` on the current instance; the derived view is not
        stored as independent state.

        Returns:
            The numeric original size bytes value, or ``None`` when the
            requested value is unavailable.
        """

        if self.stream_complete:
            return self.received_size_bytes
        return None

    @property
    def full_response_sha256(self) -> Optional[str]:
        """
        Return a full-response digest only after a complete stream read.

        Each access computes the value from ``received_sha256`` and
        ``stream_complete`` on the current instance; the derived view is not
        stored as independent state.

        Returns:
            The canonical full response SHA-256 text, or ``None`` when the
            requested value is unavailable.
        """

        return self.received_sha256 if self.stream_complete else None

    @property
    def retained_size_bytes(self) -> int:
        """
        Return the retained size bytes.

        Each access computes the value from ``prefix_bytes`` and
        ``suffix_bytes`` on the current instance; the derived view is not stored
        as independent state.

        Returns:
            The numeric retained size bytes value.
        """
        return len(self.prefix_bytes) + len(self.suffix_bytes)

    @property
    def omitted_size_bytes(self) -> Optional[int]:
        """
        Return the omitted size bytes.

        Each access computes the value from ``original_size_bytes`` and
        ``retained_size_bytes`` on the current instance; the derived view is not
        stored as independent state.

        Returns:
            The numeric omitted size bytes value, or ``None`` when the requested
            value is unavailable.
        """
        original_size = self.original_size_bytes
        if original_size is None:
            return None
        return max(0, original_size - self.retained_size_bytes)

    @property
    def content_kind(self) -> str:
        """
        Return the content kind.

        Each access computes the value from ``_looks_textual``,
        ``content_type``, ``prefix_bytes``, and ``suffix_bytes`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The canonical content kind text.
        """
        content_type = self.content_type or ""
        if "json" in content_type:
            return "json"
        if content_type.startswith("text/") or any(
            marker in content_type for marker in ("xml", "yaml", "problem+")
        ):
            return "text"
        if not content_type and self._looks_textual(
            self.prefix_bytes + self.suffix_bytes
        ):
            return "text"
        return "binary"

    @staticmethod
    def _looks_textual(value: bytes) -> bool:
        """
        Return whether ``value`` looks like textual.

        The implementation uses ``value`` to determine whether ``value`` looks
        like textual.

        Args:
            value: Bounded byte sequence supplied as value.

        Returns:
            Whether ``value`` looks like textual.
        """
        if not value or b"\x00" in value:
            return False
        sample = value[:8192]
        control_bytes = sum(byte < 32 and byte not in (9, 10, 13) for byte in sample)
        return control_bytes * 20 <= len(sample)

    def safe_summary_text(self) -> str:
        """
        Describe the bounded evidence without returning response content.

        The implementation uses current instance state to describe the bounded
        evidence without returning response content.

        Returns:
            The canonical safe summary text.
        """

        original = self.original_size_bytes
        original_text = str(original) if original is not None else "unknown"
        digest_name = "sha256" if self.stream_complete else "received_sha256"
        is_oversized = (
            self.stream_complete
            or self.received_size_bytes >= self.response_limit_bytes
            or (
                self.declared_size_bytes is not None
                and self.declared_size_bytes > self.response_limit_bytes
            )
            or self.read_error_type == "RedfishEncodedResponseTooLarge"
        )
        response_shape = "Oversized" if is_oversized else "Incomplete"
        return (
            f"{response_shape} Redfish error body retained as bounded diagnostic evidence "
            f"(original={original_text} bytes, "
            f"received={self.received_size_bytes} bytes, "
            f"retained={self.retained_size_bytes} bytes, "
            f"stream_complete={str(self.stream_complete).lower()}, "
            f"{digest_name}={self.received_sha256})"
        )

    def capture_metadata(self) -> Dict[str, Any]:
        """
        Return JSON-safe status metadata without raw retained content.

        The implementation uses current instance state to produce JSON-safe
        status metadata without raw retained content.

        Returns:
            The validated ``metadata``.
        """

        prefix_name = "prefix" if self.stream_complete else "received_head"
        suffix_name = "suffix" if self.stream_complete else "received_tail"
        metadata: Dict[str, Any] = {
            "type": "truncated_redfish_error",
            "truncated": True,
            "content_kind": self.content_kind,
            "received_size_bytes": self.received_size_bytes,
            "retained_size_bytes": self.retained_size_bytes,
            "response_limit_bytes": self.response_limit_bytes,
            "evidence_limit_bytes": self.evidence_limit_bytes,
            "truncation_method": (
                "head_tail" if self.stream_complete else "received_head_tail"
            ),
            "stream_complete": self.stream_complete,
            "retained_windows": {
                prefix_name: {
                    "size_bytes": len(self.prefix_bytes),
                    "sha256": hashlib.sha256(self.prefix_bytes).hexdigest(),
                },
                suffix_name: {
                    "size_bytes": len(self.suffix_bytes),
                    "sha256": hashlib.sha256(self.suffix_bytes).hexdigest(),
                },
            },
        }
        if self.stream_complete:
            metadata["sha256"] = self.received_sha256
        else:
            metadata["received_sha256"] = self.received_sha256
        if self.original_size_bytes is not None:
            metadata["original_size_bytes"] = self.original_size_bytes
        if self.omitted_size_bytes is not None:
            metadata["omitted_size_bytes"] = self.omitted_size_bytes
        if self.declared_size_bytes is not None:
            metadata["declared_size_bytes"] = self.declared_size_bytes
        if self.content_type:
            metadata["content_type"] = self.content_type
        if self.http_status is not None:
            metadata["http_status"] = self.http_status
        if self.attempt_number is not None:
            metadata["attempt_number"] = self.attempt_number
        if self.read_error_type:
            metadata["read_error_type"] = self.read_error_type
        return metadata

    def capture_payload(self) -> Dict[str, Any]:
        """
        Return fail-closed metadata for the canonical capture serializer.

        The implementation uses current instance state to produce fail-closed
        metadata for the canonical capture serializer.

        Returns:
            A mapping containing the ``metadata`` and ``retained_body`` fields.
        """

        retained_body: Dict[str, Any] = {
            "publication": "digest_only",
            "reason": "untrusted_truncation_windows_not_published",
        }
        return {
            "metadata": self.capture_metadata(),
            "retained_body": retained_body,
        }


class StreamedRedfishBody:
    """
    A complete binary response held in a private, one-shot staging file.

    The path is deliberately omitted from ``str``/``repr`` so request captures
    cannot expose host-local temporary layout. The receiving artifact writer
    takes ownership with :meth:`mark_published`; otherwise callers must invoke
    :meth:`cleanup`. ``DUTManager.cleanup`` provides a final directory-level
    safety net for interrupted collection flows.
    """

    __slots__ = (
        "_path",
        "_identity",
        "size_bytes",
        "sha256",
        "prefix_bytes",
        "content_type",
    )

    def __init__(
        self,
        path: Path,
        *,
        size_bytes: int,
        sha256: str,
        prefix_bytes: bytes = b"",
        content_type: Optional[str] = None,
    ) -> None:
        """
        Initialize a ``StreamedRedfishBody`` instance.

        The initializer records ``_identity``, ``_path``, ``content_type``,
        ``prefix_bytes``, and ``sha256`` for later operations and establishes
        the instance invariants before any public method runs. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            path: filesystem location used as the path for this operation.
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
            sha256: Text supplied as SHA-256 in the format accepted by this
                function.
            prefix_bytes: Bounded byte sequence supplied as prefix bytes.
            content_type: Optional content type; ``None`` selects the function's
                default behavior.
        """
        self._path: Optional[Path] = Path(path)
        try:
            metadata = self._path.lstat()
        except OSError:
            self._identity: Optional[tuple[int, int, int]] = None
        else:
            self._identity = (
                self._file_identity(metadata)
                if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                else None
            )
        self.size_bytes = int(size_bytes)
        self.sha256 = str(sha256)
        self.prefix_bytes = bytes(prefix_bytes)
        self.content_type = content_type

    def __len__(self) -> int:
        """
        Return the number of entries owned by the StreamedRedfishBody.

        The implementation uses current instance state to produce the number of
        entries owned by the StreamedRedfishBody.

        Returns:
            The numeric len value.
        """
        return self.size_bytes

    def __repr__(self) -> str:
        """
        Return a developer-facing representation of the StreamedRedfishBody.

        The implementation uses current instance state to produce a
        developer-facing representation of the StreamedRedfishBody.

        Returns:
            The canonical repr text.
        """
        return (
            "StreamedRedfishBody("
            f"size_bytes={self.size_bytes}, sha256='{self.sha256}')"
        )

    __str__ = __repr__

    @staticmethod
    def _file_identity(metadata: os.stat_result) -> tuple[int, int, int]:
        """
        Return the stable device, inode, and file-type identity.

        The implementation uses ``metadata`` to produce the stable device,
        inode, and file-type identity.

        Args:
            metadata: Metadata object whose ``st_dev``, ``st_ino``, and
                ``st_mode`` state is read while performing stable device, inode,
                and file-type identity.

        Returns:
            A tuple containing ``st dev``, ``st ino``, and ``s ifmt`` in that
            order.
        """

        return (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
        )

    def _checked_private_path(self) -> Path:
        """
        Return the staging path only while it names the owned inode.

        The implementation uses current instance state to produce the staging
        path only while it names the owned inode. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot produce the staging path only while it names the
        owned inode, its exception reaches the caller instead of being converted
        into a successful result.

        Returns:
            The validated ``path``.

        Raises:
            RuntimeError: If streamed Redfish body has already been published.
            ValueError: If streamed Redfish body has no owned staging identity;
                streamed Redfish body staging file is missing; or streamed
                Redfish body path identity changed.
        """

        path = self._path
        if path is None:
            raise RuntimeError("Streamed Redfish body has already been published")
        if self._identity is None:
            raise ValueError("Streamed Redfish body has no owned staging identity")
        try:
            visible = path.lstat()
        except FileNotFoundError:
            raise ValueError("Streamed Redfish body staging file is missing") from None
        if (
            not stat.S_ISREG(visible.st_mode)
            or visible.st_nlink != 1
            or self._file_identity(visible) != self._identity
        ):
            raise ValueError("Streamed Redfish body path identity changed")
        return path

    @property
    def private_path(self) -> Path:
        """
        Return the owned staging path to trusted artifact-publish code.

        Each access computes the value from ``_checked_private_path`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The validated private path filesystem path.
        """

        return self._checked_private_path()

    def _open_stream(self, *, writable: bool) -> BinaryIO:
        """
        Open and verify the owned staging inode without following symlinks.

        After applying local validation, the function forwards ``writable`` to
        ``os.fdopen`` and preserves its return and exception contract.

        Args:
            writable: Whether writable is enabled or required for this
                operation.

        Returns:
            A ``BinaryIO`` representing open stream.

        Raises:
            ValueError: If streamed Redfish body path identity changed.
        """

        flags = (
            (os.O_RDWR if writable else os.O_RDONLY)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(self._checked_private_path(), flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                self._identity is None
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or self._file_identity(metadata) != self._identity
            ):
                raise ValueError("Streamed Redfish body path identity changed")
            return os.fdopen(descriptor, "r+b" if writable else "rb")
        except BaseException:
            os.close(descriptor)
            raise

    def open(self) -> BinaryIO:
        """
        Open the staged response for bounded, chunked processing.

        After applying local validation, the function forwards current instance
        state to ``self._open_stream`` and preserves its return and exception
        contract.

        Returns:
            A ``BinaryIO`` representing open.
        """

        return self._open_stream(writable=False)

    def open_for_update(self) -> BinaryIO:
        """
        Open the owned staging inode for verified in-place normalization.

        After applying local validation, the function forwards current instance
        state to ``self._open_stream`` and preserves its return and exception
        contract.

        Returns:
            A ``BinaryIO`` representing open for update.

        Raises:
            OSError: If the staging path cannot be opened.
            RuntimeError: If ownership was already released after publication.
            ValueError: If the staging path no longer names the owned file.
        """

        return self._open_stream(writable=True)

    def read_bytes(self, *, max_bytes: int) -> bytes:
        """
        Read a response only when its known size fits a caller's memory bound.

        The implementation uses ``max_bytes`` to read a response only when its
        known size fits a caller's memory bound. Parsing or I/O must finish
        before the validated representation is made available to the caller. If
        the function cannot read a response only when its known size fits a
        caller's memory bound, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            The validated ``data``.

        Raises:
            ValueError: If the streamed redfish read limit is not non-negative;
                streamed Redfish body exceeds ``max_bytes``-byte read limit;
                streamed Redfish body changed while reading; or streamed Redfish
                body size metadata is stale; or another input invariant is
                violated.
        """

        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or max_bytes < 0
        ):
            raise ValueError("Streamed Redfish read limit must be non-negative")
        if self.size_bytes > max_bytes:
            raise ValueError(
                f"Streamed Redfish body exceeds {max_bytes}-byte read limit"
            )
        with self.open() as source:
            before = os.fstat(source.fileno())
            data = source.read(self.size_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError(
                    f"Streamed Redfish body exceeds {max_bytes}-byte read limit"
                )
            after = os.fstat(source.fileno())
            before_identity = (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if before_identity != after_identity:
                raise ValueError("Streamed Redfish body changed while reading")
            if len(data) != after.st_size or len(data) != self.size_bytes:
                raise ValueError("Streamed Redfish body size metadata is stale")
            if hashlib.sha256(data).hexdigest() != self.sha256:
                raise ValueError("Streamed Redfish body digest metadata is stale")
            return data

    def capture_metadata(self) -> Dict[str, object]:
        """
        Return JSON-safe content metadata without the private path.

        The implementation uses current instance state to produce JSON-safe
        content metadata without the private path.

        Returns:
            The validated ``metadata``.
        """

        metadata: Dict[str, object] = {
            "type": "streamed_binary",
            "length": self.size_bytes,
            "sha256": self.sha256,
            "note": "binary content omitted",
        }
        if self.content_type:
            metadata["content_type"] = self.content_type
        return metadata

    def mark_published(self) -> None:
        """
        Release ownership after the staging file was atomically promoted.

        The implementation uses current instance state to release ownership
        after the staging file was atomically promoted. It updates ``_identity``
        and ``_path`` on the instance as part of that state transition.
        """

        self._path = None
        self._identity = None

    def cleanup(self) -> None:
        """
        Delete an unpublished staging file.

        The implementation uses current instance state to delete an unpublished
        staging file. It updates ``_identity`` and ``_path`` on the instance as
        part of that state transition. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.
        """

        path = self._path
        self._path = None
        identity = self._identity
        self._identity = None
        if path is None:
            return
        try:
            visible = path.lstat()
        except FileNotFoundError:
            return
        if (
            identity is None
            or not stat.S_ISREG(visible.st_mode)
            or visible.st_nlink != 1
            or self._file_identity(visible) != identity
        ):
            return
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def __del__(self) -> None:
        # Best-effort only; deterministic cleanup belongs to callers/manager.
        """
        Release remaining resources owned by the StreamedRedfishBody.

        The implementation uses current instance state to release remaining
        resources owned by the StreamedRedfishBody.
        """
        try:
            self.cleanup()
        except Exception:
            pass
