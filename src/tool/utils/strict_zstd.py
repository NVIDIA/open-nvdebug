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
Strict, resource-bounded decoding for concatenated Zstandard frames.

This module owns the strict zstd boundary and exposes ``StrictZstdError`` and
``StrictZstdReader``. Keeping those contracts together gives importers one
source of truth for their validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import io
import time
from collections.abc import Callable
from typing import Any, BinaryIO

try:
    import zstandard
except ImportError:  # pragma: no cover - callers own optional-backend policy
    zstandard = None

ZSTD_FRAME_MAGIC = b"\x28\xb5\x2f\xfd"
_ZSTD_SKIPPABLE_MAGIC_MIN = 0x184D2A50
_ZSTD_SKIPPABLE_MAGIC_MAX = 0x184D2A5F
_ZSTD_BLOCK_MAX_OUTPUT_BYTES = 128 * 1024
_ZSTD_MAX_TRANSIENT_OUTPUT_BYTES = 32 * 1024 * 1024
DEFAULT_STRICT_ZSTD_MAX_SECONDS = 900.0


class StrictZstdError(ValueError):
    """
    A Zstandard stream violated its completeness or resource policy.

    Callers receive this exception when the strict zstd error invariant prevents
    the requested operation from completing. The distinct type lets them handle
    that boundary without parsing an error message.
    """

    def __init__(self, reason: str) -> None:
        """
        Initialize a ``StrictZstdError`` instance.

        The initializer records ``reason`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            reason: Text supplied as reason in the format accepted by this
                function.
        """
        super().__init__(reason)
        self.reason = reason


class StrictZstdReader(io.RawIOBase):
    """
    Decode complete concatenated frames without accepting a partial suffix.

    ``zstandard.ZstdDecompressor.stream_reader`` reports physical EOF as
    decompressed EOF even when the final frame is incomplete. This reader uses
    one decompression object per frame and requires its explicit ``eof`` bit.
    Compressed input is fed in small enough pieces to keep a single decoder
    return bounded even for minimal RLE blocks; decoded bytes, input bytes,
    frame count, window size, and caller-supplied elapsed time are all finite.
    """

    def __init__(
        self,
        source: BinaryIO,
        *,
        max_window_size: int,
        max_output_bytes: int,
        max_input_bytes: int,
        max_frames: int,
        max_seconds: float = DEFAULT_STRICT_ZSTD_MAX_SECONDS,
        check_deadline: Callable[[], None] | None = None,
    ) -> None:
        """
        Initialize a bounded reader over one caller-owned binary stream.

        The initializer records ``_check_deadline``, ``_compressed_read_size``,
        ``_decoded``, ``_decoder``, and ``_finished`` for later operations and
        establishes the instance invariants before any public method runs. If
        the function cannot initialize a bounded reader over one caller-owned
        binary stream, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            source: Source consumed while the function attempts to initialize a
                bounded reader over one caller-owned binary stream.
            max_window_size: Upper bound enforced for max window size; the
                consuming boundary rejects or truncates values that exceed it.
            max_output_bytes: Upper bound enforced for max output bytes; the
                consuming boundary rejects or truncates values that exceed it.
            max_input_bytes: Upper bound enforced for max input bytes; the
                consuming boundary rejects or truncates values that exceed it.
            max_frames: Upper bound enforced for max frames; the consuming
                boundary rejects or truncates values that exceed it.
            max_seconds: Maximum elapsed seconds allowed when the caller does
                not supply its own deadline checker.
            check_deadline: Optional check deadline; ``None`` selects the
                finite module-owned deadline derived from ``max_seconds``.

        Raises:
            ValueError: If the integer limits are not positive integers or
                ``max_seconds`` is not a positive finite number.
            StrictZstdError: If backend_unavailable.
        """

        super().__init__()
        integer_limits = (
            max_window_size,
            max_output_bytes,
            max_input_bytes,
            max_frames,
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in integer_limits
        ):
            raise ValueError("strict Zstandard limits must be positive integers")
        if (
            isinstance(max_seconds, bool)
            or not isinstance(max_seconds, (int, float))
            or not 0 < float(max_seconds) < float("inf")
        ):
            raise ValueError("strict Zstandard max_seconds must be positive and finite")
        if zstandard is None:
            raise StrictZstdError("backend_unavailable")

        self._source = source
        self._max_window_size = max_window_size
        self._max_output_bytes = max_output_bytes
        self._max_input_bytes = max_input_bytes
        self._max_frames = max_frames
        if check_deadline is None:
            deadline = time.monotonic() + float(max_seconds)

            def check_default_deadline() -> None:
                """
                Reject decoding after the module-owned monotonic deadline.

                Each call compares the current monotonic clock with the
                deadline captured when the reader was initialized.

                Raises:
                    StrictZstdError: If the finite decode deadline has elapsed.
                """
                if time.monotonic() > deadline:
                    raise StrictZstdError("time_limit")

            self._check_deadline = check_default_deadline
        else:
            self._check_deadline = check_deadline
        self._decoder: Any | None = None
        self._pending_compressed = b""
        self._decoded = bytearray()
        self._physical_eof = False
        self._finished = False
        self._input_bytes = 0
        self._output_bytes = 0
        self._frames = 0

        block_output = min(
            _ZSTD_BLOCK_MAX_OUTPUT_BYTES,
            self._max_window_size,
        )
        transient_target = min(
            _ZSTD_MAX_TRANSIENT_OUTPUT_BYTES,
            self._max_window_size,
        )
        # A non-empty RLE block needs a three-byte header and one payload byte.
        # Include one block which may already be buffered inside the decoder.
        admitted_blocks = max(1, transient_target // max(1, block_output))
        self._compressed_read_size = max(1, (admitted_blocks - 1) * 4)

    @property
    def input_bytes(self) -> int:
        """
        Return the input bytes.

        Each access computes the value from ``_input_bytes`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric input bytes value.
        """
        return self._input_bytes

    @property
    def output_bytes(self) -> int:
        """
        Return the output bytes.

        Each access computes the value from ``_output_bytes`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric output bytes value.
        """
        return self._output_bytes

    @property
    def frames(self) -> int:
        """
        Return the frames.

        Each access computes the value from ``_frames`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            The numeric frames value.
        """
        return self._frames

    def readable(self) -> bool:
        """
        Return whether the stream supports reading.

        The implementation uses current instance state to determine whether the
        stream supports reading.

        Returns:
            Whether the stream supports reading.
        """
        return True

    def _read_source(self, size: int) -> bytes:
        """
        Read source.

        The implementation uses ``size`` to read source. Parsing or I/O must
        finish before the validated representation is made available to the
        caller. It updates ``_input_bytes`` and ``_physical_eof`` on the
        instance as part of that state transition. If the function cannot read
        source, its exception reaches the caller instead of being converted into
        a successful result.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The validated ``chunk``.

        Raises:
            StrictZstdError: If input_read_failed; invalid_input; or
                input_size_limit.
        """
        self._check_deadline()
        remaining = self._max_input_bytes - self._input_bytes
        requested = min(max(1, size), remaining + 1)
        try:
            chunk = self._source.read(requested)
        except StrictZstdError:
            raise
        except Exception as error:
            raise StrictZstdError("input_read_failed") from error
        self._check_deadline()
        if not isinstance(chunk, bytes):
            raise StrictZstdError("invalid_input")
        self._input_bytes += len(chunk)
        if self._input_bytes > self._max_input_bytes:
            raise StrictZstdError("input_size_limit")
        if not chunk:
            self._physical_eof = True
        return chunk

    def _ensure_frame_prefix(self) -> None:
        """
        Ensure frame prefix.

        The implementation uses current instance state to ensure frame prefix.
        It updates ``_decoder``, ``_finished``, ``_frames``, and
        ``_pending_compressed`` on the instance as part of that state
        transition. If the function cannot ensure frame prefix, its exception
        reaches the caller instead of being converted into a successful result.

        Raises:
            StrictZstdError: If empty_stream; truncated_frame;
                frame_count_limit; or decompressor_memory_limit; or another
                input invariant is violated.
        """
        while True:
            prefix = self._read_compressed_exact(len(ZSTD_FRAME_MAGIC))
            if not prefix:
                if self._frames == 0:
                    raise StrictZstdError("empty_stream")
                self._finished = True
                return
            if len(prefix) < len(ZSTD_FRAME_MAGIC):
                raise StrictZstdError("truncated_frame")
            if self._frames >= self._max_frames:
                raise StrictZstdError("frame_count_limit")

            if prefix == ZSTD_FRAME_MAGIC:
                self._pending_compressed = prefix + self._pending_compressed
                try:
                    self._decoder = zstandard.ZstdDecompressor(
                        max_window_size=self._max_window_size,
                    ).decompressobj(write_size=min(self._max_window_size, 1024 * 1024))
                except (MemoryError, zstandard.ZstdError) as error:
                    raise StrictZstdError("decompressor_memory_limit") from error
                self._frames += 1
                return

            magic = int.from_bytes(prefix, "little")
            if not _ZSTD_SKIPPABLE_MAGIC_MIN <= magic <= _ZSTD_SKIPPABLE_MAGIC_MAX:
                raise StrictZstdError("non_frame_suffix")
            size_bytes = self._read_compressed_exact(4)
            if len(size_bytes) != 4:
                raise StrictZstdError("truncated_frame")
            self._frames += 1
            self._discard_compressed(int.from_bytes(size_bytes, "little"))

    def _read_compressed_exact(self, size: int) -> bytes:
        """
        Read compressed exact.

        After applying local validation, the function forwards ``size`` to
        ``bytes`` and preserves its return and exception contract. Parsing or
        I/O must finish before the validated representation is made available to
        the caller. It updates ``_pending_compressed`` on the instance as part
        of that state transition.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The bounded compressed exact bytes.
        """
        accepted = bytearray()
        if self._pending_compressed:
            count = min(size, len(self._pending_compressed))
            accepted.extend(self._pending_compressed[:count])
            self._pending_compressed = self._pending_compressed[count:]
        while len(accepted) < size and not self._physical_eof:
            chunk = self._read_source(size - len(accepted))
            if not chunk:
                break
            accepted.extend(chunk)
        return bytes(accepted)

    def _discard_compressed(self, size: int) -> None:
        """
        Discard compressed.

        The implementation uses ``size`` to discard compressed. It updates
        ``_pending_compressed`` on the instance as part of that state
        transition. If the function cannot discard compressed, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Raises:
            StrictZstdError: If truncated_frame.
        """
        remaining = size
        if self._pending_compressed:
            count = min(remaining, len(self._pending_compressed))
            self._pending_compressed = self._pending_compressed[count:]
            remaining -= count
        while remaining:
            chunk = self._read_source(min(remaining, self._compressed_read_size))
            if not chunk:
                raise StrictZstdError("truncated_frame")
            remaining -= len(chunk)

    def _pump(self) -> None:
        """
        Pump one strictly framed Zstandard chunk into the read buffer.

        The implementation uses current instance state to pump one strictly
        framed Zstandard chunk into the read buffer. It updates ``_decoder``,
        ``_output_bytes``, and ``_pending_compressed`` on the instance as part
        of that state transition. If the function cannot pump one strictly
        framed Zstandard chunk into the read buffer, its exception reaches the
        caller instead of being converted into a successful result.

        Raises:
            StrictZstdError: If truncated_frame; decompressor_memory_limit; the
                function cannot pump one strictly framed Zstandard chunk into
                the read buffer safely; or output_size_limit; or another input
                invariant is violated.
        """
        while not self._decoded and not self._finished:
            self._check_deadline()
            if self._decoder is None:
                self._ensure_frame_prefix()
                if self._finished:
                    return

            compressed = self._pending_compressed
            self._pending_compressed = b""
            if not compressed:
                compressed = self._read_source(self._compressed_read_size)
            if not compressed:
                raise StrictZstdError("truncated_frame")

            try:
                decoded = self._decoder.decompress(compressed)
            except MemoryError as error:
                raise StrictZstdError("decompressor_memory_limit") from error
            except zstandard.ZstdError as error:
                message = str(error).casefold()
                reason = (
                    "decompressor_memory_limit"
                    if "window" in message or "memory" in message
                    else "decompression_failed"
                )
                raise StrictZstdError(reason) from error
            self._check_deadline()

            if decoded:
                self._output_bytes += len(decoded)
                if self._output_bytes > self._max_output_bytes:
                    raise StrictZstdError("output_size_limit")
                self._decoded.extend(decoded)

            if self._decoder.eof:
                unused = bytes(self._decoder.unused_data)
                unconsumed = bytes(self._decoder.unconsumed_tail)
                if unused and unconsumed and unused != unconsumed:
                    raise StrictZstdError("decompression_failed")
                self._pending_compressed = unused or unconsumed
                self._decoder = None

    def read(self, size: int = -1) -> bytes:
        """
        Read bounded data from the owned source.

        Raw streams may return fewer than ``size`` bytes. Returning the
        currently decoded frame chunk avoids retaining or eagerly producing a
        caller-sized buffer while still guaranteeing progress.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The bounded result bytes.

        Raises:
            ValueError: If i/O operation on closed Zstandard reader.
        """
        if self.closed:
            raise ValueError("I/O operation on closed Zstandard reader")
        if size == 0:
            return b""
        if size < 0:
            output = bytearray()
            while True:
                chunk = self.read(1024 * 1024)
                if not chunk:
                    return bytes(output)
                output.extend(chunk)

        # Raw streams may return fewer than ``size`` bytes. Returning the
        # currently decoded frame chunk avoids retaining or eagerly producing
        # a caller-sized buffer while still guaranteeing progress.
        if not self._decoded and not self._finished:
            self._pump()
        accepted = bytes(self._decoded[:size])
        del self._decoded[:size]
        return accepted

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

    def close(self) -> None:
        """
        Close the StrictZstdReader.

        The implementation uses current instance state to close the
        StrictZstdReader. It updates ``_decoder`` and ``_pending_compressed`` on
        the instance as part of that state transition.
        """
        self._decoded.clear()
        self._pending_compressed = b""
        self._decoder = None
        super().close()


__all__ = ["StrictZstdError", "StrictZstdReader", "ZSTD_FRAME_MAGIC"]
