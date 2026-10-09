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
Compress bounded ZIP member blocks in parallel without diagnostic staging files.

Each independent raw DEFLATE block uses the preceding 32 KiB as its dictionary
and ends with a byte-aligned, nonterminal sync flush. Ordered blocks and one final
empty block form a single ordinary DEFLATE stream, as in pigz's parallel design.
The standard library still owns ZIP headers, CRCs, sizes, ZIP64, and publication.
Only compression uses workers; source reads and archive writes retain one owner.
"""

from __future__ import annotations

import time
import zipfile
import zlib
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from typing import BinaryIO, Iterator

from ..core.finalization_receipt import select_authoritative_exception

DEFLATE_CHUNK_BYTES = 1024 * 1024
MIN_PARALLEL_DEFLATE_BYTES = 4 * DEFLATE_CHUNK_BYTES
MAX_DEFLATE_WORKERS = 8
_DICTIONARY_BYTES = 32 * 1024


def _compress_block(data: bytes, dictionary: bytes, level: int) -> bytes:
    """
    Produce a byte-aligned partial DEFLATE stream for one bounded input block.

    Independent compressor state avoids sharing zlib objects between workers.
    The prior input dictionary preserves matches across block boundaries while
    the sync flush leaves the stream open for the next ordered block.

    Args:
        data: At most one MiB of immutable source bytes.
        dictionary: Up to 32 KiB immediately preceding these bytes.
        level: The archive's existing zlib compression level.

    Returns:
        Raw DEFLATE bytes ending at a nonterminal byte boundary.

    Raises:
        ValueError: If either buffer exceeds its fixed memory bound.
        Exception: If zlib raises its compression error instead of producing a
            valid partial stream.
    """

    if len(data) > DEFLATE_CHUNK_BYTES or len(dictionary) > _DICTIONARY_BYTES:
        raise ValueError("Parallel DEFLATE block exceeds its memory bound")
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15, zdict=dictionary)
    return compressor.compress(data) + compressor.flush(zlib.Z_SYNC_FLUSH)


class _ParallelDeflateCompressor:
    """
    Adapt an owned bounded worker queue to zipfile's compressor protocol.

    One caller submits immutable input and consumes compressed blocks in order.
    At most eight one-MiB jobs are outstanding, regardless of member size. The
    archive transaction owns the shared executor; this adapter observes and
    drains its own futures on success, failure, deadline expiry, and interruption.
    No worker reads a path, writes an archive, or retains a complete member.
    """

    def __init__(
        self,
        executor: ThreadPoolExecutor,
        workers: int,
        level: int,
        deadline: float | None,
    ) -> None:
        """
        Initialize a member-local queue without creating worker threads.

        The executor remains owned by the surrounding archive. Threads start
        only when a large member submits its first immutable input block.

        Args:
            executor: Archive-owned executor reused between large members.
            workers: Maximum outstanding blocks, between two and eight.
            level: Existing archive compression level, from minus one to nine.
            deadline: Absolute monotonic archive deadline, or no time limit.

        Raises:
            ValueError: If the queue bound or compression level is invalid.
        """

        if type(workers) is not int or not 2 <= workers <= MAX_DEFLATE_WORKERS:
            raise ValueError("Parallel DEFLATE worker bound is invalid")
        if type(level) is not int or not -1 <= level <= 9:
            raise ValueError("Parallel DEFLATE compression level is invalid")
        self._executor = executor
        self._workers = workers
        self._level = level
        self._deadline = deadline
        self._pending: deque[Future[bytes]] = deque()
        self._dictionary = b""
        self._closed = False

    def _check_deadline(self) -> float | None:
        """
        Reject expired work and bound the next wait by the archive deadline.

        The shared deadline includes source IO and queue waits, so waiting for
        CPU work cannot restart the archive's existing elapsed-time budget.

        Returns:
            Remaining seconds, or ``None`` when the caller has no deadline.

        Raises:
            ValueError: If the archive deadline has elapsed.
        """

        if self._deadline is None:
            return None
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("ZIP creation deadline exceeded")
        return remaining

    def _next_block(self) -> bytes:
        """
        Consume the oldest result while retaining ownership until it completes.

        A failed or timed-out future stays in the queue for abort to drain.
        Later completed blocks never overtake an earlier input block.

        Returns:
            Compressed bytes for the earliest pending input block.

        Raises:
            ValueError: If waiting reaches the archive deadline.
            BaseException: If the worker or caller interrupts compression.
        """

        future = self._pending[0]
        try:
            result = future.result(timeout=self._check_deadline())
        except TimeoutError as error:
            raise ValueError("ZIP creation deadline exceeded") from error
        # Leave a failed or interrupted future queued so abort can observe it
        # along with every later job before the transaction releases resources.
        self._pending.popleft()
        self._check_deadline()
        return result

    def compress(self, data: bytes) -> bytes:
        """
        Submit one bounded input block and apply backpressure at the queue limit.

        Empty writes leave the dictionary unchanged. Uneven writes preserve the
        complete preceding window without retaining an entire source member.

        Args:
            data: Immutable source bytes, no larger than the writer's one-MiB read.

        Returns:
            The next ordered compressed block when the queue fills, else empty
            bytes. Delayed output is permitted by the zlib compressor protocol.

        Raises:
            ValueError: If input exceeds its bound, the member is closed, or its
                archive deadline has elapsed.
            BaseException: If submission, compression, or waiting fails.
        """

        if self._closed:
            raise ValueError("Parallel DEFLATE member is closed")
        if type(data) is not bytes or len(data) > DEFLATE_CHUNK_BYTES:
            raise ValueError("Parallel DEFLATE input exceeds its memory bound")
        self._check_deadline()
        if not data:
            return b""
        self._pending.append(
            self._executor.submit(_compress_block, data, self._dictionary, self._level)
        )
        self._dictionary = (
            data[-_DICTIONARY_BYTES:]
            if len(data) >= _DICTIONARY_BYTES
            else (self._dictionary + data)[-_DICTIONARY_BYTES:]
        )
        if len(self._pending) >= self._workers:
            return self._next_block()
        return b""

    def _wait_for_pending(self) -> None:
        """
        Observe every block before releasing the compression context to zipfile.

        The outer writable-member context closes after this adapter's context
        exits. Observing results here prevents an interruption between those
        exits from abandoning unobserved worker failures. Output remains queued
        in order for the normal ZIP close to consume without copying buffers.

        Raises:
            ValueError: If waiting reaches the archive's existing deadline.
            BaseException: If a worker fails or the caller interrupts waiting.
        """

        for future in self._pending:
            try:
                future.result(timeout=self._check_deadline())
            except TimeoutError as error:
                raise ValueError("ZIP creation deadline exceeded") from error
        self._check_deadline()

    def abort(self, error: BaseException) -> BaseException:
        """
        Cancel unstarted blocks, drain started work, and preserve control flow.

        A running zlib call cannot be interrupted. Its input is limited to one
        MiB, so cleanup waits only for the fixed number of already owned blocks.
        Later worker failures cannot hide cancellation or an interrupt.

        Args:
            error: The source, writer, compression, or caller failure to preserve.

        Returns:
            The authoritative exception after observing every owned future.

        Side Effects:
            Closes the member and releases all queued input and output buffers.
            Subsequent zipfile cleanup flushes return empty bytes; the owning
            transaction still receives the failure and cannot publish success.
        """

        self._closed = True
        self._dictionary = b""
        errors = [error]
        for future in self._pending:
            future.cancel()
        while self._pending:
            future = self._pending[0]
            try:
                future.result()
            except BaseException as failure:
                errors.append(failure)
                if not future.done():
                    # A caller interruption during the wait does not transfer
                    # ownership or permit a still-running block to escape.
                    continue
            self._pending.popleft()
        return select_authoritative_exception(errors)

    def flush(self) -> bytes:
        """
        Finish all queued blocks and terminate the ordinary raw DEFLATE stream.

        The queue bound also bounds this final output join. Any failure closes
        and drains the member before the outer ZIP writer can finish cleanup.

        Returns:
            At most eight bounded compressed blocks plus an empty final block,
            or empty bytes when unwinding a previously aborted member.

        Raises:
            BaseException: The authoritative compression, deadline, or caller
                failure after every remaining future has been observed.
        """

        if self._closed:
            return b""
        try:
            self._check_deadline()
            chunks = []
            while self._pending:
                chunks.append(self._next_block())
            chunks.append(zlib.compressobj(self._level, zlib.DEFLATED, -15).flush())
            self._closed = True
            self._dictionary = b""
            return b"".join(chunks)
        except BaseException as error:
            raise self.abort(error)


@contextmanager
def parallel_zip_compression(
    destination: BinaryIO,
    *,
    executor: ThreadPoolExecutor | None,
    workers: int,
    level: int,
    source_bytes: int,
    deadline: float | None,
) -> Iterator[None]:
    """
    Install bounded parallel compression only on a supported large ZIP member.

    The private stdlib seam is restricted to its exact writable-member class,
    before any bytes are written. Unknown ZIP implementations retain their
    ordinary compressor. Standard zipfile remains responsible for all format
    bookkeeping, and the caller retains the no-follow source and receipt checks.

    Args:
        destination: Newly opened writable member owned by the outer context.
        executor: Archive-owned pool, or ``None`` for serial compression.
        workers: Effective bounded pool size selected from available CPU capacity.
        level: Existing ZIP compression level.
        source_bytes: Descriptor-pinned source size used to avoid tiny-file jobs.
        deadline: Absolute monotonic archive deadline, or no time limit.

    Yields:
        Control to the existing bounded source-copy loop without changing its IO.

    Raises:
        BaseException: An owned copy or compression failure after worker cleanup.

    Side Effects:
        Replaces only this member's unused compressor. It never patches zipfile
        globally, changes compression level, or creates staging files. The outer
        member context calls flush on normal close, before archive verification.
    """

    if (
        executor is None
        or workers < 2
        or source_bytes < MIN_PARALLEL_DEFLATE_BYTES
        or type(destination) is not getattr(zipfile, "_ZipWriteFile", None)
        or getattr(destination, "_compressor", None) is None
        or getattr(destination, "_file_size", None) != 0
        or getattr(destination, "_compress_size", None) != 0
        or destination._zinfo.compress_type != zipfile.ZIP_DEFLATED
    ):
        yield
        return
    compressor = _ParallelDeflateCompressor(executor, workers, level, deadline)
    destination._compressor = compressor
    try:
        yield
        compressor._wait_for_pending()
    except BaseException as error:
        raise compressor.abort(error)
