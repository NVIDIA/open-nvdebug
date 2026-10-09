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
Owned execution for bounded filesystem and archive operations.

The shared pool limits blocking work while retaining ownership through normal
completion, worker failure, and asynchronous cancellation.
"""

from __future__ import annotations

import asyncio
import threading
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from contextvars import ContextVar
from typing import Any, Callable, Optional

MANAGED_FILESYSTEM_WORKERS = 4
_MANAGED_FILESYSTEM_BULK_LIMIT = max(1, MANAGED_FILESYSTEM_WORKERS - 1)
_MANAGED_FILESYSTEM_BULK_ACTIVE = 0
_MANAGED_FILESYSTEM_EXECUTOR = ThreadPoolExecutor(
    max_workers=MANAGED_FILESYSTEM_WORKERS,
    thread_name_prefix="nvdebug-managed-artifact",
)
_MANAGED_FILESYSTEM_CAPACITY = threading.BoundedSemaphore(MANAGED_FILESYSTEM_WORKERS)
_MANAGED_FILESYSTEM_ADMISSION_LOCK = threading.Lock()
_MANAGED_FILESYSTEM_WAITERS: deque[
    tuple[asyncio.AbstractEventLoop, asyncio.Event, bool]
] = deque()
_MANAGED_FILESYSTEM_ADMISSION_WAKEUP: ContextVar[Optional[asyncio.Event]] = ContextVar(
    "managed_filesystem_admission_wakeup", default=None
)


async def _filesystem_worker_heartbeat() -> None:
    """
    Yield once without relying on a replaceable sleep implementation.

    A loop-owned timer provides a portable cross-thread observation heartbeat
    and keeps deterministic sleep shims from turning admission into a busy loop.
    Queued owners may wake earlier when shared capacity or queue order changes;
    the timer remains a fallback if a cross-thread notification is lost. The
    context is scoped to admission and never escapes into submitted workers.
    """

    loop = asyncio.get_running_loop()
    heartbeat = _MANAGED_FILESYSTEM_ADMISSION_WAKEUP.get() or asyncio.Event()
    timer = loop.call_later(0.01, heartbeat.set)
    try:
        await heartbeat.wait()
    finally:
        timer.cancel()
        heartbeat.clear()


async def _await_managed_worker(future: Future[Any]) -> Any:
    """
    Observe one owned worker without blocking the event-loop thread.

    The small heartbeat keeps compatibility with event-loop implementations
    that do not reliably wake for cross-thread future notifications. The
    concurrent future remains owned by the caller until its terminal result or
    exception has been observed.

    Args:
        future: Submitted concurrent future whose terminal state is awaited.

    Returns:
        The exact value returned by the worker operation.
    """

    while not future.done():
        await _filesystem_worker_heartbeat()
    return future.result()


async def _drain_cancelled_worker(future: Future[Any]) -> None:
    """
    Join a submitted worker after its asynchronous owner is cancelled.

    Repeated cancellation requests are deferred until the finite worker has
    stopped. Its exception is observed here and the original cancellation
    remains authoritative for the caller.

    Args:
        future: Submitted concurrent future that must reach a terminal state.
    """

    while not future.done():
        try:
            await _filesystem_worker_heartbeat()
        except asyncio.CancelledError:
            continue
    try:
        future.result()
    except BaseException:
        pass


def _next_managed_filesystem_waiter() -> (
    Optional[tuple[asyncio.AbstractEventLoop, asyncio.Event, bool]]
):
    """
    Select the oldest currently eligible owner under the admission lock.

    Explicit bulk preparation may occupy at most three of the four workers.
    Small operations can pass a bulk waiter whose class allowance is full;
    arrival order remains authoritative among currently eligible owners. This
    is a scheduling allowance, not a relaxation of any input or output bound.
    Closed-loop tokens cannot make progress and are removed before selection;
    live owners retain their queue positions even when notification is lost.

    Returns:
        The oldest eligible queue token, or None when no owner is eligible.
    """
    while _MANAGED_FILESYSTEM_WAITERS:
        for waiter in _MANAGED_FILESYSTEM_WAITERS:
            if waiter[0].is_closed():
                _MANAGED_FILESYSTEM_WAITERS.remove(waiter)
                break
            if (
                not waiter[2]
                or _MANAGED_FILESYSTEM_BULK_ACTIVE < _MANAGED_FILESYSTEM_BULK_LIMIT
            ):
                return waiter
        else:
            return None
    return None


def _notify_managed_filesystem_head() -> None:
    """
    Prompt the oldest eligible owner while holding the shared admission lock.

    Notifications only shorten its portable timer wait; they never reserve or
    transfer capacity. A loop that closes during notification must not replace a
    completed worker's result with a notification error. Closed-loop owners are
    discarded without consuming capacity. A notification failure on a live loop
    retains its queue position and portable heartbeat fallback.
    """
    while (waiter := _next_managed_filesystem_waiter()) is not None:
        loop, wakeup, _bulk = waiter
        try:
            loop.call_soon_threadsafe(wakeup.set)
        except RuntimeError:
            if loop.is_closed():
                continue
        return


def _release_managed_filesystem_slot(*, bulk: bool = False) -> None:
    """
    Return one owned slot and promptly wake the oldest queued owner.

    The admission lock makes the capacity change and notification atomic with
    queue changes. Both successful workers and failed submissions use this
    boundary, preserving the exact shared capacity accounting.

    Args:
        bulk: Whether this owner also holds one bulk-preparation allowance.
    """
    global _MANAGED_FILESYSTEM_BULK_ACTIVE
    with _MANAGED_FILESYSTEM_ADMISSION_LOCK:
        if bulk:
            _MANAGED_FILESYSTEM_BULK_ACTIVE -= 1
        _MANAGED_FILESYSTEM_CAPACITY.release()
        _notify_managed_filesystem_head()


async def _acquire_managed_filesystem_slot(*, bulk: bool = False) -> None:
    """
    Admit eligible owners in arrival order across threads and event loops.

    A short synchronous lock protects queue membership and nonblocking capacity
    acquisition only. Capacity release, admission and queued cancellation wake
    the next owner, so free slots do not wait for one timer tick per caller. The
    portable heartbeat remains a fallback. A full bulk allowance defers only
    bulk preparation, preserving capacity for small operations. New callers
    cannot overtake an eligible older owner; cancellation removes only the
    unadmitted token and consumes no slot or bulk allowance.

    Args:
        bulk: Whether this operation requires a bulk-preparation allowance.

    Raises:
        asyncio.CancelledError: If cancelled before admission, after removing
            the owner's token so following callers can continue.
    """

    global _MANAGED_FILESYSTEM_BULK_ACTIVE
    token = (asyncio.get_running_loop(), asyncio.Event(), bulk)
    context_token = _MANAGED_FILESYSTEM_ADMISSION_WAKEUP.set(token[1])
    with _MANAGED_FILESYSTEM_ADMISSION_LOCK:
        _MANAGED_FILESYSTEM_WAITERS.append(token)
    admitted = False
    try:
        while True:
            with _MANAGED_FILESYSTEM_ADMISSION_LOCK:
                is_first = _next_managed_filesystem_waiter() is token
                if is_first and _MANAGED_FILESYSTEM_CAPACITY.acquire(blocking=False):
                    _MANAGED_FILESYSTEM_WAITERS.remove(token)
                    if bulk:
                        _MANAGED_FILESYSTEM_BULK_ACTIVE += 1
                    _notify_managed_filesystem_head()
                    admitted = True
                    return
            await _filesystem_worker_heartbeat()
    finally:
        _MANAGED_FILESYSTEM_ADMISSION_WAKEUP.reset(context_token)
        if not admitted:
            with _MANAGED_FILESYSTEM_ADMISSION_LOCK:
                if token in _MANAGED_FILESYSTEM_WAITERS:
                    _MANAGED_FILESYSTEM_WAITERS.remove(token)
                _notify_managed_filesystem_head()


async def run_managed_filesystem_operation(
    operation: Callable[..., Any],
    *args: Any,
    cancellation_event: Optional[threading.Event] = None,
    bulk: bool = False,
) -> Any:
    """
    Run one blocking finite filesystem operation on the shared bounded pool.

    Admission is asynchronous and ordered among eligible owners across event
    loops. Explicit bulk work uses at most three workers, leaving capacity for
    small operations; the total pool remains bounded at four. The submitted
    future is always observed, and a cancelled admitted owner first signals an
    optional cooperative cancellation event and then joins the worker. This
    prevents archive work from blocking the event loop or becoming untracked
    fire-and-forget work during shutdown.

    Args:
        operation: Callable executed by the managed filesystem worker.
        args: Positional arguments forwarded in caller-provided order.
        cancellation_event: Optional cooperative event signalled when the
            asynchronous owner is cancelled.
        bulk: Limit this operation to the bulk-preparation allowance. The
            default retains ordinary filesystem admission and argument handling.

    Returns:
        The exact value returned by ``operation``.

    Raises:
        TypeError: If ``operation`` is not callable or ``bulk`` is not a bool.
        asyncio.CancelledError: If the asynchronous owner is cancelled after
            the submitted worker has been drained.
    """

    if not callable(operation):
        raise TypeError("managed filesystem operation must be callable")
    if type(bulk) is not bool:
        raise TypeError("managed filesystem bulk admission must be a bool")
    await _acquire_managed_filesystem_slot(bulk=bulk)

    def run_and_release() -> Any:
        """
        Execute the admitted operation and release its exact pool slot.

        The ``finally`` release keeps capacity accounting truthful when the
        delegated operation returns, raises, or receives cooperative shutdown.

        Returns:
            The exact value returned by the admitted operation.
        """

        try:
            return operation(*args)
        finally:
            _release_managed_filesystem_slot(bulk=bulk)

    try:
        future = _MANAGED_FILESYSTEM_EXECUTOR.submit(run_and_release)
    except BaseException:
        _release_managed_filesystem_slot(bulk=bulk)
        raise

    try:
        return await _await_managed_worker(future)
    except asyncio.CancelledError:
        if cancellation_event is not None:
            cancellation_event.set()
        await _drain_cancelled_worker(future)
        raise


__all__ = ["MANAGED_FILESYSTEM_WORKERS", "run_managed_filesystem_operation"]
