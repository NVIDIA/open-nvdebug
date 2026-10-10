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
Side-effect-free policy for Redfish task and diagnostic monitors.

The Redfish service owns transport, deadlines, logging, and evidence
persistence. This module owns only bounded monitor values and the deterministic
decisions made from one response.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, Union
from urllib.parse import urlsplit

_TASK_STATE_CANONICAL = {
    state.casefold(): state
    for state in (
        "New",
        "Starting",
        "Running",
        "Suspended",
        "Interrupted",
        "Pending",
        "Stopping",
        "Completed",
        "Completed with Warnings",
        "CompletedWithWarnings",
        "Succeeded",
        "Done",
        "Failed",
        "Exception",
        "Cancelled",
        "Canceled",
        "Aborted",
        "Killed",
        "Killing",
        "Cancelling",
        "Service",
        "TaskResourceMissing",
        "HttpFailure",
        "PollFailed",
        "MonitoringException",
        "Timeout",
        "Inaccessible",
    )
}
_TASK_STATUS_CANONICAL = {
    status.casefold(): status
    for status in (
        "OK",
        "Warning",
        "Critical",
        "Error",
        "Unknown",
    )
}
_SUCCESS_STATES = frozenset(
    {
        "Completed",
        "Succeeded",
        "Done",
        "Completed with Warnings",
        "CompletedWithWarnings",
    }
)
_FAILURE_STATES = frozenset(
    {"Failed", "Cancelled", "Canceled", "Killed", "Exception", "Aborted"}
)
_TASK_MONITOR_PATH = re.compile(
    r"/TaskService/TaskMonitors(?:/|$)", flags=re.IGNORECASE
)
_TASK_RESOURCE_PATH = re.compile(
    r"/TaskService/(?:Tasks|TaskMonitors)(?:/|$)", flags=re.IGNORECASE
)


class TaskPollDisposition(str, Enum):
    """
    Collector-visible meaning of one successful task poll response.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    MALFORMED = "malformed"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class TaskPollFailureKind(str, Enum):
    """
    Failure retained after a transport poll attempt.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    TASK_RESOURCE_MISSING = "task_resource_missing"
    HTTP_FAILURE = "http_failure"


@dataclass(frozen=True)
class TaskPollDecision:
    """
    Bounded task values and policy result for one response.

    The immutable record keeps ``disposition``, ``task_state``, ``task_status``,
    ``percent_complete``, and ``should_log_progress`` together so consumers
    observe one task poll decision state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        disposition: Disposition retained as part of the record's public state.
        task_state: Canonical text used as task state.
        task_status: Canonical text used as task status.
        percent_complete: Numeric percent complete retained by this record.
        should_log_progress: Whether log progress applies to this record.
    """

    disposition: TaskPollDisposition
    task_state: Optional[str]
    task_status: Optional[str]
    percent_complete: Optional[Union[int, float]]
    should_log_progress: bool


@dataclass(frozen=True)
class TaskMonitorNormalization:
    """
    A pure response projection for the compatibility facade to apply.

    The immutable record keeps ``response`` and ``applied`` together so
    consumers observe one task monitor normalization state. Consumers receive
    the fields as one unit instead of assembling partial state.

    Attributes:
        response: Response retained as part of the record's public state.
        applied: Whether applied applies to this record.
    """

    response: Any
    applied: bool


@dataclass(frozen=True)
class TaskMonitorExhaustionDecision:
    """
    Collector failure state selected after the polling budget is exhausted.

    The immutable record keeps ``task_state``, ``task_status``, ``message``, and
    ``log_as_timeout`` together so consumers observe one task monitor exhaustion
    decision state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        task_state: Canonical text used as task state.
        task_status: Canonical text used as task status.
        message: Canonical text used as message.
        log_as_timeout: Whether log as timeout applies to this record.
    """

    task_state: str
    task_status: str
    message: str
    log_as_timeout: bool = False


def bounded_task_state(value: Any) -> Optional[str]:
    """
    Return only a recognized fixed-width Redfish task state.

    After applying local validation, the function forwards ``value`` to
    ``_TASK_STATE_CANONICAL.get`` and preserves its return and exception
    contract.

    Args:
        value: Value object whose ``strip`` state is read while performing only
            a recognized fixed-width Redfish task state.

    Returns:
        The canonical bounded task state text, or ``None`` when the requested
        value is unavailable.
    """
    if type(value) is not str or len(value) > 64:
        return None
    return _TASK_STATE_CANONICAL.get(value.strip().casefold())


def bounded_task_status(value: Any) -> Optional[str]:
    """
    Return only a recognized fixed-width Redfish task health value.

    After applying local validation, the function forwards ``value`` to
    ``_TASK_STATUS_CANONICAL.get`` and preserves its return and exception
    contract.

    Args:
        value: Value object whose ``strip`` state is read while performing only
            a recognized fixed-width Redfish task health value.

    Returns:
        The canonical bounded task status, or ``None`` when the requested value
        is unavailable.
    """
    if type(value) is not str or len(value) > 32:
        return None
    return _TASK_STATUS_CANONICAL.get(value.strip().casefold())


def bounded_task_percent_complete(value: Any) -> Optional[Union[int, float]]:
    """
    Return a scalar percentage without converting an attacker-sized value.

    The implementation uses ``value`` to produce a scalar percentage without
    converting an attacker-sized value.

    Args:
        value: Value object whose ``strip`` state is read while performing
            scalar percentage without converting an attacker-sized value.

    Returns:
        The numeric bounded task percent complete value, or ``None`` when the
        requested value is unavailable.
    """
    if type(value) is int:
        return value if 0 <= value <= 100 else None
    if type(value) is float:
        return value if math.isfinite(value) and 0 <= value <= 100 else None
    if type(value) is not str or len(value) > 16:
        return None
    candidate = value.strip()
    if not re.fullmatch(r"(?:100(?:\.0+)?|\d{1,2}(?:\.\d+)?)", candidate):
        return None
    parsed = float(candidate)
    return int(parsed) if parsed.is_integer() else parsed


def parse_retry_after_seconds(value: Any) -> Optional[float]:
    """
    Parse a bounded delta-seconds Retry-After value.

    The implementation uses ``value`` to parse a bounded delta-seconds
    Retry-After value. Parsing or I/O must finish before the validated
    representation is made available to the caller.

    Args:
        value: Value object whose ``strip`` state is read while performing
            bounded delta-seconds Retry-After value.

    Returns:
        The validated ``delay``, or ``None`` when no value qualifies.
    """
    if value is None or type(value) is bool:
        return None
    if type(value) is str:
        if len(value) > 64:
            return None
        raw_value: Any = value.strip()
    elif type(value) in {int, float}:
        if type(value) is int and int.bit_length(value) > 256:
            return None
        raw_value = value
    else:
        return None
    try:
        delay = float(raw_value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(delay) or delay < 0:
        return None
    return delay


def is_task_monitor_uri(uri: Any, *, max_text_chars: int = 2048) -> bool:
    """
    Return whether a bounded URI identifies a Redfish TaskMonitor resource.

    The implementation uses ``uri`` and ``max_text_chars`` to determine whether
    a bounded URI identifies a Redfish TaskMonitor resource.

    Args:
        uri: Validated remote resource identifier used for URI.
        max_text_chars: Upper bound enforced for max text chars; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        Whether a bounded URI identifies a Redfish TaskMonitor resource.
    """
    if type(uri) is not str or len(uri) > max_text_chars or not uri.strip():
        return False
    try:
        path = urlsplit(uri).path
    except ValueError:
        path = uri
    return bool(_TASK_MONITOR_PATH.search(path))


def normalize_task_monitor_response(
    response: Any,
    *,
    http_status: Optional[int],
    monitor_uri: Any,
    location: Any,
    max_text_chars: int,
    max_headers: int,
) -> TaskMonitorNormalization:
    """
    Return a task-shaped copy for a recognized TaskMonitor HTTP response.

    The implementation uses ``response``, ``http_status``, ``monitor_uri``,
    ``location``, and ``max_text_chars`` to produce a task-shaped copy for a
    recognized TaskMonitor HTTP response. Remote I/O uses the configured
    transport policy and returns only after its response or failure has been
    observed.

    Args:
        response: Transport response governed by the configured authentication
            and trust policy.
        http_status: Numeric HTTP status used while the operation performs
            bounded accounting.
        monitor_uri: Validated remote resource identifier used for monitor URI.
        location: Location consumed while the function attempts to produce a
            task-shaped copy for a recognized TaskMonitor HTTP response.
        max_text_chars: Upper bound enforced for max text chars; the consuming
            boundary rejects or truncates values that exceed it.
        max_headers: Upper bound enforced for max headers; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        A ``TaskMonitorNormalization`` representing task monitor response.
    """
    if not is_task_monitor_uri(monitor_uri, max_text_chars=max_text_chars):
        return TaskMonitorNormalization(response=response, applied=False)
    if type(response) is dict and dict.get(response, "TaskState"):
        return TaskMonitorNormalization(response=response, applied=False)

    if http_status == 202:
        normalized = dict.copy(response) if type(response) is dict else {}
        normalized["TaskState"] = "Running"
        normalized.setdefault("PercentComplete", "")
        return TaskMonitorNormalization(response=normalized, applied=True)
    if http_status is None or not 200 <= http_status < 300:
        return TaskMonitorNormalization(response=response, applied=False)

    normalized = dict.copy(response) if type(response) is dict else {}
    normalized["TaskState"] = "Completed"
    normalized.setdefault("TaskStatus", "OK")
    normalized.setdefault("PercentComplete", 100)

    safe_location = location
    if not _is_bounded_text(safe_location, max_text_chars):
        body_uri = dict.get(normalized, "@odata.id")
        if type(body_uri) is str and _is_bounded_text(body_uri, max_text_chars):
            try:
                body_path = urlsplit(body_uri).path
            except ValueError:
                body_path = body_uri
            if not _TASK_RESOURCE_PATH.search(body_path):
                safe_location = body_uri

    if _is_bounded_text(safe_location, max_text_chars):
        payload = dict.get(normalized, "Payload")
        raw_headers = (
            dict.get(payload, "HttpHeaders") if type(payload) is dict else None
        )
        headers = []
        if type(raw_headers) is list:
            for index, header in enumerate(list.__iter__(raw_headers)):
                if index >= max_headers:
                    break
                if type(header) is str and len(header) <= max_text_chars:
                    headers.append(header)
        if not any(
            header.partition(":")[0].strip().casefold() == "location"
            for header in headers
        ):
            headers.append(f"Location: {safe_location.strip()}")
        normalized["Payload"] = {"HttpHeaders": headers}

    return TaskMonitorNormalization(response=normalized, applied=True)


def should_try_next_monitor_candidate(
    response: Any,
    *,
    http_status: Optional[int],
    monitor_uri: Any,
    has_fallback: bool,
    require_result_location: bool = False,
    location: Any = None,
    max_text_chars: int = 2048,
    max_items: int = 64,
) -> bool:
    """
    Return whether an ambiguous successful response needs the next candidate.

    The implementation uses ``response``, ``http_status``, ``monitor_uri``,
    ``has_fallback``, and ``require_result_location`` to determine whether an
    ambiguous successful response needs the next candidate. Remote I/O uses the
    configured transport policy and returns only after its response or failure
    has been observed.

    Args:
        response: Transport response governed by the configured authentication
            and trust policy.
        http_status: Numeric HTTP status used while the operation performs
            bounded accounting.
        monitor_uri: Validated remote resource identifier used for monitor URI.
        has_fallback: Whether has fallback is enabled or required for this
            operation.
        require_result_location: Whether require result location is enabled or
            required for this operation.
        location: Optional location; ``None`` selects the function's default
            behavior.
        max_text_chars: Upper bound enforced for max text chars; the consuming
            boundary rejects or truncates values that exceed it.
        max_items: Upper bound enforced for max items; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        Whether an ambiguous successful response needs the next candidate.
    """
    if not has_fallback:
        return False

    task_state = (
        bounded_task_state(dict.get(response, "TaskState"))
        if type(response) is dict
        else None
    )
    if task_state is not None and task_state not in _SUCCESS_STATES:
        return False

    is_monitor = is_task_monitor_uri(
        monitor_uri,
        max_text_chars=max_text_chars,
    )
    if (
        require_result_location
        and is_monitor
        and http_status is not None
        and http_status != 202
        and 200 <= http_status < 300
    ):
        return not _has_task_result_location(
            response,
            location=location,
            max_text_chars=max_text_chars,
            max_items=max_items,
        )

    if task_state is not None:
        return False
    return not (
        is_monitor
        and http_status is not None
        and (http_status == 202 or 200 <= http_status < 300)
    )


def evaluate_task_poll(
    response: Any,
    *,
    attempt_index: int,
    previous_state: Optional[str],
    previous_percent: Optional[Union[int, float]],
) -> TaskPollDecision:
    """
    Classify one task response without logging, sleeping, or issuing I/O.

    The implementation uses ``response``, ``attempt_index``, ``previous_state``,
    and ``previous_percent`` to classify one task response without logging,
    sleeping, or issuing I/O. Remote I/O uses the configured transport policy
    and returns only after its response or failure has been observed.

    Args:
        response: Transport response governed by the configured authentication
            and trust policy.
        attempt_index: Numeric attempt index used by the operation's bounded
            accounting.
        previous_state: Text supplied as previous state in the format accepted
            by this function.
        previous_percent: Numeric previous percent used while the operation
            performs bounded accounting.

    Returns:
        A ``TaskPollDecision`` representing evaluate task poll.
    """
    task_state = (
        bounded_task_state(dict.get(response, "TaskState"))
        if type(response) is dict
        else None
    )
    task_status = (
        bounded_task_status(dict.get(response, "TaskStatus"))
        if type(response) is dict
        else None
    )
    percent_complete = (
        bounded_task_percent_complete(dict.get(response, "PercentComplete"))
        if type(response) is dict
        else None
    )

    if task_state is None:
        return TaskPollDecision(
            disposition=TaskPollDisposition.MALFORMED,
            task_state=None,
            task_status=task_status,
            percent_complete=percent_complete,
            should_log_progress=False,
        )
    if task_state in _SUCCESS_STATES:
        disposition = TaskPollDisposition.SUCCEEDED
    elif task_state in _FAILURE_STATES:
        disposition = TaskPollDisposition.FAILED
    else:
        disposition = TaskPollDisposition.RUNNING

    should_log_progress = (
        task_state != previous_state
        or percent_complete != previous_percent
        or (attempt_index + 1) % 5 == 0
        or attempt_index == 0
    )
    return TaskPollDecision(
        disposition=disposition,
        task_state=task_state,
        task_status=task_status,
        percent_complete=percent_complete,
        should_log_progress=should_log_progress,
    )


def is_task_monitor_authorization_failure(
    response: Any,
    *,
    http_status: Optional[int],
    max_text_chars: int,
) -> bool:
    """
    Return whether a failed poll is an explicit authorization failure.

    The implementation uses ``response``, ``http_status``, and
    ``max_text_chars`` to determine whether a failed poll is an explicit
    authorization failure.

    Args:
        response: Transport response governed by the configured authentication
            and trust policy.
        http_status: Numeric HTTP status used while the operation performs
            bounded accounting.
        max_text_chars: Upper bound enforced for max text chars; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        Whether a failed poll is an explicit authorization failure.
    """
    if http_status in {401, 403}:
        return True
    bounded_prefix = (
        response[:max_text_chars].casefold() if type(response) is str else ""
    )
    return any(marker in bounded_prefix for marker in ("unauthorized", "forbidden"))


def classify_task_monitor_exhaustion(
    poll_kind: Optional[TaskPollFailureKind],
    *,
    http_status: Optional[int],
    max_retries: int,
    total_timeout: float,
) -> TaskMonitorExhaustionDecision:
    """
    Select the failure record emitted after the polling budget ends.

    The implementation uses ``poll_kind``, ``http_status``, ``max_retries``, and
    ``total_timeout`` to select the failure record emitted after the polling
    budget ends.

    Args:
        poll_kind: Poll kind consumed while the function attempts to select the
            failure record emitted after the polling budget ends.
        http_status: Numeric HTTP status used while the operation performs
            bounded accounting.
        max_retries: Upper bound enforced for max retries; the consuming
            boundary rejects or truncates values that exceed it.
        total_timeout: Maximum duration in seconds allowed for total timeout.

    Returns:
        A ``TaskMonitorExhaustionDecision`` representing classify task monitor
        exhaustion.
    """
    if poll_kind is TaskPollFailureKind.TASK_RESOURCE_MISSING:
        return TaskMonitorExhaustionDecision(
            task_state="TaskResourceMissing",
            task_status="Error",
            message=(
                "Accepted task resources were missing after "
                f"{max_retries} polls within the original deadline"
            ),
        )
    if poll_kind is TaskPollFailureKind.HTTP_FAILURE:
        if http_status is not None:
            task_state = "HttpFailure"
            message = f"Task monitor HTTP {http_status} failure"
        else:
            task_state = "PollFailed"
            message = "Task monitor polling failed"
        return TaskMonitorExhaustionDecision(
            task_state=task_state,
            task_status="Error",
            message=message,
        )
    return TaskMonitorExhaustionDecision(
        task_state="Timeout",
        task_status="Warning",
        message=(f"Task did not complete after {max_retries} polls ({total_timeout}s)"),
        log_as_timeout=True,
    )


def _is_bounded_text(value: Any, max_text_chars: int) -> bool:
    """
    Return whether ``value`` is bounded text.

    The implementation uses ``value`` and ``max_text_chars`` to determine
    whether ``value`` is bounded text.

    Args:
        value: Value object whose ``strip`` state is read while performing
            ``value`` is bounded text.
        max_text_chars: Upper bound enforced for max text chars; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        Whether ``value`` is bounded text.
    """
    return type(value) is str and len(value) <= max_text_chars and bool(value.strip())


def _is_result_location(value: Any, max_text_chars: int) -> bool:
    """
    Return whether a bounded URI identifies an operation result, not a task.

    The implementation uses ``value`` and ``max_text_chars`` to determine
    whether a bounded URI identifies an operation result, not a task.

    Args:
        value: Value evaluated while performing bounded URI identifies an
            operation result, not a task.
        max_text_chars: Upper bound enforced for max text chars; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        Whether a bounded URI identifies an operation result, not a task.
    """
    if not _is_bounded_text(value, max_text_chars):
        return False
    try:
        path = urlsplit(value).path
    except ValueError:
        path = value
    return not _TASK_RESOURCE_PATH.search(path)


def _has_task_result_location(
    response: Any,
    *,
    location: Any,
    max_text_chars: int,
    max_items: int,
) -> bool:
    """
    Recognize the bounded result-location forms consumed by dump resolution.

    The implementation uses ``response``, ``location``, ``max_text_chars``, and
    ``max_items`` to recognize the bounded result-location forms consumed by
    dump resolution. Remote I/O uses the configured transport policy and returns
    only after its response or failure has been observed.

    Args:
        response: Transport response governed by the configured authentication
            and trust policy.
        location: Location consumed while the function attempts to recognize the
            bounded result-location forms consumed by dump resolution.
        max_text_chars: Upper bound enforced for max text chars; the consuming
            boundary rejects or truncates values that exceed it.
        max_items: Upper bound enforced for max items; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        Whether the recognize the bounded result-location forms consumed by dump
        resolution operation succeeds.
    """
    if _is_result_location(location, max_text_chars):
        return True
    if type(response) is not dict:
        return False

    for key in ("Location", "@odata.id"):
        if _is_result_location(dict.get(response, key), max_text_chars):
            return True

    payload = dict.get(response, "Payload")
    raw_headers = dict.get(payload, "HttpHeaders") if type(payload) is dict else None
    if type(raw_headers) is list:
        for index, header in enumerate(list.__iter__(raw_headers)):
            if index >= max_items:
                break
            if type(header) is not str or len(header) > max_text_chars:
                continue
            name, separator, value = header.partition(":")
            if (
                separator
                and name.strip().casefold() == "location"
                and _is_result_location(value.strip(), max_text_chars)
            ):
                return True

    messages = dict.get(response, "Messages")
    if type(messages) is list:
        for index, message in enumerate(list.__iter__(messages)):
            if index >= max_items:
                break
            if type(message) is not dict:
                continue
            arguments = dict.get(message, "MessageArgs")
            if type(arguments) not in {list, tuple} or not arguments:
                continue
            candidate = arguments[0]
            if _is_result_location(candidate, max_text_chars) and candidate.startswith(
                "/redfish/"
            ):
                return True

    return False
