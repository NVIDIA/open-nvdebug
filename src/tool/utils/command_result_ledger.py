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
Task-local, credential-free command-result capture.

Collector commands can contain credentials, tokens, paths, and customer data.
Offline verification therefore receives only bounded execution metadata; the
command text and stdout/stderr bytes never enter this ledger.
"""

from __future__ import annotations

import asyncio
import contextvars
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator, Literal

CommandTransport = Literal["host_ssh", "bmc_ssh"]
CommandNonzeroDisposition = Literal[
    "expected_nonzero",
    "optional_failure",
    "probe_negative",
    "retry_recovered",
    "cleanup_failure",
]

COMMAND_RESULT_LEDGER_SCHEMA_VERSION = "1.1"
MAX_COMMAND_RESULT_ENTRIES = 4096
MAX_BYTE_COUNT = (1 << 63) - 1
MAX_DURATION_MS = (1 << 31) - 1
MAX_COMMAND_KIND_LENGTH = 80
MAX_OPERATION_ROLE_LENGTH = 80
_COMMAND_KIND_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_OPERATION_ROLE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_NONZERO_DISPOSITIONS = frozenset(
    {
        "expected_nonzero",
        "optional_failure",
        "probe_negative",
        "retry_recovered",
        "cleanup_failure",
    }
)
_ANY_NONZERO_DISPOSITIONS = frozenset(
    {"optional_failure", "retry_recovered", "cleanup_failure"}
)


@dataclass(frozen=True)
class CommandResultPolicy:
    """
    Non-secret semantics selected by the service before one command call.

    The immutable record keeps ``operation_role``, ``nonzero_disposition``,
    ``accepted_nonzero_exit_codes``, ``allow_any_nonzero``, and
    ``defer_nonzero_resolution`` together so consumers observe one command
    result policy state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        operation_role: Canonical text used as operation role.
        nonzero_disposition: Canonical text used as nonzero disposition.
        accepted_nonzero_exit_codes: Collection of accepted nonzero exit codes
            entries retained by this record.
        allow_any_nonzero: Whether any nonzero applies to this record.
        defer_nonzero_resolution: Whether defer nonzero resolution applies to
            this record.
    """

    operation_role: str = "required_command"
    nonzero_disposition: str | None = None
    accepted_nonzero_exit_codes: frozenset[int] = frozenset()
    allow_any_nonzero: bool = False
    defer_nonzero_resolution: bool = False


_default_command_result_policy = CommandResultPolicy()
_active_command_result_policy: contextvars.ContextVar[CommandResultPolicy] = (
    contextvars.ContextVar(
        "active_command_result_policy", default=_default_command_result_policy
    )
)


@contextmanager
def command_result_policy(
    *,
    operation_role: str,
    nonzero_disposition: CommandNonzeroDisposition | None = None,
    accepted_nonzero_exit_codes: Any = (),
    allow_any_nonzero: bool = False,
    defer_nonzero_resolution: bool = False,
) -> Iterator[None]:
    """
    Apply a bounded per-call exit policy without exposing command text.

    Exact-code policies are used for probes and documented expected exits.
    ``allow_any_nonzero`` is limited to product paths which explicitly tolerate
    arbitrary optional, retry, or cleanup failures.

    Args:
        operation_role: Text supplied as operation role in the format accepted
            by this function.
        nonzero_disposition: Optional nonzero disposition; ``None`` selects the
            function's default behavior.
        accepted_nonzero_exit_codes: Accepted nonzero exit codes consumed while
            the function attempts to apply a bounded per-call exit policy
            without exposing command text.
        allow_any_nonzero: Whether allow any nonzero is enabled or required for
            this operation.
        defer_nonzero_resolution: Whether defer nonzero resolution is enabled or
            required for this operation.

    Yields:
        Each command result policy admitted by the operation, in deterministic
        iteration order.

    Raises:
        ValueError: If invalid command-result operation role; invalid
            command-result nonzero disposition; invalid command-result exit
            policy; or invalid command-result boolean policy.
    """

    if (
        not isinstance(operation_role, str)
        or _OPERATION_ROLE_RE.fullmatch(operation_role) is None
    ):
        raise ValueError("invalid command-result operation role")
    if nonzero_disposition is not None and nonzero_disposition not in (
        _NONZERO_DISPOSITIONS
    ):
        raise ValueError("invalid command-result nonzero disposition")
    try:
        raw_codes = tuple(accepted_nonzero_exit_codes)
    except TypeError:
        raise ValueError("invalid command-result exit policy") from None
    if any(
        not isinstance(value, int)
        or isinstance(value, bool)
        or value == 0
        or not -(1 << 31) <= value < (1 << 31)
        for value in raw_codes
    ):
        raise ValueError("invalid command-result exit policy")
    normalized_codes = frozenset(raw_codes)
    if not isinstance(allow_any_nonzero, bool) or not isinstance(
        defer_nonzero_resolution, bool
    ):
        raise ValueError("invalid command-result boolean policy")
    if (
        ((normalized_codes or allow_any_nonzero) and nonzero_disposition is None)
        or (normalized_codes and allow_any_nonzero)
        or (allow_any_nonzero and nonzero_disposition not in _ANY_NONZERO_DISPOSITIONS)
        or (
            defer_nonzero_resolution
            and (
                nonzero_disposition != "expected_nonzero"
                or not normalized_codes
                or allow_any_nonzero
            )
        )
    ):
        raise ValueError("invalid command-result exit policy")
    policy = CommandResultPolicy(
        operation_role=operation_role,
        nonzero_disposition=nonzero_disposition,
        accepted_nonzero_exit_codes=normalized_codes,
        allow_any_nonzero=allow_any_nonzero,
        defer_nonzero_resolution=defer_nonzero_resolution,
    )
    token = _active_command_result_policy.set(policy)
    try:
        yield
    finally:
        _active_command_result_policy.reset(token)


def _bounded_nonnegative_integer(value: Any, maximum: int) -> int:
    """
    Return the bounded nonnegative integer.

    The implementation uses ``value`` and ``maximum`` to produce the bounded
    nonnegative integer.

    Args:
        value: Value evaluated while performing bounded nonnegative integer.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.

    Returns:
        The numeric bounded nonnegative integer value.
    """
    try:
        integer = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return min(max(integer, 0), maximum)


def _encoded_size(value: Any) -> int:
    """
    Return the encoded size.

    The implementation uses ``value`` to produce the encoded size.

    Args:
        value: Value evaluated while performing encoded size.

    Returns:
        The numeric encoded size.
    """
    try:
        if value is None:
            return 0
        if isinstance(value, bytes):
            return min(len(value), MAX_BYTE_COUNT)
        return min(len(str(value).encode("utf-8", errors="replace")), MAX_BYTE_COUNT)
    except Exception:
        return 0


def _safe_command_kind(value: Any) -> str:
    """
    Return a bounded identifier without ever deriving one from unsafe text.

    The implementation uses ``value`` to produce a bounded identifier without
    ever deriving one from unsafe text.

    Args:
        value: Value evaluated while performing bounded identifier without ever
            deriving one from unsafe text.

    Returns:
        The canonical safe command kind text.
    """

    if isinstance(value, str) and _COMMAND_KIND_RE.fullmatch(value) is not None:
        return value
    return "command"


@dataclass
class CommandResultCapture:
    """
    Mutable state owned by one collector task.

    The coherent record keeps ``dut_id``, ``collector_id``, ``transport``,
    ``commands``, and ``total_commands`` together so consumers observe one
    command result capture state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        dut_id: Canonical text used as DUT identifier.
        collector_id: Canonical text used as collector identifier.
        transport: Transport retained as part of the record's public state.
        commands: Mapping that retains the commands fields for this record.
        total_commands: Number of total commands represented by this record.
        dropped_commands: Number of dropped commands represented by this record.
        enabled: Whether enabled applies to this record.
    """

    dut_id: str
    collector_id: str
    transport: CommandTransport
    commands: list[dict[str, Any]] = field(default_factory=list)
    total_commands: int = 0
    dropped_commands: int = 0
    enabled: bool = True

    def add(
        self,
        *,
        transport: CommandTransport,
        dut_id: str,
        exit_code: Any,
        stdout: Any,
        stderr: Any,
        duration_seconds: Any,
        target: str,
        command_kind: str,
        raised: bool = False,
        policy: CommandResultPolicy | None = None,
    ) -> None:
        """
        Record one result when it belongs to this collector capture.

        The implementation uses ``transport``, ``dut_id``, ``exit_code``,
        ``stdout``, and ``stderr`` to record one result when it belongs to this
        collector capture. It updates ``dropped_commands`` and
        ``total_commands`` on the instance as part of that state transition.

        Args:
            transport: Transport object whose ``split`` state is read while
                performing record one result when it belongs to this collector
                capture.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            exit_code: Exit code consumed while the function attempts to record
                one result when it belongs to this collector capture.
            stdout: Stdout consumed while the function attempts to record one
                result when it belongs to this collector capture.
            stderr: Stderr consumed while the function attempts to record one
                result when it belongs to this collector capture.
            duration_seconds: Maximum duration in seconds allowed for duration
                seconds.
            target: Text supplied as target in the format accepted by this
                function.
            command_kind: Text supplied as command kind in the format accepted
                by this function.
            raised: Whether raised is enabled or required for this operation.
            policy: Optional Policy governing record one result when it belongs
                to this collector capture.
        """

        if not self.enabled or transport != self.transport or dut_id != self.dut_id:
            return

        self.total_commands += 1
        if len(self.commands) >= MAX_COMMAND_RESULT_ENTRIES:
            self.dropped_commands += 1
            return

        exit_code_valid = (
            isinstance(exit_code, int)
            and not isinstance(exit_code, bool)
            and -(1 << 31) <= exit_code < (1 << 31)
        )
        normalized_exit_code = exit_code if exit_code_valid else -1
        duration_ms = _bounded_nonnegative_integer(
            float(duration_seconds) * 1000 if duration_seconds is not None else 0,
            MAX_DURATION_MS,
        )
        sequence = self.total_commands
        active_policy = policy or _default_command_result_policy
        if raised:
            semantic_disposition = "raised"
        elif not exit_code_valid:
            semantic_disposition = "required_failure"
        elif normalized_exit_code == 0:
            semantic_disposition = "success"
        elif active_policy.defer_nonzero_resolution:
            # Output-aware expected-nonzero policies start as failures.  The
            # service may promote this one result only after its in-memory
            # output predicate succeeds; raw output never enters the ledger.
            semantic_disposition = "required_failure"
        elif active_policy.nonzero_disposition is not None and (
            active_policy.allow_any_nonzero
            or normalized_exit_code in active_policy.accepted_nonzero_exit_codes
        ):
            semantic_disposition = active_policy.nonzero_disposition
        else:
            semantic_disposition = "required_failure"
        self.commands.append(
            {
                "command_id": f"{transport}:{sequence:06d}",
                "command_name": _safe_command_kind(command_kind),
                "transport": transport,
                "target": "hmc" if target == "hmc" else transport.split("_", 1)[0],
                "operation_role": active_policy.operation_role,
                "semantic_disposition": semantic_disposition,
                "exit_code": normalized_exit_code,
                "duration_ms": duration_ms,
                "stdout_bytes": _encoded_size(stdout),
                "stderr_bytes": _encoded_size(stderr),
                "raised": bool(raised),
            }
        )

    def as_document(self) -> dict[str, Any]:
        """
        Return the strict on-disk document without command or output data.

        The implementation uses current instance state to produce the strict
        on-disk document without command or output data.

        Returns:
            A mapping containing the ``schema_version``, ``collector_id``,
            ``transport``, ``complete``, and ``summary`` fields.
        """

        exit_code_counts: dict[str, int] = {}
        for command in self.commands:
            key = str(command["exit_code"])
            exit_code_counts[key] = exit_code_counts.get(key, 0) + 1
        return {
            "schema_version": COMMAND_RESULT_LEDGER_SCHEMA_VERSION,
            "collector_id": self.collector_id,
            "transport": self.transport,
            "complete": self.dropped_commands == 0,
            "summary": {
                "total_commands": self.total_commands,
                "recorded_commands": len(self.commands),
                "dropped_commands": self.dropped_commands,
                "exit_code_counts": exit_code_counts,
            },
            "commands": list(self.commands),
        }


@dataclass(frozen=True)
class DeferredCommandResultResolution:
    """
    Ephemeral identity for exactly one task-local command result.

    The immutable record keeps ``capture``, ``transport``, ``dut_id``,
    ``operation_role``, and ``expected_sequence`` together so consumers observe
    one deferred command result resolution state. Consumers receive the fields
    as one unit instead of assembling partial state.

    Attributes:
        capture: Capture retained as part of the record's public state.
        transport: Transport retained as part of the record's public state.
        dut_id: Canonical text used as DUT identifier.
        operation_role: Canonical text used as operation role.
        expected_sequence: Numeric expected sequence retained by this record.
    """

    capture: CommandResultCapture = field(repr=False)
    transport: CommandTransport
    dut_id: str
    operation_role: str
    expected_sequence: int


@dataclass(frozen=True)
class _CommandResultCaptureBinding:
    """
    Immutable context binding whose mutable capture belongs to one task.

    The immutable record keeps ``capture`` and ``owner_task`` together so
    consumers observe one command result capture binding state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        capture: Capture retained as part of the record's public state.
        owner_task: Owner task retained as part of the record's public state.
    """

    capture: CommandResultCapture = field(repr=False)
    owner_task: asyncio.Task[Any] | None = field(repr=False)


def _current_asyncio_task() -> asyncio.Task[Any] | None:
    """
    Return the current task, including safe use from synchronous callers.

    After applying local validation, the function forwards current instance
    state to ``asyncio.current_task`` and preserves its return and exception
    contract.

    Returns:
        The current task, including safe use from synchronous callers, or
        ``None`` when the requested value is unavailable.
    """

    try:
        return asyncio.current_task()
    except RuntimeError:
        return None


_active_command_result_capture: contextvars.ContextVar[
    _CommandResultCaptureBinding | None
] = contextvars.ContextVar("active_command_result_capture", default=None)


def begin_command_result_capture(
    dut_id: str, collector_id: str, transport: CommandTransport
) -> tuple[
    CommandResultCapture,
    contextvars.Token[_CommandResultCaptureBinding | None],
]:
    """
    Start an isolated capture and return its reset token.

    The implementation uses ``dut_id``, ``collector_id``, and ``transport`` to
    start an isolated capture and return its reset token.

    Args:
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        transport: Transport consumed while the function attempts to start an
            isolated capture and return its reset token.

    Returns:
        A tuple containing ``capture`` and ``set`` in that order.
    """

    capture = CommandResultCapture(
        dut_id=str(dut_id), collector_id=str(collector_id), transport=transport
    )
    binding = _CommandResultCaptureBinding(
        capture=capture,
        owner_task=_current_asyncio_task(),
    )
    return capture, _active_command_result_capture.set(binding)


def end_command_result_capture(
    token: contextvars.Token[_CommandResultCaptureBinding | None],
) -> None:
    """
    Restore the prior task-local capture.

    The implementation uses ``token`` to restore the prior task-local capture.

    Args:
        token: Sensitive value supplied through the approved input boundary and
            never logged.
    """

    _active_command_result_capture.reset(token)


def get_command_result_capture() -> CommandResultCapture | None:
    """
    Return the capture visible to the current asyncio task.

    The implementation uses current instance state to produce the capture
    visible to the current asyncio task.

    Returns:
        A ``CommandResultCapture`` representing command result capture, or
        ``None`` when the requested value is unavailable.
    """

    binding = _active_command_result_capture.get()
    if binding is None or binding.owner_task is not _current_asyncio_task():
        return None
    return binding.capture


def command_result_started_at() -> float:
    """
    Return a monotonic timestamp for a command wrapper.

    After applying local validation, the function forwards current instance
    state to ``time.monotonic`` and preserves its return and exception contract.

    Returns:
        The numeric command result started at value.
    """

    return time.monotonic()


def record_command_result(
    *,
    transport: CommandTransport,
    dut_id: str,
    exit_code: Any,
    stdout: Any = "",
    stderr: Any = "",
    started_at: float | None = None,
    duration_seconds: float | None = None,
    target: str = "",
    command_kind: str = "command",
    raised: bool = False,
) -> None:
    """
    Append a bounded result to the active matching collector capture.

    The implementation uses ``transport``, ``dut_id``, ``exit_code``,
    ``stdout``, and ``stderr`` to append a bounded result to the active matching
    collector capture.

    Args:
        transport: Transport consumed while the function attempts to append a
            bounded result to the active matching collector capture.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        exit_code: Exit code consumed while the function attempts to append a
            bounded result to the active matching collector capture.
        stdout: Stdout consumed while the function attempts to append a bounded
            result to the active matching collector capture.
        stderr: Stderr consumed while the function attempts to append a bounded
            result to the active matching collector capture.
        started_at: Optional started at; ``None`` selects the function's default
            behavior.
        duration_seconds: Maximum duration in seconds allowed for duration
            seconds.
        target: Text supplied as target in the format accepted by this function.
        command_kind: Text supplied as command kind in the format accepted by
            this function.
        raised: Whether raised is enabled or required for this operation.
    """

    capture = get_command_result_capture()
    if capture is None:
        return
    if duration_seconds is not None:
        duration = max(float(duration_seconds), 0.0)
    else:
        duration = max(time.monotonic() - started_at, 0.0) if started_at else 0.0
    capture.add(
        transport=transport,
        dut_id=str(dut_id),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=duration,
        target=target,
        command_kind=command_kind,
        raised=raised,
        policy=_active_command_result_policy.get(),
    )


def begin_deferred_expected_nonzero_resolution(
    *,
    transport: CommandTransport,
    dut_id: str,
    operation_role: str,
) -> DeferredCommandResultResolution | None:
    """
    Bind a future resolution to the next result in the active capture.

    After applying local validation, the function forwards ``transport``,
    ``dut_id``, and ``operation_role`` to ``DeferredCommandResultResolution``
    and preserves its return and exception contract.

    Args:
        transport: Transport consumed while the function attempts to bind a
            future resolution to the next result in the active capture.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        operation_role: Text supplied as operation role in the format accepted
            by this function.

    Returns:
        A ``DeferredCommandResultResolution`` representing begin deferred
        expected nonzero resolution, or ``None`` when the requested value is
        unavailable.
    """

    capture = get_command_result_capture()
    policy = _active_command_result_policy.get()
    if (
        capture is None
        or not capture.enabled
        or capture.transport != transport
        or capture.dut_id != str(dut_id)
        or policy.operation_role != operation_role
        or not policy.defer_nonzero_resolution
        or policy.nonzero_disposition != "expected_nonzero"
        or policy.allow_any_nonzero
    ):
        return None
    return DeferredCommandResultResolution(
        capture=capture,
        transport=transport,
        dut_id=str(dut_id),
        operation_role=operation_role,
        expected_sequence=capture.total_commands + 1,
    )


def resolve_deferred_expected_nonzero_result(
    *,
    resolution: DeferredCommandResultResolution | None,
    transport: CommandTransport,
    dut_id: str,
    operation_role: str,
    exit_code: Any,
) -> bool:
    """
    Promote the immediately preceding output-validated non-zero result.

    The caller must remain inside the same task-local policy context used for
    execution. Every identity, role, sequence, and exit-code check is exact; on
    any mismatch the entry remains ``required_failure``. No command text or
    output bytes are accepted by this API.

    Args:
        resolution: Optional resolution; ``None`` selects the function's default
            behavior.
        transport: Transport consumed while the function attempts to promote the
            immediately preceding output-validated non-zero result.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        operation_role: Text supplied as operation role in the format accepted
            by this function.
        exit_code: Exit code consumed while the function attempts to promote the
            immediately preceding output-validated non-zero result.

    Returns:
        Whether the promote the immediately preceding output-validated non-zero
        result operation succeeds.
    """

    capture = get_command_result_capture()
    policy = _active_command_result_policy.get()
    if (
        resolution is None
        or capture is None
        or resolution.capture is not capture
        or resolution.transport != transport
        or resolution.dut_id != str(dut_id)
        or resolution.operation_role != operation_role
        or not capture.enabled
        or capture.transport != transport
        or capture.dut_id != str(dut_id)
        or policy.operation_role != operation_role
        or not policy.defer_nonzero_resolution
        or policy.nonzero_disposition != "expected_nonzero"
        or policy.allow_any_nonzero
    ):
        return False
    if (
        not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
        or exit_code == 0
        or exit_code not in policy.accepted_nonzero_exit_codes
        or not capture.commands
        or capture.dropped_commands
        or capture.total_commands != resolution.expected_sequence
    ):
        return False

    command = capture.commands[-1]
    expected_command_id = f"{transport}:{resolution.expected_sequence:06d}"
    if (
        command.get("command_id") != expected_command_id
        or command.get("transport") != transport
        or command.get("operation_role") != operation_role
        or command.get("exit_code") != exit_code
        or command.get("semantic_disposition") != "required_failure"
        or command.get("raised") is not False
    ):
        return False

    command["semantic_disposition"] = "expected_nonzero"
    return True


__all__ = [
    "COMMAND_RESULT_LEDGER_SCHEMA_VERSION",
    "CommandNonzeroDisposition",
    "CommandResultCapture",
    "CommandResultPolicy",
    "CommandTransport",
    "DeferredCommandResultResolution",
    "begin_command_result_capture",
    "begin_deferred_expected_nonzero_resolution",
    "command_result_policy",
    "command_result_started_at",
    "end_command_result_capture",
    "get_command_result_capture",
    "record_command_result",
    "resolve_deferred_expected_nonzero_result",
]
