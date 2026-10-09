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
Validated execution bindings and bounded evidence for collector fallbacks.

This module owns the collector attempt policy boundary and exposes
``CollectorAttemptPolicyError``, ``EnforcedCollectorAttemptPolicy``,
``CollectorAttemptPolicyRun``, ``_mode_name``, and ``_positive_timeout``.
Keeping those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Mapping, Optional, Sequence

from .collector_budget import MAX_MANAGED_ARTIFACT_BYTES
from .managed_host_command import (
    MANAGED_CLEANUP_VERIFICATION_GRACE_SECONDS,
    MANAGED_IDENTITY_READINESS_GRACE_SECONDS,
)

ATTEMPT_POLICY_SCHEMA_VERSION = "1.0"
MAX_ATTEMPT_MODES = 8
MAX_MANAGED_METADATA_COMMANDS = 8
MAX_MODE_NAME_CHARS = 64
MAX_MANAGED_COMMAND_BYTES = 8192
MAX_MANAGED_STAGE_SECONDS = 86_400
MAX_MANAGED_CANCELLATION_GRACE_SECONDS = 60
MIN_MANAGED_CLEANUP_SECONDS = (
    MANAGED_IDENTITY_READINESS_GRACE_SECONDS
    + 10
    + 5
    + MANAGED_CLEANUP_VERIFICATION_GRACE_SECONDS
)
MANAGED_INSPECTION_SECONDS = 30
MANAGED_WRAPPER_GRACE_SECONDS = 25

_MODE_NAME = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")
_CONFIG_KEY = re.compile(r"\A[A-Z][A-Z0-9_]{0,127}\Z")
_REMOTE_BASENAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_FILE_EXTENSION = re.compile(r"\A(?:\.[A-Za-z0-9][A-Za-z0-9._-]{0,15})?\Z")
_FALLBACK_FAILURES = frozenset(
    {"timeout", "nonzero_exit", "missing_artifact", "invalid_artifact"}
)
_FAILURE_CATEGORIES = _FALLBACK_FAILURES | frozenset(
    {
        "transport_error",
        "cleanup_unverified",
        "artifact_cleanup_unverified",
        "cancelled",
    }
)
_DISPOSITIONS = frozenset({"success", "failed", "not_attempted", "cancelled"})
_COMMAND_STATUSES = frozenset(
    {
        "success",
        "timeout",
        "nonzero_exit",
        "transport_error",
        "cleanup_unverified",
        "cancelled",
        "not_attempted",
    }
)
_ARTIFACT_STATUSES = frozenset(
    {"valid", "missing", "invalid", "not_checked", "not_applicable"}
)
_CLEANUP_STATUSES = frozenset(
    {"verified_absent", "failed", "unverified", "not_required"}
)
_CLEANUP_SCOPES = frozenset({"process_group", "cgroup_v2"})
_TERMINAL_REASONS = frozenset(
    {
        "preferred_success",
        "fallback_success",
        "noneligible_failure",
        "cleanup_unverified",
        "artifact_cleanup_unverified",
        "attempts_exhausted",
        "cancelled",
        "internal_error",
    }
)
_ADDITIVE_SKIP_DISPOSITIONS = frozenset({"skipped_config", "skipped_policy"})


class CollectorAttemptPolicyError(ValueError):
    """
    Raised when executable fallback configuration or evidence is malformed.

    Callers receive this exception when the collector attempt policy error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


@dataclass(frozen=True)
class EnforcedCollectorAttemptPolicy:
    """
    Runtime binding between a resolved budget and catalog command modes.

    The immutable record keeps ``ordered_modes``, ``mode_timeouts``,
    ``fallback_on``, ``cleanup_requirement``, and ``cleanup_timeout_seconds``
    together so consumers observe one enforced collector attempt policy state.
    Construction validates cross-field invariants before the instance is
    exposed.

    Attributes:
        ordered_modes: Collection of ordered modes entries retained by this
            record.
        mode_timeouts: Mapping that retains the mode timeouts fields for this
            record.
        fallback_on: Collection of fallback on entries retained by this record.
        cleanup_requirement: Canonical text used as cleanup requirement.
        cleanup_timeout_seconds: Number of cleanup timeout seconds represented
            by this record.
        command_lifecycle: Canonical text used as command lifecycle.
        containment: Kernel ownership primitive required for every managed
            attempt governed by the policy.
        additive_modes: Collection of additive modes entries retained by this
            record.
        preferred_mode: Canonical text used as preferred mode.
        transfer_timeouts: Mapping that retains the transfer timeouts fields for
            this record.
        validation_timeouts: Mapping that retains the validation timeouts fields
            for this record.
        persistence_timeouts: Mapping that retains the persistence timeouts
            fields for this record.
        min_artifact_bytes: Byte count recorded for min artifact.
        additive_enabled: Whether additive enabled applies to this record.
    """

    ordered_modes: tuple[str, ...]
    mode_timeouts: Mapping[str, float]
    fallback_on: tuple[str, ...]
    cleanup_requirement: str
    cleanup_timeout_seconds: float
    command_lifecycle: str
    containment: str
    additive_modes: tuple[str, ...]
    preferred_mode: str
    transfer_timeouts: Mapping[str, float]
    validation_timeouts: Mapping[str, float]
    persistence_timeouts: Mapping[str, float]
    min_artifact_bytes: Mapping[str, int]
    additive_enabled: Mapping[str, bool]

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized EnforcedCollectorAttemptPolicy state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.
        """
        object.__setattr__(
            self, "mode_timeouts", MappingProxyType(dict(self.mode_timeouts))
        )
        for field_name in (
            "transfer_timeouts",
            "validation_timeouts",
            "persistence_timeouts",
            "min_artifact_bytes",
            "additive_enabled",
        ):
            object.__setattr__(
                self,
                field_name,
                MappingProxyType(dict(getattr(self, field_name))),
            )


@dataclass(frozen=True)
class CollectorAttemptPolicyRun:
    """
    Terminal first-success decision returned by the generic state machine.

    The immutable record keeps ``receipt``, ``selected_mode``, and
    ``executed_modes`` together so consumers observe one collector attempt
    policy run state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        receipt: Mapping that retains the receipt fields for this record.
        selected_mode: Canonical text used as selected mode.
        executed_modes: Collection of executed modes entries retained by this
            record.
    """

    receipt: Mapping[str, Any]
    selected_mode: Optional[str]
    executed_modes: tuple[str, ...]


def _mode_name(value: Any, field: str) -> str:
    """
    Return the mode name.

    The implementation uses ``value`` and ``field`` to produce the mode name. If
    the function cannot produce the mode name, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        value: Value evaluated while performing mode name.
        field: Text supplied as field in the format accepted by this function.

    Returns:
        The validated ``value``.

    Raises:
        CollectorAttemptPolicyError: If ``field`` must match ``pattern``.
    """
    if not isinstance(value, str) or not _MODE_NAME.fullmatch(value):
        raise CollectorAttemptPolicyError(f"{field} must match {_MODE_NAME.pattern}")
    return value


def _cleanup_scope(value: Any, field: str) -> str:
    """
    Validate one serialized managed-command ownership scope.

    Cleanup evidence is security-sensitive transition input. Keeping its scope
    in a closed vocabulary prevents an executed cgroup attempt from being
    projected as legacy process-group proof, or vice versa.

    Args:
        value: Candidate serialized cleanup scope.
        field: Operator-facing field name used in validation errors.

    Returns:
        The validated cleanup scope.

    Raises:
        CollectorAttemptPolicyError: If ``value`` is not a supported scope.
    """
    if not isinstance(value, str) or value not in _CLEANUP_SCOPES:
        raise CollectorAttemptPolicyError(f"{field} is unsupported")
    return value


def _positive_timeout(value: Any, field: str) -> float:
    """
    Return the positive timeout.

    The implementation uses ``value`` and ``field`` to produce the positive
    timeout. If the function cannot produce the positive timeout, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        value: Value evaluated while performing positive timeout.
        field: Text supplied as field in the format accepted by this function.

    Returns:
        The validated ``timeout``.

    Raises:
        CollectorAttemptPolicyError: If the ``field`` is not a positive number.
    """
    if isinstance(value, bool):
        raise CollectorAttemptPolicyError(f"{field} must be a positive number")
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise CollectorAttemptPolicyError(
            f"{field} must be a positive number"
        ) from error
    if not math.isfinite(timeout) or timeout <= 0:
        raise CollectorAttemptPolicyError(f"{field} must be a positive number")
    return timeout


def _managed_seconds(value: Any, field: str) -> float:
    """
    Validate a duration accepted by the managed target/supervisor boundary.

    The implementation uses ``value`` and ``field`` to validate a duration
    accepted by the managed target/supervisor boundary. Every required invariant
    is checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        value: Value evaluated while performing duration accepted by the managed
            target/supervisor boundary.
        field: Text supplied as field in the format accepted by this function.

    Returns:
        The validated ``timeout``.

    Raises:
        CollectorAttemptPolicyError: If the ``field`` is not a whole number no
            greater than ``MAX_MANAGED_STAGE_SECONDS``.
    """

    timeout = _positive_timeout(value, field)
    if not timeout.is_integer() or timeout > MAX_MANAGED_STAGE_SECONDS:
        raise CollectorAttemptPolicyError(
            f"{field} must be a whole number no greater than "
            f"{MAX_MANAGED_STAGE_SECONDS}"
        )
    return timeout


def _bounded_nonnegative_seconds(value: Any, field: str, *, maximum: float) -> float:
    """
    Validate a finite nonnegative duration with an explicit upper bound.

    The implementation uses ``value``, ``field``, and ``maximum`` to validate a
    finite nonnegative duration with an explicit upper bound. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing finite nonnegative duration with
            an explicit upper bound.
        field: Text supplied as field in the format accepted by this function.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.

    Returns:
        The validated ``duration``.

    Raises:
        CollectorAttemptPolicyError: If the ``field`` is not a nonnegative
            number no greater than ``maximum``.
    """

    if isinstance(value, bool):
        raise CollectorAttemptPolicyError(
            f"{field} must be a nonnegative number no greater than {maximum}"
        )
    try:
        duration = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise CollectorAttemptPolicyError(
            f"{field} must be a nonnegative number no greater than {maximum}"
        ) from error
    if not math.isfinite(duration) or duration < 0 or duration > maximum:
        raise CollectorAttemptPolicyError(
            f"{field} must be a nonnegative number no greater than {maximum}"
        )
    return duration


def _managed_command(value: Any, field: str) -> str:
    """
    Validate exactly what the managed executor can encode and submit.

    The implementation uses ``value`` and ``field`` to validate exactly what the
    managed executor can encode and submit. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        value: Value object whose ``encode`` and ``strip`` state is read while
            performing exactly what the managed executor can encode and submit.
        field: Text supplied as field in the format accepted by this function.

    Returns:
        The validated ``value``.

    Raises:
        CollectorAttemptPolicyError: If the ``field`` is not a bounded
            single-line command; or the ``field`` is not valid UTF-8 and at most
            ``MAX_MANAGED_COMMAND_BYTES`` bytes.
    """

    if (
        not isinstance(value, str)
        or not value.strip()
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise CollectorAttemptPolicyError(
            f"{field} must be a bounded single-line command"
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise CollectorAttemptPolicyError(
            f"{field} must be valid UTF-8 and at most "
            f"{MAX_MANAGED_COMMAND_BYTES} bytes"
        ) from error
    if len(encoded) > MAX_MANAGED_COMMAND_BYTES:
        raise CollectorAttemptPolicyError(
            f"{field} must be valid UTF-8 and at most "
            f"{MAX_MANAGED_COMMAND_BYTES} bytes"
        )
    return value


def _minimum_artifact_bytes(value: Any, field: str) -> int:
    """
    Validate a fail-closed per-mode artifact size floor.

    The implementation uses ``value`` and ``field`` to validate a fail-closed
    per-mode artifact size floor. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        value: Value evaluated while performing fail-closed per-mode artifact
            size floor.
        field: Text supplied as field in the format accepted by this function.

    Returns:
        The validated ``value``.

    Raises:
        CollectorAttemptPolicyError: If the ``field`` is not an integer between
            1 and ``MAX_MANAGED_ARTIFACT_BYTES``.
    """

    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_MANAGED_ARTIFACT_BYTES
    ):
        raise CollectorAttemptPolicyError(
            f"{field} must be an integer between 1 and " f"{MAX_MANAGED_ARTIFACT_BYTES}"
        )
    return value


def _projection_factors(runtime_budget: Any) -> tuple[Mapping[str, Any], ...]:
    """
    Return the projection factors.

    After applying local validation, the function forwards ``runtime_budget`` to
    ``tuple`` and preserves its return and exception contract.

    Args:
        runtime_budget: Runtime budget object whose ``get`` state is read while
            performing projection factors.

    Returns:
        The projection factors returned in operation-defined order.

    Raises:
        CollectorAttemptPolicyError: If enforced managed fallback lacks resolved
            projection factors.
    """
    factors = getattr(runtime_budget, "projection_factors", None)
    if factors is None and isinstance(runtime_budget, Mapping):
        factors = runtime_budget.get("projection_factors")
    if not isinstance(factors, (list, tuple)) or any(
        not isinstance(factor, Mapping) for factor in factors
    ):
        raise CollectorAttemptPolicyError(
            "enforced managed fallback requires resolved projection factors"
        )
    return tuple(factors)


def _managed_metadata_timeouts(initial_commands: Any) -> tuple[float, ...]:
    """
    Validate the exact metadata commands admitted to managed execution.

    After applying local validation, the function forwards ``initial_commands``
    to ``tuple`` and preserves its return and exception contract. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        initial_commands: Entries supplied as ``initial_commands`` and processed
            in caller-provided order.

    Returns:
        The managed metadata timeouts returned in operation-defined order.

    Raises:
        CollectorAttemptPolicyError: If the initial_commands are not a list of
            at most ``MAX_MANAGED_METADATA_COMMANDS`` commands; the ``field`` is
            not a mapping; the ``field``.file_name is not a relative basename;
            or initial_commands must have unique file_name values; or another
            input invariant is violated.
    """

    if (
        not isinstance(initial_commands, list)
        or len(initial_commands) > MAX_MANAGED_METADATA_COMMANDS
    ):
        raise CollectorAttemptPolicyError(
            "initial_commands must be a list of at most "
            f"{MAX_MANAGED_METADATA_COMMANDS} commands"
        )

    timeouts: list[float] = []
    file_names: set[str] = set()
    for index, raw_command in enumerate(initial_commands):
        field = f"initial_commands[{index}]"
        if not isinstance(raw_command, Mapping):
            raise CollectorAttemptPolicyError(f"{field} must be a mapping")
        _managed_command(raw_command.get("command"), f"{field}.command")
        file_name = raw_command.get("file_name")
        if not isinstance(file_name, str) or not _REMOTE_BASENAME.fullmatch(file_name):
            raise CollectorAttemptPolicyError(
                f"{field}.file_name must be a relative basename"
            )
        if file_name in file_names:
            raise CollectorAttemptPolicyError(
                "initial_commands must have unique file_name values"
            )
        file_names.add(file_name)
        if raw_command.get("expect_file") is not False:
            raise CollectorAttemptPolicyError(
                f"{field}.expect_file must be false for managed metadata"
            )
        timeouts.append(
            _managed_seconds(raw_command.get("timeout"), f"{field}.timeout")
        )
    return tuple(timeouts)


def _bind_managed_metadata_factor(
    factors: Sequence[Mapping[str, Any]],
    target_timeouts: Sequence[float],
    *,
    cleanup_timeout_seconds: float,
) -> None:
    """
    Bind metadata commands to one unconditional conservative wall factor.

    The implementation uses ``factors``, ``target_timeouts``, and
    ``cleanup_timeout_seconds`` to bind metadata commands to one unconditional
    conservative wall factor. If the function cannot bind metadata commands to
    one unconditional conservative wall factor, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        factors: Mapping supplying fields for bind metadata commands to one
            unconditional conservative wall factor.
        target_timeouts: Maximum duration in seconds allowed for target
            timeouts.
        cleanup_timeout_seconds: Maximum duration in seconds allowed for cleanup
            timeout seconds.

    Raises:
        CollectorAttemptPolicyError: If initial_commands require exactly one
            managed_metadata_command budget factor; managed_metadata_command
            budget factor is inconsistent; managed_metadata_command factor
            contribution is invalid; or managed_metadata_command factor
            contribution is inconsistent; or another input invariant is
            violated.
    """

    matches = [
        factor
        for factor in factors
        if factor.get("classification") == "managed_metadata_command"
    ]
    if len(matches) != 1:
        raise CollectorAttemptPolicyError(
            "initial_commands require exactly one managed_metadata_command "
            "budget factor"
        )
    factor = matches[0]
    count = factor.get("count")
    max_retries = factor.get("max_retries")
    if (
        factor.get("type") != "serial_step"
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(target_timeouts)
        or not isinstance(max_retries, int)
        or isinstance(max_retries, bool)
        or max_retries != 0
        or factor.get("enabled") is not True
        or "enabled_config_key" in factor
        or factor.get("timeout_source") != "explicit"
    ):
        raise CollectorAttemptPolicyError(
            "managed_metadata_command budget factor is inconsistent"
        )

    factor_timeout = _managed_seconds(
        factor.get("timeout_seconds"),
        "managed_metadata_command factor timeout_seconds",
    )
    cancellation_grace = _bounded_nonnegative_seconds(
        factor.get("cancellation_grace_seconds"),
        "managed_metadata_command factor cancellation_grace_seconds",
        maximum=MAX_MANAGED_CANCELLATION_GRACE_SECONDS,
    )

    retry_backoff = factor.get("retry_backoff_seconds")
    if (
        isinstance(retry_backoff, bool)
        or not isinstance(retry_backoff, (int, float))
        or not math.isfinite(float(retry_backoff))
        or float(retry_backoff) != 0
    ):
        raise CollectorAttemptPolicyError(
            "managed_metadata_command budget factor is inconsistent"
        )

    raw_contribution = factor.get("contribution_seconds")
    if isinstance(raw_contribution, bool):
        raise CollectorAttemptPolicyError(
            "managed_metadata_command factor contribution is invalid"
        )
    try:
        contribution = float(raw_contribution)
    except (TypeError, ValueError, OverflowError) as error:
        raise CollectorAttemptPolicyError(
            "managed_metadata_command factor contribution is invalid"
        ) from error
    expected_contribution = count * (factor_timeout + cancellation_grace)
    if not math.isfinite(contribution) or contribution != expected_contribution:
        raise CollectorAttemptPolicyError(
            "managed_metadata_command factor contribution is inconsistent"
        )

    per_command_overhead = MANAGED_WRAPPER_GRACE_SECONDS + (2 * cleanup_timeout_seconds)
    if any(
        factor_timeout + cancellation_grace < target_timeout + per_command_overhead
        for target_timeout in target_timeouts
    ):
        raise CollectorAttemptPolicyError(
            "managed_metadata_command factor contribution is incomplete"
        )


def _resolved_fallback_policy(runtime_budget: Any) -> Optional[Mapping[str, Any]]:
    """
    Return the resolved fallback policy.

    The implementation uses ``runtime_budget`` to produce the resolved fallback
    policy.

    Args:
        runtime_budget: Runtime budget object whose ``get`` state is read while
            performing resolved fallback policy.

    Returns:
        A mapping containing resolved fallback policy, or ``None`` when the
        requested value is unavailable.
    """
    policies = getattr(runtime_budget, "policies", None)
    if policies is None and isinstance(runtime_budget, Mapping):
        policies = runtime_budget.get("policies", runtime_budget)
    if not isinstance(policies, Mapping):
        return None
    fallback = policies.get("fallback")
    return fallback if isinstance(fallback, Mapping) else None


def resolve_enforced_attempt_policy_definition(
    runtime_budget: Any,
) -> Optional[EnforcedCollectorAttemptPolicy]:
    """
    Resolve the governed policy independently of executable mode binding.

    This narrow first phase lets a caller publish truthful all-not-attempted
    evidence if catalog command binding fails before any command is launched.
    Projection-only fallback blocks intentionally return ``None``.

    Args:
        runtime_budget: Runtime budget consumed while the function attempts to
            resolve the governed policy independently of executable mode
            binding.

    Returns:
        An ``EnforcedCollectorAttemptPolicy`` representing enforced attempt
        policy definition, or ``None`` when the requested value is unavailable.

    Raises:
        CollectorAttemptPolicyError: If the enforced fallback policy is not
            first_success; enforced fallback must resolve between 2 and
            ``MAX_ATTEMPT_MODES`` modes; the ``field`` is not a mapping; or
            runtime fallback modes must have unique names; or another input
            invariant is violated.
    """

    fallback = _resolved_fallback_policy(runtime_budget)
    if not fallback or fallback.get("enforced") is not True:
        return None
    if fallback.get("policy") != "first_success":
        raise CollectorAttemptPolicyError(
            "enforced fallback policy must be first_success"
        )

    raw_policy_modes = fallback.get("modes")
    if (
        not isinstance(raw_policy_modes, list)
        or not 2 <= len(raw_policy_modes) <= MAX_ATTEMPT_MODES
    ):
        raise CollectorAttemptPolicyError(
            "enforced fallback must resolve between 2 and " f"{MAX_ATTEMPT_MODES} modes"
        )

    ordered_modes: list[str] = []
    mode_timeouts: dict[str, float] = {}
    min_artifact_bytes: dict[str, int] = {}
    for index, raw_mode in enumerate(raw_policy_modes):
        field = f"runtime fallback modes[{index}]"
        if not isinstance(raw_mode, Mapping):
            raise CollectorAttemptPolicyError(f"{field} must be a mapping")
        if raw_mode.get("enabled") is not True:
            continue
        name = _mode_name(raw_mode.get("name"), f"{field}.name")
        if name in mode_timeouts:
            raise CollectorAttemptPolicyError(
                "runtime fallback modes must have unique names"
            )
        ordered_modes.append(name)
        mode_timeouts[name] = _managed_seconds(
            raw_mode.get("timeout_seconds"), f"{field}.timeout_seconds"
        )
        min_artifact_bytes[name] = _minimum_artifact_bytes(
            raw_mode.get("min_artifact_bytes"), f"{field}.min_artifact_bytes"
        )
    if not 2 <= len(ordered_modes) <= MAX_ATTEMPT_MODES:
        raise CollectorAttemptPolicyError(
            "enforced fallback must have at least two enabled modes"
        )

    raw_additive_modes = fallback.get("additive_modes", [])
    if (
        not isinstance(raw_additive_modes, list)
        or len(raw_additive_modes) > MAX_ATTEMPT_MODES
    ):
        raise CollectorAttemptPolicyError(
            "enforced fallback additive_modes must be a list of at most "
            f"{MAX_ATTEMPT_MODES} names"
        )
    additive_modes = tuple(
        _mode_name(mode, f"runtime fallback additive_modes[{index}]")
        for index, mode in enumerate(raw_additive_modes)
    )
    if len(set(additive_modes)) != len(additive_modes):
        raise CollectorAttemptPolicyError(
            "runtime fallback additive_modes must be unique"
        )
    additive_collisions = set(additive_modes).intersection(ordered_modes)
    if additive_collisions:
        raise CollectorAttemptPolicyError(
            "runtime fallback additive_modes must not overlap primary modes: "
            + ", ".join(sorted(additive_collisions))
        )

    raw_fallback_on = fallback.get("fallback_on")
    if not isinstance(raw_fallback_on, list) or not raw_fallback_on:
        raise CollectorAttemptPolicyError(
            "enforced fallback requires a non-empty fallback_on list"
        )
    fallback_on = tuple(raw_fallback_on)
    if len(set(fallback_on)) != len(raw_fallback_on) or not set(fallback_on).issubset(
        _FALLBACK_FAILURES
    ):
        raise CollectorAttemptPolicyError(
            "enforced fallback_on contains duplicate or unsupported values"
        )

    cleanup = fallback.get("cleanup")
    if not isinstance(cleanup, Mapping):
        raise CollectorAttemptPolicyError("enforced fallback requires cleanup")
    cleanup_requirement = cleanup.get("requirement")
    command_lifecycle = cleanup.get("command_lifecycle")
    containment = _cleanup_scope(
        cleanup.get("containment", "process_group"),
        "runtime fallback cleanup.containment",
    )
    expected_cleanup = {
        "process_group": (
            "verified_owned_process_group_exit",
            "foreground_non_daemonizing",
        ),
        "cgroup_v2": (
            "verified_owned_cgroup_v2_exit",
            "cgroup_v2_contained",
        ),
    }
    if (
        containment not in expected_cleanup
        or (
            cleanup_requirement,
            command_lifecycle,
        )
        != expected_cleanup[containment]
    ):
        raise CollectorAttemptPolicyError(
            "unsupported enforced fallback cleanup contract"
        )
    cleanup_timeout = _managed_seconds(
        cleanup.get("timeout_seconds"), "runtime fallback cleanup.timeout_seconds"
    )
    if cleanup_timeout < MIN_MANAGED_CLEANUP_SECONDS:
        raise CollectorAttemptPolicyError(
            "runtime fallback cleanup.timeout_seconds must cover managed identity "
            "readiness, TERM, KILL, and verification grace"
        )

    return EnforcedCollectorAttemptPolicy(
        ordered_modes=tuple(ordered_modes),
        mode_timeouts=mode_timeouts,
        fallback_on=fallback_on,
        cleanup_requirement=cleanup_requirement,
        cleanup_timeout_seconds=cleanup_timeout,
        command_lifecycle=command_lifecycle,
        containment=containment,
        additive_modes=additive_modes,
        preferred_mode=ordered_modes[0],
        transfer_timeouts={},
        validation_timeouts={},
        persistence_timeouts={},
        min_artifact_bytes=min_artifact_bytes,
        additive_enabled={},
    )


def resolve_enforced_attempt_policy(
    runtime_budget: Any,
    command_modes: Any,
    initial_commands: Any,
) -> Optional[EnforcedCollectorAttemptPolicy]:
    """
    Bind an opt-in resolved fallback policy to executable command modes.

    Enforced policies fail closed before any command is launched when their
    ordered modes, metadata commands, timeouts, or additive-mode annotations
    drift from the independently validated policy definition.

    Args:
        runtime_budget: Runtime budget consumed while the function attempts to
            bind an opt-in resolved fallback policy to executable command modes.
        command_modes: Entries supplied as ``command_modes`` and processed in
            caller-provided order.
        initial_commands: Initial commands consumed while the function attempts
            to bind an opt-in resolved fallback policy to executable command
            modes.

    Returns:
        An ``EnforcedCollectorAttemptPolicy`` representing enforced attempt
        policy, or ``None`` when the requested value is unavailable.

    Raises:
        CollectorAttemptPolicyError: If the command_modes are not a non-empty
            list; resolved fallback policy is unavailable; the ``field`` is not
            a mapping; or command_modes must have unique modes; or another input
            invariant is violated.
    """

    definition = resolve_enforced_attempt_policy_definition(runtime_budget)
    if definition is None:
        return None
    if not isinstance(command_modes, list) or not command_modes:
        raise CollectorAttemptPolicyError("command_modes must be a non-empty list")

    fallback = _resolved_fallback_policy(runtime_budget)
    if fallback is None:
        raise CollectorAttemptPolicyError("resolved fallback policy is unavailable")
    factors = _projection_factors(runtime_budget)
    metadata_timeouts = _managed_metadata_timeouts(initial_commands)
    _bind_managed_metadata_factor(
        factors,
        metadata_timeouts,
        cleanup_timeout_seconds=definition.cleanup_timeout_seconds,
    )
    budget_modes = {
        str(mode.get("name")): mode
        for mode in fallback.get("modes", [])
        if isinstance(mode, Mapping) and mode.get("enabled") is True
    }

    def stage_timeout(raw_mode: Mapping[str, Any], key: str, field: str) -> float:
        """
        Return the stage timeout.

        After applying local validation, the function forwards ``raw_mode``,
        ``key``, and ``field`` to ``_managed_seconds`` and preserves its return
        and exception contract.

        Args:
            raw_mode: Mapping supplying fields for stage timeout.
            key: Stable key used for lookup and operator-facing diagnostics.
            field: Text supplied as field in the format accepted by this
                function.

        Returns:
            The numeric stage timeout value.

        Raises:
            CollectorAttemptPolicyError: If the ``field``.``key`` is not
                explicitly budget-bound.
        """
        if key not in raw_mode:
            raise CollectorAttemptPolicyError(
                f"{field}.{key} must be explicitly budget-bound"
            )
        return _managed_seconds(raw_mode.get(key), f"{field}.{key}")

    def additive_factor(
        mode_name: str,
        stage: str,
        config_key: str,
    ) -> Mapping[str, Any]:
        """
        Return the additive factor.

        The implementation uses ``mode_name``, ``stage``, and ``config_key`` to
        produce the additive factor. If the function cannot produce the additive
        factor, its exception reaches the caller instead of being converted into
        a successful result.

        Args:
            mode_name: Stable mode name used for lookup and operator-facing
                diagnostics.
            stage: Text supplied as stage in the format accepted by this
                function.
            config_key: Stable config key used for lookup and operator-facing
                diagnostics.

        Returns:
            The validated ``factor``.

        Raises:
            CollectorAttemptPolicyError: If additive mode ``mode_name`` lacks
                exactly one ``stage`` budget factor; or additive mode
                ``mode_name`` ``stage`` budget factor is inconsistent.
        """
        classification = f"managed_additive_{stage}:{mode_name}"
        matches = [
            factor
            for factor in factors
            if factor.get("classification") == classification
        ]
        if len(matches) != 1:
            raise CollectorAttemptPolicyError(
                f"additive mode {mode_name} requires exactly one {stage} budget factor"
            )
        factor = matches[0]
        if (
            factor.get("type") != "serial_step"
            or factor.get("count") != 1
            or factor.get("max_retries") != 0
            or factor.get("enabled_config_key") != config_key
            or not isinstance(factor.get("enabled"), bool)
        ):
            raise CollectorAttemptPolicyError(
                f"additive mode {mode_name} {stage} budget factor is inconsistent"
            )
        return factor

    configured_by_name: dict[str, Mapping[str, Any]] = {}
    transfer_timeouts: dict[str, float] = {}
    validation_timeouts: dict[str, float] = {}
    persistence_timeouts: dict[str, float] = {}
    min_artifact_bytes: dict[str, int] = {}
    additive_enabled: dict[str, bool] = {}
    for index, raw_mode in enumerate(command_modes):
        field = f"command_modes[{index}]"
        if not isinstance(raw_mode, Mapping):
            raise CollectorAttemptPolicyError(f"{field} must be a mapping")
        name = _mode_name(raw_mode.get("mode"), f"{field}.mode")
        if name in configured_by_name:
            raise CollectorAttemptPolicyError("command_modes must have unique modes")
        configured_by_name[name] = raw_mode
        _managed_command(raw_mode.get("command"), f"{field}.command")
        configured_min_artifact_bytes = _minimum_artifact_bytes(
            raw_mode.get("min_artifact_bytes"), f"{field}.min_artifact_bytes"
        )
        min_artifact_bytes[name] = configured_min_artifact_bytes
        remote_file = raw_mode.get("remote_file")
        if not isinstance(remote_file, str) or not _REMOTE_BASENAME.fullmatch(
            remote_file
        ):
            raise CollectorAttemptPolicyError(
                f"{field}.remote_file must be a relative basename"
            )
        file_name = raw_mode.get("file_name")
        if not isinstance(file_name, str) or not _REMOTE_BASENAME.fullmatch(file_name):
            raise CollectorAttemptPolicyError(
                f"{field}.file_name must be a relative basename"
            )
        file_extensions = raw_mode.get("file_extensions")
        if (
            not isinstance(file_extensions, list)
            or not 1 <= len(file_extensions) <= 8
            or any(
                not isinstance(extension, str)
                or not _FILE_EXTENSION.fullmatch(extension)
                for extension in file_extensions
            )
            or len(set(file_extensions)) != len(file_extensions)
        ):
            raise CollectorAttemptPolicyError(
                f"{field}.file_extensions must contain 1..8 unique safe suffixes"
            )
        if raw_mode.get("expect_file") is not True:
            raise CollectorAttemptPolicyError(
                f"managed mode {name} must require an artifact"
            )
        preserve_invalid_artifact = raw_mode.get("preserve_invalid_artifact", False)
        if not isinstance(preserve_invalid_artifact, bool):
            raise CollectorAttemptPolicyError(
                f"{field}.preserve_invalid_artifact must be boolean"
            )
        transfer_timeout = stage_timeout(raw_mode, "transfer_timeout", field)
        validation_timeout = stage_timeout(raw_mode, "validation_timeout", field)
        persistence_timeout = stage_timeout(raw_mode, "persistence_timeout", field)
        transfer_timeouts[name] = transfer_timeout
        validation_timeouts[name] = validation_timeout
        persistence_timeouts[name] = persistence_timeout
        if name in definition.mode_timeouts:
            if configured_min_artifact_bytes != definition.min_artifact_bytes[name]:
                raise CollectorAttemptPolicyError(
                    f"fallback mode {name} min_artifact_bytes does not match "
                    "runtime budget"
                )
            if raw_mode.get("always_run") is not None:
                raise CollectorAttemptPolicyError(
                    f"fallback mode {name} must not define always_run"
                )
            configured_timeout = _managed_seconds(
                raw_mode.get("timeout"), f"{field}.timeout"
            )
            if configured_timeout != definition.mode_timeouts[name]:
                raise CollectorAttemptPolicyError(
                    f"fallback mode {name} timeout does not match runtime budget"
                )
            budget_mode = budget_modes.get(name)
            post_operation = (
                budget_mode.get("post_operation")
                if isinstance(budget_mode, Mapping)
                else None
            )
            if not isinstance(post_operation, Mapping):
                raise CollectorAttemptPolicyError(
                    f"fallback mode {name} requires a post-operation budget"
                )
            post_count = post_operation.get("count")
            if isinstance(post_count, bool) or not isinstance(post_count, int):
                raise CollectorAttemptPolicyError(
                    f"fallback mode {name} post-operation count is invalid"
                )
            post_timeout = _managed_seconds(
                post_operation.get("timeout_seconds"),
                f"fallback mode {name} post-operation timeout",
            )
            cancellation_grace = _bounded_nonnegative_seconds(
                post_operation.get("cancellation_grace_seconds", 0),
                f"fallback mode {name} post-operation cancellation grace",
                maximum=MAX_MANAGED_CANCELLATION_GRACE_SECONDS,
            )
            if not (
                transfer_timeout == post_timeout
                and validation_timeout == post_timeout
                and persistence_timeout == post_timeout
            ):
                raise CollectorAttemptPolicyError(
                    f"fallback mode {name} processing timeouts do not match its "
                    "post-operation budget"
                )
            required_processing = (
                transfer_timeout
                + validation_timeout
                + persistence_timeout
                + MANAGED_INSPECTION_SECONDS
                + (2 * definition.cleanup_timeout_seconds)
                + MANAGED_WRAPPER_GRACE_SECONDS
            )
            if post_count * (post_timeout + cancellation_grace) < required_processing:
                raise CollectorAttemptPolicyError(
                    f"fallback mode {name} post-operation budget is incomplete"
                )
        elif name in definition.additive_modes:
            if raw_mode.get("execution_role") != "additive":
                raise CollectorAttemptPolicyError(
                    f"unmanaged mode {name} must declare execution_role: additive"
                )
            if raw_mode.get("run_after") != "preferred_success":
                raise CollectorAttemptPolicyError(
                    f"additive mode {name} must declare run_after: preferred_success"
                )
            if raw_mode.get("safety_qualified") is not True:
                raise CollectorAttemptPolicyError(
                    f"additive mode {name} must declare safety_qualified: true"
                )
            configured_timeout = _managed_seconds(
                raw_mode.get("timeout"), f"{field}.timeout"
            )
            config_key = raw_mode.get("config_key")
            if not isinstance(config_key, str) or not _CONFIG_KEY.fullmatch(config_key):
                raise CollectorAttemptPolicyError(
                    f"additive mode {name} requires a safe config_key"
                )
            command_factor = additive_factor(name, "command", config_key)
            transfer_factor = additive_factor(name, "transfer", config_key)
            validation_factor = additive_factor(name, "validation", config_key)
            persistence_factor = additive_factor(name, "persistence", config_key)
            overhead_factor = additive_factor(name, "overhead", config_key)
            if command_factor.get("timeout_seconds") != configured_timeout:
                raise CollectorAttemptPolicyError(
                    f"additive mode {name} command timeout does not match runtime budget"
                )
            for stage, factor, configured_stage_timeout in (
                ("transfer", transfer_factor, transfer_timeout),
                ("validation", validation_factor, validation_timeout),
                ("persistence", persistence_factor, persistence_timeout),
            ):
                if factor.get("timeout_seconds") != configured_stage_timeout:
                    raise CollectorAttemptPolicyError(
                        f"additive mode {name} {stage} timeout does not match runtime budget"
                    )
            required_overhead = (
                MANAGED_INSPECTION_SECONDS
                + (2 * definition.cleanup_timeout_seconds)
                + MANAGED_WRAPPER_GRACE_SECONDS
            )
            if float(overhead_factor.get("timeout_seconds", 0)) < required_overhead:
                raise CollectorAttemptPolicyError(
                    f"additive mode {name} overhead budget is incomplete"
                )
            enabled_values = {
                bool(factor["enabled"])
                for factor in (
                    command_factor,
                    transfer_factor,
                    validation_factor,
                    persistence_factor,
                    overhead_factor,
                )
            }
            if len(enabled_values) != 1:
                raise CollectorAttemptPolicyError(
                    f"additive mode {name} budget gates are inconsistent"
                )
            additive_enabled[name] = enabled_values.pop()
        else:
            raise CollectorAttemptPolicyError(
                f"command mode {name} is not declared by the runtime fallback policy"
            )

    expected_mode_order = definition.ordered_modes + definition.additive_modes
    if tuple(configured_by_name) != expected_mode_order:
        raise CollectorAttemptPolicyError(
            "command_modes must exactly match runtime fallback mode names and order"
        )

    return EnforcedCollectorAttemptPolicy(
        ordered_modes=definition.ordered_modes,
        mode_timeouts=definition.mode_timeouts,
        fallback_on=definition.fallback_on,
        cleanup_requirement=definition.cleanup_requirement,
        cleanup_timeout_seconds=definition.cleanup_timeout_seconds,
        command_lifecycle=definition.command_lifecycle,
        containment=definition.containment,
        additive_modes=definition.additive_modes,
        preferred_mode=definition.preferred_mode,
        transfer_timeouts=transfer_timeouts,
        validation_timeouts=validation_timeouts,
        persistence_timeouts=persistence_timeouts,
        min_artifact_bytes=min_artifact_bytes,
        additive_enabled=additive_enabled,
    )


def not_attempted_record(
    mode: str,
    *,
    cleanup_scope: str = "process_group",
) -> dict[str, Any]:
    """
    Return the canonical bounded record for an unstarted fallback mode.

    The implementation uses ``mode`` to produce the canonical bounded record for
    an unstarted fallback mode.

    Args:
        mode: Text supplied as mode in the format accepted by this function.
        cleanup_scope: Kernel ownership primitive selected by the governing
            fallback policy.

    Returns:
        A mapping containing the ``mode``, ``disposition``,
        ``failure_category``, ``command``, and ``artifact`` fields.
    """

    return {
        "mode": _mode_name(mode, "mode"),
        "disposition": "not_attempted",
        "failure_category": None,
        "command": {"status": "not_attempted", "exit_code": None},
        "artifact": {"status": "not_checked"},
        "cleanup": {
            "scope": _cleanup_scope(cleanup_scope, "cleanup_scope"),
            "status": "not_required",
        },
    }


def attempt_record(
    mode: str,
    *,
    disposition: str,
    failure_category: Optional[str],
    command_status: str,
    exit_code: Optional[int],
    artifact_status: str,
    cleanup_status: str,
    cleanup_scope: str = "process_group",
) -> dict[str, Any]:
    """
    Construct and validate one path-free attempt evidence record.

    After applying local validation, the function forwards ``mode``,
    ``disposition``, ``failure_category``, ``command_status``, and ``exit_code``
    to ``_project_attempt`` and preserves its return and exception contract.

    Args:
        mode: Text supplied as mode in the format accepted by this function.
        disposition: Text supplied as disposition in the format accepted by this
            function.
        failure_category: Text supplied as failure category in the format
            accepted by this function.
        command_status: Text supplied as command status in the format accepted
            by this function.
        exit_code: Numeric exit code used while the operation performs bounded
            accounting.
        artifact_status: Text supplied as artifact status in the format accepted
            by this function.
        cleanup_status: Text supplied as cleanup status in the format accepted
            by this function.
        cleanup_scope: Kernel ownership primitive selected by the governing
            fallback policy.

    Returns:
        A mapping containing attempt record.
    """

    raw = {
        "mode": mode,
        "disposition": disposition,
        "failure_category": failure_category,
        "command": {"status": command_status, "exit_code": exit_code},
        "artifact": {"status": artifact_status},
        "cleanup": {
            "scope": _cleanup_scope(cleanup_scope, "cleanup_scope"),
            "status": cleanup_status,
        },
    }
    return _project_attempt(raw, "attempt")


def build_attempt_policy_receipt(
    policy: EnforcedCollectorAttemptPolicy,
    attempts: Sequence[Mapping[str, Any]],
    *,
    selected_mode: Optional[str],
    fallback_used: bool,
    terminal_reason: str,
) -> dict[str, Any]:
    """
    Build the canonical receipt and enforce first-success transition truth.

    After applying local validation, the function forwards ``policy``,
    ``attempts``, ``selected_mode``, ``fallback_used``, and ``terminal_reason``
    to ``project_attempt_policy`` and preserves its return and exception
    contract.

    Args:
        policy: Policy governing canonical receipt and enforce first-success
            transition truth.
        attempts: Mapping supplying fields for canonical receipt and enforce
            first-success transition truth.
        selected_mode: Text supplied as selected mode in the format accepted by
            this function.
        fallback_used: Whether fallback used is enabled or required for this
            operation.
        terminal_reason: Text supplied as terminal reason in the format accepted
            by this function.

    Returns:
        A mapping containing attempt policy receipt.
    """

    cleanup_policy = {
        "requirement": policy.cleanup_requirement,
        "command_lifecycle": policy.command_lifecycle,
    }
    if policy.containment != "process_group":
        cleanup_policy["containment"] = policy.containment
    raw = {
        "schema_version": ATTEMPT_POLICY_SCHEMA_VERSION,
        "policy": "first_success",
        "enforced": True,
        "ordered_modes": list(policy.ordered_modes),
        "fallback_on": list(policy.fallback_on),
        "cleanup": cleanup_policy,
        "selected_mode": selected_mode,
        "fallback_used": fallback_used,
        "terminal_reason": terminal_reason,
        "attempts": list(attempts),
    }
    return project_attempt_policy(raw)


async def run_first_success_attempt_policy(
    policy: EnforcedCollectorAttemptPolicy,
    execute_attempt: Callable[[str], Awaitable[Mapping[str, Any]]],
) -> CollectorAttemptPolicyRun:
    """
    Execute the ordered policy without authorizing an unsafe transition.

    The service-specific callback owns command execution and artifact
    validation, then returns one canonical, path-free attempt record. Control
    flow exceptions are intentionally not swallowed.

    Args:
        policy: Policy governing ordered policy without authorizing an unsafe
            transition.
        execute_attempt: Mapping supplying fields for ordered policy without
            authorizing an unsafe transition.

    Returns:
        A ``CollectorAttemptPolicyRun`` representing run first success attempt
        policy.

    Raises:
        CollectorAttemptPolicyError: If attempt callback returned evidence for
            the wrong mode.
    """

    attempts = [
        not_attempted_record(mode, cleanup_scope=policy.containment)
        for mode in policy.ordered_modes
    ]
    selected_mode: Optional[str] = None
    executed_modes: list[str] = []
    terminal_reason = "internal_error"

    for index, mode in enumerate(policy.ordered_modes):
        projected = _project_attempt(
            await execute_attempt(mode), f"execute_attempt({mode})"
        )
        if projected["mode"] != mode:
            raise CollectorAttemptPolicyError(
                "attempt callback returned evidence for the wrong mode"
            )
        if projected["cleanup"]["scope"] != policy.containment:
            raise CollectorAttemptPolicyError(
                "attempt callback returned evidence for the wrong cleanup scope"
            )
        attempts[index] = projected
        executed_modes.append(mode)

        if projected["disposition"] == "success":
            selected_mode = mode
            terminal_reason = "preferred_success" if index == 0 else "fallback_success"
            break

        if projected["disposition"] == "cancelled":
            terminal_reason = "cancelled"
            break

        if projected["cleanup"]["status"] != "verified_absent":
            terminal_reason = "cleanup_unverified"
            break

        failure_category = projected["failure_category"]
        if failure_category == "artifact_cleanup_unverified":
            terminal_reason = "artifact_cleanup_unverified"
            break
        if index == len(policy.ordered_modes) - 1:
            terminal_reason = "attempts_exhausted"
            break
        if failure_category not in policy.fallback_on:
            terminal_reason = "noneligible_failure"
            break

    fallback_used = len(executed_modes) > 1
    receipt = build_attempt_policy_receipt(
        policy,
        attempts,
        selected_mode=selected_mode,
        fallback_used=fallback_used,
        terminal_reason=terminal_reason,
    )
    return CollectorAttemptPolicyRun(
        receipt=receipt,
        selected_mode=selected_mode,
        executed_modes=tuple(executed_modes),
    )


def _project_attempt(raw: Any, field: str) -> dict[str, Any]:
    """
    Project attempt.

    The implementation uses ``raw`` and ``field`` to project attempt. If the
    function cannot project attempt, its exception reaches the caller instead of
    being converted into a successful result.

    Args:
        raw: Raw object whose ``get`` state is read while performing project
            attempt.
        field: Text supplied as field in the format accepted by this function.

    Returns:
        A mapping containing the ``mode``, ``disposition``,
        ``failure_category``, ``command``, and ``artifact`` fields.

    Raises:
        CollectorAttemptPolicyError: If the ``field`` is not a mapping;
            ``field``.disposition is unsupported; ``field``.failure_category is
            unsupported; or the ``field`` command, artifact, and cleanup is not
            mappings; or another input invariant is violated.
    """
    if not isinstance(raw, Mapping):
        raise CollectorAttemptPolicyError(f"{field} must be a mapping")
    mode = _mode_name(raw.get("mode"), f"{field}.mode")
    disposition = raw.get("disposition")
    if disposition not in _DISPOSITIONS:
        raise CollectorAttemptPolicyError(f"{field}.disposition is unsupported")
    failure_category = raw.get("failure_category")
    if failure_category is not None and failure_category not in _FAILURE_CATEGORIES:
        raise CollectorAttemptPolicyError(f"{field}.failure_category is unsupported")
    command = raw.get("command")
    artifact = raw.get("artifact")
    cleanup = raw.get("cleanup")
    if not all(isinstance(value, Mapping) for value in (command, artifact, cleanup)):
        raise CollectorAttemptPolicyError(
            f"{field} command, artifact, and cleanup must be mappings"
        )
    command_status = command.get("status")
    if command_status not in _COMMAND_STATUSES:
        raise CollectorAttemptPolicyError(f"{field}.command.status is unsupported")
    exit_code = command.get("exit_code")
    if exit_code is not None and (
        not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
        or not -(1 << 31) <= exit_code < (1 << 31)
    ):
        raise CollectorAttemptPolicyError(f"{field}.command.exit_code is invalid")
    artifact_status = artifact.get("status")
    if artifact_status not in _ARTIFACT_STATUSES:
        raise CollectorAttemptPolicyError(f"{field}.artifact.status is unsupported")
    cleanup_scope = _cleanup_scope(cleanup.get("scope"), f"{field}.cleanup.scope")
    cleanup_status = cleanup.get("status")
    if cleanup_status not in _CLEANUP_STATUSES:
        raise CollectorAttemptPolicyError(f"{field}.cleanup.status is unsupported")

    if disposition == "not_attempted":
        if any(
            (
                failure_category is not None,
                command_status != "not_attempted",
                exit_code is not None,
                artifact_status != "not_checked",
                cleanup_status != "not_required",
            )
        ):
            raise CollectorAttemptPolicyError(
                f"{field} not_attempted evidence is inconsistent"
            )
    else:
        if command_status == "not_attempted" or cleanup_status == "not_required":
            raise CollectorAttemptPolicyError(
                f"{field} executed evidence is inconsistent"
            )
        if disposition == "success":
            if (
                failure_category is not None
                or command_status != "success"
                or exit_code != 0
                or artifact_status != "valid"
                or cleanup_status != "verified_absent"
            ):
                raise CollectorAttemptPolicyError(
                    f"{field} successful evidence is inconsistent"
                )
        elif failure_category is None:
            raise CollectorAttemptPolicyError(
                f"{field} non-success evidence requires failure_category"
            )

        failure_shape = {
            "timeout": (
                disposition == "failed"
                and command_status == "timeout"
                and exit_code is None
                and artifact_status == "not_checked"
                and cleanup_status == "verified_absent"
            ),
            "nonzero_exit": (
                disposition == "failed"
                and command_status == "nonzero_exit"
                and exit_code not in (None, 0)
                and artifact_status == "not_checked"
                and cleanup_status == "verified_absent"
            ),
            "missing_artifact": (
                disposition == "failed"
                and command_status == "success"
                and exit_code == 0
                and artifact_status == "missing"
                and cleanup_status == "verified_absent"
            ),
            "invalid_artifact": (
                disposition == "failed"
                and command_status == "success"
                and exit_code == 0
                and artifact_status == "invalid"
                and cleanup_status == "verified_absent"
            ),
            "transport_error": (
                disposition == "failed"
                and command_status == "transport_error"
                and exit_code is None
                and artifact_status == "not_checked"
                and cleanup_status == "verified_absent"
            ),
            "cleanup_unverified": (
                disposition == "failed"
                and command_status == "cleanup_unverified"
                and exit_code is None
                and artifact_status == "not_checked"
                and cleanup_status in {"failed", "unverified"}
            ),
            "artifact_cleanup_unverified": (
                disposition == "failed"
                and artifact_status == "not_checked"
                and cleanup_status == "verified_absent"
                and (
                    (command_status == "success" and exit_code == 0)
                    or (command_status == "timeout" and exit_code is None)
                    or (command_status == "nonzero_exit" and exit_code not in (None, 0))
                    or (command_status == "transport_error" and exit_code is None)
                )
            ),
            "cancelled": (
                disposition == "cancelled"
                and command_status == "cancelled"
                and exit_code is None
                and artifact_status == "not_checked"
                and cleanup_status == "verified_absent"
            ),
        }
        if failure_category is not None and not failure_shape[failure_category]:
            raise CollectorAttemptPolicyError(
                f"{field} failure_category evidence is inconsistent"
            )

    return {
        "mode": mode,
        "disposition": disposition,
        "failure_category": failure_category,
        "command": {"status": command_status, "exit_code": exit_code},
        "artifact": {"status": artifact_status},
        "cleanup": {"scope": cleanup_scope, "status": cleanup_status},
    }


def project_attempt_policy(raw: Any) -> dict[str, Any]:
    """
    Return a strict, bounded, path-free status projection.

    The implementation uses ``raw`` to produce a strict, bounded, path-free
    status projection. If the function cannot produce a strict, bounded,
    path-free status projection, its exception reaches the caller instead of
    being converted into a successful result.

    Args:
        raw: Raw object whose ``get`` state is read while performing strict,
            bounded, path-free status projection.

    Returns:
        A mapping containing the ``schema_version``, ``policy``, ``enforced``,
        ``ordered_modes``, and ``fallback_on`` fields.

    Raises:
        CollectorAttemptPolicyError: If the attempt_policy is not a mapping;
            attempt_policy schema_version is unsupported; the attempt_policy is
            not enforced first_success; or attempt_policy ordered_modes is
            invalid; or another input invariant is violated.
    """

    if not isinstance(raw, Mapping):
        raise CollectorAttemptPolicyError("attempt_policy must be a mapping")
    if raw.get("schema_version") != ATTEMPT_POLICY_SCHEMA_VERSION:
        raise CollectorAttemptPolicyError(
            "attempt_policy schema_version is unsupported"
        )
    if raw.get("policy") != "first_success" or raw.get("enforced") is not True:
        raise CollectorAttemptPolicyError(
            "attempt_policy must be enforced first_success"
        )

    raw_modes = raw.get("ordered_modes")
    if not isinstance(raw_modes, list) or not 2 <= len(raw_modes) <= MAX_ATTEMPT_MODES:
        raise CollectorAttemptPolicyError("attempt_policy ordered_modes is invalid")
    ordered_modes = [
        _mode_name(mode, f"attempt_policy.ordered_modes[{index}]")
        for index, mode in enumerate(raw_modes)
    ]
    if len(set(ordered_modes)) != len(ordered_modes):
        raise CollectorAttemptPolicyError("attempt_policy ordered_modes must be unique")

    raw_fallback_on = raw.get("fallback_on")
    if not isinstance(raw_fallback_on, list) or not raw_fallback_on:
        raise CollectorAttemptPolicyError("attempt_policy fallback_on is invalid")
    fallback_on = list(raw_fallback_on)
    if len(set(fallback_on)) != len(fallback_on) or not set(fallback_on).issubset(
        _FALLBACK_FAILURES
    ):
        raise CollectorAttemptPolicyError("attempt_policy fallback_on is unsupported")

    cleanup = raw.get("cleanup")
    if not isinstance(cleanup, Mapping):
        raise CollectorAttemptPolicyError("attempt_policy cleanup must be a mapping")
    containment = _cleanup_scope(
        cleanup.get("containment", "process_group"),
        "attempt_policy cleanup containment",
    )
    expected_cleanup = {
        "process_group": (
            "verified_owned_process_group_exit",
            "foreground_non_daemonizing",
        ),
        "cgroup_v2": (
            "verified_owned_cgroup_v2_exit",
            "cgroup_v2_contained",
        ),
    }[containment]
    if (
        cleanup.get("requirement"),
        cleanup.get("command_lifecycle"),
    ) != expected_cleanup:
        raise CollectorAttemptPolicyError("attempt_policy cleanup contract is invalid")

    selected_mode = raw.get("selected_mode")
    if selected_mode is not None and selected_mode not in ordered_modes:
        raise CollectorAttemptPolicyError("attempt_policy selected_mode is invalid")
    fallback_used = raw.get("fallback_used")
    if not isinstance(fallback_used, bool):
        raise CollectorAttemptPolicyError(
            "attempt_policy fallback_used must be boolean"
        )
    terminal_reason = raw.get("terminal_reason")
    if terminal_reason not in _TERMINAL_REASONS:
        raise CollectorAttemptPolicyError("attempt_policy terminal_reason is invalid")

    raw_attempts = raw.get("attempts")
    if not isinstance(raw_attempts, list) or len(raw_attempts) != len(ordered_modes):
        raise CollectorAttemptPolicyError(
            "attempt_policy attempts must cover every ordered mode"
        )
    attempts = [
        _project_attempt(attempt, f"attempt_policy.attempts[{index}]")
        for index, attempt in enumerate(raw_attempts)
    ]
    if [attempt["mode"] for attempt in attempts] != ordered_modes:
        raise CollectorAttemptPolicyError(
            "attempt_policy attempt order must match ordered_modes"
        )
    if any(attempt["cleanup"]["scope"] != containment for attempt in attempts):
        raise CollectorAttemptPolicyError(
            "attempt_policy attempt cleanup scope does not match its policy"
        )

    projected_cleanup = {
        "requirement": expected_cleanup[0],
        "command_lifecycle": expected_cleanup[1],
    }
    if containment != "process_group":
        projected_cleanup["containment"] = containment

    successful_modes = [
        attempt["mode"] for attempt in attempts if attempt["disposition"] == "success"
    ]
    if successful_modes != ([] if selected_mode is None else [selected_mode]):
        raise CollectorAttemptPolicyError(
            "attempt_policy selected_mode must identify the only successful attempt"
        )
    first_fallback_started = attempts[1]["disposition"] != "not_attempted"
    if fallback_used != first_fallback_started:
        raise CollectorAttemptPolicyError(
            "attempt_policy fallback_used does not match executed attempts"
        )
    if selected_mode == ordered_modes[0] and terminal_reason != "preferred_success":
        raise CollectorAttemptPolicyError(
            "preferred success requires terminal_reason preferred_success"
        )
    if selected_mode in ordered_modes[1:] and terminal_reason != "fallback_success":
        raise CollectorAttemptPolicyError(
            "fallback success requires terminal_reason fallback_success"
        )
    if selected_mode is None and terminal_reason in {
        "preferred_success",
        "fallback_success",
    }:
        raise CollectorAttemptPolicyError(
            "attempt_policy success terminal_reason requires selected_mode"
        )
    if selected_mode is not None:
        selected_index = ordered_modes.index(selected_mode)
        if any(
            attempt["disposition"] != "not_attempted"
            for attempt in attempts[selected_index + 1 :]
        ):
            raise CollectorAttemptPolicyError(
                "attempt_policy ran a mode after first success"
            )
    for index, attempt in enumerate(attempts[:-1]):
        next_started = attempts[index + 1]["disposition"] != "not_attempted"
        if next_started and (
            attempt["disposition"] != "failed"
            or attempt["failure_category"] not in fallback_on
            or attempt["cleanup"]["status"] != "verified_absent"
        ):
            raise CollectorAttemptPolicyError(
                "attempt_policy fallback transition was not eligible"
            )

    started_attempts = [
        attempt for attempt in attempts if attempt["disposition"] != "not_attempted"
    ]
    last_started = started_attempts[-1] if started_attempts else None
    if selected_mode is None:
        if terminal_reason == "cleanup_unverified" and (
            last_started is None
            or last_started["failure_category"] != "cleanup_unverified"
            or last_started["cleanup"]["status"] not in {"failed", "unverified"}
        ):
            raise CollectorAttemptPolicyError(
                "cleanup_unverified terminal reason requires unverified cleanup"
            )
        if terminal_reason == "artifact_cleanup_unverified" and (
            last_started is None
            or last_started["failure_category"] != "artifact_cleanup_unverified"
            or last_started["cleanup"]["status"] != "verified_absent"
        ):
            raise CollectorAttemptPolicyError(
                "artifact_cleanup_unverified terminal reason requires unverified "
                "artifact cleanup"
            )
        if terminal_reason == "noneligible_failure" and (
            last_started is None
            or last_started["disposition"] != "failed"
            or last_started["failure_category"] in fallback_on
            or last_started["failure_category"] == "artifact_cleanup_unverified"
            or last_started["cleanup"]["status"] != "verified_absent"
            or last_started["mode"] == ordered_modes[-1]
        ):
            raise CollectorAttemptPolicyError(
                "noneligible_failure terminal reason is inconsistent"
            )
        if terminal_reason == "attempts_exhausted" and (
            not fallback_used
            or last_started is None
            or last_started["mode"] != ordered_modes[-1]
            or last_started["disposition"] != "failed"
            or last_started["failure_category"] == "artifact_cleanup_unverified"
            or last_started["cleanup"]["status"] != "verified_absent"
        ):
            raise CollectorAttemptPolicyError(
                "attempts_exhausted terminal reason is inconsistent"
            )
        if terminal_reason == "cancelled" and (
            last_started is None or last_started["disposition"] != "cancelled"
        ):
            raise CollectorAttemptPolicyError(
                "cancelled terminal reason requires a cancelled attempt"
            )
        if terminal_reason == "internal_error" and started_attempts:
            raise CollectorAttemptPolicyError(
                "internal_error receipt must not claim a completed attempt"
            )

    return {
        "schema_version": ATTEMPT_POLICY_SCHEMA_VERSION,
        "policy": "first_success",
        "enforced": True,
        "ordered_modes": ordered_modes,
        "fallback_on": fallback_on,
        "cleanup": projected_cleanup,
        "selected_mode": selected_mode,
        "fallback_used": fallback_used,
        "terminal_reason": terminal_reason,
        "attempts": attempts,
    }


def project_additive_attempts(raw: Any) -> list[dict[str, Any]]:
    """
    Project bounded additive-mode evidence without paths or raw output.

    The implementation uses ``raw`` to project bounded additive-mode evidence
    without paths or raw output. If the function cannot project bounded
    additive-mode evidence without paths or raw output, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        raw: Entries supplied as ``raw`` and processed in caller-provided order.

    Returns:
        The validated ``projected``.

    Raises:
        CollectorAttemptPolicyError: If additive_attempts must contain at most
            ``MAX_ATTEMPT_MODES`` entries; the ``field`` is not a mapping;
            additive_attempts must have unique modes; or the ``field`` is not
            executed or explicitly skipped.
    """

    if not isinstance(raw, list) or len(raw) > MAX_ATTEMPT_MODES:
        raise CollectorAttemptPolicyError(
            f"additive_attempts must contain at most {MAX_ATTEMPT_MODES} entries"
        )
    projected: list[dict[str, Any]] = []
    modes: set[str] = set()
    for index, entry in enumerate(raw):
        field = f"additive_attempts[{index}]"
        if not isinstance(entry, Mapping):
            raise CollectorAttemptPolicyError(f"{field} must be a mapping")
        mode = _mode_name(entry.get("mode"), f"{field}.mode")
        if mode in modes:
            raise CollectorAttemptPolicyError(
                "additive_attempts must have unique modes"
            )
        modes.add(mode)
        disposition = entry.get("disposition")
        if disposition in _ADDITIVE_SKIP_DISPOSITIONS:
            projected.append({"mode": mode, "disposition": disposition})
            continue
        attempt = _project_attempt(entry, field)
        if attempt["disposition"] == "not_attempted":
            raise CollectorAttemptPolicyError(
                f"{field} must be executed or explicitly skipped"
            )
        projected.append(attempt)
    return projected


def project_advanced_managed_receipt(raw: Any) -> dict[str, Any]:
    """
    Project one strict single-attempt advanced managed receipt.

    The projection deliberately excludes paths, timings, and arbitrary
    nested context. Its canonical attempt record proves command outcome,
    artifact integrity, and cgroup-v2 cleanup as one inseparable lifecycle.

    Args:
        raw: Candidate serialized receipt from an advanced collector.

    Returns:
        A canonical advanced managed receipt with exactly one attempt.

    Raises:
        CollectorAttemptPolicyError: If the receipt or its attempt is
            malformed, noncanonical, or not cgroup-v2 owned.
    """

    if not isinstance(raw, Mapping) or set(raw) != {
        "schema_version",
        "policy",
        "enforced",
        "attempt",
    }:
        raise CollectorAttemptPolicyError("advanced managed receipt shape is invalid")
    if (
        raw.get("schema_version") != "1.0"
        or raw.get("policy") != "single_managed_advanced"
        or raw.get("enforced") is not True
    ):
        raise CollectorAttemptPolicyError("advanced managed receipt policy is invalid")
    candidate = raw.get("attempt")
    if not isinstance(candidate, Mapping):
        raise CollectorAttemptPolicyError("advanced managed receipt attempt is invalid")
    command = candidate.get("command")
    artifact = candidate.get("artifact")
    cleanup = candidate.get("cleanup")
    if not all(isinstance(value, Mapping) for value in (command, artifact, cleanup)):
        raise CollectorAttemptPolicyError("advanced managed receipt attempt is invalid")
    projected_attempt = attempt_record(
        candidate.get("mode"),
        disposition=candidate.get("disposition"),
        failure_category=candidate.get("failure_category"),
        command_status=command.get("status"),
        exit_code=command.get("exit_code"),
        artifact_status=artifact.get("status"),
        cleanup_status=cleanup.get("status"),
        cleanup_scope=cleanup.get("scope"),
    )
    if projected_attempt != candidate:
        raise CollectorAttemptPolicyError(
            "advanced managed receipt attempt is noncanonical"
        )
    if projected_attempt["cleanup"]["scope"] != "cgroup_v2":
        raise CollectorAttemptPolicyError(
            "advanced managed receipt requires cgroup_v2 ownership"
        )
    return {
        "schema_version": "1.0",
        "policy": "single_managed_advanced",
        "enforced": True,
        "attempt": projected_attempt,
    }
