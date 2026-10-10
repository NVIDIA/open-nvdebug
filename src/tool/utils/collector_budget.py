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
Collector operation, retry, remote-task, and wall-budget contracts.

The historical catalog ``timeout`` is an operation timeout. It is deliberately
not reinterpreted as a collector deadline here. A collector gets an enforced
wall deadline only when its catalog entry contains an explicit, reviewed
``runtime_budget`` contract.

The projection is a conservative planning model. It accounts for declared serial
work, fallback chains, pagination, and retry attempts, then applies the
independent collector wall ceiling. Catalog entries without the new contract
retain their historical execution behaviour and receive a clearly-labelled
legacy estimate rather than a claimed upper bound.
"""

from __future__ import annotations

import hashlib
import heapq
import inspect
import math
import re
import secrets
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from .redfish_limits import MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS

RUNTIME_BUDGET_SCHEMA_VERSION = "1.0"
MAX_BUDGET_SECONDS = 7 * 24 * 60 * 60
MAX_PROJECTION_SECONDS = 10 * 365 * 24 * 60 * 60
MAX_PROJECTION_ITEMS = 64
MAX_PROJECTION_COUNT = 100_000
MAX_POLICY_TEXT = 1024
COLLECTOR_CANCELLATION_GRACE_SECONDS = 5.0
MAX_ENFORCED_FALLBACK_MODES = 8
MAX_FALLBACK_ADDITIVE_MODES = 8
MAX_MANAGED_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024
FALLBACK_FAILURE_KINDS = frozenset(
    {"timeout", "nonzero_exit", "missing_artifact", "invalid_artifact"}
)
FALLBACK_CLEANUP_REQUIREMENTS = frozenset(
    {"verified_owned_process_group_exit", "verified_owned_cgroup_v2_exit"}
)
FALLBACK_COMMAND_LIFECYCLES = frozenset(
    {"foreground_non_daemonizing", "cgroup_v2_contained"}
)
FALLBACK_CONTAINMENTS = frozenset({"process_group", "cgroup_v2"})
_FALLBACK_MODE_NAME = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")
_HMC_DOMAIN_HASH_KEY = secrets.token_bytes(16)


class CollectorBudgetError(ValueError):
    """
    Raised when a catalog runtime-budget contract is malformed.

    Callers receive this exception when the collector budget error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


async def resolve_effective_runtime_config(
    orchestrator: Any,
    dut_manager: Any,
    dut_id: str,
) -> dict[str, Any]:
    """
    Resolve the one runtime-config view used by plans and execution.

    The orchestrator's per-DUT getter is authoritative when present because it
    owns ConfigFile/global merging. A getter failure or a non-mapping result is
    a planning/execution safety error, not permission to silently choose a
    different fallback. The live DUT mapping is applied last so explicit DUT
    values have the same precedence at every call site.

    Args:
        orchestrator: Orchestrator consumed while the function attempts to
            resolve the one runtime-config view used by plans and execution.
        dut_manager: DUT manager object whose ``get_dut`` state is read while
            performing one runtime-config view used by plans and execution.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.

    Returns:
        The validated ``resolved``.

    Raises:
        CollectorBudgetError: If failed to resolve effective runtime config for
            DUT ``dut_id``; the effective runtime config for dut ``dut_id`` is
            not a mapping; failed to resolve global runtime config; or the
            global runtime config is not a mapping; or another input invariant
            is violated.
    """

    resolved: dict[str, Any] = {}
    effective_getter = getattr(orchestrator, "get_dut_specific_tool_config", None)
    if callable(effective_getter):
        try:
            effective = effective_getter(dut_id)
            if inspect.isawaitable(effective):
                effective = await effective
        except Exception as error:
            raise CollectorBudgetError(
                f"failed to resolve effective runtime config for DUT {dut_id}"
            ) from error
        if not isinstance(effective, Mapping):
            raise CollectorBudgetError(
                f"effective runtime config for DUT {dut_id} must be a mapping"
            )
        resolved.update(effective)
    else:
        config_manager = getattr(orchestrator, "config_manager", None)
        global_getter = getattr(config_manager, "get_tool_config", None)
        if callable(global_getter):
            try:
                global_config = global_getter() or {}
            except Exception as error:
                raise CollectorBudgetError(
                    "failed to resolve global runtime config"
                ) from error
            if not isinstance(global_config, Mapping):
                raise CollectorBudgetError("global runtime config must be a mapping")
            resolved.update(global_config)
        else:
            manager_config = getattr(dut_manager, "tool_config", {}) or {}
            if not isinstance(manager_config, Mapping):
                raise CollectorBudgetError("manager runtime config must be a mapping")
            resolved.update(manager_config)

    dut_getter = getattr(dut_manager, "get_dut_config", None)
    if callable(dut_getter):
        try:
            dut_config = dut_getter(dut_id) or {}
        except Exception as error:
            raise CollectorBudgetError(
                f"failed to resolve runtime config for DUT {dut_id}"
            ) from error
    else:
        try:
            dut = dut_manager.get_dut(dut_id)
        except Exception as error:
            raise CollectorBudgetError(
                f"failed to resolve runtime config for DUT {dut_id}"
            ) from error
        dut_config = getattr(dut, "config", {}) or {}
    if not isinstance(dut_config, Mapping):
        raise CollectorBudgetError(f"runtime config for DUT {dut_id} must be a mapping")
    resolved.update(dut_config)
    live_getter = getattr(dut_manager, "get_dut", None)
    if callable(live_getter):
        try:
            live_dut = live_getter(dut_id)
        except Exception:
            live_dut = None
        live_config = getattr(live_dut, "config", None)
        if isinstance(live_config, Mapping):
            resolved.update(live_config)
    return resolved


def hmc_diagnostic_serialization_domain_id(
    dut_manager: Any,
    dut_id: str,
) -> Optional[str]:
    """
    Return an opaque shared-domain ID only for HMC-forwarded Redfish.

    The live Redfish lock uses this shared helper so its domain remains stable
    for the process lifetime without exposing a hostname or address in logs or
    future evidence surfaces. A process-local key prevents offline enumeration
    of common internal addresses from the logged digest.

    Args:
        dut_manager: DUT manager object whose ``get_dut`` state is read while
            performing opaque shared-domain ID only for HMC-forwarded Redfish.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.

    Returns:
        The canonical HMC diagnostic serialization domain identifier text, or
        ``None`` when the requested value is unavailable.
    """

    try:
        dut = dut_manager.get_dut(dut_id)
    except Exception:
        dut = None
    credentials = getattr(dut, "credentials", None)
    live_config = getattr(dut, "config", None)
    config = dict(live_config) if isinstance(live_config, Mapping) else {}
    getter = getattr(dut_manager, "get_dut_config", None)
    if callable(getter):
        try:
            manager_config = getter(dut_id)
        except Exception:
            manager_config = None
        if isinstance(manager_config, Mapping):
            # The live DUT object is authoritative, matching runtime routing.
            config = {**manager_config, **config}

    access_method = getattr(credentials, "rf_hmc_access_method", None)
    if not isinstance(access_method, str) or not access_method.strip():
        access_method = config.get("RF_HMC_ACCESS_METHOD", "")
    if not isinstance(access_method, str):
        return None
    normalized_method = re.sub(r"[^a-z0-9]", "", access_method.casefold())
    if not normalized_method.endswith("portforwarding"):
        return None

    hmc_target = getattr(credentials, "hmc_ip", None)
    if not isinstance(hmc_target, (str, int)) or not str(hmc_target).strip():
        hmc_target = config.get("HMC_IP") or config.get("hmc_ip")
    normalized_target = (
        str(hmc_target).strip().casefold()
        if isinstance(hmc_target, (str, int)) and str(hmc_target).strip()
        else "shared"
    )
    digest = hashlib.blake2s(
        normalized_target.encode("utf-8"),
        key=_HMC_DOMAIN_HASH_KEY,
        digest_size=8,
    ).hexdigest()
    return f"hmc-diagnostic:{digest}"


def project_discovered_diagnostic_work(
    target_counts_by_system: Mapping[str, int],
    per_target_timeout_seconds: float,
    *,
    parallel_systems: bool,
    max_concurrent_systems: int,
    shared_hmc_serialization: bool,
    planning_max_targets_per_dut: Optional[int] = None,
) -> dict[str, Any]:
    """
    Describe discovered diagnostic work without creating a kill deadline.

    Diagnostic collectors such as R35, R36, and R37 learn their target count
    only after capability and device discovery.  A static collector wall cannot
    safely represent that work.  This projection uses the discovered per-system
    target counts and the actual scheduling mode to expose a conservative local
    critical path.  It is evidence for planning and reporting only; callers must
    not turn it into an implicit collector cancellation boundary.

    When multiple DUTs share an HMC diagnostic slot, the run-level critical path
    is the sum of target slots within that serialization domain.  This helper has
    one DUT's task graph, so it explicitly marks that cross-DUT aggregation is
    still required instead of pretending the local projection is the run total.
    Independent serialization domains can run concurrently, making the run-level
    diagnostic critical path the maximum of their domain totals.

    Args:
        target_counts_by_system: Mapping from each discovered system to its
            number of diagnostic targets.
        per_target_timeout_seconds: Spreadsheet/configured timeout for one
            diagnostic target lifecycle.
        parallel_systems: Whether different systems may execute concurrently.
        max_concurrent_systems: Maximum number of concurrently executing
            systems when parallel execution is enabled.
        shared_hmc_serialization: Whether one shared HMC diagnostic slot
            serializes the selected DUT's target lifecycles.
        planning_max_targets_per_dut: Optional advisory platform cardinality
            from the selected baseboard. It is compared with discovery but is
            never enforced.

    Returns:
        An observed-only mapping containing discovered cardinality, local
        critical-path work, fully serialized work, and run aggregation
        semantics.

    Raises:
        CollectorBudgetError: If counts, timeouts, concurrency, or mode flags
            are malformed or the resulting projection is not finite.
    """

    if not isinstance(target_counts_by_system, Mapping):
        raise CollectorBudgetError(
            "target_counts_by_system must be a mapping of system names to counts"
        )
    if isinstance(per_target_timeout_seconds, bool) or not isinstance(
        per_target_timeout_seconds, (int, float)
    ):
        raise CollectorBudgetError("per_target_timeout_seconds must be numeric")
    timeout = float(per_target_timeout_seconds)
    if not math.isfinite(timeout) or timeout <= 0:
        raise CollectorBudgetError(
            "per_target_timeout_seconds must be positive and finite"
        )
    if not isinstance(parallel_systems, bool):
        raise CollectorBudgetError("parallel_systems must be boolean")
    if not isinstance(shared_hmc_serialization, bool):
        raise CollectorBudgetError("shared_hmc_serialization must be boolean")
    if (
        isinstance(max_concurrent_systems, bool)
        or not isinstance(max_concurrent_systems, int)
        or max_concurrent_systems <= 0
    ):
        raise CollectorBudgetError("max_concurrent_systems must be a positive integer")
    concurrency = max_concurrent_systems
    if planning_max_targets_per_dut is not None and (
        isinstance(planning_max_targets_per_dut, bool)
        or not isinstance(planning_max_targets_per_dut, int)
        or planning_max_targets_per_dut <= 0
    ):
        raise CollectorBudgetError(
            "planning_max_targets_per_dut must be a positive integer"
        )

    system_target_counts: list[int] = []
    for system_name, raw_count in target_counts_by_system.items():
        if not isinstance(system_name, str) or not system_name:
            raise CollectorBudgetError(
                "target_counts_by_system keys must be non-empty strings"
            )
        if (
            isinstance(raw_count, bool)
            or not isinstance(raw_count, int)
            or raw_count < 0
        ):
            raise CollectorBudgetError(
                f"target_counts_by_system[{system_name!r}] must be a nonnegative integer"
            )
        count = raw_count
        system_target_counts.append(count)

    total_targets = sum(system_target_counts)
    nonempty_system_counts = [count for count in system_target_counts if count]
    if not nonempty_system_counts:
        effective_concurrency = 0
        critical_path_slots = 0
    elif shared_hmc_serialization or not parallel_systems:
        effective_concurrency = 1
        critical_path_slots = total_targets
    else:
        effective_concurrency = min(concurrency, len(nonempty_system_counts))
        slot_loads = [0] * effective_concurrency
        heapq.heapify(slot_loads)
        # The runtime creates system tasks in this same stable mapping order and
        # admits them through a semaphore.  Simulating that list schedule gives
        # the local critical-path slot count without assuming per-device
        # parallelism inside a system.
        for count in nonempty_system_counts:
            earliest = heapq.heappop(slot_loads)
            heapq.heappush(slot_loads, earliest + count)
        critical_path_slots = max(slot_loads)

    fully_serialized_seconds = float(total_targets) * timeout
    critical_path_seconds = float(critical_path_slots) * timeout
    if not math.isfinite(fully_serialized_seconds) or not math.isfinite(
        critical_path_seconds
    ):
        raise CollectorBudgetError("diagnostic work projection is not finite")

    planning_profile = {
        "available": planning_max_targets_per_dut is not None,
        "planning_max_targets_per_dut": planning_max_targets_per_dut,
        "projected_max_remote_task_seconds_per_dut": (
            float(planning_max_targets_per_dut) * timeout
            if planning_max_targets_per_dut is not None
            else None
        ),
        "discovered_targets_exceed_profile": (
            total_targets > planning_max_targets_per_dut
            if planning_max_targets_per_dut is not None
            else None
        ),
        "enforced": False,
    }

    return {
        "schema_version": RUNTIME_BUDGET_SCHEMA_VERSION,
        "scope": "selected_dut_discovered_targets",
        "target_count": total_targets,
        "system_count": len(nonempty_system_counts),
        "per_target_timeout_seconds": timeout,
        "parallel_systems": parallel_systems,
        "configured_max_concurrent_systems": concurrency,
        "effective_system_concurrency": effective_concurrency,
        "shared_hmc_serialization": shared_hmc_serialization,
        "critical_path_target_slots": critical_path_slots,
        "projected_critical_path_seconds": critical_path_seconds,
        "fully_serialized_target_slots": total_targets,
        "fully_serialized_seconds": fully_serialized_seconds,
        "fixed_overhead_included": False,
        "requires_cross_dut_domain_aggregation": shared_hmc_serialization,
        "run_aggregation": (
            "sum_within_each_shared_serialization_domain_then_max_across_domains"
            if shared_hmc_serialization
            else "max_across_independent_duts"
        ),
        "planning_profile": planning_profile,
        "available": True,
        "enforced": False,
    }


def runtime_budget_requires_runtime_config(
    collector_definition: Mapping[str, Any],
) -> bool:
    """
    Return whether a budget contract references a live config key.

    This deliberately performs only routing discovery; the full resolver still
    owns schema validation. Legacy collectors and fixed explicit contracts do
    not need an effective-config read and therefore retain historical behavior
    when an unrelated config provider is unavailable.

    Args:
        collector_definition: Mapping supplying fields for budget contract
            references a live config key.

    Returns:
        Whether a budget contract references a live config key.
    """

    runtime_budget = collector_definition.get("runtime_budget")
    if not isinstance(runtime_budget, Mapping):
        return False
    if runtime_budget.get("operation_timeout_config") or runtime_budget.get(
        "remote_task_timeout_config"
    ):
        return True
    pagination = runtime_budget.get("pagination")
    if isinstance(pagination, Mapping) and pagination.get("max_pages_config_key"):
        return True
    projection = runtime_budget.get("projection")
    if isinstance(projection, Mapping):
        serial_steps = projection.get("serial_steps")
        if isinstance(serial_steps, list) and any(
            isinstance(step, Mapping) and step.get("enabled_config_key")
            for step in serial_steps
        ):
            return True
    fallback = runtime_budget.get("fallback")
    if isinstance(fallback, Mapping):
        modes = fallback.get("modes")
        if isinstance(modes, list) and any(
            isinstance(mode, Mapping) and mode.get("enabled_config_key")
            for mode in modes
        ):
            return True
    return False


def _positive_number(value: Any, field: str, *, maximum: float) -> float:
    """
    Return the positive number.

    The implementation uses ``value``, ``field``, and ``maximum`` to produce the
    positive number. If the function cannot produce the positive number, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        value: Value evaluated while performing positive number.
        field: Text supplied as field in the format accepted by this function.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.

    Returns:
        The validated ``number``.

    Raises:
        CollectorBudgetError: If the ``field`` is not a positive number; or the
            ``field`` is not greater than zero and at most ``maximum``.
    """
    if isinstance(value, bool):
        raise CollectorBudgetError(f"{field} must be a positive number")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise CollectorBudgetError(f"{field} must be a positive number") from error
    if not math.isfinite(number) or number <= 0 or number > maximum:
        raise CollectorBudgetError(
            f"{field} must be greater than zero and at most {maximum:g}"
        )
    return number


def _nonnegative_number(value: Any, field: str, *, maximum: float) -> float:
    """
    Return the nonnegative number.

    The implementation uses ``value``, ``field``, and ``maximum`` to produce the
    nonnegative number. If the function cannot produce the nonnegative number,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        value: Value evaluated while performing nonnegative number.
        field: Text supplied as field in the format accepted by this function.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.

    Returns:
        The validated ``number``.

    Raises:
        CollectorBudgetError: If the ``field`` is not a non-negative number; or
            the ``field`` is not non-negative and at most ``maximum``.
    """
    if isinstance(value, bool):
        raise CollectorBudgetError(f"{field} must be a non-negative number")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise CollectorBudgetError(f"{field} must be a non-negative number") from error
    if not math.isfinite(number) or number < 0 or number > maximum:
        raise CollectorBudgetError(
            f"{field} must be non-negative and at most {maximum:g}"
        )
    return number


def _nonnegative_int(value: Any, field: str, *, maximum: int) -> int:
    """
    Return the nonnegative int.

    The implementation uses ``value``, ``field``, and ``maximum`` to produce the
    nonnegative int. If the function cannot produce the nonnegative int, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        value: Value object whose ``strip`` state is read while performing
            nonnegative int.
        field: Text supplied as field in the format accepted by this function.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.

    Returns:
        The validated ``number``.

    Raises:
        CollectorBudgetError: If the ``field`` is not a non-negative integer; or
            the ``field`` is not between zero and ``maximum``.
    """
    if isinstance(value, bool):
        raise CollectorBudgetError(f"{field} must be a non-negative integer")
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise CollectorBudgetError(f"{field} must be a non-negative integer") from error
    if number != value and not (
        isinstance(value, str) and str(number) == value.strip()
    ):
        raise CollectorBudgetError(f"{field} must be a non-negative integer")
    if number < 0 or number > maximum:
        raise CollectorBudgetError(f"{field} must be between zero and {maximum}")
    return number


def _positive_int(value: Any, field: str, *, maximum: int) -> int:
    """
    Validate an authored positive integer without coercing strings/floats.

    The implementation uses ``value``, ``field``, and ``maximum`` to validate an
    authored positive integer without coercing strings/floats. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing authored positive integer
            without coercing strings/floats.
        field: Text supplied as field in the format accepted by this function.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.

    Returns:
        The validated ``value``.

    Raises:
        CollectorBudgetError: If the ``field`` is not a positive integer; or the
            ``field`` is not between 1 and ``maximum``.
    """

    if isinstance(value, bool) or not isinstance(value, int):
        raise CollectorBudgetError(f"{field} must be a positive integer")
    if not 1 <= value <= maximum:
        raise CollectorBudgetError(f"{field} must be between 1 and {maximum}")
    return value


def _bounded_text(value: Any, field: str, *, required: bool = False) -> str:
    """
    Return the bounded text.

    The implementation uses ``value``, ``field``, and ``required`` to produce
    the bounded text. If the function cannot produce the bounded text, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        value: Value object whose ``strip`` state is read while performing
            bounded text.
        field: Text supplied as field in the format accepted by this function.
        required: Whether required is enabled or required for this operation.

    Returns:
        The canonical bounded text.

    Raises:
        CollectorBudgetError: If the ``field`` is not a string; the ``field`` is
            not ``qualifier``string of at most ``MAX_POLICY_TEXT`` characters;
            or ``field`` contains control characters.
    """
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise CollectorBudgetError(f"{field} must be a string")
    text = value.strip()
    if (required and not text) or len(text) > MAX_POLICY_TEXT:
        qualifier = "a non-empty " if required else "a "
        raise CollectorBudgetError(
            f"{field} must be {qualifier}string of at most {MAX_POLICY_TEXT} characters"
        )
    if any(ord(character) < 32 and character not in "\t\n" for character in text):
        raise CollectorBudgetError(f"{field} contains control characters")
    return text


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    """
    Return the mapping.

    The implementation uses ``value`` and ``field`` to produce the mapping. If
    the function cannot produce the mapping, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        value: Value evaluated while performing mapping.
        field: Text supplied as field in the format accepted by this function.

    Returns:
        A mapping containing mapping.

    Raises:
        CollectorBudgetError: If the ``field`` is not a mapping.
    """
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise CollectorBudgetError(f"{field} must be a mapping")
    return value


def _reject_unknown_keys(
    value: Mapping[str, Any],
    allowed_keys: set[str],
    field: str,
) -> None:
    """
    Fail closed on authored safety-contract fields we do not understand.

    The implementation uses ``value``, ``allowed_keys``, and ``field`` to fail
    closed on authored safety-contract fields we do not understand. If the
    function cannot fail closed on authored safety-contract fields we do not
    understand, its exception reaches the caller instead of being converted into
    a successful result.

    Args:
        value: Mapping supplying fields for fail closed on authored
            safety-contract fields we do not understand.
        allowed_keys: Entries supplied as ``allowed_keys`` without transferring
            container ownership.
        field: Text supplied as field in the format accepted by this function.

    Raises:
        CollectorBudgetError: If a configured resource limit is exceeded while
            attempting to fail closed on authored safety-contract fields we do
            not understand.
    """

    unknown = sorted(str(key) for key in value if key not in allowed_keys)
    if unknown:
        raise CollectorBudgetError(
            f"{field} contains unsupported field(s): {', '.join(unknown)}"
        )


def _retry_backoff_seconds(max_retries: int) -> float:
    """
    Match the bounded exponential transport backoff used by Redfish.

    After applying local validation, the function forwards ``max_retries`` to
    ``float`` and preserves its return and exception contract.

    Args:
        max_retries: Upper bound enforced for max retries; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        The numeric retry backoff seconds.
    """

    return float(sum(min(2**attempt, 30) for attempt in range(max_retries)))


def _config_enabled(
    config: Optional[Mapping[str, Any]], key: str, default: bool
) -> bool:
    """
    Return the config enabled.

    The implementation uses ``config``, ``key``, and ``default`` to produce the
    config enabled.

    Args:
        config: Config governing config enabled.
        key: Stable key used for lookup and operator-facing diagnostics.
        default: Fallback used when the requested value is absent or invalid.

    Returns:
        Whether the config enabled operation succeeds.
    """
    if config is None or key not in config:
        return default
    return bool(config[key])


@dataclass(frozen=True)
class ResolvedCollectorBudget:
    """
    Validated public collector budget and preflight projection.

    The immutable record keeps ``collector_id``, ``operation_timeout_seconds``,
    ``remote_task_timeout_seconds``, ``max_retries``, and
    ``retry_backoff_seconds`` together so consumers observe one resolved
    collector budget state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        collector_id: Canonical text used as collector identifier.
        operation_timeout_seconds: Number of operation timeout seconds
            represented by this record.
        remote_task_timeout_seconds: Number of remote task timeout seconds
            represented by this record.
        max_retries: Maximum retries admitted by this record.
        retry_backoff_seconds: Number of retry backoff seconds represented by
            this record.
        retry_budget_seconds: Number of retry budget seconds represented by this
            record.
        wall_timeout_seconds: Number of wall timeout seconds represented by this
            record.
        enforce_wall_timeout: Whether enforce wall timeout applies to this
            record.
        projection_kind: Canonical text used as projection kind.
        uncapped_projection_seconds: Number of uncapped projection seconds
            represented by this record.
        projected_wall_seconds: Number of projected wall seconds represented by
            this record.
        projection_factors: Mapping that retains the projection factors fields
            for this record.
        policies: Mapping that retains the policies fields for this record.
        source: Canonical text used as source.
    """

    collector_id: str
    operation_timeout_seconds: float
    remote_task_timeout_seconds: Optional[float]
    max_retries: int
    retry_backoff_seconds: float
    retry_budget_seconds: float
    wall_timeout_seconds: Optional[float]
    enforce_wall_timeout: bool
    projection_kind: str
    uncapped_projection_seconds: float
    projected_wall_seconds: float
    projection_factors: tuple[Mapping[str, Any], ...]
    policies: Mapping[str, Any]
    source: str

    def to_dict(self) -> dict[str, Any]:
        """
        Return the to dict.

        The implementation uses current instance state to produce the to dict.

        Returns:
            A mapping containing the ``schema_version``, ``collector_id``,
            ``source``, ``operation``, and ``remote_task`` fields.
        """
        wall = {
            "budget_seconds": self.wall_timeout_seconds,
            "enforced": self.enforce_wall_timeout,
            "enforcement_mode": (
                "cooperative_async_with_post_return_overrun_detection"
                if self.enforce_wall_timeout
                else "observation_only"
            ),
            "hard_preemption": False,
            "cooperative_cancellation_grace_seconds": (
                COLLECTOR_CANCELLATION_GRACE_SECONDS
                if self.enforce_wall_timeout
                else None
            ),
        }
        return {
            "schema_version": RUNTIME_BUDGET_SCHEMA_VERSION,
            "collector_id": self.collector_id,
            "source": self.source,
            "operation": {
                "timeout_seconds": self.operation_timeout_seconds,
                "scope": "single_command_or_request",
            },
            "remote_task": {
                "timeout_seconds": self.remote_task_timeout_seconds,
                "scope": "single_remote_firmware_task",
            },
            "retry": {
                "max_retries_per_operation": self.max_retries,
                "max_attempts_per_operation": self.max_retries + 1,
                "backoff_budget_seconds": self.retry_backoff_seconds,
                "retry_budget_seconds": self.retry_budget_seconds,
                "scope": "per_retryable_operation",
            },
            "collector_wall": wall,
            "projection": {
                "kind": self.projection_kind,
                "uncapped_seconds": self.uncapped_projection_seconds,
                "projected_wall_seconds": self.projected_wall_seconds,
                "configured_deadline_seconds": (
                    self.wall_timeout_seconds if self.enforce_wall_timeout else None
                ),
                "capped_by_collector_wall": bool(
                    self.enforce_wall_timeout
                    and self.wall_timeout_seconds is not None
                    and self.uncapped_projection_seconds > self.wall_timeout_seconds
                ),
                "projection_reaches_configured_deadline": bool(
                    self.enforce_wall_timeout
                    and self.wall_timeout_seconds is not None
                    and self.projected_wall_seconds == self.wall_timeout_seconds
                ),
                "factors": [dict(factor) for factor in self.projection_factors],
            },
            "policies": dict(self.policies),
        }


def _resolve_serial_steps(
    projection: Mapping[str, Any],
    *,
    operation_timeout: float,
    remote_task_timeout: Optional[float],
    runtime_config: Optional[Mapping[str, Any]],
) -> tuple[float, list[Mapping[str, Any]]]:
    """
    Resolve serial steps.

    The implementation uses ``projection``, ``operation_timeout``,
    ``remote_task_timeout``, and ``runtime_config`` to resolve serial steps. If
    the function cannot resolve serial steps, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        projection: Mapping supplying fields for serial steps.
        operation_timeout: Maximum duration in seconds allowed for operation
            timeout.
        remote_task_timeout: Maximum duration in seconds allowed for remote task
            timeout.
        runtime_config: Runtime config governing serial steps.

    Returns:
        A tuple containing ``total`` and ``factors`` in that order.

    Raises:
        CollectorBudgetError: If the runtime_budget.projection.serial_steps are
            not a list of at most ``MAX_PROJECTION_ITEMS`` items;
            ``field``.timeout_source lacks remote_task_timeout_seconds; the
            ``field``.timeout_source is not operation, remote_task, or explicit;
            or the ``field``.enabled_by_default is not boolean; or another input
            invariant is violated.
    """
    raw_steps = projection.get("serial_steps", [])
    if raw_steps is None:
        raw_steps = []
    if not isinstance(raw_steps, list) or len(raw_steps) > MAX_PROJECTION_ITEMS:
        raise CollectorBudgetError(
            f"runtime_budget.projection.serial_steps must be a list of at most {MAX_PROJECTION_ITEMS} items"
        )

    total = 0.0
    factors: list[Mapping[str, Any]] = []
    for index, raw_step in enumerate(raw_steps):
        field = f"runtime_budget.projection.serial_steps[{index}]"
        step = _mapping(raw_step, field)
        _reject_unknown_keys(
            step,
            {
                "name",
                "count",
                "timeout_source",
                "timeout_seconds",
                "max_retries",
                "retry_backoff_seconds",
                "enabled_config_key",
                "enabled_by_default",
                "classification",
                "cancellation_grace_seconds",
            },
            field,
        )
        name = _bounded_text(step.get("name"), f"{field}.name", required=True)
        count = _nonnegative_int(
            step.get("count", 1), f"{field}.count", maximum=MAX_PROJECTION_COUNT
        )
        timeout_source = _bounded_text(
            step.get("timeout_source", "operation"),
            f"{field}.timeout_source",
            required=True,
        )
        if timeout_source == "operation":
            timeout = operation_timeout
        elif timeout_source == "remote_task":
            if remote_task_timeout is None:
                raise CollectorBudgetError(
                    f"{field}.timeout_source requires remote_task_timeout_seconds"
                )
            timeout = remote_task_timeout
        elif timeout_source == "explicit":
            timeout = _positive_number(
                step.get("timeout_seconds"),
                f"{field}.timeout_seconds",
                maximum=MAX_BUDGET_SECONDS,
            )
        else:
            raise CollectorBudgetError(
                f"{field}.timeout_source must be operation, remote_task, or explicit"
            )

        retries = _nonnegative_int(
            step.get("max_retries", 0),
            f"{field}.max_retries",
            maximum=100,
        )
        raw_retry_backoff = step.get("retry_backoff_seconds")
        retry_backoff = (
            _nonnegative_number(
                raw_retry_backoff,
                f"{field}.retry_backoff_seconds",
                maximum=MAX_BUDGET_SECONDS,
            )
            if raw_retry_backoff is not None
            else _retry_backoff_seconds(retries)
        )
        enabled_key = _bounded_text(
            step.get("enabled_config_key"), f"{field}.enabled_config_key"
        )
        enabled_by_default = step.get("enabled_by_default", True)
        if not isinstance(enabled_by_default, bool):
            raise CollectorBudgetError(f"{field}.enabled_by_default must be boolean")
        enabled = (
            _config_enabled(runtime_config, enabled_key, enabled_by_default)
            if enabled_key
            else True
        )
        classification = _bounded_text(
            step.get("classification"), f"{field}.classification"
        )
        cancellation_grace = _nonnegative_number(
            step.get("cancellation_grace_seconds", 0),
            f"{field}.cancellation_grace_seconds",
            maximum=60,
        )
        contribution = (
            float(count)
            * ((timeout + cancellation_grace) * float(retries + 1) + retry_backoff)
            if enabled
            else 0.0
        )
        if not math.isfinite(contribution) or contribution > MAX_PROJECTION_SECONDS:
            raise CollectorBudgetError(f"{field} projection is unreasonably large")
        total += contribution
        factor: dict[str, Any] = {
            "type": "serial_step",
            "name": name,
            "enabled": enabled,
            "count": count,
            "timeout_source": timeout_source,
            "timeout_seconds": timeout,
            "cancellation_grace_seconds": cancellation_grace,
            "max_retries": retries,
            "retry_backoff_seconds": retry_backoff,
            "contribution_seconds": contribution,
        }
        if enabled_key:
            factor["enabled_config_key"] = enabled_key
        if classification:
            factor["classification"] = classification
        factors.append(factor)
    return total, factors


def _resolve_fallback(
    raw_fallback: Mapping[str, Any],
    *,
    runtime_config: Optional[Mapping[str, Any]],
) -> tuple[float, Optional[Mapping[str, Any]], list[Mapping[str, Any]]]:
    """
    Resolve fallback.

    The implementation uses ``raw_fallback`` and ``runtime_config`` to resolve
    fallback. If the function cannot resolve fallback, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        raw_fallback: Mapping supplying fields for fallback.
        runtime_config: Runtime config governing fallback.

    Returns:
        A tuple containing the reserved duration, fallback policy, and additive
        modes.

    Raises:
        CollectorBudgetError: If the runtime_budget.fallback.policy is not
            first_success; the runtime_budget.fallback.enforce is not boolean;
            the runtime_budget.fallback.additive_modes are not a list of at most
            ``MAX_FALLBACK_ADDITIVE_MODES`` items; or the ``field`` is not a
            snake_case name of at most 64 characters; or another input invariant
            is violated.
    """
    if not raw_fallback:
        return 0.0, None, []
    _reject_unknown_keys(
        raw_fallback,
        {
            "policy",
            "enforce",
            "fallback_on",
            "cleanup",
            "modes",
            "additive_modes",
        },
        "runtime_budget.fallback",
    )
    policy = _bounded_text(
        raw_fallback.get("policy"), "runtime_budget.fallback.policy", required=True
    )
    if policy != "first_success":
        raise CollectorBudgetError(
            "runtime_budget.fallback.policy must be first_success"
        )

    enforce = raw_fallback.get("enforce", False)
    if not isinstance(enforce, bool):
        raise CollectorBudgetError("runtime_budget.fallback.enforce must be boolean")

    raw_additive_modes = raw_fallback.get("additive_modes", [])
    if (
        not isinstance(raw_additive_modes, list)
        or len(raw_additive_modes) > MAX_FALLBACK_ADDITIVE_MODES
    ):
        raise CollectorBudgetError(
            "runtime_budget.fallback.additive_modes must be a list of at most "
            f"{MAX_FALLBACK_ADDITIVE_MODES} items"
        )
    additive_modes: list[str] = []
    for index, raw_additive_mode in enumerate(raw_additive_modes):
        field = f"runtime_budget.fallback.additive_modes[{index}]"
        if not isinstance(raw_additive_mode, str) or not _FALLBACK_MODE_NAME.fullmatch(
            raw_additive_mode
        ):
            raise CollectorBudgetError(
                f"{field} must be a snake_case name of at most 64 characters"
            )
        if raw_additive_mode in additive_modes:
            raise CollectorBudgetError(
                "runtime_budget.fallback.additive_modes must contain unique names"
            )
        additive_modes.append(raw_additive_mode)

    raw_fallback_on = raw_fallback.get("fallback_on")
    raw_cleanup = raw_fallback.get("cleanup")
    fallback_on: list[str] = []
    cleanup_policy: dict[str, Any] = {}
    cleanup_timeout = 0.0
    if enforce:
        if (
            not isinstance(raw_fallback_on, list)
            or not raw_fallback_on
            or len(raw_fallback_on) > len(FALLBACK_FAILURE_KINDS)
        ):
            raise CollectorBudgetError(
                "runtime_budget.fallback.fallback_on must contain between 1 and "
                f"{len(FALLBACK_FAILURE_KINDS)} items"
            )
        for index, raw_failure_kind in enumerate(raw_fallback_on):
            field = f"runtime_budget.fallback.fallback_on[{index}]"
            failure_kind = _bounded_text(raw_failure_kind, field, required=True)
            if failure_kind not in FALLBACK_FAILURE_KINDS:
                choices = ", ".join(sorted(FALLBACK_FAILURE_KINDS))
                raise CollectorBudgetError(f"{field} must be one of: {choices}")
            if failure_kind in fallback_on:
                raise CollectorBudgetError(
                    "runtime_budget.fallback.fallback_on must contain unique items"
                )
            fallback_on.append(failure_kind)

        if raw_cleanup is None:
            raise CollectorBudgetError(
                "runtime_budget.fallback.enforce requires cleanup"
            )
        cleanup = _mapping(raw_cleanup, "runtime_budget.fallback.cleanup")
        _reject_unknown_keys(
            cleanup,
            {
                "requirement",
                "timeout_seconds",
                "command_lifecycle",
                "containment",
            },
            "runtime_budget.fallback.cleanup",
        )
        cleanup_requirement = _bounded_text(
            cleanup.get("requirement"),
            "runtime_budget.fallback.cleanup.requirement",
            required=True,
        )
        if cleanup_requirement not in FALLBACK_CLEANUP_REQUIREMENTS:
            choices = ", ".join(sorted(FALLBACK_CLEANUP_REQUIREMENTS))
            raise CollectorBudgetError(
                "runtime_budget.fallback.cleanup.requirement must be one of: "
                f"{choices}"
            )
        command_lifecycle = _bounded_text(
            cleanup.get("command_lifecycle"),
            "runtime_budget.fallback.cleanup.command_lifecycle",
            required=True,
        )
        if command_lifecycle not in FALLBACK_COMMAND_LIFECYCLES:
            choices = ", ".join(sorted(FALLBACK_COMMAND_LIFECYCLES))
            raise CollectorBudgetError(
                "runtime_budget.fallback.cleanup.command_lifecycle must be one of: "
                f"{choices}"
            )
        containment = _bounded_text(
            cleanup.get("containment", "process_group"),
            "runtime_budget.fallback.cleanup.containment",
            required=True,
        )
        if containment not in FALLBACK_CONTAINMENTS:
            choices = ", ".join(sorted(FALLBACK_CONTAINMENTS))
            raise CollectorBudgetError(
                "runtime_budget.fallback.cleanup.containment must be one of: "
                f"{choices}"
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
        if (cleanup_requirement, command_lifecycle) != expected_cleanup:
            raise CollectorBudgetError(
                "runtime_budget.fallback.cleanup requirement, lifecycle, and "
                "containment are inconsistent"
            )
        cleanup_timeout = _positive_number(
            cleanup.get("timeout_seconds"),
            "runtime_budget.fallback.cleanup.timeout_seconds",
            maximum=MAX_BUDGET_SECONDS,
        )
        cleanup_policy = {
            "requirement": cleanup_requirement,
            "timeout_seconds": cleanup_timeout,
            "command_lifecycle": command_lifecycle,
        }
        if containment != "process_group" or "containment" in cleanup:
            cleanup_policy["containment"] = containment
    elif raw_fallback_on is not None or raw_cleanup is not None:
        raise CollectorBudgetError(
            "runtime_budget.fallback.fallback_on and cleanup require enforce: true"
        )

    raw_modes = raw_fallback.get("modes")
    if not isinstance(raw_modes, list) or not raw_modes or len(raw_modes) > 32:
        raise CollectorBudgetError(
            "runtime_budget.fallback.modes must contain between 1 and 32 items"
        )
    if enforce and not 2 <= len(raw_modes) <= MAX_ENFORCED_FALLBACK_MODES:
        raise CollectorBudgetError(
            "runtime_budget.fallback.enforce requires between 2 and "
            f"{MAX_ENFORCED_FALLBACK_MODES} modes"
        )

    total = 0.0
    preferred = 0.0
    modes: list[dict[str, Any]] = []
    factors: list[Mapping[str, Any]] = []
    mode_names: set[str] = set()
    for index, raw_mode in enumerate(raw_modes):
        field = f"runtime_budget.fallback.modes[{index}]"
        mode = _mapping(raw_mode, field)
        _reject_unknown_keys(
            mode,
            {
                "name",
                "timeout_seconds",
                "post_operation_count",
                "post_operation_timeout_seconds",
                "post_operation_classification",
                "post_operation_cancellation_grace_seconds",
                "enabled_config_key",
                "enabled_by_default",
                "min_artifact_bytes",
            },
            field,
        )
        name = _bounded_text(mode.get("name"), f"{field}.name", required=True)
        if name in mode_names:
            raise CollectorBudgetError(
                "runtime_budget.fallback.modes must have unique names"
            )
        mode_names.add(name)
        timeout = _positive_number(
            mode.get("timeout_seconds"),
            f"{field}.timeout_seconds",
            maximum=MAX_BUDGET_SECONDS,
        )
        raw_min_artifact_bytes = mode.get("min_artifact_bytes")
        if enforce and raw_min_artifact_bytes is None:
            raise CollectorBudgetError(
                f"{field}.min_artifact_bytes is required for enforced fallback"
            )
        min_artifact_bytes = (
            _positive_int(
                raw_min_artifact_bytes,
                f"{field}.min_artifact_bytes",
                maximum=MAX_MANAGED_ARTIFACT_BYTES,
            )
            if raw_min_artifact_bytes is not None
            else None
        )
        post_operation_count = _nonnegative_int(
            mode.get("post_operation_count", 0),
            f"{field}.post_operation_count",
            maximum=MAX_PROJECTION_COUNT,
        )
        raw_post_timeout = mode.get("post_operation_timeout_seconds")
        if post_operation_count and raw_post_timeout is None:
            raise CollectorBudgetError(
                f"{field}.post_operation_count requires post_operation_timeout_seconds"
            )
        post_operation_timeout = (
            _positive_number(
                raw_post_timeout,
                f"{field}.post_operation_timeout_seconds",
                maximum=MAX_BUDGET_SECONDS,
            )
            if raw_post_timeout is not None
            else 0.0
        )
        post_operation_classification = _bounded_text(
            mode.get("post_operation_classification"),
            f"{field}.post_operation_classification",
        )
        post_operation_cancellation_grace = _nonnegative_number(
            mode.get("post_operation_cancellation_grace_seconds", 0),
            f"{field}.post_operation_cancellation_grace_seconds",
            maximum=60,
        )
        enabled_key = _bounded_text(
            mode.get("enabled_config_key"), f"{field}.enabled_config_key"
        )
        enabled_by_default = mode.get("enabled_by_default", True)
        if not isinstance(enabled_by_default, bool):
            raise CollectorBudgetError(f"{field}.enabled_by_default must be boolean")
        enabled = (
            _config_enabled(runtime_config, enabled_key, enabled_by_default)
            if enabled_key
            else True
        )
        mode_worst_case = timeout + (
            float(post_operation_count)
            * (post_operation_timeout + post_operation_cancellation_grace)
        )
        contribution = mode_worst_case if enabled else 0.0
        if enabled and preferred == 0.0:
            preferred = mode_worst_case
        total += contribution
        public_mode: dict[str, Any] = {
            "name": name,
            "timeout_seconds": timeout,
            "worst_case_seconds": mode_worst_case,
            "enabled": enabled,
        }
        if min_artifact_bytes is not None:
            public_mode["min_artifact_bytes"] = min_artifact_bytes
        if post_operation_count:
            public_mode["post_operation"] = {
                "count": post_operation_count,
                "timeout_seconds": post_operation_timeout,
                "cancellation_grace_seconds": (post_operation_cancellation_grace),
                "classification": post_operation_classification or None,
            }
        if enabled_key:
            public_mode["enabled_config_key"] = enabled_key
        modes.append(public_mode)
        factors.append(
            {
                "type": "fallback_mode",
                **public_mode,
                "contribution_seconds": contribution,
            }
        )

    additive_collisions = mode_names.intersection(additive_modes)
    if additive_collisions:
        raise CollectorBudgetError(
            "runtime_budget.fallback.additive_modes must not overlap fallback "
            f"modes: {', '.join(sorted(additive_collisions))}"
        )

    if enforce:
        enabled_mode_count = sum(bool(mode["enabled"]) for mode in modes)
        transition_count = max(enabled_mode_count - 1, 0)
        cleanup_contribution = float(transition_count) * cleanup_timeout
        total += cleanup_contribution
        cleanup_policy.update(
            {
                "maximum_transitions": transition_count,
                "worst_case_seconds": cleanup_contribution,
            }
        )
        factors.append(
            {
                "type": "fallback_cleanup",
                **cleanup_policy,
                "contribution_seconds": cleanup_contribution,
            }
        )

    public_policy = {
        "policy": policy,
        "enforced": enforce,
        "semantics": "run_next_only_after_prior_mode_failure",
        "preferred_path_seconds": preferred,
        "worst_case_seconds": total,
        "modes": modes,
    }
    if enforce:
        public_policy["fallback_on"] = fallback_on
        public_policy["cleanup"] = cleanup_policy
    if "additive_modes" in raw_fallback:
        public_policy["additive_modes"] = additive_modes
    return total, public_policy, factors


def _resolve_pagination(
    raw_pagination: Mapping[str, Any],
    *,
    operation_timeout: float,
    transport_max_retries: int,
    transport_backoff_seconds: float,
    runtime_config: Optional[Mapping[str, Any]],
) -> tuple[float, Optional[Mapping[str, Any]], list[Mapping[str, Any]]]:
    """
    Resolve pagination.

    The implementation uses ``raw_pagination``, ``operation_timeout``,
    ``transport_max_retries``, ``transport_backoff_seconds``, and
    ``runtime_config`` to resolve pagination. If the function cannot resolve
    pagination, its exception reaches the caller instead of being converted into
    a successful result.

    Args:
        raw_pagination: Mapping supplying fields for pagination.
        operation_timeout: Maximum duration in seconds allowed for operation
            timeout.
        transport_max_retries: Numeric transport max retries used while the
            operation performs bounded accounting.
        transport_backoff_seconds: Maximum duration in seconds allowed for
            transport backoff seconds.
        runtime_config: Runtime config governing pagination.

    Returns:
        A tuple containing ``numeric value``, ``metadata mapping``, and
        ``selected entries`` in that order.

    Raises:
        CollectorBudgetError: If the runtime_budget.pagination.consistency is
            not initial_snapshot or bounded_live_window; the
            runtime_budget.pagination.max_pages is not positive; the runtime
            config ``max_pages_config_key`` is not positive; or the
            runtime_budget.pagination.max_entities is not positive; or another
            input invariant is violated.
    """
    if not raw_pagination:
        return 0.0, None, []
    _reject_unknown_keys(
        raw_pagination,
        {
            "consistency",
            "deadline_seconds",
            "max_pages",
            "max_pages_config_key",
            "max_entities",
            "max_concurrent_entities",
            "offset_continuity",
            "max_members_per_page",
            "max_retries_per_page",
            "retry_backoff_seconds",
            "initial_requests_per_entity",
        },
        "runtime_budget.pagination",
    )
    consistency = _bounded_text(
        raw_pagination.get("consistency"),
        "runtime_budget.pagination.consistency",
        required=True,
    )
    if consistency not in {"initial_snapshot", "bounded_live_window"}:
        raise CollectorBudgetError(
            "runtime_budget.pagination.consistency must be initial_snapshot or bounded_live_window"
        )
    catalog_max_pages = _nonnegative_int(
        raw_pagination.get("max_pages"),
        "runtime_budget.pagination.max_pages",
        maximum=MAX_PROJECTION_COUNT,
    )
    if catalog_max_pages == 0:
        raise CollectorBudgetError(
            "runtime_budget.pagination.max_pages must be positive"
        )
    max_pages_config_key = _bounded_text(
        raw_pagination.get("max_pages_config_key"),
        "runtime_budget.pagination.max_pages_config_key",
    )
    configured_max_pages = None
    if (
        max_pages_config_key
        and runtime_config is not None
        and runtime_config.get(max_pages_config_key) is not None
    ):
        configured_max_pages = _nonnegative_int(
            runtime_config[max_pages_config_key],
            f"runtime config {max_pages_config_key}",
            maximum=MAX_PROJECTION_COUNT,
        )
        if configured_max_pages == 0:
            raise CollectorBudgetError(
                f"runtime config {max_pages_config_key} must be positive"
            )
    max_pages = min(
        value
        for value in (catalog_max_pages, configured_max_pages)
        if value is not None
    )
    max_entities = _nonnegative_int(
        raw_pagination.get("max_entities", 1),
        "runtime_budget.pagination.max_entities",
        maximum=MAX_PROJECTION_COUNT,
    )
    if max_entities == 0:
        raise CollectorBudgetError(
            "runtime_budget.pagination.max_entities must be positive"
        )
    requested_max_concurrent_entities = _nonnegative_int(
        raw_pagination.get("max_concurrent_entities", 1),
        "runtime_budget.pagination.max_concurrent_entities",
        maximum=MAX_PROJECTION_COUNT,
    )
    if requested_max_concurrent_entities == 0:
        raise CollectorBudgetError(
            "runtime_budget.pagination.max_concurrent_entities must be positive"
        )
    max_concurrent_entities = min(
        requested_max_concurrent_entities,
        max_entities,
    )
    offset_continuity = _bounded_text(
        raw_pagination.get("offset_continuity", "exact"),
        "runtime_budget.pagination.offset_continuity",
        required=True,
    )
    if offset_continuity not in {"exact", "monotonic"}:
        raise CollectorBudgetError(
            "runtime_budget.pagination.offset_continuity must be exact or monotonic"
        )
    requested_max_members_per_page = _nonnegative_int(
        raw_pagination.get(
            "max_members_per_page", MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS
        ),
        "runtime_budget.pagination.max_members_per_page",
        maximum=MAX_PROJECTION_COUNT,
    )
    if requested_max_members_per_page == 0:
        raise CollectorBudgetError(
            "runtime_budget.pagination.max_members_per_page must be positive"
        )
    max_members_per_page = min(
        requested_max_members_per_page,
        MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS,
    )
    retries = _nonnegative_int(
        raw_pagination.get("max_retries_per_page", 0),
        "runtime_budget.pagination.max_retries_per_page",
        maximum=100,
    )
    page_retry_backoff = _nonnegative_number(
        raw_pagination.get("retry_backoff_seconds", 0),
        "runtime_budget.pagination.retry_backoff_seconds",
        maximum=MAX_BUDGET_SECONDS,
    )
    initial_requests = _nonnegative_int(
        raw_pagination.get("initial_requests_per_entity", 1),
        "runtime_budget.pagination.initial_requests_per_entity",
        maximum=MAX_PROJECTION_COUNT,
    )
    transport_attempt_budget = (
        operation_timeout * float(transport_max_retries + 1) + transport_backoff_seconds
    )
    per_page_budget = transport_attempt_budget * float(
        retries + 1
    ) + page_retry_backoff * float(retries)
    per_entity_contribution = (
        float(initial_requests) * transport_attempt_budget
        + float(max_pages) * per_page_budget
    )
    entity_waves = math.ceil(max_entities / max_concurrent_entities)
    contribution = float(entity_waves) * per_entity_contribution
    if not math.isfinite(contribution) or contribution > MAX_PROJECTION_SECONDS:
        raise CollectorBudgetError(
            "runtime_budget.pagination projection is unreasonably large"
        )
    default_deadline_seconds = per_entity_contribution
    deadline_seconds = _nonnegative_number(
        raw_pagination.get("deadline_seconds", default_deadline_seconds),
        "runtime_budget.pagination.deadline_seconds",
        maximum=MAX_PROJECTION_SECONDS,
    )
    if deadline_seconds == 0:
        raise CollectorBudgetError(
            "runtime_budget.pagination.deadline_seconds must be positive"
        )
    policy = {
        "consistency": consistency,
        "deadline_seconds": deadline_seconds,
        "max_pages": max_pages,
        "catalog_max_pages": catalog_max_pages,
        "configured_max_pages": configured_max_pages,
        "max_entities": max_entities,
        "max_concurrent_entities": max_concurrent_entities,
        "requested_max_concurrent_entities": requested_max_concurrent_entities,
        "entity_waves": entity_waves,
        "offset_continuity": offset_continuity,
        "max_members_per_page": max_members_per_page,
        "requested_max_members_per_page": requested_max_members_per_page,
        "max_retries_per_page": retries,
        "page_retry_backoff_seconds": page_retry_backoff,
        "initial_requests_per_entity": initial_requests,
        "transport_max_retries_per_request": transport_max_retries,
        "transport_backoff_seconds_per_request": transport_backoff_seconds,
        "snapshot_boundary": (
            "initial_odata_count" if consistency == "initial_snapshot" else None
        ),
    }
    factor = {
        "type": "pagination",
        **policy,
        "timeout_seconds_per_page": operation_timeout,
        "transport_attempt_budget_seconds": transport_attempt_budget,
        "per_page_budget_seconds": per_page_budget,
        "contribution_seconds": contribution,
    }
    return contribution, policy, [factor]


def resolve_collector_budget(
    collector_id: str,
    collector_definition: Mapping[str, Any],
    *,
    runtime_config: Optional[Mapping[str, Any]] = None,
) -> ResolvedCollectorBudget:
    """
    Resolve one catalog collector into a strict public budget contract.

    After applying local validation, the function forwards ``collector_id``,
    ``collector_definition``, and ``runtime_config`` to
    ``ResolvedCollectorBudget`` and preserves its return and exception contract.

    Args:
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        collector_definition: Mapping supplying fields for one catalog collector
            into a strict public budget contract.
        runtime_config: Optional Runtime config governing one catalog collector
            into a strict public budget contract.

    Returns:
        A ``ResolvedCollectorBudget`` representing collector budget.

    Raises:
        CollectorBudgetError: If the collector_definition is not a mapping; the
            runtime_budget.schema_version is not
            ``RUNTIME_BUDGET_SCHEMA_VERSION``; the
            runtime_budget.enforce_wall_timeout is not boolean; or
            runtime_budget.enforce_wall_timeout lacks wall_timeout_seconds; or
            another input invariant is violated.
    """

    collector_id = _bounded_text(collector_id, "collector_id", required=True)
    if not isinstance(collector_definition, Mapping):
        raise CollectorBudgetError("collector_definition must be a mapping")

    raw_contract_value = collector_definition.get("runtime_budget")
    explicit_contract = raw_contract_value not in (None, "", {})
    contract = _mapping(raw_contract_value, "runtime_budget")
    if explicit_contract:
        _reject_unknown_keys(
            contract,
            {
                "schema_version",
                "operation_timeout_seconds",
                "operation_timeout_config",
                "remote_task_timeout_seconds",
                "remote_task_timeout_config",
                "wall_timeout_seconds",
                "enforce_wall_timeout",
                "retry",
                "projection",
                "fallback",
                "pagination",
                "serialization",
                "rationale",
            },
            "runtime_budget",
        )
        version = _bounded_text(
            contract.get("schema_version"),
            "runtime_budget.schema_version",
            required=True,
        )
        if version != RUNTIME_BUDGET_SCHEMA_VERSION:
            raise CollectorBudgetError(
                f"runtime_budget.schema_version must be {RUNTIME_BUDGET_SCHEMA_VERSION}"
            )

    raw_operation_timeout = contract.get(
        "operation_timeout_seconds", collector_definition.get("timeout", 300)
    )
    operation_timeout = _positive_number(
        raw_operation_timeout,
        "operation_timeout_seconds",
        maximum=MAX_BUDGET_SECONDS,
    )
    operation_timeout_config = _bounded_text(
        contract.get("operation_timeout_config"),
        "runtime_budget.operation_timeout_config",
    )
    if (
        operation_timeout_config
        and runtime_config is not None
        and runtime_config.get(operation_timeout_config) is not None
    ):
        operation_timeout = _positive_number(
            runtime_config[operation_timeout_config],
            f"runtime config {operation_timeout_config}",
            maximum=MAX_BUDGET_SECONDS,
        )

    remote_task_timeout_config = _bounded_text(
        contract.get("remote_task_timeout_config"),
        "runtime_budget.remote_task_timeout_config",
    )
    raw_remote_task = contract.get("remote_task_timeout_seconds")
    if raw_remote_task is None and remote_task_timeout_config:
        # A configured remote-task override needs a safe authored default.  Use
        # the collector's ordinary operation timeout so the spreadsheet Timeout
        # column remains authoritative instead of requiring a duplicate number
        # inside Runtime Budget JSON.
        raw_remote_task = operation_timeout
    remote_task_timeout = (
        _positive_number(
            raw_remote_task,
            "runtime_budget.remote_task_timeout_seconds",
            maximum=MAX_BUDGET_SECONDS,
        )
        if raw_remote_task is not None
        else None
    )
    if (
        remote_task_timeout_config
        and runtime_config is not None
        and runtime_config.get(remote_task_timeout_config) is not None
    ):
        remote_task_timeout = _positive_number(
            runtime_config[remote_task_timeout_config],
            f"runtime config {remote_task_timeout_config}",
            maximum=MAX_BUDGET_SECONDS,
        )

    retry = _mapping(contract.get("retry"), "runtime_budget.retry")
    _reject_unknown_keys(
        retry,
        {"max_retries", "backoff_budget_seconds"},
        "runtime_budget.retry",
    )
    raw_max_retries = retry.get(
        "max_retries", collector_definition.get("retry_count", 3)
    )
    max_retries = _nonnegative_int(
        raw_max_retries, "runtime_budget.retry.max_retries", maximum=100
    )
    raw_backoff = retry.get("backoff_budget_seconds")
    retry_backoff = (
        _nonnegative_number(
            raw_backoff,
            "runtime_budget.retry.backoff_budget_seconds",
            maximum=MAX_BUDGET_SECONDS,
        )
        if raw_backoff is not None
        else _retry_backoff_seconds(max_retries)
    )
    retry_budget = operation_timeout * max_retries + retry_backoff

    raw_wall_timeout = contract.get("wall_timeout_seconds")
    catalog_wall_timeout = (
        _positive_number(
            raw_wall_timeout,
            "runtime_budget.wall_timeout_seconds",
            maximum=MAX_BUDGET_SECONDS,
        )
        if raw_wall_timeout is not None
        else None
    )
    enforce_wall = contract.get("enforce_wall_timeout", False)
    if not isinstance(enforce_wall, bool):
        raise CollectorBudgetError(
            "runtime_budget.enforce_wall_timeout must be boolean"
        )
    if enforce_wall and catalog_wall_timeout is None:
        raise CollectorBudgetError(
            "runtime_budget.enforce_wall_timeout requires wall_timeout_seconds"
        )

    projection = _mapping(contract.get("projection"), "runtime_budget.projection")
    _reject_unknown_keys(
        projection,
        {"fixed_overhead_seconds", "serial_steps"},
        "runtime_budget.projection",
    )
    fixed_overhead = _nonnegative_number(
        projection.get("fixed_overhead_seconds", 0),
        "runtime_budget.projection.fixed_overhead_seconds",
        maximum=MAX_BUDGET_SECONDS,
    )
    total = fixed_overhead
    factors: list[Mapping[str, Any]] = []
    if fixed_overhead:
        factors.append(
            {
                "type": "fixed_overhead",
                "contribution_seconds": fixed_overhead,
            }
        )

    serial_total, serial_factors = _resolve_serial_steps(
        projection,
        operation_timeout=operation_timeout,
        remote_task_timeout=remote_task_timeout,
        runtime_config=runtime_config,
    )
    total += serial_total
    factors.extend(serial_factors)

    fallback_total, fallback_policy, fallback_factors = _resolve_fallback(
        _mapping(contract.get("fallback"), "runtime_budget.fallback"),
        runtime_config=runtime_config,
    )
    total += fallback_total
    factors.extend(fallback_factors)

    pagination_total, pagination_policy, pagination_factors = _resolve_pagination(
        _mapping(contract.get("pagination"), "runtime_budget.pagination"),
        operation_timeout=operation_timeout,
        transport_max_retries=max_retries,
        transport_backoff_seconds=retry_backoff,
        runtime_config=runtime_config,
    )
    total += pagination_total
    factors.extend(pagination_factors)

    if not explicit_contract:
        # Compatibility estimate only: historical collectors have no declared
        # entity/pagination cardinality and therefore no honest upper bound.
        total = operation_timeout * float(max_retries + 1) + retry_backoff
        factors = [
            {
                "type": "legacy_single_operation_estimate",
                "count": 1,
                "timeout_seconds": operation_timeout,
                "max_retries": max_retries,
                "backoff_seconds": retry_backoff,
                "contribution_seconds": total,
            }
        ]
    elif not factors:
        # An explicit contract with no compound factors still represents one
        # retryable operation.  This avoids both a misleading zero-second
        # projection and an upper bound that omits declared retry attempts.
        total = operation_timeout * float(max_retries + 1) + retry_backoff
        factors = [
            {
                "type": "single_operation",
                "count": 1,
                "timeout_seconds": operation_timeout,
                "max_retries": max_retries,
                "backoff_seconds": retry_backoff,
                "contribution_seconds": total,
            }
        ]

    if not math.isfinite(total) or total <= 0 or total > MAX_PROJECTION_SECONDS:
        raise CollectorBudgetError(
            "collector wall projection is outside supported bounds"
        )

    rationale = _bounded_text(contract.get("rationale"), "runtime_budget.rationale")
    serialization = _mapping(
        contract.get("serialization"), "runtime_budget.serialization"
    )
    _reject_unknown_keys(
        serialization,
        {"mode", "reason"},
        "runtime_budget.serialization",
    )
    public_serialization: Optional[dict[str, Any]] = None
    if serialization:
        mode = _bounded_text(
            serialization.get("mode"),
            "runtime_budget.serialization.mode",
            required=True,
        )
        if mode != "per_shared_hmc_diagnostic_slot":
            raise CollectorBudgetError(
                "runtime_budget.serialization.mode must be "
                "per_shared_hmc_diagnostic_slot"
            )
        reason = _bounded_text(
            serialization.get("reason"),
            "runtime_budget.serialization.reason",
            required=True,
        )
        public_serialization = {"mode": mode, "reason": reason}

    wall_timeout = catalog_wall_timeout
    if (
        not math.isfinite(total)
        or total <= 0
        or total > MAX_PROJECTION_SECONDS
        or (
            wall_timeout is not None
            and (
                not math.isfinite(wall_timeout) or wall_timeout > MAX_PROJECTION_SECONDS
            )
        )
    ):
        raise CollectorBudgetError(
            "collector wall projection is outside supported bounds"
        )
    projected_wall = (
        min(total, wall_timeout) if enforce_wall and wall_timeout is not None else total
    )

    policies: dict[str, Any] = {}
    if rationale:
        policies["rationale"] = rationale
    if public_serialization:
        policies["serialization"] = public_serialization
    if fallback_policy:
        policies["fallback"] = fallback_policy
    if pagination_policy:
        policies["pagination"] = pagination_policy

    return ResolvedCollectorBudget(
        collector_id=collector_id,
        operation_timeout_seconds=operation_timeout,
        remote_task_timeout_seconds=remote_task_timeout,
        max_retries=max_retries,
        retry_backoff_seconds=retry_backoff,
        retry_budget_seconds=retry_budget,
        wall_timeout_seconds=wall_timeout,
        enforce_wall_timeout=bool(enforce_wall and wall_timeout is not None),
        projection_kind=(
            "catalog_bounded_projection" if explicit_contract else "legacy_estimate"
        ),
        uncapped_projection_seconds=total,
        projected_wall_seconds=projected_wall,
        projection_factors=tuple(factors),
        policies=policies,
        source=("catalog.runtime_budget" if explicit_contract else "legacy_derived"),
    )
