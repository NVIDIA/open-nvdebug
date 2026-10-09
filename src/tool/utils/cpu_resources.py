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
CPU-resource detection for resource-aware scheduling.

``os.cpu_count()`` reports the *host* core count, which is wrong inside a
CPU-limited container (a Kubernetes pod may see 128-192 cores while its cgroup
quota only allows ~10). Sizing concurrency off that number over-subscribes the
CPU, triggering CFS throttling and severe multi-DUT slowdown.

This module detects the *effective* CPU budget by taking the minimum of:

1. the cgroup CPU quota (v2 ``cpu.max``, v1 ``cfs_quota_us/cfs_period_us``),.
2. the process CPU affinity (``os.sched_getaffinity``), and.
3. ``os.cpu_count()`` as a last resort, then derives a concurrency limit for
   I/O-bound collection work.

All knobs are env-overridable so the limit can be tuned per environment without
a rebuild.
"""

from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# Env overrides (all optional).
_ENV_CPU_COUNT = "NVDEBUG_CPU_COUNT"  # force the detected CPU count
_ENV_OVERSUBSCRIBE = "NVDEBUG_CPU_OVERSUBSCRIBE"  # I/O-bound oversubscription K
_ENV_MAX_DUTS = "NVDEBUG_MAX_CONCURRENT_DUTS"  # hard override of the DUT cap

# Collection work is I/O-bound (mostly waiting on Redfish/SSH/IPMI), so more
# collectors than CPUs can run before they contend. Kept conservative because
# collectors also do real CPU work (large JSON parse, sanitization) between
# waits; tune via NVDEBUG_CPU_OVERSUBSCRIBE and the CFS throttle counters.
_DEFAULT_OVERSUBSCRIBE = 3
_CGROUP_ROOT = Path("/sys/fs/cgroup")
_PROC_SELF_CGROUP = Path("/proc/self/cgroup")
_AvailableCpuInputs = Tuple[
    float,
    Tuple[str, ...],
    Dict[str, Optional[float]],
    Optional[float],
]


@dataclass(frozen=True)
class CpuResourceResolution:
    """
    The exact CPU-resource decision installed by the execution engine.

    Keeping the decision as data (instead of only returning the final integer)
    lets run artifacts explain why two environments selected different global
    collector caps without probing mutable cgroup state a second time.

    Attributes:
        effective_cpus: Number of effective cpus represented by this record.
        oversubscription_factor: Numeric oversubscription factor retained by
            this record.
        collector_operation_limit: Maximum collector operation admitted by this
            record.
        binding_sources: Collection of binding sources entries retained by this
            record.
        oversubscription_source: Canonical text used as oversubscription source.
        inputs: Mapping that retains the inputs fields for this record.
        environment_overrides: Mapping that retains the environment overrides
            fields for this record.
    """

    effective_cpus: float
    oversubscription_factor: float
    collector_operation_limit: int
    binding_sources: Tuple[str, ...]
    oversubscription_source: str
    inputs: Dict[str, Optional[float]]
    environment_overrides: Dict[str, Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        """
        Return a JSON-safe representation for resource telemetry.

        The implementation uses current instance state to produce a JSON-safe
        representation for resource telemetry.

        Returns:
            A mapping containing the ``effective_cpus``,
            ``oversubscription_factor``, ``collector_operation_limit``,
            ``binding_sources``, and ``oversubscription_source`` fields.
        """
        return {
            "effective_cpus": self.effective_cpus,
            "oversubscription_factor": self.oversubscription_factor,
            "collector_operation_limit": self.collector_operation_limit,
            "binding_sources": list(self.binding_sources),
            "oversubscription_source": self.oversubscription_source,
            "inputs": dict(self.inputs),
            "environment_overrides": {
                name: dict(value) for name, value in self.environment_overrides.items()
            },
        }


def _read_int(path: Union[str, Path]) -> Optional[int]:
    """
    Read int.

    After applying local validation, the function forwards ``path`` to ``int``
    and preserves its return and exception contract. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The numeric int value, or ``None`` when the requested value is
        unavailable.
    """
    try:
        with open(path, "r") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _quota_to_cpus(quota: int, period: int) -> Optional[float]:
    """
    Convert a positive CFS quota/period pair to a CPU budget.

    The implementation uses ``quota`` and ``period`` to convert a positive CFS
    quota/period pair to a CPU budget. The source value keeps its ownership
    while the normalized representation is returned separately.

    Args:
        quota: Numeric quota used while the operation performs bounded
            accounting.
        period: Numeric period used while the operation performs bounded
            accounting.

    Returns:
        The numeric quota to cpus value, or ``None`` when the requested value is
        unavailable.
    """
    if quota <= 0 or period <= 0:
        return None
    return quota / period


def _self_cgroup_path(controller: Optional[str] = None) -> Optional[Path]:
    """
    Return this process's relative cgroup path for v2 or a v1 controller.

    The implementation uses ``controller`` to produce this process's relative
    cgroup path for v2 or a v1 controller.

    Args:
        controller: Optional controller; ``None`` selects the function's default
            behavior.

    Returns:
        The validated self cgroup path filesystem path, or ``None`` when the
        requested value is unavailable.
    """
    try:
        lines = _PROC_SELF_CGROUP.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    for line in lines:
        try:
            hierarchy, controllers, relative_path = line.split(":", 2)
        except ValueError:
            continue
        if controller is None:
            if hierarchy == "0" and not controllers:
                return Path(relative_path.lstrip("/"))
        elif controller in controllers.split(","):
            return Path(relative_path.lstrip("/"))
    return None


def _cgroup_ancestor_dirs(root: Path, relative_path: Optional[Path]) -> List[Path]:
    """
    Return current-to-root cgroup directories without allowing path escape.

    The implementation uses ``root`` and ``relative_path`` to produce
    current-to-root cgroup directories without allowing path escape.

    Args:
        root: filesystem location used as the root for this operation.
        relative_path: filesystem location used as the relative path for this
            operation.

    Returns:
        The cgroup ancestor dirs returned in operation-defined order.
    """
    parts = tuple(relative_path.parts) if relative_path is not None else ()
    if any(part in {"..", "."} for part in parts):
        parts = ()

    current = root.joinpath(*parts)
    directories = []
    while True:
        directories.append(current)
        if current == root:
            break
        if root not in current.parents:
            return [root]
        current = current.parent
    return directories


def _parse_cpu_max(path: Path) -> Optional[float]:
    """
    Parse CPU max.

    After applying local validation, the function forwards ``path`` to
    ``_quota_to_cpus`` and preserves its return and exception contract. Parsing
    or I/O must finish before the validated representation is made available to
    the caller.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The numeric CPU max value, or ``None`` when the requested value is
        unavailable.
    """
    try:
        parts = path.read_text(encoding="utf-8").split()
    except OSError:
        return None
    if len(parts) < 2 or parts[0] == "max":
        return None
    try:
        quota, period = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    return _quota_to_cpus(quota, period)


def _cgroup_v2_cpus() -> Optional[float]:
    """
    Effective cgroup v2 CPU budget, including tighter parent quotas.

    The implementation uses current instance state to effective cgroup v2 CPU
    budget, including tighter parent quotas.

    Returns:
        The numeric cgroup v2 cpus value, or ``None`` when the requested value
        is unavailable.
    """
    budgets = [
        budget
        for directory in _cgroup_ancestor_dirs(_CGROUP_ROOT, _self_cgroup_path())
        if (budget := _parse_cpu_max(directory / "cpu.max")) is not None
    ]
    return min(budgets) if budgets else None


def _cgroup_v1_cpus() -> Optional[float]:
    """
    Effective cgroup v1 CPU budget, including tighter parent quotas.

    The implementation uses current instance state to effective cgroup v1 CPU
    budget, including tighter parent quotas.

    Returns:
        The numeric cgroup v1 cpus value, or ``None`` when the requested value
        is unavailable.
    """
    relative_path = _self_cgroup_path("cpu")
    budgets: List[float] = []
    for root in (
        _CGROUP_ROOT / "cpu",
        _CGROUP_ROOT / "cpu,cpuacct",
    ):
        for directory in _cgroup_ancestor_dirs(root, relative_path):
            quota = _read_int(directory / "cpu.cfs_quota_us")
            period = _read_int(directory / "cpu.cfs_period_us")
            if quota is None or period is None:
                continue
            budget = _quota_to_cpus(quota, period)
            if budget is not None:
                budgets.append(budget)
    return min(budgets) if budgets else None


def _affinity_cpus() -> Optional[int]:
    """
    CPUs the process is allowed to run on (respects cpuset pinning).

    After applying local validation, the function forwards current instance
    state to ``max`` and preserves its return and exception contract.

    Returns:
        The numeric affinity cpus value, or ``None`` when the requested value is
        unavailable.
    """
    try:
        return max(1, len(os.sched_getaffinity(0)))  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None


def available_cpus() -> float:
    """
    Return the effective CPU capacity available to this process.

    Takes the minimum of every limit we can detect so a container's cgroup quota
    is honored even when ``os.cpu_count()`` reports the host cores.

    Returns:
        The validated ``effective``.
    """
    effective, _, _, _ = _resolve_available_cpu_inputs()
    return effective


def _read_int_env(name: str) -> Optional[int]:
    """
    Read int environment.

    After applying local validation, the function forwards ``name`` to ``int``
    and preserves its return and exception contract. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        The numeric int environment value, or ``None`` when the requested value
        is unavailable.
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        return int(raw.strip())
    except ValueError:
        logger.warning("Ignoring non-integer %s=%r", name, raw)
        return None


def _read_float_env(name: str) -> Optional[float]:
    """
    Read float environment.

    After applying local validation, the function forwards ``name`` to ``float``
    and preserves its return and exception contract. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        The numeric float environment value, or ``None`` when the requested
        value is unavailable.
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        return float(raw.strip())
    except ValueError:
        logger.warning("Ignoring non-numeric %s=%r", name, raw)
        return None


def _positive_int(value: object, source: str) -> Optional[int]:
    """
    Return a positive integer or ignore the invalid limit with a warning.

    The implementation uses ``value`` and ``source`` to produce a positive
    integer or ignore the invalid limit with a warning.

    Args:
        value: Value object whose ``is_integer`` state is read while performing
            positive integer or ignore the invalid limit with a warning.
        source: Text supplied as source in the format accepted by this function.

    Returns:
        The validated ``parsed``, or ``None`` when no value qualifies.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        logger.warning(
            "Ignoring invalid %s=%r; expected a positive integer", source, value
        )
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        logger.warning(
            "Ignoring invalid %s=%r; expected a positive integer", source, value
        )
        return None
    if parsed <= 0 or (isinstance(value, float) and not value.is_integer()):
        logger.warning(
            "Ignoring invalid %s=%r; expected a positive integer", source, value
        )
        return None
    return parsed


def _read_positive_int_env(name: str) -> Optional[int]:
    """
    Read positive int environment.

    After applying local validation, the function forwards ``name`` to
    ``_positive_int`` and preserves its return and exception contract. Parsing
    or I/O must finish before the validated representation is made available to
    the caller.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        The numeric positive int environment value, or ``None`` when the
        requested value is unavailable.
    """
    return _positive_int(_read_int_env(name), name)


def _positive_float(value: object, source: str) -> Optional[float]:
    """
    Return a finite positive float or ignore it with a warning.

    The implementation uses ``value`` and ``source`` to produce a finite
    positive float or ignore it with a warning.

    Args:
        value: Value evaluated while performing finite positive float or ignore
            it with a warning.
        source: Text supplied as source in the format accepted by this function.

    Returns:
        The validated ``parsed``, or ``None`` when no value qualifies.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        logger.warning(
            "Ignoring invalid %s=%r; expected a positive number", source, value
        )
        return None
    if not math.isfinite(parsed) or parsed <= 0:
        logger.warning(
            "Ignoring invalid %s=%r; expected a positive number", source, value
        )
        return None
    return parsed


def _read_positive_float_env(name: str) -> Optional[float]:
    """
    Read positive float environment.

    After applying local validation, the function forwards ``name`` to
    ``_positive_float`` and preserves its return and exception contract. Parsing
    or I/O must finish before the validated representation is made available to
    the caller.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        The numeric positive float environment value, or ``None`` when the
        requested value is unavailable.
    """
    return _positive_float(_read_float_env(name), name)


def _resolve_available_cpu_inputs() -> _AvailableCpuInputs:
    """
    Resolve effective CPUs and retain every normalized scheduler input.

    The implementation uses current instance state to resolve effective CPUs and
    retain every normalized scheduler input.

    Returns:
        A tuple containing ``available CPU inputs value 1``, ``available CPU
        inputs value 2``, ``inputs``, and ``available CPU inputs value 4`` in
        that order.
    """
    forced = _read_positive_float_env(_ENV_CPU_COUNT)
    inputs: Dict[str, Optional[float]] = {
        "cgroup_v2_quota_cpus": _cgroup_v2_cpus(),
        "cgroup_v1_quota_cpus": _cgroup_v1_cpus(),
        "affinity_cpus": _affinity_cpus(),
        "host_cpu_count": float(os.cpu_count() or 1),
    }

    if forced is not None:
        return forced, (f"env:{_ENV_CPU_COUNT}",), inputs, forced

    candidates = {
        name: float(value)
        for name, value in inputs.items()
        if value is not None and value > 0
    }
    effective = min(candidates.values()) if candidates else 1.0
    binding_sources = tuple(
        name
        for name, value in candidates.items()
        if math.isclose(value, effective, rel_tol=1e-12, abs_tol=1e-12)
    )
    return effective, binding_sources or ("fallback",), inputs, None


def resolve_collector_operation_resources(
    configured_oversubscription: Optional[object] = None,
) -> CpuResourceResolution:
    """
    Return the complete resource decision for collector-operation admission.

    An explicitly resolved tool/CLI value has normal configuration precedence
    over the legacy environment fallback.  Omitting it preserves the existing
    ``NVDEBUG_CPU_OVERSUBSCRIBE`` behavior.

    Args:
        configured_oversubscription: Optional positive CPU multiplier already
            resolved through tool and CLI precedence.

    Returns:
        The validated ``resolution``.
    """
    effective, binding_sources, inputs, accepted_cpu_override = (
        _resolve_available_cpu_inputs()
    )
    accepted_k_override = _read_positive_float_env(_ENV_OVERSUBSCRIBE)
    configured_k = _positive_float(
        configured_oversubscription,
        "execution.initial_io_oversubscription",
    )
    oversubscription = configured_k or accepted_k_override or _DEFAULT_OVERSUBSCRIBE
    limit = max(1, math.floor(effective * oversubscription))

    resolution = CpuResourceResolution(
        effective_cpus=effective,
        oversubscription_factor=oversubscription,
        collector_operation_limit=limit,
        binding_sources=binding_sources,
        oversubscription_source=(
            "config:execution.initial_io_oversubscription"
            if configured_k is not None
            else (
                f"env:{_ENV_OVERSUBSCRIBE}"
                if accepted_k_override is not None
                else "default"
            )
        ),
        inputs=inputs,
        environment_overrides={
            _ENV_CPU_COUNT: {
                "raw": os.environ.get(_ENV_CPU_COUNT),
                "accepted_value": accepted_cpu_override,
            },
            _ENV_OVERSUBSCRIBE: {
                "raw": os.environ.get(_ENV_OVERSUBSCRIBE),
                "accepted_value": accepted_k_override,
                "shadowed_by_config": configured_k is not None,
            },
            _ENV_MAX_DUTS: {
                "raw": os.environ.get(_ENV_MAX_DUTS),
                "applies_to": "whole_dut_admission_only",
            },
        },
    )
    logger.info(
        "Resolved global collector-operation concurrency=%d "
        "(cpus=%.3g, K=%.3g, binding=%s)",
        resolution.collector_operation_limit,
        resolution.effective_cpus,
        resolution.oversubscription_factor,
        ",".join(resolution.binding_sources),
    )
    return resolution


def explicit_dut_concurrency_limit(
    num_duts: int, configured_max: Optional[object] = None
) -> Optional[int]:
    """
    Return an explicitly requested whole-DUT limit, or ``None``.

    A whole-DUT permit is intentionally opt-in. CPU-derived throttling belongs
    at the collector-operation level; otherwise one slow collector holds a DUT
    permit and prevents unrelated DUTs from making progress.

    Args:
        num_duts: Numeric num duts used while the operation performs bounded
            accounting.
        configured_max: Optional Configured max governing explicitly requested
            whole-DUT limit, or ``None``.

    Returns:
        The numeric explicit DUT concurrency limit, or ``None`` when the
        requested value is unavailable.
    """
    num_duts = max(1, int(num_duts))
    env_override = _read_positive_int_env(_ENV_MAX_DUTS)
    config_override = _positive_int(configured_max, "configured max_concurrent_duts")
    explicit = env_override if env_override is not None else config_override
    if explicit is None:
        return None
    return max(1, min(explicit, num_duts))


def resolve_collector_operation_concurrency() -> int:
    """
    Return the shared collector-operation concurrency budget.

    Collectors are mostly I/O bound, so the effective (cgroup-aware) CPU budget
    is multiplied by the configurable oversubscription factor ``K``. Flooring
    preserves fractional CPU quotas instead of inflating them to a full core.

    Returns:
        The numeric collector operation concurrency value.
    """
    return resolve_collector_operation_resources().collector_operation_limit


def resolve_dut_concurrency(
    num_duts: int,
    operations_per_dut: int,
    configured_max: Optional[object] = None,
) -> int:
    """
    Decide how many DUT plans to admit concurrently.

    All plans are admitted unless ``NVDEBUG_MAX_CONCURRENT_DUTS`` or
    ``configured_max`` explicitly requests a positive whole-DUT cap. The
    ``operations_per_dut`` argument remains for API compatibility and logging;
    CPU-derived protection is enforced by
    :func:`resolve_collector_operation_concurrency` around real collector calls.

    Args:
        num_duts: Numeric num duts used while the operation performs bounded
            accounting.
        operations_per_dut: Numeric operations per DUT used while the operation
            performs bounded accounting.
        configured_max: Optional Configured max governing decide how many DUT
            plans to admit concurrently.

    Returns:
        The validated ``resolved``.
    """
    num_duts = max(1, int(num_duts))
    operations_per_dut = max(1, int(operations_per_dut))

    explicit = explicit_dut_concurrency_limit(num_duts, configured_max)

    resolved = explicit if explicit is not None else num_duts

    logger.info(
        "Resolved DUT plan admission=%d/%d (operations_per_dut=%d, explicit=%s)",
        resolved,
        num_duts,
        operations_per_dut,
        explicit,
    )
    return resolved
