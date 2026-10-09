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
Construct deterministic, transport-free collector scheduling summaries.

The summary is deliberately derived only from resolved configuration,
preflight outcomes, and governed catalog fields.  It contains no remote
endpoint, credential, command, payload, or captured-output value and is safe to
embed in bounded run metadata and dry-run artifacts.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Any, Mapping, Sequence

from ..utils.collector_resource_profile import profile_for_collector

SCHEDULING_PLAN_SCHEMA_VERSION = "1.0"
_SAFE_SERVICE_PATTERN = re.compile(r"[^a-z0-9_-]+")
_MAX_DUTS_IN_PLAN = 4096
_MAX_SERVICES_IN_PLAN = 64
_MAX_PROFILED_COLLECTORS = 4096


def _service_name(collector_definition: Mapping[str, Any]) -> str:
    """
    Normalize a catalog collector group into a bounded scheduler lane name.

    Known transport aliases collapse to runtime lane names, while unexpected
    governed groups are sanitized and bounded for aggregate evidence.

    Args:
        collector_definition: Governed collector fields used only to identify
            the service lane.

    Returns:
        A lower-case service label containing only safe identifier characters.
    """

    raw_group = str(collector_definition.get("group") or "unknown").strip().lower()
    aliases = {
        "ssh": "bmc_ssh",
        "bmc ssh": "bmc_ssh",
        "redfish": "redfish",
        "host": "host",
        "ipmi": "ipmi",
        "hmc": "hmc",
    }
    normalized = aliases.get(raw_group, raw_group.replace(" ", "_"))
    normalized = _SAFE_SERVICE_PATTERN.sub("_", normalized).strip("_")
    return (normalized or "unknown")[:64]


def _percentile(values: Sequence[float], percentile: float) -> float | None:
    """
    Return a deterministic nearest-rank percentile for bounded evidence.

    Invalid, negative, boolean, and non-finite observations are discarded so
    malformed optional timing data cannot poison the plan artifact.

    Args:
        values: Finite nonnegative duration values.
        percentile: Fraction from zero through one selecting the rank.

    Returns:
        The rounded percentile, or ``None`` when no values are available.
    """

    ordered = sorted(
        float(value)
        for value in values
        if isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0
    )
    if not ordered:
        return None
    rank = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(ordered[rank], 3)


def _preflight_summary(preflight_results: Mapping[str, Any] | None) -> dict[str, Any]:
    """
    Aggregate preflight reachability and duration without retaining endpoints.

    Per-DUT records are reduced to transport-level status counts and latency
    percentiles, preserving planning value without endpoint disclosure.

    Args:
        preflight_results: Existing per-DUT preflight outcomes, or ``None``
            when preflight was intentionally skipped.

    Returns:
        A deterministic aggregate containing status counts and duration
        percentiles by transport.
    """

    if not preflight_results:
        return {"available": False, "services": {}}

    statuses: dict[str, Counter[str]] = defaultdict(Counter)
    durations: dict[str, list[float]] = defaultdict(list)
    for dut_result in preflight_results.values():
        if not isinstance(dut_result, Mapping):
            continue
        services = dut_result.get("services", {})
        if not isinstance(services, Mapping):
            continue
        for raw_service, raw_result in services.items():
            service = _SAFE_SERVICE_PATTERN.sub(
                "_", str(raw_service).strip().lower()
            ).strip("_")[:64]
            if not service or not isinstance(raw_result, Mapping):
                continue
            status = str(raw_result.get("status") or "unknown").strip().lower()[:32]
            statuses[service][status or "unknown"] += 1
            duration = raw_result.get("duration_seconds")
            if (
                isinstance(duration, (int, float))
                and not isinstance(duration, bool)
                and math.isfinite(float(duration))
                and float(duration) >= 0
            ):
                durations[service].append(float(duration))

    services_summary: dict[str, Any] = {}
    for service in sorted(statuses)[:_MAX_SERVICES_IN_PLAN]:
        service_durations = durations.get(service, [])
        services_summary[service] = {
            "status_counts": dict(sorted(statuses[service].items())),
            "reachable_duts": statuses[service].get("pass", 0),
            "duration_samples": len(service_durations),
            "duration_p50_seconds": _percentile(service_durations, 0.50),
            "duration_p95_seconds": _percentile(service_durations, 0.95),
        }
    return {"available": True, "services": services_summary}


def build_scheduling_summary(
    *,
    filtered_collectors_per_dut: Mapping[str, Sequence[str]],
    skipped_collectors_per_dut: Mapping[str, Any] | None,
    collector_definitions: Mapping[str, Any],
    preflight_results: Mapping[str, Any] | None,
    collection_level: str,
    resource_inputs: Mapping[str, Any],
    concurrency_mode: str,
    initial_limit: int,
    minimum_limit: int,
    maximum_limit: int,
    max_concurrent_duts: int | None,
    max_concurrent_collectors_per_dut: int,
) -> dict[str, Any]:
    """
    Build the immutable scheduler plan used by execution and run evidence.

    Construction occurs after filtering and preflight, and consumes only
    governed catalog fields plus aggregate local resource decisions.

    Args:
        filtered_collectors_per_dut: Runnable collector identifiers after
            configuration, applicability, and preflight filtering.
        skipped_collectors_per_dut: Typed skip evidence retained only as counts.
        collector_definitions: Runtime catalog mapping keyed by collector ID.
        preflight_results: Existing preflight results reused for reachability
            and latency evidence.
        collection_level: Resolved collection level for the run.
        resource_inputs: Cgroup-aware CPU decision already installed by the
            execution engine.
        concurrency_mode: Resolved conservative, fixed, or adaptive mode.
        initial_limit: Initial weighted collector-operation capacity.
        minimum_limit: Smallest capacity the controller may install.
        maximum_limit: Hard capacity ceiling for this run.
        max_concurrent_duts: Optional explicit whole-DUT cap.
        max_concurrent_collectors_per_dut: Parallel-class per-DUT cap.

    Returns:
        A deterministic, JSON-safe scheduling summary.

    Raises:
        ValueError: If a governed collector resource profile is invalid or the
            resolved plan exceeds its bounded DUT inventory.
    """

    if len(filtered_collectors_per_dut) > _MAX_DUTS_IN_PLAN:
        raise ValueError(
            f"scheduler plan exceeds the {_MAX_DUTS_IN_PLAN}-DUT metadata bound"
        )

    definitions = collector_definitions.get("collectors", collector_definitions)
    if not isinstance(definitions, Mapping):
        definitions = {}

    service_totals: dict[str, Counter[str]] = defaultdict(Counter)
    workload_counts: Counter[str] = Counter()
    per_dut: list[dict[str, Any]] = []
    runnable_operations = 0
    weighted_demand = 0
    operation_weighted_demand = 0
    remote_generation_weighted_demand = 0
    local_transfer_weighted_demand = 0
    estimated_output_bytes = 0
    estimated_output_operations = 0
    maximum_operation_weight = 1
    maximum_base_operation_weight = 1
    maximum_remote_generation_weight = 1
    maximum_local_transfer_weight = 1
    runnable_service_lanes = 0
    critical_scores: Counter[str] = Counter()
    profile_flag_counts: Counter[str] = Counter()
    profiled_collector_counts: Counter[str] = Counter()
    normalized_profiles: dict[str, dict[str, Any]] = {}

    for dut_index, dut_id in enumerate(
        sorted(str(value) for value in filtered_collectors_per_dut), start=1
    ):
        collector_ids = list(filtered_collectors_per_dut.get(dut_id, ()) or ())
        dut_services: dict[str, Counter[str]] = defaultdict(Counter)
        dut_weighted_demand = 0
        for collector_id in collector_ids:
            definition = definitions.get(collector_id, {})
            if not isinstance(definition, Mapping):
                definition = {}
            service = _service_name(definition)
            sequential = (
                bool(definition.get("sequential_execution", False))
                or str(definition.get("execution_phase", "")).strip().lower() == "tail"
            )
            execution_class = "sequential" if sequential else "parallel"
            profile = profile_for_collector(
                definition, collector_id=str(collector_id)[:128]
            )

            dut_services[service][execution_class] += 1
            dut_services[service]["weighted_demand"] += profile.effective_weight
            service_totals[service]["runnable_operations"] += 1
            service_totals[service][f"{execution_class}_operations"] += 1
            service_totals[service]["weighted_demand"] += profile.effective_weight
            workload_counts[profile.workload_class] += 1
            runnable_operations += 1
            weighted_demand += profile.effective_weight
            dut_weighted_demand += profile.effective_weight
            operation_weighted_demand += profile.operation_weight
            remote_generation_weighted_demand += profile.remote_generation_weight
            local_transfer_weighted_demand += profile.local_transfer_weight
            maximum_operation_weight = max(
                maximum_operation_weight, profile.effective_weight
            )
            maximum_base_operation_weight = max(
                maximum_base_operation_weight, profile.operation_weight
            )
            maximum_remote_generation_weight = max(
                maximum_remote_generation_weight,
                profile.remote_generation_weight,
            )
            maximum_local_transfer_weight = max(
                maximum_local_transfer_weight, profile.local_transfer_weight
            )
            for flag_name in ("remote_cpu", "heavy_transfer", "diagnostic"):
                if getattr(profile, flag_name):
                    profile_flag_counts[flag_name] += 1
            if definition.get("resource_profile") not in (None, "", {}):
                safe_collector_id = str(collector_id)[:128]
                profiled_collector_counts[safe_collector_id] += 1
                normalized_profiles[safe_collector_id] = profile.to_dict()
            if profile.estimated_output_bytes is not None:
                estimated_output_bytes += profile.estimated_output_bytes
                estimated_output_operations += 1
            if sequential:
                critical_scores[service] += profile.effective_weight

        lane_summary: dict[str, Any] = {}
        for service in sorted(dut_services)[:_MAX_SERVICES_IN_PLAN]:
            counts = dut_services[service]
            lane_summary[service] = {
                "sequential_operations": counts["sequential"],
                "sequential_lanes": 1 if counts["sequential"] else 0,
                "parallel_demand": counts["parallel"],
                "weighted_demand": counts["weighted_demand"],
            }
        runnable_service_lanes += len(lane_summary)
        per_dut.append(
            {
                "dut_index": dut_index,
                "runnable_operations": len(collector_ids),
                "weighted_demand": dut_weighted_demand,
                "service_lanes": lane_summary,
            }
        )

    skipped_operations = 0
    for skipped in (skipped_collectors_per_dut or {}).values():
        if isinstance(skipped, Mapping):
            if isinstance(skipped.get("collector_id"), str):
                skipped_ids = [skipped["collector_id"]]
            else:
                skipped_ids = [str(collector_id) for collector_id in skipped]
        elif isinstance(skipped, Sequence) and not isinstance(skipped, (str, bytes)):
            skipped_ids = [
                str(item["collector_id"])
                for item in skipped
                if isinstance(item, Mapping)
                and isinstance(item.get("collector_id"), str)
            ]
        else:
            skipped_ids = []
        skipped_operations += len(skipped_ids)
        for collector_id in skipped_ids:
            definition = definitions.get(collector_id, {})
            if not isinstance(definition, Mapping):
                definition = {}
            service_totals[_service_name(definition)]["skipped_operations"] += 1

    services: dict[str, Any] = {}
    for service in sorted(service_totals)[:_MAX_SERVICES_IN_PLAN]:
        counts = service_totals[service]
        services[service] = dict(sorted(counts.items()))

    preflight_summary = _preflight_summary(preflight_results)
    critical_paths: list[dict[str, Any]] = []
    for service, score in sorted(
        critical_scores.items(), key=lambda item: (-item[1], item[0])
    )[:8]:
        entry: dict[str, Any] = {
            "service": service,
            "weighted_sequential_demand": score,
        }
        preflight_service = preflight_summary.get("services", {}).get(service, {})
        p95 = (
            preflight_service.get("duration_p95_seconds")
            if isinstance(preflight_service, Mapping)
            else None
        )
        if isinstance(p95, (int, float)) and not isinstance(p95, bool):
            entry["preflight_duration_p95_seconds"] = p95
            entry["estimated_sequential_seconds"] = round(
                float(p95) * service_totals[service].get("sequential_operations", 0),
                3,
            )
        critical_paths.append(entry)

    declared_profiles = {
        collector_id: {
            "planned_operations": profiled_collector_counts[collector_id],
            "profile": normalized_profiles[collector_id],
        }
        for collector_id in sorted(normalized_profiles)[:_MAX_PROFILED_COLLECTORS]
    }

    safe_resource_inputs = {
        key: resource_inputs.get(key)
        for key in (
            "effective_cpus",
            "oversubscription_factor",
            "collector_operation_limit",
            "binding_sources",
            "oversubscription_source",
        )
        if key in resource_inputs
    }
    if (
        concurrency_mode in {"fixed", "adaptive"}
        and maximum_operation_weight > maximum_limit
    ):
        raise ValueError(
            "maximum_collector_operations cannot admit the plan's largest "
            f"resource weight ({maximum_operation_weight})"
        )
    return {
        "schema_version": SCHEDULING_PLAN_SCHEMA_VERSION,
        "collection_level": str(collection_level)[:16],
        "dut_count": len(per_dut),
        "runnable_service_lanes": runnable_service_lanes,
        "runnable_collector_operations": runnable_operations,
        "skipped_collector_operations": skipped_operations,
        "weighted_demand": weighted_demand,
        "services": services,
        "duts": per_dut,
        "preflight": preflight_summary,
        "limits": {
            "concurrency_mode": concurrency_mode,
            "weighted_capacity_enabled": concurrency_mode in {"fixed", "adaptive"},
            "endpoint_cooldown_enabled": concurrency_mode == "adaptive",
            "minimum_collector_operations": minimum_limit,
            "initial_collector_operations": initial_limit,
            "maximum_collector_operations": maximum_limit,
            "max_concurrent_duts": max_concurrent_duts,
            "max_concurrent_collectors_per_dut": max_concurrent_collectors_per_dut,
            "redfish_per_dut": 1,
        },
        "resource_inputs": safe_resource_inputs,
        "workload_profiles": {
            "counts": dict(sorted(workload_counts.items())),
            "flagged_operation_counts": dict(sorted(profile_flag_counts.items())),
            "declared_collectors": declared_profiles,
            "declared_collectors_truncated": (
                len(normalized_profiles) > _MAX_PROFILED_COLLECTORS
            ),
            "stage_weighted_demand": {
                "operation": operation_weighted_demand,
                "remote_generation": remote_generation_weighted_demand,
                "local_transfer": local_transfer_weighted_demand,
            },
            "maximum_operation_weight": maximum_operation_weight,
            "maximum_stage_weights": {
                "operation": maximum_base_operation_weight,
                "remote_generation": maximum_remote_generation_weight,
                "local_transfer": maximum_local_transfer_weight,
            },
        },
        "predicted_critical_paths": critical_paths,
        "expected_output": {
            "bounded_estimate_bytes": estimated_output_bytes,
            "operations_with_estimates": estimated_output_operations,
            "operations_without_estimates": (
                runnable_operations - estimated_output_operations
            ),
        },
        "downstream_capacity": {
            "collection_overlap": False,
            "maximum_active_phases": 1,
            "workloads": ["archive", "report", "publication"],
        },
    }


def format_scheduling_summary(summary: Mapping[str, Any]) -> str:
    """
    Format a compact operator explanation for logs and preflight output.

    The bounded line intentionally omits per-DUT details while surfacing the
    installed limits and the largest aggregate critical-path lanes.

    Args:
        summary: Scheduling plan created by :func:`build_scheduling_summary`.

    Returns:
        A bounded single-line summary containing counts and installed limits.
    """

    limits = summary.get("limits", {})
    critical = summary.get("predicted_critical_paths", [])
    critical_names = ",".join(
        str(entry.get("service"))
        for entry in critical[:3]
        if isinstance(entry, Mapping) and entry.get("service")
    )
    rendered = (
        f"{summary.get('dut_count', 0)} DUTs; "
        f"{summary.get('runnable_service_lanes', 0)} runnable service lanes; "
        f"{summary.get('runnable_collector_operations', 0)} collector operations; "
        f"mode={limits.get('concurrency_mode')}; "
        f"initial/min/max={limits.get('initial_collector_operations')}/"
        f"{limits.get('minimum_collector_operations')}/"
        f"{limits.get('maximum_collector_operations')}; "
        f"per-DUT parallel cap={limits.get('max_concurrent_collectors_per_dut')}; "
        f"Redfish per-DUT cap=1"
    )
    if critical_names:
        rendered += f"; predicted critical paths={critical_names}"
    return rendered[:1024]
