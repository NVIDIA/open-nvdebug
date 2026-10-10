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
Validate governed collector resource profiles used by scheduling.

Collector cost is catalog data rather than execution-engine policy.  This
module provides the single normalization boundary shared by spreadsheet
generation, runtime loading, scheduling-plan construction, and admission.
Missing profiles deliberately resolve to an ordinary weight-one operation so
existing catalogs retain their behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

RESOURCE_PROFILE_SCHEMA_VERSION = "1.0"
DEFAULT_WORKLOAD_CLASS = "ordinary"
MAX_OPERATION_WEIGHT = 64
MAX_ESTIMATED_OUTPUT_BYTES = 16 * 1024**4

_WORKLOAD_CLASSES = frozenset(
    {
        "ordinary",
        "bounded_multi_request",
        "heavy_diagnostic",
        "publication",
    }
)
_PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "workload_class",
        "operation_weight",
        "remote_generation_weight",
        "local_transfer_weight",
        "remote_cpu",
        "heavy_transfer",
        "diagnostic",
        "estimated_output_bytes",
    }
)


@dataclass(frozen=True)
class CollectorResourceProfile:
    """
    Describe bounded scheduler demand for one collector operation.

    The three weight fields preserve the vocabulary needed for later separate
    capacity pools.  Until an operation exposes narrower governed stage
    boundaries, the global collector permit conservatively uses their maximum.

    Attributes:
        workload_class: Governed, platform-neutral workload category.
        operation_weight: Base share of global collector capacity.
        remote_generation_weight: Share attributed to remote generation work.
        local_transfer_weight: Share attributed to local transfer processing.
        remote_cpu: Whether the operation is expected to consume material DUT
            or management-controller CPU.
        heavy_transfer: Whether the operation transfers a comparatively large
            bounded artifact.
        diagnostic: Whether the operation starts or retrieves diagnostic work.
        estimated_output_bytes: Optional conservative output-volume estimate.
    """

    workload_class: str = DEFAULT_WORKLOAD_CLASS
    operation_weight: int = 1
    remote_generation_weight: int = 1
    local_transfer_weight: int = 1
    remote_cpu: bool = False
    heavy_transfer: bool = False
    diagnostic: bool = False
    estimated_output_bytes: int | None = None

    @property
    def effective_weight(self) -> int:
        """
        Return the conservative weight held for the whole collector.

        Until narrower stage boundaries exist, taking the maximum prevents a
        collector from being under-accounted in any declared resource stage.

        Returns:
            The largest declared stage or operation weight.
        """

        return max(
            self.operation_weight,
            self.remote_generation_weight,
            self.local_transfer_weight,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Return a deterministic JSON-safe representation of the profile.

        The normalized mapping is shared by planning evidence and catalog
        round-trip validation, including the computed effective weight.

        Returns:
            A mapping containing every normalized profile field.
        """

        result: dict[str, Any] = {
            "schema_version": RESOURCE_PROFILE_SCHEMA_VERSION,
            "workload_class": self.workload_class,
            "operation_weight": self.operation_weight,
            "remote_generation_weight": self.remote_generation_weight,
            "local_transfer_weight": self.local_transfer_weight,
            "effective_weight": self.effective_weight,
            "remote_cpu": self.remote_cpu,
            "heavy_transfer": self.heavy_transfer,
            "diagnostic": self.diagnostic,
        }
        if self.estimated_output_bytes is not None:
            result["estimated_output_bytes"] = self.estimated_output_bytes
        return result


def _bounded_weight(value: Any, field_name: str, context: str) -> int:
    """
    Validate one strict positive resource weight.

    Strict integer validation rejects booleans and caps catalog-driven demand
    before it reaches admission arithmetic.

    Args:
        value: Candidate value from governed catalog data.
        field_name: Profile field named in validation diagnostics.
        context: Bounded collector location named in validation diagnostics.

    Returns:
        The validated integer weight.

    Raises:
        ValueError: If the value is not an integer from one through the
            supported maximum.
    """

    if type(value) is not int or not 1 <= value <= MAX_OPERATION_WEIGHT:
        raise ValueError(
            f"{context} resource_profile.{field_name} must be an integer "
            f"from 1 through {MAX_OPERATION_WEIGHT}"
        )
    return value


def parse_collector_resource_profile(
    raw_profile: Any,
    *,
    context: str = "collector",
) -> CollectorResourceProfile:
    """
    Validate and normalize one optional catalog resource profile.

    Empty legacy values select a compatibility profile, while every explicit
    profile is fail-closed against unknown fields and unsupported values.

    Args:
        raw_profile: Mapping decoded from YAML or the runtime catalog; an empty
            value selects the compatibility profile.
        context: Bounded collector location named in validation diagnostics.

    Returns:
        An immutable normalized resource profile.

    Raises:
        ValueError: If the profile has unknown fields, an unsupported schema or
            workload class, non-boolean flags, invalid weights, or an unbounded
            output estimate.
    """

    if raw_profile in (None, "", {}):
        return CollectorResourceProfile()
    if not isinstance(raw_profile, Mapping):
        raise ValueError(f"{context} resource_profile must be a mapping")

    unknown = sorted(str(key) for key in set(raw_profile) - _PROFILE_FIELDS)
    if unknown:
        raise ValueError(
            f"{context} resource_profile contains unknown field {unknown[0]!r}"
        )

    schema_version = raw_profile.get("schema_version", RESOURCE_PROFILE_SCHEMA_VERSION)
    if schema_version != RESOURCE_PROFILE_SCHEMA_VERSION:
        raise ValueError(
            f"{context} resource_profile.schema_version must be "
            f"{RESOURCE_PROFILE_SCHEMA_VERSION!r}"
        )

    workload_class = raw_profile.get("workload_class", DEFAULT_WORKLOAD_CLASS)
    if not isinstance(workload_class, str) or workload_class not in _WORKLOAD_CLASSES:
        allowed = ", ".join(sorted(_WORKLOAD_CLASSES))
        raise ValueError(
            f"{context} resource_profile.workload_class must be one of: {allowed}"
        )

    operation_weight = _bounded_weight(
        raw_profile.get("operation_weight", 1), "operation_weight", context
    )
    remote_generation_weight = _bounded_weight(
        raw_profile.get("remote_generation_weight", operation_weight),
        "remote_generation_weight",
        context,
    )
    local_transfer_weight = _bounded_weight(
        raw_profile.get("local_transfer_weight", operation_weight),
        "local_transfer_weight",
        context,
    )

    flags: dict[str, bool] = {}
    for field_name in ("remote_cpu", "heavy_transfer", "diagnostic"):
        value = raw_profile.get(field_name, False)
        if type(value) is not bool:
            raise ValueError(
                f"{context} resource_profile.{field_name} must be true or false"
            )
        flags[field_name] = value

    estimated_output_bytes = raw_profile.get("estimated_output_bytes")
    if estimated_output_bytes is not None and (
        type(estimated_output_bytes) is not int
        or not 0 <= estimated_output_bytes <= MAX_ESTIMATED_OUTPUT_BYTES
    ):
        raise ValueError(
            f"{context} resource_profile.estimated_output_bytes must be an "
            f"integer from 0 through {MAX_ESTIMATED_OUTPUT_BYTES}"
        )

    return CollectorResourceProfile(
        workload_class=workload_class,
        operation_weight=operation_weight,
        remote_generation_weight=remote_generation_weight,
        local_transfer_weight=local_transfer_weight,
        remote_cpu=flags["remote_cpu"],
        heavy_transfer=flags["heavy_transfer"],
        diagnostic=flags["diagnostic"],
        estimated_output_bytes=estimated_output_bytes,
    )


def profile_for_collector(
    collector_definition: Mapping[str, Any] | None,
    *,
    collector_id: str = "collector",
) -> CollectorResourceProfile:
    """
    Resolve a profile directly from a runtime collector definition.

    This helper keeps callers on the same normalization boundary and adds a
    bounded collector identifier only to actionable validation diagnostics.

    Args:
        collector_definition: Catalog definition whose optional profile is
            normalized without modifying the source mapping.
        collector_id: Stable identifier included only in validation errors.

    Returns:
        The normalized compatibility or declared resource profile.

    Raises:
        ValueError: If the declared profile violates its governed schema.
    """

    definition = collector_definition or {}
    return parse_collector_resource_profile(
        definition.get("resource_profile"),
        context=f"collector {collector_id}",
    )
