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
Advisory per-baseboard workload profiles for variable-cardinality collectors.

These values describe platform topology for planning and reporting.  They are
not scheduler admission limits and must never suppress discovered work.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Dict, Optional

COLLECTOR_WORKLOAD_PROFILES_KEY = "collector_workload_profiles"
PLANNING_MAX_TARGETS_PER_DUT_KEY = "planning_max_targets_per_dut"


class CollectorWorkloadProfileError(ValueError):
    """
    Raised when an authored collector workload profile is malformed.

    The distinct type lets catalog producers and runtime loaders reject or
    ignore invalid advisory metadata without parsing an error message.
    """


def validate_collector_workload_profiles(value: Any) -> Dict[str, Dict[str, int]]:
    """
    Return a normalized advisory workload-profile mapping.

    A profile currently carries only the maximum number of targets expected on
    one DUT for one collector.  The number is intentionally not used as an
    execution ceiling.  Collector IDs remain exact catalog keys so spreadsheet
    round trips cannot silently retarget an override.

    Args:
        value: Candidate mapping keyed by collector ID.

    Returns:
        A newly owned mapping containing validated integer target counts.

    Raises:
        CollectorWorkloadProfileError: If the mapping, collector IDs, profile
            fields, or counts are malformed.
    """

    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise CollectorWorkloadProfileError(
            f"{COLLECTOR_WORKLOAD_PROFILES_KEY} must be a mapping"
        )

    normalized: Dict[str, Dict[str, int]] = {}
    for collector_id, raw_profile in value.items():
        if (
            not isinstance(collector_id, str)
            or not collector_id
            or collector_id != collector_id.strip()
        ):
            raise CollectorWorkloadProfileError(
                f"{COLLECTOR_WORKLOAD_PROFILES_KEY} keys must be exact "
                "non-empty collector IDs"
            )
        if not isinstance(raw_profile, Mapping):
            raise CollectorWorkloadProfileError(
                f"{COLLECTOR_WORKLOAD_PROFILES_KEY}[{collector_id!r}] must be "
                "a mapping"
            )
        unknown = set(raw_profile) - {PLANNING_MAX_TARGETS_PER_DUT_KEY}
        if unknown:
            rendered = ", ".join(sorted(str(key) for key in unknown))
            raise CollectorWorkloadProfileError(
                f"{COLLECTOR_WORKLOAD_PROFILES_KEY}[{collector_id!r}] has "
                f"unknown fields: {rendered}"
            )
        if PLANNING_MAX_TARGETS_PER_DUT_KEY not in raw_profile:
            raise CollectorWorkloadProfileError(
                f"{COLLECTOR_WORKLOAD_PROFILES_KEY}[{collector_id!r}] requires "
                f"{PLANNING_MAX_TARGETS_PER_DUT_KEY}"
            )
        raw_count = raw_profile[PLANNING_MAX_TARGETS_PER_DUT_KEY]
        if isinstance(raw_count, bool) or not isinstance(raw_count, int):
            raise CollectorWorkloadProfileError(
                f"{COLLECTOR_WORKLOAD_PROFILES_KEY}[{collector_id!r}]."
                f"{PLANNING_MAX_TARGETS_PER_DUT_KEY} must be an integer"
            )
        if raw_count <= 0:
            raise CollectorWorkloadProfileError(
                f"{COLLECTOR_WORKLOAD_PROFILES_KEY}[{collector_id!r}]."
                f"{PLANNING_MAX_TARGETS_PER_DUT_KEY} must be positive"
            )
        normalized[collector_id] = {
            PLANNING_MAX_TARGETS_PER_DUT_KEY: raw_count,
        }
    return normalized


def collector_workload_profile(
    baseboard_config: Any,
    collector_id: str,
) -> Optional[Dict[str, int]]:
    """
    Return one validated advisory profile, when the baseboard declares it.

    The returned mapping is detached from the baseboard configuration so a
    caller cannot mutate catalog state while annotating runtime evidence.

    Args:
        baseboard_config: Resolved baseboard configuration mapping.
        collector_id: Exact collector ID to look up.

    Returns:
        A newly owned profile mapping, or ``None`` when none is authored.

    Raises:
        CollectorWorkloadProfileError: If an authored mapping is malformed.
    """

    if not isinstance(baseboard_config, Mapping):
        return None
    profiles = validate_collector_workload_profiles(
        baseboard_config.get(COLLECTOR_WORKLOAD_PROFILES_KEY, {})
    )
    profile = profiles.get(str(collector_id))
    return dict(profile) if profile is not None else None
