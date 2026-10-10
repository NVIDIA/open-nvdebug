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
Resolve catalog-owned command profiles before execution and budget calculation.

Operator configuration selects a named profile; commands and deadlines always
come from the catalog. Resolution copies the definition so concurrent DUTs can
select different profiles without mutating the shared runtime workbook.
"""

from copy import deepcopy
from typing import Any, Iterator, Mapping


def iter_command_profile_hooks(
    definition: dict[str, Any],
) -> Iterator[tuple[str, int, dict[str, Any]]]:
    """
    Find profile-bearing hooks without taking over general catalog validation.

    Malformed stages and ordinary hook parameters remain the lifecycle runner's
    responsibility. Timeout reporting can still use a catalog's basic deadline
    when those unrelated structures are invalid.

    Args:
        definition: Runtime collector definition to inspect without mutation.

    Yields:
        Stage name, hook index, and parameters for each explicit profile selector.
    """

    stages = definition.get("stages")
    if not isinstance(stages, dict):
        return
    for stage_name, stage in stages.items():
        if not isinstance(stage, dict) or not isinstance(stage.get("hooks"), list):
            continue
        for index, hook in enumerate(stage["hooks"]):
            if not isinstance(hook, dict):
                continue
            params = hook.get("params")
            if isinstance(params, dict) and "command_profiles" in params:
                yield stage_name, index, params


def resolve_collector_command_profiles(
    definition: dict[str, Any],
    dut_config: Mapping[str, Any],
    tool_config: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Select an authored command profile using DUT, tool, then catalog precedence.

    A profile may replace only command modes and their shared timeout. Both
    values are required so the collector deadline and its command deadlines
    cannot accidentally retain the defaults for a different profile. Definitions
    without profiles are returned unchanged.

    Args:
        definition: Runtime collector definition containing stage hook parameters.
        dut_config: Resolved DUT configuration; null values inherit tool values.
        tool_config: Tool configuration providing global profile selections.

    Returns:
        The original definition or an independent copy with one selected profile.

    Raises:
        ValueError: If a profile selector, selection, command list, or timeout is
            invalid, or multiple hooks attempt to own the collector deadline.
    """

    result = definition
    selected = False
    for stage_name, index, params in iter_command_profile_hooks(definition):
        selector = params.get("command_profiles")
        if selector is None:
            continue
        if (
            selected
            or not isinstance(selector, dict)
            or set(selector) != {"config_key", "default", "profiles"}
        ):
            raise ValueError("Invalid catalog command profile selector")
        key = selector["config_key"]
        profiles = selector["profiles"]
        if not isinstance(key, str) or not isinstance(profiles, dict):
            raise ValueError("Invalid catalog command profile configuration")
        value = dut_config.get(key)
        if value is None:
            value = tool_config.get(key)
        if value is None:
            value = selector["default"]
        if not isinstance(value, str) or value not in profiles:
            raise ValueError(f"Unsupported command profile for {key}")
        profile = profiles[value]
        if not isinstance(profile, dict) or set(profile) != {
            "timeout",
            "command_modes",
        }:
            raise ValueError("Invalid catalog command profile fields")
        timeout = profile["timeout"]
        modes = profile["command_modes"]
        if (
            type(timeout) is not int
            or not 0 < timeout <= 86400
            or not isinstance(modes, list)
            or not modes
            or any(
                not isinstance(mode, dict) or mode.get("timeout") != timeout
                for mode in modes
            )
        ):
            raise ValueError("Invalid catalog command profile deadline or modes")
        result = deepcopy(definition)
        resolved = result["stages"][stage_name]["hooks"][index]["params"]
        resolved.pop("command_profiles")
        resolved.update(deepcopy(profile))
        result["timeout"] = timeout
        selected = True
    return result
