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
Timeout configuration utilities for open-nvdebugtool.

This module provides utilities for handling timeout overrides based on
collector definitions and DUT configuration.
"""

from typing import Any, Dict


def _is_positive_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and value > 0


def _get_positive_int(value: Any) -> int | None:
    if _is_positive_number(value):
        return int(value)
    return None


def _resolve_timeout_config_value(
    timeout_config_key: str,
    dut_config: Dict[str, Any],
    tool_config: Dict[str, Any] | None = None,
    collector_timeout: int | None = None,
) -> int | None:
    """Resolve timeout_config while preserving DUT-level overrides.

    ConfigManager may populate tool_config with default values for compatibility.
    When that value matches the collector timeout, treat it as a default rather
    than an explicit global override. H14's NVOS tech dump timeout is
    intentionally per-DUT overridable even when a global tool timeout is set.
    """
    tool_timeout = None
    if tool_config and timeout_config_key in tool_config:
        tool_timeout = _get_positive_int(tool_config[timeout_config_key])

    dut_timeout = None
    if dut_config and timeout_config_key in dut_config:
        dut_timeout = _get_positive_int(dut_config[timeout_config_key])

    if timeout_config_key == "NVOS_TECH_DUMP_TIMEOUT" and dut_timeout is not None:
        return dut_timeout

    if (
        tool_timeout is not None
        and (
            dut_timeout is None
            or collector_timeout is None
            or tool_timeout != collector_timeout
        )
    ):
        return tool_timeout

    if dut_timeout is not None:
        return dut_timeout

    return tool_timeout


def get_collector_timeout(
    collector_id: str,
    collector_def: Dict[str, Any],
    dut_config: Dict[str, Any],
    default_timeout: int = 300,
    tool_config: Dict[str, Any] = None,
) -> int:
    """
    Get the appropriate timeout for a collector based on configuration.

    Priority order:
    1. timeout_config override in tool_config (if explicitly set in YAML)
    2. timeout_config override in dut_config (if explicitly set in YAML)
    3. Collector's own timeout (from spreadsheet)
    4. Default timeout

    A tool_config value matching the collector's own timeout is treated as a
    default, not an explicit global override, so DUT-specific overrides still
    apply.

    Args:
        collector_id: The collector ID
        collector_def: Collector definition from spreadsheet
        dut_config: DUT configuration dictionary
        default_timeout: Default timeout if no configuration is found
        tool_config: Tool configuration dictionary (optional)

    Returns:
        int: The timeout value to use
    """
    if not collector_def:
        return default_timeout

    # First priority: Check collector definition timeout
    collector_timeout = collector_def.get("timeout")
    collector_timeout_int = _get_positive_int(collector_timeout)
    if collector_timeout_int is not None:
        # Check if there's a timeout_config override that should take precedence
        stages = collector_def.get("stages", {})
        for stage_name, stage_config in stages.items():
            if isinstance(stage_config, dict) and "hooks" in stage_config:
                for hook in stage_config["hooks"]:
                    if isinstance(hook, dict) and "params" in hook:
                        params = hook["params"]
                        timeout_config_key = params.get("timeout_config")
                        if timeout_config_key:
                            timeout_value = _resolve_timeout_config_value(
                                timeout_config_key,
                                dut_config,
                                tool_config,
                                collector_timeout_int,
                            )
                            if timeout_value is not None:
                                return timeout_value

        # No explicit override found, use collector's timeout
        return collector_timeout_int

    # Fallback: Check for timeout_config if collector doesn't have its own timeout
    stages = collector_def.get("stages", {})
    for stage_name, stage_config in stages.items():
        if isinstance(stage_config, dict) and "hooks" in stage_config:
            for hook in stage_config["hooks"]:
                if isinstance(hook, dict) and "params" in hook:
                    params = hook["params"]
                    timeout_config_key = params.get("timeout_config")
                    if timeout_config_key:
                        timeout_value = _resolve_timeout_config_value(
                            timeout_config_key,
                            dut_config,
                            tool_config,
                        )
                        if timeout_value is not None:
                            return timeout_value

    return default_timeout


def get_collector_sleep_duration(
    collector_id: str,
    collector_def: Dict[str, Any],
    dut_config: Dict[str, Any],
    default_sleep: int = 5,
) -> int:
    """
    Get the appropriate sleep duration for a collector based on configuration.

    Args:
        collector_id: The collector ID
        collector_def: Collector definition from collector_definitions.yaml
        dut_config: DUT configuration dictionary
        default_sleep: Default sleep duration if no configuration is found

    Returns:
        int: The sleep duration to use
    """
    if not collector_def or not dut_config:
        return default_sleep

    # Check if collector definition specifies a sleep duration config variable
    stages = collector_def.get("stages", {})
    for stage_name, stage_config in stages.items():
        if isinstance(stage_config, dict) and "hooks" in stage_config:
            for hook in stage_config["hooks"]:
                if isinstance(hook, dict) and "params" in hook:
                    params = hook["params"]

                    # Check for sleep_duration_config parameter
                    sleep_config_key = params.get("sleep_duration_config")
                    if sleep_config_key and sleep_config_key in dut_config:
                        sleep_value = dut_config[sleep_config_key]
                        if isinstance(sleep_value, (int, float)) and sleep_value >= 0:
                            return int(sleep_value)

    return default_sleep


def get_expand_level(
    collector_id: str,
    collector_def: Dict[str, Any],
    dut_config: Dict[str, Any],
    default_expand_level: int = 1,
) -> int:
    """
    Get the appropriate expand level for a collector based on configuration.

    Args:
        collector_id: The collector ID
        collector_def: Collector definition from collector_definitions.yaml
        dut_config: DUT configuration dictionary
        default_expand_level: Default expand level if no configuration is found

    Returns:
        int: The expand level to use
    """
    if not collector_def or not dut_config:
        return default_expand_level

    # Check if collector definition specifies an expand query config variable
    stages = collector_def.get("stages", {})
    for stage_name, stage_config in stages.items():
        if isinstance(stage_config, dict) and "hooks" in stage_config:
            for hook in stage_config["hooks"]:
                if isinstance(hook, dict) and "params" in hook:
                    params = hook["params"]

                    # Check for expand_query_config parameter
                    expand_config_key = params.get("expand_query_config")
                    if expand_config_key and expand_config_key in dut_config:
                        expand_value = dut_config[expand_config_key]
                        if isinstance(expand_value, bool):
                            # If it's a boolean, use 1 for True, 0 for False
                            return 1 if expand_value else 0
                        elif (
                            isinstance(expand_value, (int, float)) and expand_value >= 0
                        ):
                            return int(expand_value)

    # Check collector definition expand_level
    collector_expand_level = collector_def.get("expand_level")
    if isinstance(collector_expand_level, (int, float)) and collector_expand_level >= 0:
        return int(collector_expand_level)

    return default_expand_level


def get_nvos_tech_dump_timeout(
    collector_id: str,
    collector_def: Dict[str, Any],
    dut_config: Dict[str, Any],
    default_timeout: int = 600,
) -> int:
    """
    Get the NVOS tech dump timeout for H14 collector.

    Args:
        collector_id: The collector ID (should be H14)
        collector_def: Collector definition from collector_definitions.yaml
        dut_config: DUT configuration dictionary
        default_timeout: Default timeout if no configuration is found

    Returns:
        int: The timeout value to use
    """
    if not dut_config:
        return default_timeout

    # Check for NVOS_TECH_DUMP_TIMEOUT in DUT config
    nvos_timeout = dut_config.get("NVOS_TECH_DUMP_TIMEOUT")
    if (
        nvos_timeout is not None
        and isinstance(nvos_timeout, (int, float))
        and nvos_timeout > 0
    ):
        return int(nvos_timeout)

    # Check collector definition timeout as fallback
    collector_timeout = collector_def.get("timeout") if collector_def else None
    if isinstance(collector_timeout, (int, float)) and collector_timeout > 0:
        return int(collector_timeout)

    return default_timeout
