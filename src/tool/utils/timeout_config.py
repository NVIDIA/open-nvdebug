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

from typing import Any, Dict, Optional, Union


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
    1. Collector's own timeout (from spreadsheet)
    2. timeout_config override in tool_config (if explicitly set in YAML)
    3. timeout_config override in dut_config (if explicitly set in YAML)
    4. Default timeout

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
    if isinstance(collector_timeout, (int, float)) and collector_timeout > 0:
        # Check if there's a timeout_config override that should take precedence
        stages = collector_def.get("stages", {})
        for stage_name, stage_config in stages.items():
            if isinstance(stage_config, dict) and "hooks" in stage_config:
                for hook in stage_config["hooks"]:
                    if isinstance(hook, dict) and "params" in hook:
                        params = hook["params"]
                        timeout_config_key = params.get("timeout_config")
                        if timeout_config_key:
                            # Check tool config for explicit override (only if set in YAML)
                            if tool_config and timeout_config_key in tool_config:
                                timeout_value = tool_config[timeout_config_key]
                                if (
                                    timeout_value is not None
                                    and isinstance(timeout_value, (int, float))
                                    and timeout_value > 0
                                ):
                                    return int(timeout_value)

                            # Check DUT config for explicit override (only if set in YAML)
                            if dut_config and timeout_config_key in dut_config:
                                timeout_value = dut_config[timeout_config_key]
                                if (
                                    isinstance(timeout_value, (int, float))
                                    and timeout_value > 0
                                ):
                                    return int(timeout_value)

        # No explicit override found, use collector's timeout
        return int(collector_timeout)

    # Fallback: Check for timeout_config if collector doesn't have its own timeout
    stages = collector_def.get("stages", {})
    for stage_name, stage_config in stages.items():
        if isinstance(stage_config, dict) and "hooks" in stage_config:
            for hook in stage_config["hooks"]:
                if isinstance(hook, dict) and "params" in hook:
                    params = hook["params"]
                    timeout_config_key = params.get("timeout_config")
                    if timeout_config_key:
                        # Check tool config for explicit override
                        if tool_config and timeout_config_key in tool_config:
                            timeout_value = tool_config[timeout_config_key]
                            if (
                                timeout_value is not None
                                and isinstance(timeout_value, (int, float))
                                and timeout_value > 0
                            ):
                                return int(timeout_value)

                        # Check DUT config for explicit override
                        if dut_config and timeout_config_key in dut_config:
                            timeout_value = dut_config[timeout_config_key]
                            if (
                                isinstance(timeout_value, (int, float))
                                and timeout_value > 0
                            ):
                                return int(timeout_value)

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
    default_timeout: int = 450,
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
