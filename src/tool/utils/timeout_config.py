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

This module provides utilities for handling timeout overrides based on collector
definitions and DUT configuration.
"""

from typing import Any, Dict

from .collector_command_profiles import resolve_collector_command_profiles

# Tool-level values for these catalog ``params.timeout_config`` keys can come
# from either YAML or BaseSettings environment fallback. Every boundary that
# projects configuration provenance must use this shared set so the resolver
# can distinguish those source layers without collector-specific checks.
TIMEOUT_CONFIG_OVERRIDE_KEYS = frozenset(
    {
        "NVOS_TECH_DUMP_TIMEOUT",
        "REDFISH_DUMP_TIMEOUT",
    }
)


def _is_positive_number(value: Any) -> bool:
    """
    Return whether ``value`` is positive number.

    The implementation uses ``value`` to determine whether ``value`` is positive
    number.

    Args:
        value: Value evaluated while performing ``value`` is positive number.

    Returns:
        Whether ``value`` is positive number.
    """
    return isinstance(value, (int, float)) and value > 0


def _get_positive_int(value: Any) -> int | None:
    """
    Return positive int.

    After applying local validation, the function forwards ``value`` to ``int``
    and preserves its return and exception contract.

    Args:
        value: Value evaluated while performing positive int.

    Returns:
        The numeric positive int value, or ``None`` when the requested value is
        unavailable.
    """
    if _is_positive_number(value):
        return int(value)
    return None


def _iter_hook_params(collector_def: Dict[str, Any]):
    """
    Yield each hook's params dict across all stages, in stage/hook order.

    Tolerates malformed stage/hook entries (skips them) rather than raising.

    Args:
        collector_def: Mapping supplying fields for yield each hook's params
            dict across all stages, in stage/hook order.

    Yields:
        Each hook params admitted by the operation, in deterministic iteration
        order.
    """
    if not collector_def:
        return
    stages = collector_def.get("stages") or {}
    if not isinstance(stages, dict):
        return
    for stage_config in stages.values():
        if not isinstance(stage_config, dict):
            continue
        hooks = stage_config.get("hooks") or []
        if not isinstance(hooks, list):
            continue
        for hook in hooks:
            if isinstance(hook, dict) and isinstance(hook.get("params"), dict):
                yield hook["params"]


def _explicit_tool_config_keys(config: Dict[str, Any]) -> set[str] | None:
    """
    Return tool-YAML source metadata, or None for legacy unmarked callers.

    The implementation uses ``config`` to produce tool-YAML source metadata, or
    None for legacy unmarked callers.

    Args:
        config: Config governing tool-YAML source metadata, or None for legacy
            unmarked callers.

    Returns:
        The unique explicit tool config keys returned by the operation, or
        ``None`` when the requested value is unavailable.
    """

    if not isinstance(config, dict) or "__explicit_tool_config_fields" not in config:
        return None
    raw = config.get("__explicit_tool_config_fields")
    if isinstance(raw, dict):
        return {str(key) for key, value in raw.items() if value}
    if isinstance(raw, (list, tuple, set, frozenset)):
        return {str(key) for key in raw}
    return set()


def get_collector_timeout(
    collector_id: str,
    collector_def: Dict[str, Any],
    dut_config: Dict[str, Any],
    default_timeout: int = 300,
    tool_config: Dict[str, Any] = None,
) -> int:
    """
    Resolve the effective timeout for a collector.

    Priority (most specific wins; first non-empty positive integer is returned):

    1. DUT config override When a stage hook declares ``params.timeout_config:
       "<KEY>"`` and ``dut_config[<KEY>]`` is a positive integer, that value
       wins. This is the operator's per-DUT, per-run knob — most specific.
    2. Tool config override Same opt-in via ``timeout_config``, but the value is
       read from ``tool_config``. Useful for CI / lab-wide tuning.
    3. Spreadsheet timeout ``collector_def["timeout"]`` — the catalog author's
       reviewed default. Authoritative whenever no DUT/tool override is set, OR
       when the collector does not declare a ``timeout_config`` opt-in.
    4. Environment fallback A timeout populated by BaseSettings but absent from
       the tool YAML. Source-presence metadata keeps this below the spreadsheet.
    5. Caller default ``default_timeout`` arg — last-resort fallback when
       neither the catalog nor any operator config specifies a value.

    The opt-in: only hooks with ``params.timeout_config: "<KEY>"`` participate
    in admin overrides. Collectors without that declaration are
    spreadsheet-authoritative — no DUT or tool config can change them.

    Catalog command profiles select their authored deadlines before this
    precedence chain, including during status-plan projection. A caller probing
    only explicit overrides can still suppress the catalog timeout by omitting it.

    Args:
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        collector_def: Mapping supplying fields for effective timeout for a
            collector.
        dut_config: DUT config governing effective timeout for a collector.
        default_timeout: Maximum duration in seconds allowed for default
            timeout.
        tool_config: Optional Tool config governing effective timeout for a
            collector.

    Returns:
        The numeric collector timeout value.
    """
    tool_values = tool_config or {}
    if collector_def:
        had_catalog_timeout = "timeout" in collector_def
        collector_def = resolve_collector_command_profiles(
            collector_def, dut_config or {}, tool_values
        )
        if not had_catalog_timeout and "timeout" in collector_def:
            collector_def = {
                key: value for key, value in collector_def.items() if key != "timeout"
            }
    explicit_tool_keys = _explicit_tool_config_keys(tool_values)
    environment_tool_values = tool_values if explicit_tool_keys is not None else {}
    if explicit_tool_keys is not None:
        tool_config = {
            key: value
            for key, value in tool_values.items()
            if key in explicit_tool_keys
        }
    else:
        tool_config = tool_values

    # Priority is DUT > tool > spreadsheet > environment > default.
    # The previous implementation had tool > dut > spreadsheet which inverted the
    # specificity rule, contradicted tool_config.yaml's "Global defaults — can
    # be overridden per-DUT" comment, and required a hardcoded
    # NVOS_TECH_DUMP_TIMEOUT carve-out to compensate.
    if not collector_def:
        return default_timeout

    # Resolve the complete DUT source layer before inspecting tool values. A
    # later hook's DUT override is still more specific than an earlier hook's
    # tool override.
    for params in _iter_hook_params(collector_def):
        key = params.get("timeout_config")
        if not key:
            continue
        dut_val = _get_positive_int((dut_config or {}).get(key))
        if dut_val is not None:
            return dut_val

    for params in _iter_hook_params(collector_def):
        key = params.get("timeout_config")
        if not key:
            continue
        tool_val = _get_positive_int((tool_config or {}).get(key))
        if tool_val is not None:
            return tool_val

    # 3: spreadsheet timeout.
    spreadsheet_timeout = _get_positive_int(collector_def.get("timeout"))
    if spreadsheet_timeout is not None:
        return spreadsheet_timeout

    # 4: source-aware tool values absent from the YAML marker came from the
    # environment and participate only after the spreadsheet.
    for params in _iter_hook_params(collector_def):
        key = params.get("timeout_config")
        if not key:
            continue
        environment_value = _get_positive_int(environment_tool_values.get(key))
        if environment_value is not None:
            return environment_value

    # 5: caller default.
    return default_timeout


def get_collector_sleep_duration(
    collector_id: str,
    collector_def: Dict[str, Any],
    dut_config: Dict[str, Any],
    default_sleep: int = 5,
) -> int:
    """
    Get the appropriate sleep duration for a collector based on configuration.

    Check if collector definition specifies a sleep duration config variable.

    Args:
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        collector_def: Mapping supplying fields for get the appropriate sleep
            duration for a collector based on configuration.
        dut_config: DUT config governing get the appropriate sleep duration for
            a collector based on configuration.
        default_sleep: Numeric default sleep used while the operation performs
            bounded accounting.

    Returns:
        The numeric collector sleep duration value.
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
    explicit_config_keys: Dict[str, bool] | None = None,
) -> int:
    """
    Get the appropriate expand level for a collector based on configuration.

    Check if collector definition specifies an expand query config variable.

    Args:
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        collector_def: Mapping supplying fields for get the appropriate expand
            level for a collector based on configuration.
        dut_config: DUT config governing get the appropriate expand level for a
            collector based on configuration.
        default_expand_level: Numeric default expand level used while the
            operation performs bounded accounting.
        explicit_config_keys: Optional Explicit config keys governing get the
            appropriate expand level for a collector based on configuration.

    Returns:
        The numeric expand level value.
    """
    if not collector_def:
        return default_expand_level

    explicit_config_keys = explicit_config_keys or {}

    # Check if collector definition specifies an expand query config variable
    stages = collector_def.get("stages", {})
    for stage_name, stage_config in stages.items():
        if isinstance(stage_config, dict) and "hooks" in stage_config:
            for hook in stage_config["hooks"]:
                if isinstance(hook, dict) and "params" in hook:
                    params = hook["params"]

                    # Check for expand_query_config parameter
                    expand_config_key = params.get("expand_query_config")
                    if (
                        expand_config_key
                        and dut_config
                        and expand_config_key in dut_config
                        and explicit_config_keys.get(expand_config_key)
                    ):
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

    The implementation uses ``collector_id``, ``collector_def``, ``dut_config``,
    and ``default_timeout`` to get the NVOS tech dump timeout for H14 collector.

    Args:
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        collector_def: Mapping supplying fields for get the NVOS tech dump
            timeout for H14 collector.
        dut_config: DUT config governing get the NVOS tech dump timeout for H14
            collector.
        default_timeout: Maximum duration in seconds allowed for default
            timeout.

    Returns:
        The numeric nvos tech dump timeout value.
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
