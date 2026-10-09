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
Extracted helpers for collect() config resolution in main.py.

These eliminate duplication across the multiple config-loading branches.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from ..cli_handler import ToolConfig
from ..config import (
    DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT,
    Config,
    DUTConfig,
    auto_assign_config_file_to_use,
    load_config,
    load_dut_config,
    load_yaml_strict,
    tool_config_deprecation_messages,
)
from ..services.redfish_pagination import DEFAULT_MAX_PAGINATION_PAGES
from ..utils.catalog_snapshot import CatalogSnapshot
from ..utils.redfish_limits import RedfishRequestCaptureLimits, RedfishResponseLimits
from ..utils.resources import find_all_config_files
from ..utils.timeout_config import TIMEOUT_CONFIG_OVERRIDE_KEYS
from ..utils.validation import (
    display_dut_config_error,
    display_validation_errors,
    validate_collection_level,
    validate_collector_groups,
    validate_collector_ids,
)
from .config_manager import ConfigurationManager


def _get_config_value(obj, key: str, default=None):
    """
    Safely retrieve a value from a config object or dict.

    The implementation uses ``obj``, ``key``, and ``default`` to safely retrieve
    a value from a config object or dict.

    Args:
        obj: Object whose ``__dict__`` and ``get`` state is read while
            performing safely retrieve a value from a config object or dict.
        key: Stable key used for lookup and operator-facing diagnostics.
        default: Fallback used when the requested value is absent or invalid.

    Returns:
        The value read from the mapping or attribute, or ``default`` when
        absent.
    """
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    if hasattr(obj, key):
        return getattr(obj, key)
    if hasattr(obj, "__dict__") and key in obj.__dict__:
        return obj.__dict__.get(key, default)
    return default


def _resolve_configured_skip_validation(
    config_data: Any,
    cli_value: bool,
    explicit_cli_params: Optional[Set[str]],
) -> bool:
    """
    Resolve the validation bypass through CLI and tool-YAML presence.

    The implementation uses ``config_data``, ``cli_value``, and
    ``explicit_cli_params`` to resolve the validation bypass through CLI and
    tool-YAML presence.

    Args:
        config_data: Config data governing validation bypass through CLI and
            tool-YAML presence.
        cli_value: Whether CLI value is enabled or required for this operation.
        explicit_cli_params: Entries supplied as ``explicit_cli_params`` without
            transferring container ownership.

    Returns:
        Whether the validation bypass through CLI and tool-YAML presence
        operation succeeds.
    """

    # Callers without Click provenance may have supplied either the CLI default
    # or an explicit false. Preserve their established value-based behavior.
    if explicit_cli_params is None or "skip_validation" in explicit_cli_params:
        return cli_value

    yaml_fields = getattr(config_data, "_yaml_fields", None)
    tool_value_is_explicit = (
        "skip_validation" in yaml_fields
        if yaml_fields is not None
        else _config_key_was_explicit(config_data, "skip_validation")
    )
    if tool_value_is_explicit:
        return bool(_get_config_value(config_data, "skip_validation", False))

    return cli_value


EXPAND_QUERY_LEVEL_KEYS = (
    "EXPAND_QUERY_CHASSIS_LEVEL",
    "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL",
    "EXPAND_QUERY_MANAGER_LEVEL",
    "EXPAND_QUERY_SYSTEM_LEVEL",
)

# These values can also be populated by BaseSettings environment fallbacks.
# Preserve their source through the Config -> ToolConfig boundary so runtime
# resolvers can keep tool YAML above lower-priority environment values.
SOURCE_SENSITIVE_TOOL_KEYS = (
    *EXPAND_QUERY_LEVEL_KEYS,
    *sorted(TIMEOUT_CONFIG_OVERRIDE_KEYS),
    "REDFISH_R31_PAYLOAD",
    "COLLECTOR_EXTENSION_CONFIG",
    "include_collectors",
    "skip_collectors",
    "COLLECTOR_TO_SKIP",
)

REDFISH_SESSION_POLICY_KEYS = frozenset({"tls_mode"})


def _config_key_was_explicit(config_data: Any, key: str) -> bool:
    """
    Return True when a key was present in the loaded tool config file.

    The compact expand_level spelling intentionally supplies all four
    resource-specific expansion keys.

    Args:
        config_data: Config data governing true when a key was present in the
            loaded tool config file.
        key: Stable key used for lookup and operator-facing diagnostics.

    Returns:
        Whether the true when a key was present in the loaded tool config file
        operation succeeds.
    """
    if config_data is None:
        return False
    if isinstance(config_data, dict):
        return key in config_data

    yaml_fields = getattr(config_data, "_yaml_fields", None)
    if yaml_fields is not None:
        if key in yaml_fields:
            return True
        # The compact expand_level spelling intentionally supplies all four
        # resource-specific expansion keys.
        if key in EXPAND_QUERY_LEVEL_KEYS and "expand_level" in yaml_fields:
            return True
        return False

    fields_set = getattr(config_data, "model_fields_set", None)
    if fields_set is not None:
        return key in fields_set

    fields_set = getattr(config_data, "__fields_set__", None)
    if fields_set is not None:
        return key in fields_set

    if hasattr(config_data, "__dict__"):
        return key in config_data.__dict__
    return False


def _execution_config_key_was_explicit(config_data: Any, key: str) -> bool:
    """
    Return True for an explicitly supplied flat or nested execution key.

    The implementation uses ``config_data`` and ``key`` to produce True for an
    explicitly supplied flat or nested execution key.

    Args:
        config_data: Config data governing true for an explicitly supplied flat
            or nested execution key.
        key: Stable key used for lookup and operator-facing diagnostics.

    Returns:
        Whether the true for an explicitly supplied flat or nested execution key
        operation succeeds.
    """
    if _config_key_was_explicit(config_data, key):
        return True
    for holder in ("execution", "execution_config"):
        section = _get_config_value(config_data, holder, None)
        if isinstance(section, dict):
            if key in section:
                return True
        elif _config_key_was_explicit(section, key):
            return True
    return False


def _resolve_report_format(
    config_data: Any,
    cli_value: str,
    explicit_cli_params: Optional[Set[str]],
) -> str:
    """
    Resolve CLI and accepted tool-config report format spellings.

    The implementation uses ``config_data``, ``cli_value``, and
    ``explicit_cli_params`` to resolve CLI and accepted tool-config report
    format spellings.

    Args:
        config_data: Config data governing CLI and accepted tool-config report
            format spellings.
        cli_value: Text supplied as CLI value in the format accepted by this
            function.
        explicit_cli_params: Entries supplied as ``explicit_cli_params`` without
            transferring container ownership.

    Returns:
        The canonical report format text.
    """

    # Callers predating provenance cannot prove that their value is only the
    # CLI default, so retain their existing behavior.
    if explicit_cli_params is None or "report_format" in explicit_cli_params:
        return cli_value

    if _config_key_was_explicit(config_data, "report_format"):
        return _get_config_value(config_data, "report_format", cli_value)

    output_config = _get_config_value(config_data, "output", None)
    if _config_key_was_explicit(output_config, "report_format"):
        return _get_config_value(output_config, "report_format", cli_value)

    return cli_value


def _to_plain_dict(val):
    """
    Convert a Pydantic model (v2 or v1), dict, or object to a plain dict.

    The implementation uses ``val`` to convert a Pydantic model (v2 or v1),
    dict, or object to a plain dict. The source value keeps its ownership while
    the normalized representation is returned separately.

    Args:
        val: Val object whose ``__dict__``, ``dict``, and ``model_dump`` state
            is read while performing pydantic model (v2 or v1), dict, or object
            to a plain dict.

    Returns:
        The plain dictionary.
    """
    if val is None:
        return None
    if isinstance(val, dict):
        return val
    if hasattr(val, "model_dump"):
        return val.model_dump()
    if hasattr(val, "dict"):
        return val.dict()
    if hasattr(val, "__dict__"):
        return dict(val.__dict__)
    return None


def _get_nested_config_as_dict(obj, key: str):
    """
    Get a nested config attribute and convert Pydantic models to dicts.

    After applying local validation, the function forwards ``obj`` and ``key``
    to ``_to_plain_dict`` and preserves its return and exception contract.

    Args:
        obj: Object evaluated while performing get a nested config attribute and
            convert Pydantic models to dicts.
        key: Stable key used for lookup and operator-facing diagnostics.

    Returns:
        The dictionary representation of nested config.
    """
    val = _get_config_value(obj, key, None)
    return _to_plain_dict(val)


def _get_redfish_session_config_as_dict(obj) -> Dict[str, Any]:
    """
    Project source-present Redfish session fields onto the tool boundary.

    The implementation uses ``obj`` to project source-present Redfish session
    fields onto the tool boundary.

    Args:
        obj: Object evaluated while performing project source-present Redfish
            session fields onto the tool boundary.

    Returns:
        A mapping containing dictionary representation of Redfish session
        config.
    """

    value = _get_config_value(obj, "redfish_session_config", None)
    if value is None:
        value = _get_config_value(obj, "redfish_sessions", None)
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "model_dump"):
        resolved = value.model_dump(exclude_unset=True)
        fields_set = set(getattr(value, "model_fields_set", set()))
        for field_name in RedfishResponseLimits.model_fields:
            if field_name in fields_set:
                resolved[field_name] = getattr(value, field_name)
        return resolved
    return _to_plain_dict(value) or {}


def _redfish_session_mode_was_explicit(obj) -> bool:
    """
    Return whether either holder supplied the canonical TLS policy selector.

    The implementation uses ``obj`` to determine whether either holder supplied
    the canonical TLS policy selector.

    Args:
        obj: Object evaluated while performing either holder supplied the
            canonical TLS policy selector.

    Returns:
        Whether either holder supplied the canonical TLS policy selector.
    """

    for holder in ("redfish_session_config", "redfish_sessions"):
        value = _get_config_value(obj, holder, None)
        if value is None:
            continue
        if isinstance(value, dict):
            fields = set(value)
        else:
            fields = set(getattr(value, "model_fields_set", set()))
            if not fields and hasattr(value, "model_dump"):
                fields = set(value.model_dump(exclude_unset=True))
        if REDFISH_SESSION_POLICY_KEYS.intersection(fields):
            return True
    return False


def _get_preflight_config_as_dict(obj) -> Dict[str, Any]:
    """
    Project only explicitly supplied fields from the canonical holder.

    The implementation uses ``obj`` to project only explicitly supplied fields
    from the canonical holder.

    Args:
        obj: Object evaluated while performing project only explicitly supplied
            fields from the canonical holder.

    Returns:
        A mapping containing dictionary representation of preflight config.
    """

    value = _get_config_value(obj, "preflight_config", None)
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(exclude_unset=True)
    return _to_plain_dict(value) or {}


def should_use_cli_value(cli_value, config_value, default_value):
    """
    Return True if CLI value should override config file value.

    If CLI value differs from its default, the user explicitly set it and it
    wins. Otherwise fall back to the config file value.

    Args:
        cli_value: CLI value consumed while the function attempts to produce
            True if CLI value should override config file value.
        config_value: Config value governing true if CLI value should override
            config file value.
        default_value: Default value consumed while the function attempts to
            produce True if CLI value should override config file value.

    Returns:
        Whether the true if CLI value should override config file value
        operation succeeds.
    """
    if cli_value != default_value:
        return True
    if config_value != default_value:
        return False
    return True


def _resolve_configured_debug(
    config_data: Any,
    cli_value: bool,
    explicit_cli_params: Optional[Set[str]],
) -> bool:
    """
    Resolve CLI and accepted tool-config debug spellings by source presence.

    The implementation uses ``config_data``, ``cli_value``, and
    ``explicit_cli_params`` to resolve CLI and accepted tool-config debug
    spellings by source presence.

    Args:
        config_data: Config data governing CLI and accepted tool-config debug
            spellings by source presence.
        cli_value: Whether CLI value is enabled or required for this operation.
        explicit_cli_params: Entries supplied as ``explicit_cli_params`` without
            transferring container ownership.

    Returns:
        Whether the CLI and accepted tool-config debug spellings by source
        presence operation succeeds.
    """

    # Callers without Click provenance may have supplied either the CLI default
    # or an explicit false. Preserve their established value-based behavior.
    if explicit_cli_params is None or "debug" in explicit_cli_params:
        return cli_value

    yaml_fields = getattr(config_data, "_yaml_fields", None)
    flat_is_explicit = (
        "debug" in yaml_fields
        if yaml_fields is not None
        else _config_key_was_explicit(config_data, "debug")
    )
    if flat_is_explicit:
        return _get_config_value(config_data, "debug", False)

    logging_config = _get_config_value(config_data, "logging", None)
    if _config_key_was_explicit(logging_config, "debug"):
        return _get_config_value(logging_config, "debug", False)

    return cli_value


class ToolConfigLoadError(RuntimeError):
    """
    Raised when a resolved tool configuration cannot be loaded.

    Callers receive this exception when the tool config load error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


def _resolve_configured_verbose(
    config_data: Any,
    cli_value: bool,
    explicit_cli_params: Optional[Set[str]],
) -> bool:
    """
    Resolve CLI and accepted tool-config verbose spellings by source presence.

    The implementation uses ``config_data``, ``cli_value``, and
    ``explicit_cli_params`` to resolve CLI and accepted tool-config verbose
    spellings by source presence.

    Args:
        config_data: Config data governing CLI and accepted tool-config verbose
            spellings by source presence.
        cli_value: Whether CLI value is enabled or required for this operation.
        explicit_cli_params: Entries supplied as ``explicit_cli_params`` without
            transferring container ownership.

    Returns:
        Whether the CLI and accepted tool-config verbose spellings by source
        presence operation succeeds.
    """

    # Callers without Click provenance may have supplied either the CLI default
    # or an explicit false. Preserve their established value-based behavior.
    if explicit_cli_params is None or "verbose" in explicit_cli_params:
        return cli_value

    yaml_fields = getattr(config_data, "_yaml_fields", None)
    flat_is_explicit = (
        "verbose" in yaml_fields
        if yaml_fields is not None
        else _config_key_was_explicit(config_data, "verbose")
    )
    if flat_is_explicit:
        return _get_config_value(config_data, "verbose", False)

    logging_config = _get_config_value(config_data, "logging", None)
    if _config_key_was_explicit(logging_config, "verbose"):
        return _get_config_value(logging_config, "verbose", False)

    return cli_value


def _load_tool_config(
    config_file: Optional[Path],
    sanitized_console,
) -> Config | dict:
    """
    Load a tool config file safely.

    An omitted configuration uses defaults; a resolved configuration must load.

    Args:
        config_file: filesystem location used as the config file for this
            operation.
        sanitized_console: Sanitized console object whose ``print_error``,
            ``print_info``, and ``print_warning`` state is read while performing
            tool config file safely.

    Returns:
        Validated tool configuration, or an empty mapping when no file is supplied.

    Raises:
        ToolConfigLoadError: If tool configuration file not found:
            ``config_file``; or could not load tool configuration: ``e``.
    """
    if config_file is None:
        return {}
    if not config_file.exists():
        raise ToolConfigLoadError(f"Tool configuration file not found: {config_file}")

    try:
        config_data = load_config(config_file)
        sanitized_console.print_info(f"Loaded tool configuration from: {config_file}")
        for message in tool_config_deprecation_messages(config_data):
            sanitized_console.print_warning(message)
        return config_data
    except Exception as e:
        if "Invalid YAML" in str(e):
            sanitized_console.print_warning(
                f"Warning: Tool config file has YAML syntax errors: {e}"
            )
        elif "not found" in str(e).lower():
            sanitized_console.print_warning(
                f"Warning: Tool config file not found or inaccessible: {e}"
            )
        elif "Permission denied" in str(e):
            sanitized_console.print_warning(
                f"Warning: Permission denied reading tool config file: {e}"
            )
        else:
            sanitized_console.print_error(
                f"Configuration error loading tool config file: {e}"
            )
        raise ToolConfigLoadError(f"Could not load tool configuration: {e}") from e


def _extract_tool_defaults(
    config_data,
    cli_output_dir: Path,
    *,
    cli_output_explicit: bool = False,
) -> Dict[str, Any]:
    """
    Extract tool-level defaults from a loaded config object.

    Returns a flat dict with all the config-derived values that collect() needs
    to build a ToolConfig. When config_data is empty / a plain dict (i.e. no
    config was loaded), every key gets its hard-coded default.

    Args:
        config_data: Config data governing extract tool-level defaults from a
            loaded config object.
        cli_output_dir: filesystem location used as the CLI output dir for this
            operation.
        cli_output_explicit: Whether CLI output explicit is enabled or required
            for this operation.

    Returns:
        A mapping containing tool defaults.
    """
    d: Dict[str, Any] = {
        "config_generate_html_reports": True,
        "config_log_sanitization": True,
        "final_output_dir": str(cli_output_dir),
        "tool_config_baseboard": None,
        "environment_baseboard": None,
        "concurrency_mode": "conservative",
        "initial_io_oversubscription": None,
        "minimum_collector_operations": 1,
        "maximum_collector_operations": None,
        "adaptive_concurrency": {},
        "max_concurrent_duts": None,
        "max_concurrent_collectors_per_dut": (
            DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT
        ),
        "timeout": 300,
        "retry_count": 3,
        "config_skip_zip": False,
        "config_skip_zip_split": False,
        "config_zip_split_threshold": 200.0,
        "config_log_level": "INFO",
        "config_log_format": "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        "execution_scheduler": "per_dut",
        "parallel_dut_sequential_collectors": True,
        "service_grouped_sequential_collectors": True,
    }

    if not config_data or isinstance(config_data, dict):
        return d

    # --- HTML reports ---
    output_config = _get_config_value(config_data, "output", None)
    flat_skip_explicit = _config_key_was_explicit(config_data, "skip_html_reports")
    nested_generate_explicit = _config_key_was_explicit(output_config, "generate_html")
    if flat_skip_explicit and not nested_generate_explicit:
        d["config_generate_html_reports"] = not getattr(
            config_data, "skip_html_reports"
        )
    elif nested_generate_explicit:
        d["config_generate_html_reports"] = _get_config_value(
            output_config, "generate_html", True
        )
    else:
        d["config_generate_html_reports"] = getattr(
            config_data, "GENERATE_HTML_REPORTS", True
        )

    # --- Log sanitization ---
    if hasattr(config_data, "sanitization") and config_data.sanitization:
        d["config_log_sanitization"] = _get_config_value(
            config_data.sanitization, "enabled", True
        )
    else:
        d["config_log_sanitization"] = getattr(config_data, "LogSanitization", True)

    # --- Baseboard source separation ---
    # BaseSettings materializes BASEBOARD into Config. Keep that lower-priority
    # environment value separate from an actual YAML value so catalog-assisted
    # detection can run first. Presence is authoritative, including an explicit
    # empty value or the displayed code default.
    yaml_fields = getattr(config_data, "_yaml_fields", None)
    if yaml_fields is not None:
        if "baseboard" in yaml_fields:
            d["tool_config_baseboard"] = getattr(config_data, "baseboard", None)
        elif "TargetBaseboard" in yaml_fields:
            legacy_baseboard = getattr(config_data, "TargetBaseboard", None)
            d["tool_config_baseboard"] = (
                legacy_baseboard.lower()
                if isinstance(legacy_baseboard, str)
                else legacy_baseboard
            )
        elif "BASEBOARD" in os.environ:
            d["environment_baseboard"] = str(os.environ["BASEBOARD"]).strip() or None
    elif hasattr(config_data, "TargetBaseboard") and config_data.TargetBaseboard:
        # Programmatic objects have no source provenance. Retain their legacy
        # value-based behavior.
        d["tool_config_baseboard"] = config_data.TargetBaseboard
    elif (
        hasattr(config_data, "baseboard")
        and config_data.baseboard
        and config_data.baseboard != "compute"
    ):
        d["tool_config_baseboard"] = config_data.baseboard

    # --- Output directory (only override when CLI left the /tmp default) ---
    # A materialized OutputConfig.directory is not itself a tool source. Use
    # Pydantic's field-presence boundary for both accepted YAML spellings, then
    # consult the declared environment alias as the lower-priority fallback.
    output_config = getattr(config_data, "output", None)
    nested_output_explicit = _config_key_was_explicit(output_config, "directory")
    flat_output_explicit = _config_key_was_explicit(config_data, "output_directory")
    environment_output_dir = next(
        (value for key, value in os.environ.items() if key.casefold() == "output_dir"),
        None,
    )
    if not cli_output_explicit and (
        str(cli_output_dir) == "/tmp" or cli_output_dir == Path("/tmp")
    ):
        if nested_output_explicit:
            output_value = _get_config_value(output_config, "directory")
        elif flat_output_explicit:
            output_value = _get_config_value(config_data, "output_directory")
        else:
            output_value = environment_output_dir

        if output_value is not None:
            d["final_output_dir"] = str(output_value)
        if d["final_output_dir"].startswith("~"):
            d["final_output_dir"] = os.path.expanduser(d["final_output_dir"])

    # --- Execution params ---
    nested_execution_values: Dict[str, Any] = {}
    for holder in ("execution_config", "execution"):
        section = _get_config_value(config_data, holder, None)
        if hasattr(section, "model_dump"):
            section = section.model_dump(exclude_unset=True)
        if isinstance(section, dict):
            nested_execution_values.update(section)

    environment_keys = {key.casefold() for key in os.environ}

    for field_name, default_value in (
        ("concurrency_mode", "conservative"),
        ("initial_io_oversubscription", None),
        ("minimum_collector_operations", 1),
        ("maximum_collector_operations", None),
    ):
        if field_name in nested_execution_values:
            d[field_name] = nested_execution_values[field_name]
        elif _config_key_was_explicit(config_data, field_name):
            d[field_name] = getattr(config_data, field_name, default_value)
        elif field_name in environment_keys:
            d[field_name] = getattr(config_data, field_name, default_value)
    raw_adaptive = nested_execution_values.get("adaptive", {}) or {}
    if hasattr(raw_adaptive, "model_dump"):
        raw_adaptive = raw_adaptive.model_dump(exclude_unset=True)
    if isinstance(raw_adaptive, dict):
        d["adaptive_concurrency"] = dict(raw_adaptive)

    if "max_concurrent_duts" in nested_execution_values:
        d["max_concurrent_duts"] = nested_execution_values["max_concurrent_duts"]
    elif _config_key_was_explicit(config_data, "max_concurrent_duts"):
        d["max_concurrent_duts"] = getattr(config_data, "max_concurrent_duts", None)
    elif "max_concurrent_duts" in environment_keys:
        d["max_concurrent_duts"] = getattr(config_data, "max_concurrent_duts", None)
    if "max_concurrent_collectors_per_dut" in nested_execution_values:
        d["max_concurrent_collectors_per_dut"] = nested_execution_values[
            "max_concurrent_collectors_per_dut"
        ]
    elif _config_key_was_explicit(config_data, "max_concurrent_collectors_per_dut"):
        d["max_concurrent_collectors_per_dut"] = getattr(
            config_data, "max_concurrent_collectors_per_dut"
        )
    elif "max_concurrent_collectors_per_dut" in environment_keys:
        d["max_concurrent_collectors_per_dut"] = getattr(
            config_data, "max_concurrent_collectors_per_dut"
        )
    else:
        d["max_concurrent_collectors_per_dut"] = (
            DEFAULT_MAX_CONCURRENT_COLLECTORS_PER_DUT
        )
    d["timeout"] = nested_execution_values.get(
        "timeout", getattr(config_data, "timeout", 300)
    )
    d["retry_count"] = nested_execution_values.get(
        "retry_count", getattr(config_data, "retry_count", 3)
    )

    # --- Zip settings ---
    if hasattr(config_data, "output"):
        create_zip = getattr(config_data.output, "create_zip", True)
        create_split_zip = getattr(config_data.output, "create_split_zip", True)
        d["config_zip_split_threshold"] = getattr(
            config_data.output, "zip_split_threshold", 200.0
        )
    else:
        create_zip = True
        create_split_zip = True
    d["config_skip_zip"] = not create_zip
    d["config_skip_zip_split"] = not create_split_zip

    # --- Logging ---
    d["config_log_level"] = getattr(config_data, "log_level", "INFO")
    d["config_log_format"] = getattr(
        config_data,
        "log_format",
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    )

    # --- Parallelization ---
    d["execution_scheduler"] = getattr(config_data, "execution_scheduler", "per_dut")
    d["parallel_dut_sequential_collectors"] = getattr(
        config_data, "PARALLEL_DUT_SEQUENTIAL_COLLECTORS", True
    )
    d["service_grouped_sequential_collectors"] = getattr(
        config_data, "SERVICE_GROUPED_SEQUENTIAL_COLLECTORS", True
    )

    return d


def _load_dut_defaults_from_yaml(path: Optional[Path]) -> Dict[str, Any]:
    """
    Read the ``DUT_Defaults`` block from a dut_config.yaml.

    Used in CLI mode so an auto-detected dut_config.yaml (one sitting next to
    the executable, picked up by ``_resolve_config_paths``) can still supply
    defaults like ``baseboard`` even though CLI mode builds the DUT from
    scratch. Missing files and sections return an empty mapping; an explicitly
    invalid section type fails closed.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        A mapping containing DUT defaults from YAML.

    Raises:
        ValueError: If invalid auto-detected DUT configuration YAML:
            ``source_path``; or the dut_defaults are not a mapping.
    """
    if path is None or not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = load_yaml_strict(f)
            data = loaded if isinstance(loaded, dict) else {}
    except yaml.YAMLError as exc:
        source_path = repr(str(path))
        if len(source_path) > 512:
            source_path = f"{source_path[:254]}...{source_path[-255:]}"
        raise ValueError(
            f"Invalid auto-detected DUT configuration YAML: {source_path}"
        ) from exc
    except OSError:
        return {}
    if not isinstance(data, dict) or "DUT_Defaults" not in data:
        return {}
    defaults = data["DUT_Defaults"]
    if not isinstance(defaults, dict):
        raise ValueError("DUT_Defaults must be a mapping")
    return defaults


def _build_cli_dut_config(
    baseboard,
    tool_config_baseboard,
    local,
    non_interactive,
    bmc_ip,
    bmc_user,
    bmc_pass,
    bmc_ssh_user,
    bmc_ssh_pass,
    bmc_ssh_port,
    bmc_ssh_key_path,
    bmc_ssh_passwordless,
    bmc_ssh_max_retries,
    bmc_rf_user,
    bmc_rf_pass,
    bmc_rf_port,
    host_ip,
    host_user,
    host_pass,
    host_ssh_port,
    host_ssh_key_path,
    host_ssh_passwordless,
    host_ssh_max_retries,
    hmc_ip,
    hmc_user,
    hmc_pass,
    hmc_ssh_user,
    hmc_ssh_pass,
    hmc_ssh_port,
    hmc_ssh_key_path,
    hmc_ssh_passwordless,
    hmc_ssh_max_retries,
    hmc_http_port,
    hmc_https_port,
    hmc_use_https,
    use_port_forwarding,
    tunnel_tcp_port,
    setup_port_forwarding,
    force_port_fw,
    hmc_access_method,
    rf_hmc_prefix,
    rf_bmc_prefix,
    ssh_proxy_host,
    ssh_proxy_port,
    ssh_proxy_user,
    ssh_proxy_pass,
    ssh_proxy_key_path,
    ssh_proxy_passwordless,
    ssh_proxy_max_retries,
    sanitized_console,
    dut_defaults: Optional[Dict[str, Any]] = None,
    dut_name: str = "dut-1",
):
    """
    Build a single DUTConfig from CLI arguments (CLI mode).

    ``dut_defaults`` is the ``DUT_Defaults`` block loaded from an auto-detected
    ``dut_config.yaml`` (or empty if none was found). It supplies fallbacks that
    CLI flags can still override — currently just ``baseboard``, but the
    parameter is generic so more fields can be added without another signature
    change.

    ``dut_name`` identifies the CLI-defined target and its output directory.

    Returns a List[DUTConfig] with one entry.

    Args:
        baseboard: Baseboard consumed while the function attempts to build a
            single DUTConfig from CLI arguments (CLI mode).
        tool_config_baseboard: Tool config baseboard governing single DUTConfig
            from CLI arguments (CLI mode).
        local: Local consumed while the function attempts to build a single
            DUTConfig from CLI arguments (CLI mode).
        non_interactive: Non interactive consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        bmc_ip: BMC IP consumed while the function attempts to build a single
            DUTConfig from CLI arguments (CLI mode).
        bmc_user: BMC user consumed while the function attempts to build a
            single DUTConfig from CLI arguments (CLI mode).
        bmc_pass: BMC pass consumed while the function attempts to build a
            single DUTConfig from CLI arguments (CLI mode).
        bmc_ssh_user: BMC SSH user consumed while the function attempts to build
            a single DUTConfig from CLI arguments (CLI mode).
        bmc_ssh_pass: BMC SSH pass consumed while the function attempts to build
            a single DUTConfig from CLI arguments (CLI mode).
        bmc_ssh_port: BMC SSH port consumed while the function attempts to build
            a single DUTConfig from CLI arguments (CLI mode).
        bmc_ssh_key_path: filesystem location used as the BMC SSH key path for
            this operation.
        bmc_ssh_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        bmc_ssh_max_retries: BMC SSH max retries consumed while the function
            attempts to build a single DUTConfig from CLI arguments (CLI mode).
        bmc_rf_user: BMC Redfish user consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        bmc_rf_pass: BMC Redfish pass consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        bmc_rf_port: BMC Redfish port consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        host_ip: Host IP consumed while the function attempts to build a single
            DUTConfig from CLI arguments (CLI mode).
        host_user: Host user consumed while the function attempts to build a
            single DUTConfig from CLI arguments (CLI mode).
        host_pass: Host pass consumed while the function attempts to build a
            single DUTConfig from CLI arguments (CLI mode).
        host_ssh_port: Host SSH port consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        host_ssh_key_path: filesystem location used as the host SSH key path for
            this operation.
        host_ssh_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        host_ssh_max_retries: Host SSH max retries consumed while the function
            attempts to build a single DUTConfig from CLI arguments (CLI mode).
        hmc_ip: HMC IP consumed while the function attempts to build a single
            DUTConfig from CLI arguments (CLI mode).
        hmc_user: HMC user consumed while the function attempts to build a
            single DUTConfig from CLI arguments (CLI mode).
        hmc_pass: HMC pass consumed while the function attempts to build a
            single DUTConfig from CLI arguments (CLI mode).
        hmc_ssh_user: HMC SSH user consumed while the function attempts to build
            a single DUTConfig from CLI arguments (CLI mode).
        hmc_ssh_pass: HMC SSH pass consumed while the function attempts to build
            a single DUTConfig from CLI arguments (CLI mode).
        hmc_ssh_port: HMC SSH port consumed while the function attempts to build
            a single DUTConfig from CLI arguments (CLI mode).
        hmc_ssh_key_path: filesystem location used as the HMC SSH key path for
            this operation.
        hmc_ssh_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        hmc_ssh_max_retries: HMC SSH max retries consumed while the function
            attempts to build a single DUTConfig from CLI arguments (CLI mode).
        hmc_http_port: HMC HTTP port consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        hmc_https_port: HMC HTTPS port consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        hmc_use_https: HMC use HTTPS consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        use_port_forwarding: Whether use port forwarding is enabled or required
            for this operation.
        tunnel_tcp_port: Tunnel TCP port consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        setup_port_forwarding: Setup port forwarding consumed while the function
            attempts to build a single DUTConfig from CLI arguments (CLI mode).
        force_port_fw: Force port firmware consumed while the function attempts
            to build a single DUTConfig from CLI arguments (CLI mode).
        hmc_access_method: HMC access method consumed while the function
            attempts to build a single DUTConfig from CLI arguments (CLI mode).
        rf_hmc_prefix: Redfish HMC prefix consumed while the function attempts
            to build a single DUTConfig from CLI arguments (CLI mode).
        rf_bmc_prefix: Redfish BMC prefix consumed while the function attempts
            to build a single DUTConfig from CLI arguments (CLI mode).
        ssh_proxy_host: SSH proxy host consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        ssh_proxy_port: SSH proxy port consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        ssh_proxy_user: SSH proxy user consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        ssh_proxy_pass: SSH proxy pass consumed while the function attempts to
            build a single DUTConfig from CLI arguments (CLI mode).
        ssh_proxy_key_path: filesystem location used as the SSH proxy key path
            for this operation.
        ssh_proxy_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        ssh_proxy_max_retries: SSH proxy max retries consumed while the function
            attempts to build a single DUTConfig from CLI arguments (CLI mode).
        sanitized_console: Sanitized console object whose ``print_info`` state
            is read while performing single DUTConfig from CLI arguments (CLI
            mode).
        dut_defaults: Optional DUT defaults; ``None`` selects the function's
            default behavior.
        dut_name: Stable DUT name used for lookup and operator-facing
            diagnostics.

    Returns:
        A validated DUT configuration assembled from CLI values and configured
        defaults.
    """
    dut_defaults = dut_defaults or {}
    dut_defaults_baseboard = dut_defaults.get("baseboard")
    # Precedence: CLI --baseboard > DUT_Defaults.baseboard > tool_config baseboard
    effective_baseboard = baseboard or dut_defaults_baseboard or tool_config_baseboard

    if not local and not effective_baseboard:
        sanitized_console.print_info(
            "No baseboard specified - auto-detection will be used to determine baseboard"
        )
    elif not baseboard and dut_defaults_baseboard:
        sanitized_console.print_info(
            f"Using baseboard '{dut_defaults_baseboard}' from auto-detected dut_config.yaml DUT_Defaults"
        )
    elif not baseboard and tool_config_baseboard:
        sanitized_console.print_info(
            f"Using baseboard '{tool_config_baseboard}' from tool_config.yaml"
        )

    dut_config_obj = DUTConfig(
        name=dut_name,
        **(
            {"baseboard": effective_baseboard}
            if effective_baseboard is not None
            else {}
        ),
        local=local,
        non_interactive=non_interactive,
        bmc_ip=bmc_ip,
        bmc_user=bmc_user,
        bmc_pass=bmc_pass,
        bmc_ssh_user=bmc_ssh_user,
        bmc_ssh_pass=bmc_ssh_pass,
        bmc_ssh_port=bmc_ssh_port,
        bmc_ssh_key_path=bmc_ssh_key_path,
        bmc_ssh_passwordless=bmc_ssh_passwordless,
        bmc_ssh_max_retries=bmc_ssh_max_retries,
        bmc_rf_user=bmc_rf_user,
        bmc_rf_pass=bmc_rf_pass,
        bmc_rf_port=bmc_rf_port,
        host_ip=host_ip,
        host_user=host_user,
        host_pass=host_pass,
        host_ssh_port=host_ssh_port,
        host_ssh_key_path=host_ssh_key_path,
        host_ssh_passwordless=host_ssh_passwordless,
        host_ssh_max_retries=host_ssh_max_retries,
        hmc_ip=hmc_ip,
        hmc_user=hmc_user,
        hmc_pass=hmc_pass,
        hmc_ssh_user=hmc_ssh_user,
        hmc_ssh_pass=hmc_ssh_pass,
        hmc_ssh_port=hmc_ssh_port,
        hmc_ssh_key_path=hmc_ssh_key_path,
        hmc_ssh_passwordless=hmc_ssh_passwordless,
        hmc_ssh_max_retries=hmc_ssh_max_retries,
        hmc_http_port=hmc_http_port,
        hmc_https_port=hmc_https_port,
        hmc_use_https=hmc_use_https,
        use_port_forwarding=use_port_forwarding,
        tunnel_tcp_port=tunnel_tcp_port,
        setup_port_forwarding=(
            setup_port_forwarding if setup_port_forwarding is not None else False
        ),
        force_port_fw=force_port_fw if force_port_fw is not None else False,
        hmc_access_method=hmc_access_method,
        ssh_proxy_host=ssh_proxy_host,
        ssh_proxy_port=ssh_proxy_port,
        ssh_proxy_user=ssh_proxy_user,
        ssh_proxy_pass=ssh_proxy_pass,
        ssh_proxy_key_path=ssh_proxy_key_path,
        ssh_proxy_passwordless=ssh_proxy_passwordless,
        ssh_proxy_max_retries=ssh_proxy_max_retries,
        **(
            {"RF_HMC_DEFAULT_PREFIX": rf_hmc_prefix}
            if rf_hmc_prefix is not None
            else {}
        ),
        **({"RF_DEFAULT_PREFIX": rf_bmc_prefix} if rf_bmc_prefix is not None else {}),
    )
    return [dut_config_obj]


def _load_config_mode_duts(
    dut_config: Path,
    config_file: Optional[Path],
    baseboard: Optional[str],
    non_interactive: bool,
    sanitized_console,
    *,
    non_interactive_cli_explicit: Optional[bool] = None,
    non_interactive_tool_explicit: bool = False,
) -> tuple:
    """
    Load DUT configs from a DUT config file (config mode).

    Handles auto_assign_config_file_to_use for baseboard resolution, applies the
    CLI --baseboard override for a single DUT, and resolves non_interactive
    without treating an omitted CLI default as explicit.

    Returns (List[DUTConfig], original_dut_config_path). Any private
    auto-assigned snapshot is deleted immediately after model loading.

    Args:
        dut_config: filesystem location used as the DUT config for this
            operation.
        config_file: filesystem location used as the config file for this
            operation.
        baseboard: Text supplied as baseboard in the format accepted by this
            function.
        non_interactive: Whether non interactive is enabled or required for this
            operation.
        sanitized_console: Sanitized console object whose ``print_error``,
            ``print_info``, ``print_success``, and ``print_warning`` state is
            read while performing DUT configs from a DUT config file (config
            mode).
        non_interactive_cli_explicit: Optional non interactive CLI explicit;
            ``None`` selects the function's default behavior.
        non_interactive_tool_explicit: Whether non interactive tool explicit is
            enabled or required for this operation.
    Returns:
        A tuple containing ``DUT configs`` and ``DUT config`` in that order.

    Raises:
        SystemExit: If the function cannot load DUT configs from a DUT config
            file (config mode) safely.
    """
    # Auto-assign ConfigFileToUse for DUTs that have no baseboard set
    if config_file:
        # The active tool file is the only eligible per-DUT fallback. Pulling
        # an unrelated discovered legacy config into this list would introduce
        # an unselected source above the active global tool configuration.
        config_files_for_auto_assignment = [config_file]
    else:
        _auto_dut, auto_config, _auto_tool = find_all_config_files()
        config_files_for_auto_assignment = [auto_config]
    resolved_dut_config = auto_assign_config_file_to_use(
        dut_config, config_files_for_auto_assignment
    )

    if not resolved_dut_config.exists():
        sanitized_console.print_failure(
            f"DUT config file '{resolved_dut_config}' does not exist.",
            title="DUT Configuration Error",
            suggestions=(
                "Check the --dut-config path and file permissions.",
                "Run 'nvdebug collect --help' to review supported target sources.",
            ),
        )
        raise SystemExit(2)

    try:
        dut_configs = load_dut_config(resolved_dut_config)
        sanitized_console.print_success(
            f"Loaded DUT config from: {resolved_dut_config}"
        )
    except Exception as e:
        display_dut_config_error(str(e))
        raise SystemExit(2)
    finally:
        # auto_assign_config_file_to_use writes a credential-bearing private
        # snapshot. Once load_dut_config has materialized the models, no later
        # phase needs that file. Delete it here on success and every parse/load
        # failure so later validation errors cannot strand credentials.
        if resolved_dut_config != dut_config:
            try:
                resolved_dut_config.unlink(missing_ok=True)
                sanitized_console.print_info("Cleaned up temporary DUT config file")
            except Exception as cleanup_error:
                sanitized_console.print_warning(
                    f"Could not clean up temporary file: {cleanup_error}"
                )

    # Apply --baseboard CLI override
    if baseboard:
        if len(dut_configs) == 1:
            sanitized_console.print_info(
                f"CLI baseboard parameter '-b {baseboard}' provided - overriding baseboard in DUT config file"
            )
            for dut in dut_configs:
                dut.baseboard = baseboard
                sanitized_console.print_success(
                    f"Set baseboard '{baseboard}' for DUT '{dut.name}' (overriding config file)"
                )
        else:
            sanitized_console.print_failure(
                "-b/--baseboard is only applicable when running on a single DUT. "
                "A multi-DUT configuration defines more than one DUT, so this "
                "per-DUT override is ambiguous.",
                title="Conflicting DUT Options",
                suggestions=(
                    "Remove -b/--baseboard and configure the baseboard on each DUT in the DUT config file.",
                    "Use a DUT config containing one DUT when applying a CLI baseboard override.",
                ),
            )
            raise SystemExit(2)

    cli_non_interactive_wins = (
        bool(non_interactive)
        if non_interactive_cli_explicit is None
        else non_interactive_cli_explicit
    )
    for dc in dut_configs:
        if cli_non_interactive_wins:
            dc.non_interactive = non_interactive
        elif (
            non_interactive_tool_explicit
            and "non_interactive" not in dc.model_fields_set
        ):
            dc.non_interactive = non_interactive

    return dut_configs, dut_config


def _resolve_config_paths(
    config_file: Optional[Path],
    dut_config: Optional[Path],
    sanitized_console,
    local_mode: bool = False,
) -> tuple:
    """
    Resolve config paths through CLI, environment, then discovery.

    Discovery runs only when either higher-priority locator remains unresolved.
    Returns (tool_config_path, dut_config_path). Environment ``~`` expansion
    errors are allowed to propagate so an invalid selected locator is not
    silently replaced by discovery.

    Args:
        config_file: filesystem location used as the config file for this
            operation.
        dut_config: filesystem location used as the DUT config for this
            operation.
        sanitized_console: Sanitized console object whose ``print_info`` state
            is read while performing config paths through CLI, environment, then
            discovery.
        local_mode: Whether local mode is enabled or required for this
            operation.

    Returns:
        A tuple containing ``resolved tool`` and ``resolved DUT`` in that order.
    """
    resolved_dut = dut_config
    resolved_tool = config_file

    # Explicit CLI paths remain authoritative. Environment locators are used
    # only when their CLI counterpart was omitted, and outrank discovery.
    if resolved_dut is None:
        env_dut = os.environ.get("NVDEBUG_DUT_CONFIG", "").strip()
        if env_dut:
            resolved_dut = Path(env_dut).expanduser()
            sanitized_console.print_info(
                f"Using DUT config from NVDEBUG_DUT_CONFIG: {resolved_dut}"
            )
    if resolved_tool is None:
        env_tool = os.environ.get("NVDEBUG_CONFIG_FILE", "").strip()
        if env_tool:
            resolved_tool = Path(env_tool).expanduser()
            sanitized_console.print_info(
                f"Using tool config from NVDEBUG_CONFIG_FILE: {resolved_tool}"
            )

    auto_dut_config = None
    auto_config = None
    auto_tool_config = None
    if not resolved_dut or not resolved_tool:
        auto_dut_config, auto_config, auto_tool_config = find_all_config_files()

    if not resolved_dut and auto_dut_config:
        resolved_dut = auto_dut_config
        if local_mode:
            sanitized_console.print_info(
                "Auto-detected dut_config.yaml for DUT_Defaults only "
                f"(--local uses local dut-1, not configured DUT targets): {resolved_dut}"
            )
        else:
            sanitized_console.print_info(
                f"Auto-detected DUT config file: {resolved_dut}"
            )

    if not resolved_tool:
        if auto_tool_config:
            resolved_tool = auto_tool_config
            sanitized_console.print_info(
                f"Auto-detected tool_config.yaml: {resolved_tool}"
            )
        elif auto_config:
            resolved_tool = auto_config
            sanitized_console.print_info(
                f"Auto-detected config.yaml (legacy): {resolved_tool}"
            )

    return resolved_tool, resolved_dut


def _preflight_target_source_available(
    dut_config: Optional[Path],
    *,
    local: bool,
    ansible_inventory: Optional[Path],
    has_cli_credentials: bool,
) -> bool:
    """
    Return whether preflight has an explicit, environment, or discovered target.

    The implementation uses ``dut_config``, ``local``, ``ansible_inventory``,
    and ``has_cli_credentials`` to determine whether preflight has an explicit,
    environment, or discovered target.

    Args:
        dut_config: filesystem location used as the DUT config for this
            operation.
        local: Whether local is enabled or required for this operation.
        ansible_inventory: filesystem location used as the ansible inventory for
            this operation.
        has_cli_credentials: Sensitive value supplied through the approved input
            boundary and never logged.

    Returns:
        Whether preflight has an explicit, environment, or discovered target.
    """

    if local or ansible_inventory is not None or has_cli_credentials:
        return True
    if dut_config is not None or os.environ.get("NVDEBUG_DUT_CONFIG", "").strip():
        return True
    auto_dut_config, _, _ = find_all_config_files()
    return auto_dut_config is not None


def _resolve_source_config_paths(
    config_file: Optional[Path],
    original_dut_config: Optional[Path],
    dut_config,  # Path or other; only used if original_dut_config is not a Path
) -> tuple:
    """
    Resolve source tool config and DUT config paths for archiving (best-effort).

    Returns (source_tool_config_path, source_dut_config_path); either may be
    None. Falls back to find_all_config_files() when a path is missing or does
    not exist.

    Args:
        config_file: filesystem location used as the config file for this
            operation.
        original_dut_config: filesystem location used as the original DUT config
            for this operation.
        dut_config: DUT config governing source tool config and DUT config paths
            for archiving (best-effort).

    Returns:
        A tuple containing ``source tool config path`` and ``source DUT config
        path`` in that order.
    """
    source_tool_config_path = config_file if isinstance(config_file, Path) else None
    source_dut_config_path = (
        original_dut_config
        if isinstance(original_dut_config, Path)
        else (dut_config if isinstance(dut_config, Path) else None)
    )

    if source_tool_config_path is None or not source_tool_config_path.exists():
        try:
            _, _, auto_tool_config = find_all_config_files()
            if auto_tool_config and auto_tool_config.exists():
                source_tool_config_path = auto_tool_config
        except Exception:
            pass

    if source_dut_config_path is None or not source_dut_config_path.exists():
        try:
            auto_dut_config, _, _ = find_all_config_files()
            if auto_dut_config and auto_dut_config.exists():
                source_dut_config_path = auto_dut_config
        except Exception:
            pass

    return source_tool_config_path, source_dut_config_path


def build_tool_config(
    config_file_data: Any,
    *,
    final_output_dir: str,
    final_collection_level: str,
    tool_config_baseboard: Optional[str] = None,
    environment_baseboard: Optional[str] = None,
    concurrency_mode: str = "conservative",
    initial_io_oversubscription: Optional[float] = None,
    minimum_collector_operations: int = 1,
    maximum_collector_operations: Optional[int] = None,
    adaptive_concurrency: Optional[Dict[str, Any]] = None,
    max_concurrent_duts: Optional[int],
    max_concurrent_collectors_per_dut: int,
    timeout: int,
    retry_count: int,
    config_skip_zip: bool,
    config_skip_zip_split: bool,
    config_zip_split_threshold: float,
    config_log_level: str,
    config_log_format: str,
    config_log_sanitization: bool,
    config_generate_html_reports: bool,
    execution_scheduler: str,
    parallel_dut_sequential_collectors: bool,
    service_grouped_sequential_collectors: bool,
    skip_zip: bool,
    skip_zip_split: bool,
    zip_split_threshold: float,
    skip_sanitization: bool,
    apply_sanitization: bool = False,
    skip_html_reports: bool,
    report_format: str = "spa",
    collector_id: Optional[str],
    collector_group: Optional[List[str]],
    skip_collectors: Optional[str],
    include_collectors: Optional[str],
    spreadsheet: Optional[Path],
    debug: bool,
    verbose: bool,
    dry_run: bool,
    skip_preflight: bool,
    streaming_only: bool = False,
    stream_begin: Any = "24",
    stream_end: Any = "0",
    stream_destination: Optional[str] = None,
    append: bool = False,
    rack_id: Optional[str] = None,
    cli_expand_fallback_mode: Optional[str] = None,
    cli_expand_level: Optional[int] = None,
    explicit_cli_params: Optional[Set[str]] = None,
) -> ToolConfig:
    """
    Build tool config.

    After applying local validation, the function forwards ``config_file_data``,
    ``final_output_dir``, ``final_collection_level``, ``tool_config_baseboard``,
    and ``environment_baseboard`` to ``ToolConfig`` and preserves its return and
    exception contract.

    Args:
        config_file_data: Config file data governing tool config.
        final_output_dir: filesystem location used as the final output dir for
            this operation.
        final_collection_level: Text supplied as final collection level in the
            format accepted by this function.
        tool_config_baseboard: Optional Tool config baseboard governing tool
            config.
        environment_baseboard: Optional environment baseboard; ``None`` selects
            the function's default behavior.
        concurrency_mode: Conservative, fixed, or adaptive global admission.
        initial_io_oversubscription: Optional configured CPU multiplier.
        minimum_collector_operations: Adaptive weighted-capacity floor.
        maximum_collector_operations: Optional hard weighted-capacity ceiling.
        adaptive_concurrency: Bounded AIMD pressure and lifecycle settings.
        max_concurrent_duts: Upper bound enforced for max concurrent duts; the
            consuming boundary rejects or truncates values that exceed it.
        max_concurrent_collectors_per_dut: Upper bound enforced for max
            concurrent collectors per DUT; the consuming boundary rejects or
            truncates values that exceed it.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.
        retry_count: Numeric retry count used by the operation's bounded
            accounting.
        config_skip_zip: Whether config skip ZIP is enabled or required for this
            operation.
        config_skip_zip_split: Whether config skip ZIP split is enabled or
            required for this operation.
        config_zip_split_threshold: Config ZIP split threshold governing tool
            config.
        config_log_level: Config log level governing tool config.
        config_log_format: Config log format governing tool config.
        config_log_sanitization: Whether config log sanitization is enabled or
            required for this operation.
        config_generate_html_reports: Whether config generate HTML reports is
            enabled or required for this operation.
        execution_scheduler: Text supplied as execution scheduler in the format
            accepted by this function.
        parallel_dut_sequential_collectors: Whether parallel DUT sequential
            collectors is enabled or required for this operation.
        service_grouped_sequential_collectors: Whether service grouped
            sequential collectors is enabled or required for this operation.
        skip_zip: Whether skip ZIP is enabled or required for this operation.
        skip_zip_split: Whether skip ZIP split is enabled or required for this
            operation.
        zip_split_threshold: Numeric ZIP split threshold used while the
            operation performs bounded accounting.
        skip_sanitization: Whether skip sanitization is enabled or required for
            this operation.
        apply_sanitization: Whether apply sanitization is enabled or required
            for this operation.
        skip_html_reports: Whether skip HTML reports is enabled or required for
            this operation.
        report_format: Text supplied as report format in the format accepted by
            this function.
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        collector_group: Entries supplied as ``collector_group`` without
            transferring container ownership.
        skip_collectors: Whether skip collectors is enabled or required for this
            operation.
        include_collectors: Whether include collectors is enabled or required
            for this operation.
        spreadsheet: filesystem location used as the spreadsheet for this
            operation.
        debug: Whether debug is enabled or required for this operation.
        verbose: Whether verbose is enabled or required for this operation.
        dry_run: Whether dry run is enabled or required for this operation.
        skip_preflight: Whether skip preflight is enabled or required for this
            operation.
        streaming_only: Whether streaming only is enabled or required for this
            operation.
        stream_begin: Stream begin consumed while the function attempts to build
            tool config.
        stream_end: Stream end consumed while the function attempts to build
            tool config.
        stream_destination: Optional stream destination; ``None`` selects the
            function's default behavior.
        append: Whether append is enabled or required for this operation.
        rack_id: Stable rack identifier used to correlate configuration, logs,
            and results.
        cli_expand_fallback_mode: Optional CLI expand fallback mode; ``None``
            selects the function's default behavior.
        cli_expand_level: Optional CLI expand level; ``None`` selects the
            function's default behavior.
        explicit_cli_params: Optional explicit CLI params; ``None`` selects the
            function's default behavior.

    Returns:
        A ``ToolConfig`` representing tool config.
    """
    preflight_config = _get_preflight_config_as_dict(config_file_data)
    config_skip_preflight = preflight_config.get(
        "skip",
        _get_config_value(config_file_data, "skip_preflight", False),
    )
    if explicit_cli_params is not None:
        resolved_skip_preflight = (
            skip_preflight
            if "skip_preflight" in explicit_cli_params
            else config_skip_preflight
        )
    else:
        resolved_skip_preflight = (
            skip_preflight
            if should_use_cli_value(skip_preflight, config_skip_preflight, False)
            else config_skip_preflight
        )

    explicit_tool_config_keys = {
        key: True
        for key in SOURCE_SENSITIVE_TOOL_KEYS
        if (key in EXPAND_QUERY_LEVEL_KEYS and cli_expand_level is not None)
        or _config_key_was_explicit(config_file_data, key)
    }
    if _execution_config_key_was_explicit(config_file_data, "max_concurrent_duts"):
        explicit_tool_config_keys["max_concurrent_duts"] = True
    if _redfish_session_mode_was_explicit(config_file_data):
        # Canonicalize both accepted holder spellings in the runtime metadata.
        # Pool-only settings intentionally do not become a TLS-policy winner.
        explicit_tool_config_keys["redfish_session_config"] = True

    explicit_cli_config_keys = {
        selector_name: True
        for selector_name in (
            "collector_id",
            "collector_group",
            "include_collectors",
            "skip_collectors",
        )
        if explicit_cli_params is not None and selector_name in explicit_cli_params
    }

    def resolve_selector_list(parameter_name: str, cli_value: Optional[str]) -> list:
        """
        Resolve selector list.

        The implementation uses ``parameter_name`` and ``cli_value`` to resolve
        selector list.

        Args:
            parameter_name: Stable parameter name used for lookup and
                operator-facing diagnostics.
            cli_value: Text supplied as CLI value in the format accepted by this
                function.

        Returns:
            The selector list returned in operation-defined order.
        """
        cli_values = cli_value.split(",") if cli_value else []
        configured_values = list(
            _get_config_value(config_file_data, parameter_name, []) or []
        )
        if explicit_cli_params is not None:
            return (
                cli_values
                if parameter_name in explicit_cli_params
                else configured_values
            )
        return cli_values if cli_value is not None else configured_values

    resolved_report_format = _resolve_report_format(
        config_file_data,
        report_format,
        explicit_cli_params,
    )

    return ToolConfig(
        baseboard=tool_config_baseboard,
        environment_baseboard=environment_baseboard,
        concurrency_mode=concurrency_mode,
        initial_io_oversubscription=initial_io_oversubscription,
        minimum_collector_operations=minimum_collector_operations,
        maximum_collector_operations=maximum_collector_operations,
        adaptive_concurrency=dict(adaptive_concurrency or {}),
        max_concurrent_duts=max_concurrent_duts,
        max_concurrent_collectors_per_dut=max_concurrent_collectors_per_dut,
        timeout=timeout,
        retry_count=retry_count,
        output_directory=final_output_dir,
        caller_output_was_explicit=bool(
            explicit_cli_params is not None
            and (
                "output_dir" in explicit_cli_params
                or "stream_destination" in explicit_cli_params
            )
        ),
        skip_zip=streaming_only
        or dry_run
        or (
            skip_zip
            if (
                "skip_zip" in explicit_cli_params
                if explicit_cli_params is not None
                else should_use_cli_value(skip_zip, config_skip_zip, False)
            )
            else config_skip_zip
        ),
        skip_zip_split=streaming_only
        or (
            skip_zip_split
            if (
                "skip_zip_split" in explicit_cli_params
                if explicit_cli_params is not None
                else should_use_cli_value(skip_zip_split, config_skip_zip_split, False)
            )
            else config_skip_zip_split
        ),
        zip_split_threshold=(
            zip_split_threshold
            if (
                "zip_split_threshold" in explicit_cli_params
                if explicit_cli_params is not None
                else should_use_cli_value(
                    zip_split_threshold, config_zip_split_threshold, 200.0
                )
            )
            else config_zip_split_threshold
        ),
        log_level=config_log_level,
        log_format=config_log_format,
        debug=debug,
        verbose=_resolve_configured_verbose(
            config_file_data,
            verbose,
            explicit_cli_params,
        ),
        collection_level=final_collection_level,
        dry_run=dry_run,
        skip_preflight=resolved_skip_preflight,
        skip_sanitization=(
            skip_sanitization
            if (
                "skip_sanitization" in explicit_cli_params
                if explicit_cli_params is not None
                else should_use_cli_value(
                    skip_sanitization, not config_log_sanitization, False
                )
            )
            else not config_log_sanitization
        ),
        apply_sanitization=(
            apply_sanitization
            if (
                "apply_sanitization" in explicit_cli_params
                if explicit_cli_params is not None
                else should_use_cli_value(
                    apply_sanitization,
                    bool(
                        _get_config_value(
                            _get_config_value(config_file_data, "sanitization", None),
                            "apply_post_collection",
                            False,
                        )
                    ),
                    False,
                )
            )
            else bool(
                _get_config_value(
                    _get_config_value(config_file_data, "sanitization", None),
                    "apply_post_collection",
                    False,
                )
            )
        ),
        skip_html_reports=dry_run
        or (
            skip_html_reports
            if (
                "skip_html_reports" in explicit_cli_params
                if explicit_cli_params is not None
                else should_use_cli_value(
                    skip_html_reports,
                    not config_generate_html_reports,
                    False,
                )
            )
            else not config_generate_html_reports
        ),
        report_format=resolved_report_format,
        execution_scheduler=execution_scheduler,
        collector_id=collector_id,
        collector_group=collector_group,
        skip_collectors=resolve_selector_list("skip_collectors", skip_collectors),
        include_collectors=resolve_selector_list(
            "include_collectors", include_collectors
        ),
        spreadsheet=str(spreadsheet) if spreadsheet else None,
        parallel_dut_sequential_collectors=parallel_dut_sequential_collectors,
        service_grouped_sequential_collectors=service_grouped_sequential_collectors,
        SKIP_PORT_FW=getattr(config_file_data, "SKIP_PORT_FW", False),
        SKIP_BMC_SSH_LOGS=getattr(config_file_data, "SKIP_BMC_SSH_LOGS", True),
        SKIP_HOST_LOGS=getattr(config_file_data, "SKIP_HOST_LOGS", False),
        SKIP_IPMI_LOGS=getattr(config_file_data, "SKIP_IPMI_LOGS", False),
        SKIP_REDFISH_OOB_LOGS=getattr(config_file_data, "SKIP_REDFISH_OOB_LOGS", False),
        COLLECTOR_TO_SKIP=getattr(config_file_data, "COLLECTOR_TO_SKIP", None),
        SYSTEM_ID_TO_SKIP=getattr(config_file_data, "SYSTEM_ID_TO_SKIP", None),
        CHASSIS_ID_TO_SKIP=getattr(config_file_data, "CHASSIS_ID_TO_SKIP", None),
        MANAGER_ID_TO_SKIP=getattr(config_file_data, "MANAGER_ID_TO_SKIP", None),
        # CLI --expand-level acts as a coarse override for all four per-resource
        # knobs (Chassis / FirmwareInventory / Manager / System). If you need
        # per-resource granularity, set them individually in tool_config.yaml.
        # Per-DUT EXPAND_QUERY_*_LEVEL in dut_config.yaml still wins over both.
        EXPAND_QUERY_CHASSIS_LEVEL=(
            cli_expand_level
            if cli_expand_level is not None
            else getattr(config_file_data, "EXPAND_QUERY_CHASSIS_LEVEL", 1)
        ),
        EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL=(
            cli_expand_level
            if cli_expand_level is not None
            else getattr(config_file_data, "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL", 1)
        ),
        EXPAND_QUERY_MANAGER_LEVEL=(
            cli_expand_level
            if cli_expand_level is not None
            else getattr(config_file_data, "EXPAND_QUERY_MANAGER_LEVEL", 1)
        ),
        EXPAND_QUERY_SYSTEM_LEVEL=(
            cli_expand_level
            if cli_expand_level is not None
            else getattr(config_file_data, "EXPAND_QUERY_SYSTEM_LEVEL", 1)
        ),
        explicit_tool_config_keys={
            **explicit_tool_config_keys,
            "i2c_config": _config_key_was_explicit(config_file_data, "i2c_config"),
        },
        explicit_cli_config_keys=explicit_cli_config_keys,
        EXPAND_FALLBACK_MODE=(
            cli_expand_fallback_mode
            if cli_expand_fallback_mode is not None
            else getattr(config_file_data, "EXPAND_FALLBACK_MODE", "auto")
        ),
        NVOS_TECH_DUMP_TIMEOUT=getattr(
            config_file_data, "NVOS_TECH_DUMP_TIMEOUT", None
        ),
        REDFISH_DUMP_TIMEOUT=getattr(config_file_data, "REDFISH_DUMP_TIMEOUT", None),
        REDFISH_DEVICE_DUMP_SLEEP_DURATION=getattr(
            config_file_data, "REDFISH_DEVICE_DUMP_SLEEP_DURATION", 60
        ),
        COLLECTOR_EXTENSION_CONFIG=getattr(
            config_file_data, "COLLECTOR_EXTENSION_CONFIG", {}
        ),
        BMC_TEMP_DIR=getattr(config_file_data, "BMC_TEMP_DIR", "/tmp"),
        FW_INVENTORY_TABLE_PROPERTIES=getattr(
            config_file_data, "FW_INVENTORY_TABLE_PROPERTIES", []
        ),
        ADDITIONAL_OOB_URI_COLLECTION=getattr(
            config_file_data, "ADDITIONAL_OOB_URI_COLLECTION", []
        ),
        NVLINK_OOB_URI=getattr(config_file_data, "NVLINK_OOB_URI", []),
        CUSTOM_DUMP_SERVICES=getattr(config_file_data, "CUSTOM_DUMP_SERVICES", []),
        REDFISH_R31_PAYLOAD=getattr(config_file_data, "REDFISH_R31_PAYLOAD", None),
        POST_CODES_URI=getattr(config_file_data, "POST_CODES_URI", []),
        task_id_prefix=getattr(config_file_data, "TASK_ID_PREFIX", ""),
        tool_temp_dir=getattr(config_file_data, "TOOL_TEMP_DIR", "/tmp"),
        EXTRA_LOG_COLLECTION=getattr(config_file_data, "EXTRA_LOG_COLLECTION", None),
        sysinfo_snapshot_mode=getattr(
            config_file_data, "sysinfo_snapshot_mode", "fast"
        ),
        i2c_config=getattr(config_file_data, "i2c_config", None),
        preflight_config=preflight_config,
        redfish_session_config=_get_redfish_session_config_as_dict(config_file_data),
        ssh_connection_pool=_get_nested_config_as_dict(
            config_file_data, "ssh_connection_pool"
        ),
        ssh_host_key_policy=getattr(config_file_data, "ssh_host_key_policy", "insecure")
        or "insecure",
        ssh_known_hosts_file=getattr(config_file_data, "ssh_known_hosts_file", None),
        redfish_request_capture=RedfishRequestCaptureLimits.from_tool_config(
            config_file_data
        ).as_dict(),
        uri_overrides=_get_nested_config_as_dict(config_file_data, "uri_overrides"),
        max_pagination_pages=getattr(
            config_file_data,
            "max_pagination_pages",
            DEFAULT_MAX_PAGINATION_PAGES,
        ),
        max_duplicate_url_retries=getattr(
            config_file_data, "max_duplicate_url_retries", 3
        ),
        streaming_only=streaming_only,
        stream_begin=stream_begin,
        stream_end=stream_end,
        stream_destination=stream_destination,
        append=append,
        rack_id=rack_id,
    )


def _run_collector_and_level_validation(
    tool_config,
    dut_configs: list,
    collector_id: Optional[str],
    collector_group: Optional[List[str]],
    include_collectors: Optional[str],
    skip_collectors: Optional[str],
    final_collection_level: str,
    sanitized_console,
    reported_config_errors: Set[str],
    catalog_snapshot: Optional[CatalogSnapshot] = None,
) -> None:
    """
    Run collector ID/group and collection level validation; exit on failure.

    Creates a minimal ConfigurationManager, runs validation, and calls
    display_validation_errors + usage exit 2 if invalid. On exception, adds to
    reported_config_errors and prints a warning (does not exit).

    Args:
        tool_config: Tool config governing collector ID/group and collection
            level validation; exit on failure.
        dut_configs: DUT configs governing collector ID/group and collection
            level validation; exit on failure.
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        collector_group: Entries supplied as ``collector_group`` without
            transferring container ownership.
        include_collectors: Whether include collectors is enabled or required
            for this operation.
        skip_collectors: Whether skip collectors is enabled or required for this
            operation.
        final_collection_level: Text supplied as final collection level in the
            format accepted by this function.
        sanitized_console: Sanitized console object whose ``console`` and
            ``print_warning`` state is read while performing collector ID/group
            and collection level validation; exit on failure.
        reported_config_errors: Reported config errors governing collector
            ID/group and collection level validation; exit on failure.
        catalog_snapshot: Optional catalog snapshot; ``None`` selects the
            function's default behavior.

    Raises:
        SystemExit: If the function cannot run collector ID/group and collection
            level validation; exit on failure safely.
    """
    try:
        progress_console = sanitized_console.console
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=progress_console,
            transient=True,
        ) as progress:
            validation_task = progress.add_task(
                "Running fast collector validation...", total=None
            )
            progress.update(
                validation_task,
                description="Loading collector definitions...",
            )
            config_manager = ConfigurationManager.from_objects(
                tool_config=tool_config,
                dut_configs=dut_configs,
                sanitized_console=sanitized_console,
                quiet_mode=True,
                catalog_snapshot=catalog_snapshot,
            )
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(config_manager.initialize_minimal())
            finally:
                loop.close()

            progress.update(validation_task, description="Validating collector IDs...")
            validation_errors: List[str] = []
            _, errors = validate_collector_ids(collector_id, config_manager)
            validation_errors.extend(errors)
            if include_collectors:
                _, errors = validate_collector_ids(include_collectors, config_manager)
                validation_errors.extend(errors)
            if skip_collectors:
                _, errors = validate_collector_ids(skip_collectors, config_manager)
                validation_errors.extend(errors)
            _, errors = validate_collector_groups(collector_group, config_manager)
            validation_errors.extend(errors)
            _, errors = validate_collection_level(final_collection_level)
            validation_errors.extend(errors)

            if validation_errors:
                display_validation_errors(validation_errors)
                raise SystemExit(2)

            progress.update(
                validation_task,
                description="Validation complete",
                completed=True,
            )
    except Exception as e:
        error_key = f"collector_validation_{str(e)}"
        if error_key not in reported_config_errors:
            reported_config_errors.add(error_key)
            sanitized_console.print_warning(
                f"Warning: Could not validate collector IDs/groups: {e}. "
                "Continuing with basic validation only."
            )
