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

from .cli_handler import ToolConfig
from .config import (
    DUTConfig,
    auto_assign_config_file_to_use,
    load_config,
    load_dut_config,
)
from .core.config_manager import ConfigurationManager
from .utils.resources import find_all_config_files
from .utils.validation import (
    display_dut_config_error,
    display_validation_errors,
    validate_collection_level,
    validate_collector_groups,
    validate_collector_ids,
)


def _get_config_value(obj, key: str, default=None):
    """Safely retrieve a value from a config object or dict."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    if hasattr(obj, key):
        return getattr(obj, key)
    if hasattr(obj, "__dict__") and key in obj.__dict__:
        return obj.__dict__.get(key, default)
    return default


def _to_plain_dict(val):
    """Convert a Pydantic model (v2 or v1), dict, or object to a plain dict."""
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
    """Get a nested config attribute and convert Pydantic models to dicts."""
    val = _get_config_value(obj, key, None)
    return _to_plain_dict(val)


def should_use_cli_value(cli_value, config_value, default_value):
    """Return True if CLI value should override config file value.

    If CLI value differs from its default, the user explicitly set it and it wins.
    Otherwise fall back to the config file value.
    """
    if cli_value != default_value:
        return True
    if config_value != default_value:
        return False
    return True


def _load_tool_config(
    config_file: Optional[Path],
    sanitized_console,
) -> tuple:
    """Load a tool config file safely.

    Returns the loaded config data. On any failure, an empty dict is returned.
    """
    if not config_file or not config_file.exists():
        return {}

    try:
        config_data = load_config(config_file)
        sanitized_console.print_info(f"Loaded tool configuration from: {config_file}")
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
            sanitized_console.print_warning(
                f"Warning: Could not load tool config file: {e}"
            )
        sanitized_console.print_warning("Continuing with default configuration values")
        return {}


def _extract_tool_defaults(config_data, cli_output_dir: Path) -> Dict[str, Any]:
    """Extract tool-level defaults from a loaded config object.

    Returns a flat dict with all the config-derived values that collect() needs
    to build a ToolConfig.  When config_data is empty / a plain dict (i.e. no
    config was loaded), every key gets its hard-coded default.
    """
    d: Dict[str, Any] = {
        "config_generate_html_reports": True,
        "config_log_sanitization": True,
        "final_output_dir": str(cli_output_dir),
        "tool_config_baseboard": None,
        "max_concurrent_duts": 1,
        "max_concurrent_collectors_per_dut": 1,
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
    if hasattr(config_data, "output") and hasattr(config_data.output, "generate_html"):
        d["config_generate_html_reports"] = config_data.output.generate_html
    else:
        d["config_generate_html_reports"] = getattr(
            config_data, "GENERATE_HTML_REPORTS", True
        )

    # --- Log sanitization ---
    if hasattr(config_data, "sanitization") and config_data.sanitization:
        d["config_log_sanitization"] = config_data.sanitization.get("enabled", True)
    else:
        d["config_log_sanitization"] = getattr(config_data, "LogSanitization", True)

    # --- Baseboard from tool config ---
    if hasattr(config_data, "TargetBaseboard") and config_data.TargetBaseboard:
        d["tool_config_baseboard"] = config_data.TargetBaseboard
    elif (
        hasattr(config_data, "baseboard")
        and config_data.baseboard
        and config_data.baseboard != "compute"
    ):
        d["tool_config_baseboard"] = config_data.baseboard

    # --- Output directory (only override when CLI left the /tmp default) ---
    if (
        hasattr(config_data, "output")
        and hasattr(config_data.output, "directory")
        and config_data.output.directory
        and (str(cli_output_dir) == "/tmp" or cli_output_dir == Path("/tmp"))
    ):
        d["final_output_dir"] = str(config_data.output.directory)
        if d["final_output_dir"].startswith("~"):
            d["final_output_dir"] = os.path.expanduser(d["final_output_dir"])

    # --- Execution params ---
    d["max_concurrent_duts"] = getattr(config_data, "max_concurrent_duts", 1)
    d["max_concurrent_collectors_per_dut"] = getattr(
        config_data, "max_concurrent_collectors_per_dut", 1
    )
    d["timeout"] = getattr(config_data, "timeout", 300)
    d["retry_count"] = getattr(config_data, "retry_count", 3)

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
    """Read the ``DUT_Defaults`` block from a dut_config.yaml.

    Used in CLI mode so an auto-detected dut_config.yaml (one sitting next to
    the executable, picked up by ``_resolve_config_paths``) can still supply
    defaults like ``baseboard`` even though CLI mode builds the DUT from
    scratch. Returns an empty dict on any failure — callers treat missing
    defaults as a non-event.
    """
    if path is None or not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return {}
    defaults = data.get("DUT_Defaults") or {}
    return defaults if isinstance(defaults, dict) else {}


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
):
    """Build a single DUTConfig from CLI arguments (CLI mode).

    ``dut_defaults`` is the ``DUT_Defaults`` block loaded from an auto-detected
    ``dut_config.yaml`` (or empty if none was found). It supplies fallbacks
    that CLI flags can still override — currently just ``baseboard``, but the
    parameter is generic so more fields can be added without another signature
    change.

    Returns a List[DUTConfig] with one entry.
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
        name="dut-1",
        baseboard=effective_baseboard,
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
        RF_HMC_DEFAULT_PREFIX=(
            rf_hmc_prefix if rf_hmc_prefix is not None else "/redfish/v1"
        ),
        RF_DEFAULT_PREFIX=rf_bmc_prefix if rf_bmc_prefix is not None else "/redfish/v1",
    )
    return [dut_config_obj]


def _load_config_mode_duts(
    dut_config: Path,
    config_file: Optional[Path],
    baseboard: Optional[str],
    non_interactive: bool,
    sanitized_console,
) -> tuple:
    """Load DUT configs from a DUT config file (config mode).

    Handles auto_assign_config_file_to_use for baseboard resolution,
    applies the CLI --baseboard override (single-DUT only), and sets
    non_interactive on every loaded DUT.

    Returns (List[DUTConfig], resolved_dut_config_path).  Calls sys.exit(1) on unrecoverable errors.
    """
    # Auto-assign ConfigFileToUse for DUTs that have no baseboard set
    auto_dut_config, auto_config, auto_tool_config = find_all_config_files()
    config_files_for_auto_assignment = [auto_config]
    if config_file:
        config_files_for_auto_assignment.append(config_file)
    resolved_dut_config = auto_assign_config_file_to_use(
        dut_config, config_files_for_auto_assignment
    )

    if not resolved_dut_config.exists():
        sanitized_console.print_error(
            f"Error: DUT config file '{resolved_dut_config}' does not exist"
        )
        sys.exit(1)

    try:
        dut_configs = load_dut_config(resolved_dut_config)
        sanitized_console.print_success(
            f"Loaded DUT config from: {resolved_dut_config}"
        )
    except Exception as e:
        display_dut_config_error(str(e))
        sys.exit(1)

    # Apply --baseboard CLI override
    if baseboard:
        if len(dut_configs) == 1:
            sanitized_console.print_info(
                f"CLI baseboard parameter '-b {baseboard}' provided - overriding baseboard in DUT config file"
            )
            dut_configs[0].baseboard = baseboard
            sanitized_console.print_success(
                f"Set baseboard '{baseboard}' for DUT '{dut_configs[0].name}' (overriding config file)"
            )
        else:
            sanitized_console.print_warning(
                f"CLI baseboard parameter '-b {baseboard}' provided but ignored for multi-DUT configuration"
            )
            sanitized_console.print_warning(
                "Multi-DUT operations require baseboards to be configured in the DUT config file for each DUT"
            )

    for dc in dut_configs:
        dc.non_interactive = non_interactive

    return dut_configs, resolved_dut_config


def _resolve_config_paths(
    config_file: Optional[Path],
    dut_config: Optional[Path],
    sanitized_console,
    local_mode: bool = False,
) -> tuple:
    """Auto-detect config_file and dut_config paths when not explicitly provided.

    Returns (tool_config_path, dut_config_path).
    """
    auto_dut_config, auto_config, auto_tool_config = find_all_config_files()

    resolved_dut = dut_config
    resolved_tool = config_file

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


def _resolve_source_config_paths(
    config_file: Optional[Path],
    original_dut_config: Optional[Path],
    dut_config,  # Path or other; only used if original_dut_config is not a Path
) -> tuple:
    """Resolve source tool config and DUT config paths for archiving (best-effort).

    Returns (source_tool_config_path, source_dut_config_path); either may be None.
    Falls back to find_all_config_files() when a path is missing or does not exist.
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
    max_concurrent_duts: int,
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
) -> ToolConfig:
    """Build ToolConfig from config file data and resolved CLI/defaults (CLI precedence)."""
    return ToolConfig(
        max_concurrent_duts=max_concurrent_duts,
        max_concurrent_collectors_per_dut=max_concurrent_collectors_per_dut,
        timeout=timeout,
        retry_count=retry_count,
        output_directory=final_output_dir,
        skip_zip=(
            skip_zip
            if should_use_cli_value(skip_zip, config_skip_zip, False)
            else config_skip_zip
        ),
        skip_zip_split=(
            skip_zip_split
            if should_use_cli_value(skip_zip_split, config_skip_zip_split, False)
            else config_skip_zip_split
        ),
        zip_split_threshold=(
            zip_split_threshold
            if should_use_cli_value(
                zip_split_threshold, config_zip_split_threshold, 200.0
            )
            else config_zip_split_threshold
        ),
        log_level=config_log_level,
        log_format=config_log_format,
        debug=debug,
        verbose=verbose,
        collection_level=final_collection_level,
        dry_run=dry_run,
        skip_preflight=skip_preflight,
        skip_sanitization=(
            skip_sanitization
            if should_use_cli_value(
                skip_sanitization, not config_log_sanitization, False
            )
            else not config_log_sanitization
        ),
        skip_html_reports=(
            skip_html_reports
            if should_use_cli_value(
                skip_html_reports, not config_generate_html_reports, False
            )
            else not config_generate_html_reports
        ),
        report_format=report_format,
        execution_scheduler=execution_scheduler,
        collector_id=collector_id,
        collector_group=collector_group,
        skip_collectors=(skip_collectors.split(",") if skip_collectors else []),
        include_collectors=(
            include_collectors.split(",") if include_collectors else []
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
        EXPAND_QUERY_CHASSIS_LEVEL=getattr(
            config_file_data, "EXPAND_QUERY_CHASSIS_LEVEL", 1
        ),
        EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL=getattr(
            config_file_data, "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL", 1
        ),
        EXPAND_QUERY_MANAGER_LEVEL=getattr(
            config_file_data, "EXPAND_QUERY_MANAGER_LEVEL", 1
        ),
        EXPAND_QUERY_SYSTEM_LEVEL=getattr(
            config_file_data, "EXPAND_QUERY_SYSTEM_LEVEL", 1
        ),
        NVOS_TECH_DUMP_TIMEOUT=getattr(
            config_file_data, "NVOS_TECH_DUMP_TIMEOUT", None
        ),
        REDFISH_DUMP_TIMEOUT=getattr(config_file_data, "REDFISH_DUMP_TIMEOUT", None),
        REDFISH_DEVICE_DUMP_SLEEP_DURATION=getattr(
            config_file_data, "REDFISH_DEVICE_DUMP_SLEEP_DURATION", 60
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
        POST_CODES_URI=getattr(config_file_data, "POST_CODES_URI", []),
        task_id_prefix=getattr(config_file_data, "TASK_ID_PREFIX", ""),
        tool_temp_dir=getattr(config_file_data, "TOOL_TEMP_DIR", "/tmp"),
        EXTRA_LOG_COLLECTION=getattr(config_file_data, "EXTRA_LOG_COLLECTION", None),
        i2c_config=getattr(config_file_data, "i2c_config", None),
        preflight_config=_get_nested_config_as_dict(
            config_file_data, "preflight_config"
        ),
        redfish_session_config=_get_nested_config_as_dict(
            config_file_data, "redfish_session_config"
        ),
        uri_overrides=_get_nested_config_as_dict(config_file_data, "uri_overrides"),
        max_pagination_pages=getattr(config_file_data, "max_pagination_pages", 100),
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
) -> None:
    """Run collector ID/group and collection level validation; exit on failure.

    Creates a minimal ConfigurationManager, runs validation, and calls
    display_validation_errors + sys.exit(1) if invalid. On exception, adds to
    reported_config_errors and prints a warning (does not exit).
    """
    try:
        progress_console = sanitized_console.console
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=progress_console,
            transient=False,
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
                sys.exit(1)

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
