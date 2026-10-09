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
Open-NVDebug Tool - Main Entry Point.

This tool collects system logs and debug information from NVIDIA platforms.
"""

import asyncio
import math
import os
import sys
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, NoReturn, Optional, Sequence

import click
import typer
from rich.console import Console

from .cli_handler import (
    CLICollector,
    CLIDefaultCollectors,
    CLIListBaseboards,
    CLIListCollectors,
    CLIPreflight,
    _require_safe_rack_id,
)
from .compat.cli import LegacyCompatibleTyperGroup
from .compat.help import format_cli_help
from .config import (
    HMC_ACCESS_METHOD_HELP,
    HMC_ACCESS_METHODS,
    LEGACY_FIELD_MAPPINGS,
    MIN_ZIP_SPLIT_THRESHOLD_MB,
    DUTConfig,
    auto_assign_config_file_to_use,
    get_available_baseboards,
    load_config,
    load_dut_config,
    sync_legacy_fields,
    tool_config_deprecation_messages,
    validate_baseboard,
)
from .core import main_helpers
from .core.delivery_evidence import write_delivery_result_evidence
from .core.finalization_receipt import (
    FinalizationReceipt,
    finalization_failures_allow_delivery,
    is_interruption_exception,
    select_authoritative_exception,
    validate_structural_finalization_receipt,
)
from .core.main_helpers import (
    ToolConfigLoadError,
    _build_cli_dut_config,
    _config_key_was_explicit,
    _extract_tool_defaults,
    _get_config_value,
    _load_config_mode_duts,
    _load_dut_defaults_from_yaml,
    _load_tool_config,
    _resolve_config_paths,
    _resolve_configured_debug,
    _resolve_configured_skip_validation,
    _resolve_source_config_paths,
    _run_collector_and_level_validation,
    build_tool_config,
    should_use_cli_value,
)
from .core.run_result import (
    CollectionStatus,
    DeliveryResult,
    DeliveryStatus,
    RunMode,
    RunResult,
    RuntimeStatus,
)
from .utils.ansible_inventory import (
    cleanup_temp_config_files,
    generate_config_files_from_ansible,
)
from .utils.artifact_components import require_safe_artifact_component
from .utils.bounded_archive import ArchivePolicyError, read_regular_file_bounded
from .utils.catalog_snapshot import CatalogSnapshot, read_catalog_snapshot
from .utils.console_output import SanitizedConsole, create_sanitized_console
from .utils.frozen_path import get_base_path, is_frozen
from .utils.redfish_limits import MAX_SIGNED_64_BIT_INTEGER, RedfishResponseLimits
from .utils.redfish_tls import INSECURE_REDFISH_TRANSPORT_WARNING_MESSAGE
from .utils.resources import (
    CONFIG_DISCOVERY_TRUST_HELP,
    config_discovery_failure_details,
    trusted_discovered_file,
)
from .utils.sanitizer import neutralize_terminal_text
from .utils.secret_env import scrub_secret_environment
from .utils.spreadsheet_utils import (
    auto_detect_spreadsheet,
    validate_spreadsheet_requirement,
)
from .utils.ssh_proxy_projection import project_tool_ssh_proxy_defaults
from .utils.streaming import format_stream_window_component, normalize_stream_window
from .utils.validation import (
    display_dut_config_error,
    display_validation_errors,
    run_comprehensive_validation,
    validate_collection_level,
    validate_collector_groups,
    validate_collector_ids,
)
from .utils.zip_utils import (
    publish_archive_artifacts_shared_read,
    publish_loose_bundle_shared_read,
)
from .version import __build_hash__, __build_time__, __version__

_FROZEN_INTEGRITY_FATAL = (
    "FATAL: Packaged integrity check failed. Binary may be corrupted or incomplete."
)

_MINIMUM_CLI_OUTPUT_UMASK = 0o022


def _restore_process_umask(previous_umask: int) -> None:
    """
    Restore the caller's process umask when the CLI context closes.

    Click owns this callback through the root command context, so restoration
    runs on successful completion and on command exceptions without relying on
    process termination.

    Args:
        previous_umask: Original process mask captured before the CLI applied
            its minimum output-safety policy.

    Side Effects:
        Changes the process-wide umask back to ``previous_umask``.
    """

    os.umask(previous_umask)


def _install_minimum_cli_output_umask(ctx: typer.Context) -> None:
    """
    Prevent CLI-created files and directories from inheriting shared write.

    NVDebug creates output through several services and worker tasks. Applying
    one process-boundary minimum mask keeps their ordinary ``mkdir`` and file
    creation calls compatible with ``umask 002`` while preventing group or
    world writes. Ordinary live output retains read access; credential-bearing
    configuration and private capture staging use their explicit private modes.
    More restrictive caller masks remain restrictive, and Click restores the
    original mask when the command context closes.

    Args:
        ctx: Typer-owned command context that owns restoration of the original
            process umask.

    Side Effects:
        Temporarily adds group/world write permission bits to the process umask
        and registers restoration on the command context.
    """

    previous_umask = os.umask(0o077)
    os.umask(previous_umask | _MINIMUM_CLI_OUTPUT_UMASK)
    ctx.call_on_close(partial(_restore_process_umask, previous_umask))


_REMOTE_TARGET_CLI_PARAMS = frozenset(
    {
        "bmc_ip",
        "bmc_user",
        "bmc_pass",
        "bmc_ssh_user",
        "bmc_ssh_pass",
        "bmc_ssh_port",
        "bmc_ssh_key_path",
        "bmc_ssh_passwordless",
        "bmc_ssh_max_retries",
        "bmc_rf_user",
        "bmc_rf_pass",
        "bmc_rf_port",
        "host_ip",
        "host_user",
        "host_pass",
        "host_ssh_port",
        "host_ssh_key_path",
        "host_ssh_passwordless",
        "host_ssh_max_retries",
        "hmc_ip",
        "hmc_user",
        "hmc_pass",
        "hmc_ssh_user",
        "hmc_ssh_pass",
        "hmc_ssh_port",
        "hmc_ssh_key_path",
        "hmc_ssh_passwordless",
        "hmc_ssh_max_retries",
        "hmc_http_port",
        "hmc_https_port",
        "hmc_use_https",
        "use_port_forwarding",
        "tunnel_tcp_port",
        "setup_port_forwarding",
        "force_port_fw",
        "hmc_access_method",
        "rf_hmc_prefix",
        "rf_bmc_prefix",
    }
)


def _frozen_self_check() -> None:
    """
    Validate critical files embedded inside the frozen binary.

    Loose catalogs, configuration, licenses, and helper scripts are relocatable
    operator inputs or release support files. They must never become startup
    prerequisites for the one-file executable. Only PyInstaller-extracted
    components owned by the binary are checked here.

    Raises:
        SystemExit: With ``EX_CONFIG`` when an embedded critical component is
            absent from the frozen binary.
    """
    if not is_frozen():
        return

    global _FROZEN_SELF_CHECK_PASSED

    base = get_base_path()
    resolved_base = base.resolve()
    if _FROZEN_SELF_CHECK_PASSED == resolved_base:
        return

    critical = ["tool"]
    for component in critical:
        path = base / component
        if not path.exists():
            create_sanitized_console().print_failure(
                _FROZEN_INTEGRITY_FATAL,
                title="Packaged Integrity Check Failed",
                suggestions=(
                    "Replace this executable with a verified release package.",
                    "Do not continue with a binary whose embedded payload is incomplete.",
                ),
            )
            sys.exit(78)

    _FROZEN_SELF_CHECK_PASSED = resolved_base


_FROZEN_SELF_CHECK_PASSED: Path | None = None


def _cli_param_was_set(ctx: typer.Context, param_name: str) -> bool:
    """
    Return True when a CLI parameter was explicitly provided by the user.

    Typer injects the command context which owns the parameter-source metadata.
    Comparing the public enum member name avoids coupling this module to
    Click's process-global context stack or to Typer's internal Click import.

    Args:
        ctx: Typer-owned context for the active command invocation.
        param_name: Stable param name used for lookup and operator-facing
            diagnostics.

    Returns:
        ``True`` only when the parser classified the value as command-line
        input.
    """

    source = ctx.get_parameter_source(param_name)
    return source is not None and source.name == "COMMANDLINE"


SECRET_ENVIRONMENT_BY_PARAMETER = {
    "bmc_pass": "NVDEBUG_BMC_PASSWORD",
    "bmc_ssh_pass": "NVDEBUG_BMC_SSH_PASSWORD",
    "bmc_rf_pass": "NVDEBUG_BMC_REDFISH_PASSWORD",
    "host_pass": "NVDEBUG_HOST_PASSWORD",
    "hmc_pass": "NVDEBUG_HMC_PASSWORD",
    "hmc_ssh_pass": "NVDEBUG_HMC_SSH_PASSWORD",
    "ssh_proxy_pass": "NVDEBUG_SSH_PROXY_PASSWORD",
}

_ENV_FILE_ALLOWED_KEYS = frozenset(
    {
        *SECRET_ENVIRONMENT_BY_PARAMETER.values(),
        "NVDEBUG_E2E_DUT_CONFIG",
        "NVDEBUG_E2E_TOOL_CONFIG",
        "NVDEBUG_E2E_BUG_ID",
        "NVDEBUG_E2E_OUTPUT_DIR",
        "NVDEBUG_E2E_ARGS",
        "NVDEBUG_REFUSE_LITERAL_SECRETS",
    }
)
_MAX_ENV_FILE_BYTES = 1024 * 1024
_REFUSE_LITERAL_SECRETS_ENV = (
    "NVDEBUG_REFUSE_LITERAL_SECRETS"  # pragma: allowlist secret
)


def _literal_secrets_refused() -> bool:
    """
    Return whether compatibility password options must fail closed.

    The implementation uses current instance state to determine whether
    compatibility password options must fail closed.

    Returns:
        Whether compatibility password options must fail closed.
    """

    return os.environ.get(_REFUSE_LITERAL_SECRETS_ENV, "").strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _warn_for_literal_secret_options(ctx: typer.Context, *param_names: str) -> None:
    """
    Warn about secrets supplied through process-visible command arguments.

    Parameter provenance comes from the injected Typer context so environment,
    configuration, and hidden-prompt values do not trigger the warning. Literal
    password options remain accepted for compatibility, but the diagnostic
    names an argv-free replacement for every option without interpolating any
    supplied value. Operators can opt into fail-closed behavior with
    ``NVDEBUG_REFUSE_LITERAL_SECRETS=1``.

    Args:
        ctx: Typer-owned context for the active command invocation.
        param_names: Stable secret parameter names to inspect in caller-provided
            order.

    Raises:
        typer.BadParameter: If literal password options were supplied while the
            explicit fail-closed policy is enabled.

    Side Effects:
        Writes one value-free deprecation warning to standard error when one or
        more compatibility password options were supplied.
    """
    explicit_parameters = [
        param_name
        for param_name in param_names
        if param_name in SECRET_ENVIRONMENT_BY_PARAMETER
        and _cli_param_was_set(ctx, param_name)
    ]
    if not explicit_parameters:
        return

    option_guidance = "; ".join(
        f"--{param_name.replace('_', '-')} -> "
        f"{SECRET_ENVIRONMENT_BY_PARAMETER[param_name]}"
        for param_name in explicit_parameters
    )
    parameter_hint = ", ".join(
        f"--{param_name.replace('_', '-')}" for param_name in explicit_parameters
    )
    if _literal_secrets_refused():
        raise typer.BadParameter(
            "Literal secret options are refused by "
            f"{_REFUSE_LITERAL_SECRETS_ENV}; values are visible in process "
            "arguments. Use a protected configuration file, the hidden TTY "
            f"prompt, or the documented environment variables: {option_guidance}",
            param_hint=parameter_hint,
        )

    typer.echo(
        "Deprecation warning: literal password options remain supported for "
        "compatibility, but their values are visible in process arguments. "
        "Prefer a protected configuration file, the hidden TTY prompt, or the "
        f"documented environment variables: {option_guidance}",
        err=True,
    )


def _backfill_secret_option_from_environment(
    ctx: typer.Context,
    param_name: str,
    value: Optional[str],
) -> Optional[str]:
    """
    Resolve a secret loaded by the group callback after option parsing.

    Click may bind a subcommand's ``envvar`` option before the root callback
    loads the selected ``.env`` file. Explicit CLI values (including an empty
    value) always win; only an omitted, still-``None`` option is backfilled.

    Args:
        ctx: Typer-owned context for the active command invocation.
        param_name: Stable param name used for lookup and operator-facing
            diagnostics.
        value: Text supplied as value in the format accepted by this function.

    Returns:
        The canonical backfill secret option from environment text, or ``None``
        when the requested value is unavailable.
    """

    if value is not None or _cli_param_was_set(ctx, param_name):
        return value
    environment_name = SECRET_ENVIRONMENT_BY_PARAMETER[param_name]
    return os.environ.get(environment_name) or None


_SECRET_PROMPT_DETAILS = {
    "bmc_pass": ("BMC password", "--bmc-pass"),
    "bmc_ssh_pass": ("BMC SSH password", "--bmc-ssh-pass"),
    "bmc_rf_pass": ("BMC Redfish password", "--bmc-rf-pass"),
    "host_pass": ("host SSH password", "--host-pass"),
    "hmc_pass": ("HMC password", "--hmc-pass"),
    "hmc_ssh_pass": ("HMC SSH password", "--hmc-ssh-pass"),
    "ssh_proxy_pass": ("SSH proxy password", "--ssh-proxy-pass"),
}


def _secret_prompt_tty_available() -> bool:
    """
    Return whether stdin can safely support an interactive secret prompt.

    The implementation uses current instance state to determine whether stdin
    can safely support an interactive secret prompt.

    Returns:
        Whether stdin can safely support an interactive secret prompt.
    """

    try:
        return bool(click.get_text_stream("stdin").isatty())
    except (AttributeError, OSError):
        return False


def _prompt_for_secret(
    param_name: str,
    current_value: Optional[str],
    *,
    required: bool,
    non_interactive: bool,
) -> Optional[str]:
    """
    Return the prompt for secret.

    The implementation uses ``param_name``, ``current_value``, ``required``, and
    ``non_interactive`` to produce the prompt for secret. If the function cannot
    produce the prompt for secret, its exception reaches the caller instead of
    being converted into a successful result.

    Args:
        param_name: Stable param name used for lookup and operator-facing
            diagnostics.
        current_value: Text supplied as current value in the format accepted by
            this function.
        required: Whether required is enabled or required for this operation.
        non_interactive: Whether non interactive is enabled or required for this
            operation.

    Returns:
        The canonical prompt for secret text, or ``None`` when the requested
        value is unavailable.

    Raises:
        typer.BadParameter: If missing ``label``; non-interactive mode cannot
            request it. ``source_guidance``; missing ``label``; hidden
            credential entry lacks a TTY. ``source_guidance``; credential entry
            for ``label`` was cancelled. ``source_guidance``; or missing
            ``label``. ``source_guidance``.
    """

    # An explicitly supplied empty option remains authoritative. Validation
    # will reject it as unusable, but prompting must not silently replace a
    # command-line value and violate Click's source precedence contract.
    if current_value is not None or not required:
        return current_value

    label, option = _SECRET_PROMPT_DETAILS[param_name]
    environment_name = SECRET_ENVIRONMENT_BY_PARAMETER[param_name]
    source_guidance = (
        f"Set {environment_name}, use a protected configuration file, or run "
        "interactively from a TTY."
    )
    if non_interactive:
        raise typer.BadParameter(
            f"Missing {label}; non-interactive mode cannot request it. "
            f"{source_guidance}",
            param_hint=option,
        )
    if not _secret_prompt_tty_available():
        raise typer.BadParameter(
            f"Missing {label}; hidden credential entry requires a TTY. "
            f"{source_guidance}",
            param_hint=option,
        )

    try:
        prompted_value = click.prompt(
            label,
            hide_input=True,
            show_default=False,
            err=True,
        )
    except (click.Abort, EOFError):
        raise typer.BadParameter(
            f"Credential entry for {label} was cancelled. {source_guidance}",
            param_hint=option,
        ) from None

    if not prompted_value:
        raise typer.BadParameter(
            f"Missing {label}. {source_guidance}",
            param_hint=option,
        )
    return str(prompted_value)


def _prompt_for_unresolved_cli_secrets(
    cli_values: Mapping[str, Any],
    *,
    non_interactive: bool,
) -> Dict[str, Optional[str]]:
    """
    Prompt only for authentication paths selected by direct CLI fields.

    Callers merge protected configuration before invoking this helper.
    Controller and proxy prompts are tied only to the effective endpoints and
    usernames present in ``cli_values``.

    Args:
        cli_values: Mapping supplying fields for prompt only for authentication
            paths selected by direct CLI fields.
        non_interactive: Whether non interactive is enabled or required for this
            operation.

    Returns:
        The validated ``resolved``, or ``None`` when no value qualifies.
    """

    resolved = {
        param_name: cli_values.get(param_name)
        for param_name in SECRET_ENVIRONMENT_BY_PARAMETER
    }

    bmc_selected = bool(cli_values.get("bmc_ip"))
    bmc_alternative_auth = bool(
        resolved["bmc_ssh_pass"] is not None
        or resolved["bmc_rf_pass"] is not None
        or cli_values.get("bmc_ssh_key_path")
        or cli_values.get("bmc_ssh_passwordless")
    )
    # The generic BMC password is the runtime fallback for both BMC SSH and
    # Redfish. Resolve it first so one hidden entry does not become two prompts.
    resolved["bmc_pass"] = _prompt_for_secret(
        "bmc_pass",
        resolved["bmc_pass"],
        required=bool(
            bmc_selected and cli_values.get("bmc_user") and not bmc_alternative_auth
        ),
        non_interactive=non_interactive,
    )
    resolved["bmc_ssh_pass"] = _prompt_for_secret(
        "bmc_ssh_pass",
        resolved["bmc_ssh_pass"],
        required=bool(
            bmc_selected
            and cli_values.get("bmc_ssh_user")
            and resolved["bmc_pass"] is None
            and not cli_values.get("bmc_ssh_key_path")
            and not cli_values.get("bmc_ssh_passwordless")
        ),
        non_interactive=non_interactive,
    )
    resolved["bmc_rf_pass"] = _prompt_for_secret(
        "bmc_rf_pass",
        resolved["bmc_rf_pass"],
        required=bool(
            bmc_selected
            and cli_values.get("bmc_rf_user")
            and resolved["bmc_pass"] is None
        ),
        non_interactive=non_interactive,
    )

    resolved["host_pass"] = _prompt_for_secret(
        "host_pass",
        resolved["host_pass"],
        required=bool(
            cli_values.get("host_ip")
            and cli_values.get("host_user")
            and not cli_values.get("host_ssh_key_path")
            and not cli_values.get("host_ssh_passwordless")
        ),
        non_interactive=non_interactive,
    )
    hmc_alternative_auth = bool(
        resolved["hmc_ssh_pass"] is not None
        or cli_values.get("hmc_ssh_key_path")
        or cli_values.get("hmc_ssh_passwordless")
    )
    # HMC SSH uses the generic HMC password as its fallback too.
    resolved["hmc_pass"] = _prompt_for_secret(
        "hmc_pass",
        resolved["hmc_pass"],
        required=bool(
            cli_values.get("hmc_ip")
            and cli_values.get("hmc_user")
            and not hmc_alternative_auth
        ),
        non_interactive=non_interactive,
    )
    resolved["hmc_ssh_pass"] = _prompt_for_secret(
        "hmc_ssh_pass",
        resolved["hmc_ssh_pass"],
        required=bool(
            cli_values.get("hmc_ip")
            and cli_values.get("hmc_ssh_user")
            and resolved["hmc_pass"] is None
            and not cli_values.get("hmc_ssh_key_path")
            and not cli_values.get("hmc_ssh_passwordless")
        ),
        non_interactive=non_interactive,
    )
    resolved["ssh_proxy_pass"] = _prompt_for_secret(
        "ssh_proxy_pass",
        resolved["ssh_proxy_pass"],
        required=bool(
            cli_values.get("ssh_proxy_host")
            and cli_values.get("ssh_proxy_user")
            and not cli_values.get("ssh_proxy_key_path")
            and not cli_values.get("ssh_proxy_passwordless")
        ),
        non_interactive=non_interactive,
    )
    return resolved


def _explicit_cli_params(ctx: typer.Context) -> set[str]:
    """
    Return every parameter explicitly supplied on the current command line.

    The injected context is the sole authority for the active command's parser
    provenance; no process-global Click context lookup is performed.

    Args:
        ctx: Typer-owned context for the active command invocation.

    Returns:
        The unique explicit CLI params returned by the operation.
    """

    return {name for name in ctx.params if _cli_param_was_set(ctx, name)}


def _validate_zip_split_threshold(value: float) -> float:
    """
    Reject thresholds that cannot safely reach the archive boundary.

    The implementation uses ``value`` to reject thresholds that cannot safely
    reach the archive boundary. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        value: Numeric value used while the operation performs bounded
            accounting.

    Returns:
        The validated ``value``.

    Raises:
        typer.BadParameter: If the zip split threshold is not finite and at
            least ``MIN_ZIP_SPLIT_THRESHOLD_MB`` MB.
    """

    if not math.isfinite(value) or value < MIN_ZIP_SPLIT_THRESHOLD_MB:
        raise typer.BadParameter(
            "Zip split threshold must be finite and at least "
            f"{MIN_ZIP_SPLIT_THRESHOLD_MB:g} MB."
        )
    return value


_REDFISH_LIMIT_CLI_FIELDS = {
    "redfish_structured_response_max_bytes": "structured_response_max_bytes",
    "redfish_attachment_max_bytes": "attachment_max_bytes",
    "redfish_error_response_max_bytes": "error_response_max_bytes",
    "redfish_error_evidence_max_bytes": "error_evidence_max_bytes",
    "redfish_error_evidence_aggregate_max_bytes": (
        "error_evidence_aggregate_max_bytes"
    ),
    "redfish_error_evidence_max_responses": "error_evidence_max_responses",
    "redfish_preflight_response_max_bytes": "preflight_response_max_bytes",
    "redfish_cache_max_bytes": "cache_max_bytes",
    "redfish_cache_entry_max_bytes": "cache_entry_max_bytes",
}


def _apply_redfish_limit_cli_overrides(
    config_file_data: object,
    *,
    explicit_cli_params: set[str],
    values: Dict[str, Optional[int]],
) -> None:
    """
    Apply only explicit CLI ceilings over tool config/environment values.

    The implementation uses ``config_file_data``, ``explicit_cli_params``, and
    ``values`` to apply only explicit CLI ceilings over tool config/environment
    values. The operation mutates ``config_file_data`` in place; ownership of
    those objects remains with the caller. If the function cannot apply only
    explicit CLI ceilings over tool config/environment values, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        config_file_data: Config file data governing apply only explicit CLI
            ceilings over tool config/environment values.
        explicit_cli_params: Entries supplied as ``explicit_cli_params`` without
            transferring container ownership.
        values: Mapping supplying fields for apply only explicit CLI ceilings
            over tool config/environment values.

    Raises:
        typer.BadParameter: If the function cannot apply only explicit CLI
            ceilings over tool config/environment values safely.
    """

    overrides = {
        field_name: values[parameter_name]
        for parameter_name, field_name in _REDFISH_LIMIT_CLI_FIELDS.items()
        if parameter_name in explicit_cli_params
    }
    if not overrides:
        return

    if isinstance(config_file_data, dict):
        current = config_file_data.setdefault("redfish_session_config", {})
        current_values = dict(current) if isinstance(current, dict) else {}
        try:
            RedfishResponseLimits.from_session_config({**current_values, **overrides})
        except ValueError as error:
            raise typer.BadParameter(str(error)) from error
        current_values.update(overrides)
        config_file_data["redfish_session_config"] = current_values
        return

    current = getattr(config_file_data, "redfish_session_config", None)
    current_values = (
        current.model_dump(exclude_unset=True)
        if hasattr(current, "model_dump")
        else (dict(current) if isinstance(current, dict) else {})
    )
    if hasattr(current, "model_fields_set"):
        for field_name in RedfishResponseLimits.model_fields:
            if field_name in current.model_fields_set:
                current_values[field_name] = getattr(current, field_name)
    try:
        validated = type(current).model_validate({**current_values, **overrides})
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    config_file_data.redfish_session_config = validated


def _find_env_file() -> Optional[Path]:
    """
    Return the configured .env file, or the repo-local .env when available.

    PyInstaller one-file modules live below the transient extraction root.
    Walking upward from ``__file__`` there would turn a shared temporary
    directory into an implicit configuration source.

    Returns:
        The validated environment file filesystem path, or ``None`` when the
        requested value is unavailable.
    """
    env_path = os.environ.get("NVDEBUG_ENV_FILE")
    if env_path:
        candidate = Path(env_path).expanduser()
        return candidate if candidate.is_file() else None

    # PyInstaller one-file modules live below the transient extraction root.
    # Walking upward from ``__file__`` there would turn a shared temporary
    # directory into an implicit configuration source.
    if is_frozen():
        return None

    try:
        repo_root = Path(__file__).resolve().parents[2]
    except (OSError, RuntimeError, IndexError):
        return None

    candidate = repo_root / ".env"
    return candidate if candidate.is_file() else None


def _load_env_file(env_path: Path, *, override: bool = False) -> bool:
    """
    Load KEY=VALUE pairs from a .env file into ``os.environ``.

    The implementation uses ``env_path`` and ``override`` to load KEY=VALUE
    pairs from a .env file into ``os.environ``. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        env_path: filesystem location used as the environment path for this
            operation.
        override: Whether override is enabled or required for this operation.

    Returns:
        Whether the KEY=VALUE pairs from a .env file into ``os.environ``
        operation succeeds.
    """
    trusted_path = trusted_discovered_file(env_path, private=True)
    if trusted_path is None:
        click.echo(
            "Ignoring environment file: it must be a private, non-symlink "
            "regular file owned by the invoking user (or root) in a trusted "
            "directory.",
            err=True,
        )
        return False
    try:
        content = read_regular_file_bounded(
            trusted_path,
            maximum_bytes=_MAX_ENV_FILE_BYTES,
        ).decode("utf-8")
    except (ArchivePolicyError, OSError, UnicodeError):
        click.echo(
            "Ignoring environment file: file is unreadable or too large.",
            err=True,
        )
        return False

    allowed_keys = _ENV_FILE_ALLOWED_KEYS

    unsupported_key_seen = False
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        if not key:
            continue

        if key not in allowed_keys:
            unsupported_key_seen = True
            continue

        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]

        if override or key not in os.environ:
            os.environ[key] = value

    if unsupported_key_seen:
        click.secho(
            "Ignoring one or more unsupported environment-file keys; only declared "
            "NVDebug credential and integration variables are accepted.",
            fg="yellow",
            bold=True,
            err=True,
        )

    return True


_PREFLIGHT_PER_DUT_CLI_PARAMS = frozenset(
    {
        "bmc_ip",
        "bmc_user",
        "bmc_pass",
        "bmc_ssh_user",
        "bmc_ssh_pass",
        "bmc_ssh_port",
        "bmc_ssh_key_path",
        "bmc_ssh_passwordless",
        "bmc_ssh_max_retries",
        "bmc_rf_user",
        "bmc_rf_pass",
        "bmc_rf_port",
        "host_ip",
        "host_user",
        "host_pass",
        "host_ssh_port",
        "host_ssh_key_path",
        "host_ssh_passwordless",
        "host_ssh_max_retries",
        "hmc_ip",
        "hmc_user",
        "hmc_pass",
        "hmc_ssh_user",
        "hmc_ssh_pass",
        "hmc_ssh_port",
        "hmc_ssh_key_path",
        "hmc_ssh_passwordless",
        "hmc_ssh_max_retries",
        "hmc_http_port",
        "hmc_https_port",
        "hmc_use_https",
    }
)


class _AmbiguousPreflightDUTScope(ValueError):
    """
    An environment-selected multi-DUT file received a per-DUT CLI override.

    Callers receive this exception when the ambiguous preflight DUT scope
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


_PREFLIGHT_SHARED_SECRET_PARAMS = frozenset({"host_pass", "ssh_proxy_pass"})
_PREFLIGHT_DIRECT_TARGET_PARAMS = frozenset({"bmc_ip", "host_ip", "hmc_ip"})
_PREFLIGHT_GLOBAL_PROXY_PARAMS = frozenset(
    {
        "ssh_proxy_host",
        "ssh_proxy_port",
        "ssh_proxy_user",
        "ssh_proxy_pass",
        "ssh_proxy_key_path",
        "ssh_proxy_passwordless",
        "ssh_proxy_max_retries",
    }
)


class _HelpUsageError(click.ClickException):
    """
    Report a usage failure after complete command help has already been shown.

    Unlike ``click.UsageError``, this exception deliberately carries no command
    context. Typer therefore renders one standard Rich error panel without
    repeating the short usage line or suggesting help that is already visible.
    """

    exit_code = 2


def _usage_help_uses_stderr(
    ctx: click.Context,
    raw_args: Sequence[str] = (),
) -> bool:
    """
    Preserve machine-readable stdout when rendering contextual usage help.

    Callback-time failures can use parsed parameters, while parser-time
    failures may occur before Click populates ``ctx.params``. The raw-token
    fallback recognizes only the public machine-output selectors and never
    interprets paths, credentials, or arbitrary option values.

    Args:
        ctx: Click-owned context whose parsed parameters may select JSON output.
        raw_args: Raw command tokens available at a parser-time failure.

    Returns:
        Whether complete usage help must be written to standard error.
    """

    if ctx.params.get("json_output") is True:
        return True
    output_format = ctx.params.get("output_format")
    if type(output_format) is str and output_format.casefold() == "json":
        return True
    for index, argument in enumerate(raw_args):
        if argument == "--json":
            return True
        if argument.casefold() == "--format=json":
            return True
        if (
            argument == "--format"
            and index + 1 < len(raw_args)
            and raw_args[index + 1].casefold() == "json"
        ):
            return True
    return False


def _raise_help_usage_error(
    ctx: click.Context,
    message: str,
    *,
    raw_args: Sequence[str] = (),
) -> NoReturn:
    """
    Render complete command help and terminate with an actionable usage error.

    The help document is emitted first because Typer's standard usage-error
    formatter only includes the abbreviated usage line. The context-free
    exception then lets Typer own the error panel without duplicating that help
    or adding a redundant suggestion to request it.

    Args:
        ctx: Click-owned command context used to render the selected command's
            complete help document.
        message: Click-formatted explanation of the invalid or missing command
            input; terminal control characters are neutralized before output.
        raw_args: Raw command tokens used only to preserve machine-readable
            stdout when parsing failed before parameters were materialized.

    Raises:
        _HelpUsageError: Always, after the help document has been written.

    Side Effects:
        Writes complete command help to standard error for machine-readable
        invocations and to standard output otherwise. Typer then writes the
        standard Rich error panel to standard error.
    """

    if _usage_help_uses_stderr(ctx, raw_args):
        # Machine-output failures keep complete plain help on stderr, including
        # when the caller's stdout is an interactive terminal.
        formatter = ctx.make_formatter()
        click.Command.format_help(ctx.command, ctx, formatter)
        click.echo(formatter.getvalue(), err=True, nl=False)
    else:
        click.echo(ctx.get_help())
    raise _HelpUsageError(neutralize_terminal_text(message))


class _ContextualHelpCommand(typer.core.TyperCommand):
    """
    Render complete command help before every Click usage diagnostic.

    Typer normally renders only a short usage line and a suggestion to request
    help. NVDebug commands instead show the selected verb's complete help once,
    followed by Typer's standard error panel carrying the original diagnostic.
    """

    def format_help(
        self,
        ctx: click.Context,
        formatter: click.HelpFormatter,
    ) -> None:
        """
        Render complete Rich terminal help or plain redirected help.

        Both presentations use the same canonical help records. The terminal
        layout wraps long options and environment names instead of shortening
        them, while captured output retains the searchable plain format.

        Args:
            ctx: Click-owned command context for the selected command.
            formatter: Click formatter receiving the complete help document.

        Side Effects:
            Appends the command's help text to ``formatter``.
        """

        format_cli_help(self, ctx, formatter)

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        """
        Parse command arguments with complete help on syntax failures.

        Click owns option and positional parsing, including its precise
        diagnostics. This boundary changes only presentation: resilient parsing
        remains untouched, while interactive invocations receive full context
        before the same diagnostic is re-emitted in one error panel.

        Args:
            ctx: Click-owned command context used to render command help.
            args: Raw command arguments remaining after subcommand selection.

        Returns:
            The unconsumed arguments returned by Typer's standard parser.

        Raises:
            _HelpUsageError: If Click rejects the command syntax or a parsed
                parameter value.
            click.UsageError: If resilient parsing rejects the supplied input.

        Side Effects:
            Records value-free Redfish TLS option occurrence metadata for
            ``collect`` and writes complete command help before an interactive
            usage failure.
        """

        if self.name == "collect" and not ctx.resilient_parsing:
            ctx.meta["nvdebug_redfish_tls_spellings"] = frozenset(
                argument.split("=", 1)[0]
                for argument in args
                if argument.split("=", 1)[0]
                in {"--ssl-verify", "--no-ssl-verify", "--insecure"}
            )

        raw_args = tuple(args)
        try:
            return super().parse_args(ctx, args)
        except click.UsageError as error:
            if ctx.resilient_parsing:
                raise
            _raise_help_usage_error(
                ctx,
                error.format_message(),
                raw_args=raw_args,
            )

    def invoke(self, ctx: click.Context) -> Any:
        """
        Invoke the command with complete help for callback usage failures.

        Some parameter contracts depend on multiple values and therefore run in
        the command callback rather than Click's parser. Those ``UsageError``
        subclasses follow the same presentation policy as parser-time failures;
        domain failures and explicit command exit statuses remain unchanged.

        Args:
            ctx: Click-owned context containing the parsed command parameters.

        Returns:
            The delegated command callback's completion value.

        Raises:
            _HelpUsageError: If the callback rejects the invocation with a
                Click usage error.

        Side Effects:
            Runs the selected command callback and may render its complete help
            before an invocation error.
        """

        try:
            return super().invoke(ctx)
        except click.UsageError as error:
            _raise_help_usage_error(ctx, error.format_message())


def _preflight_has_ambiguous_dut_scope(
    resolved_dut_configs: Optional[List[DUTConfig]],
    explicit_cli_params: set[str],
) -> bool:
    """
    Detect explicit per-DUT overrides against a selected multi-DUT file.

    The implementation uses ``resolved_dut_configs`` and ``explicit_cli_params``
    to detect explicit per-DUT overrides against a selected multi-DUT file.

    Args:
        resolved_dut_configs: Resolved DUT configs governing detect explicit
            per-DUT overrides against a selected multi-DUT file.
        explicit_cli_params: Entries supplied as ``explicit_cli_params`` without
            transferring container ownership.

    Returns:
        Whether the detect explicit per-DUT overrides against a selected
        multi-DUT file operation succeeds.
    """

    return (
        resolved_dut_configs is not None
        and len(resolved_dut_configs) > 1
        and bool(explicit_cli_params & _PREFLIGHT_PER_DUT_CLI_PARAMS)
    )


# Create Typer app
app = typer.Typer(
    name="nvdebug",
    cls=LegacyCompatibleTyperGroup,
    help="NVDebug - NVIDIA Log Collection Tool",
    add_completion=False,
    context_settings={
        "help_option_names": ["-h", "--help"],
        "max_content_width": 120,
    },
)


# Rich console for output (sanitized wrapper used for strings)

console = Console()
sanitized_console = create_sanitized_console()


def _present_cli_failure(
    message: str,
    *,
    title: str = "Command Configuration Error",
    suggestions: Sequence[str] = (),
) -> None:
    """
    Render one fatal human-mode CLI diagnostic through the shared Rich UI.

    Human commands keep their terminal reason on the same retained transcript
    as ordinary progress. Callers that promise machine-readable stdout must use
    their JSON-aware stderr presenter instead of this helper.

    Args:
        message: Operator-facing reason the command cannot continue.
        title: Stable failure category displayed in the Rich panel heading.
        suggestions: Ordered recovery actions shown beneath the reason.

    Side Effects:
        Writes one sanitized Rich failure panel to human-output stdout.
    """

    recovery = tuple(suggestions) or (
        "Review the selected options or configuration and retry.",
        "Run the command with --help to inspect valid inputs.",
    )
    sanitized_console.print_failure(
        message,
        title=title,
        suggestions=recovery,
    )


def _normalize_cli_collector_groups(
    collector_groups: Optional[Sequence[str]],
    reporter: SanitizedConsole,
    *,
    warning_to_stderr: bool = False,
) -> Optional[List[str]]:
    """
    Normalize repeatable collector-group selectors and retained v2.1 aliases.

    Commas and whitespace delimit tokens within each option occurrence. The
    historical ``HealthCheck`` spelling is projected to the catalog's
    ``health_check`` identifier, and one value-free warning discloses the
    compatibility behavior without reflecting arbitrary caller input.

    Args:
        collector_groups: Optional option occurrences in command-line order.
        reporter: Sanitized console used for the compatibility warning.
        warning_to_stderr: Whether machine-readable stdout requires the warning
            to be emitted on stderr instead.

    Returns:
        Canonical group tokens in command-line order, or ``None`` when no group
        selector was supplied.

    Side Effects:
        Writes one sanitized warning when a retained HealthCheck alias is used.
    """

    if not collector_groups:
        return None

    normalized: List[str] = []
    used_healthcheck_alias = False
    for occurrence in collector_groups:
        for token in occurrence.replace(",", " ").split():
            group = token.strip().lower()
            if not group:
                continue
            if group == "healthcheck":
                group = "health_check"
                used_healthcheck_alias = True
            normalized.append(group)

    if used_healthcheck_alias:
        warning = (
            "Warning: deprecated collector-group spelling HealthCheck was "
            "normalized to health_check; update automation to use health_check."
        )
        if warning_to_stderr:
            sanitize = getattr(getattr(reporter, "sanitizer", None), "sanitize", None)
            click.echo(sanitize(warning) if callable(sanitize) else warning, err=True)
        else:
            reporter.print_warning(warning)
    return normalized


def _project_legacy_tool_ipmi_cipher(
    config_data: Any,
    dut_configs: Sequence[DUTConfig],
) -> None:
    """
    Apply the legacy tool-root IPMI cipher as a low-priority DUT default.

    A DUT-authored ``ipmi_cipher`` remains authoritative. The compatibility
    value is never rendered, and the tool-config loader emits a stable
    value-free migration warning when the root field was present in YAML.

    Args:
        config_data: Loaded tool configuration with source-presence metadata.
        dut_configs: Resolved DUT models which may receive the legacy default.

    Side Effects:
        Updates DUT models which did not explicitly configure ``ipmi_cipher``.
    """

    yaml_paths = getattr(config_data, "_yaml_paths", None)
    root_field_is_explicit = (
        "ipmi_cipher" in yaml_paths
        if yaml_paths is not None
        else _config_key_was_explicit(config_data, "ipmi_cipher")
    )
    if not root_field_is_explicit:
        return

    legacy_cipher = _get_config_value(config_data, "ipmi_cipher", None)
    if legacy_cipher is None:
        return
    for dut_config in dut_configs:
        if "ipmi_cipher" not in getattr(dut_config, "model_fields_set", set()):
            dut_config.ipmi_cipher = legacy_cipher


def _operator_selected_tool_config(config_file: Optional[Path]) -> bool:
    """
    Report whether the operator chose the tool configuration for this run.

    Only an explicit ``--config-file`` or a non-empty ``NVDEBUG_CONFIG_FILE``
    counts. Auto-discovery and generated fallbacks do not, so they may still be
    replaced by a document a command synthesizes for itself. Every command that
    can substitute a generated tool configuration must consult this before
    doing so, or an operator-selected document silently loses its transport
    trust settings.

    Args:
        config_file: Tool configuration path as supplied to the command, before
            any auto-detection or generation replaces it.

    Returns:
        ``True`` when the operator selected the tool configuration explicitly.
    """

    return config_file is not None or bool(
        os.environ.get("NVDEBUG_CONFIG_FILE", "").strip()
    )


def _reject_incoherent_ssh_trust_selection(
    explicit_cli_params: set[str],
    cli_ssh_host_key_policy: Optional[str],
    cli_ssh_known_hosts_file: Optional[str],
    *,
    report_error: Callable[[str], None],
    report_notice: Callable[[str], None],
) -> Optional[str]:
    """
    Reconcile a CLI known-hosts trust source with the selected host-key policy.

    ``asyncssh_host_key_options`` short-circuits on the ``insecure`` policy and
    never consults a named known-hosts file, so accepting the pair silently
    discards a trust source the operator asked for. Two distinct inputs get two
    distinct answers, and each input state gets exactly one of them: naming a
    trust source while explicitly selecting ``insecure`` on the same command
    line is contradictory and is rejected before any DUT work begins, whereas
    naming a trust source with no explicit CLI policy is treated as the
    operator's only trust signal and promotes the policy to ``strict``. The
    documented ``insecure`` default is untouched when no known-hosts file is
    supplied.

    Args:
        explicit_cli_params: Names of CLI parameters the operator supplied
            explicitly on this invocation.
        cli_ssh_host_key_policy: Normalized ``--ssh-host-key-policy`` value, or
            ``None`` when the flag was not supplied.
        cli_ssh_known_hosts_file: Resolved ``--ssh-known-hosts-file`` value, or
            ``None`` when the flag was not supplied.
        report_error: Callable used to surface the rejection to the operator on
            the command's own diagnostic channel.
        report_notice: Callable used to disclose a promoted policy, so the
            operator is never surprised by host-key verification they did not
            spell out.

    Returns:
        The host-key policy the command must apply, which is
        ``cli_ssh_host_key_policy`` unchanged unless the known-hosts file
        promoted an unselected policy to ``strict``.

    Raises:
        typer.Exit: With code ``2`` when a known-hosts file is combined with an
            explicitly selected ``insecure`` policy.

    Side Effects:
        Calls ``report_error`` before raising, and calls ``report_notice`` once
        when the policy is promoted.
    """

    if cli_ssh_known_hosts_file is None:
        return cli_ssh_host_key_policy

    if (
        "ssh_host_key_policy" in explicit_cli_params
        and cli_ssh_host_key_policy == "insecure"
    ):
        report_error(
            "--ssh-known-hosts-file names a host-key trust source, but "
            "--ssh-host-key-policy insecure disables host-key verification, so "
            "that trust source would never be consulted. Select "
            "--ssh-host-key-policy strict, or drop --ssh-known-hosts-file."
        )
        raise typer.Exit(code=2)

    if cli_ssh_host_key_policy == "strict":
        return cli_ssh_host_key_policy

    # The named trust source is the only host-key signal on this command line.
    # Honor it instead of accepting and then discarding it; promotion is
    # fail-secure and never weakens a policy the operator did select.
    report_notice(
        "--ssh-known-hosts-file selects host-key verification; applying "
        "ssh_host_key_policy=strict for this run."
    )
    return "strict"


def _print_preflight_error(message: str, *, json_output: bool) -> None:
    """
    Emit preflight diagnostics without contaminating JSON stdout.

    The implementation uses ``message`` and ``json_output`` to emit preflight
    diagnostics without contaminating JSON stdout.

    Args:
        message: Operator-facing text carried by the reported event or failure.
        json_output: Whether JSON output is enabled or required for this
            operation.
    """

    if not json_output:
        _present_cli_failure(
            message,
            title="Preflight Configuration Error",
            suggestions=(
                "Correct the selected target or configuration source and retry.",
                "Run 'nvdebug preflight --help' to review valid target combinations.",
            ),
        )
        return

    try:
        rendered = sanitized_console.sanitizer.sanitize(str(message))
        rendered = neutralize_terminal_text(str(rendered))
    except Exception:
        rendered = "Preflight command failed."
    click.echo(rendered, err=True)


def version_callback(value: bool) -> None:
    """
    Print version information and exit the application.

    The implementation uses ``value`` to print version information and exit the
    application. If the function cannot print version information and exit the
    application, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        value: Whether value is enabled or required for this operation.

    Raises:
        typer.Exit: If the function cannot print version information and exit
            the application safely.
    """
    if value:
        sanitized_console.print_info(
            f"nvdebug {__version__}  (build {__build_hash__} @ {__build_time__})"
        )
        raise typer.Exit()


def get_collection_level_from_v_count(count: int) -> str:
    """
    Convert verbosity count (-V flags) to collection level.

    The implementation uses ``count`` to convert verbosity count (-V flags) to
    collection level. The source value keeps its ownership while the normalized
    representation is returned separately.

    Args:
        count: Numeric count used by the operation's bounded accounting.

    Returns:
        The canonical collection level from v count text.
    """
    if count == 1:
        return "L2"
    elif count >= 2:
        return "L3"  # Any number of V's >= 2 maps to L3
    else:
        return "L1"


def get_higher_collection_level(level1: str, level2: str) -> str:
    """
    Get the higher collection level between two levels.

    The implementation uses ``level1`` and ``level2`` to get the higher
    collection level between two levels.

    Args:
        level1: Text supplied as level1 in the format accepted by this function.
        level2: Text supplied as level2 in the format accepted by this function.

    Returns:
        The canonical higher collection level text.
    """
    level_mapping = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
    level1_num = level_mapping.get(level1.upper(), 1)
    level2_num = level_mapping.get(level2.upper(), 1)
    max_level = max(level1_num, level2_num)
    return (
        "L3"
        if max_level == 3
        else "L2" if max_level == 2 else "L1" if max_level == 1 else "L0"
    )


def _normalize_streaming_contract(
    *,
    streaming_only: bool,
    stream_destination: Optional[Path],
    append: bool,
    stream_begin: Any,
    stream_end: Any,
    skip_zip: bool,
    explicit_cli_params: set[str],
) -> tuple[bool, Optional[Path], bool, Any, Any, bool]:
    """
    Validate streaming combinations and return their effective values.

    The implementation uses ``streaming_only``, ``stream_destination``,
    ``append``, ``stream_begin``, and ``stream_end`` to validate streaming
    combinations and return their effective values. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path. The operation mutates
    ``explicit_cli_params`` in place; ownership of those objects remains with
    the caller.

    Args:
        streaming_only: Whether streaming only is enabled or required for this
            operation.
        stream_destination: filesystem location used as the destination for this
            operation.
        append: Whether append is enabled or required for this operation.
        stream_begin: Stream begin consumed while the function attempts to
            validate streaming combinations and return their effective values.
        stream_end: Stream end consumed while the function attempts to validate
            streaming combinations and return their effective values.
        skip_zip: Whether skip ZIP is enabled or required for this operation.
        explicit_cli_params: Entries supplied as ``explicit_cli_params`` without
            transferring container ownership.

    Returns:
        A tuple containing ``streaming only``, ``stream destination``,
        ``append``, ``stream begin``, ``stream end``, and ``skip ZIP`` in that
        order.

    Raises:
        typer.Exit: If the function cannot validate streaming combinations and
            return their effective values safely.
    """

    if streaming_only and not stream_destination:
        _present_cli_failure(
            "Error: --streaming-only requires --stream-destination.\n"
            "  Provide a destination path for streamed logs "
            "(e.g. --stream-destination /mnt/shared/logs).",
            title="Streaming Options Conflict",
        )
        raise typer.Exit(code=2)

    if stream_destination and not streaming_only:
        sanitized_console.print_warning(
            "Warning: --stream-destination is set but --streaming-only is not. "
            "Enabling --streaming-only automatically."
        )
        streaming_only = True

    if stream_destination and not stream_destination.is_absolute():
        _present_cli_failure(
            "Error: --stream-destination must be an absolute path.\n"
            f"  Got: {stream_destination}",
            title="Invalid Streaming Destination",
        )
        raise typer.Exit(code=2)

    if streaming_only and stream_destination and not append:
        sanitized_console.print_warning(
            "Warning: --stream-destination is set for streaming mode. "
            "Enabling --append automatically to preserve a stable directory tree."
        )
        append = True

    if append and stream_destination is None and not streaming_only:
        _present_cli_failure(
            "Error: '--append' requires '--stream-destination' or '--streaming-only'.",
            title="Streaming Options Conflict",
        )
        raise typer.Exit(code=2)

    if streaming_only or stream_destination or append:
        try:
            stream_begin_dt, stream_end_dt = normalize_stream_window(
                stream_begin, stream_end, datetime.now(timezone.utc)
            )
        except ValueError as exc:
            _present_cli_failure(
                f"Error: {exc}",
                title="Invalid Streaming Window",
            )
            raise typer.Exit(code=2) from exc

        stream_begin = format_stream_window_component(stream_begin_dt)
        stream_end = format_stream_window_component(stream_end_dt)
        if "skip_zip" in explicit_cli_params and not skip_zip:
            _present_cli_failure(
                "Error: streaming append mode cannot be combined with "
                "--no-skip-zip because archiving would delete the destination.",
                title="Streaming Options Conflict",
            )
            raise typer.Exit(code=2)
        skip_zip = True
        explicit_cli_params.add("skip_zip")

    return (
        streaming_only,
        stream_destination,
        append,
        stream_begin,
        stream_end,
        skip_zip,
    )


def _collection_shutdown_requested(cli_collector: CLICollector) -> bool:
    """
    Return the orchestrator's authoritative command shutdown state.

    The implementation uses ``cli_collector`` to produce the orchestrator's
    authoritative command shutdown state.

    Args:
        cli_collector: CLI collector consumed while the function attempts to
            produce the orchestrator's authoritative command shutdown state.

    Returns:
        Whether the orchestrator's authoritative command shutdown state
        operation succeeds.
    """

    orchestrator = getattr(cli_collector, "orchestrator", None)
    checker = getattr(orchestrator, "is_shutdown_requested", None)
    return checker() is True if callable(checker) else False


def _raise_collection_cancellation_exit(
    cli_collector: CLICollector,
    sanitized_console: SanitizedConsole,
) -> NoReturn:
    """
    Project a raw collection cancellation onto the public CLI exit contract.

    The implementation uses ``cli_collector`` and ``sanitized_console`` to
    project a raw collection cancellation onto the public CLI exit contract. If
    the function cannot project a raw collection cancellation onto the public
    CLI exit contract, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        cli_collector: CLI collector consumed while the function attempts to
            project a raw collection cancellation onto the public CLI exit
            contract.
        sanitized_console: Sanitized console used for interruption warnings and
            terminal failure panels.

    Raises:
        typer.Exit: If the function cannot project a raw collection cancellation
            onto the public CLI exit contract safely.
    """

    if _collection_shutdown_requested(cli_collector):
        sanitized_console.print_warning("\nCollection interrupted by user")
        raise typer.Exit(code=130)
    sanitized_console.print_failure(
        "Collection task was cancelled without a shutdown request.",
        title="Collection Cancelled Unexpectedly",
        suggestions=(
            "Retry the collection and preserve the verbose transcript if cancellation recurs.",
            "Check the caller or supervisor for an unexpected task cancellation.",
        ),
    )
    raise typer.Exit(code=1)


def _retained_run_result(
    cli_collector: CLICollector,
    returned_result: object = None,
) -> Optional[RunResult]:
    """
    Return only the canonical result retained by the lifecycle owner.

    The implementation uses ``cli_collector`` and ``returned_result`` to produce
    only the canonical result retained by the lifecycle owner. If the function
    cannot produce only the canonical result retained by the lifecycle owner,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        cli_collector: CLI collector consumed while the function attempts to
            produce only the canonical result retained by the lifecycle owner.
        returned_result: Optional returned result; ``None`` selects the
            function's default behavior.

    Returns:
        A ``RunResult`` representing retained run result, or ``None`` when the
        requested value is unavailable.

    Raises:
        TypeError: If collection returned a RunResult subclass; or lifecycle
            owner retained a noncanonical RunResult.
        RuntimeError: If returned RunResult differs from retained lifecycle
            truth.
    """

    if (
        isinstance(returned_result, RunResult)
        and type(returned_result) is not RunResult
    ):
        raise TypeError("Collection returned a RunResult subclass")
    retained = getattr(cli_collector, "run_result", None)
    if type(retained) is RunResult:
        if type(returned_result) is RunResult and returned_result != retained:
            raise RuntimeError(
                "Returned RunResult differs from retained lifecycle truth"
            )
        return retained
    if retained is not None:
        raise TypeError("Lifecycle owner retained a noncanonical RunResult")
    if type(returned_result) is RunResult:
        return returned_result
    return None


def _canonical_result_committed(cli_collector: CLICollector) -> bool:
    """
    Return whether mandatory teardown already owns exact terminal truth.

    The implementation uses ``cli_collector`` to determine whether mandatory
    teardown already owns exact terminal truth.

    Args:
        cli_collector: CLI collector consumed while the function attempts to
            determine whether mandatory teardown already owns exact terminal
            truth.

    Returns:
        Whether mandatory teardown already owns exact terminal truth.
    """

    result = getattr(cli_collector, "run_result", None)
    receipt = getattr(cli_collector, "finalization_receipt", None)
    if (
        type(result) is not RunResult
        or type(receipt) is not FinalizationReceipt
        or not receipt.mandatory_teardown_complete
    ):
        return False
    try:
        validate_structural_finalization_receipt(receipt)
        projector = (
            RunResult.from_planning_receipt
            if result.mode is RunMode.PLANNING
            else RunResult.from_finalization_receipt
        )
        return projector(receipt) == result
    except (RuntimeError, TypeError, ValueError):
        return False


def _publish_finalized_explicit_loose_output_shared_read(
    cli_collector: CLICollector,
    tool_config: Any,
    *,
    delivery_authorized: bool,
    dry_run: bool,
) -> bool:
    """
    Publish one eligible finalized loose bundle for shared read access.

    A retained ``--skip-zip`` run is published only after canonical
    finalization and local delivery bookkeeping with sanitization enabled.
    Ordinary live status and completed collector outputs are already readable;
    this step also publishes remaining sanitized final artifacts. Streaming,
    append, dry-run, and failed runs do not receive that final permission change.

    Args:
        cli_collector: Lifecycle owner containing the finalized orchestrator.
        tool_config: Resolved tool configuration governing local output.
        delivery_authorized: Whether exact terminal evidence authorizes a
            deliverable for this run.
        dry_run: Whether collection ran in non-delivering planning mode.

    Returns:
        Whether a finalized loose bundle was published shared-read.

    Raises:
        RuntimeError: If an eligible retained run lacks its finalized root.
        ValueError: If a selected archive or loose tree fails publication
            validation.
        OSError: If a permission or durability transition fails.

    Side Effects:
        Changes an eligible finalized loose tree to ``0755`` directories and
        ``0755`` regular files, retaining owner-private selection evidence.
    """

    if (
        not delivery_authorized
        or dry_run
        or bool(getattr(tool_config, "skip_sanitization", False))
    ):
        return False

    if (
        not bool(getattr(tool_config, "skip_zip", False))
        or bool(getattr(tool_config, "streaming_only", False))
        or bool(getattr(tool_config, "append", False))
    ):
        return False

    orchestrator = getattr(cli_collector, "orchestrator", None)
    log_dir = getattr(orchestrator, "log_dir", None)
    if not isinstance(log_dir, (str, Path)) or not log_dir:
        raise RuntimeError("Finalized loose output root is unavailable")

    excluded_source_paths: Sequence[str | Path] = ()
    async_logger = getattr(orchestrator, "logger", None)
    exclusion_provider = getattr(
        type(async_logger),
        "managed_publication_delivery_exclusion_paths",
        None,
    )
    if callable(exclusion_provider):
        excluded_source_paths = exclusion_provider(async_logger)
    publish_loose_bundle_shared_read(
        log_dir,
        excluded_source_paths=excluded_source_paths,
        allow_live_shared_root=True,
    )
    return True


def _collection_system_exit_code(
    cli_collector: CLICollector,
    error: SystemExit,
) -> int:
    """
    Map in-lifecycle process control onto receipt-bound public semantics.

    The implementation uses ``cli_collector`` and ``error`` to map in-lifecycle
    process control onto receipt-bound public semantics.

    Args:
        cli_collector: CLI collector consumed while the function attempts to map
            in-lifecycle process control onto receipt-bound public semantics.
        error: Exception or failure detail associated with the operation.

    Returns:
        The numeric collection system exit code value.
    """

    if _collection_shutdown_requested(cli_collector) or (
        type(error.code) is int  # noqa: E721 - subclasses are rejected
        and error.code == 130  # noqa: E721 - subclasses are rejected
    ):
        return 130
    try:
        retained = _retained_run_result(cli_collector)
    except (RuntimeError, TypeError, ValueError):
        retained = None
    if (
        retained is not None
        and _canonical_result_committed(cli_collector)
        and retained.exit_code != 0
    ):
        return retained.exit_code
    # SystemExit(None/0/string) inside the lifecycle is a failure signal, not
    # authorization to turn an incomplete command into public success.
    return 1


def _write_delivery_evidence(
    cli_collector: CLICollector,
    delivery_result: DeliveryResult,
) -> Path:
    """
    Persist a separate delivery result bound to exact local evidence.

    The implementation uses ``cli_collector`` and ``delivery_result`` to persist
    a separate delivery result bound to exact local evidence. Success is
    reported only after the owning output boundary has completed its required
    write or publication step.

    Args:
        cli_collector: CLI collector consumed while the function attempts to
            persist a separate delivery result bound to exact local evidence.
        delivery_result: Delivery result consumed while the function attempts to
            persist a separate delivery result bound to exact local evidence.

    Returns:
        The validated ``sidecar``.
    """

    run_result, receipt, run_directory, archive_paths = _delivery_evidence_inputs(
        cli_collector
    )
    sidecar = write_delivery_result_evidence(
        receipt=receipt,
        run_result=run_result,
        delivery_result=delivery_result,
        run_directory=run_directory,
        archive_paths=archive_paths,
        sanitization_state=_delivery_sanitization_state(cli_collector),
    )
    setattr(cli_collector, "delivery_result", delivery_result)
    setattr(cli_collector, "delivery_result_path", sidecar)
    return sidecar


def _delivery_sanitization_state(cli_collector: CLICollector) -> str:
    """
    Return the sanitization lifecycle state carried by delivery evidence.

    The projection uses the same operator flags and terminal bundle report as
    the delivery gate. A requested pass with missing or failed evidence is
    represented as ``failed_safe`` even though normal authorization prevents
    such a bundle from reaching a provider.

    Args:
        cli_collector: CLI collection owner holding configuration and cleanup
            evidence for the completed run.

    Returns:
        One canonical delivery-evidence sanitization state.
    """
    tool_config = getattr(cli_collector, "tool_config", None)
    if getattr(tool_config, "skip_sanitization", False):
        return "disabled_by_user"
    if not getattr(tool_config, "apply_sanitization", False):
        return "write_time_only"
    orchestrator = getattr(cli_collector, "orchestrator", None)
    cleanup_manager = getattr(orchestrator, "cleanup_manager", None)
    report = getattr(cleanup_manager, "bundle_sanitization_report", None)
    errors = getattr(report, "errors", None)
    if report is None or not isinstance(errors, (list, tuple)) or errors:
        return "failed_safe"
    return "enabled"


def _delivery_evidence_inputs(
    cli_collector: CLICollector,
) -> tuple[RunResult, FinalizationReceipt, Path, tuple[Path, ...]]:
    """
    Resolve exact local evidence shared by delivery write and adoption.

    The implementation uses ``cli_collector`` to resolve exact local evidence
    shared by delivery write and adoption. If the function cannot resolve exact
    local evidence shared by delivery write and adoption, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        cli_collector: CLI collector consumed while the function attempts to
            resolve exact local evidence shared by delivery write and adoption.

    Returns:
        A tuple containing ``run result``, ``receipt``, ``path``, and ``archive
        paths`` in that order.

    Raises:
        RuntimeError: If canonical collection evidence is unavailable.
    """

    run_result = _retained_run_result(cli_collector)
    receipt = getattr(cli_collector, "finalization_receipt", None)
    orchestrator = getattr(cli_collector, "orchestrator", None)
    run_directory = getattr(orchestrator, "log_dir", None)
    if (
        type(run_result) is not RunResult
        or type(receipt) is not FinalizationReceipt
        or run_directory is None
    ):
        raise RuntimeError("Canonical collection evidence is unavailable")
    raw_archives = getattr(orchestrator, "zip_archive_path", None)
    archive_paths = (
        tuple(Path(path) for path in raw_archives)
        if isinstance(raw_archives, (list, tuple))
        else (Path(raw_archives),) if raw_archives else ()
    )
    return run_result, receipt, Path(run_directory), archive_paths


def _sanitize_collection_diagnostic(
    cli_collector: CLICollector,
    value: object,
    *,
    maximum: int = 4096,
    sensitive_values: Sequence[object] = (),
) -> str:
    """
    Use the run sanitizer for bounded collection diagnostics and rendering.

    The implementation uses ``cli_collector``, ``value``, ``maximum``, and
    ``sensitive_values`` to use the run sanitizer for bounded collection diagnostics
    and rendering. Filesystem effects remain confined to the caller-selected
    paths and the owning resource lifecycle.

    Args:
        cli_collector: CLI collector consumed while the function attempts to use
            the run sanitizer for bounded collection diagnostics and rendering.
        value: Value evaluated while performing use the run sanitizer for
            bounded collection diagnostics and rendering.
        maximum: Numeric maximum used while the operation performs bounded
            accounting.
        sensitive_values: Entries supplied as ``sensitive_values`` without
            transferring container ownership.

    Returns:
        The canonical post collection diagnostic text.
    """

    try:
        text = str(value or "")
    except Exception:
        return "[collection diagnostic rendering failed]"
    for sensitive_value in sensitive_values:
        if sensitive_value:
            text = text.replace(str(sensitive_value), "[REDACTED]")
    text = text[:maximum]
    orchestrator = getattr(cli_collector, "orchestrator", None)
    logger = getattr(orchestrator, "logger", None)
    sanitizer = getattr(logger, "sanitizer", None) or getattr(
        orchestrator, "sanitizer", None
    )
    if sanitizer is not None:
        try:
            text = str(sanitizer.sanitize(text))
        except Exception:
            return "[collection diagnostic sanitization failed]"
    return text[:maximum]


@app.callback(
    help="NVIDIA Debug Collection Tool\n\nEach command has dedicated COMMAND OPTIONS/ARGS. Run 'nvdebug COMMAND --help' to see them.\n\nExamples:\n\n -  nvdebug collect --dut-config dut_config.yaml\n\n -  nvdebug preflight --dut-config dut_config.yaml\n\n -  nvdebug --version",
    invoke_without_command=True,
)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=version_callback,
        help="Show version and exit",
    ),
) -> None:
    """
    Main entry point callback for the NVDebug CLI application.

    This function is invoked when the CLI is called without a subcommand,
    displaying help information to guide the user.

    Args:
        ctx: Typer-owned command context injected for this callback invocation.
        version: Version consumed while the function attempts to main entry
            point callback for the NVDebug CLI application.

    Raises:
        typer.Exit: If the function cannot main entry point callback for the
            NVDebug CLI application safely.
    """
    _frozen_self_check()
    _install_minimum_cli_output_umask(ctx)
    env_file = _find_env_file()
    if env_file is not None:
        _load_env_file(env_file)

    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(0)


@app.command(
    cls=_ContextualHelpCommand,
    help="Collect system logs and debug information.\n\n"
    "With no target options, trusted configuration files are auto-detected.\n\n"
    f"{CONFIG_DISCOVERY_TRUST_HELP}\n\n"
    "Examples:\n\n"
    " -  nvdebug collect --dut-config dut_config.yaml\n\n"
    ' -  nvdebug collect -i 192.0.2.10 -u admin -S "R1 R2 H4"  '
    "# password from NVDEBUG_BMC_PASSWORD",
)
def collect(
    ctx: typer.Context,
    # Required arguments (can be provided via CLI or config files)
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        "-C",
        help="Configuration file path (trusted defaults are auto-detected if omitted)",
    ),
    dut_config: Optional[Path] = typer.Option(
        None,
        "--dut-config",
        "--dutconfig",
        "-d",
        help="DUT configuration file (trusted defaults are auto-detected if omitted)",
    ),
    dut_name: str = typer.Option(
        "dut-1",
        "--dut-name",
        help=(
            "DUT identifier and output directory name for direct CLI or "
            "--local collection"
        ),
    ),
    spreadsheet: Optional[Path] = typer.Option(
        None, "--spreadsheet", help="Collector spreadsheet path"
    ),
    baseboard: Optional[str] = typer.Option(
        None, "--baseboard", "-b", help="Target baseboard"
    ),
    ansible_inventory: Optional[Path] = typer.Option(
        None,
        "--ansible-inventory",
        "--ansible_inventory",
        help="Ansible inventory file path",
    ),
    # Local Configuration
    local: bool = typer.Option(False, "--local/--no-local", help="Run in local mode"),
    # Optional arguments
    # /tmp is a public CLI base directory, not a predictable temporary artifact.
    output_dir: Path = typer.Option(
        Path("/tmp"),  # nosec B108
        "--output",
        "--outdir",
        "-o",
        help="Output directory",
    ),
    skip_validation: bool = typer.Option(
        False,
        "--skip-validation/--no-skip-validation",
        help=(
            "Skip configuration and collector-selection validation stages; "
            "explicit --baseboard values are still validated"
        ),
    ),
    # Status Tracking Configuration
    # enable_status_tracking: bool = typer.Option(
    #     True,
    #     "--enable-status-tracking",
    #     help="Enable real-time collection status tracking",
    # ),
    # disable_live_display: bool = typer.Option(
    #     False,
    #     "--disable-live-display",
    #     help="Disable live status display (status files still created)",
    # ),
    # Collector Configuration
    collector_id: Optional[str] = typer.Option(
        None,
        "--collector-id",
        "--cid",
        "--cids",
        "-S",
        help="Specific collector IDs to run (space or comma separated)",
    ),
    collector_group: Optional[List[str]] = typer.Option(
        None,
        "--collector-group",
        "--loggroup",
        "-g",
        help="Specific log groups to run (comma or space separated, e.g. -g redfish,ipmi or -g redfish -g ipmi)",
    ),
    collection_level: Optional[str] = typer.Option(
        None, "--level", help="Collection level (L1, L2, L3)"
    ),
    collection_level_v: int = typer.Option(
        0,
        "-V",
        count=True,
        help="Collection level: -V for L2, -VV or more for L3",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be executed"
    ),
    execution_scheduler: Optional[str] = typer.Option(
        None,
        "--execution-scheduler",
        help="Collector scheduler mode: per_dut or legacy_global",
    ),
    concurrency_mode: Optional[str] = typer.Option(
        None,
        "--concurrency-mode",
        help="Global collector admission: conservative, fixed, or adaptive",
    ),
    initial_io_oversubscription: Optional[float] = typer.Option(
        None,
        "--initial-io-oversubscription",
        min=0.001,
        max=64.0,
        help="Initial collector-operation multiplier for the effective CPU budget",
    ),
    minimum_collector_operations: Optional[int] = typer.Option(
        None,
        "--minimum-collector-operations",
        min=1,
        max=4096,
        help="Adaptive weighted collector-operation floor",
    ),
    maximum_collector_operations: Optional[int] = typer.Option(
        None,
        "--maximum-collector-operations",
        min=1,
        max=4096,
        help="Hard weighted collector-operation ceiling (required for adaptive)",
    ),
    # Logging Configuration
    debug: bool = typer.Option(False, "--debug/--no-debug", help="Enable debug output"),
    verbose: bool = typer.Option(
        False, "--verbose/--no-verbose", "-v", help="Print detailed output"
    ),
    # BMC Configuration
    bmc_ip: Optional[str] = typer.Option(
        None, "--bmc-ip", "--ip", "-i", help="BMC IP address"
    ),
    bmc_user: Optional[str] = typer.Option(
        None, "--bmc-user", "--user", "-u", help="BMC username"
    ),
    bmc_pass: Optional[str] = typer.Option(
        None,
        "--bmc-pass",
        "--password",
        "-p",
        envvar="NVDEBUG_BMC_PASSWORD",
        help="BMC password (DEPRECATED: visible in process arguments; prefer NVDEBUG_BMC_PASSWORD or the hidden TTY prompt)",
    ),
    bmc_ssh_user: Optional[str] = typer.Option(
        None, "--bmc-ssh-user", "--sshuser", "-r", help="BMC SSH username"
    ),
    bmc_ssh_pass: Optional[str] = typer.Option(
        None,
        "--bmc-ssh-pass",
        "--sshpass",
        "-w",
        envvar="NVDEBUG_BMC_SSH_PASSWORD",
        help="BMC SSH password (DEPRECATED: visible in process arguments; prefer NVDEBUG_BMC_SSH_PASSWORD or the hidden TTY prompt)",
    ),
    bmc_ssh_port: Optional[int] = typer.Option(
        None, "--bmc-ssh-port", help="BMC SSH port"
    ),
    bmc_ssh_key_path: Optional[str] = typer.Option(
        None, "--bmc-ssh-key-path", help="BMC SSH key path"
    ),
    bmc_ssh_passwordless: bool = typer.Option(
        False,
        "--bmc-ssh-passwordless/--no-bmc-ssh-passwordless",
        help="Use passwordless SSH for BMC",
    ),
    bmc_ssh_max_retries: Optional[int] = typer.Option(
        3, "--bmc-ssh-max-retries", help="BMC SSH max retry attempts"
    ),
    bmc_rf_user: Optional[str] = typer.Option(
        None, "--bmc-rf-user", "--rfuser", "-R", help="Redfish username"
    ),
    bmc_rf_pass: Optional[str] = typer.Option(
        None,
        "--bmc-rf-pass",
        "--rfpass",
        "-W",
        envvar="NVDEBUG_BMC_REDFISH_PASSWORD",
        help="Redfish password (DEPRECATED: visible in process arguments; prefer NVDEBUG_BMC_REDFISH_PASSWORD or the hidden TTY prompt)",
    ),
    bmc_rf_port: Optional[int] = typer.Option(
        None, "--bmc-rf-port", help="Redfish port"
    ),
    # Host Configuration
    host_ip: Optional[str] = typer.Option(
        None, "--host-ip", "--hostip", "-I", help="Host IP address"
    ),
    host_user: Optional[str] = typer.Option(
        None, "--host-user", "--hostuser", "-U", help="Host username"
    ),
    host_pass: Optional[str] = typer.Option(
        None,
        "--host-pass",
        "--hostpass",
        "-H",
        envvar="NVDEBUG_HOST_PASSWORD",
        help="Host password (DEPRECATED: visible in process arguments; prefer NVDEBUG_HOST_PASSWORD or the hidden TTY prompt)",
    ),
    host_ssh_port: Optional[int] = typer.Option(
        None, "--host-ssh-port", "--port", "-P", help="Host SSH port"
    ),
    host_ssh_key_path: Optional[str] = typer.Option(
        None, "--host-ssh-key-path", help="Host SSH key path"
    ),
    host_ssh_passwordless: bool = typer.Option(
        False,
        "--host-ssh-passwordless/--no-host-ssh-passwordless",
        help="Use passwordless SSH for Host",
    ),
    host_ssh_max_retries: Optional[int] = typer.Option(
        3, "--host-ssh-max-retries", help="Host SSH max retry attempts"
    ),
    # HMC Configuration
    hmc_ip: Optional[str] = typer.Option(None, "--hmc-ip", help="HMC IP address"),
    hmc_user: Optional[str] = typer.Option(None, "--hmc-user", help="HMC username"),
    hmc_pass: Optional[str] = typer.Option(
        None,
        "--hmc-pass",
        envvar="NVDEBUG_HMC_PASSWORD",
        help="HMC password (DEPRECATED: visible in process arguments; prefer NVDEBUG_HMC_PASSWORD or the hidden TTY prompt)",
    ),
    hmc_ssh_user: Optional[str] = typer.Option(
        None, "--hmc-ssh-user", help="HMC SSH username"
    ),
    hmc_ssh_pass: Optional[str] = typer.Option(
        None,
        "--hmc-ssh-pass",
        envvar="NVDEBUG_HMC_SSH_PASSWORD",
        help="HMC SSH password (DEPRECATED: visible in process arguments; prefer NVDEBUG_HMC_SSH_PASSWORD or the hidden TTY prompt)",
    ),
    hmc_ssh_port: Optional[int] = typer.Option(
        None, "--hmc-ssh-port", help="HMC SSH port"
    ),
    hmc_ssh_key_path: Optional[str] = typer.Option(
        None, "--hmc-ssh-key-path", help="HMC SSH key path"
    ),
    hmc_ssh_passwordless: bool = typer.Option(
        False,
        "--hmc-ssh-passwordless/--no-hmc-ssh-passwordless",
        help="Use passwordless SSH for HMC",
    ),
    hmc_ssh_max_retries: Optional[int] = typer.Option(
        3, "--hmc-ssh-max-retries", help="HMC SSH max retry attempts"
    ),
    hmc_http_port: Optional[int] = typer.Option(
        80, "--hmc-http-port", help="HMC HTTP port"
    ),
    hmc_https_port: Optional[int] = typer.Option(
        443, "--hmc-https-port", help="HMC HTTPS port"
    ),
    hmc_use_https: bool = typer.Option(
        False,
        "--hmc-use-https/--no-hmc-use-https",
        help="Use HTTPS for HMC",
    ),
    use_port_forwarding: bool = typer.Option(
        False,
        "--use-port-forwarding/--no-use-port-forwarding",
        help="Enable port forwarding (general)",
    ),
    tunnel_tcp_port: Optional[int] = typer.Option(
        None, "--tunnel-tcp-port", help="Port for SSH tunnel forwarding"
    ),
    setup_port_forwarding: bool = typer.Option(
        None,
        "--setup-port-forwarding/--no-setup-port-forwarding",
        help="Auto-setup port forwarding tunnels",
    ),
    force_port_fw: bool = typer.Option(
        None,
        "--force-port-fw/--no-force-port-fw",
        help="Replace a verified matching SSH tunnel owned by this local user, including an earlier NVDebug run",
    ),
    hmc_access_method: Optional[str] = typer.Option(
        None,
        "--hmc-access-method",
        help=HMC_ACCESS_METHOD_HELP,
        click_type=click.Choice(HMC_ACCESS_METHODS, case_sensitive=True),
    ),
    rf_hmc_prefix: Optional[str] = typer.Option(
        None,
        "--hmc-rf-prefix",
        help=(
            "Redfish URI prefix for HMC-targeted resources (e.g. /hgx/redfish/v1). "
            "Overrides RF_HMC_DEFAULT_PREFIX in DUT config. "
            "Leave unset when BMC exposes HMC resources under the same prefix as the BMC Redfish root."
        ),
    ),
    rf_bmc_prefix: Optional[str] = typer.Option(
        None,
        "--bmc-rf-prefix",
        help=(
            "Redfish URI prefix for BMC (Customer BMC) resources (e.g. /custom/redfish/v1). "
            "Overrides RF_DEFAULT_PREFIX in DUT config. "
            "Defaults to /redfish/v1 when not set."
        ),
    ),
    # SSH Proxy Configuration
    ssh_proxy_host: Optional[str] = typer.Option(
        None, "--ssh-proxy-host", help="SSH proxy hostname/IP"
    ),
    ssh_proxy_port: Optional[int] = typer.Option(
        22, "--ssh-proxy-port", help="SSH proxy port"
    ),
    ssh_proxy_user: Optional[str] = typer.Option(
        None, "--ssh-proxy-user", help="SSH proxy username"
    ),
    ssh_proxy_pass: Optional[str] = typer.Option(
        None,
        "--ssh-proxy-pass",
        envvar="NVDEBUG_SSH_PROXY_PASSWORD",
        help="SSH proxy password (DEPRECATED: visible in process arguments; prefer NVDEBUG_SSH_PROXY_PASSWORD or the hidden TTY prompt)",
    ),
    ssh_proxy_key_path: Optional[str] = typer.Option(
        None, "--ssh-proxy-key-path", help="SSH proxy private key path"
    ),
    ssh_proxy_passwordless: bool = typer.Option(
        False,
        "--ssh-proxy-passwordless/--no-ssh-proxy-passwordless",
        help="Use passwordless SSH for proxy",
    ),
    ssh_proxy_max_retries: Optional[int] = typer.Option(
        3, "--ssh-proxy-max-retries", help="SSH proxy max retry attempts"
    ),
    # Archive Configuration
    skip_zip: bool = typer.Option(
        False,
        "--skip-zip/--no-skip-zip",
        "-z",
        "--skipzip",
        help=(
            "Keep finalized output as a loose directory; live status and "
            "sanitized collector output are readable during collection"
        ),
    ),
    skip_zip_split: bool = typer.Option(
        False,
        "--skip-zip-split/--no-skip-zip-split",
        "-Z",
        "--skipzipsplit",
        help="Skip splitting zip archive",
    ),
    zip_split_threshold: float = typer.Option(
        200.0,
        "--zip-split-threshold",
        "--zipsplit_threshold",
        help="Zip archive size threshold (MB)",
    ),
    # Common Configuration
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive/--interactive",
        help="Non-interactive mode - use detected values or exit if detection fails",
    ),
    skip_preflight: bool = typer.Option(
        False,
        "--skip-preflight/--no-skip-preflight",
        help="Skip preflight checks (useful for testing with unreachable DUTs)",
    ),
    skip_sanitization: bool = typer.Option(
        False,
        "--skip-sanitization/--no-skip-sanitization",
        help="Skip write-time log sanitization (enabled by default)",
    ),
    apply_sanitization: bool = typer.Option(
        False,
        "--apply-sanitization/--no-apply-sanitization",
        help=(
            "Recursively sanitize the completed bundle before reports and archive "
            "creation (disabled by default)"
        ),
    ),
    skip_html_reports: bool = typer.Option(
        False,
        "--skip-html-reports/--no-skip-html-reports",
        help="Skip HTML report generation",
    ),
    report_format: str = typer.Option(
        "spa",
        "--report-format",
        help="Report format: 'spa' (Vue SPA, default), 'legacy' (HTML only), or 'both'",
    ),
    expand_fallback_mode: Optional[str] = typer.Option(
        None,
        "--expand-fallback-mode",
        help=(
            "Behavior when the BMC does not support Redfish $expand: "
            "'auto' (probe ServiceRoot, fall back to per-member walk on rejection), "
            "'never' (treat $expand failure as a hard error — legacy behavior), "
            "'always' (skip $expand entirely, always use per-member walk). "
            "Overrides EXPAND_FALLBACK_MODE in tool_config.yaml; per-DUT "
            "EXPAND_FALLBACK_MODE in dut_config.yaml still wins over both."
        ),
    ),
    expand_level: Optional[int] = typer.Option(
        None,
        "--expand-level",
        help=(
            "Override all EXPAND_QUERY_*_LEVEL values (Chassis, FirmwareInventory, "
            "Manager, System) for $expand-based Redfish collectors. Clamped to the "
            "BMC's advertised ExpandQuery.MaxLevels when 'auto' mode probes successfully. "
            "Per-DUT EXPAND_QUERY_*_LEVEL values in dut_config.yaml take precedence."
        ),
    ),
    ssl_verify: Optional[bool] = typer.Option(
        None,
        "--ssl-verify/--no-ssl-verify",
        help="Opt into system CA verification or explicitly disable Redfish TLS "
        "authentication. Verification is disabled by default for compatibility "
        "with self-signed BMCs; insecure operation emits a security warning.",
    ),
    insecure: bool = typer.Option(
        False,
        "--insecure",
        help=(
            "Compatibility option that selects insecure Redfish TLS transport "
            "for this run. Cannot be combined with --ssl-verify and emits a "
            "security warning."
        ),
    ),
    ssh_host_key_policy: Optional[str] = typer.Option(
        None,
        "--ssh-host-key-policy",
        help=(
            "SSH server authentication policy for all routes: 'insecure' "
            "(default) or 'strict'. Overrides tool and DUT YAML for this run."
        ),
    ),
    ssh_known_hosts_file: Optional[Path] = typer.Option(
        None,
        "--ssh-known-hosts-file",
        help=(
            "Known-hosts trust source used with --ssh-host-key-policy strict. "
            "Overrides tool and DUT YAML for this run."
        ),
    ),
    redfish_structured_response_max_bytes: Optional[int] = typer.Option(
        None,
        "--redfish-structured-response-max-bytes",
        min=1,
        max=MAX_SIGNED_64_BIT_INTEGER,
        help="Finite byte ceiling for JSON/text Redfish responses (default: 64 MiB).",
    ),
    redfish_attachment_max_bytes: Optional[int] = typer.Option(
        None,
        "--redfish-attachment-max-bytes",
        min=1,
        max=MAX_SIGNED_64_BIT_INTEGER,
        help="Finite byte ceiling for streamed Redfish attachments (default: 2 GiB).",
    ),
    redfish_error_response_max_bytes: Optional[int] = typer.Option(
        None,
        "--redfish-error-response-max-bytes",
        min=1,
        max=MAX_SIGNED_64_BIT_INTEGER,
        help="Finite byte ceiling for Redfish error bodies (default: 1 MiB).",
    ),
    redfish_error_evidence_max_bytes: Optional[int] = typer.Option(
        None,
        "--redfish-error-evidence-max-bytes",
        min=1,
        max=MAX_SIGNED_64_BIT_INTEGER,
        help="Finite per-response retained error-evidence ceiling (default: 256 KiB).",
    ),
    redfish_error_evidence_aggregate_max_bytes: Optional[int] = typer.Option(
        None,
        "--redfish-error-evidence-aggregate-max-bytes",
        min=1,
        max=MAX_SIGNED_64_BIT_INTEGER,
        help="Finite retained error-evidence ceiling across retries (default: 1 MiB).",
    ),
    redfish_error_evidence_max_responses: Optional[int] = typer.Option(
        None,
        "--redfish-error-evidence-max-responses",
        min=1,
        max=MAX_SIGNED_64_BIT_INTEGER,
        help="Maximum retained oversized error responses per request (default: 4).",
    ),
    redfish_preflight_response_max_bytes: Optional[int] = typer.Option(
        None,
        "--redfish-preflight-response-max-bytes",
        min=1,
        max=MAX_SIGNED_64_BIT_INTEGER,
        help="Finite byte ceiling for credential-preflight bodies (default: 1 MiB).",
    ),
    redfish_cache_max_bytes: Optional[int] = typer.Option(
        None,
        "--redfish-cache-max-bytes",
        min=1,
        max=MAX_SIGNED_64_BIT_INTEGER,
        help="Finite aggregate Redfish response-cache ceiling (default: 32 MiB).",
    ),
    redfish_cache_entry_max_bytes: Optional[int] = typer.Option(
        None,
        "--redfish-cache-entry-max-bytes",
        min=1,
        max=MAX_SIGNED_64_BIT_INTEGER,
        help="Finite per-entry Redfish cache ceiling (default: 4 MiB).",
    ),
    # Collector Skip Configuration
    skip_collectors: Optional[str] = typer.Option(
        None,
        "--skip-collectors",
        help="List of collector IDs to skip (comma-separated)",
    ),
    include_collectors: Optional[str] = typer.Option(
        None,
        "--include-collectors",
        help=(
            "Add collector IDs to the current selection (comma-separated; "
            "additive to defaults, groups, levels, and --collector-id)"
        ),
    ),
    # Streaming Configuration
    streaming_only: bool = typer.Option(
        False,
        "--streaming-only/--no-streaming-only",
        help=(
            "Restrict the run to collectors marked as streaming candidates; "
            "requires --stream-destination"
        ),
    ),
    stream_begin: str = typer.Option(
        "24",
        "--stream-begin",
        help="Start of streaming window as UTC timestamp (YYYYMMDDTHHMMZ) or hours ago. Defaults to 24.",
    ),
    stream_end: str = typer.Option(
        "0",
        "--stream-end",
        help="End of streaming window as UTC timestamp (YYYYMMDDTHHMMZ) or hours ago. Defaults to 0 (now).",
    ),
    stream_destination: Optional[Path] = typer.Option(
        None,
        "--stream-destination",
        help=(
            "Absolute destination for streamed logs, separate from --output; "
            "automatically enables --streaming-only, --append, and --skip-zip"
        ),
    ),
    append: bool = typer.Option(
        False,
        "--append/--no-append",
        help=(
            "Write into the stable streaming destination tree; requires "
            "--stream-destination and is enabled automatically when it is set"
        ),
    ),
    rack_id: Optional[str] = typer.Option(
        None,
        "--rack-id",
        help="Optional rack identifier used as an intermediate output directory for streaming collections.",
    ),
) -> None:
    """
    Collect system logs and debug information from NVIDIA platforms.

    This command collects comprehensive system logs, debug information, and
    diagnostic data from target devices (DUTs). It supports multiple collection
    modes: local mode, single-DUT CLI mode, and multi-DUT configuration file
    mode.

    Args:
        ctx: Typer-owned context for this collect command invocation.
        config_file: filesystem location used as the config file for this
            operation.
        dut_config: filesystem location used as the DUT config for this
            operation.
        dut_name: Stable DUT name used for lookup and operator-facing
            diagnostics.
        spreadsheet: filesystem location used as the spreadsheet for this
            operation.
        baseboard: Text supplied as baseboard in the format accepted by this
            function.
        ansible_inventory: filesystem location used as the ansible inventory for
            this operation.
        local: Whether local is enabled or required for this operation.
        output_dir: filesystem location used as the output dir for this
            operation.
        skip_validation: Whether skip validation is enabled or required for this
            operation.
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        collector_group: Entries supplied as ``collector_group`` without
            transferring container ownership.
        collection_level: Text supplied as collection level in the format
            accepted by this function.
        collection_level_v: Numeric collection level v used while the operation
            performs bounded accounting.
        dry_run: Whether dry run is enabled or required for this operation.
        concurrency_mode: Conservative, fixed, or adaptive global admission.
        initial_io_oversubscription: Optional configured CPU multiplier.
        minimum_collector_operations: Optional adaptive weighted-capacity floor.
        maximum_collector_operations: Optional hard weighted-capacity ceiling.
        execution_scheduler: Text supplied as execution scheduler in the format
            accepted by this function.
        debug: Whether debug is enabled or required for this operation.
        verbose: Whether verbose is enabled or required for this operation.
        bmc_ip: Text supplied as BMC IP in the format accepted by this function.
        bmc_user: Text supplied as BMC user in the format accepted by this
            function.
        bmc_pass: Text supplied as BMC pass in the format accepted by this
            function.
        bmc_ssh_user: Text supplied as BMC SSH user in the format accepted by
            this function.
        bmc_ssh_pass: Text supplied as BMC SSH pass in the format accepted by
            this function.
        bmc_ssh_port: Numeric BMC SSH port used while the operation performs
            bounded accounting.
        bmc_ssh_key_path: filesystem location used as the BMC SSH key path for
            this operation.
        bmc_ssh_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        bmc_ssh_max_retries: Numeric BMC SSH max retries used while the
            operation performs bounded accounting.
        bmc_rf_user: Text supplied as BMC Redfish user in the format accepted by
            this function.
        bmc_rf_pass: Text supplied as BMC Redfish pass in the format accepted by
            this function.
        bmc_rf_port: Numeric BMC Redfish port used while the operation performs
            bounded accounting.
        host_ip: Text supplied as host IP in the format accepted by this
            function.
        host_user: Text supplied as host user in the format accepted by this
            function.
        host_pass: Text supplied as host pass in the format accepted by this
            function.
        host_ssh_port: Numeric host SSH port used while the operation performs
            bounded accounting.
        host_ssh_key_path: filesystem location used as the host SSH key path for
            this operation.
        host_ssh_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        host_ssh_max_retries: Numeric host SSH max retries used while the
            operation performs bounded accounting.
        hmc_ip: Text supplied as HMC IP in the format accepted by this function.
        hmc_user: Text supplied as HMC user in the format accepted by this
            function.
        hmc_pass: Text supplied as HMC pass in the format accepted by this
            function.
        hmc_ssh_user: Text supplied as HMC SSH user in the format accepted by
            this function.
        hmc_ssh_pass: Text supplied as HMC SSH pass in the format accepted by
            this function.
        hmc_ssh_port: Numeric HMC SSH port used while the operation performs
            bounded accounting.
        hmc_ssh_key_path: filesystem location used as the HMC SSH key path for
            this operation.
        hmc_ssh_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        hmc_ssh_max_retries: Numeric HMC SSH max retries used while the
            operation performs bounded accounting.
        hmc_http_port: Numeric HMC HTTP port used while the operation performs
            bounded accounting.
        hmc_https_port: Numeric HMC HTTPS port used while the operation performs
            bounded accounting.
        hmc_use_https: Whether HMC use HTTPS is enabled or required for this
            operation.
        use_port_forwarding: Whether use port forwarding is enabled or required
            for this operation.
        tunnel_tcp_port: Numeric tunnel TCP port used while the operation
            performs bounded accounting.
        setup_port_forwarding: Whether setup port forwarding is enabled or
            required for this operation.
        force_port_fw: Whether force port firmware is enabled or required for
            this operation.
        hmc_access_method: Text supplied as HMC access method in the format
            accepted by this function.
        rf_hmc_prefix: Text supplied as Redfish HMC prefix in the format
            accepted by this function.
        rf_bmc_prefix: Text supplied as Redfish BMC prefix in the format
            accepted by this function.
        ssh_proxy_host: Text supplied as SSH proxy host in the format accepted
            by this function.
        ssh_proxy_port: Numeric SSH proxy port used while the operation performs
            bounded accounting.
        ssh_proxy_user: Text supplied as SSH proxy user in the format accepted
            by this function.
        ssh_proxy_pass: Text supplied as SSH proxy pass in the format accepted
            by this function.
        ssh_proxy_key_path: filesystem location used as the SSH proxy key path
            for this operation.
        ssh_proxy_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        ssh_proxy_max_retries: Numeric SSH proxy max retries used while the
            operation performs bounded accounting.
        skip_zip: Whether skip ZIP is enabled or required for this operation.
        skip_zip_split: Whether skip ZIP split is enabled or required for this
            operation.
        zip_split_threshold: Numeric ZIP split threshold used while the
            operation performs bounded accounting.
        non_interactive: Whether non interactive is enabled or required for this
            operation.
        skip_preflight: Whether skip preflight is enabled or required for this
            operation.
        skip_sanitization: Whether skip sanitization is enabled or required for
            this operation.
        apply_sanitization: Whether apply sanitization is enabled or required
            for this operation.
        skip_html_reports: Whether skip HTML reports is enabled or required for
            this operation.
        report_format: Text supplied as report format in the format accepted by
            this function.
        expand_fallback_mode: Text supplied as expand fallback mode in the
            format accepted by this function.
        expand_level: Numeric expand level used while the operation performs
            bounded accounting.
        ssl_verify: Ssl verify consumed while the function attempts to collect
            system logs and debug information from NVIDIA platforms.
        insecure: Whether the compatibility insecure Redfish TLS mode is
            explicitly selected for this run.
        ssh_host_key_policy: Optional SSH server-authentication policy that
            overrides tool and DUT configuration for every route in this run.
        ssh_known_hosts_file: Optional known-hosts trust source used when strict
            SSH host-key verification is selected.
        redfish_structured_response_max_bytes: Upper bound enforced for Redfish
            structured response max bytes; the consuming boundary rejects or
            truncates values that exceed it.
        redfish_attachment_max_bytes: Upper bound enforced for Redfish
            attachment max bytes; the consuming boundary rejects or truncates
            values that exceed it.
        redfish_error_response_max_bytes: Upper bound enforced for Redfish error
            response max bytes; the consuming boundary rejects or truncates
            values that exceed it.
        redfish_error_evidence_max_bytes: Upper bound enforced for Redfish error
            evidence max bytes; the consuming boundary rejects or truncates
            values that exceed it.
        redfish_error_evidence_aggregate_max_bytes: Upper bound enforced for
            Redfish error evidence aggregate max bytes; the consuming boundary
            rejects or truncates values that exceed it.
        redfish_error_evidence_max_responses: Numeric Redfish error evidence max
            responses used while the operation performs bounded accounting.
        redfish_preflight_response_max_bytes: Upper bound enforced for Redfish
            preflight response max bytes; the consuming boundary rejects or
            truncates values that exceed it.
        redfish_cache_max_bytes: Upper bound enforced for Redfish cache max
            bytes; the consuming boundary rejects or truncates values that
            exceed it.
        redfish_cache_entry_max_bytes: Upper bound enforced for Redfish cache
            entry max bytes; the consuming boundary rejects or truncates values
            that exceed it.
        skip_collectors: Whether skip collectors is enabled or required for this
            operation.
        include_collectors: Whether include collectors is enabled or required
            for this operation.
        streaming_only: Whether streaming-only collector selection is enabled.
        stream_begin: Text supplied as stream begin in the format accepted by
            this function.
        stream_end: Text supplied as stream end in the format accepted by this
            function.
        stream_destination: filesystem location used as the destination for this
            operation.
        append: Whether streaming output uses the stable destination tree.
        rack_id: Stable rack identifier used to correlate configuration, logs,
            and results.

    Raises:
        typer.Exit: If the function cannot collect system logs and debug
            information from NVIDIA platforms safely.
        typer.BadParameter: If the function cannot collect system logs and debug
            information from NVIDIA platforms safely.
        TypeError: If sanitization finalizer returned a non-exception value.
        BaseException: If a delegated failure occurs while the function attempts
            to collect system logs and debug information from NVIDIA platforms.
    """

    # Contract tooling can parse explicit values without running Click
    # callbacks, so keep local scalar validation ahead of configuration
    # resolution, secret handling, prompting, or any other I/O. Direct callback
    # tests may retain Typer's declaration sentinel.
    if not isinstance(zip_split_threshold, typer.models.OptionInfo):
        zip_split_threshold = _validate_zip_split_threshold(zip_split_threshold)

    # Resolve parameter provenance before configuration access, prompting, or
    # generated-file creation. Literal secret options are already visible in
    # the process arguments, so emit compatibility guidance (or enforce the
    # explicit fail-closed policy) before reporting any overlapping
    # target-source conflict. Empty and default-looking CLI values remain
    # explicit for both policies.
    explicit_cli_params = _explicit_cli_params(ctx)
    insecure_cli_explicit = "insecure" in explicit_cli_params
    ssl_verify_cli_explicit = "ssl_verify" in explicit_cli_params
    redfish_tls_spellings = frozenset(ctx.meta.get("nvdebug_redfish_tls_spellings", ()))
    contradictory_tls_options = insecure_cli_explicit and (
        "--ssl-verify" in redfish_tls_spellings
        or (
            not redfish_tls_spellings and ssl_verify_cli_explicit and ssl_verify is True
        )
    )
    if contradictory_tls_options:
        _present_cli_failure(
            "Error: contradictory Redfish TLS options: --insecure cannot be "
            "combined with --ssl-verify.",
            title="Conflicting Redfish TLS Options",
            suggestions=(
                "Choose --ssl-verify for authenticated TLS, or --insecure for an explicit insecure connection.",
                "Remove the contradictory option and retry.",
            ),
        )
        raise typer.Exit(code=2)
    redfish_tls_cli_explicit = insecure_cli_explicit or ssl_verify_cli_explicit
    if insecure_cli_explicit:
        # Keep the compatibility spelling semantically identical to an
        # insecure TLS selection. Downstream precedence and effective-input
        # accounting use the canonical compatibility field for both insecure
        # spellings.
        ssl_verify = False
        explicit_cli_params.add("ssl_verify")
        sanitized_console.print_warning(INSECURE_REDFISH_TRANSPORT_WARNING_MESSAGE)
    explicit_remote_cli_fields = explicit_cli_params & _REMOTE_TARGET_CLI_PARAMS
    _warn_for_literal_secret_options(ctx, *SECRET_ENVIRONMENT_BY_PARAMETER)
    env_dut_config_selected = dut_config is None and bool(
        os.environ.get("NVDEBUG_DUT_CONFIG", "").strip()
    )
    user_selected_dut_config = dut_config is not None or env_dut_config_selected

    if ansible_inventory is not None and (
        user_selected_dut_config or explicit_remote_cli_fields
    ):
        _present_cli_failure(
            "Error: mutually exclusive target sources: --ansible-inventory cannot "
            "be combined with --dut-config, NVDEBUG_DUT_CONFIG, or remote target "
            "CLI options.",
            title="Conflicting Target Sources",
            suggestions=(
                "Use --ansible-inventory by itself as the target source.",
                "Or remove --ansible-inventory and use one DUT config or direct CLI target.",
            ),
        )
        raise typer.Exit(code=2)

    if local and (
        explicit_remote_cli_fields
        or user_selected_dut_config
        or ansible_inventory is not None
    ):
        _present_cli_failure(
            "Error: --local cannot be combined with a remote target source "
            "(--dut-config, NVDEBUG_DUT_CONFIG, --ansible-inventory, or remote "
            "target CLI options).",
            title="Conflicting Target Sources",
            suggestions=(
                "Use --local by itself for local collection.",
                "Or remove --local and keep one remote target source.",
            ),
        )
        raise typer.Exit(code=2)

    bmc_pass = _backfill_secret_option_from_environment(ctx, "bmc_pass", bmc_pass)
    bmc_ssh_pass = _backfill_secret_option_from_environment(
        ctx, "bmc_ssh_pass", bmc_ssh_pass
    )
    bmc_rf_pass = _backfill_secret_option_from_environment(
        ctx, "bmc_rf_pass", bmc_rf_pass
    )
    host_pass = _backfill_secret_option_from_environment(ctx, "host_pass", host_pass)
    hmc_pass = _backfill_secret_option_from_environment(ctx, "hmc_pass", hmc_pass)
    hmc_ssh_pass = _backfill_secret_option_from_environment(
        ctx, "hmc_ssh_pass", hmc_ssh_pass
    )
    ssh_proxy_pass = _backfill_secret_option_from_environment(
        ctx, "ssh_proxy_pass", ssh_proxy_pass
    )
    scrub_secret_environment()

    dut_name_explicit = "dut_name" in explicit_cli_params

    # Configured DUT sources own their target names. Reject an explicit CLI
    # name before Ansible processing so generated credential files cannot be
    # left behind on this validation path.
    if dut_name_explicit and (
        dut_config is not None
        or ansible_inventory is not None
        or bool(os.environ.get("NVDEBUG_DUT_CONFIG", "").strip())
    ):
        _present_cli_failure(
            "Error: ambiguous per-DUT CLI option '--dut-name' for configured "
            "or multi-DUT target sources. Configured sources own target names; "
            "use --dut-name only with a direct CLI target or --local collection.",
            title="Conflicting DUT Options",
        )
        raise typer.Exit(code=2)

    if isinstance(dut_name, typer.models.OptionInfo):
        dut_name = str(dut_name.default)
    else:
        try:
            dut_name = require_safe_artifact_component(dut_name, "DUT name")
        except ValueError as error:
            raise typer.BadParameter(str(error), param_hint="--dut-name") from error

    collector_group = _normalize_cli_collector_groups(
        collector_group,
        sanitized_console,
    )

    # Default Status Tracking Configuration
    enable_status_tracking = True
    disable_live_display = False

    # Preserve catalog origin before auto-detection replaces the selected path.
    # The digest proves which bytes ran; this binding records who selected them.
    catalog_was_operator_supplied = spreadsheet is not None or bool(
        os.environ.get("NVDEBUG_SPREADSHEET", "").strip()
    )

    # Auto-detect spreadsheet if not provided
    spreadsheet = auto_detect_spreadsheet(spreadsheet)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet)

    # Own the exact workbook bytes before any Ansible/baseboard/configuration
    # consumer can derive runtime behavior from the selected catalog. If the
    # file disappears after validation, fail here rather than allowing a later
    # replacement pathname to become a second byte authority.
    catalog_snapshot: Optional[CatalogSnapshot] = None
    if spreadsheet is not None:
        try:
            # Loose catalogs may be edited in either runtime. Discovery alone
            # does not establish that their bytes match a release manifest.
            catalog_binding = (
                "operator_supplied" if catalog_was_operator_supplied else "discovered"
            )
            catalog_snapshot = read_catalog_snapshot(
                spreadsheet,
                catalog_binding=catalog_binding,
            )
        except (OSError, ValueError) as exc:
            _present_cli_failure(
                f"Error capturing the selected Telemetry Catalog: {exc}",
                title="Telemetry Catalog Error",
                suggestions=(
                    "Verify the selected spreadsheet exists and is readable.",
                    "Retry with --spreadsheet pointing to a valid Telemetry Catalog.",
                ),
            )
            raise typer.Exit(code=2) from exc
    catalog_source = catalog_snapshot if catalog_snapshot is not None else spreadsheet

    # Determine final collection level based on --level and -V/-VV flags
    # If both are specified, take the higher level
    v_level = get_collection_level_from_v_count(collection_level_v)
    # Only use CLI level if it's explicitly provided (not None)
    if collection_level is not None or collection_level_v > 0:
        cli_level = collection_level if collection_level is not None else "L1"
        final_collection_level = get_higher_collection_level(cli_level, v_level)
    else:
        # No CLI level specified - will be determined later from config file
        final_collection_level = None

    # Minimal init; config_file_data and config-derived vars are set after _load_tool_config
    config_file_data = {}
    final_output_dir = str(output_dir)

    has_cli_credentials = any([bmc_ip, host_ip, hmc_ip])

    (
        streaming_only,
        stream_destination,
        append,
        stream_begin,
        stream_end,
        skip_zip,
    ) = _normalize_streaming_contract(
        streaming_only=streaming_only,
        stream_destination=stream_destination,
        append=append,
        stream_begin=stream_begin,
        stream_end=stream_end,
        skip_zip=skip_zip,
        explicit_cli_params=explicit_cli_params,
    )

    # Track reported configuration errors to prevent duplicates
    _reported_config_errors = set()

    # Handle Ansible inventory if provided
    temp_config_file = None
    temp_dut_config_file = None

    def cleanup_generated_ansible_configs() -> None:
        """
        Remove generated credential-bearing configs exactly once.

        The implementation uses current instance state to remove generated
        credential-bearing configs exactly once.
        """

        nonlocal temp_config_file, temp_dut_config_file
        if temp_config_file is None or temp_dut_config_file is None:
            return
        cleanup_temp_config_files(temp_config_file, temp_dut_config_file)
        temp_config_file = None
        temp_dut_config_file = None

    def cleanup_generated_ansible_configs_on_context_close() -> None:
        """
        Best-effort cleanup owned by the Click command context.

        Click closes its context for ordinary returns and every exception path,
        including validation failures raised before collector construction.
        Cleanup diagnostics must not replace the command's authoritative exit.
        """
        try:
            cleanup_generated_ansible_configs()
        except BaseException as cleanup_error:
            try:
                sanitized_console.print_warning(
                    "Warning: Could not clean up temporary config files: "
                    f"{cleanup_error}"
                )
            except BaseException:
                pass

    environment_dut_locator_selected = (
        not local
        and ansible_inventory is None
        and dut_config is None
        and bool(os.environ.get("NVDEBUG_DUT_CONFIG", "").strip())
    )

    # Store original DUT config path for cleanup (in case auto-assignment creates temp file)
    original_dut_config = dut_config
    user_selected_tool_config = _operator_selected_tool_config(config_file)

    if ansible_inventory:
        if not ansible_inventory.exists():
            _present_cli_failure(
                f"Ansible inventory file '{ansible_inventory}' does not exist.",
                title="Ansible Inventory Error",
                suggestions=(
                    "Check the --ansible-inventory path and file permissions.",
                    "Use --dut-config or a direct CLI target when no inventory is available.",
                ),
            )
            sys.exit(1)

        try:
            sanitized_console.print_info(
                f"Using Ansible inventory: {ansible_inventory}",
                soft_wrap=True,
            )
            sanitized_console.print_info(
                f"Parsing ansible file: {ansible_inventory}",
                soft_wrap=True,
            )

            # Generate config files from ansible inventory
            temp_config_file, temp_dut_config_file = generate_config_files_from_ansible(
                ansible_inventory,
                baseboard,
                catalog_source,
                resolve_addon_dns=not dry_run,
            )
            # Generated inventories contain cleartext credentials. Own them as
            # soon as both paths exist so every later validation/parse exit is
            # covered, even before CLICollector registers terminal cleanup.
            ctx.call_on_close(cleanup_generated_ansible_configs_on_context_close)

            # The generated tool config is only a fallback. Keep an explicit
            # or environment-selected tool config at its normal precedence.
            if not user_selected_tool_config:
                config_file = temp_config_file
            dut_config = temp_dut_config_file

            sanitized_console.print_info(
                f"Generated config files from ansible inventory: {temp_config_file}, {temp_dut_config_file}"
            )

        except Exception as e:
            _present_cli_failure(
                f"Error parsing Ansible inventory file: {e}",
                title="Ansible Inventory Error",
                suggestions=(
                    "Correct the inventory syntax or unsupported fields and retry.",
                    "Run 'nvdebug collect --help' to review alternative target sources.",
                ),
            )
            sys.exit(1)

    # Resolve config paths (auto-detect if not explicitly provided)
    config_file, dut_config = _resolve_config_paths(
        config_file, dut_config, sanitized_console, local_mode=local
    )

    # Shared targetless-usage diagnostics. The actual "no target" check is
    # performed after the tool config is loaded (below) so that a tool config
    # selecting `local` is honored before we treat the invocation as targetless.
    no_target_message = (
        "No DUT target or configuration found. Please provide one of:\n"
        "  * --dut-config <file>\n"
        "  * --local\n"
        "  * CLI credentials (--bmc-ip, --host-ip, etc.)\n\n"
        f"{CONFIG_DISCOVERY_TRUST_HELP}"
    )
    auto_discovered_dut_config = (
        original_dut_config is None
        and ansible_inventory is None
        and not os.environ.get("NVDEBUG_DUT_CONFIG", "").strip()
        and dut_config is not None
    )

    # Load tool config once (applies to all modes)
    try:
        config_file_data = _load_tool_config(config_file, sanitized_console)
    except ToolConfigLoadError as e:
        if temp_config_file and temp_dut_config_file:
            try:
                cleanup_generated_ansible_configs()
            except Exception as cleanup_e:
                sanitized_console.print_warning(
                    f"Warning: Could not clean up temporary config files: {cleanup_e}"
                )
        _present_cli_failure(
            f"Invalid tool_config '{config_file}': {e}",
            title="Tool Configuration Error",
            suggestions=(
                "Correct the reported YAML or configuration field and retry.",
                "Run with a known-good --config file to isolate the invalid setting.",
            ),
        )
        raise typer.Exit(code=2) from e

    output_config = _get_config_value(config_file_data, "output", None)
    configured_create_zip_is_explicit = _config_key_was_explicit(
        output_config, "create_zip"
    )
    if (
        streaming_only
        and configured_create_zip_is_explicit
        and bool(_get_config_value(output_config, "create_zip", True))
    ):
        _present_cli_failure(
            "Error: streaming via --stream-destination cannot be combined with "
            "an explicit output.create_zip: true configuration. Set "
            "output.create_zip to false or omit it so streaming can disable "
            "archiving safely.",
            title="Streaming Options Conflict",
        )
        raise typer.Exit(code=2)

    _apply_redfish_limit_cli_overrides(
        config_file_data,
        explicit_cli_params=explicit_cli_params,
        values={
            "redfish_structured_response_max_bytes": (
                redfish_structured_response_max_bytes
            ),
            "redfish_attachment_max_bytes": redfish_attachment_max_bytes,
            "redfish_error_response_max_bytes": redfish_error_response_max_bytes,
            "redfish_error_evidence_max_bytes": redfish_error_evidence_max_bytes,
            "redfish_error_evidence_aggregate_max_bytes": (
                redfish_error_evidence_aggregate_max_bytes
            ),
            "redfish_error_evidence_max_responses": (
                redfish_error_evidence_max_responses
            ),
            "redfish_preflight_response_max_bytes": (
                redfish_preflight_response_max_bytes
            ),
            "redfish_cache_max_bytes": redfish_cache_max_bytes,
            "redfish_cache_entry_max_bytes": redfish_cache_entry_max_bytes,
        },
    )
    defaults = _extract_tool_defaults(
        config_file_data,
        output_dir,
        cli_output_explicit="output_dir" in explicit_cli_params,
    )
    tool_config_baseboard = defaults["tool_config_baseboard"]
    environment_baseboard = defaults.get("environment_baseboard")
    final_output_dir = defaults["final_output_dir"]
    config_generate_html_reports = defaults["config_generate_html_reports"]
    config_log_sanitization = defaults["config_log_sanitization"]
    max_concurrent_duts = defaults["max_concurrent_duts"]
    max_concurrent_collectors_per_dut = defaults["max_concurrent_collectors_per_dut"]
    final_concurrency_mode = (
        str(concurrency_mode or "").strip().lower()
        if "concurrency_mode" in explicit_cli_params
        else str(defaults["concurrency_mode"] or "conservative").strip().lower()
    )
    if final_concurrency_mode not in {"conservative", "fixed", "adaptive"}:
        _present_cli_failure(
            "Invalid --concurrency-mode value "
            f"'{final_concurrency_mode}'. Expected conservative, fixed, or adaptive.",
            title="Invalid Execution Configuration",
        )
        raise typer.Exit(code=2)
    final_initial_io_oversubscription = (
        initial_io_oversubscription
        if "initial_io_oversubscription" in explicit_cli_params
        else defaults["initial_io_oversubscription"]
    )
    final_minimum_collector_operations = (
        minimum_collector_operations
        if "minimum_collector_operations" in explicit_cli_params
        else defaults["minimum_collector_operations"]
    )
    final_maximum_collector_operations = (
        maximum_collector_operations
        if "maximum_collector_operations" in explicit_cli_params
        else defaults["maximum_collector_operations"]
    )
    if (
        final_concurrency_mode == "adaptive"
        and final_maximum_collector_operations is None
    ):
        _present_cli_failure(
            "execution.maximum_collector_operations is required in adaptive mode.",
            title="Invalid Execution Configuration",
        )
        raise typer.Exit(code=2)
    if (
        final_maximum_collector_operations is not None
        and final_minimum_collector_operations > final_maximum_collector_operations
    ):
        _present_cli_failure(
            "execution.minimum_collector_operations cannot exceed "
            "maximum_collector_operations.",
            title="Invalid Execution Configuration",
        )
        raise typer.Exit(code=2)
    adaptive_concurrency = defaults["adaptive_concurrency"]
    timeout = defaults["timeout"]
    retry_count = defaults["retry_count"]
    config_skip_zip = defaults["config_skip_zip"]
    config_skip_zip_split = defaults["config_skip_zip_split"]
    config_zip_split_threshold = defaults["config_zip_split_threshold"]
    config_log_level = defaults["config_log_level"]
    config_log_format = defaults["config_log_format"]
    config_execution_scheduler = defaults["execution_scheduler"]
    if "execution_scheduler" in explicit_cli_params:
        final_execution_scheduler = str(execution_scheduler or "").strip().lower()
    else:
        final_execution_scheduler = (
            str(config_execution_scheduler or "per_dut").strip().lower()
        )
    if final_execution_scheduler not in {"per_dut", "legacy_global"}:
        _present_cli_failure(
            "Invalid --execution-scheduler value "
            f"'{final_execution_scheduler}'. Expected 'per_dut' or 'legacy_global'.",
            title="Invalid Execution Configuration",
        )
        raise typer.Exit(code=2)

    if "report_format" in explicit_cli_params:
        report_format = str(report_format or "").strip().lower()
    else:
        report_format = str(report_format or "spa").strip().lower()
    if report_format not in {"legacy", "spa", "both"}:
        _present_cli_failure(
            "Invalid --report-format value "
            f"'{report_format}'. Expected 'legacy', 'spa', or 'both'.",
            title="Invalid Report Configuration",
        )
        raise typer.Exit(code=2)
    parallel_dut_sequential_collectors = defaults["parallel_dut_sequential_collectors"]
    service_grouped_sequential_collectors = defaults[
        "service_grouped_sequential_collectors"
    ]
    if hasattr(config_file_data, "__dict__"):
        config_file_data.LogSanitization = config_log_sanitization

    tool_yaml_fields = getattr(config_file_data, "_yaml_fields", None)
    tool_local_explicit = (
        "local" in tool_yaml_fields
        if tool_yaml_fields is not None
        else _config_key_was_explicit(config_file_data, "local")
    )
    if (
        "local" not in explicit_cli_params
        and not has_cli_credentials
        and tool_local_explicit
    ):
        local = bool(_get_config_value(config_file_data, "local", False))

    if not dut_config and not has_cli_credentials and not local:
        _present_cli_failure(
            no_target_message
            + config_discovery_failure_details(
                include_tool=not user_selected_tool_config
            ),
            title="Missing Collection Target",
            suggestions=(
                "Provide --dut-config, --local, --ansible-inventory, or direct target options.",
                "Run 'nvdebug collect --help' for target examples.",
            ),
        )
        raise typer.Exit(code=2)

    # Apply the explicit CLI trust override to redfish_session_config.
    if redfish_tls_cli_explicit:
        cli_tls_mode = "system_ca" if ssl_verify else "insecure"
        if not ssl_verify and not insecure_cli_explicit:
            sanitized_console.print_warning(
                "SECURITY WARNING: --no-ssl-verify disables Redfish server "
                "authentication and permits man-in-the-middle attacks."
            )
        if isinstance(config_file_data, dict):
            rsc = config_file_data.setdefault("redfish_session_config", {})
            rsc["ssl_verify"] = ssl_verify
            rsc["tls_mode"] = cli_tls_mode
        elif hasattr(config_file_data, "redfish_session_config"):
            rsc = config_file_data.redfish_session_config
            if rsc is None:
                rsc = {}
                config_file_data.redfish_session_config = rsc
            if isinstance(rsc, dict):
                rsc["ssl_verify"] = ssl_verify
                rsc["tls_mode"] = cli_tls_mode
            else:
                rsc_values = rsc.model_dump()
                for field_name in RedfishResponseLimits.model_fields:
                    if field_name in rsc.model_fields_set:
                        rsc_values[field_name] = getattr(rsc, field_name)
                config_file_data.redfish_session_config = type(rsc).model_validate(
                    {
                        **rsc_values,
                        "ssl_verify": ssl_verify,
                        "tls_mode": cli_tls_mode,
                    }
                )

    cli_ssh_host_key_policy: Optional[str] = None
    if "ssh_host_key_policy" in explicit_cli_params:
        cli_ssh_host_key_policy = str(ssh_host_key_policy or "").strip().lower()
        if cli_ssh_host_key_policy not in {"strict", "insecure"}:
            _present_cli_failure(
                "Invalid --ssh-host-key-policy value "
                f"'{ssh_host_key_policy}'. Expected 'strict' or 'insecure'.",
                title="Invalid SSH Trust Configuration",
            )
            raise typer.Exit(code=2)

    cli_ssh_known_hosts_file = (
        str(ssh_known_hosts_file)
        if "ssh_known_hosts_file" in explicit_cli_params
        and ssh_known_hosts_file is not None
        else None
    )
    cli_ssh_host_key_policy = _reject_incoherent_ssh_trust_selection(
        explicit_cli_params,
        cli_ssh_host_key_policy,
        cli_ssh_known_hosts_file,
        report_error=_present_cli_failure,
        report_notice=sanitized_console.print_warning,
    )
    if isinstance(config_file_data, dict):
        if cli_ssh_host_key_policy is not None:
            config_file_data["ssh_host_key_policy"] = cli_ssh_host_key_policy
        if cli_ssh_known_hosts_file is not None:
            config_file_data["ssh_known_hosts_file"] = cli_ssh_known_hosts_file
    else:
        if cli_ssh_host_key_policy is not None:
            config_file_data.ssh_host_key_policy = cli_ssh_host_key_policy
        if cli_ssh_known_hosts_file is not None:
            config_file_data.ssh_known_hosts_file = cli_ssh_known_hosts_file

    tool_non_interactive_explicit = _config_key_was_explicit(
        config_file_data, "non_interactive"
    )
    if "non_interactive" not in explicit_cli_params and tool_non_interactive_explicit:
        non_interactive = bool(
            _get_config_value(config_file_data, "non_interactive", False)
        )

    # Determine if we're in single DUT CLI mode or multi-DUT config mode.
    # Precedence rule: CLI > dut_config > defaults. A DUT config selected by
    # --dut-config or NVDEBUG_DUT_CONFIG routes through the YAML path; CLI
    # flags then merge as per-DUT overrides (see per_dut_overrides block
    # below). CLI mode (building a DUTConfig entirely from CLI args) is
    # reserved for when the user did not select a DUT config.
    # Auto-detected dut_configs (picked up by _resolve_config_paths) do not
    # block CLI mode; user-selected CLI and environment locators do.
    cli_mode = (
        (has_cli_credentials or local)
        and not original_dut_config
        and not environment_dut_locator_selected
    )
    if dut_name_explicit and not cli_mode:
        _present_cli_failure(
            "Error: --dut-name requires a direct CLI target "
            "(--bmc-ip, --host-ip, or --hmc-ip) or --local.",
            title="Conflicting DUT Options",
        )
        raise typer.Exit(code=2)

    prompted_secrets = _prompt_for_unresolved_cli_secrets(
        {
            "bmc_ip": bmc_ip if cli_mode and not dry_run else None,
            "bmc_user": bmc_user,
            "bmc_pass": bmc_pass,
            "bmc_ssh_user": bmc_ssh_user,
            "bmc_ssh_pass": bmc_ssh_pass,
            "bmc_ssh_key_path": bmc_ssh_key_path,
            "bmc_ssh_passwordless": bmc_ssh_passwordless,
            "bmc_rf_user": bmc_rf_user,
            "bmc_rf_pass": bmc_rf_pass,
            "host_ip": host_ip if cli_mode and not dry_run else None,
            "host_user": host_user,
            "host_pass": host_pass,
            "host_ssh_key_path": host_ssh_key_path,
            "host_ssh_passwordless": host_ssh_passwordless,
            "hmc_ip": hmc_ip if cli_mode and not dry_run else None,
            "hmc_user": hmc_user,
            "hmc_pass": hmc_pass,
            "hmc_ssh_user": hmc_ssh_user,
            "hmc_ssh_pass": hmc_ssh_pass,
            "hmc_ssh_key_path": hmc_ssh_key_path,
            "hmc_ssh_passwordless": hmc_ssh_passwordless,
            "ssh_proxy_host": (
                ssh_proxy_host
                if cli_mode and has_cli_credentials and not dry_run
                else None
            ),
            "ssh_proxy_user": ssh_proxy_user,
            "ssh_proxy_pass": ssh_proxy_pass,
            "ssh_proxy_key_path": ssh_proxy_key_path,
            "ssh_proxy_passwordless": ssh_proxy_passwordless,
        },
        non_interactive=non_interactive,
    )
    bmc_pass = prompted_secrets["bmc_pass"]
    bmc_ssh_pass = prompted_secrets["bmc_ssh_pass"]
    bmc_rf_pass = prompted_secrets["bmc_rf_pass"]
    host_pass = prompted_secrets["host_pass"]
    hmc_pass = prompted_secrets["hmc_pass"]
    hmc_ssh_pass = prompted_secrets["hmc_ssh_pass"]
    ssh_proxy_pass = prompted_secrets["ssh_proxy_pass"]

    # Keep prompted secrets in local memory only. This mapping is passed to
    # validation and never serialized or exported to child environments.
    cli_credentials = {
        "bmc_ip": bmc_ip,
        "bmc_user": bmc_user,
        "bmc_pass": bmc_pass,
        "bmc_ssh_user": bmc_ssh_user,
        "bmc_ssh_pass": bmc_ssh_pass,
        "bmc_ssh_key_path": bmc_ssh_key_path,
        "bmc_ssh_passwordless": bmc_ssh_passwordless,
        "bmc_rf_user": bmc_rf_user,
        "bmc_rf_pass": bmc_rf_pass,
        "host_ip": host_ip,
        "host_user": host_user,
        "host_pass": host_pass,
        "host_ssh_key_path": host_ssh_key_path,
        "host_ssh_passwordless": host_ssh_passwordless,
        "hmc_ip": hmc_ip,
        "hmc_user": hmc_user,
        "hmc_pass": hmc_pass,
        "hmc_ssh_user": hmc_ssh_user,
        "hmc_ssh_pass": hmc_ssh_pass,
        "hmc_ssh_key_path": hmc_ssh_key_path,
        "hmc_ssh_passwordless": hmc_ssh_passwordless,
    }

    skip_validation = _resolve_configured_skip_validation(
        config_file_data,
        skip_validation,
        explicit_cli_params,
    )

    if auto_discovered_dut_config and not has_cli_credentials and not local:
        # The shipped defaults-only placeholder is discoverable but is not a
        # target. Preserve normal loader diagnostics for malformed files.
        try:
            _load_dut_defaults_from_yaml(dut_config)
            discovered_duts = load_dut_config(dut_config, quiet_mode=True)
        except Exception:
            discovered_duts = None
        if discovered_duts == []:
            _present_cli_failure(
                no_target_message
                + config_discovery_failure_details(
                    include_tool=not user_selected_tool_config
                ),
                title="Missing Collection Target",
                suggestions=(
                    "Add at least one DUT to the selected DUT config.",
                    "Or provide --local, --ansible-inventory, or direct target options.",
                ),
            )
            raise typer.Exit(code=2)

    # Run early validation only for collection level (other validation happens after auto-detection)
    if not skip_validation and collection_level is not None:
        is_valid, collection_errors = validate_collection_level(collection_level)
        if not is_valid:
            display_validation_errors(collection_errors)
            raise typer.Exit(code=2)

    # Handle CLI vs config file precedence
    if cli_mode:
        # Honor DUT_Defaults from an auto-detected dut_config.yaml when the
        # user didn't pass --dut-config explicitly. Without this, fields like
        # `baseboard` set in that file's DUT_Defaults would be silently
        # ignored even though the same file is archived into the output dir.
        auto_dut_defaults = (
            _load_dut_defaults_from_yaml(dut_config)
            if dut_config and not original_dut_config
            else {}
        )
        dut_configs = _build_cli_dut_config(
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
            dut_defaults=auto_dut_defaults,
            dut_name=dut_name,
        )
        if redfish_tls_cli_explicit:
            dut_configs[0].bmc_rf_tls_mode = "system_ca" if ssl_verify else "insecure"
            dut_configs[0].bmc_rf_verify_ssl = bool(ssl_verify)
        if cli_ssh_host_key_policy is not None:
            dut_configs[0].ssh_host_key_policy = cli_ssh_host_key_policy
        if cli_ssh_known_hosts_file is not None:
            dut_configs[0].ssh_known_hosts_file = cli_ssh_known_hosts_file
    else:
        # Multi-DUT config mode (dut_config already resolved by _resolve_config_paths)
        # Load DUT configs (auto-assign, load, baseboard override, non_interactive)
        original_dut_config = dut_config
        dut_configs, resolved_dut_config = _load_config_mode_duts(
            dut_config,
            config_file,
            baseboard,
            non_interactive,
            sanitized_console,
            non_interactive_cli_explicit=("non_interactive" in explicit_cli_params),
            non_interactive_tool_explicit=tool_non_interactive_explicit,
        )

        local_cli_explicit = "local" in explicit_cli_params
        for dut in dut_configs:
            dut_fields = getattr(dut, "model_fields_set", set())
            if local_cli_explicit or (
                tool_local_explicit
                and "local" not in dut_fields
                and "ExecutionMode" not in dut_fields
            ):
                dut.local = local
                dut.ExecutionMode = "Local" if local else "REMOTE"
            if redfish_tls_cli_explicit:
                dut.bmc_rf_tls_mode = "system_ca" if ssl_verify else "insecure"
                dut.bmc_rf_verify_ssl = bool(ssl_verify)

        # Global overrides apply to every DUT; endpoint overrides require one DUT.
        try:
            global_overrides = {}
            # Validate CLI trust winners with the remaining overrides so legacy
            # tunnel options cannot reintroduce the policy or path they replaced.
            if cli_ssh_host_key_policy is not None:
                global_overrides["ssh_host_key_policy"] = cli_ssh_host_key_policy
            if cli_ssh_known_hosts_file is not None:
                global_overrides["ssh_known_hosts_file"] = cli_ssh_known_hosts_file
            if ssh_proxy_host:
                global_overrides["ssh_proxy_host"] = ssh_proxy_host
            if "ssh_proxy_port" in explicit_cli_params:
                global_overrides["ssh_proxy_port"] = ssh_proxy_port
            if ssh_proxy_user:
                global_overrides["ssh_proxy_user"] = ssh_proxy_user
            if ssh_proxy_pass:
                global_overrides["ssh_proxy_pass"] = ssh_proxy_pass
            if ssh_proxy_key_path:
                global_overrides["ssh_proxy_key_path"] = ssh_proxy_key_path
            if "ssh_proxy_passwordless" in explicit_cli_params:
                global_overrides["ssh_proxy_passwordless"] = ssh_proxy_passwordless
            if "ssh_proxy_max_retries" in explicit_cli_params:
                global_overrides["ssh_proxy_max_retries"] = ssh_proxy_max_retries

            # Per-DUT overrides (apply only to single DUT if only one DUT exists)
            per_dut_overrides = {}
            if bmc_ip:
                per_dut_overrides["bmc_ip"] = bmc_ip
                per_dut_overrides["BMC_IP"] = (
                    bmc_ip  # Ensure legacy field matches CLI override
                )
            if bmc_user:
                per_dut_overrides["bmc_user"] = bmc_user
            if bmc_pass:
                per_dut_overrides["bmc_pass"] = bmc_pass
            if bmc_ssh_user:
                per_dut_overrides["bmc_ssh_user"] = bmc_ssh_user
            if bmc_ssh_pass:
                per_dut_overrides["bmc_ssh_pass"] = bmc_ssh_pass
            if bmc_ssh_port:
                per_dut_overrides["bmc_ssh_port"] = bmc_ssh_port
            if bmc_ssh_key_path:
                per_dut_overrides["bmc_ssh_key_path"] = bmc_ssh_key_path
            if "bmc_ssh_passwordless" in explicit_cli_params:
                per_dut_overrides["bmc_ssh_passwordless"] = bmc_ssh_passwordless
            if "bmc_ssh_max_retries" in explicit_cli_params:
                per_dut_overrides["bmc_ssh_max_retries"] = bmc_ssh_max_retries
            if bmc_rf_user:
                per_dut_overrides["bmc_rf_user"] = bmc_rf_user
            if bmc_rf_pass:
                per_dut_overrides["bmc_rf_pass"] = bmc_rf_pass
            if bmc_rf_port:
                per_dut_overrides["bmc_rf_port"] = bmc_rf_port

            if host_ip:
                per_dut_overrides["host_ip"] = host_ip
            if host_user:
                per_dut_overrides["host_user"] = host_user
            if host_pass:
                per_dut_overrides["host_pass"] = host_pass
            if host_ssh_port:
                per_dut_overrides["host_ssh_port"] = host_ssh_port
            if host_ssh_key_path:
                per_dut_overrides["host_ssh_key_path"] = host_ssh_key_path
            if "host_ssh_passwordless" in explicit_cli_params:
                per_dut_overrides["host_ssh_passwordless"] = host_ssh_passwordless
            if "host_ssh_max_retries" in explicit_cli_params:
                per_dut_overrides["host_ssh_max_retries"] = host_ssh_max_retries

            if hmc_ip:
                per_dut_overrides["hmc_ip"] = hmc_ip
                # Also set legacy/uppercase key so DUTManager consumes it
                per_dut_overrides["HMC_IP"] = hmc_ip
            if hmc_user:
                per_dut_overrides["hmc_user"] = hmc_user
            if hmc_pass:
                per_dut_overrides["hmc_pass"] = hmc_pass
            if hmc_ssh_user:
                per_dut_overrides["hmc_ssh_user"] = hmc_ssh_user
            if hmc_ssh_pass:
                per_dut_overrides["hmc_ssh_pass"] = hmc_ssh_pass
            if hmc_ssh_port:
                per_dut_overrides["hmc_ssh_port"] = hmc_ssh_port
            if hmc_ssh_key_path:
                per_dut_overrides["hmc_ssh_key_path"] = hmc_ssh_key_path
            if "hmc_ssh_passwordless" in explicit_cli_params:
                per_dut_overrides["hmc_ssh_passwordless"] = hmc_ssh_passwordless
            if "hmc_ssh_max_retries" in explicit_cli_params:
                per_dut_overrides["hmc_ssh_max_retries"] = hmc_ssh_max_retries
            if "hmc_http_port" in explicit_cli_params:
                per_dut_overrides["hmc_http_port"] = hmc_http_port
            if "hmc_https_port" in explicit_cli_params:
                per_dut_overrides["hmc_https_port"] = hmc_https_port
            if "hmc_use_https" in explicit_cli_params:
                per_dut_overrides["hmc_use_https"] = hmc_use_https
            if hmc_access_method:
                per_dut_overrides["hmc_access_method"] = hmc_access_method
            if "use_port_forwarding" in explicit_cli_params:
                per_dut_overrides["use_port_forwarding"] = use_port_forwarding
            if tunnel_tcp_port is not None:
                per_dut_overrides["tunnel_tcp_port"] = tunnel_tcp_port
            if "setup_port_forwarding" in explicit_cli_params:
                per_dut_overrides["setup_port_forwarding"] = (
                    setup_port_forwarding
                    if setup_port_forwarding is not None
                    else False
                )
            if "force_port_fw" in explicit_cli_params:
                per_dut_overrides["force_port_fw"] = (
                    force_port_fw if force_port_fw is not None else False
                )
            if rf_hmc_prefix is not None:
                per_dut_overrides["RF_HMC_DEFAULT_PREFIX"] = rf_hmc_prefix
            if rf_bmc_prefix is not None:
                per_dut_overrides["RF_DEFAULT_PREFIX"] = rf_bmc_prefix
            if "expand_fallback_mode" in explicit_cli_params:
                per_dut_overrides["EXPAND_FALLBACK_MODE"] = expand_fallback_mode
            if "expand_level" in explicit_cli_params:
                for key in (
                    "EXPAND_QUERY_CHASSIS_LEVEL",
                    "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL",
                    "EXPAND_QUERY_MANAGER_LEVEL",
                    "EXPAND_QUERY_SYSTEM_LEVEL",
                ):
                    per_dut_overrides[key] = expand_level

            # Per-DUT credential overrides (bmc, host, hmc, Redfish) are ambiguous with
            # multiple DUTs — reject those only. Tool-level flags (-o, -z, -VV, etc.) are
            # applied later via ToolConfig and are always allowed.
            if len(dut_configs) > 1 and per_dut_overrides:
                _present_cli_failure(
                    "The DUT config file defines more than one DUT, so per-DUT "
                    "CLI credentials or connection overrides are not allowed "
                    "because their target would be ambiguous.",
                    title="Conflicting DUT Options",
                    suggestions=(
                        "Remove --bmc-ip, --host-ip, --hmc-ip, credentials, and Redfish prefix overrides.",
                        "Configure those values on each DUT, or select a single-DUT config before applying CLI overrides.",
                        "Tool-level options such as -o, -z, -VV, and --spreadsheet remain valid.",
                    ),
                )
                raise typer.Exit(code=2)

            # Validate all winners together so a global proxy override cannot
            # revalidate TLS policy before the matching per-DUT HMC protocol.
            for index, dut in enumerate(dut_configs):
                resolved_overrides = dict(global_overrides)
                if len(dut_configs) == 1:
                    resolved_overrides.update(per_dut_overrides)
                if resolved_overrides:
                    dut_configs[index] = dut.with_cli_overrides(resolved_overrides)
            if len(dut_configs) == 1 and per_dut_overrides:
                hmc_transport_fields = {
                    "hmc_http_port",
                    "hmc_https_port",
                    "hmc_use_https",
                }
                if hmc_transport_fields & explicit_cli_params:
                    resolved_dut = dut_configs[0]
                    resolved_dut.HMC_HTTP_PORT = resolved_dut.hmc_http_port
                    resolved_dut.HMC_HTTPS_PORT = resolved_dut.hmc_https_port
                    resolved_dut.HMC_USE_HTTPS = resolved_dut.hmc_use_https
                    resolved_dut.HMC_RF_PROTOCOL = (
                        "https" if resolved_dut.hmc_use_https else "http"
                    )
                    resolved_dut.HMC_TCP_PORT = (
                        resolved_dut.hmc_https_port
                        if resolved_dut.hmc_use_https
                        else resolved_dut.hmc_http_port
                    )

            # Clean up temporary file if it was created by auto-assignment
            if (
                "temp_" in str(resolved_dut_config)
                and resolved_dut_config != original_dut_config
            ):
                try:
                    resolved_dut_config.unlink()
                    sanitized_console.print_info("Cleaned up temporary DUT config file")
                except Exception as e:
                    sanitized_console.print_warning(
                        f"Could not clean up temporary file: {e}"
                    )

        except typer.Exit:
            raise
        except Exception as e:
            # Use pretty formatted error display for better user experience
            display_dut_config_error(str(e))
            sys.exit(1)

    _project_legacy_tool_ipmi_cipher(config_file_data, dut_configs)

    project_tool_ssh_proxy_defaults(
        config_file_data,
        dut_configs,
        explicit_cli_params,
        cli_mode=cli_mode,
    )

    # Determine final collection level (config file default, CLI override)
    config_collection_level = getattr(config_file_data, "collection_level", "L1")
    # Use CLI level if it was determined earlier, otherwise use config file
    if final_collection_level is None:
        final_collection_level = config_collection_level

    # Convert enum to string if needed
    if hasattr(final_collection_level, "value"):
        final_collection_level = final_collection_level.value

    debug = _resolve_configured_debug(
        config_file_data,
        debug,
        explicit_cli_params,
    )

    # Validate --expand-fallback-mode up front so a typo fails loudly rather
    # than silently falling back to "auto" inside RedfishService.
    if expand_fallback_mode is not None:
        mode_norm = expand_fallback_mode.strip().lower()
        if mode_norm not in ("auto", "never", "always"):
            _present_cli_failure(
                f"Invalid --expand-fallback-mode '{expand_fallback_mode}'. "
                "Must be one of: auto, never, always.",
                title="Invalid Redfish Expansion Configuration",
            )
            raise typer.Exit(code=2)
        expand_fallback_mode = mode_norm
    if expand_level is not None and expand_level < 1:
        _present_cli_failure(
            f"--expand-level must be >= 1 (got {expand_level}).",
            title="Invalid Redfish Expansion Configuration",
        )
        raise typer.Exit(code=2)

    if rack_id is not None:
        try:
            rack_id = require_safe_artifact_component(rack_id, "rack ID")
        except ValueError as exc:
            _present_cli_failure(
                str(exc),
                title="Invalid Rack Identifier",
            )
            raise typer.Exit(code=2) from exc

    # Now create the ToolConfig after all config file loading and output directory logic
    tool_config = build_tool_config(
        config_file_data,
        final_output_dir=final_output_dir,
        final_collection_level=final_collection_level,
        tool_config_baseboard=tool_config_baseboard,
        environment_baseboard=environment_baseboard,
        concurrency_mode=final_concurrency_mode,
        initial_io_oversubscription=final_initial_io_oversubscription,
        minimum_collector_operations=final_minimum_collector_operations,
        maximum_collector_operations=final_maximum_collector_operations,
        adaptive_concurrency=adaptive_concurrency,
        max_concurrent_duts=max_concurrent_duts,
        max_concurrent_collectors_per_dut=max_concurrent_collectors_per_dut,
        timeout=timeout,
        retry_count=retry_count,
        config_skip_zip=config_skip_zip,
        config_skip_zip_split=config_skip_zip_split,
        config_zip_split_threshold=config_zip_split_threshold,
        config_log_level=config_log_level,
        config_log_format=config_log_format,
        config_log_sanitization=config_log_sanitization,
        config_generate_html_reports=config_generate_html_reports,
        execution_scheduler=final_execution_scheduler,
        parallel_dut_sequential_collectors=parallel_dut_sequential_collectors,
        service_grouped_sequential_collectors=service_grouped_sequential_collectors,
        skip_zip=skip_zip,
        skip_zip_split=skip_zip_split,
        zip_split_threshold=zip_split_threshold,
        skip_sanitization=skip_sanitization,
        apply_sanitization=apply_sanitization,
        skip_html_reports=skip_html_reports,
        report_format=report_format,
        collector_id=collector_id,
        collector_group=collector_group,
        skip_collectors=skip_collectors,
        include_collectors=include_collectors,
        spreadsheet=spreadsheet,
        debug=debug,
        verbose=verbose,
        dry_run=dry_run,
        skip_preflight=skip_preflight,
        streaming_only=streaming_only,
        stream_begin=stream_begin,
        stream_end=stream_end,
        stream_destination=(str(stream_destination) if stream_destination else None),
        append=append,
        rack_id=rack_id,
        cli_expand_fallback_mode=expand_fallback_mode,
        cli_expand_level=expand_level,
        explicit_cli_params=explicit_cli_params,
    )

    if tool_config.apply_sanitization and tool_config.skip_sanitization:
        _present_cli_failure(
            "--apply-sanitization cannot be combined with --skip-sanitization",
            title="Conflicting Sanitization Options",
        )
        raise typer.Exit(code=2)

    if (
        environment_baseboard
        and not tool_config_baseboard
        and any(
            not dut.baseboard
            and (cli_mode or "baseboard" not in getattr(dut, "model_fields_set", set()))
            for dut in dut_configs
        )
        and not validate_baseboard(environment_baseboard, catalog_source)
    ):
        _present_cli_failure(
            f"Invalid BASEBOARD environment fallback '{environment_baseboard}': "
            "the value is not present in the selected spreadsheet catalog.",
            title="Invalid Baseboard Configuration",
            suggestions=(
                "Set BASEBOARD to a platform present in the selected Telemetry Catalog.",
                "Remove BASEBOARD to allow catalog-assisted platform detection.",
            ),
        )
        raise typer.Exit(code=2)

    # Resolve source config paths for archiving (best-effort)
    source_tool_config_path, source_dut_config_path = _resolve_source_config_paths(
        config_file, original_dut_config, dut_config
    )

    cli_collector = CLICollector(
        tool_config,
        dut_configs,
        source_tool_config=source_tool_config_path,
        source_dut_config=source_dut_config_path,
        enable_status_tracking=enable_status_tracking,
        disable_live_display=disable_live_display,
        skip_validation=skip_validation,
        pre_terminal_cleanup=cleanup_generated_ansible_configs,
        catalog_snapshot=catalog_snapshot,
    )

    # Run comprehensive validation after CLI collector creation (we now have access to loaded DUT configs)
    if not skip_validation:
        validation_output_dir = Path(
            tool_config.stream_destination
            if tool_config.streaming_only and tool_config.stream_destination
            else tool_config.output_directory
        )
        if tool_config.rack_id is not None:
            # Recheck programmatic ToolConfig instances before joining the same
            # leaf used at runtime; CLI values were already checked earlier.
            validation_output_dir /= _require_safe_rack_id(tool_config.rack_id)
        timestamped_output_namespace = bool(
            not getattr(tool_config, "streaming_only", False)
            and not getattr(tool_config, "append", False)
        )
        # Validate credentials and configuration for both CLI mode and DUT config mode
        # Pass the loaded DUT configs for validation so it can see the actual connection details
        is_valid, validation_errors = run_comprehensive_validation(
            dut_config=dut_configs,  # Pass the loaded DUT configs, not the file path
            local=local,
            cli_credentials=cli_credentials,
            collector_ids=collector_id,
            collector_groups=collector_group,
            collection_level=final_collection_level,
            output_dir=validation_output_dir,
            config_manager=None,  # Will be validated later when config manager is available
            ansible_inventory=ansible_inventory,
            cli_mode=cli_mode,  # In CLI mode require complete credentials and exit on error
            output_shared_read=not tool_config.skip_sanitization,
            output_repair_existing_permissions=timestamped_output_namespace,
            output_allow_sticky_run_parent=timestamped_output_namespace,
            # Every resolved collection destination uses the same mixed-owner
            # policy, regardless of CLI, config, environment, or default source.
            output_allow_external_path_owners=True,
        )

        if not is_valid:
            display_validation_errors(validation_errors)
            sys.exit(1)

    # Run collector-specific validation after CLI collector is created
    if (
        collector_id
        or collector_group
        or include_collectors
        or skip_collectors
        or final_collection_level != "L1"
    ) and not skip_validation:
        _run_collector_and_level_validation(
            tool_config=tool_config,
            dut_configs=dut_configs,
            collector_id=collector_id,
            collector_group=collector_group,
            include_collectors=include_collectors,
            skip_collectors=skip_collectors,
            final_collection_level=final_collection_level,
            sanitized_console=sanitized_console,
            reported_config_errors=_reported_config_errors,
            catalog_snapshot=catalog_snapshot,
        )

    # Validate baseboard against spreadsheet
    if baseboard is not None:
        if not spreadsheet:
            _present_cli_failure(
                "Baseboard validation requires a Telemetry Catalog spreadsheet.",
                title="Telemetry Catalog Required",
                suggestions=(
                    "Provide a valid spreadsheet with --spreadsheet.",
                    "Place one supported Telemetry Catalog in the config directory for auto-detection.",
                ),
            )
            sys.exit(1)

        if not validate_baseboard(baseboard, catalog_source):
            try:
                available = get_available_baseboards(catalog_source)
                _present_cli_failure(
                    f"Invalid baseboard '{baseboard}'.",
                    title="Invalid Baseboard Configuration",
                    suggestions=(
                        f"Available baseboards: {', '.join(available)}",
                        "Run 'nvdebug list-baseboards' to inspect supported platforms.",
                    ),
                )
            except Exception as e:
                _present_cli_failure(
                    f"Error validating baseboard: {e}",
                    title="Baseboard Validation Error",
                )
            raise typer.Exit(code=2)

    # Run collection using CLI handler
    run_result: Optional[RunResult] = None

    def present_collection_outcome(
        level: str,
        message: str,
        *,
        failure_title: str = "Collection Failed",
        failure_suggestions: Sequence[str] = (
            "Preserve the local collection artifacts and failure transcript.",
            "Correct the target or runtime configuration before retrying collection.",
        ),
    ) -> None:
        """
        Render collection status without changing its exit taxonomy.

        The implementation uses ``level`` and ``message`` to render collection
        status without changing its exit taxonomy. The source value
        keeps its ownership while the normalized representation is returned
        separately.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
            failure_title: Heading used when ``level`` is ``"error"``.
            failure_suggestions: Recovery guidance shown when ``level`` is
                ``"error"``.
        """

        presenter = (
            sanitized_console.print_failure
            if level == "error"
            else getattr(sanitized_console, f"print_{level}", None)
        )
        if not callable(presenter):
            return
        try:
            if level == "error":
                presenter(
                    message,
                    title=failure_title,
                    suggestions=failure_suggestions,
                )
            else:
                presenter(message)
        except BaseException:
            pass

    try:

        try:
            returned_result = asyncio.run(cli_collector.run_collection())
            run_result = _retained_run_result(cli_collector, returned_result)
        except typer.Exit:
            raise
        except SystemExit as error:
            exit_code = _collection_system_exit_code(cli_collector, error)
            if exit_code == 130:
                sanitized_console.print_warning("\nCollection interrupted by user")
                raise typer.Exit(code=130)
            raise typer.Exit(code=exit_code) from error
        except asyncio.CancelledError:
            _raise_collection_cancellation_exit(cli_collector, sanitized_console)
        except KeyboardInterrupt:
            sanitized_console.print_warning("\nCollection interrupted by user")
            raise typer.Exit(code=130)
        except Exception as e:
            if _collection_shutdown_requested(cli_collector):
                sanitized_console.print_warning(
                    f"Finalization after interruption reported: {e}"
                )
                sanitized_console.print_warning("\nCollection interrupted by user")
                raise typer.Exit(code=130)
            raise

        sanitization_check = getattr(
            type(cli_collector), "_failed_safe_sanitization_failure", None
        )
        sanitization_failure = (
            sanitization_check(cli_collector) if callable(sanitization_check) else None
        )
        if sanitization_failure is not None:
            finalize_collection = getattr(
                type(cli_collector), "_finalize_collection_run", None
            )
            if callable(finalize_collection):
                published_failure = asyncio.run(
                    finalize_collection(
                        cli_collector,
                        start_time=None,
                        processed_cids=[],
                        results=None,
                        active_exception=None,
                        heartbeat=None,
                    )
                )
                if published_failure is not None:
                    if not isinstance(published_failure, BaseException):
                        raise TypeError(
                            "Sanitization finalizer returned a non-exception value"
                        )
                    sanitization_failure = published_failure
            raise sanitization_failure

        if _collection_shutdown_requested(cli_collector):
            sanitized_console.print_warning("\nCollection interrupted by user")
            raise typer.Exit(code=130)

        delivery_authorized = bool(
            type(run_result) is RunResult
            and _canonical_result_committed(cli_collector)
            and (
                run_result.exit_code in {0, 3}
                or (
                    run_result.exit_code == 1
                    and type(cli_collector.finalization_receipt) is FinalizationReceipt
                    and finalization_failures_allow_delivery(
                        cli_collector.finalization_receipt
                    )
                )
            )
        )
        local_archive_paths = getattr(
            getattr(cli_collector, "orchestrator", None),
            "zip_archive_path",
            None,
        )
        local_archive_published = (
            isinstance(local_archive_paths, (str, Path)) and bool(local_archive_paths)
        ) or (
            isinstance(local_archive_paths, (list, tuple)) and bool(local_archive_paths)
        )
        if (
            delivery_authorized
            and local_archive_published
            and not dry_run
            and not bool(getattr(tool_config, "skip_sanitization", False))
        ):
            archive_paths = (
                tuple(local_archive_paths)
                if isinstance(local_archive_paths, (list, tuple))
                else (local_archive_paths,)
            )
            publish_archive_artifacts_shared_read(archive_paths)
        if delivery_authorized and local_archive_published and not dry_run:
            # A local archive is a published representation. A retained loose tree may be
            # shared-readable after finalization but remains mutable, so only
            # the immutable archive receives this evidence.
            _write_delivery_evidence(
                cli_collector,
                DeliveryResult.create(DeliveryStatus.NOT_REQUESTED),
            )

        _publish_finalized_explicit_loose_output_shared_read(
            cli_collector,
            tool_config,
            delivery_authorized=delivery_authorized,
            dry_run=dry_run,
        )

        if run_result is not None:
            try:
                if (
                    run_result.runtime_status is RuntimeStatus.SUCCESS
                    and run_result.collection_status
                    in {CollectionStatus.PARTIAL, CollectionStatus.FAILED}
                ):
                    sanitized_console.print_warning(
                        "Collection completed with domain failures or partial results."
                    )
                elif run_result.exit_code == 130:
                    sanitized_console.print_warning(
                        "Collection was interrupted before completion."
                    )
                elif run_result.exit_code:
                    present_collection_outcome(
                        "error",
                        "Collection finalization did not complete successfully.",
                        failure_title="Collection Finalization Failed",
                        failure_suggestions=(
                            "Review the collection summary and verbose transcript for the underlying failure.",
                            "Correct the target or runtime configuration before retrying.",
                        ),
                    )
            except BaseException:
                # Terminal presentation never changes the committed RunResult.
                pass
            if run_result.exit_code:
                raise typer.Exit(code=run_result.exit_code)
    except typer.Exit:
        raise
    except SystemExit as error:
        raise typer.Exit(
            code=_collection_system_exit_code(cli_collector, error)
        ) from error
    except asyncio.CancelledError:
        _raise_collection_cancellation_exit(cli_collector, sanitized_console)
    except KeyboardInterrupt:
        present_collection_outcome("warning", "\nCollection interrupted by user")
        raise typer.Exit(code=130)
    except Exception as error:
        sanitized_console.print_failure(
            f"Collection failed: {error}",
            title="Collection Failed",
            suggestions=(
                "Review the failure reason and correct the target or runtime configuration.",
                "Retry with --verbose and preserve the complete transcript if the failure recurs.",
            ),
        )
        if debug:
            console.print_exception()
        sys.exit(1)
    except BaseException as grouped_error:
        error = select_authoritative_exception((grouped_error,))
        shutdown_requested = _collection_shutdown_requested(cli_collector)
        collection_interrupted = bool(
            shutdown_requested
            or (
                not isinstance(error, asyncio.CancelledError)
                and is_interruption_exception(error)
            )
        )
        if collection_interrupted:
            present_collection_outcome("warning", "\nCollection interrupted by user")
            raise typer.Exit(code=130) from error
        present_collection_outcome(
            "error",
            f"Collection terminated unexpectedly: {type(error).__name__}",
            failure_title="Collection Failed",
            failure_suggestions=(
                "Retry with --verbose and preserve the complete transcript.",
                "Check the caller or supervisor if the same termination recurs.",
            ),
        )
        raise typer.Exit(code=1) from error
    finally:
        active_boundary_error = sys.exc_info()[1]
        final_cleanup_errors: List[BaseException] = []

        # Dry-run cannot have created a tunnel. Avoid the process-wide fallback
        # used by legacy cleanup when no tracked tunnel exists.
        try:
            if (
                not dry_run
                and not _canonical_result_committed(cli_collector)
                and hasattr(cli_collector, "dut_manager")
                and cli_collector.dut_manager
            ):
                cli_collector.dut_manager.cleanup_all_ssh_proxy_tunnels_sync()
                # sanitized_console.print_info("Cleaned up SSH proxy tunnels")
            elif (
                not dry_run
                and not _canonical_result_committed(cli_collector)
                and hasattr(cli_collector, "orchestrator")
                and hasattr(cli_collector.orchestrator, "dut_manager")
                and cli_collector.orchestrator.dut_manager
            ):
                cli_collector.orchestrator.dut_manager.cleanup_all_ssh_proxy_tunnels_sync()
                # sanitized_console.print_info("Cleaned up SSH proxy tunnels")
        except BaseException as error:
            final_cleanup_errors.append(error)
            try:
                sanitized_console.print_warning(
                    f"Warning: Could not clean up SSH proxy tunnels: {error}"
                )
            except BaseException as presentation_error:
                final_cleanup_errors.append(presentation_error)

        # Clean up temporary config files if they were generated from ansible inventory
        if temp_config_file and temp_dut_config_file:
            try:
                cleanup_generated_ansible_configs()
                sanitized_console.print_info(
                    "Cleaned up temporary config files generated from ansible inventory"
                )
            except BaseException as error:
                final_cleanup_errors.append(error)
                try:
                    sanitized_console.print_warning(
                        "Warning: Could not clean up temporary config files: "
                        f"{error}"
                    )
                except BaseException as presentation_error:
                    final_cleanup_errors.append(presentation_error)

        if final_cleanup_errors:
            cleanup_error = select_authoritative_exception(final_cleanup_errors)
            active_exit_code = (
                getattr(active_boundary_error, "exit_code", None)
                if isinstance(active_boundary_error, typer.Exit)
                else None
            )
            cleanup_interrupted = is_interruption_exception(cleanup_error)
            active_interrupted = bool(
                active_exit_code == 130
                or (
                    active_boundary_error is not None
                    and is_interruption_exception(active_boundary_error)
                )
            )

            # Normalize command-boundary control before comparing cleanup
            # failures.  Click/Typer Exit is not a Python interruption type,
            # while a late SystemExit(0) would otherwise outrank the active
            # Exit(1/130) and falsely turn the command into success.
            if cleanup_interrupted or active_interrupted:
                if cleanup_interrupted and not active_interrupted:
                    present_collection_outcome(
                        "warning",
                        "\nCollection was interrupted during final cleanup.",
                    )
                if not (
                    isinstance(active_boundary_error, typer.Exit)
                    and active_exit_code == 130
                    and not cleanup_interrupted
                ):
                    raise typer.Exit(code=130) from active_boundary_error
            elif active_boundary_error is None:
                try:
                    cleanup_diagnostic = _sanitize_collection_diagnostic(
                        cli_collector,
                        cleanup_error,
                    )
                except BaseException:
                    cleanup_diagnostic = type(cleanup_error).__name__
                present_collection_outcome(
                    "error",
                    f"Collection cleanup failed: {cleanup_diagnostic}",
                    failure_title="Collection Cleanup Failed",
                    failure_suggestions=(
                        "Confirm no SSH proxy or temporary collection process remains active.",
                        "Retry with --verbose and preserve the transcript if cleanup fails again.",
                    ),
                )
                raise typer.Exit(code=1) from cleanup_error
            # A non-interrupting cleanup error is secondary to an already
            # selected command exit/failure.  Let the active exception resume.


@app.command(
    cls=_ContextualHelpCommand,
    help='Display the default log collectors for a baseboard.\n\nExamples:\n\n  nvdebug default-collectors --baseboard "GB200 NVL"',
)
def default_collectors(
    baseboard: Optional[str] = typer.Option(
        None, "--baseboard", "-b", help="Filter by baseboard"
    ),
    spreadsheet: Optional[Path] = typer.Option(
        None, "--spreadsheet", help="Collector spreadsheet path"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON to stdout"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output file path (for JSON or table format)",
    ),
) -> None:
    """
    Display the default log collectors for a baseboard.

    This command shows which collectors are configured as defaults for a
    specific baseboard platform, helping users understand what will be collected
    by default.

    Args:
        baseboard: Text supplied as baseboard in the format accepted by this
            function.
        spreadsheet: filesystem location used as the spreadsheet for this
            operation.
        json_output: Whether JSON output is enabled or required for this
            operation.
        output_file: filesystem location used as the output file for this
            operation.

    Example:
        >>> nvdebug default-collectors --baseboard "GB200 NVL"
    """

    # Auto-detect spreadsheet if not provided
    spreadsheet = auto_detect_spreadsheet(spreadsheet, suppress_print=json_output)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet, json_output=json_output)

    cli_default = CLIDefaultCollectors()
    asyncio.run(cli_default.run(baseboard, spreadsheet, json_output, output_file))


def _resolve_selected_preflight_duts(
    dut_config: Optional[Path],
    cli_values: Dict[str, object],
    explicit_cli_params: set[str],
) -> Optional[List[DUTConfig]]:
    """
    Resolve a selected DUT file and apply unambiguous CLI winners.

    Password environment variables are intentionally not CLI parameter sources.
    Returning the selected models even when there are no explicit CLI overrides
    keeps those secrets on the in-memory configuration path instead of causing
    ``CLIPreflight`` to fall back to auto-discovery.

    Args:
        dut_config: filesystem location used as the DUT config for this
            operation.
        cli_values: Mapping supplying fields for selected DUT file and apply
            unambiguous CLI winners.
        explicit_cli_params: Entries supplied as ``explicit_cli_params`` without
            transferring container ownership.

    Returns:
        The selected preflight duts returned in operation-defined order, or
        ``None`` when the requested value is unavailable.

    Raises:
        ValueError: If selected DUT configuration is unavailable; selected DUT
            configuration could not be loaded; selected DUT configuration
            defines no DUTs; or per-DUT overrides require exactly one selected
            DUT.
        BaseException: If a delegated failure occurs while the function attempts
            to resolve a selected DUT file and apply unambiguous CLI winners.
    """

    explicit_dut_fields = explicit_cli_params & _PREFLIGHT_PER_DUT_CLI_PARAMS
    environment_selected = dut_config is None
    # Preserve the established explicit-file/remote-CLI behavior: when both
    # are supplied, CLIPreflight owns that compatibility path. Partial CLI
    # overrides still belong to the selected file and must be validated here.
    direct_endpoint_selected = any(
        field in explicit_cli_params and bool(cli_values.get(field))
        for field in ("bmc_ip", "host_ip", "hmc_ip")
    )
    if not environment_selected and direct_endpoint_selected:
        return None

    selected_path = dut_config
    try:
        if selected_path is None:
            configured_path = os.environ.get("NVDEBUG_DUT_CONFIG", "").strip()
            if not configured_path:
                return None
            selected_path = Path(configured_path).expanduser()
        if not selected_path.is_file():
            raise ValueError("selected DUT configuration is unavailable")
        resolved_duts = load_dut_config(selected_path, quiet_mode=True)
    except (OSError, RuntimeError, ValueError):
        raise ValueError("selected DUT configuration could not be loaded") from None

    if not resolved_duts:
        raise ValueError("selected DUT configuration defines no DUTs")

    if not explicit_dut_fields:
        return resolved_duts
    if len(resolved_duts) != 1:
        if environment_selected and len(resolved_duts) > 1:
            raise _AmbiguousPreflightDUTScope
        raise ValueError("per-DUT overrides require exactly one selected DUT")

    explicit_overrides = {field: cli_values[field] for field in explicit_dut_fields}
    return [resolved_duts[0].with_cli_overrides(explicit_overrides)]


@app.command(
    cls=_ContextualHelpCommand,
    help="Run preflight checks only and display results in a table format.\n\n"
    "With no target options, trusted configuration files are auto-detected.\n\n"
    f"{CONFIG_DISCOVERY_TRUST_HELP}\n\n"
    "Examples:\n"
    "  nvdebug preflight --dut-config dut_config.yaml\n"
    "  nvdebug preflight --ansible-inventory inventory.yaml",
)
def preflight(
    ctx: typer.Context,
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        "-C",
        help="Configuration file path (trusted defaults are auto-detected if omitted)",
    ),
    dut_config: Optional[Path] = typer.Option(
        None,
        "--dut-config",
        "--dutconfig",
        "-d",
        help="DUT configuration file (trusted defaults are auto-detected if omitted)",
    ),
    spreadsheet: Optional[Path] = typer.Option(
        None, "--spreadsheet", help="Collector spreadsheet path"
    ),
    ansible_inventory: Optional[Path] = typer.Option(
        None,
        "--ansible-inventory",
        "--ansible_inventory",
        help="Ansible inventory file path",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON to stdout"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "-o",
        "--output",
        "--outdir",
        help="Output file path (for JSON or table format)",
    ),
    # Local Configuration
    local: bool = typer.Option(False, "--local", help="Run in local mode"),
    # BMC Configuration
    bmc_ip: Optional[str] = typer.Option(
        None, "--bmc-ip", "--ip", "-i", help="BMC IP address"
    ),
    bmc_user: Optional[str] = typer.Option(
        None, "--bmc-user", "--user", "-u", help="BMC username"
    ),
    bmc_pass: Optional[str] = typer.Option(
        None,
        "--bmc-pass",
        "--password",
        "-p",
        envvar="NVDEBUG_BMC_PASSWORD",
        help="BMC password (DEPRECATED: visible in process arguments; prefer NVDEBUG_BMC_PASSWORD or the hidden TTY prompt)",
    ),
    bmc_ssh_user: Optional[str] = typer.Option(
        None, "--bmc-ssh-user", "--sshuser", "-r", help="BMC SSH username"
    ),
    bmc_ssh_pass: Optional[str] = typer.Option(
        None,
        "--bmc-ssh-pass",
        "--sshpass",
        "-w",
        envvar="NVDEBUG_BMC_SSH_PASSWORD",
        help="BMC SSH password (DEPRECATED: visible in process arguments; prefer NVDEBUG_BMC_SSH_PASSWORD or the hidden TTY prompt)",
    ),
    bmc_ssh_port: Optional[int] = typer.Option(
        None, "--bmc-ssh-port", help="BMC SSH port"
    ),
    bmc_ssh_key_path: Optional[str] = typer.Option(
        None, "--bmc-ssh-key-path", help="BMC SSH key path"
    ),
    bmc_ssh_passwordless: bool = typer.Option(
        False, "--bmc-ssh-passwordless", help="Use passwordless SSH for BMC"
    ),
    bmc_ssh_max_retries: Optional[int] = typer.Option(
        3, "--bmc-ssh-max-retries", help="BMC SSH max retry attempts"
    ),
    bmc_rf_user: Optional[str] = typer.Option(
        None, "--bmc-rf-user", "--rfuser", "-R", help="Redfish username"
    ),
    bmc_rf_pass: Optional[str] = typer.Option(
        None,
        "--bmc-rf-pass",
        "--rfpass",
        "-W",
        envvar="NVDEBUG_BMC_REDFISH_PASSWORD",
        help="Redfish password (DEPRECATED: visible in process arguments; prefer NVDEBUG_BMC_REDFISH_PASSWORD or the hidden TTY prompt)",
    ),
    bmc_rf_port: Optional[int] = typer.Option(
        None, "--bmc-rf-port", help="Redfish port"
    ),
    ssl_verify: Optional[bool] = typer.Option(
        None,
        "--ssl-verify/--no-ssl-verify",
        help=(
            "Verify the Redfish TLS certificate with the system trust store. "
            "Omit to use the configured policy (default: insecure)."
        ),
    ),
    # Host Configuration
    host_ip: Optional[str] = typer.Option(
        None, "--host-ip", "--hostip", "-I", help="Host IP address"
    ),
    host_user: Optional[str] = typer.Option(
        None, "--host-user", "--hostuser", "-U", help="Host username"
    ),
    host_pass: Optional[str] = typer.Option(
        None,
        "--host-pass",
        "--hostpass",
        "-H",
        envvar="NVDEBUG_HOST_PASSWORD",
        help="Host password (DEPRECATED: visible in process arguments; prefer NVDEBUG_HOST_PASSWORD or the hidden TTY prompt)",
    ),
    host_ssh_port: Optional[int] = typer.Option(
        None, "--host-ssh-port", "--port", "-P", help="Host SSH port"
    ),
    host_ssh_key_path: Optional[str] = typer.Option(
        None, "--host-ssh-key-path", help="Host SSH key path"
    ),
    host_ssh_passwordless: bool = typer.Option(
        False, "--host-ssh-passwordless", help="Use passwordless SSH for Host"
    ),
    host_ssh_max_retries: Optional[int] = typer.Option(
        3, "--host-ssh-max-retries", help="Host SSH max retry attempts"
    ),
    # HMC Configuration
    hmc_ip: Optional[str] = typer.Option(None, "--hmc-ip", help="HMC IP address"),
    hmc_user: Optional[str] = typer.Option(None, "--hmc-user", help="HMC username"),
    hmc_pass: Optional[str] = typer.Option(
        None,
        "--hmc-pass",
        envvar="NVDEBUG_HMC_PASSWORD",
        help="HMC password (DEPRECATED: visible in process arguments; prefer NVDEBUG_HMC_PASSWORD or the hidden TTY prompt)",
    ),
    hmc_ssh_user: Optional[str] = typer.Option(
        None, "--hmc-ssh-user", help="HMC SSH username"
    ),
    hmc_ssh_pass: Optional[str] = typer.Option(
        None,
        "--hmc-ssh-pass",
        envvar="NVDEBUG_HMC_SSH_PASSWORD",
        help="HMC SSH password (DEPRECATED: visible in process arguments; prefer NVDEBUG_HMC_SSH_PASSWORD or the hidden TTY prompt)",
    ),
    hmc_ssh_port: Optional[int] = typer.Option(
        None, "--hmc-ssh-port", help="HMC SSH port"
    ),
    hmc_ssh_key_path: Optional[str] = typer.Option(
        None, "--hmc-ssh-key-path", help="HMC SSH key path"
    ),
    hmc_ssh_passwordless: bool = typer.Option(
        False, "--hmc-ssh-passwordless", help="Use passwordless SSH for HMC"
    ),
    hmc_ssh_max_retries: Optional[int] = typer.Option(
        3, "--hmc-ssh-max-retries", help="HMC SSH max retry attempts"
    ),
    hmc_http_port: Optional[int] = typer.Option(
        80, "--hmc-http-port", help="HMC HTTP port"
    ),
    hmc_https_port: Optional[int] = typer.Option(
        443, "--hmc-https-port", help="HMC HTTPS port"
    ),
    hmc_use_https: bool = typer.Option(
        False, "--hmc-use-https", help="Use HTTPS for HMC"
    ),
    # SSH Proxy Configuration
    ssh_proxy_host: Optional[str] = typer.Option(
        None, "--ssh-proxy-host", help="SSH proxy hostname or IP"
    ),
    ssh_proxy_port: Optional[int] = typer.Option(
        None, "--ssh-proxy-port", help="SSH proxy port"
    ),
    ssh_proxy_user: Optional[str] = typer.Option(
        None, "--ssh-proxy-user", help="SSH proxy username"
    ),
    ssh_proxy_pass: Optional[str] = typer.Option(
        None,
        "--ssh-proxy-pass",
        envvar="NVDEBUG_SSH_PROXY_PASSWORD",
        help="SSH proxy password (DEPRECATED: visible in process arguments; prefer NVDEBUG_SSH_PROXY_PASSWORD or the hidden TTY prompt)",
    ),
    ssh_proxy_key_path: Optional[str] = typer.Option(
        None, "--ssh-proxy-key-path", help="SSH proxy private key path"
    ),
    ssh_proxy_passwordless: bool = typer.Option(
        False,
        "--ssh-proxy-passwordless",
        help="Use passwordless SSH for proxy",
    ),
    ssh_proxy_max_retries: Optional[int] = typer.Option(
        None, "--ssh-proxy-max-retries", help="SSH proxy max retry attempts"
    ),
    ssh_host_key_policy: Optional[str] = typer.Option(
        None,
        "--ssh-host-key-policy",
        help=(
            "SSH host-key policy for every selected DUT: strict or insecure. "
            "Omit to use the configured policy (default: insecure)."
        ),
    ),
    ssh_known_hosts_file: Optional[Path] = typer.Option(
        None,
        "--ssh-known-hosts-file",
        help=(
            "Known-hosts trust source used with --ssh-host-key-policy strict. "
            "Omit to use the configured or system trust source."
        ),
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive/--interactive",
        help="Do not request missing credentials from a TTY",
    ),
) -> None:
    """
    Run preflight checks only and display results in a table format.

    This command performs connectivity and configuration checks without
    collecting any logs. Useful for validating DUT accessibility before running
    full collection.

    Args:
        ctx: Typer-owned context for this preflight command invocation.
        config_file: filesystem location used as the config file for this
            operation.
        dut_config: filesystem location used as the DUT config for this
            operation.
        spreadsheet: filesystem location used as the spreadsheet for this
            operation.
        ansible_inventory: filesystem location used as the ansible inventory for
            this operation.
        json_output: Whether JSON output is enabled or required for this
            operation.
        output_file: filesystem location used as the output file for this
            operation.
        local: Whether local is enabled or required for this operation.
        bmc_ip: Text supplied as BMC IP in the format accepted by this function.
        bmc_user: Text supplied as BMC user in the format accepted by this
            function.
        bmc_pass: Text supplied as BMC pass in the format accepted by this
            function.
        bmc_ssh_user: Text supplied as BMC SSH user in the format accepted by
            this function.
        bmc_ssh_pass: Text supplied as BMC SSH pass in the format accepted by
            this function.
        bmc_ssh_port: Numeric BMC SSH port used while the operation performs
            bounded accounting.
        bmc_ssh_key_path: filesystem location used as the BMC SSH key path for
            this operation.
        bmc_ssh_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        bmc_ssh_max_retries: Numeric BMC SSH max retries used while the
            operation performs bounded accounting.
        bmc_rf_user: Text supplied as BMC Redfish user in the format accepted by
            this function.
        bmc_rf_pass: Text supplied as BMC Redfish pass in the format accepted by
            this function.
        bmc_rf_port: Numeric BMC Redfish port used while the operation performs
            bounded accounting.
        host_ip: Text supplied as host IP in the format accepted by this
            function.
        host_user: Text supplied as host user in the format accepted by this
            function.
        host_pass: Text supplied as host pass in the format accepted by this
            function.
        host_ssh_port: Numeric host SSH port used while the operation performs
            bounded accounting.
        host_ssh_key_path: filesystem location used as the host SSH key path for
            this operation.
        host_ssh_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        host_ssh_max_retries: Numeric host SSH max retries used while the
            operation performs bounded accounting.
        hmc_ip: Text supplied as HMC IP in the format accepted by this function.
        hmc_user: Text supplied as HMC user in the format accepted by this
            function.
        hmc_pass: Text supplied as HMC pass in the format accepted by this
            function.
        hmc_ssh_user: Text supplied as HMC SSH user in the format accepted by
            this function.
        hmc_ssh_pass: Text supplied as HMC SSH pass in the format accepted by
            this function.
        hmc_ssh_port: Numeric HMC SSH port used while the operation performs
            bounded accounting.
        hmc_ssh_key_path: filesystem location used as the HMC SSH key path for
            this operation.
        hmc_ssh_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        hmc_ssh_max_retries: Numeric HMC SSH max retries used while the
            operation performs bounded accounting.
        hmc_http_port: Numeric HMC HTTP port used while the operation performs
            bounded accounting.
        hmc_https_port: Numeric HMC HTTPS port used while the operation performs
            bounded accounting.
        hmc_use_https: Whether HMC use HTTPS is enabled or required for this
            operation.
        ssh_proxy_host: Text supplied as SSH proxy host in the format accepted
            by this function.
        ssh_proxy_port: Numeric SSH proxy port used while the operation performs
            bounded accounting.
        ssh_proxy_user: Text supplied as SSH proxy user in the format accepted
            by this function.
        ssh_proxy_pass: Text supplied as SSH proxy pass in the format accepted
            by this function.
        ssh_proxy_key_path: filesystem location used as the SSH proxy key path
            for this operation.
        ssh_proxy_passwordless: Sensitive value supplied through the approved
            input boundary and never logged.
        ssh_proxy_max_retries: Numeric SSH proxy max retries used while the
            operation performs bounded accounting.
        ssl_verify: Optional legacy Redfish certificate-verification override;
            omission preserves the resolved configuration policy.
        ssh_host_key_policy: Optional SSH server-authentication policy applied
            consistently to every selected DUT and proxy route.
        ssh_known_hosts_file: Optional known-hosts trust source used when strict
            SSH host-key verification is selected.
        non_interactive: Whether non interactive is enabled or required for this
            operation.

    Example:
        >>> nvdebug preflight --dut-config dut_config.yaml

    Raises:
        typer.Exit: If the function cannot run preflight checks only and display
            results in a table format safely.
        FileNotFoundError: If tool configuration file not found:
            ``config_file``.
        ValueError: If the supplied input cannot be used to run preflight checks
            only and display results in a table format.
    """

    bmc_pass = _backfill_secret_option_from_environment(ctx, "bmc_pass", bmc_pass)
    bmc_ssh_pass = _backfill_secret_option_from_environment(
        ctx, "bmc_ssh_pass", bmc_ssh_pass
    )
    bmc_rf_pass = _backfill_secret_option_from_environment(
        ctx, "bmc_rf_pass", bmc_rf_pass
    )
    host_pass = _backfill_secret_option_from_environment(ctx, "host_pass", host_pass)
    hmc_pass = _backfill_secret_option_from_environment(ctx, "hmc_pass", hmc_pass)
    hmc_ssh_pass = _backfill_secret_option_from_environment(
        ctx, "hmc_ssh_pass", hmc_ssh_pass
    )
    ssh_proxy_pass = _backfill_secret_option_from_environment(
        ctx, "ssh_proxy_pass", ssh_proxy_pass
    )
    _warn_for_literal_secret_options(
        ctx,
        "bmc_pass",
        "bmc_ssh_pass",
        "bmc_rf_pass",
        "host_pass",
        "hmc_pass",
        "hmc_ssh_pass",
        "ssh_proxy_pass",
    )
    scrub_secret_environment()

    # Auto-detect spreadsheet if not provided
    spreadsheet = auto_detect_spreadsheet(spreadsheet, suppress_print=json_output)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet, json_output=json_output)

    # Resolve and validate the tool configuration before prompting so its
    # non_interactive policy follows the same CLI > environment > discovery
    # precedence as collect and CLIPreflight. Record the operator's selection
    # first: auto-detection below overwrites ``config_file``, and the generated
    # ansible fallback must not replace a document the operator chose.
    user_selected_tool_config = _operator_selected_tool_config(config_file)
    if config_file is None:
        environment_config_file = os.environ.get("NVDEBUG_CONFIG_FILE", "").strip()
        if environment_config_file:
            try:
                config_file = Path(environment_config_file).expanduser()
            except (OSError, RuntimeError) as error:
                _print_preflight_error(
                    f"Configuration error resolving tool config: {error}",
                    json_output=json_output,
                )
                raise typer.Exit(code=2) from error
        else:
            _, legacy_config_file, tool_config_file = (
                main_helpers.find_all_config_files()
            )
            if tool_config_file is not None:
                config_file = tool_config_file
                if not json_output:
                    sanitized_console.print_info(
                        f"Auto-detected tool_config.yaml: {config_file}"
                    )
            elif legacy_config_file is not None:
                config_file = legacy_config_file
                if not json_output:
                    sanitized_console.print_info(
                        f"Auto-detected config.yaml (legacy): {config_file}"
                    )

    resolved_tool_config = None
    if config_file is not None:
        try:
            if not config_file.exists():
                raise FileNotFoundError(
                    f"Tool configuration file not found: {config_file}"
                )
            resolved_tool_config = load_config(config_file)
            extension_values = resolved_tool_config.model_extra or {}
            unknown_roots = sorted(
                key
                for key, value in extension_values.items()
                if not callable(getattr(value, "model_dump", None))
            )
            if unknown_roots:
                raise ValueError(
                    f"unknown key {unknown_roots[0]!r} in tool configuration"
                )
        except (OSError, ValueError):
            _print_preflight_error(
                "Configuration error: selected tool configuration is invalid "
                "or unavailable.",
                json_output=json_output,
            )
            raise typer.Exit(code=2) from None

        for message in tool_config_deprecation_messages(resolved_tool_config):
            if json_output:
                click.echo(message, err=True)
            else:
                sanitized_console.print_warning(message)

    explicit_cli_params = _explicit_cli_params(ctx)
    if ssh_host_key_policy is not None:
        ssh_host_key_policy = ssh_host_key_policy.strip().lower()
        if ssh_host_key_policy not in {"strict", "insecure"}:
            _print_preflight_error(
                "Invalid --ssh-host-key-policy value; expected strict or insecure.",
                json_output=json_output,
            )
            raise typer.Exit(code=2)
    resolved_ssh_known_hosts_file = (
        str(ssh_known_hosts_file) if ssh_known_hosts_file is not None else None
    )
    ssh_host_key_policy = _reject_incoherent_ssh_trust_selection(
        explicit_cli_params,
        ssh_host_key_policy,
        resolved_ssh_known_hosts_file,
        report_error=lambda message: _print_preflight_error(
            message, json_output=json_output
        ),
        report_notice=lambda message: (
            None if json_output else sanitized_console.print_warning(message)
        ),
    )
    if (
        "non_interactive" not in explicit_cli_params
        and resolved_tool_config is not None
        and _config_key_was_explicit(resolved_tool_config, "non_interactive")
    ):
        non_interactive = bool(
            _get_config_value(resolved_tool_config, "non_interactive", False)
        )

    has_cli_credentials = any([bmc_ip, host_ip, hmc_ip])
    environment_dut_config_selected = dut_config is None and bool(
        os.environ.get("NVDEBUG_DUT_CONFIG", "").strip()
    )

    if not main_helpers._preflight_target_source_available(
        dut_config,
        local=local,
        ansible_inventory=ansible_inventory,
        has_cli_credentials=has_cli_credentials,
    ):
        _print_preflight_error(
            "No DUT target was provided or discovered. Use --dut-config, "
            "--local, --ansible-inventory, or CLI credentials.\n\n"
            f"{CONFIG_DISCOVERY_TRUST_HELP}"
            + config_discovery_failure_details(
                include_tool=not user_selected_tool_config
            ),
            json_output=json_output,
        )
        raise typer.Exit(code=2)

    if ansible_inventory and (
        dut_config or environment_dut_config_selected or has_cli_credentials
    ):
        _print_preflight_error(
            "Error: --ansible-inventory cannot be combined with --dut-config, "
            "NVDEBUG_DUT_CONFIG, or CLI credentials.\n"
            "  Use --ansible-inventory alone, OR one DUT configuration/CLI target.",
            json_output=json_output,
        )
        raise typer.Exit(code=2)

    if local and (
        has_cli_credentials
        or dut_config
        or environment_dut_config_selected
        or ansible_inventory
    ):
        _print_preflight_error(
            "Error: --local cannot be combined with --dut-config, "
            "NVDEBUG_DUT_CONFIG, --ansible-inventory, or CLI credentials.\n"
            "  --local runs preflight on the local machine without remote access.",
            json_output=json_output,
        )
        raise typer.Exit(code=2)

    try:
        resolved_dut_configs = (
            _resolve_selected_preflight_duts(
                dut_config,
                dict(locals()),
                explicit_cli_params,
            )
            if not local and ansible_inventory is None
            else None
        )
    except _AmbiguousPreflightDUTScope:
        _print_preflight_error(
            "Environment-selected DUT config defines more than one DUT; "
            "per-DUT CLI overrides are not allowed.",
            json_output=json_output,
        )
        raise typer.Exit(code=2) from None
    except (OSError, RuntimeError, ValueError):
        _print_preflight_error(
            "Configuration error: selected DUT configuration is invalid or unavailable.",
            json_output=json_output,
        )
        raise typer.Exit(code=2) from None

    effective_prompt_dut: Optional[DUTConfig] = None
    if resolved_dut_configs is not None and len(resolved_dut_configs) == 1:
        effective_prompt_dut = resolved_dut_configs[0]
    elif (
        dut_config is not None
        and not has_cli_credentials
        and ansible_inventory is None
        and not local
    ):
        try:
            configured_duts = load_dut_config(dut_config, quiet_mode=True)
        except (OSError, RuntimeError, ValueError):
            configured_duts = []
        if len(configured_duts) == 1:
            effective_prompt_dut = configured_duts[0]

    prompt_values: Dict[str, Any] = {
        "bmc_ip": bmc_ip,
        "bmc_user": bmc_user,
        "bmc_pass": bmc_pass,
        "bmc_ssh_user": bmc_ssh_user,
        "bmc_ssh_pass": bmc_ssh_pass,
        "bmc_ssh_key_path": bmc_ssh_key_path,
        "bmc_ssh_passwordless": bmc_ssh_passwordless,
        "bmc_rf_user": bmc_rf_user,
        "bmc_rf_pass": bmc_rf_pass,
        "host_ip": host_ip,
        "host_user": host_user,
        "host_pass": host_pass,
        "host_ssh_key_path": host_ssh_key_path,
        "host_ssh_passwordless": host_ssh_passwordless,
        "hmc_ip": hmc_ip,
        "hmc_user": hmc_user,
        "hmc_pass": hmc_pass,
        "hmc_ssh_user": hmc_ssh_user,
        "hmc_ssh_pass": hmc_ssh_pass,
        "hmc_ssh_key_path": hmc_ssh_key_path,
        "hmc_ssh_passwordless": hmc_ssh_passwordless,
        "ssh_proxy_host": ssh_proxy_host,
        "ssh_proxy_user": ssh_proxy_user,
        "ssh_proxy_pass": ssh_proxy_pass,
        "ssh_proxy_key_path": ssh_proxy_key_path,
        "ssh_proxy_passwordless": ssh_proxy_passwordless,
    }
    if effective_prompt_dut is not None:
        for field_name in prompt_values:
            cli_value_wins = field_name in explicit_cli_params or (
                field_name in SECRET_ENVIRONMENT_BY_PARAMETER
                and prompt_values[field_name] is not None
            )
            if cli_value_wins:
                continue
            configured_value = getattr(effective_prompt_dut, field_name, None)
            if field_name in SECRET_ENVIRONMENT_BY_PARAMETER and configured_value == "":
                configured_value = None
            prompt_values[field_name] = configured_value
    elif not has_cli_credentials:
        # Multi-DUT, Ansible, local, and auto-discovered config sources own
        # their per-DUT controller credentials; never spread one controller
        # prompt across those targets. Explicit proxy settings stay global and
        # may safely request one shared proxy credential.
        prompt_values["bmc_ip"] = None
        prompt_values["host_ip"] = None
        prompt_values["hmc_ip"] = None

    effective_secret_values = {
        field_name: prompt_values[field_name]
        for field_name in SECRET_ENVIRONMENT_BY_PARAMETER
    }
    prompted_secrets = _prompt_for_unresolved_cli_secrets(
        prompt_values,
        non_interactive=non_interactive,
    )

    def prompted_overlay(
        field_name: str, original_value: Optional[str]
    ) -> Optional[str]:
        """
        Return the prompted overlay.

        The implementation uses ``field_name`` and ``original_value`` to produce
        the prompted overlay.

        Args:
            field_name: Field label included in validation failures for the
                selected input.
            original_value: Text supplied as original value in the format
                accepted by this function.

        Returns:
            The canonical prompted overlay text, or ``None`` when the requested
            value is unavailable.
        """
        if original_value is not None:
            return original_value
        if effective_secret_values[field_name] is not None:
            return None
        return prompted_secrets[field_name]

    bmc_pass = prompted_overlay("bmc_pass", bmc_pass)
    bmc_ssh_pass = prompted_overlay("bmc_ssh_pass", bmc_ssh_pass)
    bmc_rf_pass = prompted_overlay("bmc_rf_pass", bmc_rf_pass)
    host_pass = prompted_overlay("host_pass", host_pass)
    hmc_pass = prompted_overlay("hmc_pass", hmc_pass)
    hmc_ssh_pass = prompted_overlay("hmc_ssh_pass", hmc_ssh_pass)
    ssh_proxy_pass = prompted_overlay("ssh_proxy_pass", ssh_proxy_pass)

    temp_config_file = None
    temp_dut_config_file = None

    if ansible_inventory:
        if not ansible_inventory.exists():
            _print_preflight_error(
                f"Error: Ansible inventory file '{ansible_inventory}' does not exist",
                json_output=json_output,
            )
            raise typer.Exit(code=2)

        try:
            if not json_output:
                sanitized_console.print_info(
                    f"Parsing ansible inventory file: {ansible_inventory}"
                )
            temp_config_file, temp_dut_config_file = generate_config_files_from_ansible(
                ansible_inventory, None, spreadsheet
            )
            # The generated tool config is only a fallback. Keep an explicit or
            # environment-selected tool config at its normal precedence so its
            # ssh_host_key_policy and redfish_session_config still reach
            # CLIPreflight. The generated DUT document is the inventory's actual
            # output and always applies.
            if not user_selected_tool_config:
                config_file = temp_config_file
                # The already-loaded model no longer describes ``config_file``.
                resolved_tool_config = None
            dut_config = temp_dut_config_file
            if not json_output:
                sanitized_console.print_info(
                    f"Generated config files from ansible inventory: {temp_config_file}, {temp_dut_config_file}"
                )
        except Exception as e:
            _print_preflight_error(
                f"Error parsing ansible inventory file: {e}",
                json_output=json_output,
            )
            raise typer.Exit(code=2) from e

    cli_preflight = CLIPreflight()
    try:
        asyncio.run(
            cli_preflight.run(
                config_file,
                dut_config,
                spreadsheet,
                json_output,
                output_file,
                local,
                # BMC Configuration
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
                # Host Configuration
                host_ip,
                host_user,
                host_pass,
                host_ssh_port,
                host_ssh_key_path,
                host_ssh_passwordless,
                host_ssh_max_retries,
                # HMC Configuration
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
                # SSH Proxy Configuration
                ssh_proxy_host,
                ssh_proxy_port,
                ssh_proxy_user,
                ssh_proxy_pass,
                ssh_proxy_key_path,
                ssh_proxy_passwordless,
                ssh_proxy_max_retries,
                bmc_rf_verify_ssl=ssl_verify,
                ssh_host_key_policy=ssh_host_key_policy,
                ssh_known_hosts_file=resolved_ssh_known_hosts_file,
                resolved_dut_configs=resolved_dut_configs,
                resolved_tool_config=resolved_tool_config,
                explicit_cli_params=explicit_cli_params,
            )
        )
    finally:
        if temp_config_file and temp_dut_config_file:
            try:
                cleanup_temp_config_files(temp_config_file, temp_dut_config_file)
                if not json_output:
                    sanitized_console.print_info(
                        "Cleaned up temporary config files generated from ansible inventory"
                    )
            except Exception as e:
                warning = f"Warning: Could not clean up temporary config files: {e}"
                if json_output:
                    if sanitized_console.sanitizer:
                        warning = sanitized_console.sanitizer.sanitize(warning)
                    click.echo(warning, err=True)
                else:
                    sanitized_console.print_warning(warning)


@app.command(
    cls=_ContextualHelpCommand,
    help='List available collectors using the new WorkflowOrchestrator.\n\nExamples:\n\n -  nvdebug list-collectors \n\n -  nvdebug list-collectors --baseboard "GB200 NVL"\n\n -  nvdebug list-collectors --group ssh,redfish',
)
def list_collectors(
    baseboard: Optional[str] = typer.Option(
        None, "--baseboard", "-b", help="Filter by baseboard"
    ),
    group: Optional[str] = typer.Option(
        None,
        "--group",
        "-g",
        help="Filter by collector group(s), comma-separated, case-insensitive",
    ),
    spreadsheet: Optional[Path] = typer.Option(
        None, "--spreadsheet", help="Collector spreadsheet path"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON to stdout"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output file path (for JSON or table format)",
    ),
) -> None:
    """
    List available collectors using the WorkflowOrchestrator.

    This command displays all available log collectors, optionally filtered by
    baseboard or collector group.

    Args:
        baseboard: Text supplied as baseboard in the format accepted by this
            function.
        group: Text supplied as group in the format accepted by this function.
        spreadsheet: filesystem location used as the spreadsheet for this
            operation.
        json_output: Whether JSON output is enabled or required for this
            operation.
        output_file: filesystem location used as the output file for this
            operation.

    Example:
        >>> nvdebug list-collectors
        >>> nvdebug list-collectors --baseboard "GB200 NVL"
        >>> nvdebug list-collectors --group health_check,inventory
    """
    normalized_groups = _normalize_cli_collector_groups(
        [group] if group else None,
        sanitized_console,
        warning_to_stderr=json_output,
    )
    group = ",".join(normalized_groups) if normalized_groups else None

    # Auto-detect spreadsheet if not provided
    spreadsheet = auto_detect_spreadsheet(spreadsheet, suppress_print=json_output)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet, json_output=json_output)

    cli_handler = CLIListCollectors()
    asyncio.run(
        cli_handler.run(
            baseboard,
            group,
            spreadsheet,
            json_output,
            output_file,
        )
    )


@app.command(
    cls=_ContextualHelpCommand,
    help="List available baseboards from the spreadsheet.\n\nExamples:\n\n -  nvdebug list-baseboards",
)
def list_baseboards(
    spreadsheet: Optional[Path] = typer.Option(
        None, "--spreadsheet", help="Collector spreadsheet path"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON to stdout"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output file path (for JSON or table format)",
    ),
) -> None:
    """
    List available baseboards from the spreadsheet.

    This command displays all baseboard platforms defined in the collector
    definitions spreadsheet.

    Args:
        spreadsheet: filesystem location used as the spreadsheet for this
            operation.
        json_output: Whether JSON output is enabled or required for this
            operation.
        output_file: filesystem location used as the output file for this
            operation.

    Example:
        >>> nvdebug list-baseboards
    """

    # Auto-detect spreadsheet if not provided
    spreadsheet = auto_detect_spreadsheet(spreadsheet, suppress_print=json_output)

    # Validate spreadsheet requirement
    validate_spreadsheet_requirement(spreadsheet, json_output=json_output)

    cli_baseboards = CLIListBaseboards()
    asyncio.run(cli_baseboards.run(spreadsheet, json_output, output_file))


# A frozen package must prove its embedded Python payload before any optional
# extension package is imported or allowed to mutate the CLI. Loose operator
# inputs are deliberately outside this one-file self-check.
_frozen_self_check()


def cli() -> None:
    """
    Run the application through the process-boundary integrity gate.

    The implementation uses current instance state to run the application
    through the process-boundary integrity gate. Terminal status is emitted only
    after application through the process-boundary integrity gate and its owned
    cleanup have completed.
    """

    _frozen_self_check()
    app()


if __name__ == "__main__":
    cli()
