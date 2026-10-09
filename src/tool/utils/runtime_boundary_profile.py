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
Catalog-governed platform runtime boundaries with hard safety ceilings.

The catalog may select a smaller operational budget for a baseboard, but it
cannot raise the universal parser, memory, transfer, or concurrency ceilings
defined here. Collector-specific command and stage budgets remain owned by
``collector_definitions.yaml``.
"""

from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping

RUNTIME_BOUNDARY_PROFILE_KEY = "runtime_boundary_profile"
RUNTIME_BOUNDARY_OVERRIDES_KEY = "runtime_boundary_overrides"
RUNTIME_BOUNDARIES_KEY = "runtime_boundaries"
REDFISH_PREFLIGHT_OUTER_GRACE_SECONDS = 5
RUNTIME_BOUNDARY_PROFILE_VERSION = 2

MEBIBYTE = 1024 * 1024
GIBIBYTE = 1024 * MEBIBYTE
TEBIBYTE = 1024 * GIBIBYTE

_LEGACY_RUNTIME_BOUNDARY_KEYS = frozenset(
    {
        "redfish_preflight_total_timeout_seconds",
        "redfish_preflight_connect_timeout_seconds",
        "redfish_preflight_read_timeout_seconds",
        "redfish_preflight_max_retries",
        "redfish_preflight_retry_delay_seconds",
        "collector_max_concurrent_per_dut",
        "redfish_max_concurrent_requests",
        "redfish_max_concurrent_entities",
        "redfish_max_concurrent_dumps",
        "bmc_transfer_max_file_bytes",
        "managed_host_transfer_max_timeout_seconds",
        "managed_host_transfer_max_file_bytes",
        "managed_host_transfer_free_space_reserve_bytes",
        "managed_artifact_max_file_bytes",
        "managed_artifact_max_decompressed_bytes",
        "managed_artifact_persist_free_space_reserve_bytes",
    }
)

FINALIZATION_RUNTIME_BOUNDARY_KEYS = (
    "finalization_archive_max_members",
    "finalization_archive_max_member_bytes",
    "finalization_archive_max_total_bytes",
    "finalization_archive_max_metadata_bytes",
    "finalization_archive_max_metadata_member_bytes",
    "finalization_archive_max_zip_central_directory_bytes",
    "finalization_archive_max_path_nodes",
    "finalization_archive_max_tracked_path_bytes",
    "finalization_archive_max_input_bytes",
    "finalization_archive_max_decompressor_memory_bytes",
    "finalization_archive_max_seconds",
    "finalization_archive_disk_reserve_bytes",
    "finalization_archive_inode_reserve",
    "finalization_sanitizer_max_archive_total_bytes",
    "finalization_sanitizer_max_archive_metadata_bytes",
    "finalization_sanitizer_max_archive_metadata_member_bytes",
    "finalization_sanitizer_max_archive_pax_records",
    "finalization_sanitizer_max_archive_extension_headers",
    "finalization_sanitizer_max_archive_path_nodes",
    "finalization_sanitizer_max_archive_tracked_path_bytes",
    "finalization_sanitizer_max_archive_members",
    "finalization_sanitizer_max_cumulative_expanded_bytes",
    "finalization_sanitizer_max_cumulative_archive_members",
    "finalization_sanitizer_max_seconds",
    "finalization_sanitizer_max_bundle_entries",
    "finalization_sanitizer_max_bundle_path_bytes",
    "finalization_sanitizer_max_bundle_total_bytes",
    "finalization_sanitizer_max_bundle_rewrite_bytes",
    "finalization_sanitizer_max_bundle_rewrite_files",
    "finalization_manifest_max_auxiliary_json_files",
)
_FINALIZATION_LOWER_IS_LESS_RESTRICTIVE_KEYS = frozenset(
    {
        "finalization_archive_disk_reserve_bytes",
        "finalization_archive_inode_reserve",
    }
)

# Defaults preserve the behavior that predated catalog ownership.  Maximums
# are deliberately code-owned: a modified workbook can tighten these values,
# never turn a bounded operation into an unbounded one.
DEFAULT_RUNTIME_BOUNDARIES = MappingProxyType(
    {
        "redfish_preflight_total_timeout_seconds": 20,
        "redfish_preflight_connect_timeout_seconds": 5,
        "redfish_preflight_read_timeout_seconds": 18,
        "redfish_preflight_max_retries": 2,
        "redfish_preflight_retry_delay_seconds": 1,
        "collector_max_concurrent_per_dut": 8,
        "redfish_max_concurrent_requests": 10,
        "redfish_max_concurrent_entities": 10,
        "redfish_max_concurrent_dumps": 16,
        "bmc_transfer_max_file_bytes": 64 * GIBIBYTE,
        "managed_host_transfer_max_timeout_seconds": 86_400,
        "managed_host_transfer_max_file_bytes": 64 * GIBIBYTE,
        "managed_host_transfer_free_space_reserve_bytes": 512 * MEBIBYTE,
        "managed_artifact_max_file_bytes": 64 * GIBIBYTE,
        "managed_artifact_max_decompressed_bytes": 128 * GIBIBYTE,
        "managed_artifact_persist_free_space_reserve_bytes": 512 * MEBIBYTE,
        "finalization_archive_max_members": 4_000_000,
        "finalization_archive_max_member_bytes": TEBIBYTE,
        "finalization_archive_max_total_bytes": TEBIBYTE,
        "finalization_archive_max_metadata_bytes": 4 * GIBIBYTE,
        "finalization_archive_max_metadata_member_bytes": GIBIBYTE,
        "finalization_archive_max_zip_central_directory_bytes": 4 * GIBIBYTE,
        "finalization_archive_max_path_nodes": 8_000_000,
        "finalization_archive_max_tracked_path_bytes": 4 * GIBIBYTE,
        "finalization_archive_max_input_bytes": 2 * TEBIBYTE,
        "finalization_archive_max_decompressor_memory_bytes": 2 * GIBIBYTE,
        "finalization_archive_max_seconds": 86_400,
        "finalization_archive_disk_reserve_bytes": 512 * MEBIBYTE,
        "finalization_archive_inode_reserve": 4_096,
        "finalization_sanitizer_max_archive_total_bytes": TEBIBYTE,
        "finalization_sanitizer_max_archive_metadata_bytes": GIBIBYTE,
        "finalization_sanitizer_max_archive_metadata_member_bytes": 64 * MEBIBYTE,
        "finalization_sanitizer_max_archive_pax_records": 1_000_000,
        "finalization_sanitizer_max_archive_extension_headers": 2_000_000,
        "finalization_sanitizer_max_archive_path_nodes": 2_000_000,
        "finalization_sanitizer_max_archive_tracked_path_bytes": GIBIBYTE,
        "finalization_sanitizer_max_archive_members": 1_000_000,
        "finalization_sanitizer_max_cumulative_expanded_bytes": 2 * TEBIBYTE,
        "finalization_sanitizer_max_cumulative_archive_members": 2_000_000,
        "finalization_sanitizer_max_seconds": 86_400,
        "finalization_sanitizer_max_bundle_entries": 1_000_000,
        "finalization_sanitizer_max_bundle_path_bytes": GIBIBYTE,
        "finalization_sanitizer_max_bundle_total_bytes": TEBIBYTE,
        "finalization_sanitizer_max_bundle_rewrite_bytes": TEBIBYTE,
        "finalization_sanitizer_max_bundle_rewrite_files": 1_000_000,
        "finalization_manifest_max_auxiliary_json_files": 100_000,
    }
)

_BOUNDARY_RANGES = MappingProxyType(
    {
        "redfish_preflight_total_timeout_seconds": (1, 120),
        "redfish_preflight_connect_timeout_seconds": (1, 60),
        "redfish_preflight_read_timeout_seconds": (1, 120),
        "redfish_preflight_max_retries": (0, 5),
        "redfish_preflight_retry_delay_seconds": (0, 30),
        "collector_max_concurrent_per_dut": (1, 64),
        "redfish_max_concurrent_requests": (1, 64),
        "redfish_max_concurrent_entities": (1, 64),
        "redfish_max_concurrent_dumps": (1, 16),
        "bmc_transfer_max_file_bytes": (MEBIBYTE, 64 * GIBIBYTE),
        "managed_host_transfer_max_timeout_seconds": (1, 86_400),
        "managed_host_transfer_max_file_bytes": (MEBIBYTE, 64 * GIBIBYTE),
        "managed_host_transfer_free_space_reserve_bytes": (
            512 * MEBIBYTE,
            16 * GIBIBYTE,
        ),
        "managed_artifact_max_file_bytes": (MEBIBYTE, 64 * GIBIBYTE),
        "managed_artifact_max_decompressed_bytes": (MEBIBYTE, 128 * GIBIBYTE),
        "managed_artifact_persist_free_space_reserve_bytes": (
            512 * MEBIBYTE,
            16 * GIBIBYTE,
        ),
        "finalization_archive_max_members": (1, 4_000_000),
        "finalization_archive_max_member_bytes": (MEBIBYTE, TEBIBYTE),
        "finalization_archive_max_total_bytes": (MEBIBYTE, TEBIBYTE),
        "finalization_archive_max_metadata_bytes": (MEBIBYTE, 4 * GIBIBYTE),
        "finalization_archive_max_metadata_member_bytes": (MEBIBYTE, GIBIBYTE),
        "finalization_archive_max_zip_central_directory_bytes": (
            MEBIBYTE,
            4 * GIBIBYTE,
        ),
        "finalization_archive_max_path_nodes": (1, 8_000_000),
        "finalization_archive_max_tracked_path_bytes": (
            MEBIBYTE,
            4 * GIBIBYTE,
        ),
        "finalization_archive_max_input_bytes": (MEBIBYTE, 2 * TEBIBYTE),
        "finalization_archive_max_decompressor_memory_bytes": (
            MEBIBYTE,
            2 * GIBIBYTE,
        ),
        "finalization_archive_max_seconds": (1, 86_400),
        "finalization_archive_disk_reserve_bytes": (
            512 * MEBIBYTE,
            16 * GIBIBYTE,
        ),
        "finalization_archive_inode_reserve": (4_096, 1_000_000),
        "finalization_sanitizer_max_archive_total_bytes": (MEBIBYTE, TEBIBYTE),
        "finalization_sanitizer_max_archive_metadata_bytes": (
            MEBIBYTE,
            GIBIBYTE,
        ),
        "finalization_sanitizer_max_archive_metadata_member_bytes": (
            MEBIBYTE,
            64 * MEBIBYTE,
        ),
        "finalization_sanitizer_max_archive_pax_records": (1, 1_000_000),
        "finalization_sanitizer_max_archive_extension_headers": (1, 2_000_000),
        "finalization_sanitizer_max_archive_path_nodes": (1, 2_000_000),
        "finalization_sanitizer_max_archive_tracked_path_bytes": (
            MEBIBYTE,
            GIBIBYTE,
        ),
        "finalization_sanitizer_max_archive_members": (1, 1_000_000),
        "finalization_sanitizer_max_cumulative_expanded_bytes": (
            MEBIBYTE,
            2 * TEBIBYTE,
        ),
        "finalization_sanitizer_max_cumulative_archive_members": (1, 2_000_000),
        "finalization_sanitizer_max_seconds": (1, 86_400),
        "finalization_sanitizer_max_bundle_entries": (1, 1_000_000),
        "finalization_sanitizer_max_bundle_path_bytes": (MEBIBYTE, GIBIBYTE),
        "finalization_sanitizer_max_bundle_total_bytes": (MEBIBYTE, TEBIBYTE),
        "finalization_sanitizer_max_bundle_rewrite_bytes": (MEBIBYTE, TEBIBYTE),
        "finalization_sanitizer_max_bundle_rewrite_files": (1, 1_000_000),
        "finalization_manifest_max_auxiliary_json_files": (1, 100_000),
    }
)


def _validate_boundary_values(
    value: Any,
    *,
    field_name: str,
    require_complete: bool,
) -> Dict[str, int]:
    """
    Validate boundary values.

    The implementation uses ``value``, ``field_name``, and ``require_complete``
    to validate boundary values. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        value: Value object whose ``items`` state is read while performing
            boundary values.
        field_name: Field label included in validation failures for the selected
            input.
        require_complete: Whether require complete is enabled or required for
            this operation.

    Returns:
        The validated ``normalized``.

    Raises:
        ValueError: If the ``field_name`` is not an object; the ``field_name``
            keys are not strings; the supplied input cannot be used to validate
            boundary values; or the ``field_name``.``key`` is not an integer; or
            another input invariant is violated.
    """
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{field_name} keys must be strings")

    unknown = sorted(set(value) - set(_BOUNDARY_RANGES))
    if unknown:
        raise ValueError(f"{field_name} has unsupported keys: " + ", ".join(unknown))
    if require_complete:
        missing = sorted(set(_BOUNDARY_RANGES) - set(value))
        if missing:
            raise ValueError(f"{field_name} is missing keys: " + ", ".join(missing))

    normalized: Dict[str, int] = {}
    for key, raw_value in value.items():
        minimum, maximum = _BOUNDARY_RANGES[key]
        if isinstance(raw_value, bool) or not isinstance(raw_value, int):
            raise ValueError(f"{field_name}.{key} must be an integer")
        if not minimum <= raw_value <= maximum:
            raise ValueError(
                f"{field_name}.{key} must be between {minimum} and {maximum}"
            )
        normalized[key] = raw_value
    return normalized


def _validate_relationships(boundaries: Mapping[str, int]) -> None:
    """
    Validate relationships.

    The implementation uses ``boundaries`` to validate relationships. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        boundaries: Mapping supplying fields for relationships.

    Raises:
        ValueError: If a timeout, transfer, archive, sanitizer, or manifest
            child limit exceeds the corresponding aggregate limit.
    """
    total = boundaries["redfish_preflight_total_timeout_seconds"]
    if boundaries["redfish_preflight_connect_timeout_seconds"] > total:
        raise ValueError(
            "redfish_preflight_connect_timeout_seconds cannot exceed "
            "redfish_preflight_total_timeout_seconds"
        )
    if boundaries["redfish_preflight_read_timeout_seconds"] > total:
        raise ValueError(
            "redfish_preflight_read_timeout_seconds cannot exceed "
            "redfish_preflight_total_timeout_seconds"
        )
    if (
        boundaries["managed_artifact_max_file_bytes"]
        > boundaries["managed_artifact_max_decompressed_bytes"]
    ):
        raise ValueError(
            "managed_artifact_max_file_bytes cannot exceed "
            "managed_artifact_max_decompressed_bytes"
        )
    if (
        boundaries["managed_artifact_max_file_bytes"]
        > boundaries["managed_host_transfer_max_file_bytes"]
    ):
        raise ValueError(
            "managed_artifact_max_file_bytes cannot exceed "
            "managed_host_transfer_max_file_bytes"
        )
    if (
        boundaries["finalization_archive_max_member_bytes"]
        > boundaries["finalization_archive_max_total_bytes"]
    ):
        raise ValueError(
            "finalization_archive_max_member_bytes cannot exceed "
            "finalization_archive_max_total_bytes"
        )
    if (
        boundaries["finalization_archive_max_total_bytes"]
        > boundaries["finalization_archive_max_input_bytes"]
    ):
        raise ValueError(
            "finalization_archive_max_total_bytes cannot exceed "
            "finalization_archive_max_input_bytes"
        )
    if (
        boundaries["finalization_archive_max_metadata_member_bytes"]
        > boundaries["finalization_archive_max_metadata_bytes"]
    ):
        raise ValueError(
            "finalization_archive_max_metadata_member_bytes cannot exceed "
            "finalization_archive_max_metadata_bytes"
        )
    if (
        boundaries["finalization_sanitizer_max_archive_metadata_member_bytes"]
        > boundaries["finalization_sanitizer_max_archive_metadata_bytes"]
    ):
        raise ValueError(
            "finalization_sanitizer_max_archive_metadata_member_bytes cannot exceed "
            "finalization_sanitizer_max_archive_metadata_bytes"
        )
    if (
        boundaries["finalization_sanitizer_max_archive_total_bytes"]
        > boundaries["finalization_sanitizer_max_cumulative_expanded_bytes"]
    ):
        raise ValueError(
            "finalization_sanitizer_max_archive_total_bytes cannot exceed "
            "finalization_sanitizer_max_cumulative_expanded_bytes"
        )
    if (
        boundaries["finalization_sanitizer_max_bundle_rewrite_bytes"]
        > boundaries["finalization_sanitizer_max_bundle_total_bytes"]
    ):
        raise ValueError(
            "finalization_sanitizer_max_bundle_rewrite_bytes cannot exceed "
            "finalization_sanitizer_max_bundle_total_bytes"
        )
    if (
        boundaries["finalization_manifest_max_auxiliary_json_files"]
        > boundaries["finalization_sanitizer_max_bundle_entries"]
    ):
        raise ValueError(
            "finalization_manifest_max_auxiliary_json_files cannot exceed "
            "finalization_sanitizer_max_bundle_entries"
        )


def validate_runtime_boundary_profile(value: Any) -> Dict[str, Any]:
    """
    Validate one complete versioned catalog profile.

    The implementation uses ``value`` to validate one complete versioned catalog
    profile. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        value: Value object whose ``get`` state is read while performing one
            complete versioned catalog profile.

    Returns:
        A mapping containing the ``version`` and ``defaults`` fields.

    Raises:
        ValueError: If the ``runtime_boundary_profile_key`` is not an object;
            the supplied input cannot be used to validate one complete versioned
            catalog profile; or its version is unsupported.
    """

    if not isinstance(value, Mapping):
        raise ValueError(f"{RUNTIME_BOUNDARY_PROFILE_KEY} must be an object")
    unknown = sorted(set(value) - {"version", "defaults"})
    if unknown:
        raise ValueError(
            f"{RUNTIME_BOUNDARY_PROFILE_KEY} has unsupported keys: "
            + ", ".join(str(key) for key in unknown)
        )
    version = value.get("version")
    if isinstance(version, bool) or version not in {
        1,
        RUNTIME_BOUNDARY_PROFILE_VERSION,
    }:
        raise ValueError(
            f"{RUNTIME_BOUNDARY_PROFILE_KEY}.version must be 1 or "
            f"{RUNTIME_BOUNDARY_PROFILE_VERSION}"
        )
    supplied_defaults = _validate_boundary_values(
        value.get("defaults"),
        field_name=f"{RUNTIME_BOUNDARY_PROFILE_KEY}.defaults",
        require_complete=False,
    )
    required_keys = (
        _LEGACY_RUNTIME_BOUNDARY_KEYS if version == 1 else frozenset(_BOUNDARY_RANGES)
    )
    missing = sorted(required_keys - set(supplied_defaults))
    if missing:
        raise ValueError(
            f"{RUNTIME_BOUNDARY_PROFILE_KEY}.defaults is missing keys: "
            + ", ".join(missing)
        )
    # Version 1 catalogs predate finalization ownership. Preserve compatibility
    # by filling only those new fields from the fail-safe code defaults.
    defaults = {**DEFAULT_RUNTIME_BOUNDARIES, **supplied_defaults}
    _validate_relationships(defaults)
    return {"version": version, "defaults": defaults}


def validate_runtime_boundary_overrides(value: Any) -> Dict[str, int]:
    """
    Validate one baseboard's optional, partial override mapping.

    After applying local validation, the function forwards ``value`` to
    ``_validate_boundary_values`` and preserves its return and exception
    contract. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing one baseboard's optional,
            partial override mapping.

    Returns:
        A mapping containing runtime boundary overrides.
    """

    return _validate_boundary_values(
        value,
        field_name=RUNTIME_BOUNDARY_OVERRIDES_KEY,
        require_complete=False,
    )


def resolve_runtime_boundaries(
    profile: Mapping[str, Any] | None,
    overrides: Mapping[str, Any] | None = None,
) -> Dict[str, int]:
    """
    Resolve a complete immutable-at-call-site runtime boundary mapping.

    The implementation uses ``profile`` and ``overrides`` to resolve a complete
    immutable-at-call-site runtime boundary mapping.

    Args:
        profile: Optional profile; ``None`` selects the function's default
            behavior.
        overrides: Optional overrides; ``None`` selects the function's default
            behavior.

    Returns:
        The validated ``resolved``.
    """

    if profile is None:
        defaults = dict(DEFAULT_RUNTIME_BOUNDARIES)
    else:
        defaults = validate_runtime_boundary_profile(profile)["defaults"]
    resolved = {**defaults, **validate_runtime_boundary_overrides(overrides or {})}
    _validate_relationships(resolved)
    return resolved


def runtime_boundary_value(
    config: Any,
    key: str,
) -> int:
    """
    Read a resolved DUT value, falling back to the hard-coded safe default.

    The implementation uses ``config`` and ``key`` to read a resolved DUT value,
    falling back to the hard-coded safe default. Parsing or I/O must finish
    before the validated representation is made available to the caller. If the
    function cannot read a resolved DUT value, falling back to the hard-coded
    safe default, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        config: Config governing resolved DUT value, falling back to the
            hard-coded safe default.
        key: Stable key used for lookup and operator-facing diagnostics.

    Returns:
        The numeric runtime boundary value.

    Raises:
        KeyError: If unknown runtime boundary: ``key``.
    """

    if key not in DEFAULT_RUNTIME_BOUNDARIES:
        raise KeyError(f"Unknown runtime boundary: {key}")
    if not isinstance(config, Mapping):
        return DEFAULT_RUNTIME_BOUNDARIES[key]
    boundaries = config.get(RUNTIME_BOUNDARIES_KEY)
    if not isinstance(boundaries, Mapping):
        return DEFAULT_RUNTIME_BOUNDARIES[key]
    try:
        resolved = resolve_runtime_boundaries(None, boundaries)
    except ValueError:
        return DEFAULT_RUNTIME_BOUNDARIES[key]
    return resolved[key]


def resolve_run_finalization_boundaries(
    configs: Iterable[Any],
) -> Dict[str, int]:
    """
    Resolve finalization limits for every DUT participating in one run.

    A final archive or report can contain data from multiple baseboards.  The
    run therefore uses the least restrictive valid operational value selected
    by any participating DUT.  Every value has already been clamped by the
    code-owned hard range during catalog validation. Missing or malformed DUT
    mappings fail safe to the compatibility defaults.

    Args:
        configs: DUT configuration objects participating in the run.

    Returns:
        The complete run-wide finalization boundary mapping.
    """

    resolved_configs = []
    for config in configs:
        boundaries = (
            config.get(RUNTIME_BOUNDARIES_KEY) if isinstance(config, Mapping) else None
        )
        try:
            resolved_configs.append(
                resolve_runtime_boundaries(
                    None,
                    boundaries if isinstance(boundaries, Mapping) else {},
                )
            )
        except ValueError:
            resolved_configs.append(dict(DEFAULT_RUNTIME_BOUNDARIES))

    if not resolved_configs:
        resolved_configs.append(dict(DEFAULT_RUNTIME_BOUNDARIES))

    return {
        key: (
            min(boundaries[key] for boundaries in resolved_configs)
            if key in _FINALIZATION_LOWER_IS_LESS_RESTRICTIVE_KEYS
            else max(boundaries[key] for boundaries in resolved_configs)
        )
        for key in FINALIZATION_RUNTIME_BOUNDARY_KEYS
    }


def redfish_preflight_retry_budget(config: Any) -> int:
    """
    Return the complete configured request/retry budget in seconds.

    The implementation uses ``config`` to produce the complete configured
    request/retry budget in seconds.

    Args:
        config: Config governing complete configured request/retry budget in
            seconds.

    Returns:
        The numeric Redfish preflight retry budget value.
    """

    request_timeout = runtime_boundary_value(
        config, "redfish_preflight_total_timeout_seconds"
    )
    retries = runtime_boundary_value(config, "redfish_preflight_max_retries")
    delay = runtime_boundary_value(config, "redfish_preflight_retry_delay_seconds")
    return (retries + 1) * request_timeout + retries * delay


def redfish_preflight_wait_timeout(config: Any) -> int:
    """
    Return the outer lifecycle timeout including a fixed cleanup margin.

    The implementation uses ``config`` to produce the outer lifecycle timeout
    including a fixed cleanup margin.

    Args:
        config: Config governing outer lifecycle timeout including a fixed
            cleanup margin.

    Returns:
        The numeric Redfish preflight wait timeout value.
    """

    return (
        redfish_preflight_retry_budget(config) + REDFISH_PREFLIGHT_OUTER_GRACE_SECONDS
    )
