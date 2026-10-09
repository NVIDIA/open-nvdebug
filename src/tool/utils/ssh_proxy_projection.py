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
Project nested tool-level SSH proxy settings onto runtime DUT models.

This module owns the ssh proxy projection boundary and exposes ``_get_value``
and ``project_tool_ssh_proxy_defaults``. Keeping those contracts together gives
importers one source of truth for their validation, lifecycle, and compatibility
behavior.
"""

from typing import Any, Iterable

from ..config import DUTConfig
from .linked_dut_projection import (
    SSH_PROXY_CREDENTIAL_NESTED_FIELDS,
    SSH_PROXY_TOOL_TO_DUT_FIELDS,
)


def _get_value(source: Any, key: str, default: Any = None) -> Any:
    """
    Return the requested value from the supplied source.

    The implementation uses ``source``, ``key``, and ``default`` to produce the
    requested value from the supplied source.

    Args:
        source: Source object whose ``get`` state is read while performing
            requested value from the supplied source.
        key: Stable key used for lookup and operator-facing diagnostics.
        default: Fallback used when the requested value is absent or invalid.

    Returns:
        The requested value from the supplied source.
    """
    if source is None:
        return default
    if isinstance(source, dict):
        return source.get(key, default)
    return getattr(source, key, default)


def project_tool_ssh_proxy_defaults(
    config_file_data: object,
    dut_configs: Iterable[DUTConfig],
    explicit_cli_params: set[str],
    *,
    cli_mode: bool,
) -> None:
    """
    Project source-present tool proxy fields below CLI and DUT values.

    Each nested ``ssh_proxy`` child is copied onto both the canonical and the
    legacy DUT field unless a higher-precedence source already selected that
    coordinate. The tool-wide credentials are bound to the tool-wide jump host,
    so when a higher-precedence source replaces ``ssh_proxy_host`` for a DUT the
    fields in ``SSH_PROXY_CREDENTIAL_NESTED_FIELDS`` are withheld from that DUT
    while the non-authenticating coordinates such as ``port`` and
    ``max_retries`` are still projected. The resulting proxy is incompletely
    specified and fails authentication loudly rather than presenting the
    tool-wide bastion secret to a host the operator never paired it with.

    The guard reads the same two precedence sources as the per-field
    suppression below it, so it behaves identically for the CLI ``collect``
    path and for callers that reuse this helper with ``cli_mode=False``.

    Args:
        config_file_data: Tool-level configuration object or mapping whose
            ``ssh_proxy`` block supplies the projected defaults. A missing or
            ``None`` block makes the call a no-op.
        dut_configs: Runtime DUT models mutated in place; each receives the
            canonical and legacy alias for every projected coordinate.
        explicit_cli_params: Canonical field names the CLI supplied explicitly.
            These outrank the tool block and mark the jump host as replaced.
        cli_mode: Whether the caller runs the CLI precedence layer. When true
            the per-DUT model fields are not treated as an explicit source,
            because the CLI already materialized them.
    """

    tool_proxy = _get_value(config_file_data, "ssh_proxy")
    if tool_proxy is None:
        return

    tool_proxy_fields = (
        set(tool_proxy)
        if isinstance(tool_proxy, dict)
        else set(getattr(tool_proxy, "model_fields_set", set()))
    )
    for dut_config in dut_configs:
        explicit_dut_fields = (
            set() if cli_mode else set(getattr(dut_config, "model_fields_set", set()))
        )
        host_repointed = (
            "ssh_proxy_host" in explicit_cli_params
            or "ssh_proxy_host" in explicit_dut_fields
            or "SSH_PROXY_HOST" in explicit_dut_fields
        )
        for nested, canonical, legacy in SSH_PROXY_TOOL_TO_DUT_FIELDS:
            if host_repointed and nested in SSH_PROXY_CREDENTIAL_NESTED_FIELDS:
                continue
            if nested not in tool_proxy_fields or canonical in explicit_cli_params:
                continue
            if canonical in explicit_dut_fields or legacy in explicit_dut_fields:
                continue

            value = _get_value(tool_proxy, nested)
            if nested == "key_path" and value is not None:
                value = str(value)
            setattr(dut_config, canonical, value)
            setattr(dut_config, legacy, value)
