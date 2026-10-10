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
Project linked tool-config coordinates onto their per-DUT counterparts.

This module owns the linked dut projection boundary and exposes
``project_linked_tool_dut_values``. Keeping those contracts together gives
importers one source of truth for their validation, lifecycle, and compatibility
behavior.
"""

from __future__ import annotations

from typing import Any, Mapping

SSH_PROXY_TOOL_TO_DUT_FIELDS = (
    ("host", "ssh_proxy_host", "SSH_PROXY_HOST"),
    ("port", "ssh_proxy_port", "SSH_PROXY_PORT"),
    ("username", "ssh_proxy_user", "SSH_PROXY_USERNAME"),
    ("password", "ssh_proxy_pass", "SSH_PROXY_PASSWORD"),
    ("key_path", "ssh_proxy_key_path", "SSH_PROXY_KEY_PATH"),
    ("passwordless", "ssh_proxy_passwordless", "SSH_PROXY_PASSWORDLESS"),
    ("max_retries", "ssh_proxy_max_retries", "SSH_PROXY_MAX_RETRIES"),
)

# Nested ``ssh_proxy`` children that authenticate to the jump host itself.
# They only have meaning for the bastion the operator paired them with, so a
# higher-precedence source that replaces ``ssh_proxy_host`` must not keep them.
SSH_PROXY_CREDENTIAL_NESTED_FIELDS = frozenset(
    {"username", "password", "key_path", "passwordless"}
)

_REDFISH_SESSION_FIELDS = (
    ("authentication_mode", "bmc_rf_authentication_mode"),
    ("tls_mode", "bmc_rf_tls_mode"),
    ("ca_file", "bmc_rf_ca_file"),
    ("fingerprint_sha256", "bmc_rf_fingerprint_sha256"),
    ("server_name", "bmc_rf_tls_server_name"),
    ("ssl_verify", "bmc_rf_verify_ssl"),
)

_EXPAND_LEVEL_FIELDS = (
    "EXPAND_QUERY_CHASSIS_LEVEL",
    "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL",
    "EXPAND_QUERY_MANAGER_LEVEL",
    "EXPAND_QUERY_SYSTEM_LEVEL",
)


def project_linked_tool_dut_values(values: Mapping[str, Any]) -> dict[str, Any]:
    """
    Return source-present tool fields expressed as ``DUTConfig`` fields.

    ``ConfigFileToUse`` is both a strict tool document and a lower-priority
    per-DUT source. Only coordinates which have an explicit per-DUT projection
    are copied. Defaults materialized by the tool models never participate.

    The nested ``ssh_proxy`` block is projected as a pair. When the same
    document also names ``ssh_proxy_host`` or ``SSH_PROXY_HOST`` it has
    repointed the jump host, so the fields in
    ``SSH_PROXY_CREDENTIAL_NESTED_FIELDS`` are withheld and only the
    non-authenticating coordinates such as ``port`` and ``max_retries`` are
    projected. That leaves an incompletely specified proxy failing
    authentication instead of disclosing the tool-wide bastion secret.

    Args:
        values: Mapping supplying fields for source-present tool fields
            expressed as ``DUTConfig`` fields.

    Returns:
        The validated ``projected``.
    """

    projected: dict[str, Any] = {}

    if "TargetBaseboard" in values and "baseboard" not in values:
        legacy_baseboard = values["TargetBaseboard"]
        projected["baseboard"] = (
            legacy_baseboard.lower()
            if isinstance(legacy_baseboard, str)
            else legacy_baseboard
        )

    proxy = values.get("ssh_proxy")
    if isinstance(proxy, Mapping):
        # A linked document that also names its own ``ssh_proxy_host`` has
        # repointed the jump host. Its authentication coordinates were paired
        # with the tool-wide bastion, so keep only the non-authenticating
        # transport coordinates and let the incomplete proxy fail loudly.
        host_repointed = "ssh_proxy_host" in values or "SSH_PROXY_HOST" in values
        for nested, modern, legacy in SSH_PROXY_TOOL_TO_DUT_FIELDS:
            if host_repointed and nested in SSH_PROXY_CREDENTIAL_NESTED_FIELDS:
                continue
            if nested in proxy and modern not in values and legacy not in values:
                projected[modern] = proxy[nested]

    if "expand_fallback_mode" in values and "EXPAND_FALLBACK_MODE" not in values:
        projected["EXPAND_FALLBACK_MODE"] = values["expand_fallback_mode"]

    if "expand_level" in values and not any(
        field in values for field in _EXPAND_LEVEL_FIELDS
    ):
        projected.update(
            {field: values["expand_level"] for field in _EXPAND_LEVEL_FIELDS}
        )

    # The canonical holder wins on overlap after Config validation has already
    # rejected contradictory aliases. Complementary values remain one policy.
    session_values: dict[str, Any] = {}
    for holder_name in ("redfish_sessions", "redfish_session_config"):
        holder = values.get(holder_name)
        if isinstance(holder, Mapping):
            session_values.update(holder)

    if "ssl" in session_values and "ssl_verify" not in session_values:
        session_values["ssl_verify"] = session_values["ssl"]

    session_selects_policy = any(
        field in session_values for field in ("tls_mode", "ssl_verify")
    ) or any(field in values for field in ("bmc_rf_tls_mode", "bmc_rf_verify_ssl"))
    for nested, dut_field in _REDFISH_SESSION_FIELDS:
        if nested == "server_name" and not session_selects_policy:
            # A server-name-only linked section refines a lower global policy.
            # Keep it in the linked tool document for the runtime resolver
            # instead of manufacturing an incomplete standalone DUT policy.
            continue
        if nested in session_values and dut_field not in values:
            projected[dut_field] = session_values[nested]

    return projected
