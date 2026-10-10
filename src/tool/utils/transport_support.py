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
Catalog-driven transport support helpers.

Only an explicit boolean ``False`` disables a transport. Older catalogs that do
not declare a support field therefore retain their historical behaviour.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Dict, Optional, Set

from .enums import CollectorServiceMapping

SERVICE_TRANSPORT_SUPPORT_FIELDS = MappingProxyType(
    {
        CollectorServiceMapping.REDFISH.value: "supports_redfish",
        CollectorServiceMapping.IPMI.value: "supports_ipmi",
        CollectorServiceMapping.SSH.value: "supports_bmc_ssh",
        "hmc": "supports_hmc",
    }
)

_ACTION_TYPE_SERVICES = MappingProxyType(
    {
        "redfish_api": CollectorServiceMapping.REDFISH.value,
        "ipmi_command": CollectorServiceMapping.IPMI.value,
        "ssh_command": CollectorServiceMapping.SSH.value,
        "host_command": CollectorServiceMapping.HOST.value,
        "health_check": CollectorServiceMapping.HEALTH_CHECK.value,
    }
)

_COMPOSITE_CHECK_SERVICES = (
    CollectorServiceMapping.REDFISH.value,
    CollectorServiceMapping.IPMI.value,
    CollectorServiceMapping.SSH.value,
    CollectorServiceMapping.HOST.value,
)


def transport_support_field(service_name: str) -> Optional[str]:
    """
    Return the catalog support field for a transport service.

    After applying local validation, the function forwards ``service_name`` to
    ``SERVICE_TRANSPORT_SUPPORT_FIELDS.get`` and preserves its return and
    exception contract.

    Args:
        service_name: Stable service name used for lookup and operator-facing
            diagnostics.

    Returns:
        The canonical transport support field text, or ``None`` when the
        requested value is unavailable.
    """

    return SERVICE_TRANSPORT_SUPPORT_FIELDS.get(str(service_name or "").lower())


def catalog_transport_support(config: Any, service_name: str) -> Optional[bool]:
    """
    Return an explicitly declared support value, otherwise ``None``.

    The implementation uses ``config`` and ``service_name`` to produce an
    explicitly declared support value, otherwise ``None``.

    Args:
        config: Config governing explicitly declared support value, otherwise
            ``None``.
        service_name: Stable service name used for lookup and operator-facing
            diagnostics.

    Returns:
        Whether the explicitly declared support value, otherwise ``None``
        operation succeeds, or ``None`` when the decision is unavailable.
    """

    field_name = transport_support_field(service_name)
    if not field_name or not isinstance(config, Mapping):
        return None
    value = config.get(field_name)
    return value if isinstance(value, bool) else None


def collector_service_from_metadata(collector: Any) -> str:
    """
    Resolve a collector service from catalog metadata, never its ID.

    The implementation uses ``collector`` to resolve a collector service from
    catalog metadata, never its ID.

    Args:
        collector: Collector object whose ``get`` state is read while performing
            collector service from catalog metadata, never its ID.

    Returns:
        The canonical collector service from metadata text.
    """

    if not isinstance(collector, Mapping):
        return "unknown"

    service_name = CollectorServiceMapping.get_service_from_group_name(
        str(collector.get("group") or "")
    )
    if service_name != "unknown":
        return service_name

    action_type = str(collector.get("action_type") or "").strip().lower()
    return _ACTION_TYPE_SERVICES.get(action_type, "unknown")


def collector_transport_services(collector: Any) -> Set[str]:
    """
    Return catalog-declared transports a collector can execute.

    A regular collector has one service derived from its group/action metadata.
    A composite health collector declares its transports through enabled
    ``<service>_checks`` execution parameters. An unrecognised or legacy
    composite configuration fails open rather than inventing requirements.

    Args:
        collector: Collector object whose ``get`` state is read while performing
            catalog-declared transports a collector can execute.

    Returns:
        The unique collector transport services returned by the operation.
    """

    service_name = collector_service_from_metadata(collector)
    if service_name != CollectorServiceMapping.HEALTH_CHECK.value:
        return {service_name} if service_name != "unknown" else set()

    if not isinstance(collector, Mapping):
        return set()
    stages = collector.get("stages")
    execution = stages.get("execution") if isinstance(stages, Mapping) else None
    hooks = execution.get("hooks") if isinstance(execution, Mapping) else None
    if not isinstance(hooks, list):
        return set()

    services: Set[str] = set()
    for hook in hooks:
        params = hook.get("params") if isinstance(hook, Mapping) else None
        if not isinstance(params, Mapping):
            continue
        for candidate in _COMPOSITE_CHECK_SERVICES:
            check_config = params.get(f"{candidate}_checks")
            if (
                isinstance(check_config, Mapping)
                and check_config.get("enabled") is not False
            ):
                services.add(candidate)
    return services


def collector_transport_support_decision(
    collector: Any, dut_config: Any
) -> tuple[bool, Dict[str, str]]:
    """
    Return whether at least one declared collector transport is usable.

    The returned mapping contains only explicitly unsupported service/field
    pairs. Missing or non-boolean support values remain compatible.

    Args:
        collector: Collector consumed while the function attempts to determine
            whether at least one declared collector transport is usable.
        dut_config: DUT config governing at least one declared collector
            transport is usable.

    Returns:
        A tuple containing ``outcome flag`` and ``metadata mapping`` in that
        order.
    """

    services = collector_transport_services(collector)
    if not services:
        return True, {}

    unsupported = {
        service_name: transport_support_field(service_name) or ""
        for service_name in services
        if catalog_transport_support(dut_config, service_name) is False
    }
    return len(unsupported) != len(services), unsupported
