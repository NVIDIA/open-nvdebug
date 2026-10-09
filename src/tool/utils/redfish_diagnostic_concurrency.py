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
Validate catalog-owned Redfish diagnostic collector concurrency cohorts.

Firmware admits persistent diagnostic requests by dump scope.  A cohort is a
catalog assertion that collectors use mutually compatible scopes on selected
baseboards.  The scheduler keeps different cohorts, unconfigured collectors,
and shared-HMC routes exclusive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

DIAGNOSTIC_CONCURRENCY_KEY = "diagnostic_concurrency"
DIAGNOSTIC_CONCURRENCY_SCHEMA_VERSION = "1.0"
MAX_CONCURRENCY_COHORT_LENGTH = 64
MAX_CONCURRENCY_BASEBOARD_SELECTORS = 64
MAX_CONCURRENCY_BASEBOARD_SELECTOR_LENGTH = 128

_PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "cohort",
        "applicable_baseboards",
    }
)
_COHORT_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_PROFILE_HOOK_METHODS = frozenset(
    {
        "collect_diagnostic_data",
        "collect_device_diagnostic_data",
    }
)


@dataclass(frozen=True, slots=True)
class RedfishDiagnosticConcurrencyProfile:
    """
    Describe one compatible diagnostic collector cohort.

    The immutable normalized value is shared by spreadsheet validation,
    scheduler batching, endpoint admission, and diagnostic-runner scoping.

    Attributes:
        cohort: Stable catalog label shared only by mutually compatible dump
            scopes.
        applicable_baseboards: Concrete baseboards or governed baseboard-group
            selectors on which the assertion is valid.
    """

    cohort: str
    applicable_baseboards: tuple[str, ...]


def parse_redfish_diagnostic_concurrency_profile(
    raw_profile: Any,
    *,
    context: str = "collector",
) -> Optional[RedfishDiagnosticConcurrencyProfile]:
    """
    Validate and normalize one optional diagnostic concurrency profile.

    Empty values preserve exclusive Redfish endpoint behavior.  Explicit
    profiles reject unknown fields, malformed cohort names, empty selector
    lists, duplicate selectors, and oversized catalog input.

    Args:
        raw_profile: Optional mapping decoded from the governed catalog.
        context: Bounded location included in validation diagnostics.

    Returns:
        The normalized profile, or ``None`` when no profile is configured.

    Raises:
        ValueError: If the explicit profile violates the governed schema.
    """

    if raw_profile in (None, "", {}):
        return None
    if not isinstance(raw_profile, Mapping):
        raise ValueError(f"{context} {DIAGNOSTIC_CONCURRENCY_KEY} must be a mapping")

    unknown = sorted(str(key) for key in set(raw_profile) - _PROFILE_FIELDS)
    if unknown:
        raise ValueError(
            f"{context} {DIAGNOSTIC_CONCURRENCY_KEY} contains unknown field "
            f"{unknown[0]!r}"
        )

    schema_version = raw_profile.get(
        "schema_version", DIAGNOSTIC_CONCURRENCY_SCHEMA_VERSION
    )
    if schema_version != DIAGNOSTIC_CONCURRENCY_SCHEMA_VERSION:
        raise ValueError(
            f"{context} {DIAGNOSTIC_CONCURRENCY_KEY}.schema_version must be "
            f"{DIAGNOSTIC_CONCURRENCY_SCHEMA_VERSION!r}"
        )

    cohort = raw_profile.get("cohort")
    if (
        not isinstance(cohort, str)
        or len(cohort) > MAX_CONCURRENCY_COHORT_LENGTH
        or _COHORT_PATTERN.fullmatch(cohort) is None
    ):
        raise ValueError(
            f"{context} {DIAGNOSTIC_CONCURRENCY_KEY}.cohort must match "
            "[a-z][a-z0-9_-]{0,63}"
        )

    selectors = raw_profile.get("applicable_baseboards")
    if (
        not isinstance(selectors, Sequence)
        or isinstance(selectors, (str, bytes, bytearray))
        or not selectors
        or len(selectors) > MAX_CONCURRENCY_BASEBOARD_SELECTORS
    ):
        raise ValueError(
            f"{context} {DIAGNOSTIC_CONCURRENCY_KEY}.applicable_baseboards "
            f"must contain 1 through {MAX_CONCURRENCY_BASEBOARD_SELECTORS} selectors"
        )

    normalized_selectors: list[str] = []
    seen: set[str] = set()
    for selector in selectors:
        if (
            not isinstance(selector, str)
            or not selector.strip()
            or selector != selector.strip()
            or len(selector) > MAX_CONCURRENCY_BASEBOARD_SELECTOR_LENGTH
        ):
            raise ValueError(
                f"{context} {DIAGNOSTIC_CONCURRENCY_KEY}.applicable_baseboards "
                "selectors must be bounded non-empty strings without outer whitespace"
            )
        normalized = selector.casefold()
        if normalized in seen:
            raise ValueError(
                f"{context} {DIAGNOSTIC_CONCURRENCY_KEY}.applicable_baseboards "
                f"contains duplicate selector {selector!r}"
            )
        seen.add(normalized)
        normalized_selectors.append(selector)

    return RedfishDiagnosticConcurrencyProfile(
        cohort=cohort,
        applicable_baseboards=tuple(normalized_selectors),
    )


def diagnostic_concurrency_profile_for_collector(
    collector_definition: Mapping[str, Any] | None,
    *,
    collector_id: str = "collector",
) -> Optional[RedfishDiagnosticConcurrencyProfile]:
    """
    Extract one operation-level profile from a collector definition.

    Profiles live beside a supported diagnostic collection hook so the same
    generated ``Stages`` projection drives scheduling and execution. A
    collector may define the operation at most once with concurrency metadata;
    placing the key on another hook is rejected instead of silently granting no
    runtime protection.

    Args:
        collector_definition: Runtime collector definition containing stages.
        collector_id: Stable bounded identifier used in validation errors.

    Returns:
        The normalized configured profile, or ``None`` when absent.

    Raises:
        ValueError: If stage structure is malformed or multiple profiles are
            declared for one collector.
    """

    definition = collector_definition or {}
    stages = definition.get("stages", {})
    if not isinstance(stages, Mapping):
        raise ValueError(f"collector {collector_id} stages must be a mapping")
    execution = stages.get("execution", {})
    if not isinstance(execution, Mapping):
        raise ValueError(f"collector {collector_id} execution stage must be a mapping")
    hooks = execution.get("hooks", [])
    if not isinstance(hooks, Sequence) or isinstance(hooks, (str, bytes, bytearray)):
        raise ValueError(f"collector {collector_id} execution hooks must be a list")

    configured: list[Any] = []
    for hook in hooks:
        if not isinstance(hook, Mapping):
            continue
        params = hook.get("params")
        if not isinstance(params, Mapping) or DIAGNOSTIC_CONCURRENCY_KEY not in params:
            continue
        method = hook.get("method")
        if method not in _PROFILE_HOOK_METHODS:
            raise ValueError(
                f"collector {collector_id} declares {DIAGNOSTIC_CONCURRENCY_KEY} "
                f"on unsupported hook {method!r}"
            )
        configured.append(params.get(DIAGNOSTIC_CONCURRENCY_KEY))
    if len(configured) > 1:
        raise ValueError(
            f"collector {collector_id} declares multiple "
            f"{DIAGNOSTIC_CONCURRENCY_KEY} profiles"
        )
    return parse_redfish_diagnostic_concurrency_profile(
        configured[0] if configured else None,
        context=f"collector {collector_id}",
    )


def resolve_redfish_diagnostic_concurrency_cohort(
    raw_profile: Any,
    *,
    baseboard_name: Any,
    baseboard_manager: Any = None,
    context: str = "collector",
) -> Optional[str]:
    """
    Resolve the compatible cohort for one concrete DUT baseboard.

    Exact baseboard names are matched case-insensitively.  When a baseboard
    manager is available, governed semantic baseboard groups are accepted as
    selectors through its existing membership lookup.

    Args:
        raw_profile: Optional catalog concurrency profile.
        baseboard_name: Concrete baseboard selected for the DUT.
        baseboard_manager: Optional catalog manager used for group membership.
        context: Bounded location included in validation diagnostics.

    Returns:
        The cohort label when the profile applies, otherwise ``None``.

    Raises:
        ValueError: If an explicit profile is malformed.
    """

    profile = (
        raw_profile
        if isinstance(raw_profile, RedfishDiagnosticConcurrencyProfile)
        else parse_redfish_diagnostic_concurrency_profile(
            raw_profile,
            context=context,
        )
    )
    if profile is None or not isinstance(baseboard_name, str):
        return None
    normalized_baseboard = baseboard_name.strip().casefold()
    if not normalized_baseboard:
        return None

    for selector in profile.applicable_baseboards:
        if selector.casefold() == normalized_baseboard:
            return profile.cohort
        get_members = getattr(baseboard_manager, "get_baseboards_in_group", None)
        if not callable(get_members):
            continue
        members = get_members(selector)
        if isinstance(members, list) and any(
            isinstance(member, str)
            and member.strip().casefold() == normalized_baseboard
            for member in members
        ):
            return profile.cohort
    return None
