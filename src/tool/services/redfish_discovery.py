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
Pure discovery policy and lazy delegation for the Redfish facades.

The Redfish service continues to own transport, logging, and result lifecycle.
This module owns deterministic decisions derived from catalog configuration and
the small lazy adapter shared by ``RedfishService`` and ``DUTManager``. Lazy
backend lookup is intentional: tests and extensions can continue to monkeypatch
the existing facade seams after object construction.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

DiscoveryValue = Optional[Union[str, List[str]]]
DiscoveryBackendProvider = Callable[[], Any]


@dataclass(frozen=True)
class RedfishDiscoveryAdapter:
    """
    Delegate discovery operations to the backend resolved for each call.

    The immutable record keeps ``backend_provider`` together so consumers
    observe one Redfish discovery adapter state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        backend_provider: Backend provider retained as part of the record's
            public state.
    """

    backend_provider: DiscoveryBackendProvider

    def _backend(self) -> Any:
        """
        Return the backend.

        The implementation uses current instance state to produce the backend.
        If the function cannot produce the backend, its exception reaches the
        caller instead of being converted into a successful result.

        Returns:
            The validated ``backend``.

        Raises:
            RuntimeError: If redfish discovery backend is unavailable.
        """
        backend = self.backend_provider()
        if backend is None:
            raise RuntimeError("Redfish discovery backend is unavailable")
        return backend

    async def discover_all_resources(
        self,
        dut_id: str,
        preflight_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run the backend's asynchronous discovery workflow unchanged.

        After applying local validation, the function forwards ``dut_id`` and
        ``preflight_results`` to ``discover_all_resources`` and preserves its
        return and exception contract. Terminal status is emitted only after
        backend's asynchronous discovery workflow unchanged and its owned
        cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing discover all resources.
        """

        return await self._backend().discover_all_resources(dut_id, preflight_results)

    async def get_resource_members(
        self,
        dut_id: str,
        resource_type: str,
    ) -> List[str]:
        """
        Return cached member IDs from the current backend.

        After applying local validation, the function forwards ``dut_id`` and
        ``resource_type`` to ``get_resource_members`` and preserves its return
        and exception contract. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_type: Text supplied as resource type in the format accepted
                by this function.

        Returns:
            The resource members returned in operation-defined order.
        """

        return await self._backend().get_resource_members(dut_id, resource_type)

    async def get_resource_details(
        self,
        dut_id: str,
        resource_type: str,
    ) -> Dict[str, Any]:
        """
        Return cached member details from the current backend.

        After applying local validation, the function forwards ``dut_id`` and
        ``resource_type`` to ``get_resource_details`` and preserves its return
        and exception contract. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_type: Text supplied as resource type in the format accepted
                by this function.

        Returns:
            A mapping containing resource details.
        """

        return await self._backend().get_resource_details(dut_id, resource_type)

    async def get_discovery_results(
        self,
        dut_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Return complete cached discovery results from the current backend.

        After applying local validation, the function forwards ``dut_id`` to
        ``get_discovery_results`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing discovery results, or ``None`` when the
            requested value is unavailable.
        """

        return await self._backend().get_discovery_results(dut_id)

    async def get_firmware_inventory(
        self,
        dut_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Return cached firmware inventory from the current backend.

        After applying local validation, the function forwards ``dut_id`` to
        ``get_firmware_inventory`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing firmware inventory, or ``None`` when the
            requested value is unavailable.
        """

        return await self._backend().get_firmware_inventory(dut_id)


@dataclass(frozen=True)
class DiscoveryEntityPolicy:
    """
    Catalog-independent routing metadata for one Redfish entity family.

    The immutable record keeps ``resource_type``, ``facade_getter``,
    ``uri_key``, ``id_placeholder``, and ``prefix_key`` together so consumers
    observe one discovery entity policy state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        resource_type: Canonical text used as resource type.
        facade_getter: Canonical text used as facade getter.
        uri_key: Canonical text used as URI key.
        id_placeholder: Canonical text used as identifier placeholder.
        prefix_key: Canonical text used as prefix key.
        context_key: Canonical text used as context key.
        count_key: Canonical text used as count key.
        skip_id_type: Canonical text used as skip identifier type.
    """

    resource_type: str
    facade_getter: str
    uri_key: str
    id_placeholder: str
    prefix_key: str
    context_key: str
    count_key: str
    skip_id_type: str


_DISCOVERY_ENTITY_POLICIES = {
    "Systems": DiscoveryEntityPolicy(
        resource_type="Systems",
        facade_getter="get_discovered_systems",
        uri_key="Systems",
        id_placeholder="system_id",
        prefix_key="HGX_SYSTEM_ID_PREFIX",
        context_key="filtered_systems",
        count_key="system_count",
        skip_id_type="system",
    ),
    "Managers": DiscoveryEntityPolicy(
        resource_type="Managers",
        facade_getter="get_discovered_managers",
        uri_key="Managers",
        id_placeholder="manager_id",
        prefix_key="HGX_MANAGER_ID_PREFIX",
        context_key="filtered_managers",
        count_key="manager_count",
        skip_id_type="manager",
    ),
    "Chassis": DiscoveryEntityPolicy(
        resource_type="Chassis",
        facade_getter="get_discovered_chassis",
        uri_key="Chassis",
        id_placeholder="chassis_id",
        prefix_key="HGX_CHASSIS_ID_PREFIX",
        context_key="filtered_chassis",
        count_key="chassis_count",
        skip_id_type="chassis",
    ),
}


def discovery_entity_policy(entity_type: str) -> Optional[DiscoveryEntityPolicy]:
    """
    Return immutable routing metadata for a supported entity type.

    After applying local validation, the function forwards ``entity_type`` to
    ``_DISCOVERY_ENTITY_POLICIES.get`` and preserves its return and exception
    contract.

    Args:
        entity_type: Text supplied as entity type in the format accepted by this
            function.

    Returns:
        A ``DiscoveryEntityPolicy`` representing discovery entity policy, or
        ``None`` when the requested value is unavailable.
    """

    return _DISCOVERY_ENTITY_POLICIES.get(entity_type)


_ENTITY_REGEX_SPECIAL_CHARS = re.compile(r"[\\\^\$\+\?\{\}\(\)\|]")


def matches_entity_pattern(entity_id: str, patterns: List[str]) -> bool:
    """
    Match an entity ID with the facade's legacy regex/glob rules.

    The implementation uses ``entity_id`` and ``patterns`` to match an entity ID
    with the facade's legacy regex/glob rules.

    Args:
        entity_id: Stable entity identifier used to correlate configuration,
            logs, and results.
        patterns: Entries supplied as ``patterns`` without transferring
            container ownership.

    Returns:
        Whether the match an entity ID with the facade's legacy regex/glob rules
        operation succeeds.
    """

    for pattern in patterns:
        if _ENTITY_REGEX_SPECIAL_CHARS.search(pattern):
            if re.search(pattern, entity_id):
                return True
        elif fnmatch.fnmatch(entity_id, pattern):
            return True
    return False


def include_entity_for_filter_mode(
    *,
    is_hgx: bool,
    check_hgx_prefix: bool,
    filter_mode: str,
) -> bool:
    """
    Return whether one entity survives the configured platform filter.

    The implementation uses ``is_hgx``, ``check_hgx_prefix``, and
    ``filter_mode`` to determine whether one entity survives the configured
    platform filter.

    Args:
        is_hgx: Whether is hgx is enabled or required for this operation.
        check_hgx_prefix: Whether check hgx prefix is enabled or required for
            this operation.
        filter_mode: Text supplied as filter mode in the format accepted by this
            function.

    Returns:
        Whether one entity survives the configured platform filter.
    """

    if filter_mode == "hgx_only":
        return is_hgx or not check_hgx_prefix
    if filter_mode == "all_platforms":
        return True
    if filter_mode == "non_hgx_only":
        return not is_hgx
    return is_hgx or not check_hgx_prefix


@dataclass(frozen=True)
class DynamicIdPattern:
    """
    One normalized substring or regular-expression ID matcher.

    The immutable record keeps ``value`` and ``use_regex`` together so consumers
    observe one dynamic identifier pattern state. Consumers receive the fields
    as one unit instead of assembling partial state.

    Attributes:
        value: Canonical text used as value.
        use_regex: Whether use regex applies to this record.
    """

    value: str
    use_regex: bool


@dataclass(frozen=True)
class DynamicIdPolicy:
    """
    ID matching and declared fallback candidates from collector config.

    The immutable record keeps ``patterns`` together so consumers observe one
    dynamic identifier policy state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        patterns: Collection of patterns entries retained by this record.
    """

    patterns: Tuple[DynamicIdPattern, ...]

    @classmethod
    def from_filter_criteria(cls, filter_criteria: Dict[str, Any]) -> DynamicIdPolicy:
        """
        Normalize the supported scalar/sequence ID pattern forms.

        The implementation uses ``filter_criteria`` to normalize the supported
        scalar/sequence ID pattern forms. The source value keeps its ownership
        while the normalized representation is returned separately.

        Args:
            filter_criteria: Mapping supplying fields for supported
                scalar/sequence ID pattern forms.

        Returns:
            A ``DynamicIdPolicy`` initialized from filter criteria.
        """

        if "id_pattern" not in filter_criteria:
            return cls(())

        raw_patterns = filter_criteria["id_pattern"]
        if isinstance(raw_patterns, (list, tuple, set)):
            pattern_values = [str(pattern) for pattern in raw_patterns]
        else:
            pattern_values = [str(raw_patterns)]

        explicit_regex_flag = filter_criteria.get("id_pattern_regex")
        regex_special_chars = re.compile(r"[\\\^\$\*\+\?\{\}\[\]\|]")
        patterns = []
        for pattern in pattern_values:
            use_regex = explicit_regex_flag
            if use_regex is None:
                use_regex = bool(regex_special_chars.search(pattern))
            patterns.append(DynamicIdPattern(pattern, bool(use_regex)))
        return cls(tuple(patterns))

    @property
    def raw_patterns(self) -> List[str]:
        """
        Return configured pattern text in its original iteration order.

        Each access computes the value from ``patterns`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The raw patterns returned in operation-defined order.
        """

        return [pattern.value for pattern in self.patterns]

    @property
    def requires_entity_data_keys(self) -> Tuple[str, ...]:
        """
        Return filter keys whose decisions require a successful detail GET.

        Each access uses current instance state to produce filter keys whose
        decisions require a successful detail GET; the derived view is not
        cached as independent state.

        Returns:
            A tuple containing ``status text``, ``status text``, ``status
            text``, and ``status text`` in that order.
        """

        return ("check_path", "oem_keywords", "model_keywords", "name_keywords")

    def matches(self, entity_name: str) -> bool:
        """
        Return whether an entity ID matches any configured rule.

        The implementation uses ``entity_name`` to determine whether an entity
        ID matches any configured rule.

        Args:
            entity_name: Stable entity name used for lookup and operator-facing
                diagnostics.

        Returns:
            Whether an entity ID matches any configured rule.
        """

        for pattern in self.patterns:
            if pattern.use_regex:
                if re.search(pattern.value, entity_name):
                    return True
            elif pattern.value.lower() in entity_name.lower():
                return True
        return False

    def fallback_entity_ids(self, filter_criteria: Dict[str, Any]) -> List[str]:
        """
        Return only exact, catalog-declared fallback IDs matching this policy.

        The implementation uses ``filter_criteria`` to produce only exact,
        catalog-declared fallback IDs matching this policy.

        Args:
            filter_criteria: Mapping supplying fields for only exact,
                catalog-declared fallback IDs matching this policy.

        Returns:
            The validated ``fallback_entity_ids``.
        """

        raw_fallback_ids = filter_criteria.get("fallback_entity_ids", [])
        if isinstance(raw_fallback_ids, str):
            raw_fallback_ids = [raw_fallback_ids]

        fallback_entity_ids = []
        if isinstance(raw_fallback_ids, (list, tuple, set)):
            for raw_entity_id in raw_fallback_ids:
                if raw_entity_id is None:
                    continue
                entity_id = str(raw_entity_id).strip()
                if entity_id and self.matches(entity_id):
                    fallback_entity_ids.append(entity_id)
        return fallback_entity_ids


def configured_baseboard_patterns(
    baseboard_patterns: Dict[str, List[str]],
    target_baseboard: str,
) -> List[str]:
    """
    Normalize only the exact baseboard's optional entity-pattern entry.

    The implementation uses ``baseboard_patterns`` and ``target_baseboard`` to
    normalize only the exact baseboard's optional entity-pattern entry. The
    source value keeps its ownership while the normalized representation is
    returned separately.

    Args:
        baseboard_patterns: Mapping supplying fields for only the exact
            baseboard's optional entity-pattern entry.
        target_baseboard: Text supplied as target baseboard in the format
            accepted by this function.

    Returns:
        The configured baseboard patterns returned in operation-defined order.
    """

    configured_patterns = baseboard_patterns.get(target_baseboard)
    if isinstance(configured_patterns, str):
        return [configured_patterns]
    if isinstance(configured_patterns, (list, tuple, set)):
        return [str(pattern) for pattern in configured_patterns]
    return []


def resolve_baseboard_filter_mode(
    dut_baseboard: str,
    baseboard_filtering: Dict[str, str],
) -> str:
    """
    Resolve the first catalog baseboard substring match, preserving order.

    The implementation uses ``dut_baseboard`` and ``baseboard_filtering`` to
    resolve the first catalog baseboard substring match, preserving order.

    Args:
        dut_baseboard: Text supplied as DUT baseboard in the format accepted by
            this function.
        baseboard_filtering: Mapping supplying fields for first catalog
            baseboard substring match, preserving order.

    Returns:
        The canonical baseboard filter mode text.
    """

    for baseboard_pattern, filter_mode in baseboard_filtering.items():
        if baseboard_pattern.upper() in dut_baseboard.upper():
            return filter_mode
    return "hgx_only"


def skip_entity_for_baseboard_filter(entity_id: str, filter_mode: str) -> bool:
    """
    Return whether dynamic validation should skip an entity before I/O.

    The implementation uses ``entity_id`` and ``filter_mode`` to determine
    whether dynamic validation should skip an entity before I/O.

    Args:
        entity_id: Stable entity identifier used to correlate configuration,
            logs, and results.
        filter_mode: Text supplied as filter mode in the format accepted by this
            function.

    Returns:
        Whether dynamic validation should skip an entity before I/O.
    """

    is_hgx = entity_id.upper().startswith("HGX_")
    if filter_mode == "hgx_only":
        return not is_hgx
    if filter_mode == "non_hgx_only":
        return is_hgx
    return False


@dataclass(frozen=True)
class DiscoveryApplicabilityDecision:
    """
    Pure decision plus the facade-compatible diagnostic reason.

    The immutable record keeps ``applies`` and ``reason`` together so consumers
    observe one discovery applicability decision state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        applies: Whether applies to this record.
        reason: Canonical reason exposed to downstream status consumers.
    """

    applies: bool
    reason: Optional[str] = None


@dataclass(frozen=True)
class DiscoveryApplicabilityPolicy:
    """
    Staged applicability rules derived from one discovery config entry.

    The immutable record keeps ``apply_when`` and ``applicable_baseboards``
    together so consumers observe one discovery applicability policy state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        apply_when: Mapping that retains the apply when fields for this record.
        applicable_baseboards: Collection of applicable baseboards entries
            retained by this record.
    """

    apply_when: Optional[Dict[str, Any]]
    applicable_baseboards: Tuple[str, ...]

    @classmethod
    def from_config(
        cls,
        discovery_config: Dict[str, Any],
        collector_def: Optional[Dict[str, Any]],
    ) -> DiscoveryApplicabilityPolicy:
        """
        Build policy while treating universal applicability as unbounded.

        After applying local validation, the function forwards
        ``discovery_config`` and ``collector_def`` to ``cls`` and preserves its
        return and exception contract.

        Args:
            discovery_config: Discovery config governing policy while treating
                universal applicability as unbounded.
            collector_def: Mapping supplying fields for policy while treating
                universal applicability as unbounded.

        Returns:
            A ``DiscoveryApplicabilityPolicy`` initialized from config.
        """

        applicable_baseboards: List[str] = []
        if collector_def:
            collector_applicable = collector_def.get("applicable_baseboards")
            if isinstance(collector_applicable, list):
                if not any(
                    isinstance(item, str) and item.strip().lower() in {"all", "*"}
                    for item in collector_applicable
                ):
                    applicable_baseboards = collector_applicable
            elif isinstance(collector_applicable, str):
                if collector_applicable.strip().lower() not in {"all", "*"}:
                    applicable_baseboards = [collector_applicable]

        return cls(
            apply_when=discovery_config.get("apply_when"),
            applicable_baseboards=tuple(applicable_baseboards),
        )

    def evaluate_identity(
        self,
        *,
        collector_name: str,
        collector_id: str,
        function_tag: str,
    ) -> DiscoveryApplicabilityDecision:
        """
        Evaluate filters that do not require DUT/baseboard lookups.

        The implementation uses ``collector_name``, ``collector_id``, and
        ``function_tag`` to evaluate filters that do not require DUT/baseboard
        lookups.

        Args:
            collector_name: Stable collector name used for lookup and
                operator-facing diagnostics.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.

        Returns:
            A ``DiscoveryApplicabilityDecision`` representing evaluate identity.
        """

        if not self.apply_when:
            return DiscoveryApplicabilityDecision(True)

        collector_ids = self.apply_when.get("collector_ids")
        if collector_ids and collector_id not in collector_ids:
            return DiscoveryApplicabilityDecision(
                False,
                f"Dynamic discovery skipped for {collector_name}: collector_id "
                f"'{collector_id}' not in {collector_ids}",
            )

        function_tags = self.apply_when.get("function_tags")
        if function_tags and function_tag not in function_tags:
            return DiscoveryApplicabilityDecision(
                False,
                f"Dynamic discovery skipped for {collector_name}: function tag "
                f"'{function_tag}' not in {function_tags}",
            )
        return DiscoveryApplicabilityDecision(True)

    def required_baseboards(self) -> Any:
        """
        Return explicit or collector-derived baseboard requirements.

        The implementation uses current instance state to produce explicit or
        collector-derived baseboard requirements.

        Returns:
            Explicit or collector-derived baseboard requirements.
        """

        if not self.apply_when:
            return None
        baseboards = self.apply_when.get("baseboards")
        if (
            not baseboards
            and self.apply_when.get("use_applicable_baseboards")
            and self.applicable_baseboards
        ):
            return list(self.applicable_baseboards)
        return baseboards

    def configured_baseboard_groups(self) -> Any:
        """
        Return explicit group requirements before optional derivation.

        After applying local validation, the function forwards current instance
        state to ``self.apply_when.get`` and preserves its return and exception
        contract.

        Returns:
            Explicit group requirements before optional derivation.
        """

        if not self.apply_when:
            return None
        return self.apply_when.get("baseboard_groups")

    def derives_applicable_baseboard_groups(self) -> bool:
        """
        Return whether group constraints come from applicable baseboards.

        After applying local validation, the function forwards current instance
        state to ``bool`` and preserves its return and exception contract.

        Returns:
            Whether group constraints come from applicable baseboards.
        """

        return bool(
            self.apply_when
            and self.apply_when.get("use_applicable_baseboard_groups")
            and self.applicable_baseboards
        )

    @staticmethod
    def evaluate_baseboards(
        *,
        collector_name: str,
        baseboard_name: Optional[str],
        required_baseboards: Any,
        baseboard_type: Optional[str] = None,
        matching_groups: Optional[List[str]] = None,
    ) -> DiscoveryApplicabilityDecision:
        """
        Evaluate baseboard constraints against resolved catalog identities.

        Exact names remain valid constraints. When the caller supplies a
        catalog-resolved primary type or semantic groups, those governed
        identities also satisfy a collector-derived applicability constraint.
        Matching is case-insensitive so catalog capitalization does not change
        applicability.

        Args:
            collector_name: Stable collector name used for lookup and
                operator-facing diagnostics.
            baseboard_name: Stable baseboard name used for lookup and
                operator-facing diagnostics.
            required_baseboards: Required baseboards consumed while the function
                evaluates catalog-backed baseboard constraints.
            baseboard_type: Optional primary catalog type resolved for the DUT.
            matching_groups: Optional governed semantic groups containing the
                DUT baseboard.

        Returns:
            A ``DiscoveryApplicabilityDecision`` representing evaluate
            baseboards.
        """

        if not required_baseboards:
            return DiscoveryApplicabilityDecision(True)
        if not baseboard_name:
            return DiscoveryApplicabilityDecision(
                False,
                f"Dynamic discovery skipped for {collector_name}: baseboard unknown, "
                f"required one of {required_baseboards}",
            )

        required_values = (
            [required_baseboards]
            if isinstance(required_baseboards, str)
            else list(required_baseboards)
        )
        resolved_values = [baseboard_name]
        if baseboard_type:
            resolved_values.append(baseboard_type)
        resolved_values.extend(matching_groups or [])
        normalized_resolved = {
            value.strip().casefold()
            for value in resolved_values
            if isinstance(value, str) and value.strip()
        }
        if not any(
            isinstance(required, str)
            and required.strip().casefold() in normalized_resolved
            for required in required_values
        ):
            return DiscoveryApplicabilityDecision(
                False,
                f"Dynamic discovery skipped for {collector_name}: baseboard "
                f"'{baseboard_name}' not in {required_baseboards} "
                f"(resolved type={baseboard_type}, groups={matching_groups or []})",
            )
        return DiscoveryApplicabilityDecision(True)

    @staticmethod
    def evaluate_baseboard_groups(
        *,
        collector_name: str,
        baseboard_name: Optional[str],
        baseboard_type: Optional[str],
        required_groups: Any,
    ) -> DiscoveryApplicabilityDecision:
        """
        Evaluate resolved baseboard-group constraints.

        The implementation uses ``collector_name``, ``baseboard_name``,
        ``baseboard_type``, and ``required_groups`` to evaluate resolved
        baseboard-group constraints.

        Args:
            collector_name: Stable collector name used for lookup and
                operator-facing diagnostics.
            baseboard_name: Stable baseboard name used for lookup and
                operator-facing diagnostics.
            baseboard_type: Text supplied as baseboard type in the format
                accepted by this function.
            required_groups: Required groups consumed while the function
                attempts to evaluate resolved baseboard-group constraints.

        Returns:
            A ``DiscoveryApplicabilityDecision`` representing evaluate baseboard
            groups.
        """

        if not required_groups:
            return DiscoveryApplicabilityDecision(True)
        if not baseboard_name:
            return DiscoveryApplicabilityDecision(
                False,
                f"Dynamic discovery skipped for {collector_name}: baseboard unknown, "
                f"required group in {required_groups}",
            )
        if baseboard_type not in required_groups:
            return DiscoveryApplicabilityDecision(
                False,
                f"Dynamic discovery skipped for {collector_name}: baseboard "
                f"'{baseboard_name}' (type={baseboard_type}) not in groups "
                f"{required_groups}",
            )
        return DiscoveryApplicabilityDecision(True)


def apply_discovered_value(
    current_value: DiscoveryValue,
    discovered_value: DiscoveryValue,
    behavior: str,
    *,
    deduplicate: bool = False,
) -> DiscoveryValue:
    """
    Combine a discovered value with existing catalog configuration.

    The implementation uses ``current_value``, ``discovered_value``,
    ``behavior``, and ``deduplicate`` to combine a discovered value with
    existing catalog configuration.

    Args:
        current_value: Current value consumed while the function attempts to
            combine a discovered value with existing catalog configuration.
        discovered_value: Discovered value consumed while the function attempts
            to combine a discovered value with existing catalog configuration.
        behavior: Text supplied as behavior in the format accepted by this
            function.
        deduplicate: Whether deduplicate is enabled or required for this
            operation.

    Returns:
        A ``DiscoveryValue`` representing discovered value.
    """

    if discovered_value is None:
        return current_value
    if behavior != "append":
        return discovered_value

    def normalize_to_list(value: Optional[Any]) -> List[str]:
        """
        Normalize to list.

        The implementation uses ``value`` to normalize to list. The source value
        keeps its ownership while the normalized representation is returned
        separately.

        Args:
            value: Value evaluated while performing to list.

        Returns:
            The list returned in operation-defined order.
        """
        if value is None:
            return []
        if isinstance(value, list):
            return list(value)
        if isinstance(value, str):
            return [value]
        return [str(value)]

    combined = normalize_to_list(current_value)
    combined.extend(normalize_to_list(discovered_value))
    if deduplicate:
        combined = list(dict.fromkeys(combined))
    if not combined:
        return None

    should_return_list = (
        isinstance(current_value, list)
        or isinstance(discovered_value, list)
        or len(combined) != 1
    )
    return combined if should_return_list else combined[0]


def registry_member_matches(
    candidate_value: Any,
    *,
    match_type: str,
    match_values: List[str],
    match_regex: Any,
    case_insensitive: bool,
) -> bool:
    """
    Apply configured registry-member matching without transport side effects.

    The implementation uses ``candidate_value``, ``match_type``,
    ``match_values``, ``match_regex``, and ``case_insensitive`` to apply
    configured registry-member matching without transport side effects.

    Args:
        candidate_value: Candidate value object whose ``lower`` state is read
            while performing apply configured registry-member matching without
            transport side effects.
        match_type: Text supplied as match type in the format accepted by this
            function.
        match_values: Entries supplied as ``match_values`` without transferring
            container ownership.
        match_regex: Match regex consumed while the function attempts to apply
            configured registry-member matching without transport side effects.
        case_insensitive: Whether case insensitive is enabled or required for
            this operation.

    Returns:
        Whether the apply configured registry-member matching without transport
        side effects operation succeeds.
    """

    candidate_compare = (
        candidate_value.lower()
        if isinstance(candidate_value, str) and case_insensitive
        else candidate_value
    )
    if match_regex:
        regex_flags = re.IGNORECASE if case_insensitive else 0
        return bool(
            isinstance(candidate_value, str)
            and re.search(match_regex, candidate_value, flags=regex_flags)
        )

    if match_values:
        compare_values = (
            [value.lower() for value in match_values]
            if case_insensitive
            else match_values
        )
        if isinstance(candidate_compare, str):
            if match_type == "equals":
                return candidate_compare in compare_values
            return any(value in candidate_compare for value in compare_values)
        return candidate_compare in compare_values

    return True


def flatten_discovery_results(results: List[Any]) -> List[Any]:
    """
    Flatten one level of multi-result discovery values in stable order.

    The implementation uses ``results`` to flatten one level of multi-result
    discovery values in stable order.

    Args:
        results: Entries supplied as ``results`` without transferring container
            ownership.

    Returns:
        The validated ``flattened``.
    """

    flattened = []
    for item in results:
        if isinstance(item, list):
            flattened.extend(item)
        else:
            flattened.append(item)
    return flattened
