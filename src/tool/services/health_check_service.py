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
Catalog-driven out-of-band health-check execution.

This module owns the health check service boundary and exposes
``_RedfishRequestOutcome``, ``_RedfishTraversalBudget``, and
``HealthCheckService``. Keeping those contracts together gives importers one
source of truth for their validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import asyncio
import json
import pprint
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..utils.redfish_limits import (
    MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS,
    bound_redfish_collection_members,
)
from ..utils.redfish_topology_profile import (
    RedfishTopologyProfileError,
    validate_redfish_uri_path,
)
from ..utils.transport_support import (
    catalog_transport_support,
    transport_support_field,
)
from .base_service import BaseService


@dataclass
class _RedfishRequestOutcome:
    """
    Reusable result for one validated, invocation-local Redfish URI.

    The coherent record keeps ``success``, ``response``, ``metadata``,
    ``headers``, and ``exception_reason`` together so consumers observe one
    Redfish request outcome state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        success: Whether success applies to this record.
        response: Response retained as part of the record's public state.
        metadata: Metadata retained as part of the record's public state.
        headers: Headers retained as part of the record's public state.
        exception_reason: Canonical text used as exception reason.
    """

    success: bool
    response: Any = None
    metadata: Any = None
    headers: Any = None
    exception_reason: Optional[str] = None


@dataclass
class _RedfishTraversalBudget:
    """
    Finite work budget shared by every Redfish health-check component.

    The coherent record keeps ``max_members``, ``max_nodes``,
    ``max_candidates``, ``max_requests``, and ``max_depth`` together so
    consumers observe one Redfish traversal budget state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        max_members: Maximum members admitted by this record.
        max_nodes: Maximum nodes admitted by this record.
        max_candidates: Maximum candidates admitted by this record.
        max_requests: Maximum requests admitted by this record.
        max_depth: Maximum depth admitted by this record.
        deadline: Numeric deadline retained by this record.
        members: Number of members represented by this record.
        nodes: Number of nodes represented by this record.
        candidates: Number of candidates represented by this record.
        requests: Number of requests represented by this record.
        terminal_reason: Canonical text used as terminal reason.
        seen_candidates: Collection of seen candidates entries retained by this
            record.
        request_cache: Mapping that retains the request cache fields for this
            record.
        evidence_keys: Collection of evidence keys entries retained by this
            record.
    """

    max_members: int
    max_nodes: int
    max_candidates: int
    max_requests: int
    max_depth: int
    deadline: float
    members: int = 0
    nodes: int = 0
    candidates: int = 0
    requests: int = 0
    terminal_reason: Optional[str] = None
    seen_candidates: set[Tuple[int, str]] = field(default_factory=set)
    request_cache: Dict[str, _RedfishRequestOutcome] = field(default_factory=dict)
    evidence_keys: set[str] = field(default_factory=set)

    def remaining_seconds(self) -> float:
        """
        Return remaining wall-clock work time and latch expiration.

        After applying local validation, the function forwards current instance
        state to ``max`` and preserves its return and exception contract. It
        updates ``terminal_reason`` on the instance as part of that state
        transition.

        Returns:
            The numeric remaining seconds.
        """

        remaining = self.deadline - time.monotonic()
        if remaining <= 0 and self.terminal_reason is None:
            self.terminal_reason = "Redfish health traversal deadline was exceeded"
        return max(remaining, 0.0)

    def active(self) -> Tuple[bool, Optional[str]]:
        """
        Report whether new traversal work may be admitted.

        The implementation uses current instance state to report whether new
        traversal work may be admitted.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """

        if self.terminal_reason is not None:
            return False, self.terminal_reason
        if self.remaining_seconds() <= 0:
            return False, self.terminal_reason
        return True, None

    def reserve_node(self) -> Tuple[bool, Optional[str]]:
        """
        Reserve node.

        The implementation uses current instance state to reserve node. It
        updates ``nodes`` and ``terminal_reason`` on the instance as part of
        that state transition.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        active, reason = self.active()
        if not active:
            return False, reason
        if self.nodes >= self.max_nodes:
            self.terminal_reason = (
                "Redfish health traversal node budget was exhausted "
                f"({self.max_nodes})"
            )
            return False, self.terminal_reason
        self.nodes += 1
        return True, None

    def reserve_candidate(
        self,
        scope: int,
        candidate: str,
        *,
        charge_member: bool,
    ) -> Tuple[bool, Optional[str]]:
        """
        Admit one validated, deduplicated traversal candidate.

        The implementation uses ``scope``, ``candidate``, and ``charge_member``
        to admit one validated, deduplicated traversal candidate. It updates
        ``candidates``, ``members``, and ``terminal_reason`` on the instance as
        part of that state transition.

        Args:
            scope: Numeric scope used while the operation performs bounded
                accounting.
            candidate: Candidate value or resource evaluated by this operation.
            charge_member: Whether charge member is enabled or required for this
                operation.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """

        key = (scope, candidate)
        if key in self.seen_candidates:
            return False, None

        active, reason = self.active()
        if not active:
            return False, reason
        if charge_member and self.members >= self.max_members:
            self.terminal_reason = (
                "Redfish health traversal member budget was exhausted "
                f"({self.max_members})"
            )
            return False, self.terminal_reason
        if self.candidates >= self.max_candidates:
            self.terminal_reason = (
                "Redfish health traversal candidate budget was exhausted "
                f"({self.max_candidates})"
            )
            return False, self.terminal_reason

        self.seen_candidates.add(key)
        self.candidates += 1
        if charge_member:
            self.members += 1
        return True, None

    def reserve_request(self, uri: str) -> Tuple[str, Optional[str]]:
        """
        Reserve one unique validated request or identify a cached result.

        The implementation uses ``uri`` to reserve one unique validated request
        or identify a cached result. It updates ``requests`` and
        ``terminal_reason`` on the instance as part of that state transition.

        Args:
            uri: Validated remote resource identifier used for URI.

        Returns:
            A tuple containing ``status text`` and ``status or message text`` in
            that order.
        """

        active, reason = self.active()
        if not active:
            return "rejected", reason
        if uri in self.request_cache:
            return "cached", None
        if self.requests >= self.max_requests:
            self.terminal_reason = (
                "Redfish health request budget was exhausted " f"({self.max_requests})"
            )
            return "rejected", self.terminal_reason
        self.requests += 1
        return "reserved", None

    def expire(self, reason: str) -> None:
        """
        Prevent all subsequent network requests after a timed-out operation.

        The implementation uses ``reason`` to prevent all subsequent network
        requests after a timed-out operation. It updates ``terminal_reason`` on
        the instance as part of that state transition.

        Args:
            reason: Text supplied as reason in the format accepted by this
                function.
        """

        if self.terminal_reason is None:
            self.terminal_reason = reason


class HealthCheckService(BaseService):
    """
    Execute the probes declared by a health-check collector definition.

    The type coordinates ``validate_connection``,
    ``_validate_health_check_environment``, ``_validate_health_check_ready``,
    ``run_health_check``, and ``_catalog_transport_not_applicable`` and retains
    the state those operations share between calls. Resource ownership remains
    inside the instance until the matching close, exit, or cleanup operation
    completes.
    """

    _PLACEHOLDER = re.compile(r"\{[^{}]+\}")
    _SUPPORTED_OUTPUT_FORMATS = {"json", "text"}
    _SUPPORTED_THRESHOLDS = {"all_pass", "any_pass", "majority"}
    _MAX_REDFISH_COLLECTION_MEMBERS = MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS
    _MAX_REDFISH_TRAVERSAL_MEMBERS = 4096
    _MAX_REDFISH_TRAVERSAL_NODES = 4096
    _MAX_REDFISH_CANDIDATES = 4096
    _MAX_REDFISH_REQUESTS = 2048
    _MAX_REDFISH_PLACEHOLDER_DEPTH = 8
    _MAX_REDFISH_TRAVERSAL_SECONDS = 300.0

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """
        The configured probes perform their own transport validation.

        The implementation uses ``dut_id`` to the configured probes perform
        their own transport validation. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing the connection-success flag and sanitized
            diagnostic message.
        """
        return True, "Health check validation passed"

    async def _validate_health_check_environment(
        self, dut_id: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Allow execution to validate the transports selected by the catalog.

        After applying local validation, the function forwards ``dut_id`` and
        ``kwargs`` to ``self._create_standardized_collector_result`` and
        preserves its return and exception contract. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing health check environment.
        """
        return await self._create_standardized_collector_result(
            successful_operations=1,
            total_operations=1,
            output_files=[],
            error_messages=[],
            operation_name="health_check_validation",
            additional_context={
                "reason": "Health check environment ready",
                "health_check_ready": True,
            },
            dut_id=dut_id,
        )

    async def _validate_health_check_ready(
        self, dut_id: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Compatibility validation hook for catalog definitions.

        After applying local validation, the function forwards ``dut_id`` and
        ``kwargs`` to ``self._create_standardized_collector_result`` and
        preserves its return and exception contract. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing health check ready.
        """
        return await self._create_standardized_collector_result(
            successful_operations=1,
            total_operations=1,
            output_files=[],
            error_messages=[],
            operation_name="health_check_validation",
            additional_context={
                "reason": "Health check ready",
                "health_check_ready": True,
            },
            dut_id=dut_id,
        )

    async def run_health_check(self, dut_id: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Run every enabled Redfish and IPMI probe supplied by the catalog.

        The implementation uses ``dut_id`` and ``kwargs`` to run every enabled
        Redfish and IPMI probe supplied by the catalog. Terminal status is
        emitted only after every enabled Redfish and IPMI probe supplied by the
        catalog and its owned cleanup have completed. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run health check.
        """
        collector_id = str(kwargs.get("collector_id") or "health_check")
        function_tag = str(kwargs.get("function_tag") or "health_check")

        await self._log_runtime(
            "INFO",
            "HealthCheckService",
            "Starting catalog-driven out-of-band health check",
            dut_id,
        )

        redfish_checks = kwargs.get("redfish_checks")
        ipmi_checks = kwargs.get("ipmi_checks")
        settings = kwargs.get("config")
        config_errors = self._validate_execution_config(
            redfish_checks, ipmi_checks, settings
        )
        if config_errors:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=config_errors,
                operation_name="health_check_configuration",
                additional_context={
                    "status": "error",
                    "reason": "Health-check catalog configuration is invalid",
                    "dut_id": dut_id,
                },
                dut_id=dut_id,
                collector_id=collector_id,
            )

        assert isinstance(settings, dict)  # established by validation above
        records: List[Dict[str, Any]] = []
        services_checked: List[str] = []
        services_executed: List[str] = []
        services_not_applicable: List[str] = []
        dut = self.dut_manager.get_dut(dut_id)
        dut_config = getattr(dut, "config", {})

        try:
            if redfish_checks.get("enabled"):
                services_checked.append("redfish")
                unsupported = self._catalog_transport_not_applicable(
                    dut_config, "redfish"
                )
                if unsupported:
                    services_not_applicable.append("redfish")
                    records.append(unsupported)
                else:
                    services_executed.append("redfish")
                    records.extend(
                        await self._run_redfish_checks(
                            dut_id, redfish_checks.get("components", [])
                        )
                    )

            if ipmi_checks.get("enabled"):
                services_checked.append("ipmi")
                unsupported = self._catalog_transport_not_applicable(dut_config, "ipmi")
                if unsupported:
                    services_not_applicable.append("ipmi")
                    records.append(unsupported)
                else:
                    services_executed.append("ipmi")
                    records.extend(
                        await self._run_ipmi_checks(
                            dut_id, ipmi_checks.get("components", [])
                        )
                    )
        except Exception as exc:  # defensive boundary; per-probe errors are retained
            records.append(
                {
                    "transport": "health_check",
                    "phase": "execution",
                    "target": function_tag,
                    "healthy": False,
                    "counts_for_health": True,
                    "reason": f"Unexpected health-check execution error: {exc}",
                }
            )

        health_records = [
            record for record in records if record.get("counts_for_health", True)
        ]
        healthy_probes = sum(
            1 for record in health_records if record.get("healthy") is True
        )
        total_probes = len(health_records)
        all_transports_unsupported = bool(services_not_applicable) and not bool(
            services_executed
        )
        has_not_applicable_probe = any(
            record.get("status") == "not_applicable" for record in records
        )
        all_probes_not_applicable = all_transports_unsupported or (
            total_probes == 0 and has_not_applicable_probe
        )
        overall_health = (
            "not_applicable"
            if all_probes_not_applicable
            else self._health_label(healthy_probes, total_probes)
        )
        threshold = settings["overall_health_threshold"]
        threshold_met = (
            False
            if all_probes_not_applicable
            else self._threshold_met(healthy_probes, total_probes, threshold)
        )

        error_messages = [
            self._record_error(record)
            for record in health_records
            if record.get("healthy") is not True
        ]
        outcome_status = (
            "skipped"
            if all_probes_not_applicable
            else self._outcome_status(healthy_probes, total_probes)
        )

        rendered_records = self._render_records(
            records,
            include_reasons=settings.get("include_reasons", True),
            detailed_status=settings.get("detailed_status", True),
        )
        requests_and_commands = sum(
            1
            for record in records
            if (
                record.get("transport") == "redfish"
                and record.get("request_executed") is True
            )
            or (
                record.get("transport") == "ipmi"
                and record.get("status") != "not_applicable"
            )
        )
        health_data = {
            "dut_id": dut_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_health": overall_health,
            "threshold": threshold,
            "threshold_met": threshold_met,
            "summary": {
                "services_checked": services_checked,
                "services_executed": services_executed,
                "services_not_applicable": services_not_applicable,
                "healthy_probes": healthy_probes,
                "total_probes": total_probes,
                "failed_probes": total_probes - healthy_probes,
                "requests_and_commands": requests_and_commands,
            },
            "probes": rendered_records,
        }

        output_files: List[str] = []
        file_path = await self._save_data_with_common_pattern(
            dut_id,
            health_data,
            function_tag,
            output_pattern=kwargs.get("output_pattern"),
            output_format=settings["output_format"],
            collector_id=collector_id,
        )
        persistence_failed = not file_path
        if file_path:
            output_files.append(file_path)
        else:
            error_messages.append("Failed to persist the health-check artifact")
            outcome_status = "error"

        if all_probes_not_applicable:
            # Discovery GETs remain observable in the artifact request count, but
            # authoritative unsupported evidence is not a performed health-check
            # operation and must not manufacture a successful probe.
            successful_operations = 0
            total_operations = 0
        else:
            # The standardized collector result and the human-readable reason
            # must use the same configured-probe unit. Discovery and capability
            # requests remain observable through ``requests_and_commands`` but
            # must not silently change the terminal success-rate denominator.
            successful_operations = healthy_probes
            total_operations = total_probes
        if all_probes_not_applicable and not persistence_failed:
            reason = "Health check skipped: all configured probes are not applicable"
        elif total_operations == 0:
            error_messages.append("No configured health probes were executed")
            outcome_status = "error"
            reason = "Health check error: no configured health probes were executed"
            if persistence_failed:
                reason += "; artifact persistence failed"
        else:
            reason = self._outcome_reason(
                outcome_status,
                healthy_probes,
                total_probes,
                threshold,
                threshold_met,
                persistence_failed,
            )

        result_context = {
            "status": outcome_status,
            "reason": reason,
            "overall_health": overall_health,
            "threshold": threshold,
            "threshold_met": threshold_met,
            "services_checked": services_checked,
            "services_executed": services_executed,
            "services_not_applicable": services_not_applicable,
            "healthy_probes": healthy_probes,
            "total_probes": total_probes,
            "requests_and_commands": requests_and_commands,
            "dut_id": dut_id,
        }
        if all_probes_not_applicable and not persistence_failed:
            # The artifact is authoritative negative capability evidence, not a
            # successful probe. Preserve it without allowing generic lifecycle
            # aggregation to promote the intentional skip to success.
            result_context["intentional_evidence_only_skip"] = True

        return await self._create_standardized_collector_result(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="health_check_probes",
            additional_context=result_context,
            dut_id=dut_id,
            collector_id=collector_id,
        )

    @staticmethod
    def _catalog_transport_not_applicable(
        dut_config: Any, service_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Describe an explicitly unsupported transport without probing it.

        The implementation uses ``dut_config`` and ``service_name`` to describe
        an explicitly unsupported transport without probing it.

        Args:
            dut_config: DUT config governing describe an explicitly unsupported
                transport without probing it.
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.

        Returns:
            A mapping containing the ``transport``, ``phase``, ``target``,
            ``status``, and ``healthy`` fields.
        """
        if catalog_transport_support(dut_config, service_name) is not False:
            return None

        support_field = transport_support_field(service_name)
        return {
            "transport": service_name,
            "phase": "catalog_support",
            "target": service_name,
            "status": "not_applicable",
            "healthy": None,
            "transport_success": None,
            "counts_for_health": False,
            "reason": f"Baseboard catalog declares {support_field}=false",
            "details": {"catalog_transport_unsupported": True},
        }

    def _validate_execution_config(
        self, redfish_checks: Any, ipmi_checks: Any, settings: Any
    ) -> List[str]:
        """
        Validate execution config.

        The implementation uses ``redfish_checks``, ``ipmi_checks``, and
        ``settings`` to validate execution config. Every required invariant is
        checked before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            redfish_checks: Entries supplied as ``redfish_checks`` and processed
                in caller-provided order.
            ipmi_checks: Entries supplied as ``ipmi_checks`` and processed in
                caller-provided order.
            settings: Settings governing execution config.

        Returns:
            The execution config returned in operation-defined order.
        """
        errors: List[str] = []
        enabled_groups = 0

        for group_name, group, required_key in (
            ("redfish_checks", redfish_checks, "resource_path"),
            ("ipmi_checks", ipmi_checks, "command"),
        ):
            if not isinstance(group, dict):
                errors.append(f"{group_name} must be a mapping")
                continue
            if not isinstance(group.get("enabled"), bool):
                errors.append(f"{group_name}.enabled must be a boolean")
                continue
            if not group["enabled"]:
                continue

            enabled_groups += 1
            components = group.get("components")
            if not isinstance(components, list) or not components:
                errors.append(
                    f"{group_name}.components must be a non-empty list when enabled"
                )
                continue
            for index, component in enumerate(components):
                if not isinstance(component, dict):
                    errors.append(f"{group_name}.components[{index}] must be a mapping")
                    continue
                value = component.get(required_key)
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"{group_name}.components[{index}].{required_key} "
                        "must be a non-empty string"
                    )
                validation = component.get("validation", {})
                if not isinstance(validation, dict):
                    errors.append(
                        f"{group_name}.components[{index}].validation must be a mapping"
                    )

                if group_name != "redfish_checks":
                    continue
                advertised_link_path = component.get("advertised_link_path")
                if advertised_link_path is None:
                    continue
                relation = self._advertised_link_relation(advertised_link_path)
                if relation is None:
                    errors.append(
                        f"{group_name}.components[{index}].advertised_link_path "
                        "must be a non-empty dotted path"
                    )
                    continue
                if not isinstance(value, str):
                    continue
                placeholder = self._PLACEHOLDER.search(value)
                suffix = value[placeholder.end() :] if placeholder else ""
                relation_prefix = f"/{relation}"
                if not placeholder or not (
                    suffix == relation_prefix
                    or suffix.startswith(f"{relation_prefix}/")
                ):
                    errors.append(
                        f"{group_name}.components[{index}].advertised_link_path "
                        f"must identify the first child relation after {placeholder.group(0) if placeholder else 'a placeholder'}"
                    )

        if enabled_groups == 0:
            errors.append("At least one health-check transport must be enabled")

        if not isinstance(settings, dict):
            errors.append("config must be a mapping")
            return errors

        threshold = settings.get("overall_health_threshold")
        if not self._valid_threshold(threshold):
            errors.append(
                "config.overall_health_threshold must be all_pass, any_pass, "
                "majority, or a fraction greater than 0 and at most 1"
            )

        output_format = settings.get("output_format")
        if (
            not isinstance(output_format, str)
            or output_format.lower() not in self._SUPPORTED_OUTPUT_FORMATS
        ):
            errors.append("config.output_format must be json or text")

        for flag in ("include_reasons", "detailed_status"):
            if flag in settings and not isinstance(settings[flag], bool):
                errors.append(f"config.{flag} must be a boolean")

        return errors

    @staticmethod
    def _advertised_link_relation(path: Any) -> Optional[str]:
        """
        Return the first resource relation named by an advertised-link path.

        The catalog uses dotted response paths such as
        ``EthernetInterfaces.@odata.id``. The first segment identifies the
        literal relation that an authored URI template must replace with the
        advertised target. Empty segments and path separators are rejected so
        configuration cannot silently select a different URI boundary.

        Args:
            path: Catalog value naming the nested advertised-link field.

        Returns:
            The first relation name, or ``None`` when the path is malformed.
        """

        if not isinstance(path, str) or not path.strip():
            return None
        segments = [segment.strip() for segment in path.split(".")]
        if any(not segment for segment in segments):
            return None
        relation = segments[0]
        if "/" in relation or relation in {".", ".."}:
            return None
        return relation

    @staticmethod
    def _extract_advertised_link(response: Any, path: str) -> Tuple[bool, Any]:
        """
        Extract one catalog-selected field while preserving dotted Redfish keys.

        Redfish annotations such as ``@odata.id`` contain dots themselves.
        Resolution therefore chooses the longest key present at each mapping
        level instead of treating every dot as an unconditional nesting
        delimiter. The boolean distinguishes an absent field from a present but
        malformed value such as ``null`` or an integer.

        Args:
            response: JSON-compatible Redfish response to inspect.
            path: Dotted catalog path selecting the advertised URI value.

        Returns:
            A tuple containing whether the full path was present and its value.
        """

        if not isinstance(response, dict):
            return False, None
        segments = path.split(".")
        current: Any = response
        index = 0
        while index < len(segments):
            if not isinstance(current, dict):
                return False, None
            matched = False
            for end in range(len(segments), index, -1):
                candidate = ".".join(segments[index:end])
                if candidate in current:
                    current = current[candidate]
                    index = end
                    matched = True
                    break
            if not matched:
                return False, None
        return True, current

    async def _resolve_advertised_member_candidate(
        self,
        dut_id: str,
        member_uri: str,
        suffix: str,
        component: Dict[str, Any],
        records: List[Dict[str, Any]],
        budget: _RedfishTraversalBudget,
    ) -> Optional[str]:
        """
        Resolve one child candidate exclusively from its parent's advertised link.

        The parent response is requested through the invocation cache and the
        configured link is validated beneath that parent before its remaining
        template suffix is appended. An absent capability is recorded as
        not-applicable without issuing a child request. Malformed advertised
        data and parent transport failures remain status-affecting evidence.
        Child links inherit the resolved parent namespace when proxies advertise
        a shared catalog or BMC root in an HMC response.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration and
                results.
            member_uri: Validated parent resource URI discovered from a
                collection member.
            suffix: Remaining authored URI template after the parent
                placeholder.
            component: Catalog health-check component requesting link gating.
            records: Mutable evidence list owned by the calling traversal.
            budget: Invocation-local request and traversal budget.

        Returns:
            A validated child template rooted at the advertised URI, or
            ``None`` when traversal must stop for this parent.
        """

        advertised_link_path = component["advertised_link_path"]
        relation = self._advertised_link_relation(advertised_link_path)
        relation_prefix = f"/{relation}" if relation else ""
        if not relation or not (
            suffix == relation_prefix or suffix.startswith(f"{relation_prefix}/")
        ):
            records.append(
                self._redfish_incomplete_record(
                    component,
                    member_uri,
                    "Advertised-link path does not match the authored child relation",
                )
            )
            return None

        capability = await self._redfish_probe(
            dut_id,
            member_uri,
            component,
            "capability",
            budget=budget,
            assess_health=False,
        )
        records.append(capability)
        if not capability["transport_success"]:
            capability["counts_for_health"] = True
            return None

        response = capability.get("response")
        if not isinstance(response, dict):
            capability.update(
                status="incomplete",
                healthy=False,
                counts_for_health=True,
                reason=(
                    f"{member_uri} did not return a Redfish object while resolving "
                    f"advertised link {advertised_link_path}"
                ),
            )
            return None

        found, raw_link = self._extract_advertised_link(
            response,
            advertised_link_path,
        )
        if not found:
            capability.update(
                status="not_applicable",
                healthy=None,
                counts_for_health=False,
                reason=(
                    f"{member_uri} does not advertise {advertised_link_path}; "
                    "child health probe is unsupported"
                ),
            )
            return None
        if not isinstance(raw_link, str) or not raw_link.strip():
            capability.update(
                status="incomplete",
                healthy=False,
                counts_for_health=True,
                reason=(f"{member_uri} advertises malformed {advertised_link_path}"),
            )
            return None

        try:
            link_uri = validate_redfish_uri_path(
                self._configured_redfish_path(
                    dut_id,
                    raw_link,
                    hmc=self.dut_manager.uri_config_manager._is_hmc_uri(
                        member_uri, dut_id
                    ),
                ),
                context="health-check advertised child URI",
                service_root=member_uri,
            )
        except (RedfishTopologyProfileError, TypeError, ValueError) as exc:
            capability.update(
                status="incomplete",
                healthy=False,
                counts_for_health=True,
                reason=(
                    f"{member_uri} advertises invalid {advertised_link_path}: {exc}"
                ),
            )
            return None

        remainder = suffix[len(relation_prefix) :]
        return f"{link_uri.rstrip('/')}{remainder}"

    def _valid_threshold(self, threshold: Any) -> bool:
        """
        Return whether ``threshold`` is valid threshold.

        The implementation uses ``threshold`` to determine whether ``threshold``
        is valid threshold.

        Args:
            threshold: Threshold object whose ``lower`` state is read while
                performing ``threshold`` is valid threshold.

        Returns:
            Whether ``threshold`` is valid threshold.
        """
        if isinstance(threshold, str):
            return threshold.lower() in self._SUPPORTED_THRESHOLDS
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            return False
        return 0 < float(threshold) <= 1

    async def _run_redfish_checks(
        self, dut_id: str, components: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Run Redfish checks.

        The implementation uses ``dut_id`` and ``components`` to run Redfish
        checks. Terminal status is emitted only after redfish checks and its
        owned cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            components: Mapping supplying fields for redfish checks.

        Returns:
            The validated ``records``.
        """
        records: List[Dict[str, Any]] = []
        budget = _RedfishTraversalBudget(
            max_members=self._MAX_REDFISH_TRAVERSAL_MEMBERS,
            max_nodes=self._MAX_REDFISH_TRAVERSAL_NODES,
            max_candidates=self._MAX_REDFISH_CANDIDATES,
            max_requests=self._MAX_REDFISH_REQUESTS,
            max_depth=self._MAX_REDFISH_PLACEHOLDER_DEPTH,
            deadline=time.monotonic() + self._MAX_REDFISH_TRAVERSAL_SECONDS,
        )
        for scope, component in enumerate(components):
            if budget.terminal_reason is not None:
                self._append_traversal_evidence(
                    records,
                    budget,
                    component,
                    component.get("resource_path", "redfish health checks"),
                    budget.terminal_reason,
                )
                break

            resource_path = component["resource_path"].strip()
            try:
                self._validate_redfish_template(resource_path)
            except (RedfishTopologyProfileError, TypeError, ValueError) as exc:
                records.append(
                    self._redfish_incomplete_record(
                        component,
                        resource_path,
                        f"Invalid Redfish health resource path: {exc}",
                    )
                )
                continue

            admitted, reason = budget.reserve_candidate(
                scope,
                resource_path,
                charge_member=False,
            )
            if not admitted:
                if reason is not None:
                    self._append_traversal_evidence(
                        records, budget, component, resource_path, reason
                    )
                    break
                continue

            leaf_uris = await self._expand_redfish_path(
                dut_id,
                resource_path,
                component,
                records,
                budget,
                scope=scope,
                depth=0,
            )
            if budget.terminal_reason is not None:
                break

            for uri in leaf_uris:
                record = await self._redfish_probe(
                    dut_id,
                    uri,
                    component,
                    "health",
                    budget=budget,
                )
                records.append(record)
                if budget.terminal_reason is not None:
                    break
            if budget.terminal_reason is not None:
                break
        return records

    def _configured_redfish_path(
        self, dut_id: str, uri: str, *, hmc: Optional[bool] = None
    ) -> str:
        """
        Normalize a concrete health path before validating advertised ancestry.

        Collection templates and response links must share the same namespace
        before ancestry is checked. Validate both sides of the translation so
        a custom root cannot repair an unsafe advertised path.

        Args:
            dut_id: DUT whose service-root policy owns the request.
            uri: Path-only catalog request or advertised response link.
            hmc: Optional namespace override for a collection ancestry check.

        Returns:
            The validated path under the configured BMC or HMC root.

        Raises:
            ValueError: If the input or configured path violates URI policy.
        """

        validated = validate_redfish_uri_path(uri, context="health-check Redfish URI")
        return validate_redfish_uri_path(
            self.dut_manager.uri_config_manager.normalize_response_uri(
                dut_id, validated, hmc=hmc
            ),
            context="configured health-check Redfish URI",
        )

    async def _expand_redfish_path(
        self,
        dut_id: str,
        resource_path: str,
        component: Dict[str, Any],
        records: List[Dict[str, Any]],
        budget: _RedfishTraversalBudget,
        *,
        scope: int,
        depth: int,
    ) -> List[str]:
        """
        Expand a health URI template through bounded collection traversal.

        Validate advertised members before expanding the next placeholder. An
        HMC collection preserves its namespace for shared-root child links; a
        BMC collection can still advertise members in an independent HMC root.
        Record malformed data and budget exhaustion without manufacturing a
        successful leaf probe.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_path: Authored URI template with zero or more placeholders.
            component: Catalog health component supplying relation and probe policy.
            records: Caller-owned list receiving discovery and capability evidence.
            budget: Shared limits for requests, members, nodes, depth and time.
            scope: Component identity used for bounded candidate accounting.
            depth: Number of placeholders already expanded in this traversal.

        Returns:
            Validated concrete leaf URIs in discovery order.

        Side Effects:
            Awaits bounded Redfish requests, consumes the traversal budget and
            appends evidence to ``records``.
        """
        admitted, reason = budget.reserve_node()
        if not admitted:
            if reason is not None:
                self._append_traversal_evidence(
                    records, budget, component, resource_path, reason
                )
            return []

        match = self._PLACEHOLDER.search(resource_path)
        if not match:
            return [resource_path]
        if depth >= budget.max_depth:
            self._append_traversal_evidence(
                records,
                budget,
                component,
                resource_path,
                (
                    "Redfish health placeholder depth exceeds the maximum "
                    f"({budget.max_depth})"
                ),
                key=f"depth:{scope}:{resource_path}",
            )
            return []

        collection_uri = resource_path[: match.start()].rstrip("/")
        suffix = resource_path[match.end() :]
        try:
            collection_uri = validate_redfish_uri_path(
                self._configured_redfish_path(dut_id, collection_uri),
                context="health-check Redfish collection URI",
            )
        except (RedfishTopologyProfileError, TypeError, ValueError) as exc:
            records.append(
                self._redfish_incomplete_record(
                    component,
                    collection_uri or resource_path,
                    f"Invalid Redfish health collection URI: {exc}",
                )
            )
            return []

        discovery = await self._redfish_probe(
            dut_id,
            collection_uri,
            component,
            "discovery",
            budget=budget,
            assess_health=False,
        )
        records.append(discovery)
        if not discovery["transport_success"]:
            discovery["counts_for_health"] = True
            return []

        response = discovery.get("response")
        members = response.get("Members") if isinstance(response, dict) else None
        if not isinstance(members, list):
            discovery.update(
                healthy=False,
                counts_for_health=True,
                reason=f"{collection_uri} did not return a Redfish Members list",
            )
            return []
        if not members:
            discovery.update(
                healthy=False,
                counts_for_health=True,
                reason=f"{collection_uri} returned no Redfish members",
            )
            return []

        bounded_members, source_count, truncated = bound_redfish_collection_members(
            members,
            field_name=f"{collection_uri} Members",
            limit=self._MAX_REDFISH_COLLECTION_MEMBERS,
        )
        if truncated:
            self._append_traversal_evidence(
                records,
                budget,
                component,
                collection_uri,
                (
                    f"{collection_uri} returned {source_count} members; only the first "
                    f"{self._MAX_REDFISH_COLLECTION_MEMBERS} may be followed"
                ),
                key=f"collection-members:{collection_uri}",
            )

        expanded: List[str] = []
        collection_hmc = self.dut_manager.uri_config_manager._is_hmc_uri(
            collection_uri, dut_id
        )
        for index, member in enumerate(bounded_members):
            active, reason = budget.active()
            if not active:
                if reason is not None:
                    self._append_traversal_evidence(
                        records, budget, component, collection_uri, reason
                    )
                break

            member_uri = member.get("@odata.id") if isinstance(member, dict) else None
            if not isinstance(member_uri, str) or not member_uri.strip():
                records.append(
                    {
                        "transport": "redfish",
                        "phase": "discovery",
                        "component": component.get("type"),
                        "description": component.get("description"),
                        "target": f"{collection_uri} Members[{index}]",
                        "healthy": False,
                        "transport_success": True,
                        "counts_for_health": True,
                        "reason": "Redfish member is missing @odata.id",
                        "response": member,
                    }
                )
                continue
            try:
                member_uri = self._configured_redfish_path(
                    dut_id, member_uri, hmc=True if collection_hmc else None
                )
                member_collection = self._configured_redfish_path(
                    dut_id,
                    collection_uri,
                    hmc=self.dut_manager.uri_config_manager._is_hmc_uri(
                        member_uri, dut_id
                    ),
                )
                member_uri = validate_redfish_uri_path(
                    member_uri,
                    context="health-check Redfish member URI",
                    service_root=member_collection,
                )
            except (RedfishTopologyProfileError, TypeError, ValueError):
                records.append(
                    {
                        "transport": "redfish",
                        "phase": "discovery",
                        "component": component.get("type"),
                        "description": component.get("description"),
                        "target": f"{collection_uri} Members[{index}]",
                        "healthy": False,
                        "transport_success": True,
                        "counts_for_health": True,
                        "reason": "Redfish member has an invalid @odata.id",
                    }
                )
                continue
            advertised_link_path = component.get("advertised_link_path")
            advertised_relation = self._advertised_link_relation(advertised_link_path)
            advertised_prefix = f"/{advertised_relation}" if advertised_relation else ""
            if (
                advertised_link_path
                and advertised_prefix
                and (
                    suffix == advertised_prefix
                    or suffix.startswith(f"{advertised_prefix}/")
                )
            ):
                candidate = await self._resolve_advertised_member_candidate(
                    dut_id,
                    member_uri,
                    suffix,
                    component,
                    records,
                    budget,
                )
                if candidate is None:
                    continue
            else:
                candidate = f"{member_uri.rstrip('/')}{suffix}"
            try:
                self._validate_redfish_template(candidate)
            except (RedfishTopologyProfileError, TypeError, ValueError):
                records.append(
                    {
                        "transport": "redfish",
                        "phase": "discovery",
                        "component": component.get("type"),
                        "description": component.get("description"),
                        "target": f"{collection_uri} Members[{index}]",
                        "healthy": False,
                        "transport_success": True,
                        "counts_for_health": True,
                        "reason": "Redfish member produced an invalid resource path",
                    }
                )
                continue

            admitted, reason = budget.reserve_candidate(
                scope,
                candidate,
                charge_member=True,
            )
            if not admitted:
                if reason is not None:
                    self._append_traversal_evidence(
                        records, budget, component, candidate, reason
                    )
                    break
                continue

            expanded.extend(
                await self._expand_redfish_path(
                    dut_id,
                    candidate,
                    component,
                    records,
                    budget,
                    scope=scope,
                    depth=depth + 1,
                )
            )
            if budget.terminal_reason is not None:
                break
        return expanded

    async def _redfish_probe(
        self,
        dut_id: str,
        uri: str,
        component: Dict[str, Any],
        phase: str,
        *,
        budget: _RedfishTraversalBudget,
        assess_health: bool = True,
    ) -> Dict[str, Any]:
        """
        Return the Redfish probe.

        The implementation uses ``dut_id``, ``uri``, ``component``, ``phase``,
        and ``budget`` to produce the Redfish probe. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. Remote I/O uses the configured transport policy and returns only
        after its response or failure has been observed.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            uri: Validated remote resource identifier used for URI.
            component: Mapping supplying fields for redfish probe.
            phase: Text supplied as phase in the format accepted by this
                function.
            budget: Budget object whose ``expire``, ``remaining_seconds``,
                ``request_cache``, ``reserve_request``, and ``terminal_reason``
                state is read while performing redfish probe.
            assess_health: Whether assess health is enabled or required for this
                operation.

        Returns:
            A mapping containing Redfish probe.
        """
        record: Dict[str, Any] = {
            "transport": "redfish",
            "phase": phase,
            "component": component.get("type"),
            "description": component.get("description"),
            "target": uri,
            "healthy": False,
            "transport_success": False,
            "counts_for_health": assess_health,
            "request_executed": False,
        }
        try:
            uri = validate_redfish_uri_path(
                self._configured_redfish_path(dut_id, uri),
                context="health-check Redfish request URI",
            )
            record["target"] = uri
        except (RedfishTopologyProfileError, TypeError, ValueError) as exc:
            record.update(
                status="incomplete",
                counts_for_health=True,
                reason=f"Invalid Redfish health request URI: {exc}",
            )
            return record

        reservation, reason = budget.reserve_request(uri)
        if reservation == "rejected":
            record.update(
                status="incomplete",
                counts_for_health=True,
                reason=f"Redfish health traversal incomplete: {reason}",
            )
            return record

        try:
            if reservation == "cached":
                outcome = budget.request_cache[uri]
            else:
                remaining = budget.remaining_seconds()
                if remaining <= 0:
                    record.update(
                        status="incomplete",
                        counts_for_health=True,
                        reason=(
                            "Redfish health traversal incomplete: "
                            f"{budget.terminal_reason}"
                        ),
                    )
                    return record
                try:
                    record["request_executed"] = True
                    success, response, metadata, headers = await asyncio.wait_for(
                        self.dut_manager.execute_redfish_request(dut_id, "GET", uri),
                        timeout=remaining,
                    )
                    outcome = _RedfishRequestOutcome(
                        success=bool(success),
                        response=response,
                        metadata=metadata,
                        headers=headers,
                    )
                except TimeoutError:
                    timeout_reason = (
                        "Redfish health traversal deadline was exceeded while "
                        f"requesting {uri}"
                    )
                    budget.expire(timeout_reason)
                    outcome = _RedfishRequestOutcome(
                        success=False,
                        exception_reason=timeout_reason,
                    )
                except Exception as exc:
                    outcome = _RedfishRequestOutcome(
                        success=False,
                        exception_reason=(
                            f"GET {uri} raised {type(exc).__name__}: {exc}"
                        ),
                    )
                budget.request_cache[uri] = outcome

            if outcome.exception_reason is not None:
                record["reason"] = outcome.exception_reason
                if budget.terminal_reason is not None:
                    record.update(status="incomplete", counts_for_health=True)
                return record

            success = outcome.success
            response = outcome.response
            metadata = outcome.metadata
            headers = outcome.headers
            record.update(
                transport_success=success,
                response=response,
                metadata=metadata,
                headers=headers,
            )
            if not success:
                record["reason"] = f"GET {uri} failed: {response}"
                return record
            if not assess_health:
                record.update(
                    healthy=True, reason="Redfish discovery request succeeded"
                )
                return record

            healthy, reason = self._assess_redfish_health(response)
            record.update(healthy=healthy, reason=reason)
            return record
        except Exception as exc:
            record["reason"] = f"GET {uri} raised {type(exc).__name__}: {exc}"
            return record

    @classmethod
    def _validate_redfish_template(cls, resource_path: str) -> None:
        """
        Validate a health URI template by substituting inert path segments.

        The implementation uses ``resource_path`` to validate a health URI
        template by substituting inert path segments. Every required invariant
        is checked before a successful value is returned; invalid input follows
        the function's explicit exception path.

        Args:
            resource_path: filesystem location used as the source for this
                operation.
        """

        concrete_path = cls._PLACEHOLDER.sub("health_member", resource_path)
        validate_redfish_uri_path(
            concrete_path,
            context="health-check Redfish resource path",
        )

    @staticmethod
    def _redfish_incomplete_record(
        component: Dict[str, Any],
        target: Any,
        reason: str,
    ) -> Dict[str, Any]:
        """
        Build status-affecting evidence for omitted Redfish traversal work.

        The implementation uses ``component``, ``target``, and ``reason`` to
        build status-affecting evidence for omitted Redfish traversal work.

        Args:
            component: Mapping supplying fields for status-affecting evidence
                for omitted Redfish traversal work.
            target: Target consumed while the function attempts to build
                status-affecting evidence for omitted Redfish traversal work.
            reason: Text supplied as reason in the format accepted by this
                function.

        Returns:
            A mapping containing the ``transport``, ``phase``, ``component``,
            ``description``, and ``target`` fields.
        """

        return {
            "transport": "redfish",
            "phase": "traversal",
            "component": component.get("type"),
            "description": component.get("description"),
            "target": target,
            "status": "incomplete",
            "healthy": False,
            "transport_success": False,
            "counts_for_health": True,
            "reason": f"Redfish health traversal incomplete: {reason}",
        }

    def _append_traversal_evidence(
        self,
        records: List[Dict[str, Any]],
        budget: _RedfishTraversalBudget,
        component: Dict[str, Any],
        target: Any,
        reason: str,
        *,
        key: Optional[str] = None,
    ) -> None:
        """
        Append each bounded-work omission once while keeping it unhealthy.

        The implementation uses ``records``, ``budget``, ``component``,
        ``target``, and ``reason`` to append each bounded-work omission once
        while keeping it unhealthy. The operation mutates ``budget`` and
        ``records`` in place; ownership of those objects remains with the
        caller.

        Args:
            records: Mapping supplying fields for append each bounded-work
                omission once while keeping it unhealthy.
            budget: Budget object whose ``add`` and ``evidence_keys`` state is
                read while performing append each bounded-work omission once
                while keeping it unhealthy.
            component: Mapping supplying fields for append each bounded-work
                omission once while keeping it unhealthy.
            target: Target consumed while the function attempts to append each
                bounded-work omission once while keeping it unhealthy.
            reason: Text supplied as reason in the format accepted by this
                function.
            key: Stable key used for lookup and operator-facing diagnostics.
        """

        evidence_key = key or f"budget:{reason}"
        if evidence_key in budget.evidence_keys:
            return
        budget.evidence_keys.add(evidence_key)
        records.append(self._redfish_incomplete_record(component, target, reason))

    @staticmethod
    def _assess_redfish_health(response: Any) -> Tuple[bool, str]:
        """
        Return the assess Redfish health.

        The implementation uses ``response`` to produce the assess Redfish
        health. Remote I/O uses the configured transport policy and returns only
        after its response or failure has been observed.

        Args:
            response: Transport response governed by the configured
                authentication and trust policy.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        if not isinstance(response, dict):
            return False, "Redfish health resource did not return a JSON object"

        status = response.get("Status")
        if status is None:
            return True, "Redfish resource is reachable; Status is not reported"
        if not isinstance(status, dict):
            return False, "Redfish Status is not an object"

        health = status.get("HealthRollup") or status.get("Health")
        if health is not None and str(health).strip().lower() != "ok":
            return False, f"Redfish health is {health}"

        state = status.get("State")
        details = []
        if health is not None:
            details.append(f"health={health}")
        if state is not None:
            details.append(f"state={state}")
        return True, "Redfish resource healthy" + (
            f" ({', '.join(details)})" if details else ""
        )

    async def _run_ipmi_checks(
        self, dut_id: str, components: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Run IPMI checks.

        The implementation uses ``dut_id`` and ``components`` to run IPMI
        checks. Terminal status is emitted only after IPMI checks and its owned
        cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            components: Mapping supplying fields for IPMI checks.

        Returns:
            The validated ``records``.
        """
        records: List[Dict[str, Any]] = []
        for component in components:
            command = component["command"].strip()
            record: Dict[str, Any] = {
                "transport": "ipmi",
                "phase": "health",
                "component": component.get("type"),
                "description": component.get("description"),
                "target": command,
                "healthy": False,
                "transport_success": False,
                "counts_for_health": True,
            }
            try:
                exit_code, stdout, stderr = await self.dut_manager.execute_ipmi_command(
                    dut_id, command
                )
                record.update(
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    transport_success=exit_code == 0,
                )
                if exit_code != 0:
                    record["reason"] = (
                        f"IPMI command exited with {exit_code}: {stderr or stdout}"
                    )
                else:
                    failures = self._validate_ipmi_output(
                        dut_id,
                        stdout or "",
                        component.get("validation", {}),
                    )
                    record["validation_failures"] = failures
                    record["healthy"] = not failures
                    record["reason"] = (
                        "; ".join(failures)
                        if failures
                        else "IPMI command and configured validations passed"
                    )
            except Exception as exc:
                record["reason"] = f"IPMI command raised {type(exc).__name__}: {exc}"
            records.append(record)
        return records

    def _validate_ipmi_output(
        self, dut_id: str, stdout: str, validation: Dict[str, Any]
    ) -> List[str]:
        """
        Validate IPMI output.

        The implementation uses ``dut_id``, ``stdout``, and ``validation`` to
        validate IPMI output. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            stdout: Text supplied as stdout in the format accepted by this
                function.
            validation: Mapping supplying fields for IPMI output.

        Returns:
            The validated ``failures``.
        """
        failures: List[str] = []
        lowered = stdout.lower()

        if validation.get("ip_address_check"):
            expected = validation.get("expected_ip")
            if not isinstance(expected, str) or not expected:
                failures.append("IP address validation has no expected_ip")
            else:
                dut = self.dut_manager.get_dut(dut_id)
                bmc_ip = getattr(getattr(dut, "credentials", None), "bmc_ip", "")
                expected = expected.replace("{BMC_IP}", str(bmc_ip or "")).strip()
                if not expected:
                    failures.append(
                        "IP address validation resolved to an empty expected value"
                    )
                elif self._PLACEHOLDER.search(expected):
                    failures.append(
                        f"IP address validation has unresolved value {expected}"
                    )
                elif not re.search(
                    rf"(?<![0-9A-Fa-f:.]){re.escape(expected.lower())}(?![0-9A-Fa-f:.])",
                    lowered,
                ):
                    failures.append(
                        f"Expected IP address {expected} was not present in output"
                    )

        if validation.get("check_critical_readings"):
            patterns = validation.get("patterns", [])
            if not isinstance(patterns, list):
                failures.append("Critical-reading patterns must be a list")
            else:
                matched = self._matching_ipmi_patterns(stdout, patterns)
                if matched:
                    failures.append(
                        "Critical sensor patterns found: " + ", ".join(matched)
                    )

        if validation.get("check_critical_entries"):
            pattern = validation.get("pattern")
            if not isinstance(pattern, str) or not pattern.strip():
                failures.append("Critical-entry validation has no pattern")
            else:
                matching_lines = self._matching_ipmi_event_lines(stdout, pattern)
                if matching_lines:
                    failures.append(f"Critical event pattern found: {pattern}")

        return failures

    @staticmethod
    def _matching_ipmi_patterns(stdout: str, patterns: List[Any]) -> List[str]:
        """
        Return the matching IPMI patterns.

        The implementation uses ``stdout`` and ``patterns`` to produce the
        matching IPMI patterns.

        Args:
            stdout: Text supplied as stdout in the format accepted by this
                function.
            patterns: Entries supplied as ``patterns`` without transferring
                container ownership.

        Returns:
            The validated ``matched``.
        """
        fields = {
            field.strip().lower()
            for line in stdout.splitlines()
            for field in line.split("|")
            if field.strip()
        }
        lowered = stdout.lower()
        matched: List[str] = []
        for value in patterns:
            if not isinstance(value, str) or not value.strip():
                continue
            pattern = value.strip().lower()
            found = pattern in fields
            if not found and (" " in pattern or len(pattern) > 3):
                found = pattern in lowered
            if found:
                matched.append(value)
        return matched

    @staticmethod
    def _matching_ipmi_event_lines(stdout: str, pattern: str) -> List[int]:
        """
        Return SEL line numbers containing the configured event severity.

        IPMI SEL output commonly uses values such as ``Lower Non-critical`` and
        ``Upper Critical`` in pipe-delimited fields. A raw substring lookup for
        the catalog pattern ``crit`` treats both values as critical. Preserve
        the catalog's abbreviated spelling while recognizing a negated
        ``non-critical`` token as a different severity.

        Other configured patterns retain the existing case-insensitive substring
        behavior. Only the catalog's ``crit`` value is special-cased, so custom
        catalogs do not acquire broader matching changes as part of this fix.

        Args:
            stdout: Text supplied as stdout in the format accepted by this
                function.
            pattern: Text supplied as pattern in the format accepted by this
                function.

        Returns:
            The matching IPMI event lines returned in operation-defined order.
        """

        normalized_pattern = pattern.casefold()
        if not pattern.strip():
            return []

        lines = stdout.splitlines()
        if normalized_pattern != "crit":
            return [
                line_number
                for line_number, line in enumerate(lines, start=1)
                if normalized_pattern in line.casefold()
            ]

        critical_pattern = re.compile(
            r"(?<![a-z0-9])(?P<negated>non(?:[\s_-]*))?" r"crit(?:ical)?(?![a-z0-9])",
            re.IGNORECASE,
        )
        matching_lines: List[int] = []

        for line_number, line in enumerate(lines, start=1):
            fields = [field.strip().casefold() for field in line.split("|")]
            for field in fields:
                if not field:
                    continue
                if any(
                    match.group("negated") is None
                    for match in critical_pattern.finditer(field)
                ):
                    matching_lines.append(line_number)
                    break

        return matching_lines

    @staticmethod
    def _health_label(healthy: int, total: int) -> str:
        """
        Return the health label.

        The implementation uses ``healthy`` and ``total`` to produce the health
        label.

        Args:
            healthy: Numeric healthy used while the operation performs bounded
                accounting.
            total: Numeric total used while the operation performs bounded
                accounting.

        Returns:
            The canonical health label.
        """
        if total <= 0:
            return "poor"
        ratio = healthy / total
        if ratio == 1:
            return "excellent"
        if ratio >= 0.75:
            return "good"
        if ratio >= 0.5:
            return "fair"
        return "poor"

    @staticmethod
    def _threshold_met(healthy: int, total: int, threshold: Any) -> bool:
        """
        Return the threshold met.

        The implementation uses ``healthy``, ``total``, and ``threshold`` to
        produce the threshold met.

        Args:
            healthy: Numeric healthy used while the operation performs bounded
                accounting.
            total: Numeric total used while the operation performs bounded
                accounting.
            threshold: Threshold object whose ``lower`` state is read while
                performing threshold met.

        Returns:
            Whether the threshold met operation succeeds.
        """
        if total <= 0:
            return False
        if isinstance(threshold, str):
            normalized = threshold.lower()
            if normalized == "all_pass":
                return healthy == total
            if normalized == "any_pass":
                return healthy > 0
            if normalized == "majority":
                return healthy > total / 2
        return healthy / total >= float(threshold)

    @staticmethod
    def _outcome_status(healthy: int, total: int) -> str:
        """
        Return the outcome status.

        The implementation uses ``healthy`` and ``total`` to produce the outcome
        status.

        Args:
            healthy: Numeric healthy used while the operation performs bounded
                accounting.
            total: Numeric total used while the operation performs bounded
                accounting.

        Returns:
            The canonical outcome status.
        """
        if total <= 0 or healthy <= 0:
            return "error"
        if healthy < total:
            return "partial"
        return "success"

    @staticmethod
    def _record_error(record: Dict[str, Any]) -> str:
        """
        Record error.

        The implementation uses ``record`` to record error.

        Args:
            record: Mapping supplying fields for record error.

        Returns:
            The canonical record error text.
        """
        transport = record.get("transport", "probe")
        target = record.get("target", "unknown target")
        reason = record.get("reason", "health check failed")
        return f"{transport} {target}: {reason}"

    @staticmethod
    def _render_records(
        records: List[Dict[str, Any]], *, include_reasons: bool, detailed_status: bool
    ) -> List[Dict[str, Any]]:
        """
        Render records.

        The implementation uses ``records``, ``include_reasons``, and
        ``detailed_status`` to render records. The source value keeps its
        ownership while the normalized representation is returned separately.

        Args:
            records: Mapping supplying fields for records.
            include_reasons: Whether include reasons is enabled or required for
                this operation.
            detailed_status: Whether detailed status is enabled or required for
                this operation.

        Returns:
            The validated ``rendered``.
        """
        rendered: List[Dict[str, Any]] = []
        summary_keys = {
            "transport",
            "phase",
            "component",
            "description",
            "target",
            "healthy",
            "transport_success",
        }
        for record in records:
            item = (
                dict(record)
                if detailed_status
                else {
                    key: value for key, value in record.items() if key in summary_keys
                }
            )
            item.pop("counts_for_health", None)
            if not include_reasons:
                item.pop("reason", None)
                item.pop("validation_failures", None)
            rendered.append(item)
        return rendered

    @staticmethod
    def _outcome_reason(
        status: str,
        healthy: int,
        total: int,
        threshold: Any,
        threshold_met: bool,
        persistence_failed: bool,
    ) -> str:
        """
        Return the outcome reason.

        The implementation uses ``status``, ``healthy``, ``total``,
        ``threshold``, and ``threshold_met`` to produce the outcome reason.

        Args:
            status: Text supplied as status in the format accepted by this
                function.
            healthy: Numeric healthy used while the operation performs bounded
                accounting.
            total: Numeric total used while the operation performs bounded
                accounting.
            threshold: Threshold consumed while the function attempts to produce
                the outcome reason.
            threshold_met: Whether threshold met is enabled or required for this
                operation.
            persistence_failed: Whether persistence failed is enabled or
                required for this operation.

        Returns:
            The canonical outcome reason text.
        """
        if persistence_failed:
            return "Health-check artifact persistence failed"
        return (
            f"Health check {status}: {healthy}/{total} configured probes healthy; "
            f"threshold={threshold} ({'met' if threshold_met else 'not met'})"
        )

    async def _save_data_with_common_pattern(
        self,
        dut_id: str,
        data: Any,
        function_tag: str,
        output_pattern: Optional[str] = None,
        substitutions: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Optional[str]:
        """
        Serialize and persist the health artifact using catalog output policy.

        After applying local validation, the function forwards ``dut_id``,
        ``data``, ``function_tag``, ``output_pattern``, and ``substitutions`` to
        ``self.write_output_file`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. The operation
        mutates ``kwargs`` in place; ownership of those objects remains with the
        caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            data: Data consumed while the function attempts to serialize and
                persist the health artifact using catalog output policy.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            output_pattern: Optional output pattern; ``None`` selects the
                function's default behavior.
            substitutions: Optional substitutions; ``None`` selects the
                function's default behavior.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The canonical save data with common pattern text, or ``None`` when
            the requested value is unavailable.

        Raises:
            ValueError: If unsupported health-check output format:
                ``output_format``.
        """
        del substitutions  # Reserved for parity with other service writers.
        output_format = str(kwargs.pop("output_format", "json")).lower()
        try:
            if output_format == "json":
                content = json.dumps(data, indent=2, default=str)
            elif output_format == "text":
                content = pprint.pformat(data, sort_dicts=False)
            else:
                raise ValueError(
                    f"Unsupported health-check output format: {output_format}"
                )

            filename = output_pattern or f"{function_tag}_{dut_id}.{output_format}"
            return await self.write_output_file(
                dut_id, kwargs.get("collector_id", ""), filename, content
            )
        except Exception as exc:
            await self._log_runtime(
                "ERROR",
                "HealthCheckService",
                f"Failed to save data for {function_tag}: {exc}",
                dut_id,
            )
            return None
